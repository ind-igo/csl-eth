//! History reads, profile §3c: a transaction and its receipt by hash, the
//! logs of an address or topic over a span in two tiers, and an old header,
//! each verified to a header the client's head reaches.
//!
//! The anchor is one block the client trusts: the finalized execution
//! block its head files proved ([`open_history_at_head`]), or a block hash
//! supplied out of band in tests. The bucket's history manifest must name
//! exactly that block. From it the client verifies headers downward by
//! `keccak` and `parentHash`, and keeps them for the session; a block's
//! transactions or receipts are fetched whole (one range, contiguous by
//! key) and their trie rebuilt to the header's root. Nothing a hint says
//! is believed: `tx_lookup` routes to a block and index whose transaction
//! must hash to the asked hash, and `log_lookup` names blocks whose
//! receipts must verify.
//!
//! Log queries have two tiers. **Indexed:** every log returned is in a
//! verified receipt, and the set is as complete as `log_lookup`, which can
//! omit. **Complete:** the client reads every header in the range (it has
//! most already, from the chain walk), and every block whose `logsBloom`
//! admits the term is fetched and checked; a bloom has no false negatives,
//! so a block it excludes holds no such log. On mainnet most blooms are
//! saturated, and the complete tier costs close to every receipt in the
//! range.
//!
//! Like the state client, this does no I/O: each `try_` attempt computes
//! from the [`Store`] and notes every range it can predict before returning
//! [`Pending`], so a read is a few rounds whatever its size: the hint, then
//! the headers and the block together, then any blobs.
//!
//! Old headers come by the `parentHash` route only: a header a day back is
//! a day of headers. The accumulator route (`historical_summaries`) is not
//! built.

use crate::{
    head::{verify_head, HeadError},
    is_pending, Driver, Hint, Pending, RunView, Store, VerifiedHead,
};
use alloy_primitives::B256;
pub use csl_eth_store::history::{
    decode_header, decode_receipt, history_table_name, HeaderFields, HistoryManifest, Log,
    ReceiptFields, Term, HISTORY_TABLES, H_HEADERS, H_LOG_LOOKUP, H_RECEIPTS, H_TRANSACTIONS,
    H_TX_LOOKUP,
};
use csl_eth_store::{
    blob_path,
    history::{
        block_key, history_manifest_path, history_run_path, log_lookup_block, log_lookup_key,
        ordered_root, parse_locator, tx_hash, tx_lookup_key, HISTORY_FORMAT_VERSION,
        HISTORY_LATEST, HISTORY_RUN_FORMAT, MAX_INDEX,
    },
};
use csl_run::{Entry, Reader};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    sync::Arc,
    time::SystemTime,
};

/// The block the client trusts, and the manifest must name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub number: u64,
    pub hash: B256,
}

impl From<&VerifiedHead> for Anchor {
    fn from(h: &VerifiedHead) -> Anchor {
        Anchor {
            number: h.execution.block_number,
            hash: h.execution.block_hash,
        }
    }
}

/// Why a history read could not be answered. None of these is evidence
/// that something does not exist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Insufficient {
    /// The block is outside the manifest's span.
    OutOfSpan { block: u64 },
    /// `tx_lookup` has no row for the hash. A hint can omit.
    NotIndexed,
    /// A hint routed to something that is not what was asked.
    Hint(String),
    /// A run file misbehaved: a short or failed range, a malformed page,
    /// fences that do not partition the keys.
    Run { table: u16, error: String },
    /// A blob that is missing or does not hash to its name.
    Blob(String),
    /// The header chain from the anchor breaks at `block`.
    Header { block: u64, what: String },
    /// A block's transactions or receipts do not rebuild its header's root.
    Block { block: u64, what: String },
    /// A verified leaf that does not decode as the profile says.
    Value { block: u64, what: &'static str },
    /// More rounds than a read may take.
    Budget,
}

impl fmt::Display for Insufficient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Insufficient::OutOfSpan { block } => {
                write!(f, "block {block} is outside the history span")
            }
            Insufficient::NotIndexed => write!(
                f,
                "tx_lookup has no row for the hash (not evidence of absence)"
            ),
            Insufficient::Hint(w) => write!(f, "hint: {w}"),
            Insufficient::Run { table, error } => {
                write!(f, "{}: {error}", history_table_name(*table))
            }
            Insufficient::Blob(w) => write!(f, "blob: {w}"),
            Insufficient::Header { block, what } => write!(f, "header {block}: {what}"),
            Insufficient::Block { block, what } => write!(f, "block {block}: {what}"),
            Insufficient::Value { block, what } => write!(f, "block {block}: {what}"),
            Insufficient::Budget => write!(f, "round budget exhausted"),
        }
    }
}

/// A history read: verified, or why not.
pub type HRead<T> = Result<T, Insufficient>;

/// What one read cost.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HistoryCost {
    pub requests: u64,
    pub bytes: u64,
    pub rounds: u32,
    /// Bytes received per table (`headers`, `receipts`, ...), blobs as
    /// `blobs`.
    pub table_bytes: BTreeMap<&'static str, u64>,
    /// Headers this read verified (not those the session already held).
    pub headers_verified: u64,
    /// Blocks whose transactions or receipts this read rebuilt.
    pub blocks_verified: u64,
}

/// A transaction and its receipt, both verified against their block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxReceipt {
    pub block_number: u64,
    pub block_hash: B256,
    pub index: u64,
    pub tx_hash: B256,
    /// The EIP-2718 envelope.
    pub tx: Vec<u8>,
    /// The receipt leaf and its fields.
    pub receipt_leaf: Vec<u8>,
    pub receipt: ReceiptFields,
    /// The whole block's receipt bytes, which the read had to fetch.
    pub block_receipt_bytes: u64,
    pub block_tx_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogTier {
    /// As complete as `log_lookup`.
    Indexed,
    /// Every block whose bloom admits the term was checked.
    Complete,
}

impl LogTier {
    pub fn name(self) -> &'static str {
        match self {
            LogTier::Indexed => "indexed",
            LogTier::Complete => "complete",
        }
    }
}

/// One log, located.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LogAt {
    pub block_number: u64,
    pub tx_index: u64,
    /// Position among the block's logs.
    pub log_index: u64,
    pub block_hash: B256,
    pub log: Log,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Logs {
    pub tier: LogTier,
    pub from: u64,
    pub to: u64,
    /// In block, then log order.
    pub logs: Vec<LogAt>,
    /// Blocks the hint named (indexed) or whose bloom matched (complete),
    /// each fetched and verified.
    pub blocks_fetched: u64,
    /// Of those, blocks holding no matching log: the hint's false rows, or
    /// the bloom's false positives.
    pub blocks_without_match: u64,
}

/// The manifest's checks: the anchor's block, this format, contiguous
/// periods covering the span.
fn check_history_manifest(bytes: &[u8], anchor: &Anchor) -> Result<HistoryManifest, String> {
    let m = HistoryManifest::from_json(bytes).map_err(|e| e.to_string())?;
    if m.block_hash != anchor.hash || m.block_number != anchor.number {
        return Err(format!(
            "history manifest names block {} ({}), the anchor is {} ({})",
            m.block_number, m.block_hash, anchor.number, anchor.hash
        ));
    }
    if m.format_version != HISTORY_FORMAT_VERSION {
        return Err(format!(
            "history format version {}, this client reads {HISTORY_FORMAT_VERSION}",
            m.format_version
        ));
    }
    let mut next = m.first_block;
    for p in &m.periods {
        if p.first_block != next || p.last_block < p.first_block {
            return Err("history manifest periods are not contiguous".into());
        }
        next = p.last_block + 1;
    }
    if m.periods.is_empty() || next != m.block_number + 1 {
        return Err("history manifest periods do not end at its block".into());
    }
    Ok(m)
}

type Readers = Vec<Option<Result<Reader<RunView>, String>>>;

fn table_slot(t: u16) -> usize {
    (t - H_HEADERS) as usize
}

/// A history span being opened: the manifest, then every run's model in
/// one round.
pub struct HistoryOpener<D> {
    driver: Option<D>,
    store: Arc<Store>,
    anchor: Anchor,
}

impl<D: Driver> HistoryOpener<D> {
    pub fn new(driver: D, store: Arc<Store>, anchor: Anchor) -> HistoryOpener<D> {
        HistoryOpener {
            driver: Some(driver),
            store,
            anchor,
        }
    }

    pub fn round(&self) {
        if let Some(d) = &self.driver {
            crate::drive(d, &self.store, true);
        }
    }

    /// Open from what the store holds, or `Pending`. `Ok(Err)` is a refusal.
    pub fn try_open(&mut self) -> Result<Result<History<D>, String>, Pending> {
        let manifest = match self.store.file(&history_manifest_path(&self.anchor.hash))? {
            Ok(Some(m)) => match check_history_manifest(&m, &self.anchor) {
                Ok(m) => m,
                Err(e) => return Ok(Err(e)),
            },
            Ok(None) => {
                let newest = match self.store.file(HISTORY_LATEST)? {
                    Ok(Some(s)) => String::from_utf8_lossy(&s).trim().to_string(),
                    _ => "none".into(),
                };
                return Ok(Err(format!(
                    "no history at block {} ({}); history/latest names {newest}",
                    self.anchor.number, self.anchor.hash
                )));
            }
            Err(e) => return Ok(Err(e)),
        };
        let mut readers: Vec<Readers> = Vec::new();
        let mut rels = HashMap::new();
        let mut pending = false;
        for p in &manifest.periods {
            let mut row: Readers = Vec::new();
            for t in HISTORY_TABLES {
                let Some(tr) = p.table(t) else {
                    row.push(None);
                    continue;
                };
                let rel = history_run_path(&tr.root);
                rels.insert(rel.clone(), t);
                let view = RunView {
                    store: self.store.clone(),
                    rel,
                };
                let mut r = match Reader::try_with_format(
                    view,
                    tr.run_ref(p.last_block),
                    HISTORY_RUN_FORMAT,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        row.push(Some(Err(e.to_string())));
                        continue;
                    }
                };
                match r.prepare() {
                    Ok(()) => row.push(Some(Ok(r))),
                    Err(e) if is_pending(&e) => {
                        pending = true;
                        row.push(Some(Ok(r)));
                    }
                    Err(e) => row.push(Some(Err(e.to_string()))),
                }
            }
            readers.push(row);
        }
        if pending {
            return Err(Pending);
        }
        Ok(Ok(History {
            driver: self.driver.take().expect("opened once"),
            store: self.store.clone(),
            manifest,
            anchor: self.anchor,
            readers,
            rels,
            headers: BTreeMap::new(),
            keep_headers: true,
            hint: Hint::none(),
            max_rounds: 64,
            tally: BTreeMap::new(),
            headers_at_begin: 0,
            blocks_verified: 0,
        }))
    }
}

/// An open history span.
pub struct History<D> {
    driver: D,
    store: Arc<Store>,
    manifest: HistoryManifest,
    anchor: Anchor,
    /// Per period, per table (`H_HEADERS..`): the run's reader, `None`
    /// when the period has no such run.
    readers: Vec<Readers>,
    rels: HashMap<String, u16>,
    /// Verified headers, always one contiguous range ending at the anchor.
    headers: BTreeMap<u64, HeaderFields>,
    /// Keep verified headers across reads (an indexer's or a wallet's
    /// session). Off, every read walks from the anchor again.
    pub keep_headers: bool,
    /// How each round is widened around the predicted pages.
    pub hint: Hint,
    /// Rounds a read may take before it is `Budget`.
    pub max_rounds: u32,
    tally: BTreeMap<&'static str, u64>,
    headers_at_begin: usize,
    blocks_verified: u64,
}

impl<D: Driver> History<D> {
    /// Open the span whose manifest names `anchor`. Synchronous.
    pub fn open(driver: D, anchor: Anchor) -> Result<History<D>, String> {
        let mut o = HistoryOpener::new(driver, Store::new(), anchor);
        loop {
            match o.try_open() {
                Ok(r) => return r,
                Err(Pending) => o.round(),
            }
        }
    }

    pub fn manifest(&self) -> &HistoryManifest {
        &self.manifest
    }

    pub fn anchor(&self) -> Anchor {
        self.anchor
    }

    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// Verified headers the session holds.
    pub fn verified_headers(&self) -> usize {
        self.headers.len()
    }

    pub fn forget_headers(&mut self) {
        self.headers.clear();
    }

    /// A read is starting.
    pub fn begin_read(&mut self) {
        self.store.begin_read();
        self.tally.clear();
        if !self.keep_headers {
            self.headers.clear();
        }
        self.headers_at_begin = self.headers.len();
        self.blocks_verified = 0;
    }

    /// One round: the wants, fetched, tallied by table.
    pub fn round(&mut self) -> bool {
        let wants = self.store.take_wanted(self.hint.merge);
        if wants.is_empty() {
            return false;
        }
        let got = self.driver.fetch(&wants);
        for (w, g) in wants.iter().zip(got) {
            if let Ok(Some(v)) = &g {
                let name = match self.rels.get(w.rel()) {
                    Some(t) => history_table_name(*t),
                    None if w.rel().starts_with("blobs/") => "blobs",
                    None => "files",
                };
                *self.tally.entry(name).or_default() += v.len() as u64;
            }
            self.store.supply(w, g);
        }
        true
    }

    pub fn cost(&self) -> HistoryCost {
        let (requests, bytes, rounds) = self.store.cost();
        HistoryCost {
            requests,
            bytes,
            rounds,
            table_bytes: self.tally.clone(),
            headers_verified: self.headers.len().saturating_sub(self.headers_at_begin) as u64,
            blocks_verified: self.blocks_verified,
        }
    }

    fn run<T>(
        &mut self,
        mut f: impl FnMut(&mut Self) -> Result<HRead<T>, Pending>,
    ) -> (HRead<T>, HistoryCost) {
        self.begin_read();
        loop {
            match f(self) {
                Ok(v) => return (v, self.cost()),
                Err(Pending) => {
                    if self.store.cost().2 >= self.max_rounds || !self.round() {
                        return (Err(Insufficient::Budget), self.cost());
                    }
                }
            }
        }
    }

    /// The transaction with hash `hash` and its receipt.
    pub fn tx(&mut self, hash: &B256) -> (HRead<TxReceipt>, HistoryCost) {
        let h = *hash;
        self.run(|s| s.try_tx(&h))
    }

    /// The header of block `number`, by the `parentHash` route from the
    /// anchor.
    pub fn header(&mut self, number: u64) -> (HRead<HeaderFields>, HistoryCost) {
        self.run(|s| s.try_header(number))
    }

    /// Every log carrying `term` in blocks `from..=to`, in `tier`.
    pub fn logs(
        &mut self,
        term: &Term,
        from: u64,
        to: u64,
        tier: LogTier,
    ) -> (HRead<Logs>, HistoryCost) {
        let t = *term;
        self.run(|s| s.try_logs(&t, from, to, tier))
    }

    pub fn try_header(&mut self, number: u64) -> Result<HRead<HeaderFields>, Pending> {
        if let Err(e) = self.try_headers(number)? {
            return Ok(Err(e));
        }
        Ok(Ok(self.headers[&number].clone()))
    }

    pub fn try_tx(&mut self, hash: &B256) -> Result<HRead<TxReceipt>, Pending> {
        // The hint, in every period's run at once.
        let key = tx_lookup_key(hash);
        let mut rows = Vec::new();
        let mut pending = false;
        for pi in 0..self.manifest.periods.len() {
            match self.scan(pi, H_TX_LOOKUP, &key, &key) {
                Err(Pending) => pending = true,
                Ok(Err(e)) => return Ok(Err(e)),
                Ok(Ok(es)) => rows.extend(es),
            }
        }
        if pending {
            return Err(Pending);
        }
        let mut candidates = Vec::new();
        for e in rows {
            if e.tag != 0 {
                return Ok(Err(Insufficient::Hint(
                    "tx_lookup row is not an inline value".into(),
                )));
            }
            match parse_locator(&e.value) {
                Some(l) => candidates.push(l),
                None => {
                    return Ok(Err(Insufficient::Hint(
                        "tx_lookup row is not a locator".into(),
                    )));
                }
            }
        }
        let Some(&(block, index)) = candidates.first() else {
            return Ok(Err(Insufficient::NotIndexed));
        };
        if candidates.len() > 1 {
            return Ok(Err(Insufficient::Hint(
                "tx_lookup has two rows for one hash".into(),
            )));
        }
        if !self.in_span(block) {
            return Ok(Err(Insufficient::Hint(format!(
                "tx_lookup names block {block}, outside the span"
            ))));
        }

        // The block: headers down to it, its transactions and receipts, in
        // one round.
        let hs = self.try_headers(block);
        let txs = self.try_leaves(block, H_TRANSACTIONS);
        let rs = self.try_leaves(block, H_RECEIPTS);
        let (hs, txs, rs) = (hs?, txs?, rs?);
        if let Err(e) = hs {
            return Ok(Err(e));
        }
        let (txs, rs) = match (txs, rs) {
            (Ok(t), Ok(r)) => (t, r),
            (Err(e), _) | (_, Err(e)) => return Ok(Err(e)),
        };
        let h = self.headers[&block].clone();
        if let Err(e) = verify_leaves(&h, &txs, &rs) {
            return Ok(Err(e));
        }
        self.blocks_verified += 1;
        let Some(tx) = txs.get(index as usize) else {
            return Ok(Err(Insufficient::Hint(format!(
                "tx_lookup names index {index} of a block with {}",
                txs.len()
            ))));
        };
        if tx_hash(tx) != *hash {
            return Ok(Err(Insufficient::Hint(
                "tx_lookup routed to a transaction with another hash".into(),
            )));
        }
        let leaf = rs[index as usize].clone();
        let receipt = match decode_receipt(&leaf) {
            Ok(r) => r,
            Err(what) => return Ok(Err(Insufficient::Value { block, what })),
        };
        Ok(Ok(TxReceipt {
            block_number: block,
            block_hash: h.hash,
            index,
            tx_hash: *hash,
            tx: tx.clone(),
            receipt_leaf: leaf,
            receipt,
            block_receipt_bytes: rs.iter().map(|r| r.len() as u64).sum(),
            block_tx_bytes: txs.iter().map(|t| t.len() as u64).sum(),
        }))
    }

    pub fn try_logs(
        &mut self,
        term: &Term,
        from: u64,
        to: u64,
        tier: LogTier,
    ) -> Result<HRead<Logs>, Pending> {
        if from > to {
            return Ok(Err(Insufficient::OutOfSpan { block: from }));
        }
        for b in [from, to] {
            if !self.in_span(b) {
                return Ok(Err(Insufficient::OutOfSpan { block: b }));
            }
        }
        // Which blocks to fetch.
        let blocks: Vec<u64> = match tier {
            LogTier::Indexed => {
                let th = term.hash();
                let mut named = BTreeSet::new();
                let mut pending = false;
                for pi in 0..self.manifest.periods.len() {
                    let p = &self.manifest.periods[pi];
                    let (a, b) = (from.max(p.first_block), to.min(p.last_block));
                    if a > b {
                        continue;
                    }
                    let lo = log_lookup_key(&th, a);
                    let mut hi = log_lookup_key(&th, b);
                    hi[8..].fill(0xff);
                    let mut lo0 = lo;
                    lo0[8..].fill(0);
                    match self.scan(pi, H_LOG_LOOKUP, &lo0, &hi) {
                        Err(Pending) => pending = true,
                        Ok(Err(e)) => return Ok(Err(e)),
                        Ok(Ok(es)) => {
                            for e in es {
                                if let Some(n) = log_lookup_block(&th, &e.key) {
                                    if (from..=to).contains(&n) {
                                        named.insert(n);
                                    }
                                }
                            }
                        }
                    }
                }
                if pending {
                    return Err(Pending);
                }
                named.into_iter().collect()
            }
            LogTier::Complete => {
                if let Err(e) = self.try_headers(from)? {
                    return Ok(Err(e));
                }
                (from..=to)
                    .filter(|n| term.in_bloom(&self.headers[n].logs_bloom))
                    .collect()
            }
        };

        // Their headers and receipts, in one round.
        let low = blocks.first().copied().unwrap_or(to);
        let hs = self.try_headers(low);
        let mut leaves = Vec::with_capacity(blocks.len());
        let mut pending = false;
        for &b in &blocks {
            match self.try_leaves(b, H_RECEIPTS) {
                Err(Pending) => pending = true,
                Ok(r) => leaves.push(r),
            }
        }
        let hs = hs?;
        if pending {
            return Err(Pending);
        }
        if let Err(e) = hs {
            return Ok(Err(e));
        }
        let mut logs = Vec::new();
        let mut without = 0u64;
        for (&b, rs) in blocks.iter().zip(leaves) {
            let rs = match rs {
                Ok(rs) => rs,
                Err(e) => return Ok(Err(e)),
            };
            let h = self.headers[&b].clone();
            if ordered_root(&rs) != h.receipts_root {
                return Ok(Err(Insufficient::Block {
                    block: b,
                    what: "receipts do not rebuild receiptsRoot".into(),
                }));
            }
            self.blocks_verified += 1;
            let mut log_index = 0u64;
            let mut found = false;
            for (i, leaf) in rs.iter().enumerate() {
                let r = match decode_receipt(leaf) {
                    Ok(r) => r,
                    Err(what) => return Ok(Err(Insufficient::Value { block: b, what })),
                };
                for l in r.logs {
                    if term.matches(&l) {
                        found = true;
                        logs.push(LogAt {
                            block_number: b,
                            tx_index: i as u64,
                            log_index,
                            block_hash: h.hash,
                            log: l,
                        });
                    }
                    log_index += 1;
                }
            }
            if !found {
                without += 1;
            }
        }
        Ok(Ok(Logs {
            tier,
            from,
            to,
            logs,
            blocks_fetched: blocks.len() as u64,
            blocks_without_match: without,
        }))
    }

    fn in_span(&self, block: u64) -> bool {
        (self.manifest.first_block..=self.manifest.block_number).contains(&block)
    }

    /// Verified headers from `from` up to the anchor, into the session's
    /// chain. One scan per period below what the chain already holds.
    fn try_headers(&mut self, from: u64) -> Result<HRead<()>, Pending> {
        if !self.in_span(from) {
            return Ok(Err(Insufficient::OutOfSpan { block: from }));
        }
        let top = match self.headers.keys().next() {
            Some(&low) if low <= from => return Ok(Ok(())),
            Some(&low) => low - 1,
            None => self.anchor.number,
        };
        let mut entries = Vec::new();
        let mut pending = false;
        for pi in 0..self.manifest.periods.len() {
            let p = &self.manifest.periods[pi];
            let (a, b) = (from.max(p.first_block), top.min(p.last_block));
            if a > b {
                continue;
            }
            let lo = block_key(a, 0);
            let hi = block_key(b, 0);
            match self.scan(pi, H_HEADERS, &lo, &hi) {
                Err(Pending) => pending = true,
                Ok(Err(e)) => return Ok(Err(e)),
                Ok(Ok(es)) => entries.extend(es),
            }
        }
        if pending {
            return Err(Pending);
        }
        let values = match self.resolve(&entries)? {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        let by_block: HashMap<[u8; 32], &Vec<u8>> =
            entries.iter().map(|e| e.key).zip(values.iter()).collect();
        let mut expect = match self.headers.get(&(top + 1)) {
            Some(h) => h.parent_hash,
            None => self.anchor.hash,
        };
        let mut verified = Vec::new();
        for n in (from..=top).rev() {
            let Some(rlp) = by_block.get(&block_key(n, 0)) else {
                return Ok(Err(Insufficient::Header {
                    block: n,
                    what: "not served".into(),
                }));
            };
            let h = match decode_header(rlp) {
                Ok(h) => h,
                Err(w) => {
                    return Ok(Err(Insufficient::Header {
                        block: n,
                        what: w.into(),
                    }));
                }
            };
            if h.hash != expect {
                return Ok(Err(Insufficient::Header {
                    block: n,
                    what: format!("hashes to {}, the chain expects {expect}", h.hash),
                }));
            }
            if h.number != n {
                return Ok(Err(Insufficient::Header {
                    block: n,
                    what: format!("carries number {}", h.number),
                }));
            }
            expect = h.parent_hash;
            verified.push(h);
        }
        for h in verified {
            self.headers.insert(h.number, h);
        }
        Ok(Ok(()))
    }

    /// Every leaf of `block` in `table` (transactions or receipts), blobs
    /// resolved, in index order. Unverified: the caller rebuilds the root.
    fn try_leaves(&mut self, block: u64, table: u16) -> Result<HRead<Vec<Vec<u8>>>, Pending> {
        let Some(pi) = self.manifest.period_of(block) else {
            return Ok(Err(Insufficient::OutOfSpan { block }));
        };
        let es = match self.scan(
            pi,
            table,
            &block_key(block, 0),
            &block_key(block, MAX_INDEX),
        )? {
            Ok(es) => es,
            Err(e) => return Ok(Err(e)),
        };
        for (i, e) in es.iter().enumerate() {
            if e.key != block_key(block, i as u64) {
                return Ok(Err(Insufficient::Block {
                    block,
                    what: format!("{} entries are not indices 0..n", history_table_name(table)),
                }));
            }
        }
        self.resolve(&es)
    }

    /// Entry values with blob entries fetched and checked against their
    /// names; every missing blob is wanted before `Pending`.
    fn resolve(&mut self, es: &[Entry]) -> Result<HRead<Vec<Vec<u8>>>, Pending> {
        let mut out = Vec::with_capacity(es.len());
        let mut pending = false;
        for e in es {
            match e.tag {
                0 => out.push(e.value.clone()),
                2 => {
                    let Ok(h) = <[u8; 32]>::try_from(e.value.as_slice()) else {
                        return Ok(Err(Insufficient::Blob("blob entry without a hash".into())));
                    };
                    match self.store.file(&blob_path(&h)) {
                        Err(Pending) => pending = true,
                        Ok(Ok(Some(v))) if *blake3::hash(&v).as_bytes() == h => out.push(v),
                        Ok(Ok(Some(_))) => {
                            return Ok(Err(Insufficient::Blob(format!(
                                "{} does not hash to its name",
                                hex::encode(h)
                            ))));
                        }
                        Ok(Ok(None)) => {
                            return Ok(Err(Insufficient::Blob(format!(
                                "{} not found",
                                hex::encode(h)
                            ))));
                        }
                        Ok(Err(e)) => return Ok(Err(Insufficient::Blob(e))),
                    }
                }
                _ => return Ok(Err(Insufficient::Blob("tombstone in a history run".into()))),
            }
        }
        if pending {
            return Err(Pending);
        }
        Ok(Ok(out))
    }

    /// The entries of `table` in period `pi` with keys in `lo..=hi`, from
    /// the store. The pages the model predicts for both ends, and every
    /// page between, are wanted at once (widened by the hint); a page the
    /// prediction missed is wanted with its `ε + 1` neighbourhood, so a
    /// miss costs one more round, not one per page. Fences route; nothing
    /// here is evidence, and an entry the run omits is caught by the root
    /// or the chain it fails to rebuild.
    fn scan(
        &mut self,
        pi: usize,
        table: u16,
        lo: &[u8; 32],
        hi: &[u8; 32],
    ) -> Result<HRead<Vec<Entry>>, Pending> {
        let h = self.hint;
        let store = self.store.clone();
        let broken = |e: String| Insufficient::Run { table, error: e };
        let r = match self.readers[pi][table_slot(table)].as_mut() {
            None => return Ok(Ok(Vec::new())),
            Some(Err(e)) => return Ok(Err(broken(e.clone()))),
            Some(Ok(r)) => r,
        };
        let Some(layout) = r.layout().copied() else {
            return Ok(Err(broken("no valid run layout".into())));
        };
        let pc = layout.page_count;
        let eps = u64::from(r.run_ref().epsilon_pages);
        let rel = history_run_path(&r.run_ref().root);
        let rec = layout.record_bytes;
        let want = |a: u64, b: u64| {
            let (a, b) = (a.max(1), b.min(pc));
            if a <= b {
                store.want_range(&rel, layout.record_off(a), ((b - a + 1) * rec) as usize);
            }
        };
        let predict = |r: &mut Reader<RunView>, k: &[u8; 32]| r.predict_page(csl_run::k64(k));
        let (p_lo, p_hi) = match (predict(r, lo), predict(r, hi)) {
            (Ok(a), Ok(b)) => (a.clamp(1, pc), b.clamp(1, pc).max(a.clamp(1, pc))),
            (Err(e), _) | (_, Err(e)) => return Ok(Err(broken(e.to_string()))),
        };
        let held = |p: u64| store.holds_range(&rel, layout.record_off(p), rec as usize);
        let first_try = !held(p_lo);
        want(p_lo.saturating_sub(h.below), p_hi + h.above);
        let start = match r.locate(lo) {
            Ok((p, _, _)) => p,
            Err(e) if is_pending(&e) => {
                if !first_try {
                    want(p_lo.saturating_sub(eps + 1), p_lo + eps + 1);
                }
                return Err(Pending);
            }
            Err(e) => return Ok(Err(broken(e.to_string()))),
        };
        let mut out = Vec::new();
        let mut q = start;
        loop {
            if !held(q) {
                want(q, q.max(p_hi) + eps + 1);
                return Err(Pending);
            }
            let page = match r.fetch_page(q) {
                Ok(p) => p,
                Err(e) if is_pending(&e) => return Err(Pending),
                Err(e) => return Ok(Err(broken(e.to_string()))),
            };
            for e in &page.entries {
                if e.key >= *lo && e.key <= *hi {
                    out.push(e.clone());
                }
            }
            if q >= pc || *hi < page.hi {
                break;
            }
            q += 1;
        }
        Ok(Ok(out))
    }
}

/// A block's transactions and receipts against its header.
fn verify_leaves(h: &HeaderFields, txs: &[Vec<u8>], rs: &[Vec<u8>]) -> HRead<()> {
    let block = h.number;
    if ordered_root(txs) != h.transactions_root {
        return Err(Insufficient::Block {
            block,
            what: "transactions do not rebuild transactionsRoot".into(),
        });
    }
    if ordered_root(rs) != h.receipts_root {
        return Err(Insufficient::Block {
            block,
            what: "receipts do not rebuild receiptsRoot".into(),
        });
    }
    if txs.len() != rs.len() {
        return Err(Insufficient::Block {
            block,
            what: format!("{} transactions, {} receipts", txs.len(), rs.len()),
        });
    }
    Ok(())
}

#[derive(Debug)]
pub enum HistoryOpenError {
    Head(HeadError),
    Open(String),
}

impl fmt::Display for HistoryOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HistoryOpenError::Head(e) => write!(f, "head: {e}"),
            HistoryOpenError::Open(e) => write!(f, "history: {e}"),
        }
    }
}

impl std::error::Error for HistoryOpenError {}

/// Verify the finalized head from the bucket's head files and open the
/// history span that ends at its block.
pub fn open_history_at_head<D: Driver>(
    driver: D,
    checkpoint: B256,
    now: SystemTime,
) -> Result<(History<D>, VerifiedHead), HistoryOpenError> {
    let head = verify_head(&driver, checkpoint, now).map_err(HistoryOpenError::Head)?;
    let h = History::open(driver, Anchor::from(&head)).map_err(HistoryOpenError::Open)?;
    Ok((h, head))
}
