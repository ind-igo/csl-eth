//! What a read costs on a published layered snapshot, with and without the
//! layers' hints (and with the hints but no owner index), against the plain
//! base: requests, bytes, rounds, layer runs asked, and the requests each run
//! took.
//!
//!   cargo run --release --features http -p csl-eth-client --example layer_cost -- \
//!       https://storage.googleapis.com/csl-eth-demo/full 0x<block hash> 0x<state root> \
//!       0x<base hash> 0x<base state root>
use alloy_primitives::{address, keccak256, Address, B256, U256};
use csl_eth_client::{http::HttpDriver, Cost, Driver, Read, Snapshot, Want};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    rc::Rc,
};

type Log = Rc<RefCell<BTreeMap<String, u64>>>;

struct Probe {
    inner: HttpDriver,
    hints: bool,
    owners: bool,
    log: Log,
}

impl Driver for Probe {
    fn fetch(&self, wants: &[Want]) -> Vec<csl_eth_client::Got> {
        let mut out = Vec::with_capacity(wants.len());
        let mut pass = Vec::new();
        let mut at = Vec::new();
        for (i, w) in wants.iter().enumerate() {
            let rel = match w {
                Want::File { rel } | Want::Range { rel, .. } => rel.clone(),
            };
            if (!self.hints && rel.ends_with(".hints"))
                || (!self.owners && rel.ends_with(".owners"))
            {
                out.push((i, Ok(None)));
                continue;
            }
            *self.log.borrow_mut().entry(rel).or_default() += 1;
            pass.push(w.clone());
            at.push(i);
        }
        for (i, g) in at.into_iter().zip(self.inner.fetch(&pass)) {
            out.push((i, g));
        }
        out.sort_by_key(|(i, _)| *i);
        out.into_iter().map(|(_, g)| g).collect()
    }
}

enum Key {
    Account(Address),
    Slot(Address, U256),
}

fn read(snap: &mut Snapshot<Probe>, k: &Key) -> (String, Cost) {
    match k {
        Key::Account(a) => {
            let (r, c) = snap.account(&keccak256(a));
            (short(&r), c)
        }
        Key::Slot(a, s) => {
            let (r, c) = snap.storage(&keccak256(a), &keccak256(B256::from(*s)));
            (short(&r), c)
        }
    }
}

fn short<T: std::fmt::Debug>(r: &Read<T>) -> String {
    match r {
        Read::Verified(_) => "verified".into(),
        other => format!("{other:?}").chars().take(60).collect(),
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let url = &a[1];
    let at: B256 = a[2].parse().unwrap();
    let root: B256 = a[3].parse().unwrap();
    let base: B256 = a[4].parse().unwrap();
    let base_root: B256 = a[5].parse().unwrap();
    let keys = [
        ("vitalik.eth account", Key::Account(address!("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045"))),
        ("absent account", Key::Account(address!("00000000000000000000000000000000c0ffee01"))),
        ("USDT slot 1", Key::Slot(address!("dAC17F958D2ee523a2206206994597C13D831ec7"), U256::from(1))),
        ("WETH slot 0", Key::Slot(address!("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"), U256::from(0))),
        ("The DAO slot 0", Key::Slot(address!("BB9bC244D798123fDe783fCc1C72d3Bb8C189413"), U256::from(0))),
        ("CryptoPunks slot 0", Key::Slot(address!("b47e3cd837dDF8e4c57F05d70Ab865de6e193BBB"), U256::from(0))),
        // Quiet: no storage change since the base when this was written.
        ("Uniswap v1 slot 0", Key::Slot(address!("c0a47dFe034B400B8bDDf2D2EA1D6F8f0dB8fBc1"), U256::from(0))),
        ("REP v1 slot 0", Key::Slot(address!("E94327D07Fc17907b4DB788E5aDf2ed424adDff6"), U256::from(0))),
    ];
    let runs_named = |log: &Log| -> String {
        let l = log.borrow();
        l.iter()
            .filter(|(r, _)| r.ends_with(".run"))
            .map(|(r, n)| format!("{}:{n}", &r[5..13]))
            .collect::<Vec<_>>()
            .join(" ")
    };
    for (name, k) in &keys {
        for (mode, hash, sroot, hints, owners) in [
            ("base only", base, base_root, true, true),
            ("hinted", at, root, true, true),
            ("no index", at, root, true, false),
            ("unhinted", at, root, false, false),
        ] {
            let log: Log = Default::default();
            let d = Probe { inner: HttpDriver::new(url, None).unwrap(), hints, owners, log: log.clone() };
            let mut snap = Snapshot::open(d, Some(hash), sroot).unwrap();
            log.borrow_mut().clear();
            let (r, c) = read(&mut snap, k);
            println!(
                "{name:20} {mode:9} {r:9} req {:3} bytes {:7} rounds {} layers {} nodes {:2} | {}",
                c.requests, c.bytes, c.rounds, c.layers, c.nodes, runs_named(&log)
            );
        }
    }
}
