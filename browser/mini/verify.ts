// The minimal light client's whole trust path, in one file.
//
// Everything here is a pure function over bytes already held. A function
// that needs bytes it does not hold records the byte range in `Held.wants`
// and throws `Pending`; the driver (driver.ts) fetches every wanted range in
// one round, adds the bytes, and calls `read` again from the top. Nothing in
// this file does I/O, and nothing it returns rests on anything but:
//
//   1. the checkpoint below, a beacon block root the reader trusts;
//   2. BLS signatures by two thirds of the sync committee, whose members the
//      checkpoint's state names, period after period (bootstrap, updates);
//   3. Merkle branches from a signed beacon header to the execution block's
//      state root;
//   4. keccak hashes from that state root down the Merkle-Patricia trie to
//      the account, the storage slot, or the code.
//
// The bucket's index files (manifest, models, pages) are only a way to find
// trie nodes. A wrong index can make a read fail; it cannot make one lie,
// because every node is taken only if it hashes to its parent's reference,
// and absence is decided by the trie's shape, never by a missing file.
//
// Mirrors the Rust client (crates/head, crates/csl-run, crates/trie,
// crates/client) for the current mainnet fork only. Left out: hints, the
// owner index, the by-hash baseline, the finalized tier, checkpoint rotation,
// history, tracing and every fork but fulu.

import { bls12_381 } from "@noble/curves/bls12-381.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

// ---------------------------------------------------------------- trust

/** The one trust input: a finalized beacon block root (slot 15,661,216). */
export const CHECKPOINT = "0x431b33af8452e2d644377405e69d4f382182ab906f31461190ca24cb3401d70b";

const GENESIS_TIME = 1_606_824_023;
const GENESIS_VALIDATORS_ROOT = "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95";
const FULU_EPOCH = 411_392;
const FULU_VERSION = Uint8Array.of(6, 0, 0, 0);
const SLOTS_PER_PERIOD = 8192; // 32 slots an epoch, 256 epochs a period
const COMMITTEE = 512;
const BLS_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
// Generalized indices since electra: (depth, index within that depth).
const CURRENT_COMMITTEE = [6, 22] as const; // 86 in the beacon state
const NEXT_COMMITTEE = [6, 23] as const; // 87 in the beacon state
const EXECUTION_PAYLOAD = [4, 9] as const; // 25 in the block body

// ---------------------------------------------------------------- bytes

/** Every failure is a refusal: the read returns nothing. */
export class Refused extends Error {}
const refuse = (why: string): never => {
  throw new Refused(why);
};

export const hex = (b: Uint8Array) => "0x" + Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

export function unhex(s: string, len?: number): Uint8Array {
  const h = s.startsWith("0x") ? s.slice(2) : s;
  if (h.length % 2 || !/^[0-9a-fA-F]*$/.test(h)) refuse(`not hex: ${s.slice(0, 20)}`);
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  if (len !== undefined && out.length !== len) refuse(`expected ${len} bytes, got ${out.length}`);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) out.set(p, (o += p.length) - p.length);
  return out;
}

export const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Lexicographic order, as Rust orders `[u8; 32]`. */
function cmp(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i]! - b[i]!;
  return a.length - b.length;
}

export const keccak = (b: Uint8Array) => keccak_256(b);
const ZERO32 = new Uint8Array(32);
/** keccak(rlp("")): the root of an empty trie. */
export const EMPTY_ROOT = unhex("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");
/** keccak(""): the code hash of an account without code. */
export const KECCAK_EMPTY = unhex("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

const dv = (b: Uint8Array) => new DataView(b.buffer, b.byteOffset, b.byteLength);
const u16 = (b: Uint8Array, o: number) => dv(b).getUint16(o, true);
const u32 = (b: Uint8Array, o: number) => dv(b).getUint32(o, true);
const u64 = (b: Uint8Array, o: number) => dv(b).getBigUint64(o, true);
const i64 = (b: Uint8Array, o: number) => dv(b).getBigInt64(o, true);

/** Little-endian, zero-padded to `len` bytes (an SSZ uint chunk). */
function le(n: bigint, len = 32): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len && n > 0n; i++, n >>= 8n) out[i] = Number(n & 0xffn);
  return out;
}

// ---------------------------------------------------------------- held bytes

/** A byte range of a file under the bucket's base URL; no `off` means the whole file. */
export type Want = {
  path: string;
  off?: number;
  len?: number;
  /** For a run's data page: which table and run (the tamper demo picks by this). */
  run?: { table: number; index: number; of: number; pages: number };
};

/** Thrown when bytes are missing; `Held.wants` then lists everything this pass found missing. */
export class Pending extends Error {}
const PENDING = new Pending("pending");

export class Held {
  readonly bytes = new Map<string, Uint8Array>();
  readonly wants = new Map<string, Want>();
  readonly memo = new Map<string, unknown>();
  /** Wants whose fetch failed: a refusal for whoever needs them, so another run can still answer. */
  readonly failed = new Map<string, string>();
  static id = (w: Want) => (w.off === undefined ? w.path : `${w.path}@${w.off}+${w.len}`);
  /** The bytes if held, else noted as wanted. */
  get(w: Want): Uint8Array | undefined {
    const b = this.bytes.get(Held.id(w));
    const f = this.failed.get(Held.id(w));
    if (f !== undefined) refuse(f);
    if (!b) this.wants.set(Held.id(w), w);
    return b;
  }
  need(w: Want): Uint8Array {
    const b = this.get(w);
    if (!b) throw PENDING;
    return b;
  }
  put(w: Want, b: Uint8Array) {
    this.bytes.set(Held.id(w), b);
  }
  fail(w: Want, why: string) {
    this.failed.set(Held.id(w), why);
  }
  once<T>(key: string, f: () => T): T {
    if (!this.memo.has(key)) this.memo.set(key, f());
    return this.memo.get(key) as T;
  }
}

/** Run `f` only for the wants it notes: missing bytes and refusals both wait for the real attempt. */
function soft(f: () => unknown) {
  try {
    f();
  } catch (e) {
    if (!(e instanceof Pending || e instanceof Refused)) throw e;
  }
}

/** Run `f` on every item, so all their wants land in one round; then rethrow a `Pending`. */
function each<T, R>(xs: T[], f: (x: T) => R): R[] {
  let pending = false;
  const out = xs.map((x) => {
    try {
      return f(x);
    } catch (e) {
      if (e instanceof Pending) return (pending = true), undefined as R;
      throw e;
    }
  });
  if (pending) throw PENDING;
  return out;
}

// ---------------------------------------------------------------- SSZ

const H = (a: Uint8Array, b: Uint8Array) => sha256(concat(a, b));

/** hash_tree_root of `chunks`, padded with zero chunks to a power of two ≥ `limit`. */
export function merkleize(chunks: Uint8Array[], limit = chunks.length): Uint8Array {
  let width = 1;
  while (width < Math.max(limit, chunks.length)) width *= 2;
  let layer = [...chunks];
  while (layer.length < width) layer.push(ZERO32);
  while (layer.length > 1) layer = Array.from({ length: layer.length / 2 }, (_, i) => H(layer[2 * i]!, layer[2 * i + 1]!));
  return layer[0]!;
}

/** Bytes split into 32-byte chunks, the last zero-padded. */
function chunks(b: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let i = 0; i < b.length; i += 32) out.push(concat(b.subarray(i, i + 32), ZERO32).subarray(0, 32));
  return out.length ? out : [ZERO32];
}

/** is_valid_merkle_branch. */
function branchOk(leaf: Uint8Array, branch: Uint8Array[], [depth, index]: readonly [number, number], root: Uint8Array): boolean {
  if (branch.length !== depth) return false;
  let v = leaf;
  for (let i = 0; i < depth; i++) v = (index >> i) & 1 ? H(branch[i]!, v) : H(v, branch[i]!);
  return eq(v, root);
}

// JSON fields of the beacon API's objects, checked as they are read.
type J = any; // eslint-disable-line @typescript-eslint/no-explicit-any
function str(x: unknown, what: string): string {
  return typeof x === "string" ? x : refuse(`${what}: missing`);
}
function uint(x: unknown, what: string, bits = 64): bigint {
  if (typeof x === "number" && Number.isSafeInteger(x) && x >= 0) return BigInt(x); // the manifest's JSON numbers
  const s = str(x, what);
  if (!/^(0|[1-9][0-9]*)$/.test(s) || BigInt(s) >> BigInt(bits)) refuse(`${what}: not a u${bits}`);
  return BigInt(s);
}
const num = (x: unknown, what: string) => Number(uint(x, what, 53));
const fixed = (x: unknown, n: number, what: string) => unhex(str(x, what), n);
const b32 = (x: unknown, what: string) => fixed(x, 32, what);
const list = (x: unknown, what: string): unknown[] => (Array.isArray(x) ? x : refuse(`${what}: not a list`));

/** BeaconBlockHeader. */
export function beaconRoot(b: J): Uint8Array {
  return merkleize([le(uint(b?.slot, "slot")), le(uint(b?.proposer_index, "proposer_index")), b32(b?.parent_root, "parent_root"), b32(b?.state_root, "state_root"), b32(b?.body_root, "body_root")]);
}

/** ExecutionPayloadHeader (deneb's layout, unchanged through fulu). */
export function executionRoot(e: J): Uint8Array {
  const extra = unhex(str(e?.extra_data, "extra_data"));
  if (extra.length > 32) refuse("extra_data longer than 32 bytes");
  const u = (k: string) => le(uint(e?.[k], k));
  const r = (k: string) => b32(e?.[k], k);
  return merkleize([
    r("parent_hash"),
    chunks(fixed(e?.fee_recipient, 20, "fee_recipient"))[0]!,
    r("state_root"),
    r("receipts_root"),
    merkleize(chunks(fixed(e?.logs_bloom, 256, "logs_bloom"))),
    r("prev_randao"),
    u("block_number"),
    u("gas_limit"),
    u("gas_used"),
    u("timestamp"),
    H(chunks(extra)[0]!, le(BigInt(extra.length))), // ByteList[32]: one chunk, length mixed in
    le(uint(e?.base_fee_per_gas, "base_fee_per_gas", 256)),
    r("block_hash"),
    r("transactions_root"),
    r("withdrawals_root"),
    u("blob_gas_used"),
    u("excess_blob_gas"),
  ]);
}

/** A sync committee's 512 public keys, and its hash_tree_root. */
function committee(c: J, what: string): { keys: Uint8Array[]; root: Uint8Array } {
  const keys = list(c?.pubkeys, `${what} pubkeys`).map((k) => fixed(k, 48, `${what} pubkey`));
  if (keys.length !== COMMITTEE) refuse(`${what}: ${keys.length} members, not ${COMMITTEE}`);
  const keyRoot = (k: Uint8Array) => merkleize(chunks(k));
  const agg = fixed(c?.aggregate_pubkey, 48, `${what} aggregate_pubkey`);
  return { keys, root: H(merkleize(keys.map(keyRoot)), keyRoot(agg)) };
}

const branch = (x: unknown, what: string) => list(x, what).map((h) => b32(h, what));
const period = (slot: number) => Math.floor(slot / SLOTS_PER_PERIOD);

// ---------------------------------------------------------------- head

export type Head = {
  checkpointSlot: number;
  updates: number;
  slot: number;
  signatureSlot: number;
  participants: number;
  block: number;
  blockHash: Uint8Array;
  stateRoot: Uint8Array;
  timestamp: number;
};

/** A head file: the beacon API's JSON, `{version, data}`. Only fulu is read. */
function envelope(b: Uint8Array, what: string): J {
  let v: J;
  try {
    v = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(b));
  } catch {
    return refuse(`${what}: not JSON`);
  }
  if (v?.version !== "fulu") refuse(`${what} is a "${v?.version}" object; this verifier knows only fulu`);
  return v.data;
}

/**
 * The sync committee's signature over `u.attested_header`: at least two
 * thirds of `keys` signed, and the aggregate verifies. Returns the signers.
 */
function signed(u: J, keys: Uint8Array[] | undefined, what: string, nowSlot: number): number {
  const sigSlot = num(u?.signature_slot, `${what} signature_slot`);
  if (sigSlot > nowSlot) refuse(`${what}: signed at slot ${sigSlot}, after the clock's ${nowSlot}`);
  if (!keys) return refuse(`${what}: no proven committee for period ${period(sigSlot)}`);
  if (Math.floor((Math.max(sigSlot, 1) - 1) / 32) < FULU_EPOCH) refuse(`${what}: signed before fulu, a fork this verifier does not know`);
  const bits = fixed(u?.sync_aggregate?.sync_committee_bits, COMMITTEE / 8, `${what} sync_committee_bits`);
  const signers = keys.filter((_, i) => (bits[i >> 3]! >> (i & 7)) & 1);
  if (signers.length * 3 < COMMITTEE * 2) refuse(`${what}: ${signers.length} of ${COMMITTEE} signed, under two thirds`);
  const attested = u?.attested_header?.beacon;
  if (sigSlot <= num(attested?.slot, `${what} attested slot`)) refuse(`${what}: signed before the slot it attests`);
  const forkData = H(concat(FULU_VERSION, new Uint8Array(28)), unhex(GENESIS_VALIDATORS_ROOT, 32));
  const domain = concat(Uint8Array.of(7, 0, 0, 0), forkData.subarray(0, 28)); // DOMAIN_SYNC_COMMITTEE
  const bls = bls12_381.longSignatures;
  let ok = false;
  try {
    const msg = bls.hash(H(beaconRoot(attested), domain), BLS_DST);
    ok = bls.verify(fixed(u?.sync_aggregate?.sync_committee_signature, 96, `${what} signature`), msg, bls.aggregatePublicKeys(signers));
  } catch (e) {
    if (e instanceof Refused) throw e;
  }
  if (!ok) refuse(`${what}: the sync committee's signature does not verify`);
  return signers.length;
}

/**
 * The attested head: bootstrap from the checkpoint, one update a period to
 * the period `head/optimistic` was signed in, then that update itself. `now`
 * is the reader's clock in ms, to refuse a stale head.
 */
export function verifyHead(h: Held, now: number): Head {
  return h.once("head", () => {
    const ob = h.get({ path: "head/optimistic" });
    const bb = h.get({ path: `head/bootstrap/${CHECKPOINT}` });
    if (!ob || !bb) throw PENDING;
    const opt = envelope(ob, "head/optimistic");
    const boot = envelope(bb, "bootstrap");

    const bootSlot = num(boot?.header?.beacon?.slot, "bootstrap slot");
    const sigSlot = num(opt?.signature_slot, "head/optimistic signature_slot");
    const [first, signedIn] = [period(bootSlot), period(sigSlot)];
    const nowSlot = Math.floor((now / 1000 - GENESIS_TIME) / 12);
    const current = period(nowSlot);
    if (signedIn > current) refuse(`head signed in period ${signedIn}, after the clock's ${current}`);
    if (signedIn + 1 < current) refuse(`stale head: signed in period ${signedIn}, the clock is in ${current}`);
    const periods = Array.from({ length: Math.max(signedIn - first, 0) }, (_, i) => first + i);
    const ups = periods.map((p) => h.get({ path: `head/updates/${p}` }));
    // Fetched now to save a round; checked against the head before use.
    soft(() => h.get({ path: manifestPath(b32(opt?.attested_header?.execution?.block_hash, "block_hash")) }));
    if (ups.some((u) => !u)) throw PENDING;

    // The checkpoint names the bootstrap header; its state names the committee.
    if (!eq(beaconRoot(boot.header.beacon), unhex(CHECKPOINT))) refuse("bootstrap header is not the checkpoint");
    const c0 = committee(boot.current_sync_committee, "bootstrap committee");
    if (!branchOk(c0.root, branch(boot.current_sync_committee_branch, "committee branch"), CURRENT_COMMITTEE, b32(boot.header.beacon.state_root, "state_root")))
      refuse("bootstrap committee is not in the checkpoint's state");
    const keys = new Map([[first, c0.keys]]);

    // Each period's committee signs a header whose state names the next one.
    periods.forEach((p, i) => {
      const u = envelope(ups[i]!, `update ${p}`);
      const what = `update ${p}`;
      if (period(num(u?.attested_header?.beacon?.slot, `${what} slot`)) !== p) refuse(`${what} attests a header of another period`);
      signed(u, keys.get(period(num(u.signature_slot, what))), what, nowSlot);
      const next = committee(u.next_sync_committee, `${what} next committee`);
      if (!branchOk(next.root, branch(u.next_sync_committee_branch, what), NEXT_COMMITTEE, b32(u.attested_header.beacon.state_root, what)))
        refuse(`${what}: next committee is not in the signed state`);
      keys.set(p + 1, next.keys);
    });

    // The head: signed by its period's committee, and its execution header
    // is in the signed block body.
    const participants = signed(opt, keys.get(signedIn), "head/optimistic", nowSlot);
    const beacon = opt.attested_header.beacon;
    const slot = num(beacon.slot, "head slot");
    if (slot === 0 || slot < bootSlot) refuse(`head slot ${slot} is before the checkpoint's ${bootSlot}`);
    const exec = opt.attested_header.execution;
    if (!branchOk(executionRoot(exec), branch(opt.attested_header.execution_branch, "execution branch"), EXECUTION_PAYLOAD, b32(beacon.body_root, "body_root")))
      refuse("execution header is not in the signed block");
    return {
      checkpointSlot: bootSlot,
      updates: periods.length,
      slot,
      signatureSlot: sigSlot,
      participants,
      block: num(exec.block_number, "block_number"),
      blockHash: b32(exec.block_hash, "block_hash"),
      stateRoot: b32(exec.state_root, "state_root"),
      timestamp: num(exec.timestamp, "timestamp"),
    };
  });
}

// ---------------------------------------------------------------- manifest

const PAGE = 4096;
const TABLE_FILES = ["account_nodes.run", "storage_nodes.run", "code.run"];
const [ACCOUNTS, STORAGE, CODE] = [0, 1, 2];
const D_ACCOUNT = 9; // depths asked for in the first round, as the Rust client
const D_STORAGE = 7;

type Ref = { root: Uint8Array; pages: number; eps: number; modelBytes: number; modelRoot: Uint8Array };
export type Run = { path: string; ref: Ref; table: number; index: number; of: number };

const manifestPath = (blockHash: Uint8Array) => `snapshots/${hex(blockHash).slice(2)}/manifest.json`;

/** Each table's runs, oldest first: the base snapshot, then its layers. */
function runs(h: Held, head: Head): Run[][] {
  return h.once("runs", () => {
    let m: J;
    try {
      m = JSON.parse(new TextDecoder().decode(h.need({ path: manifestPath(head.blockHash) })));
    } catch (e) {
      if (e instanceof Pending) throw e;
      return refuse("manifest: not JSON");
    }
    // Not evidence: the manifest only says where nodes are. These checks
    // match the Rust client's, so a mismatched snapshot fails early.
    if (!eq(b32(m?.block_hash, "manifest block_hash"), head.blockHash)) refuse("manifest names a different block");
    if (!eq(b32(m?.state_root, "manifest state_root"), head.stateRoot)) refuse("manifest claims a different state root");
    const layers = m.layers === undefined ? [] : list(m.layers, "layers");
    const layered = m.base != null || layers.length > 0;
    const base = m.base == null ? head.blockHash : b32(m.base, "base");
    const tid = (t: J) => num(t?.table_id, "table_id");
    const all = [m.tables, ...layers.map((l: J) => l?.tables)].flatMap((t) => list(t, "tables"));
    if (!(m.format_version === 2 && !layered) && !(m.format_version === 3 && m.base != null && !eq(base, head.blockHash) && all.every((t) => tid(t) !== 3)))
      refuse(`manifest format ${m.format_version}: this verifier reads 2 (plain) and 3 (layered)`);
    const ref = (t: J): Ref => {
      const pages = num(t.page_count, "page_count");
      if (pages < 1 || pages > 2 ** 31) refuse("page_count outside [1, 2^31]");
      const eps = num(t.epsilon_pages, "epsilon_pages");
      if (eps > 0xffff) refuse("epsilon_pages is a u16");
      return { root: b32(t.root, "root"), pages, eps, modelBytes: num(t.model_bytes, "model_bytes"), modelRoot: b32(t.model_root, "model_root") };
    };
    return TABLE_FILES.map((file, table) => {
      const out: Omit<Run, "index" | "of">[] = [];
      const t0 = list(m.tables, "tables").find((t: J) => tid(t) === table);
      if (t0) out.push({ path: `snapshots/${hex(base).slice(2)}/${file}`, ref: ref(t0), table });
      for (const l of layers) {
        const t = list((l as J).tables, "layer tables").find((t: J) => tid(t) === table);
        if (t) out.push({ path: `runs/${hex(ref(t).root).slice(2)}.run`, ref: ref(t), table });
      }
      return out.map((r, index) => ({ ...r, index, of: out.length }));
    });
  });
}

// ---------------------------------------------------------------- runs
//
// A run file: page 0 (header, top model), data pages 1..n of 4096 bytes,
// then the paged model. Keys are found by two learned-index steps: the top
// model on page 0 predicts a model page, that page's model predicts a data
// page, each within ε pages, with a walk and then binary search as fallback.

type Seg = { k: bigint; i: bigint; s: bigint };
type Model = { pages: bigint; eps: bigint; segs: Seg[] };

/** pgm::Model::predict: the last segment at or below `k`, capped by the next intercept + ε. */
function predict(m: Model, k: bigint): number {
  let i = 0;
  while (i < m.segs.length && m.segs[i]!.k <= k) i++;
  const s = m.segs[Math.max(i - 1, 0)]!;
  let p = s.i + (i === 0 ? 0n : ((k - s.k) * s.s) >> 64n);
  const next = m.segs[Math.max(i, 1)];
  if (next && next.i + m.eps < p) p = next.i + m.eps;
  return Number(p < 1n ? 1n : p > m.pages ? m.pages : p);
}

function segments(b: Uint8Array, o: number, n: number, pages: bigint, what: string): Seg[] {
  const segs: Seg[] = [];
  for (let j = 0; j < n; j++, o += 24) {
    const seg = { k: u64(b, o), i: i64(b, o + 8), s: u64(b, o + 16) };
    if (j && seg.k <= segs[j - 1]!.k) refuse(`${what}: segments unsorted`);
    if (seg.i < 1n || seg.i > pages) refuse(`${what}: intercept is not a page`);
    segs.push(seg);
  }
  return segs;
}

const zeroFrom = (b: Uint8Array, o: number) => b.subarray(o).every((x) => x === 0);
/** Depth of the blake3 page tree over `n` leaves. */
const treeDepth = (n: number) => (n <= 1 ? 0 : Math.ceil(Math.log2(n)));
const be32 = (n: number) => Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);

/** tree::verify_inline: a model page's blake3 path to the tree root on page 0. */
function inlineOk(leaves: number, pos: number, page: Uint8Array, proof: Uint8Array, root: Uint8Array): boolean {
  let v = blake3(concat(be32(pos), blake3(page)));
  let [p, size, next] = [pos, leaves, 0];
  while (size > 1) {
    if (p % 2 === 0 && p + 1 >= size) v = blake3(concat(v, v));
    else {
      if (next + 32 > proof.length) return false;
      const sib = proof.subarray(next, (next += 32));
      v = blake3(p % 2 === 0 ? concat(v, sib) : concat(sib, v));
    }
    p = Math.floor(p / 2);
    size = Math.ceil(size / 2);
  }
  return zeroFrom(proof, next) && eq(blake3(concat(be32(leaves), v)), root);
}

type Top = { modelPages: number; root: Uint8Array; model: Model };

/** Page 0: blake3 must be the manifest's `model_root`. */
function top(h: Held, r: Run): Top {
  return h.once(`top ${r.path}`, () => {
    const b = h.need({ path: r.path, off: 0, len: PAGE });
    if (b.length !== PAGE || !eq(blake3(b), r.ref.modelRoot)) refuse(`${r.path}: page 0 does not hash to the manifest's model root`);
    const modelPages = u32(b, 56);
    const n = u32(b, 94);
    if (modelPages === 0 || n === 0 || n > 166) refuse(`${r.path}: bad top model`);
    const t = { modelPages, root: b.slice(62, 94), model: { pages: BigInt(modelPages), eps: BigInt(u16(b, 60)), segs: segments(b, 98, n, BigInt(modelPages), r.path) } };
    if (!zeroFrom(b, 98 + 24 * n)) refuse(`${r.path}: page 0 padding`);
    if (modelPages * (PAGE + 32 * treeDepth(modelPages)) !== r.ref.modelBytes) refuse(`${r.path}: model size disagrees with the manifest`);
    return t;
  });
}

type ModelPage = { lo: bigint; hi: bigint; model: Model };

/** Model page `m` (1-based), checked against page 0's tree root; its routing model. */
function modelPage(h: Held, r: Run, m: number): ModelPage {
  const t = top(h, r);
  return h.once(`model ${r.path} ${m}`, () => {
    if (m < 1 || m > t.modelPages) refuse(`${r.path}: model page ${m} out of range`);
    const record = PAGE + 32 * treeDepth(t.modelPages);
    const rec = h.need({ path: r.path, off: (r.ref.pages + 1) * PAGE + (m - 1) * record, len: record });
    const b = rec.subarray(0, PAGE);
    if (rec.length !== record || !inlineOk(t.modelPages, m - 1, b, rec.subarray(PAGE), t.root)) refuse(`${r.path}: model page ${m} is not in the model tree`);
    const [n, lo, hi, nextI, last] = [u16(b, 0), u64(b, 2), u64(b, 10), i64(b, 18), m === t.modelPages];
    const pages = BigInt(r.ref.pages);
    if (n === 0 || n > 169 || (m === 1 && lo !== 0n) || (last ? hi !== 2n ** 64n - 1n : hi <= lo) || nextI < 1n || nextI > pages) refuse(`${r.path}: model page ${m} header`);
    const segs = segments(b, 26, n, pages, r.path);
    if (segs[0]!.k < lo || (!last && segs[n - 1]!.k >= hi) || !zeroFrom(b, 26 + 24 * n)) refuse(`${r.path}: model page ${m} body`);
    // Routing appends the next page's first segment, as a flat sentinel.
    return { lo, hi, model: { pages, eps: BigInt(r.ref.eps), segs: [...segs, { k: hi, i: nextI, s: 0n }] } };
  });
}

/**
 * Reader::locate's search: page `p` predicted, then up to ε+1 neighbours
 * in the key's direction, then binary search beyond them. `below(q)`:
 * the key is under page q's lower fence; `covers(q)`: page q holds its range.
 */
function search(p: number, count: number, eps: number, below: (q: number) => boolean, covers: (q: number) => boolean): number {
  if (covers(p)) return p;
  const down = below(p);
  const near = (step: number) => (down ? p - step : p + step);
  // Ask for the whole window at once (one round), then search it in order.
  for (let step = 1; step <= Math.min(eps + 1, count); step++) soft(() => near(step) >= 1 && near(step) <= count && covers(near(step)));
  for (let step = 1; step <= eps + 1; step++) {
    const q = down ? p - step : p + step;
    if (q < 1 || q > count) break;
    if (covers(q)) return q;
  }
  let [lo, hi] = down ? [1, p - eps - 2] : [p + eps + 2, count];
  while (lo >= 1 && hi <= count && lo <= hi) {
    const mid = lo + Math.floor((hi - lo) / 2);
    if (covers(mid)) return mid;
    if (below(mid)) hi = mid - 1;
    else lo = mid + 1;
  }
  return refuse("no page covers the key (fence gap)");
}

type Entry = { key: Uint8Array; tag: number; value: Uint8Array; at: number };
type Page = { lo: Uint8Array; hi: Uint8Array; entries: Entry[] };
const MAX_INLINE = PAGE - 66 - 2 - 32 - 1 - 2;
const KEY_MAX = new Uint8Array(32).fill(255);

/**
 * A data page, accepted only in its canonical encoding:
 * `n: u16 ‖ lo[32] ‖ hi[32] ‖ offsets: u16[n] ‖ entries ‖ zeros`, an entry
 * `key[32] ‖ tag ‖ body` (tag 0 `len: u16 ‖ value`, 1 empty, 2 a blob's
 * blake3, 3 a pack location).
 */
export function decodePage(b: Uint8Array, last: boolean): Page {
  const bad = (what: string): never => refuse(`malformed page: ${what}`);
  if (b.length !== PAGE) bad("length");
  const n = u16(b, 0);
  if (66 + 35 * n > PAGE) bad("entry count");
  const [lo, hi] = [b.slice(2, 34), b.slice(34, 66)];
  if (cmp(lo, hi) > 0 || (!last && eq(lo, hi)) || (last && !eq(hi, KEY_MAX))) bad("fences");
  const entries: Entry[] = [];
  let o = 66 + 2 * n;
  for (let i = 0; i < n; i++) {
    if (u16(b, 66 + 2 * i) !== o) bad("offsets");
    if (o + 33 > PAGE) bad("overflow");
    const key = b.slice(o, o + 32);
    const tag = b[o + 32]!;
    o += 33;
    let len = [-1, 0, 32, 44][tag] ?? bad("tag");
    if (tag === 0) {
      if (o + 2 > PAGE) bad("overflow");
      len = u16(b, o);
      o += 2;
      if (len > MAX_INLINE) bad("value length");
    }
    if (o + len > PAGE) bad("overflow");
    if (i && cmp(key, entries[i - 1]!.key) <= 0) bad("entry order");
    if (cmp(key, lo) < 0 || cmp(key, hi) > 0 || (!last && eq(key, hi))) bad("key outside fences");
    entries.push({ key, tag, value: b.slice(o, o + len), at: o });
    o += len;
  }
  if (!zeroFrom(b, o)) bad("padding");
  return { lo, hi, entries };
}

const k64 = (key: Uint8Array) => dv(key).getBigUint64(0, false);

/** The entry for `key` in run `r`, or null if the run does not hold it. */
function lookup(h: Held, r: Run, key: Uint8Array): Entry | null {
  const t = top(h, r);
  const k = k64(key);
  const m = search(predict(t.model, k), t.modelPages, Number(t.model.eps), (q) => k < modelPage(h, r, q).lo, (q) => {
    const mp = modelPage(h, r, q);
    return mp.lo <= k && (k < mp.hi || q === t.modelPages);
  });
  const pages = r.ref.pages;
  const tag = { table: r.table, index: r.index, of: r.of, pages };
  const page = (i: number) =>
    h.once(`page ${r.path} ${i}`, () => decodePage(h.need({ path: r.path, off: i * PAGE, len: PAGE, run: tag }), i === pages));
  const guess = predict(modelPage(h, r, m).model, k);
  // The pages either side come in the same round, as the full client's default.
  for (const q of [guess - 1, guess + 1]) if (q >= 1 && q <= pages) soft(() => h.get({ path: r.path, off: q * PAGE, len: PAGE, run: tag }));
  const p = search(guess, pages, r.ref.eps, (q) => cmp(key, page(q).lo) < 0, (q) => {
    const pg = page(q);
    return cmp(key, pg.lo) >= 0 && (cmp(key, pg.hi) < 0 || (q === pages && cmp(key, pg.hi) <= 0));
  });
  return page(p).entries.find((e) => eq(e.key, key)) ?? null;
}

/** Every run's entry for `key`; a run that errs is skipped while another answers. */
function entries(h: Held, rs: Run[], key: Uint8Array): Entry[] {
  let err: string | undefined;
  const found = each(rs, (r) => {
    try {
      return lookup(h, r, key);
    } catch (e) {
      if (e instanceof Refused) return (err ??= e.message), null;
      throw e;
    }
  }).filter((e): e is Entry => e !== null);
  if (!found.length && err) refuse(err);
  return found;
}

/** For the tamper demo: where `key`'s value sits in a fetched data page, if it is there. */
export function tamperSpot(b: Uint8Array, key: Uint8Array, last: boolean): number | null {
  try {
    const e = decodePage(b, last).entries.find((e) => eq(e.key, key) && e.tag === 0 && e.value.length > 0);
    return e ? e.at + (e.value.length >> 1) : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- keys

const STORAGE_DOMAIN = new TextEncoder().encode("csl/eth/storage-node/v1");

/** The 64 nibbles of a hashed key. */
export const nibbles = (h: Uint8Array) => Array.from(h).flatMap((b) => [b >> 4, b & 15]);

/** A trie position's table key: its path packed left-aligned in 31 bytes, then the depth. */
export function tableKey(path: number[], depth: number): Uint8Array {
  if (depth > 62) refuse(`node at depth ${depth} cannot be keyed`);
  const out = new Uint8Array(32);
  for (let i = 0; i < depth; i++) out[i >> 1]! |= i & 1 ? path[i]! : path[i]! << 4;
  out[31] = depth;
  return out;
}

/** Storage positions are keyed under their account: keccak(domain ‖ keccak(address) ‖ table key). */
export const storageKey = (owner: Uint8Array, path: number[], depth: number) => keccak(concat(STORAGE_DOMAIN, owner, tableKey(path, depth)));

// ---------------------------------------------------------------- RLP

type Item = { list: boolean; start: number; end: number };

/** One RLP header at `o`, canonical as alloy-rlp requires; the item spans [o, end). */
export function rlpItem(b: Uint8Array, o: number): Item {
  const x = b[o] ?? refuse("rlp: short");
  let [list, start, len] = [false, o + 1, 0];
  if (x < 0x80) [start, len] = [o, 1];
  else if (x <= 0xb7) {
    len = x - 0x80;
    if (len === 1 && (b[o + 1] ?? refuse("rlp: short")) < 0x80) refuse("rlp: non-canonical single byte");
  } else if (x < 0xc0 || x >= 0xf8) {
    list = x >= 0xf8;
    const n = x - (list ? 0xf7 : 0xb7);
    if (o + 1 + n > b.length) refuse("rlp: short");
    if (b[o + 1] === 0) refuse("rlp: leading zero in length");
    for (let i = 0; i < n; i++) len = len * 256 + b[o + 1 + i]!;
    if (len < 56) refuse("rlp: non-canonical length");
    start = o + 1 + n;
  } else [list, len] = [true, x - 0xc0];
  if (start + len > b.length) refuse("rlp: short");
  return { list, start, end: start + len };
}

/** The items of a list item. */
function rlpList(b: Uint8Array, it: Item): Item[] {
  if (!it.list) refuse("rlp: expected a list");
  const out: Item[] = [];
  const inner = b.subarray(0, it.end); // no item may run past the list
  for (let at = it.start; at < it.end; at = out[out.length - 1]!.end) out.push(rlpItem(inner, at));
  return out;
}
const strOf = (b: Uint8Array, it: Item) => (it.list ? refuse("rlp: expected a string") : b.subarray(it.start, it.end));

/** A minimal big-endian unsigned integer of at most `max` bytes. */
function rlpUint(b: Uint8Array, it: Item, max: number): bigint {
  const s = strOf(b, it);
  if (s.length > max) refuse("rlp: integer overflow");
  if (s[0] === 0) refuse("rlp: integer with a leading zero");
  return s.reduce((n, x) => (n << 8n) | BigInt(x), 0n);
}

type Node =
  | { kind: "branch"; children: (Uint8Array | null)[] }
  | { kind: "extension"; key: number[]; child: Uint8Array }
  | { kind: "leaf"; key: number[]; value: Uint8Array }
  | { kind: "empty" };

/** alloy-trie's TrieNode::decode, plus: nothing may follow the node. */
export function decodeNode(b: Uint8Array): Node {
  const top = rlpItem(b, 0);
  if (top.end !== b.length) refuse("rlp: bytes after the node");
  if (!top.list) return top.end === top.start ? { kind: "empty" } : refuse("rlp: node is a string");
  const items: Item[] = [];
  for (let at = top.start; at < top.end; at = items[items.length - 1]!.end) {
    if (items.length === 17) refuse("rlp: too many items");
    items.push(rlpItem(b, at));
  }
  // An item's raw bytes, from its header on.
  const rawOf = (i: number) => b.subarray(i === 0 ? top.start : items[i - 1]!.end, items[i]!.end);
  const ref = (r: Uint8Array) => (r.length > 33 ? refuse("rlp: child reference too long") : r);
  if (items.length === 17) {
    if (!eq(rawOf(16), Uint8Array.of(0x80))) refuse("branch node with a value");
    return { kind: "branch", children: items.slice(0, 16).map((_, i) => (eq(rawOf(i), Uint8Array.of(0x80)) ? null : ref(rawOf(i)))) };
  }
  if (items.length !== 2) refuse("rlp: node has neither 2 nor 17 items");
  const enc = strOf(b, items[0]!);
  if (!enc.length) refuse("trie node key empty");
  const flag = enc[0]! & 0xf0;
  if (flag > 0x30) refuse("node is not extension or leaf");
  const odd = (flag & 0x10) !== 0;
  if (enc.length - 1 > 32 - (odd ? 1 : 0)) refuse("trie node key too long");
  const key = [...(odd ? [enc[0]! & 15] : []), ...nibbles(enc.subarray(1))];
  return flag >= 0x20 ? { kind: "leaf", key, value: strOf(b, items[1]!) } : { kind: "extension", key, child: ref(rawOf(1)) };
}

// ---------------------------------------------------------------- trie walk

export type Outcome = { value: Uint8Array } | { absent: string };

/**
 * Walk from `root` along `path` (64 nibbles). `node(depth, hash)` returns
 * the stored node for that position, or null. Every hashed node must hash
 * to its parent's reference; embedded ones (under 32 bytes) are covered by
 * their parent's hash. Absence is proven only by shape: an empty trie, an
 * empty branch slot, or an extension or leaf that diverges from the path.
 */
export function walk(root: Uint8Array, path: number[], node: (depth: number, hash: Uint8Array) => Uint8Array | null): Outcome {
  if (eq(root, EMPTY_ROOT)) return { absent: "the trie is empty" };
  let [depth, nodes, ref] = [0, 0, concat(Uint8Array.of(0xa0), root)];
  for (;;) {
    if (nodes >= 64) refuse("walk longer than 64 nodes");
    let bytes = ref;
    if (ref.length === 33) {
      const hash = ref.subarray(1);
      bytes = node(depth, hash) ?? refuse(`trie node at depth ${depth} is not in the bucket`);
      if (bytes.length > 1024) refuse(`trie node at depth ${depth} is too large`);
      if (!eq(keccak(bytes), hash)) refuse(`trie node at depth ${depth} does not hash to its parent's reference`);
    }
    nodes++;
    const n = decodeNode(bytes);
    if (n.kind === "empty") return refuse("empty node inside the trie");
    if (n.kind === "branch") {
      if (depth >= 64) refuse("branch below the last nibble");
      const c = n.children[path[depth]!];
      if (!c) return { absent: `branch at depth ${depth} has no child ${path[depth]!.toString(16)}` };
      [ref, depth] = [c, depth + 1];
    } else if (n.kind === "extension") {
      if (n.key.length === 0 || depth + n.key.length > 64) refuse("extension out of shape");
      if (n.key.some((x, i) => x !== path[depth + i])) return { absent: `extension at depth ${depth} leads elsewhere` };
      [ref, depth] = [n.child, depth + n.key.length];
    } else {
      const rest = path.slice(depth);
      if (rest.length !== n.key.length || n.key.some((x, i) => x !== rest[i])) return { absent: `leaf at depth ${depth} is another key's` };
      return { value: n.value };
    }
  }
}

/** Walk a table: each position's candidates come from every run, the one hashing to the reference is taken. */
function walkTable(h: Held, rs: Run[], root: Uint8Array, path: number[], keyOf: (d: number) => Uint8Array, prefetch: number): Outcome {
  if (eq(root, EMPTY_ROOT)) return { absent: "the trie is empty" };
  // Ask for the first depths at once, so they share rounds.
  for (let d = 0; d <= prefetch; d++) soft(() => entries(h, rs, keyOf(d)));
  return walk(root, path, (d, hash) => {
    const c = entries(h, rs, keyOf(d)).filter((e) => e.tag === 0).map((e) => e.value);
    return c.find((v) => eq(keccak(v), hash)) ?? c[0] ?? null;
  });
}

// ---------------------------------------------------------------- values

export type Account = { nonce: bigint; balance: bigint; storageRoot: Uint8Array; codeHash: Uint8Array };

/** rlp([nonce, balance, storageRoot, codeHash]), minimal, nothing after it. */
export function decodeAccount(b: Uint8Array): Account {
  const it = rlpItem(b, 0);
  if (it.end !== b.length) refuse("account: bytes after the list");
  const f = rlpList(b, it);
  if (f.length !== 4) refuse("account: not four fields");
  const h32 = (x: Item) => (x.list || x.end - x.start !== 32 || b[x.start - 1] !== 0xa0 ? refuse("account: not a 32-byte hash") : b.slice(x.start, x.end));
  return { nonce: rlpUint(b, f[0]!, 8), balance: rlpUint(b, f[1]!, 32), storageRoot: h32(f[2]!), codeHash: h32(f[3]!) };
}

/** A storage leaf: rlp of a minimal, non-zero word. */
export function decodeWord(b: Uint8Array): bigint {
  const it = rlpItem(b, 0);
  if (it.end !== b.length) refuse("storage: bytes after the word");
  const w = rlpUint(b, it, 32);
  return w === 0n ? refuse("storage: zero word stored as a leaf") : w;
}

// ---------------------------------------------------------------- read

export type Query = { address: Uint8Array; slot?: bigint; code?: boolean; now: number };
export type Answer = {
  head: Head;
  account: Account | null;
  absent?: string;
  storage?: { value: bigint; absent?: string };
  code?: Uint8Array;
};

/** Read one account, and one of its slots or its code, proven against the attested head. */
export function read(h: Held, q: Query): Answer {
  if (q.address.length !== 20) refuse("an address is 20 bytes");
  if (q.slot !== undefined && (q.slot < 0n || q.slot >= 2n ** 256n)) refuse("a slot is a 256-bit unsigned number");
  const head = verifyHead(h, q.now);
  const tables = runs(h, head);
  const hashed = keccak(q.address);
  const apath = nibbles(hashed);
  const slotPath = q.slot === undefined ? null : nibbles(keccak(le(q.slot).reverse()));
  // The storage trie's first pages depend only on the owner: ask in the account's rounds.
  if (slotPath) for (let d = 0; d <= D_STORAGE; d++) soft(() => entries(h, tables[STORAGE]!, storageKey(hashed, slotPath, d)));
  if (q.code) for (const r of tables[CODE]!) soft(() => top(h, r)); // page 0s need no key
  const a = walkTable(h, tables[ACCOUNTS]!, head.stateRoot, apath, (d) => tableKey(apath, d), D_ACCOUNT);
  if ("absent" in a) return { head, account: null, absent: a.absent, ...(slotPath ? { storage: { value: 0n, absent: "no account" } } : {}) };
  const account = decodeAccount(a.value);
  const out: Answer = { head, account };
  if (slotPath) {
    const s = walkTable(h, tables[STORAGE]!, account.storageRoot, slotPath, (d) => storageKey(hashed, slotPath, d), D_STORAGE);
    out.storage = "absent" in s ? { value: 0n, absent: s.absent } : { value: decodeWord(s.value) };
  }
  if (q.code) out.code = code(h, tables[CODE]!, account.codeHash);
  return out;
}

/** Bytecode under a verified code hash: any run's copy that hashes to it; large code is a blob named by its blake3. */
function code(h: Held, rs: Run[], codeHash: Uint8Array): Uint8Array {
  if (eq(codeHash, KECCAK_EMPTY)) return new Uint8Array();
  const found = entries(h, rs, codeHash);
  if (!found.length) refuse("code is not in the bucket");
  let why = "";
  for (const e of found) {
    let bytes = e.value;
    if (e.tag === 2) {
      bytes = h.need({ path: `blobs/${hex(e.value).slice(2)}` });
      if (!eq(blake3(bytes), e.value)) {
        why ||= "code blob does not hash to its name";
        continue;
      }
    } else if (e.tag !== 0) {
      why ||= "code entry is neither a value nor a blob";
      continue;
    }
    if (eq(keccak(bytes), codeHash)) return bytes;
    why ||= "bytecode does not hash to the account's code hash";
  }
  return refuse(why);
}
