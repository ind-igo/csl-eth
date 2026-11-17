// bun test light — RLP, SSZ, key encoding, the walk, and page decoding.
import { describe, expect, test } from "bun:test";
import {
  beaconRoot, CHECKPOINT, decodeAccount, Held, read, decodeNode, decodePage, decodeWord, EMPTY_ROOT, executionRoot, hex, keccak,
  KECCAK_EMPTY, merkleize, nibbles, Refused, storageKey, tableKey, unhex, walk,
} from "./verify.ts";
import { Reader } from "./driver.ts";

const b = (...x: number[]) => Uint8Array.from(x);

describe("rlp", () => {
  test("non-canonical and short encodings are refused", () => {
    for (const bad of [
      b(0x81, 0x05), // single byte < 0x80 wrapped
      b(0xb8, 0x05, 1, 2, 3, 4, 5), // long form under 56
      b(0xb9, 0x00, 0x40, ...new Array(64).fill(1)), // leading zero in the length
      b(0x83, 1, 2), // short
      b(), // nothing
      b(0x82, 1, 2, 3), // trailing byte
      b(0xc1, 0x80), // a list where a word goes
    ])
      expect(() => decodeWord(bad)).toThrow(Refused);
    expect(() => decodeNode(b(0xc2, 0x83, 1, 2, 3))).toThrow(Refused); // item overruns its list
    const long = Uint8Array.from([0xb8, 56, ...new Array(56).fill(1)]);
    expect(() => decodeWord(long)).toThrow(/overflow/); // canonical, but 56 bytes is no word
  });
  test("storage words, as the Rust tests", () => {
    expect(decodeWord(b(0x82, 0x12, 0x34))).toBe(0x1234n);
    expect(decodeWord(b(0x01))).toBe(1n);
    for (const bad of [b(0x80), b(0x81, 0x01), b(0x01, 0x00), b(0x00), b(0x82, 0x00, 0x01)]) expect(() => decodeWord(bad)).toThrow(Refused);
    const max = new Uint8Array(33).fill(0xff);
    max[0] = 0xa0;
    expect(decodeWord(max)).toBe(2n ** 256n - 1n);
  });
  test("accounts", () => {
    // rlp([7, 1_000_000, EMPTY_ROOT, KECCAK_EMPTY])
    const enc = Uint8Array.from([0xf8, 0x47, 0x07, 0x83, 0x0f, 0x42, 0x40, 0xa0, ...EMPTY_ROOT, 0xa0, ...KECCAK_EMPTY]);
    const a = decodeAccount(enc);
    expect([a.nonce, a.balance, hex(a.storageRoot), hex(a.codeHash)]).toEqual([7n, 1_000_000n, hex(EMPTY_ROOT), hex(KECCAK_EMPTY)]);
    expect(() => decodeAccount(Uint8Array.from([...enc, 0]))).toThrow(Refused); // trailing byte
    const leading = Uint8Array.from([0xf8, 0x48, 0x81, 0x00, ...enc.slice(3)]); // nonce 0 as 0x81 0x00: not minimal
    expect(() => decodeAccount(leading)).toThrow(Refused);
  });
  test("trie nodes", () => {
    const leaf = decodeNode(b(0xc4, 0x82, 0x20, 0xab, 0x01)); // leaf, even, key ab, value 01
    expect(leaf).toEqual({ kind: "leaf", key: [0xa, 0xb], value: b(0x01) });
    const ext = decodeNode(Uint8Array.from([0xe2, 0x11, 0xa0, ...new Uint8Array(32)])); // extension, odd, key 1
    expect(ext.kind === "extension" && ext.key).toEqual([1]);
    const branch = Uint8Array.from([0xd1, ...new Array(17).fill(0x80)]);
    expect(decodeNode(branch).kind).toBe("branch");
    expect(() => decodeNode(Uint8Array.from([0xd1, ...new Array(16).fill(0x80), 0x01]))).toThrow(Refused); // branch value
    expect(() => decodeNode(b(0xc4, 0x82, 0x40, 0xab, 0x01))).toThrow(Refused); // flag 4
    expect(() => decodeNode(b(0xc4, 0x82, 0x20, 0xab, 0x01, 0x00))).toThrow(Refused); // trailing byte
    expect(decodeNode(b(0x80))).toEqual({ kind: "empty" });
  });
});

describe("ssz", () => {
  test("the checkpoint is the bootstrap header's root", () => {
    const header = {
      slot: "15661216",
      proposer_index: "2189907",
      parent_root: "0x631fd23eea5537b410a8108526c39b35cd67529fb27dabbeeb04713d2bffc4a0",
      state_root: "0xcf4a2c7cd7356640db239f35789c463207e022bcea4d811b4ac1b4390b79e5bc",
      body_root: "0xe7ea467b64a286060c9a9f1062b70050dd213208db47ea363eca84307421c387",
    };
    expect(hex(beaconRoot(header))).toBe(CHECKPOINT);
    expect(hex(beaconRoot({ ...header, slot: "15661217" }))).not.toBe(CHECKPOINT);
  });
  test("merkleize pads to a power of two", () => {
    const z = new Uint8Array(32);
    expect(merkleize([z])).toEqual(z);
    const one = new Uint8Array(32).fill(1);
    expect(merkleize([one], 4)).toEqual(merkleize([one, z, z, z]));
    expect(merkleize([one, one, one])).toEqual(merkleize([one, one, one, z]));
  });
  test("an execution header with a field missing is refused", () => {
    expect(() => executionRoot({})).toThrow(Refused);
  });
});

describe("keys", () => {
  const full = nibbles(new Uint8Array(32).fill(0xab));
  test("table keys pack left-aligned with the depth last", () => {
    const k = tableKey(full, 3);
    expect([...k.slice(0, 2)]).toEqual([0xab, 0xa0]);
    expect(k.slice(2, 31).every((x) => x === 0)).toBe(true);
    expect(k[31]).toBe(3);
    expect(tableKey(full, 0)).toEqual(new Uint8Array(32));
    expect(tableKey(full, 62)[31]).toBe(62);
    expect(() => tableKey(full, 63)).toThrow(Refused);
  });
  test("storage keys hash the domain, owner and table key", () => {
    const owner = keccak(unhex("0xdAC17F958D2ee523a2206206994597C13D831ec7"));
    const k = storageKey(owner, full, 2);
    const pre = Uint8Array.from([...new TextEncoder().encode("csl/eth/storage-node/v1"), ...owner, ...tableKey(full, 2)]);
    expect(k).toEqual(keccak(pre));
    expect(storageKey(owner, full, 3)).not.toEqual(k);
  });
});

describe("walk", () => {
  // A trie of one leaf: rlp([0x20 ‖ path, value]).
  const path = new Uint8Array(32).fill(0x11);
  const node = Uint8Array.from([0xe4, 0xa1, 0x20, ...path, 0x81, 0x99]);
  const root = keccak(node);
  const src = (n: Uint8Array) => (d: number) => (d === 0 ? n : null);
  test("present, absent by shape, and tampered", () => {
    expect(walk(root, nibbles(path), src(node))).toEqual({ value: b(0x99) });
    const other = walk(root, nibbles(new Uint8Array(32).fill(0x12)), src(node));
    expect("absent" in other).toBe(true);
    expect(walk(EMPTY_ROOT, nibbles(path), () => null)).toEqual({ absent: "the trie is empty" });
    const bad = node.slice();
    bad[10] = bad[10]! ^ 1;
    expect(() => walk(root, nibbles(path), src(bad))).toThrow(/does not hash/);
    expect(() => walk(root, nibbles(path), () => null)).toThrow(/not in the bucket/);
  });
});

describe("pages", () => {
  test("a canonical page decodes; a dirty one is refused", () => {
    const p = new Uint8Array(4096);
    p[0] = 1; // one entry
    p.fill(0xff, 34, 66); // lo = 0, hi = max (last page)
    const at = 66 + 2;
    p[66] = at; // its offset
    p.fill(0x42, at, at + 32); // key
    p[at + 32] = 0; // tag 0
    p[at + 33] = 2; // len 2
    p[at + 35] = 7, p[at + 36] = 8;
    const page = decodePage(p, true);
    expect(page.entries[0]!.value).toEqual(b(7, 8));
    const short = p.slice();
    short[65] = 0xfe;
    expect(() => decodePage(short, true)).toThrow(/fences/); // the last page ends at the key maximum
    const dirty = p.slice();
    dirty[4000] = 1;
    expect(() => decodePage(dirty, true)).toThrow(/padding/);
  });
});

describe("queries and fetches", () => {
  test("a slot outside 256 bits is refused, not wrapped", () => {
    const address = new Uint8Array(20);
    for (const slot of [-1n, 2n ** 256n]) expect(() => read(new Held(), { address, slot, now: Date.now() })).toThrow(/256-bit/);
  });
  test("a failed fetch is a refusal for whoever needs it", () => {
    const h = new Held();
    const w = { path: "x.run", off: 4096, len: 4096 };
    expect(h.get(w)).toBeUndefined();
    h.fail(w, "fetch failed: HTTP 404");
    expect(() => h.get(w)).toThrow(Refused);
    expect(() => h.need(w)).toThrow(/404/);
  });
});

describe("remembered checkpoint", () => {
  const start = (v: string | null) => new Reader("http://unused", { get: () => v, set: () => {} }).session.checkpoint;
  test("a well-formed root other than the built-in one is where a session starts", () => {
    const r = "0x5bd5c7450adb03520cb650f2e2cd3b336f90b5c394843a618326fbaae34a0273";
    expect(start(r)).toBe(r);
    expect(start(r.toUpperCase().replace("0X", "0x"))).toBe(r);
  });
  test("anything else starts from the built-in checkpoint", () => {
    for (const v of [null, "", "hello", "0x5bd5c745", "5bd5c7450adb03520cb650f2e2cd3b336f90b5c394843a618326fbaae34a0273", `0x${"g".repeat(64)}`, ` 0x${"ab".repeat(32)}`, CHECKPOINT])
      expect(start(v)).toBe(CHECKPOINT);
  });
  test("a store that throws is no store", () => {
    // light.ts wraps localStorage in try/catch; the Reader itself only sees null.
    expect(new Reader("http://unused").session.checkpoint).toBe(CHECKPOINT);
  });
});
