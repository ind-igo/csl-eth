// bun test mini — RLP, SSZ, key encoding, the walk, and page decoding.
import { describe, expect, test } from "bun:test";
import {
  beaconRoot, CHECKPOINT, decodeAccount, decodeNode, decodePage, decodeWord, EMPTY_ROOT, executionRoot, hex, keccak,
  KECCAK_EMPTY, merkleize, nibbles, Refused, rlpItem, storageKey, tableKey, unhex, walk,
} from "./verify.ts";

const b = (...x: number[]) => Uint8Array.from(x);

describe("rlp", () => {
  test("headers", () => {
    expect(rlpItem(b(0x05), 0)).toEqual({ list: false, start: 0, end: 1 });
    expect(rlpItem(b(0x82, 1, 2), 0)).toEqual({ list: false, start: 1, end: 3 });
    expect(rlpItem(b(0xc1, 0x80), 0)).toEqual({ list: true, start: 1, end: 2 });
    const long = new Uint8Array(58).fill(1);
    long[0] = 0xb8, long[1] = 56;
    expect(rlpItem(long, 0)).toEqual({ list: false, start: 2, end: 58 });
  });
  test("non-canonical and short headers are refused", () => {
    expect(() => rlpItem(b(0x81, 0x05), 0)).toThrow(Refused); // single byte < 0x80 wrapped
    expect(() => rlpItem(b(0xb8, 0x05, 1, 2, 3, 4, 5), 0)).toThrow(Refused); // long form under 56
    expect(() => rlpItem(b(0xb9, 0x00, 0x40), 0)).toThrow(Refused); // leading zero length
    expect(() => rlpItem(b(0x83, 1, 2), 0)).toThrow(Refused); // short
    expect(() => rlpItem(b(), 0)).toThrow(Refused);
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
