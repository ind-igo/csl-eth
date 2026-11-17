---
name: csl-eth-light-client
description: Everything needed to build, in any language, a light client that reads Ethereum mainnet state (accounts, storage slots, code) from the csl-eth static bucket and verifies every answer from a beacon checkpoint. Use when asked to implement, port, test or review such a client.
---

# A light client for Ethereum state in a static bucket

The bucket is plain files over HTTP with byte ranges. Nothing in it is trusted. A read is correct if and only if these four checks pass:

1. **Checkpoint.** A beacon block root you trust (below).
2. **Sync committee signatures.** At least two thirds of the 512-member committee signed each header you use, and each committee is proven from the previous one, starting at the checkpoint.
3. **Merkle branches.** From a signed beacon header to the execution block's `state_root`.
4. **Keccak.** Every trie node from `state_root` down hashes to the reference its parent holds. Absence is proven only by the trie's shape.

Everything else (manifest, index models, page fences, hints) is routing: it tells you where to look. If routing is wrong, a read costs more or fails, but it can never return a wrong value. Keep that boundary sharp. Never accept a value, or an absence, on the strength of a routing file.

Reference implementation: `browser/light/verify.ts` (one file, no I/O) and `browser/light/driver.ts` (fetching) in github.com/ind-igo/csl-eth. If this file and that code disagree, the code wins.

## Constants (mainnet, fulu)

```
BASE      https://storage.googleapis.com/csl-eth-demo/full/      (any mirror works)
CHECKPOINT 0x431b33af8452e2d644377405e69d4f382182ab906f31461190ca24cb3401d70b  (slot 15,661,216)
GENESIS_TIME 1606824023          GENESIS_VALIDATORS_ROOT 0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95
FORK_VERSION 0x06000000 (fulu, from epoch 411392)   DOMAIN_SYNC_COMMITTEE 0x07000000
SLOTS_PER_PERIOD 8192    COMMITTEE 512    BLS DST "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
gindex: current_sync_committee 86 (depth 6), next_sync_committee 87 (depth 6), execution payload in body 25 (depth 4)
```

Use a vetted library for BLS12-381 (min-pk: 48-byte G1 keys, 96-byte G2 signatures), SHA-256, keccak-256 and blake3. Write everything else yourself, or use a strict RLP decoder that refuses non-canonical input.

## 1. The head

The files are beacon-API JSON, `{"version": "fulu", "data": {...}}`. Refuse any other version.

- `head/bootstrap/<CHECKPOINT>`: LightClientBootstrap
- `head/updates/<period>`: LightClientUpdate, one per sync-committee period
- `head/optimistic`: LightClientOptimisticUpdate, the newest attested header

Steps:

1. **Bootstrap.** `hash_tree_root(header.beacon) == CHECKPOINT`. The committee's root must pass `is_valid_merkle_branch` at gindex 86 against `header.beacon.state_root`. That committee belongs to `period(header.beacon.slot)`.
2. **Updates.** For each period `p` from the checkpoint's period to the period `head/optimistic` was signed in, minus one, read `head/updates/p`:
   - `attested_header.beacon.slot` is in period `p`;
   - it is signed (see below) by the committee of `period(signature_slot)`;
   - `next_sync_committee` passes the branch at gindex 87 against the attested `state_root`, and becomes the committee for `p+1`.
3. **Head.** `head/optimistic` must be signed by the committee of `period(signature_slot)`. Its `attested_header.execution` (an ExecutionPayloadHeader) must pass the branch at gindex 25 against `attested_header.beacon.body_root`. That gives `block_number`, `block_hash` and `state_root`.
4. **Freshness.** Let `now_slot = (unix_now - GENESIS_TIME) / 12`. Refuse if the head's signing period is more than one behind `period(now_slot)`, or if `signature_slot > now_slot`.

**Signed** means all of the following:
- `signature_slot > attested slot`;
- the `sync_committee_bits` (512 bits, little-endian within each byte) mark at least 342 members;
- the aggregate of the marked members' keys verifies the 96-byte signature over `sha256(hash_tree_root(attested_header.beacon) ‖ domain)`, where `domain = 0x07000000 ‖ sha256(FORK_VERSION‖28 zero bytes ‖ GENESIS_VALIDATORS_ROOT)[0:28]`.

**SSZ, the only shapes needed:**
- `uint64` is 8 bytes little-endian, zero-padded to 32. `merkleize` pads to a power of two with zero chunks and pairs with sha256.
- BeaconBlockHeader is `merkleize[slot, proposer_index, parent_root, state_root, body_root]`.
- A SyncCommittee root is `sha256(merkleize(512 pubkey roots) ‖ root(aggregate_pubkey))`, where a pubkey's root is `merkleize` of its 48 bytes as 2 chunks.
- ExecutionPayloadHeader is `merkleize` of 17 fields, in order:
  1. `parent_hash`
  2. `fee_recipient` (20 bytes, right-padded)
  3. `state_root`
  4. `receipts_root`
  5. `logs_bloom` (`merkleize` of 8 chunks)
  6. `prev_randao`
  7. `block_number`
  8. `gas_limit`
  9. `gas_used`
  10. `timestamp`
  11. `extra_data` (ByteList[32]: `sha256(chunk ‖ uint256 length)`)
  12. `base_fee_per_gas` (uint256)
  13. `block_hash`
  14. `transactions_root`
  15. `withdrawals_root`
  16. `blob_gas_used`
  17. `excess_blob_gas`

**Caching.** You may keep the newest committee you proved, with its period, and start from it next time. Store only what your own code proved. The unverified `head/checkpoint` file may say where to look, but adopt nothing from it without proof.

## 2. The manifest

Fetch `snapshots/<block_hash hex, no 0x>/manifest.json`. Fail early if its `block_hash` or `state_root` differ from the head's. This is a sanity check; the trust still comes from the walk.

- `format_version` is 3.
- `tables` describes the base snapshot, under `snapshots/<base>/`:

  | `table_id` | File |
  |---|---|
  | 0 | `account_nodes.run` |
  | 1 | `storage_nodes.run` |
  | 2 | `code.run` |

- `layers[]` are updates since the base, oldest first. A layer's table lives at `runs/<root>.run`.
- Each table entry has `root`, `page_count`, `epsilon_pages`, `model_bytes` and `model_root`.
- Hashes in the manifest are hex without `0x`.

A key can appear in several runs, because layers overwrite the base. Ask runs newest first, and take the first candidate that hashes to the parent's reference.

## 3. Finding a node in a run (routing)

**Keys.** Every key is 32 bytes. `path` means the 64 nibbles of `keccak(address)`, or of `keccak(slot as 32 bytes, big-endian)`.

- **Account trie node** at depth `d`: the first `d` nibbles of the path, packed left-aligned into bytes 0..30, with byte 31 set to `d`.
- **Storage trie node**: `keccak("csl/eth/storage-node/v1" ‖ keccak(address) ‖ that same 32-byte key over the slot's path)`.
- **Code**: the code hash.

The router uses `k`, the key's first 8 bytes as a big-endian u64.

**Run file layout.** Pages are 4096 bytes. All integers are little-endian.

- **Page 0** is the top model:
  - `u32` model page count at byte 56;
  - `u16` ε at 60;
  - the 32-byte blake3 tree root of the model pages at 62;
  - `u32` segment count `n` at 94;
  - `n` segments from byte 98, each `(key u64, intercept i64, slope u64)`.
- **Data pages** are pages `1..=page_count`, at byte `i*4096`.
- **Model page `m`** (1-based) is a record of `4096 + 32*ceil(log2(model_pages))` bytes, at `(page_count+1)*4096 + (m-1)*record`. Its first 4096 bytes:
  - `u16 n` at 0, `u64 lo` at 2, `u64 hi` at 10, `i64 next_intercept` at 18;
  - segments from byte 26.

  Append the sentinel segment `(hi, next_intercept, 0)` before predicting with it.

**Prediction.** Take `s`, the last segment with `s.key ≤ k` (the first segment if there is none). The guess is `p = s.intercept + ((k - s.key) * s.slope >> 64)` (just `s.intercept` when no segment had `s.key ≤ k`). If the next segment's `intercept + ε < p`, cap `p` there. Clamp to `[1, count]`.

**Search.** The true page is within about ε of the guess. Check the guess. If it doesn't cover the key, step toward the key up to ε+1 pages, then binary-search beyond that. Page 0 predicts the model page, and the model page predicts the data page.

**Data page.** `u16 n ‖ lo[32] ‖ hi[32] ‖ u16 offsets[n] ‖ entries ‖ zero padding`.
- The page covers keys in `[lo, hi)`. On the last page, `hi` is all `0xff` and inclusive.
- An entry is `key[32] ‖ tag ‖ body`:

  | Tag | Body |
  |---|---|
  | 0 | `u16 len ‖ value`; for trie tables the value is the node's RLP |
  | 1 | empty (a deletion) |
  | 2 | a 32-byte blake3 naming `blobs/<hex>`, for large code |
  | 3 | not used by readers |

The integrity checks are optional, because none of them affects correctness:
- page 0's blake3 equals the manifest's `model_root`;
- model pages are verified to page 0's root;
- data pages are canonical.

What they buy is earlier failure on a corrupt run, so you can skip it and ask another.

## 4. The walk (trust)

```
ref = state_root; depth = 0
loop:
  node = fetch the candidate for (depth) whose keccak == ref   # embedded nodes (<32 bytes RLP) come inline from the parent
  decode node (strict RLP), then by its shape:
    branch (17 items, item 16 must be empty) → child = item[path[depth]]
        empty → ABSENT; else ref = child, depth += 1
    extension (2 items, hex-prefix flag 0/1) → if its nibbles ≠ path[depth..] → ABSENT
        else depth += len, ref = child
    leaf (flag 2/3) → if its nibbles == path[depth..] (exactly the rest) → value, else ABSENT
```

A child reference is either 33 bytes of RLP (a 32-byte hash) or the embedded node itself.

Refuse if:
- no candidate hashes to `ref`;
- the walk takes more than 64 nodes, or a node is larger than 1024 bytes;
- an extension is empty or overruns the path.

An empty trie has root `0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421`.

**Values.**
- **Account leaf:** RLP `[nonce, balance, storageRoot, codeHash]`, with minimal integers.
- **Storage:** walk the storage trie from `storageRoot` with the slot's path. The leaf is RLP of a minimal, non-zero big-endian word. Absent means 0.
- **Code:** look up `codeHash` in the code table, in every run. Take a tag 0 value, or a tag 2 blob whose blake3 matches its name, but only if `keccak(bytes) == codeHash`. The hash `0xc5d2…a470` (keccak of nothing) means no code.

## 5. Speed (optional, but this is what makes it usable)

- **Separate verification from I/O.** Make `read()` pure over the bytes you hold. Have it return the byte ranges it lacks, fetch them all in one parallel round, and call it again. Merge adjacent ranges, and cap a read at about 40 rounds.
- **Fetch every depth at once.** Keys come from the path, not from hashes, so you know every depth's key before any node arrives. In the first round, ask each run for depths 0–9 (accounts) and 0–7 (storage), plus the pages either side of each guess. A read then takes about 2–7 rounds, not one per trie level.
- **Cache.** Keep each run's page 0 and model pages, and the top 4 levels of account nodes keyed by hash (safe under any root), across reads.
- **Hints** (per-layer `hints` or `hints_file`, owner index) let a read skip layers that cannot hold a key. They are routing. If a hint wrongly skips the layer that holds the node, the walk meets an older node that fails its hash, so ask every run before refusing. See `verify.ts` §hints for the formats. Without hints, a read asks every layer (about 3 MB against 0.5 MB, but the same answers).

## 6. Done means these pass

Answers at any recent head (they don't change):

| Read | Expected |
|---|---|
| account `0x5a17e00000000000000000000000000000c0ffee` | absent |
| WETH `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2` slot 0 | `0x577261707065642045746865720000000000000000000000000000000000001a` ("Wrapped Ether") |
| WETH slot 1 | `0x5745544800000000000000000000000000000000000000000000000000000008` ("WETH") |
| WETH slot 12345 | absent (0) |
| WETH code | 3,124 bytes, keccak `0xd0a06b12ac47863b5c7be4185c2deaad1c61557033f56c7d4ea74429cbb25e23` |
| USDT `0xdAC17F958D2ee523a2206206994597C13D831ec7` code | 11,075 bytes, keccak `0xb44fb4e949d0f78f87f79ee46428f23a2a5713ce6fc6e0beb3dda78c2ac1ea55` |
| The DAO `0xBB9bc244D798123fDe783fCc1C72d3Bb8C189413` slot 0 | `0x13d` |
| CryptoPunks `0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB` slot 0 | `0x81` |

For values that change (balances, nonces), compare with an Ethereum RPC's `eth_getProof` at the same `block_number`.

**Tamper tests.** Wrap the fetch so it flips one byte in a chosen file. Each of these must end in a refusal, never an answer:
- in `head/optimistic`: the signature, one participation bit, the execution `state_root`, the `block_number`;
- a committee key, in the bootstrap or in an update's `next_sync_committee`;
- the manifest's `state_root`;
- a byte inside a trie node's value on a data page. This may instead give the right answer from another run; it must never give a wrong one.

Also run a lying-routing test: corrupt hints or model pages. The answer must stay correct, or be refused.
