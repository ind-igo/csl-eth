# Keeping full state current: the delta producer

Design note, 2026-11-16. Not built; reviewed once (GPT 6.1 via omp, same day; what it changed is folded in, what was set aside is at the end). `full/` holds all of mainnet's state at block 26,422,083 and nothing moves it forward. A re-export is a burst (about $7 of VM and 8.7 hours), so a daily one costs about $210 a month and is always a day old. An always-on full node was ruled out on cost. This note is how the files follow the chain without either.

## What has to happen per step

The published state moves from a complete trie at root R0 to root R1, a `state_root` the beacon light client verified. The bucket holds trie nodes by position: `packed_path ‖ depth` in `account_nodes`, `keccak(domain ‖ owner ‖ packed_path ‖ depth)` in `storage_nodes` (`trie/src/key.rs:87-103`), code by hash. Embedded nodes (RLP under 32 bytes) have no entry of their own; they live inside their parent (`build.rs:262-270`). So a step's output is every hashed node of R1 whose (owner, position, hash) is not already published, plus new code. Three ways to get those nodes:

1. **Execute.** Run each block against the state at R0 and check the result is R1. That is a node: random reads over about 160 GB of flat state plus the trie. Writing our own executor buys nothing in hardware over reth and costs months. The honest form is reth itself, following a tip our light client chooses (an Engine API `forkchoiceUpdated` to a verified hash, which reth backfills from peers, as `--debug.tip` does once), with an ExEx or its changesets naming the changed keys. In asia-east1: n2-standard-4 about $164 a month list (about $131 with sustained use), 700 GiB pd-ssd about $119: **$250 to $283 a month.** It is the always-on node by another name.
2. **Heal.** What snap sync does at its end: walk R1 from the root, fetch nodes from peers with snap/1 `GetTrieNodes`, and descend only where a child's reference differs from what we hold at that position for that owner. Every node is checked by hash against its parent's reference, so the result is R1's trie by construction, and the step is complete when no reference is unresolved. No execution, no bodies, no flat state; the only local state is our node store. Because completeness is checked against R1 alone, a step can heal from **any** complete R0 to R1; R0 need not be R1's ancestor, which makes reorgs and missed epochs a non-issue for this route.
3. **Apply block access lists.** EIP-7928 (Glamsterdam) commits `block_access_list_hash` in the header; the list carries every changed account's and slot's post-value. Fetch it from `eth/71` peers, check it against the header, apply the post-values, rebuild the changed paths from our node store, and require the header's `state_root`. Unlike healing this is per block and in order: every block between R0 and R1 needs its header, hash-linked back from the verified one, and its list. Sepolia serves the lists today (`crates/snap/src/bal.rs`); mainnet does not until Glamsterdam, whose date is not in this repo.

**Recommendation: prototype healing first, but only commit to it after a sustained probe shows mainnet peers serve it; switch to access lists when mainnet has them; keep reth-following as the fallback.** Healing has a shelf life: snap/2 removes trie-node messages because access lists replace them, so healing lasts as long as peers keep serving snap/1. A fourth source, also with no execution and more peer support, is **range-proof healing**: `GetAccountRange`/`GetStorageRanges` replies carry the boundary paths' nodes, and `trie/src/range.rs` already verifies them and extracts subtree references. Narrow ranges expose changed paths; small changed subtrees are fetched whole. It wastes bytes on unchanged leaves and proofs but needs only the requests the fetcher already makes. It is the first fallback if `GetTrieNodes` is not served.

## The healer

What has to be written. reth's wire crates (both checkouts in use) implement snap/2 only and have no message ids or types for `GetTrieNodes`/`TrieNodes` (0x06/0x07), and `peer.rs:264-270` prefers snap/2 when both are offered, so the healer needs: negotiating snap/1 specifically on the peers it heals from; the request and response RLP (request id, root, path sets of compact-encoded account paths or `[owner_hash, storage_path, …]`, byte limit; response: nodes). Geth 1.16 serves it, capped at 2 MiB, about 1,024 trie loads or five seconds per request, and may omit nodes, so responses are matched to requests by hash, never by position in the list.

How a step walks. The comparison key is (owner, absolute path, reference), not the storage root alone: an account whose storage root is unchanged but which is new at its leaf position (a new contract whose storage root equals an existing one's, common for proxies; a recreated account) needs that whole storage trie materialized under its own owner's keys. The healer copies it locally from any owner that already has a trie with that root (a storage-root → owner index, built with the base) and fetches it only if none does. Embedded children are decoded from their parent's bytes, never requested; transitions between hashed and embedded, branch collapse and extension splits are cases in the test table. A new `codeHash` is fetched with `GetByteCodes`.

Peers serve roots from about the last 128 blocks, but that is a retention envelope, not time we are guaranteed: a step that loses its root re-pivots to a newer verified head and keeps every node already fetched (they are checked by hash against whatever root they end up under). Missed epochs are not two-epoch diffs: in production a failed peer search cost about four boundaries, and five-epoch gaps were the commonest after one-epoch ones (`decisions.md`, 2026-11-08), and the healer must recover from such a backlog inside the window.

## Layers, and why a reader cannot be fooled by them

A layer is a set of runs in the existing format (`RUN_FORMAT`), one per table, holding a step's (or a merge's) nodes keyed by position as the base is. The rule for reading over several runs is not "newest wins" but **the candidate that hashes to the parent's reference is the node**; the root must be the verified `state_root` as now. Embedded nodes come from authenticated parent bytes, storage traversal is driven by the verified account's current storage root, and code is checked by keccak (and blobs by BLAKE3 first), so:

- a stale node left in an older run is never accepted;
- deletion needs nothing: absence is still proven by the shape of verified nodes, and no reader trusts a tombstone;
- a missing node gives `Insufficient`, never a wrong value. The fault contract is **correct answer or `Insufficient`**, with `Insufficient` required exactly when a fault removes every matching candidate a read needs; dropping an irrelevant layer may leave a read verified.

What the client has to change, more than the walk:

- `NodeSource` returns the candidate matching the expected reference (the walk knows it at every step); the speculative map stops overwriting one value per position (`client/src/lib.rs:977-980`).
- The top-levels cache (`top_keep`, `lib.rs:900-940, 1053`) caches from the speculative map and then suppresses fetches at those positions. With several candidates it must cache only the nodes the walk selected and the gaps it proved, scoped to the snapshot's root, or a stale candidate cached once becomes a persistent `Insufficient`.
- Repair rounds and code lookup (`lib.rs:1300-1385`, one reader today) search every run; one broken candidate must not hide a valid one.
- A per-run, per-depth density in the manifest may tell the speculative round which runs to skip, but only as scheduling: a skipped run is searched in a repair round before any `Insufficient`.

**What it costs a read.** Each run is one more predicted page per depth in the speculative round, and a sparse run's cold model page can add a dependent round (`lib.rs:865-896`). With four or five runs, a cold account read might go from about 10 requests and 80 KB to 30 to 50 requests and 200 to 400 KB. That is a guess; the prototype measures it, and the success bar below is twice the base-only read.

## Tiers and compaction

The first draft rewrote the whole 344 GiB base daily to keep three runs. That is about 10 TiB a month of uploads for a cadence nothing in the verification needs. Instead:

- **The base is sharded by key range** (say 16 shards per table). A reader picks the shard by key, so sharding costs no fan-out, and a compaction rewrites one shard at a time with scratch bounded by a shard, not a second 344 GiB.
- **Geometric tiers, size-triggered**, factor about 8: epoch runs (up to 8), then runs of about an hour, then of about half a day, then everything since the base. That is four or five runs per table for a reader. A node is rewritten about once per tier.
- **Base compaction** runs when the since-base tier passes about 10% of the base, expected every one to two weeks, shard by shard.

The merge is new code. `extsort`'s merges reject duplicate keys or require identical values (`extsort.rs:122-127, 640-674`); a compaction needs an ordered merge where the newest input wins per (table, key) and a position is dropped only if it is absent from the target trie. Tombstones only nominate positions for that check. Dropping a whole old subtree after a restructure can delete descendants still reachable through a new extension. A compaction is accepted only after the reads that pass before it (every key the steps changed, plus a random sample) pass again over the compacted runs.

**Collection.** Runs move to content-addressed paths (`runs/<blake3>.run`) so manifests share them. Retention is its own rule, separate from the verifier's P+2 freshness limit: a run is deleted when no protected manifest (the latest attested and finalized ones and those named by the head files readers may still hold) reaches it. Soft delete is off for the whole bucket (2026-11-16, the owner's call; Google sets it per bucket, not per prefix), so a run deleted by collection stops being billed at once.

## The head and the bodies, with no RPC

The head is what the producer already verifies: beacon light-client updates from a public beacon API, checked from the checkpoint, giving each boundary's block hash and `state_root`. Healing needs nothing else. Access lists need headers: `GetBlockHeaders` from eth peers, hash-linked back from the verified block to the last applied one. No execution RPC anywhere.

## Cost

asia-east1 list prices, before the bucket:

| | VM | disk | monthly |
|---|---|---|---|
| reth following a light-client tip | n2-standard-4 | 700 GiB pd-ssd | $250 to $283 |
| daily re-export burst | burst only | none kept | about $210, always a day stale |
| **healer or access lists** | e2-standard-2 ($57) | about 500 GiB pd-balanced (base 344, tiers, one shard of scratch; $50) | **about $110** |

The healer's disk holds the base for position lookups (an estimated few hundred thousand per epoch, which wants pd-balanced's IOPS, not pd-standard's). The bucket adds about $9 a month per base copy held, the tiers, and whatever soft delete retains. Initial blob uploads cost Class A operations (about $6.50 for mainnet's 1.3 M blobs, once); later steps upload only new code. Hardware sufficiency is measured, not assumed.

## Prototype

1. **Probe, sustained.** For a day: which mainnet clients answer snap/1 `GetTrieNodes` for a recent root, how often we hold such a peer, response size and latency, partial responses, and grouped storage requests. Range-proof healing is probed the same way. If neither is served reliably, the fallback is reth until Glamsterdam.
2. **Measure the diff before building tiers.** From the probe's peers, heal one epoch and record distinct changed positions per table and depth, RLP bytes, run bytes, and model pages, for a normal epoch and for a five-epoch gap. Every size in this note is a hypothesis until then.
3. **Synthetic tests.** Base from state S0, layers from S1 and S2 (built with the existing producer), including owner replacement with a shared storage root, recreation, branch collapse, extension splits and hashed/embedded transitions. The client over base plus layers must answer every key of S2 as `produce_with` over S2 does. The fault table follows the contract above, and the same reads pass after a compaction.
4. **Mainnet.** A temporary VM in asia-east1 with 500 GiB pd-balanced; copy the base runs from the bucket (same region, about 30 minutes). The reth VM that built the base is gone, but healing does not need it. Catch up from 26,422,083 to the current boundary (a multi-day diff, the worst case; if it is too slow, a fresh burst re-bases first), then heal every epoch for at least 12 hours. Measure, per step: nodes, bytes, requests, heal time against the 6.4-minute epoch, peers, failures, backlog recovery; and reads through the client against base plus layers (requests, bytes, rounds) against the base alone.

Success is every step complete (every changed key and a random sample verified through the client against R1), heals inside the epoch, recovery from a five-epoch gap, and read cost within twice the base-only read.

On Sepolia, which has access lists today, option 3 can be prototyped by replaying historical blocks and reproducing each block's `state_root`, once a Sepolia base exists.

## Review: what was set aside

- **Pricing a third-party executor's change feed** (an ExEx or changesets pushed from someone else's reth, verified by rebuilding R1). It is sound, since the rebuild checks it, but it puts a named operator in the data path. It's worth pricing if healing fails; not pursued first.
- **A bounded local cache of the bucket's base** instead of a full local copy. Healing's lookups would become remote range reads, a few hundred thousand per epoch in GCS operations and latency. The 344 GiB on disk is cheaper.
- **Version pointers in layer entries** (each child's run named in its parent's entry). They were considered before the review: they cut requests but add a dependent round at every run boundary on a path, and a random path crosses three or four runs. They're kept as a possible optimization for the top depths only.
