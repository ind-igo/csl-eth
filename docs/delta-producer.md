# Keeping full state current: the delta producer

Design note, 2026-11-16. Layers in the client and the tracker (`csl-eth track`) are built on branch `healer` and tested on synthetic states and on a mainnet slice (§ Built, at the end). Reviewed once (GPT 6.1 via omp, same day; what it changed is folded in, what was set aside is at the end). `full/` holds all of mainnet's state at block 26,422,083 and nothing moves it forward. A re-export is a burst (about $7 of VM and 8.7 hours), so a daily one costs about $210 a month and is always a day old. An always-on full node was ruled out on cost. This note is how the files follow the chain without either.

## What has to happen per step

The published state moves from a complete trie at root R0 to root R1, a `state_root` the beacon light client verified. The bucket holds trie nodes by position: `packed_path ‖ depth` in `account_nodes`, `keccak(domain ‖ owner ‖ packed_path ‖ depth)` in `storage_nodes` (`trie/src/key.rs:87-103`), code by hash. Embedded nodes (RLP under 32 bytes) have no entry of their own; they live inside their parent (`build.rs:262-270`). So a step's output is every hashed node of R1 whose (owner, position, hash) is not already published, plus new code. Three ways to get those nodes:

1. **Execute.** Run each block against the state at R0 and check the result is R1. That is a node: random reads over about 160 GB of flat state plus the trie. Writing our own executor buys nothing in hardware over reth and costs months. The honest form is reth itself, following a tip our light client chooses (an Engine API `forkchoiceUpdated` to a verified hash, which reth backfills from peers, as `--debug.tip` does once), with an ExEx or its changesets naming the changed keys. In asia-east1: n2-standard-4 about $164 a month list (about $131 with sustained use), 700 GiB pd-ssd about $119: **$250 to $283 a month.** It is the always-on node by another name.
2. **Fetch the changed trie nodes.** What snap sync does at its end (geth calls this step "healing"): walk R1 from the root, fetch nodes from peers with snap/1 `GetTrieNodes`, and descend only where a child's reference differs from what we hold at that position for that owner. Every node is checked by hash against its parent's reference, so the result is R1's trie by construction, and the step is complete when no reference is unresolved. No execution, no bodies, no flat state; the only local state is our node store. Because completeness is checked against R1 alone, a step can go from **any** complete R0 to R1; R0 need not be R1's ancestor, which makes reorgs and missed epochs a non-issue for this route.
3. **Apply block access lists.** EIP-7928 (Glamsterdam) commits `block_access_list_hash` in the header; the list carries every changed account's and slot's post-value. Fetch it from `eth/71` peers, check it against the header, apply the post-values, rebuild the changed paths from our node store, and require the header's `state_root`. Unlike fetching changed nodes this is per block and in order: every block between R0 and R1 needs its header, hash-linked back from the verified one, and its list. Sepolia serves the lists today (`crates/snap/src/bal.rs`); mainnet does not until Glamsterdam, whose date is not in this repo.

**Recommendation: prototype fetching the changed trie nodes first, but only commit to it after a sustained probe shows mainnet peers serve it; switch to access lists when mainnet has them; keep reth-following as the fallback.** It has a shelf life: snap/2 removes trie-node messages because access lists replace them, so it lasts as long as peers keep serving snap/1. A fourth source, also with no execution and more peer support, is **fetching changed nodes through range proofs**: `GetAccountRange`/`GetStorageRanges` replies carry the boundary paths' nodes, and `trie/src/range.rs` already verifies them and extracts subtree references. Narrow ranges expose changed paths; small changed subtrees are fetched whole. It wastes bytes on unchanged leaves and proofs but needs only the requests the fetcher already makes. It is the first fallback if `GetTrieNodes` is not served.

## The tracker

What has to be written. reth's wire crates (both checkouts in use) implement snap/2 only and have no message ids or types for `GetTrieNodes`/`TrieNodes` (0x06/0x07), and `peer.rs:264-270` prefers snap/2 when both are offered, so the tracker needs: negotiating snap/1 specifically on the peers it fetches from; the request and response RLP (request id, root, path sets of compact-encoded account paths or `[owner_hash, storage_path, …]`, byte limit; response: nodes). Geth 1.16 serves it, capped at 2 MiB, about 1,024 trie loads or five seconds per request, and may omit nodes, so responses are matched to requests by hash, never by position in the list.

How a step walks. The comparison key is (owner, absolute path, reference), not the storage root alone: an account whose storage root is unchanged but which is new at its leaf position (a new contract whose storage root equals an existing one's, common for proxies; a recreated account) needs that whole storage trie materialized under its own owner's keys. The tracker copies it locally from any owner that already has a trie with that root (a storage-root → owner index, built with the base) and fetches it only if none does. Embedded children are decoded from their parent's bytes, never requested; transitions between hashed and embedded, branch collapse and extension splits are cases in the test table. A new `codeHash` is fetched with `GetByteCodes`.

Peers serve roots from about the last 128 blocks, but that is a retention envelope, not time we are guaranteed: a step that loses its root re-pivots to a newer verified head and keeps every node already fetched (they are checked by hash against whatever root they end up under). Missed epochs are not two-epoch diffs: in production a failed peer search cost about four boundaries, and five-epoch gaps were the commonest after one-epoch ones (`decisions.md`, 2026-11-08), and the tracker must recover from such a backlog inside the window.

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

The head is what the producer already verifies: beacon light-client updates from a public beacon API, checked from the checkpoint, giving each boundary's block hash and `state_root`. The tracker needs nothing else. Access lists need headers: `GetBlockHeaders` from eth peers, hash-linked back from the verified block to the last applied one. No execution RPC anywhere.

## Cost

asia-east1 list prices, before the bucket:

| | VM | disk | monthly |
|---|---|---|---|
| reth following a light-client tip | n2-standard-4 | 700 GiB pd-ssd | $250 to $283 |
| daily re-export burst | burst only | none kept | about $210, always a day stale |
| **tracker or access lists** | e2-standard-2 ($57) | about 500 GiB pd-balanced (base 344, tiers, one shard of scratch; $50) | **about $110** |

The tracker's disk (in this first plan) holds the base for position lookups (an estimated few hundred thousand per epoch, which wants pd-balanced's IOPS, not pd-standard's). The bucket adds about $9 a month per base copy held, the tiers, and whatever soft delete retains. Initial blob uploads cost Class A operations (about $6.50 for mainnet's 1.3 M blobs, once); later steps upload only new code. Hardware sufficiency is measured, not assumed.

## Prototype

1. **Probe, sustained.** For a day: which mainnet clients answer snap/1 `GetTrieNodes` for a recent root, how often we hold such a peer, response size and latency, partial responses, and grouped storage requests. Range proofs are probed the same way. If neither is served reliably, the fallback is reth until Glamsterdam.
2. **Measure the diff before building tiers.** From the probe's peers, fetch one epoch's changed nodes and record distinct changed positions per table and depth, RLP bytes, run bytes, and model pages, for a normal epoch and for a five-epoch gap. Every size in this note is a hypothesis until then.
3. **Synthetic tests.** Base from state S0, layers from S1 and S2 (built with the existing producer), including owner replacement with a shared storage root, recreation, branch collapse, extension splits and hashed/embedded transitions. The client over base plus layers must answer every key of S2 as `produce_with` over S2 does. The fault table follows the contract above, and the same reads pass after a compaction.
4. **Mainnet.** A temporary VM in asia-east1 with 500 GiB pd-balanced; copy the base runs from the bucket (same region, about 30 minutes). The reth VM that built the base is gone, but the tracker does not need it. Catch up from 26,422,083 to the current boundary (a multi-day diff, the worst case; if it is too slow, a fresh burst re-bases first), then track every epoch for at least 12 hours. Measure, per step: nodes, bytes, requests, step time against the 6.4-minute epoch, peers, failures, backlog recovery; and reads through the client against base plus layers (requests, bytes, rounds) against the base alone.

Success is every step complete (every changed key and a random sample verified through the client against R1), steps inside the epoch, recovery from a five-epoch gap, and read cost within twice the base-only read.

On Sepolia, which has access lists today, option 3 can be prototyped by replaying historical blocks and reproducing each block's `state_root`, once a Sepolia base exists.

## Built (branch `healer`, 2026-11-16)

**The client** reads a format-3 manifest: a plain base (another block's tables) plus layers, each layer one run per table at `runs/<blake3>.run`. At every position it asks every run and the walk takes the candidate that hashes to the parent's reference (`NodeSource::node_hashed`); the top-levels cache keeps only what the walk selected. Repair rounds and code search every run. A plain (format 2) snapshot reads exactly as before: the pinned cost (1,469 reads, 7,897 requests, 34,340,864 bytes, 2,805 rounds) is unchanged from main.

**The store** writes a step's rows as a layer (`write_layer`), merges consecutive layers newest-wins and drops nothing (`merge_layers`, two streaming passes), and writes layered manifests.

**The tracker** (`crates/snap/src/track.rs`) is § The tracker with these choices:

- The local store is the published runs themselves (base and layers, read through `csl-run` readers by position), so there is no second node database.
- A step diffs the verified head's trie against the held state from the root down, wave by wave. One wave is one `GetTrieNodes` round across peers. Served nodes are checked by hash before use, and a bounded cache (`--cache-mib`) keeps them across a re-pivot. New code comes with `GetByteCodes`.
- A step that leaves anything unresolved after four tries, or passes its deadline (about 110 blocks after the target), re-pivots to the newest verified head.
- Commit order:
  1. Write the layer and merge tiers.
  2. Read back every changed account, up to `--verify-slots` changed slots and every new code through the client over the local files at the new root.
  3. Only then publish: runs and blobs, the manifest, head files, `snapshots/latest`.
  4. Collect manifests past `--keep` and the runs only they reach.
- `track.json` holds the base, the head, the tiers and what is published, so a restart resumes.
- Publishing goes to `scripts/gcs-publish.sh` (runs are cached as immutable), to a directory, or to a dry run.

**Catch-up from any gap.** A step is two walks. The sync fetches onto disk (`work/nodes`: a log of hash-checked records and an index of eight bytes per hash) every node of the new root that the held state lacks at its position, depth first, and marks a subtree complete once it and everything under it is local. Nodes and markers survive re-pivots and restarts, so a re-pivot re-walks from the newest root and skips what is complete, as snap sync does. The materializing walk then runs locally with no deadline and streams each changed node into an external sorter (`--sort-mib`, spilling under `work/sort`). A multi-day backlog therefore needs neither the peers' window for its local work nor memory for its rows. Test: four pivots and a restart with a torn log tail publish what one uninterrupted step does, byte for byte.

**The finalized tier.** Every 30 s the tracker checks the light client's finalized header. If a manifest for that block is published, it pins it: `head/finality` is written, and collection keeps the last two pinned manifests and every run they reach, whatever `--keep` says. If the finalized block is ahead of the held head (a catch-up), the tracker steps to the finalized root first, so the first manifest after a gap is a finalized one. If it is behind the head and was never a step, the event is `finalized_missed` and the next one is pinned. On mainnet (2026-11-16, the Mac's slice) an earlier run missed two finalized heads (each fell between steps below the held head); on the next run three in a row (blocks 26,428,472, 26,428,504 and 26,428,535) were pinned as the light client reported them.

**Per-layer skip hints** (`crates/store/src/hints.rs`). Each layer carries, per table, what it may hold: account positions cut to the shallowest depth at which they cover at most 1% of that depth's prefixes, storage owners, and code hashes (eight-byte prefixes). A table over 65,536 entries gets no hint. Hints up to 4 KiB sit in the manifest; larger ones go to `runs/<blake3>.hints`, which the client fetches with the page 0s when it opens the snapshot. The client asks a position only of the runs whose hint says Maybe or Yes, newest first, and stops at the first Yes. Hints are not authenticated, so they only schedule. A position whose walk fails (Missing or Invalid) after some runs were skipped is asked of every run before the read can be `Insufficient`; a lying, missing or non-hashing hint costs repair rounds, never an answer (tested).

**The storage-root → owner index.** When an account appears with a storage root that another owner already holds, the tracker copies that trie locally under the new owner instead of fetching it from peers. The index (`work/roots.idx`, sorted 40-byte records, plus an append log) is built once from the held manifest's account runs, and each committed step appends its new tries. A copy is verified against the root before it is used, and an index entry that has gone stale only means a fetch.

**Without a local base** (`--base-url`). The tracker can run with no copy of the base: the root holds the base's manifest, the layers and the head files, and the base's runs stay in the bucket. A diff still needs the old side, the held state's node at each changed position. The tracker takes it from the node log or the local layers when it can. Otherwise the node waits, and its old node is asked for in the same wave as the new side's nodes:

- **In the window** (the held head is under about 128 blocks old), from peers at the old root. This is what the probe did on every step: about twice the requests, 6.7 s p50 a block with six or more peers. Nodes changed recently are in the local layers and cost nothing.
- **After a gap**, from the base's runs in the bucket by HTTP range, many requests in flight and each page fetched once per batch. No peer serves a root that old.

Every old node is checked against the hash its parent committed to, so wrong bytes from a peer or the bucket cost a request, never a wrong layer. The rows are the same as with the base on disk (`tracks_without_a_local_base`), and read-back works without it. There is no storage-root index in this mode (a shared storage trie is fetched from peers), and code the base already holds may be written again when an account takes it, which is harmless. From the Mac through the VPN, the real `full/` base answered its first three levels of the account trie (273 nodes) by range in about 63 s and 814 requests, cold. From a VM in the bucket's region, latency should be one to two orders of magnitude lower; measuring it is part of the deploy.

Cost of a gap, estimated: a day's diff is about 7.5 M new nodes, so about as many old-side lookups. At about 1.2 range requests a lookup once model pages are cached, that is about 9 M Class B operations, about $3.60 per day of gap. GCS to a VM in the same region moves no billable egress. Time is set by the peers' side (about 3,000 nodes/s with a few peers, so about 45 minutes a day of gap) as long as the bucket keeps up: at 128 in flight and 30 ms each, about 4,000 lookups/s.

**Disk without the base.** What stays local is the layers and scratch: the since-base layer S twice while it merges (every 256 blocks at the defaults), the lower tiers (under a gigabyte), and during a catch-up the node log (new and old nodes, about 4.6 GB per day of gap) and the sort spill (about 2.3 GB per day of gap). S grows with the base's age: about 2.3 GB a day after the base, 11 GB at a week, 34 GB at a month (from the probe's growth of about blocks^0.79). A 100 GB disk runs a month without rebasing; a rebase (a new base from the base and S, a 344 GiB rewrite) is not built, and would run as a burst with a large disk.

**Not built, against the plan above:**

- The sharded base and base compaction (rebasing onto a newer block).
- Size-triggered tiers. Tiers are count-triggered (`--fanout` per tier, `--tiers` levels, the top tier one layer since the base), and compaction runs inside the step.
- Access lists.

**Tests.** The client has three layer tests: a base plus two layers answers every key as a fresh build of the last state; a dropped or corrupted layer yields only `Insufficient`; plain cost is pinned. They run over a crafted transition table: an extension split, a branch collapse, an owner sharing another's storage root, deletion then recreation with new code, and embedded↔hashed. The tracker has four tests on the same table:

- Step by step and across a two-step gap, each layer a superset of the full row diff and nothing outside the new state.
- A step with a zero-size cache.
- A re-pivot that reuses fetched nodes.
- Twenty steps through tiers with every state read back.

**Read cost over layers** (synthetic: about 4% of accounts change per step, so each layer is dense; `read_cost_over_n_layers_and_merged`):

Costs are relative to a fresh plain build of the same state; "layers/read" is the distinct layer runs a read asked.

| layers | hinted: requests, bytes, layers/read | unhinted: requests, bytes, layers/read | merged into one | manifest |
|---|---|---|---|---|
| 1 | 1.01×, 1.01×, 1.00 | 1.32×, 1.35×, 1.14 | 1.01×, 1.01× | 2.5 KB |
| 2 | 1.00×, 1.00×, 1.12 | 1.60×, 1.66×, 2.28 | 1.03×, 1.01× | 3.6 KB |
| 4 | 1.05×, 1.03×, 1.38 | 2.26×, 2.37×, 4.51 | 1.01×, 1.00× | 5.7 KB |
| 8 | 1.09×, 1.08×, 1.66 | 3.38×, 3.60×, 8.96 | 1.02×, 1.04× | 9.7 KB |
| 16 | 1.11×, 1.08×, 2.05 | 5.65×, 6.07×, 18.00 | 1.07×, 1.07× | 18.3 KB |

Rounds stay between 2.0 and 2.3 throughout. Without hints, requests and bytes grow about linearly with runs, because each run is one more predicted page per depth. With hints a read asks about two layers even at sixteen, and the merged layer now costs nearly what a fresh build does, because a key the layer did not change skips it. The success bar (twice the base-only read) holds at the default tiers (fanout 4, 5 tiers: at most 13 hinted layers plus the since-base layer).

On mainnet the hint sizes decide which tiers are hinted. A block changes about a thousand accounts, so a 64-block layer holds about 50,000 and fits under the cap, while a 256-block layer would not. At five tiers the hinted tiers are the 1-, 4-, 16- and 64-block ones, and the top tier (since the base) is asked with the base. The price is the hint files: about 2 MB in all when every tier is full, fetched once when a snapshot is opened. A reader that makes only a few reads would do better skipping them; the client fetches them always for now.

**On mainnet, from the Mac (2026-11-16).**

- **Base.** A fresh 1/4096 slice (prefix `1a7`, block 26,428,265: 105,262 accounts, 134,125 slots, 2,218 codes), fetched over 27 minutes from the one Nethermind peer reachable through a VPN.
- **Run.** `csl-eth track --to-dir pub --steps 5` (then named `heal`) against live peers and the Lodestar light-client endpoints, verifying from the 2026-11-15 checkpoint.
- **Steps.** The first closed the 122 blocks since the base in 0.9 s (47 nodes, 15 KiB, 9 waves). The next four followed the head block by block, 0.2 to 0.7 s each, publishing about 16 s after each block's timestamp, which is the attested update's own delay. One peer was enough at this size.
- **Checks.** Each step read its changed accounts back through the client before publishing, and the fourth merged a tier.
- **Completeness.** `tracked_dir_is_complete` (ignored test, `crates/snap/src/track.rs`) then read every account of the slice from the published directory at block 26,428,391: 105,253 unchanged, 9 changed, 29,355 slots, 2,218 codes, none insufficient.

**On `full/` (2026-11-17).** The tracker now keeps the full state current from a spot VM without the base; `docs/decisions.md` (2026-11-17) has the run: the first catch-up of 8,903 blocks, per-block lag (median 35 s from slot start), a finalized checkpoint pinned every epoch, and the read cost over the live layers. On mainnet the synthetic table above is optimistic for two kinds of read: a slot of a contract that changes every block costs about 3.5× the base-only read, because storage hints name only owners, and every read asks the since-base layer, which is too large to hint.

## Review: what was set aside

- **Pricing a third-party executor's change feed** (an ExEx or changesets pushed from someone else's reth, verified by rebuilding R1). It is sound, since the rebuild checks it, but it puts a named operator in the data path. It's worth pricing if fetching changed nodes fails; not pursued first.
- **A bounded local cache of the bucket's base** instead of a full local copy. The tracker's lookups would become remote range reads, a few hundred thousand per epoch in GCS operations and latency. The 344 GiB on disk is cheaper. (Revisited below, § Without a local base: the old side comes from peers instead, and the bucket is read only after a gap.)
- **Version pointers in layer entries** (each child's run named in its parent's entry). They were considered before the review: they cut requests but add a dependent round at every run boundary on a path, and a random path crosses three or four runs. They're kept as a possible optimization for the top depths only.
