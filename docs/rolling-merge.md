# Rolling merge: keeping the base current without a rebase

Status: parked (2026-11-17). Nothing here is built.

**Why parked.** The PoC doesn't need it. The tracker already publishes each
block about 35 s after its slot, and what grows (the since-base layer, its
rewrite, the tracker's disk) lasts about six weeks on the current VM. For the
PoC we run the since-base merge in the background, give the since-base layer a
paged index of the contracts it changed, and, if the demo runs longer, grow the
disk or re-run the full export. See `docs/decisions.md`.

**Where it belongs: a node.** The tracker exists because we run no node: it
rebuilds each block's changes from peers' trie nodes, and it can't refresh the
base because it holds no copy of the state. A full node computes each block's
changed trie nodes anyway, to check the state root, and keeps the whole state
on local disk, where reth stores trie nodes keyed by path, close to this
layout. So the production shape is a node that publishes layers as a side
effect and refreshes the base range by range from its own database, which is
this design with the bucket reads replaced by local ones.

**Future PoC: a reth execution extension (ExEx).** reth's ExEx notifications
carry each committed block's state changes and trie updates, with separate
notifications for reorgs and reverts (Paradigm, "Reth Execution Extensions",
2024: https://www.paradigm.xyz/2024/05/reth-exex ; `ExExNotification` at
https://reth.rs/docs/reth_exex/enum.ExExNotification.html). An ExEx could:

- write each committed block's changed nodes as a layer, from the trie
  updates, and drop or re-publish on a reorg notification;
- run the rolling merge below against the node's own trie tables, one key
  range at a time, instead of streaming the old base from the bucket;
- publish the head files from the node's consensus client, so no peer, no
  `snap/1` and no `GetTrieNodes` is needed.

To check first: that the trie updates in a notification are complete per block
(every changed node, storage tries included) and keyed in a way that maps
cleanly onto our positions, or whether the ExEx has to walk the changed paths
in the node's database itself. The rest of this document stays as written,
with "the tracker" read as "the publisher".


## The problem

The bucket holds a base snapshot (block 26,422,083, 351 GB in three runs) and
layers of changed trie nodes on top, one per tracker step, merged in tiers of
four. The oldest layer, the since-base layer, holds every change since the
base, and every 1,024 steps (about 7.5 hours) the next top-tier layer is merged
into it, rewriting all of it. Three things grow without bound:

- **The since-base rewrite.** 3.44 GB and 68 s today, at 1.4 days of changes.
  At about 2.3 GB a day (the probe's blocks^0.79 fit), it is 11 GB at a week
  and 34 GB at a month. Each rewrite stalls a step and uploads the whole layer
  again.
- **Disk.** The tracker keeps its layer runs locally: 5.7 GB now, growing with
  the since-base layer, on a 100 GB disk.
- **Read cost.** The since-base layer is too large for hints (65,536 entries a
  table, `hints.rs:37`), so every read asks it at every depth. That is the
  whole extra cost of a quiet contract (27 to 28 requests: The DAO is 73
  against 47 base-only) and 6 of an absent account's 20.

The base itself never changes, because changing it means rewriting a whole
run. The storage run is 254.5 GB, and the run writer
(`csl-run/src/writer.rs`) needs a local seekable file of the run's full size:
it writes page 0 last, reads every page back to check the model, and hashes
the whole file for its name. A one-piece rebase therefore needs a scratch disk
of about 400 GB and four disk-bound passes over 351 GB. That is the burst job
this design replaces.

## Why the base can't be edited in place

Object storage replaces whole objects. Each block changes a few thousand trie
nodes, and their keys are hashes, so they land everywhere in the key space.
Editing pages in place would mean rewriting nearly every file every block; one
object per 4 KB page would mean thousands of PUTs per block, on the order of
$100 a day. A reader verifying block N must also never see a page already
rewritten for block N+1. Immutable layers give each block a consistent version
for free, which is why the design is an LSM tree, as in LevelDB, RocksDB and
SlateDB.

## The design in one paragraph

Split the base by key range into partitions of about 1 GB, each an ordinary
run. Stop merging into the since-base layer: when a layer reaches the top tier
it is sealed and kept as is. In the background, the tracker rewrites one
partition at a time, folding every finalized sealed layer into it, and records
the block each partition is now current to. A reader routes each key to its
partition and skips any sealed layer the partition already contains. A sealed
layer is deleted once every partition has passed it. Over a cycle of about a
day every partition is rewritten, so the base is never more than about a day
old, nothing grows, and the work is spread evenly on the tracker's own VM.

## Partitions

**Grid.** A fixed grid by the key's first byte: 256 partitions for
`storage_nodes` (about 1.0 GB each) and 256 for `account_nodes` (about
370 MB each). `code` (2.46 GB) is one partition. Storage keys are keccak
hashes, so storage partitions are even and stay even. Account keys are the
packed path then the depth, so an account partition is a set of whole
subtrees; paths are hashes too, so these are even as well. The grid is fixed
for the life of the bucket; state grows a few percent a month, so 256 lasts
years, and doubling later is a rewrite of the directory, not of the format.

**Files.** A partition's file is a complete run in today's format: fences
`KEY_MIN` and `KEY_MAX` (`page.rs:205-210`), entries only inside its range.
Fences never prove absence (`client/src/lib.rs:1-28`), so no format change is
needed and no trust is added.

**Directory.** A new content-addressed object,
`full/dirs/<blake3>.dir`, lists for each table and partition: the file's root,
`page_count`, `entry_count`, `model_root`, `model_pages`, the top model (what
page 0 carries today), and `as_of`, the block the partition is current to.
About 120 bytes a partition, so about 60 KB for 513 partitions; it compresses
well and changes only when a partition rewrite commits. Carrying the top model
here saves a page-0 request per partition: a cold read goes directory, model
page, data pages, the same rounds as today.

**Manifest v4.** `base` and the base `tables` are replaced by
`base_dir: <blake3>`. Everything else stays: block, state root, layers, hints.
A sealed layer is an ordinary `Layer` with a `sealed: true` flag.

**Migration is the first cycle.** A directory entry may point at the old
monolithic run, with `as_of` 26,422,083. All 513 entries start that way, so
switching to v4 changes nothing a reader sees. The first rewrite of each
partition reads its key range out of the monolithic run by HTTP range, using
that run's model to find the first page. When every partition has been
rewritten once, the monolithic runs fall out of every directory and are
collected. No burst VM, no flag day.

## Sealed layers and views

Today the tiers below the top are 1, 4, 16, 64 and 256 steps a layer, and a
layer that reaches the top tier is merged into the since-base layer. Instead,
it is sealed: never merged again, kept until every partition has folded it.
A sealed layer covers about 1,024 steps (7.5 hours) and about 1 GB.

SlateDB's incremental compaction hides the finished key ranges of an old file
with per-file "views" in the manifest. Here a view is a single number per
partition. A rewrite always folds whole sealed layers, oldest first, and only
finalized ones, so partition p holds exactly the state at `as_of[p]`, and a
reader of a key in p skips every sealed layer with `to_block <= as_of[p]`.
Layers below the top tier are newer than any `as_of`, so they are always asked.

With a one-day cycle there are at most about five sealed layers, and a read
asks only those its partition hasn't folded: about two and a half on average.

**Hints for sealed layers.** A sealed layer is too big for inline hints, so it
gets a paged owner index: its changed storage owners, 8 bytes each, sorted,
in 4 KB pages, with the first owner of each page in a small top index inside
the layer's hint file. A storage read fetches one owner page per sealed layer
in its first round and skips every sealed layer that never touched the
contract. That removes the quiet-contract cost (27 requests becomes at most
one per sealed layer, all in one round). Accounts get no paged index: in a
random path's top five or six depths the nodes really did change, so the
layer must be asked there anyway. Bloom filters, SlateDB's choice (10 bits a
key per SST), were rejected here: an exact sorted list costs the same one page
and has no false positives.

## The rewrite

One partition at a time, lowest `as_of` first, in a background thread at low
priority:

1. Pick the finalized sealed layers the partition hasn't folded: those with
   `to_block` after its `as_of` and at or before the finalized block. Folding
   only finalized layers keeps the base free of anything a reorg can undo.
2. Stream the partition's current file from the bucket (one GET), merge it by
   key with the same range of each sealed layer (local files; seek by model),
   newest value wins, as `merge_layers` does today (`layer.rs:496-546`).
3. Write the new run to local scratch (at most about 1.1 GB), let the writer
   verify it, upload it under its hash.
4. Commit: write a new directory with this partition's file and `as_of`, and
   point the next manifest at it. Until then readers use the old file, which
   is still correct.

A rewrite is all or nothing per partition, so a crash or a spot preemption
loses at most one partition's work, and the next start picks the lowest
`as_of` again. This is SlateDB's resume rule with a much smaller unit.

**Cadence.** 513 partitions a day is one every 2.8 minutes. At the 50 MB/s the
tracker achieves today for the since-base rewrite (3,438 MB in 67.9 s,
including upload), the whole base is about 2 hours of work a day, plus the
read from the bucket and the writer's read-back. Estimate 2 to 4 hours a day
on the e2-medium; milestone 1 measures it before anything else is built.

## Collection

A partition's old file and a fully folded sealed layer are deleted once no
kept manifest references them, through its directory or its layer list.
Collection becomes a reference count per file over the kept manifests,
replacing the per-layer `manifest_runs` (`track.rs:2278-2289`). Kept manifests
are the last 128 (about an hour) plus the pinned finalized ones, so a reader
mid-session keeps its files for about an hour, as today. With soft delete off,
a deleted file stops costing at once.

## Fencing the writer

There is one tracker, but it runs on a spot VM restarted every hour, so two
can briefly overlap. Today every upload is a plain PUT
(`scripts/gcs-publish.sh:73`). Following SlateDB's conditional manifest
commits, the publisher writes pointers (`snapshots/latest`, `head/*`) with
`x-goog-if-generation-match` set to the generation it last wrote, kept in
`track.json`, and writes hash-named files with `ifGenerationMatch=0`
(create only). A tracker whose precondition fails stops. Content-addressed
files can't conflict, so only pointers need it.

## What it costs and what it should buy

| | Today | Rolling merge |
|---|---|---|
| Base age | grows (1.4 days now) | at most about one cycle (1 day) |
| Biggest rewrite | since-base, 3.4 GB and growing | one partition, about 1 GB |
| Step stall from merging | 68 s every 7.5 h, growing | none (background) |
| Tracker disk | grows with since-base | flat: sealed layers (about 5 GB) plus 1 GB scratch |
| Bucket operations | | plus about 513 PUTs and GETs a day, under $0.01 |
| Extra storage | | replaced files kept about an hour, about $0.30 a month |
| Quiet contract slot | 73 requests (base 47) | about 47 plus 3 hint pages (expected) |
| Absent account | 20 (base 10) | about 14 (expected) |

Transfer inside the region is free. The VM may need more CPU; if milestone 1
shows the rewrite starving the tracker, an e2-standard-2 spot is about $10 a
month more. The read numbers are expectations to be measured, not results.

## What we took from SlateDB, and what we didn't

- **Taken:** sorted runs split into key-range files listed by a manifest;
  folding a merge in range by range and committing as it goes (RFC 0035);
  resuming from durable progress; per-file skip structures; conditional
  commits that fence a second writer; deleting a file only when no kept
  manifest references it and it is old enough.
- **Simplified:** SlateDB views are per file and per key range, with fresh
  IDs on every split. Our layers are block ranges and a partition always folds
  whole layers, so a view is one block number per partition.
- **Not taken:** segments as separate LSM trees (RFC 0024; aimed at one active
  key prefix, like a time bucket, and explicitly not at writes spread over
  every segment, which is our case); write-ahead log and memtable (a block is
  our unit of write, and peers can resend it); the block cache (the browser's
  HTTP cache does it); the library itself (its point read is index block, then
  filter, then data block, each a request; ours fetches a whole trie path in
  one speculative round, in a browser, with every node verified).

## Alternatives rejected

- **Burst rebase on a large VM.** Works, but it is a periodic job with a 400 GB
  scratch disk, and the base is stale between runs.
- **Full rebase on the tracker with a temporary disk.** Four passes over
  351 GB on persistent disk, 4 to 8 hours each time; the same work as the
  rolling merge in one lump, with the since-base layer still growing between.
- **Many small partitions (4,096).** The directory grows to about 1 MB and a
  storage read touches seven partitions anyway; 256 is enough to make each
  rewrite small.
- **Leveled compaction.** Rewrites each level repeatedly (more write
  amplification) and adds levels a read must ask.

## Build plan

1. **Measure.** On the VM, rewrite one storage partition out of the
   monolithic base into a scratch prefix (not published): time, CPU, memory,
   and the tracker's step latency meanwhile. Go or no-go, and the cycle length.
2. **Fencing and paged owner hints**, independent of the rest. Owner hints go
   on the current since-base layer first, so the quiet-contract cost drops
   before the format changes. Measure.
3. **Manifest v4 and the directory**, with every partition pointing at the
   monolithic runs. Client routing by partition and top models from the
   directory; the tracker's diskless old-side reads routed the same way; the
   viewer showing partition files. No change in what readers see. Deploy.
4. **Sealed layers** replacing the since-base merge, and the client skipping
   sealed layers by `as_of`.
5. **The rolling rewriter and reference-counted collection.** Deploy, let the
   first cycle migrate the base, re-measure the read table.

Tests, synthetic as for the layers: partitions at mixed `as_of`; a crash in
each step of a rewrite; a directory that lies (a newer `as_of` hides a layer,
and the read must end in a refusal, because the base's older node won't hash
to its parent's reference; an older `as_of` only costs requests; a wrong file
fails its hash); an unfinalized sealed layer never folded; a reorg below a
sealed layer.

## Open questions

- **Cycle length.** One day is a guess that balances the rewrite load against
  the number of sealed layers a read asks; milestone 1 decides it.
- **Dead entries.** Merges keep nodes at positions no longer in the trie
  (`layer.rs:498-503`), and so would a partition rewrite, so the base slowly
  accumulates them. How fast is unmeasured. The account table is in pre-order
  and a rewrite could drop unreachable nodes in one pass, given the parent
  hashes at its partition's edge; the storage table is hashed and can't. Count
  them in a sealed layer before deciding.
- **Directory per open.** About 60 KB, compressed, once per session and cached
  until a partition commits. Acceptable, or page it by partition range?
- **Account partitions.** A walk touches the root's partition, the depth-1
  node's and then the leaf's, so up to three partitions; the top four levels
  are already cached across reads. Check this doesn't add a round.
