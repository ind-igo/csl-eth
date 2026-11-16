# csl-eth

Ethereum state as static files, verified to the block header. A client in
the browser reads mainnet accounts, storage and code from a plain bucket by
byte range, and proves every value and every absence from the state root the
beacon chain signed. No RPC and no node at read time. This is PoC 2 of the
cold state layer; PoC 1 (cinder) built the same layer on a chain of its own.

- **Client:** https://storage.googleapis.com/csl-eth-demo/index.html?open
- **Visualizer:** https://storage.googleapis.com/csl-eth-demo/viz.html shows
  each read's proof node by node, lets you flip a byte to watch the client
  refuse, and races the read against a by-hash baseline. Nothing on it is
  simulated.

The page is served from the same Cloud Storage bucket it reads, so the whole
demo is one bucket and one small VM that publishes to it.

**Scope:** the bucket holds two things.

- **All of mainnet's state at one block** under `full/` (block 26,422,083,
  finalized; 432 M accounts, 1.69 G storage slots, 344 GiB), with the last
  22,084 blocks of transactions, receipts and logs beside it:
  https://storage.googleapis.com/csl-eth-demo/index.html?open&bucket=https://storage.googleapis.com/csl-eth-demo/full&tier=finalized
- **1/4096 of mainnet state, kept fresh** (account-trie prefix `1a7`, about
  105,000 accounts), refreshed every epoch. A key outside the prefix answers
  `Insufficient`, never a false absence.

## How a read is verified

1. **Head.** `head/` holds the beacon light-client objects as files: a
   bootstrap, one update per sync-committee period, and the latest finality
   and optimistic updates. The client verifies them with
   `helios-consensus-core` from one checkpoint root, requires 342 of 512
   signatures, and ends with an execution block hash and state root.
2. **Snapshot.** The snapshot's manifest must name that block and state root.
3. **State.** The trie's own nodes are stored by position in sorted 4 KB
   pages, with a small learned index that predicts a key's page. The client
   fetches the path from the root in one speculative round and hashes it up to
   the state root. Absence is proven by the trie's shape.

The bucket is never trusted. A wrong byte, a missing page or a snapshot for
another block ends in a refusal or `Insufficient`, not a wrong answer. The
trust inputs are the checkpoint root and an honest two thirds of the sync
committee.

There are two tiers. **Attested** is the default: the committee signed the
block as head, and it can still be reorged out (the page says so).
**Finalized** (`?tier=finalized`) means Casper finalized it, about 13 minutes
later. When the producer has one, the page also shows Ankr's fast-confirmation
report as a named source's claim, which the client does not verify.

## Numbers

Read cost against Cloudflare R2, from Taipei through a VPN
(2026-10-31 to 11-01, `results/m1.md`; not yet re-measured on Cloud Storage):

- **Account:** 2.7 requests, 37 KB, one round (two when its index pages are
  cold), 135 ms p50.
- **Storage slot:** 10 requests, one round, 250 to 310 ms in the browser.
- **By-hash baseline**, one round per trie node: 8.9 rounds and 1,162 ms p50
  per account, against one round and 118 ms by path, uncached.
- **Opening the head**, once per session: 13 requests in 4 rounds, 248 KB
  (on loopback, 2026-11-03).
- **Correctness:** zero false answers in 86,368 workload reads and 23 aimed
  faults.

Freshness in production (fafo-0 publishing to R2, 258 cycles, 2026-11-06
11:34 to 11-08 12:51 UTC):

- **Snapshot age a reader sees**, averaged over time: median about 14
  minutes, p90 39, p99 73, max 91.
- **Cycles:** 200 of 258 published. 53 failed because no snap peer could be
  found within 21 minutes, and 5 missed the attested update.
- **Publish lag** of a successful cycle: 1.7 minutes after its block (median;
  p90 7.5). Almost all of it is the fetch; building takes about 1 s and
  publishing about 6 s.

The lag comes from how this PoC gets state. It has no node, so every cycle
fetches the slice again over devp2p `snap` from mainnet peers, which accept
about one dial in a hundred. The verifiable floor is much lower: the
optimistic update for a block arrived 15.5 s after it (median). An earlier
five-cycle run on a laptop measured 1 to 11 minutes; production is the number
above. Details in `docs/decisions.md`.

## Limits

- **Full state is one block.** One burst (`deploy/gcp/full-export.sh`: reth's
  snapshot, a sync, a 2.4 h export, a 2.4 h upload, about $7) publishes it;
  keeping it current is a diff of changed trie nodes per snapshot, not built.
  Cold reads against it, from Taipei: an account in 4 rounds and 80 KB
  (843 ms), a storage slot in 7 rounds and 280 KB.
- **History is recent.** `full/history/` covers the 22,084 blocks the node
  kept (three days). Old headers cost a walk (6.4 MB for a transaction a day
  back) until the beacon accumulator's files are published. History from
  genesis is sized (about 4.9 TB, about $100 a month) but not run.
- **The producer needs care.** It restarts under systemd, but nothing alerts
  when cycles fail, and each failed fetch costs about four epochs.
- **The checkpoint.** The default root (slot 15,661,216, 2026-11-15) must be
  replaced before it leaves the weak-subjectivity period, around the end of
  November.
  The page also accepts `?checkpoint=` and `?bucket=` from the URL without a
  warning.
- **Gloas.** EIP-7732 removes the state root from the light-client header, so
  after that fork the head verifier needs the execution header from another
  source.

## Build

| crate | what |
|---|---|
| `crates/pgm` | the learned index (piecewise-linear, Q0.64), from cinder |
| `crates/csl-run` | run files: sorted pages under a blake3 tree, the paged model, writer and verifying reader, from cinder at `ba2b9d8` |
| `crates/trie` | node positions, a streaming trie builder, the verifier walk |
| `crates/store` | the bucket layout, manifest, and building a bucket from verified state |
| `crates/client` | the client as a sans-I/O state machine: each read returns the ranges it needs next |
| `crates/head` | the beacon light-client protocol from files, verified with helios |
| `crates/wasm` | the client and head verifier for the browser |
| `crates/snap` | bin `csl-eth`: mainnet state over devp2p `snap` with no node; `fetch`, `build`, `check`, `produce` |

```
cargo test --workspace
cargo build --release -p csl-eth-snap
./target/release/csl-eth fetch --prefix 1a7 --out data/slice-1a7      # 1/4096 of mainnet state
./target/release/csl-eth build --slice data/slice-1a7 --out data/bucket-1a7
./target/release/csl-eth check --slice data/slice-1a7 --url https://host/bucket --prefetch 1 --top-levels 4

# the producer: a snapshot every epoch, published under the attested head, upgraded when finalized
./target/release/csl-eth produce --prefix 1a7 --work data/produce --checkpoint 0x<root> \
    --publish scripts/r2-publish.sh --every-mins 6 --keep 10   # CSL_ETH_FCR_RPC adds the FCR note

# the browser page
mise install && ./scripts/build-wasm.sh
cd browser && bun install && bun run serve                     # http://127.0.0.1:8791/

# the demo on Google Cloud (project csl-eth): bucket, VM, network, in one Alchemy stack
cd infra && bun install && bun run plan && bun run deploy --yes
deploy/gcp/apply.sh        # build the producer on the VM, run it under systemd
deploy/gcp/site.sh         # build the page, upload it into the bucket
```

The producer publishes with `scripts/gcs-publish.sh`, as the VM's service
account; pointers are served `no-cache` and hash-named files `immutable`.
The reasoning behind each choice is in `docs/decisions.md`, in the order it
was made.
