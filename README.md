# csl-eth

Ethereum state as static files, verified to the block header. A client in
the browser reads mainnet accounts, storage and code from a plain bucket by
byte range, and proves every value and every absence from the state root the
beacon chain signed. No RPC and no node at read time. This is PoC 2 of the
cold state layer; PoC 1 (cinder) built the same layer on a chain of its own.

**Demo:** https://storage.googleapis.com/csl-eth-demo/index.html opens all of
mainnet's state, verifies the head and reads vitalik.eth on its own, then
shows each read's requests and its proof node by node. A checkbox flips one
byte of a fetched page to show the client refusing it. Nothing on it is
simulated.

**Scope:** all of mainnet's state, current to the head, under `full/` in the
bucket. A base at block 26,422,083 (432 M accounts, 1.69 G storage slots,
344 GiB) carries layers of changed trie nodes that `csl-eth track` publishes
block by block from a small spot VM with no node and no copy of the base: it
fetches the changed nodes from mainnet peers over devp2p `snap/1`, reads
them back, and publishes each block about 35 s after its slot starts (the
attested tier) and each finalized checkpoint about 13 minutes later. The
last 22,084 blocks before the base of transactions, receipts and logs sit
beside it. The page is served from the same Cloud Storage bucket it reads.

Before the full state, the PoC kept 1/4096 of the state (account-trie prefix
`1a7`) fresh every epoch, fetched over devp2p `snap` with no node. That
producer is stopped (2026-11-16) and its R2 bucket and Worker deleted
(2026-11-17); its numbers below are kept for the record.

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

**Keeping it current** (`csl-eth track` on an e2-medium spot VM in the
bucket's region, 2026-11-17; `docs/decisions.md` has the detail):

- **Per block,** over 31 minutes at the head: all 162 blocks published, in
  92 steps (59 of one block). Lag from the slot's start to the published
  pointer: median 35 s, p90 46 s. Of that, the light client knows the
  attested head 20 s after the slot starts; fetching and diffing the changed
  nodes takes 9 to 15 s, reading them back 1.1 s (a sample, since; it was
  3.6 s), uploading 1.1 s. No block was published within its own slot.
- **Finalized:** each finalized checkpoint's block gets its own step, so
  `head/finality` moved every epoch (five in a row in the window).
- **Catch-up:** the first, 8,903 blocks (about 30 hours) from the base,
  wrote 1.21 M changed accounts as 10.2 M trie nodes (2.45 GB of runs) and
  uploaded 3.05 GB in 1,402 files. Its last attempt took 27 minutes (fetch 7,
  materialize 7, build and read-back 9, upload 4); the bucket served the old
  side by range, about $7 of reads.
- **Reads over layers,** cold, against the base alone, eight layers: an
  account 0.85× the requests, an absent account 1.9×, a slot of a contract
  that changed recently 1.6× to 1.7×, a slot of USDT 1.5× (3.5× before
  storage hints by contract and path), WETH 2.2× (path hints for owners
  with 16 or more changed nodes, kept through merges for owners hot
  lately; WETH's re-measure waits for the older merged layers to go). Most of what remains is
  the since-base layer, which carries no hints (`docs/decisions.md`).
- **Cost:** about $30 a month (the VM and its disks about $22, about
  50,000 writes a day about $8), plus about $3.60 of bucket reads per day of
  gap when it has to catch up.

The full state on Cloud Storage, cold, in headless Chromium from Taipei
(2026-11-16, no VPN): the page loads, verifies the head and reads an account
in 0.7 s. An account takes 3 to 5 rounds and about 80 KB (about 220 to
260 ms), a storage slot 7 rounds (540 ms), an absent account 3 rounds
(230 ms).

Earlier, the slice against Cloudflare R2, from Taipei through a VPN
(2026-10-31 to 11-01, `results/m1.md`):

- **Account:** 2.7 requests, 37 KB, one round (two when its index pages are
  cold), 135 ms p50.
- **Storage slot:** 10 requests, one round, 250 to 310 ms in the browser.
- **By-hash baseline**, one round per trie node: 8.9 rounds and 1,162 ms p50
  per account, against one round and 118 ms by path, uncached.
- **Opening the head**, once per session: 13 requests in 4 rounds, 248 KB
  (on loopback, 2026-11-03).
- **Correctness:** zero false answers in 86,368 workload reads and 23 aimed
  faults.

The slice's freshness in production (fafo-0 publishing to R2, 258 cycles,
2026-11-06 11:34 to 11-08 12:51 UTC):

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

- **The base is one block, and the layers grow.** One burst
  (`deploy/gcp/full-export.sh`: reth's snapshot, a sync, a 2.4 h export, a
  2.4 h upload, about $7) published the base. The layer since the base grows
  about 2.3 GB a day and carries no skip hints (it is too large), so every
  read asks it, and it is now most of a read's extra cost (10 to 28 requests
  for a slot). Folding it into a new base (a rebase, a burst) is not built.
- **It depends on peers serving `snap/1`.** The tracker has no node: it
  needs mainnet peers that answer `GetTrieNodes` at the head, which snap/2
  removes. A restart used to take 2 to 26 minutes to find three such peers;
  the peers that served are now kept on disk and dialed first, and a restart
  has five within a minute. A step that
  no peer can serve re-pivots to a newer head.
- **History is recent.** `full/history/` covers the 22,084 blocks the node
  kept (three days). Old headers cost a walk (6.4 MB for a transaction a day
  back) until the beacon accumulator's files are published. History from
  genesis is sized (about 4.9 TB, about $100 a month) but not run.
- **HTTP/3 through a VPN.** Through Mullvad (Manila relay, 2026-11-16) the
  page hung loading: Chrome's HTTP/3 to storage.googleapis.com stalled, first
  because the tunnel's MTU (1,320) was below Google's QUIC packets, then, at
  MTU 1,420, because bulk UDP through the relay crawled (600 KB from
  Cloudflare in 13 to 18 s over HTTP/3, 0.08 s over TCP). Without the VPN the
  page opens, verifies the head and reads an account in 0.7 s, all over
  HTTP/3. Behind such a VPN, turning QUIC off in Chrome fixes it.
- **The checkpoint.** The page's built-in root (slot 15,661,216, 2026-11-15)
  ages out of the weak-subjectivity period around the end of November, but
  a visitor moves past it. Once a period, the tracker publishes a newer
  finalized root's bootstrap and a pointer, `head/checkpoint`. After each
  open, the page adopts that root only if the open proved it finalized from
  the root it held, then remembers it in localStorage (`docs/decisions.md`).
  The tracker moves its own root the same way. A first visit still starts
  from the built-in root. `?checkpoint=` pins a root and is never rotated.
  The page accepts it and `?bucket=` from the URL without a warning.
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
| `crates/snap` | bin `csl-eth`: mainnet state over devp2p `snap` with no node; `fetch`, `build`, `check`, `produce`, `track` |

```
cargo test --workspace
cargo build --release -p csl-eth-snap
./target/release/csl-eth fetch --prefix 1a7 --out data/slice-1a7      # 1/4096 of mainnet state
./target/release/csl-eth build --slice data/slice-1a7 --out data/bucket-1a7
./target/release/csl-eth check --slice data/slice-1a7 --url https://host/bucket --prefetch 1 --top-levels 4

# the producer: a snapshot every epoch, published under the attested head, upgraded when finalized
./target/release/csl-eth produce --prefix 1a7 --work data/produce --checkpoint 0x<root> \
    --publish scripts/r2-publish.sh --every-mins 6 --keep 10   # CSL_ETH_FCR_RPC adds the FCR note

# the tracker: keep a full-state base current from mainnet peers, the base left in the bucket
./target/release/csl-eth track --root data/track/root --work data/track/work --base 0x<base block hash> \
    --base-url https://storage.googleapis.com/csl-eth-demo/full/ --checkpoint 0x<root> \
    --publish scripts/gcs-publish.sh

# the browser page
mise install && ./scripts/build-wasm.sh
cd browser && bun install && bun run serve                     # http://127.0.0.1:8791/

# the demo on Google Cloud (project csl-eth): bucket, VM, network, in one Alchemy stack
cd infra && bun install && bun run plan && bun run deploy --yes
deploy/gcp/apply.sh        # build the tracker on the VM, run it under systemd
deploy/gcp/site.sh         # build the page (gzipped), upload it into the bucket
```

The producer publishes with `scripts/gcs-publish.sh`, as the VM's service
account; pointers are served `no-cache` and hash-named files `immutable`.
The reasoning behind each choice is in `docs/decisions.md`, in the order it
was made.
