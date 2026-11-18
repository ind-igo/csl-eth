# Cold state light client: Ethereum light clients in about 1,000 lines of code

**WASM Demo (410 kb):** https://storage.googleapis.com/csl-eth-demo/index.html to read up to date mainnet state in your browser.
**Minimal Demo (61 kb):** https://storage.googleapis.com/csl-eth-demo/light.html

## What is it?

An experimental light client for Ethereum mainnet, running completely in the browser and utilizing object storage, removing the RPC dependency for access to the chain. Instead, we rely on static self-verifying files, a lightweight index algorithm, and any old file serving protocol (in this case object storage but could be anything, including a p2p network). The full demo light client is a 410kb wasm implementation that runs in the browser, and alongside there is a minimal 61kb version written in typescript.

## Why?

I've been frustrated with the progress on light clients. Light clients are the end goal way for access to Ethereum. However, access is currently gated by an (paid) RPC dependency. All previous major light client proposals (LES, Portal) failed due to incentivization issues around who serves state.

This project is aimed to give a alternative design that is cheaper and practical, utilizing modern database techniques and can be implemented today with no protocol changes. I am starting with the current state, but the techniques used can be applied to history as well to create archival nodes.

## How? 

Inspired by Open Table Formats (OTF) like Iceberg which create highly scalable databases on top of object stores, CSL utilizes a type of database index called a **Learned Index**, along with **self-validating files**, and a normal object store to create an OTF specifically for validating and serving Ethereum state.

The **Learned Index**, in contrast to a classical tree-based index, is a small model of how the keys are spread across the pages, which makes it extremely lightweight compared to a tree-based index. Our learned index is about **2.7 MB** to index the entire Ethereum current state. An equivalent B-Tree index would be **2.8 GB** with full 32-byte keys, or around **700 MB** with 8 byte keys, a **250-1000x** difference. This is what allows the light client to be so small. The tradeoff is that it takes more requests to get the result, an acceptable tradeoff for the massive portability increase.

The resulting light client is a ~1000 line file that can be written in any language. See skills/csl-eth-light-client/SKILL.md for an AI skill to make them, and browser/light/verify.ts for a simple typescript implementation.

## How a read is verified

1. **Head.** `head/` holds the beacon light-client objects as files: a bootstrap, one update per sync-committee period, and the latest finality and optimistic updates. The client verifies them from one checkpoint root, requires 342 of 512 signatures, and ends with an execution block hash and state root.
2. **Snapshot.** The snapshot's manifest must name that block and state root.
3. **State.** The trie's own nodes are stored by position in sorted 4 KB pages, with a small learned index that predicts a key's page. The client fetches the path from the root in one speculative round and hashes it up to the state root. Absence is proven by the trie's shape.

## Trust Assumptions, Tradeoffs and Implications

The biggest trust assumption is that there needs to be a full node or some service that is propagating the latest block to the bucket. My prototype has a custom tracker service doing this rather than running a full node, however a full node would be the appropriate source.
The learned index is orders of magnitude smaller in size than a tree-based index, but it instead has a bounded error (ε). The error is configurable, however what it means is a query for a specific piece of state requires multiple requests. This means more total data is requested, which means higher egress and stress on the network. However there are multiple optimizations like batching and caching that reduce the impact of this significantly. You can see this in the demo page, where each read query breaks down how many requests are made, how many total round trips, and how much data gets transferred.

----

## More detail

**What is trusted.** One beacon checkpoint and an honest two thirds of the
sync committee. Everything else is checked: the head by signatures and
Merkle branches, every trie node by its hash, and absence by the trie's
shape. The bucket is never trusted; a wrong or missing byte ends in a
refusal, never a wrong answer. Reads default to the latest signed head,
which can be reorged out; `?tier=finalized` reads the last finalized block,
about 13 minutes behind.

**What is in the bucket.** All of mainnet's current state: a snapshot
(432 M accounts, 1.69 B storage slots, about 350 GB) plus small update
layers of changed trie nodes, merged over time so a read asks only a few.

**How it stays current.** A tracker follows the chain about 35 seconds
behind without running a node. For each new head it asks mainnet peers for
the trie nodes that changed, checks each by hash, and publishes them as a
layer. It costs about $30 a month. A full node could publish the same
layers as a side effect, which is the natural next step.

**Copies are cheap.** One copy of the bucket costs about $3–15 a month to
store and keep current, and any static host can serve one; see
`docs/replication-cost.md`.

## Limits

- **The snapshot ages.** The layer since the snapshot grows about 2 GB a
  day until it is folded into a new snapshot, which is not automated yet.
- **The tracker depends on peers** that still serve `snap/1`
  `GetTrieNodes`. A full node publishing layers would remove that.
- **State only.** No contract calls (`eth_call`), only recent history, no
  archive state, and no sending transactions.
- **Checkpoints age out** after the weak-subjectivity period. The page and
  the tracker each rotate theirs, adopting a newer one only after proving
  it from the one they hold.
- **Gloas** (EIP-7732) removes the state root from the light-client header,
  so the head check will need another source for it after that fork.

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
