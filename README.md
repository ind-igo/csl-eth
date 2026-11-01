# csl-eth

Ethereum state as static files, verified to the header. PoC 2 of the cold
state layer: the trie's own nodes, keyed by position, in sorted pages with
a learned index, served by any host that does byte ranges, and a client
that proves every value and every absence from `state_root` with no RPC
and no node at query time.

The profile and the plan live in the vault
(`wiki/projects/cold-state-layer/specs/profiles/ethereum.md`,
`specs/poc-ethereum.md`). The reasoning behind each choice here is in
`docs/decisions.md`. The format crates (`pgm`, `csl-run`) are the cinder
PoC's, used by path from `../cinder/crates/`, so both PoCs share one
implementation.

## Crates

| crate | what |
|---|---|
| `crates/trie` (`csl-eth-trie`) | node positions and table keys; a streaming builder from sorted leaves that emits every hashed node and agrees with alloy's `HashBuilder` root; the verifier walk (`Present` / `Absent` by trie shape / `Missing` / `Invalid`) |
| `crates/store` (`csl-eth-store`) | the bucket layout, the JSON manifest, and the producer: storage tries built and checked per account, the account trie checked against `state_root`, code checked against `codeHash`, four tables written through `csl-run` in the variable layout, code blobs above 3,968 B |
| `crates/client` (`csl-eth-client`) | the client as a state machine over a `Store` of fetched bytes: `try_account` / `try_storage` / `try_code` compute from what the store holds and return `Pending` with the round's wants (`Want::Range`, `Want::File`) when they need more; a `Driver` (a directory, HTTP over threads) fetches each round for the synchronous `account` / `storage` / `code`; one speculative round over depths `0..=D`, the walk, repairs, with requests, bytes and rounds per read |
| `crates/head` (`csl-eth-head`) | the beacon light-client protocol from files: `head/bootstrap/<root>`, `head/updates/<period>`, `head/finality`, verified with helios-consensus-core from one checkpoint root to the finalized execution block |
| `crates/wasm` (`csl-eth-wasm`) | the client and the head verifier for the browser: wasm-bindgen bindings over the step loop (`open` / `account` / `storage` / `code` return a `need` list, `supply` hands bytes back, `step` continues to `done`); the page fetches every round with `Promise.all` |
| `crates/snap` (`csl-eth-snap`, bin `csl-eth`) | mainnet state with no node: peers from the EIP-1459 DNS tree and discv4, RLPx with eth/68–69 and snap/1–2 over reth's wire crates, account and storage ranges verified by rebuilding, bytecode by hash; `fetch` writes a slice, `build` makes a bucket from it with the range proofs as the trie boundary |

```
cargo test --workspace
cargo test -p csl-eth-client --test e2e epsilon -- --nocapture   # ε against requests per read
cargo build --release -p csl-eth-snap
./target/release/csl-eth peers                                   # dial five mainnet peers
./target/release/csl-eth fetch --prefix 1a7 --out data/slice-1a7 # 1/4096 of mainnet state
./target/release/csl-eth build --slice data/slice-1a7 --out data/bucket-1a7
```

## Status (2026-10-31)

Built and tested end to end on synthetic state (3,000 accounts, 1,000
storage tries, code inline and as blobs, a crafted extension): every
present key verifies, every absent key is proven by the trie with the shape
named, random byte flips, truncation and dropped pages end in
`Insufficient` or the right answer and never a false absence, and a
snapshot claiming a different `state_root` refuses to open. A path-prefix
slice built from range-proof boundaries verifies inside, proves absence
inside, and ends `Insufficient` outside (`tests/slice.rs`).

The first mainnet slice is in: 1/4096 of state at block 26,305,903 fetched
over snap from one peer in two minutes (104,361 accounts, 129,555 slots,
2,168 bytecodes, 17.9 MB), built into a bucket that proves to the header's
`state_root`, and read back with the client: every sampled value verified,
absence proven inside the prefix, `Insufficient` outside. On the wire
(`check --url`, a bucket behind HTTP) an account read at ε = 1 is 6.7
range requests and 27 KB, or one round of 12 requests and 48 KB with the
predicted page and its neighbours prefetched; the table's pre-order puts a
path's deeper nodes on the same pages. Against the same bucket on
Cloudflare R2, read from Taipei through a VPN (one range request about
105 ms), an account read is 829 ms sequential and 131 ms with the predicted
pages ± 1 prefetched as merged ranges and the top four trie levels kept
across reads: 3 requests, 37 KB (44 at p95), one round trip and a quarter.
Numbers and reasoning in `docs/decisions.md`.

The head is in, and the chain of trust closes on one block. `head/` holds
the beacon light-client objects as files (bootstrap, period updates,
finality update), verified offline with `helios-consensus-core` from one
weak-subjectivity checkpoint root; forged or misplaced files are rejected
with the step named (`crates/head/tests`). The client's `open_at_head`
reads only at the finalized block's `state_root` and refuses a bucket with
no snapshot there. The producer fetches at the epoch-boundary block as soon
as it exists (`fetch --pivot-at next`), since that is the block finality
will name 13 to 19 minutes later, and writes the head files once it does.
Run live on 2026-10-31 from two machines at once: both pivoted on block
26,311,778 and fetched the same slice (17 MB, 14 to 24 seconds of transfer,
2 to 3 peers), the finality update named it, and `check --checkpoint`
verified every sampled value through the head, locally and on R2 (head: 5
requests, 117 KB once; then the same 3 requests and 37 KB per account read
as before). Finding peers is the hard part: mainnet nodes are full, and about one dial in a hundred is accepted,
most of those for under a minute.

```
./target/release/csl-eth head fetch --bucket data/bucket-fin          # bootstrap, updates, finality from a beacon node
./target/release/csl-eth check --slice data/slice-fin --bucket data/bucket-fin --checkpoint 0x<root> --prefetch 1 --top-levels 4
```

```
./target/release/csl-eth check --slice data/slice-1a7 --bucket data/bucket-1a7
./target/release/csl-eth check --slice data/slice-1a7 --url https://host/bucket --prefetch 1 --top-levels 4
```

The client runs in the browser: `crates/wasm` compiles the client and the
head verifier to WebAssembly, `browser/` is a page that opens the R2 bucket
through the head and reads accounts, storage and code with each answer's
status and cost. The client does no I/O: `browser/src/client.ts` drives its
`need` / `supply` / `step` loop, fetching every round's ranges at once from
the main thread (`cache: "no-store"`, or Chromium queues same-URL ranges
behind its cache lock). Deployed at https://csl-eth.indigo-db8.workers.dev;
`?open` opens on load, `?bucket=<url>&checkpoint=<root>` change the inputs.
From Taipei through a VPN: the head in 8 requests and 5 rounds (about 1 s),
an account in 2 to 4 requests and one round (120 to 310 ms), a storage slot
in 10 requests and one round (250 to 310 ms).

```
mise install                      # rust + wasm32 target + llvm-tools, bun, wasm-bindgen-cli
./scripts/build-wasm.sh           # browser/pkg/
cd browser && bun install && bun run serve      # http://127.0.0.1:8791/
bun run site && (cd deploy && cf deploy)        # assemble browser/site and deploy it
```

The model is fetched by key (2026-10-31): `csl-run` pages the model section
under a tree with a top model on page 0, so a client reads 4 KB of model per
key neighbourhood instead of the whole model (45 MB per snapshot at full
state), and a cold neighbourhood costs one round before its data pages.
Measured against R2: accounts 2.7 requests, 37 KB, one round (two when cold),
135 ms p50; the page shows the model pages a read fetched.

The content-addressed baseline (2026-10-31) reads the same state by node
hash from `nodes_by_hash`, one dependent round per node: `check --baseline`
and the page's "baseline (by hash, serial)" toggle. Against R2, uncached:
8.9 rounds, 106 KB, 1162 ms p50 per account against 1 round, 48 KB, 118 ms
path-keyed; the baseline uses fewer bytes only on storage (76 against 130 KB).

Milestone 1 is closed: `csl-eth workload` and `csl-eth faults` are its exit tests, and `results/m1.md` walks the PoC spec's exit table row by row (zero false answers in 86,368 workload reads and 23 aimed faults; path-keyed account reads 40 KB and one round at p95 on R2).

The visualizer is at https://csl-eth.indigo-db8.workers.dev/viz.html (`browser/viz.html`, `browser/src/viz/`): the chain of trust lighting as the head verifies, the trie path node by node from the state root, every page of every table with each request's pages lit in its round's colour, and a waterfall of the rounds on the real clock. It can race the path-keyed read against the by-hash baseline on two cold clients, flip a byte of a fetched page to show the client refuse, and replay a read in slow motion. Everything drawn comes from the tab's own client: the requests from the driver's log, the nodes from the trace each read now returns (`done.trace`: per node its depth, kind, hash, the slot taken and the run-file page it was read from).

Not yet built, in order: a producer loop that follows finality (a frozen snapshot stops opening once the sync-committee period after its finality update begins), the head's period updates batched into one round.
