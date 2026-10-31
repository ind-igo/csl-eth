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
| `crates/client` (`csl-eth-client`) | `Snapshot::open(bucket, block, state_root)` then `account`, `storage`, `code`: one speculative round over depths `0..=D`, the walk, repair rounds, with requests, bytes and rounds per read |
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
Numbers and reasoning in `docs/decisions.md`. Finding peers is the slow part: about one
dial in a hundred is accepted.

```
./target/release/csl-eth check --slice data/slice-1a7 --bucket data/bucket-1a7
./target/release/csl-eth check --slice data/slice-1a7 --url https://host/bucket --prefetch 1 --top-levels 4
```

Not yet built, in order: the model section fetched by key (the per-snapshot
budget for a following client), storage speculation in the account's round,
the head verifier over bucket files
(`helios-consensus-core`), the content-addressed baseline client, the
milestone 1 workload and fault table.
