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

```
cargo test --workspace
cargo test -p csl-eth-client --test e2e epsilon -- --nocapture   # ε against requests per read
```

## Status (2026-10-30)

Built and tested end to end on synthetic state (3,000 accounts, 1,000
storage tries, code inline and as blobs, a crafted extension): every
present key verifies, every absent key is proven by the trie with the shape
named, random byte flips, truncation and dropped pages end in
`Insufficient` or the right answer and never a false absence, and a
snapshot claiming a different `state_root` refuses to open.

Not yet built, in order: state acquisition over `snap` from mainnet peers
(reth's wire crates at `v2.9.0`), the head verifier over bucket files
(`helios-consensus-core`), an HTTP range `Bucket` and the remote-host
measurement, the content-addressed baseline client, the milestone 1
workload and fault table.
