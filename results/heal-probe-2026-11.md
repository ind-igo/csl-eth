# The healing probe: keeping the full state current from peers' trie nodes

Run 2026-11-16, 09:04 to 14:02 UTC, on a temporary spot VM in `asia-east1-b`
(e2-standard-2, Debian 13, public IP, UDP 30303 open). The design it tests is
`docs/delta-producer.md`, "The healer". The question: can a process with no
node and no execution keep a path-keyed copy of mainnet's state current by
asking public peers for the trie nodes that changed, over snap/1
`GetTrieNodes`? And how fast, at what volume?

It can, block by block. Once healing was current and had 6 or more peers, it
healed each block from its parent in 6.7 s (p50). 94% of blocks finished
inside one 12 s slot. Every one of the 572 steps in that phase completed.
Peers to ask for trie nodes are the hard part: about 1 dial in 140 gets a
snap/1 peer, and only about 2 in 5 of those are at the head.

Code: `csl-eth heal-probe` (`crates/snap/src/heal.rs`), snap/1 trie-node
messages in `crates/snap/src/peer.rs`, the VM in `deploy/gcp/heal-probe.sh`,
the reduction in `scripts/heal-probe-summary.py`. Branch `heal-probe`.

## What the probe does

- **Peers.** It discovers peers over discv4 and the DNS tree like the
  fetcher, and offers `snap/1` only, because snap/2 drops the trie-node
  messages for block access lists. A peer whose head is more than 5 minutes
  old is dropped on connect ("behind"). So is a peer that answers nothing
  six times in a row.
- **The diff.** It walks from the root down, level by level. Where a node's
  hash at a path differs from the old trie's node at that path, it fetches
  the node at the new root (the healer's download) and the old node at the
  old root (a real healer has that on disk). Children whose hash at the same
  path is unchanged are skipped. Changed accounts lead into their storage
  tries the same way. An account whose leaf moved (an insert beside it), or
  that is new, is found by walking the old trie. Those steps ride the same
  waves of requests, mostly through nodes already fetched.
- **What it counts.** It counts what a path-keyed store would rewrite:
  hashed nodes whose (trie, path, hash) is new. Inline nodes are counted
  apart. Replies are matched to requests by hash, not by position. An
  in-memory test builds two tries and checks the counts equal the set
  difference exactly (`diff_counts_exactly_the_new_nodes`).
- **Each level is one wave.** The new and old sides go out together,
  spread over the connected peers, 48 to 384 paths per request. A missing
  node is retried on up to 4 peers. `levels` is the number of dependent
  round trips.
- **Two modes.** *Epoch* mode: one diff per 384 s between successive roots,
  and every peer asked for the root node at 17 ages behind the head.
  *Per-block* mode (`--per-block`): the base is the head, then each block
  is healed from its parent as soon as a peer has its header (polled every
  250 ms), back to back.

The VM ran epoch mode for 1.3 h, per-block mode for 3.0 h (887 blocks,
26,427,042 to 26,427,928), then epoch mode for 0.4 h.

## Per block

Per-block results, split at the point where healing caught up with the head
(65.9 minutes in, block 315 of 887):

| | all 887 steps | behind, then catching up (315) | caught up (572) |
|---|---|---|---|
| peers connected (min / p50 / max) | 1 / 7 / 11 | 1 / 5 / 6 | 6 / 8 / 11 |
| complete | 884 | 312 | 572 |
| heal time p50 / p90 / p99 / max, s | 7.6 / 12.5 / 21.9 / 99 | 9.5 / 15.3 / 20.2 / 99 | 6.7 / 9.8 / 22.2 / 42 |
| heal time within 12 s | 87.9% | 76.8% | 94.1% |
| root known after slot start, p50 / p90 / p99, s | 4.3 / 403 / 490 | 291 / 458 / 493 | 3.1 / 12.2 / 96 |
| heal done after slot start, p50 / p90 / p99, s | 12.5 / 414 / 502 | 303 / 473 / 504 | 10.1 / 24.1 / 108 |
| done within 12 s of slot start / within 24 s | 49% / 58% | 0% / 0.3% | 75% / 90% |
| dependent round trips (levels), p50 | 18 | 18 | 18 |
| time per round trip, p50 | 0.41 s | 0.52 s | 0.36 s |
| requests per block, p50 (both sides) | 123 | 96 | 133 |
| distinct peers that served, p50 | 7 | 5 | 8 |

*Heal time* runs from the moment the probe has the block's header to the
moment the diff completes. When healing is behind, the header is already
out when asked for, so this is pure heal time. *Done after slot* is
completion time minus the block's timestamp. It is the freshness a healer
would deliver, and it includes the 3 s or so a header takes to reach a peer
and be polled.

What changes per block (p50, all complete steps): 3,217 account-trie nodes
and 3,594 storage nodes. That is **2.35 MiB** of new nodes (p90 3.35 MiB, max
5.8 MiB) from 519 changed accounts, 22 of them new, and 128 changed storage
tries. The old side costs the same again (2.34 MiB), which a real healer
reads locally. Over 3 h the probe pulled 4.2 GiB from peers.

### Catching up, and peers dropping

The base was the head at 2.4 minutes. The first three steps had 1 peer and
did not finish (39 to 56 s, the peer dropped mid-diff). Twice there were
no peers at all ("no next header", at 4.7 and 6.3 minutes). By 19 minutes
the healer was 40 blocks (8 minutes) behind. With 3 to 6 peers it healed
faster than blocks arrive and worked the backlog down: 34 blocks behind at
14 minutes, 20 at 43, 5 at 60, level at 66. Catching up took about 47
minutes from the worst point. That is the margin between about 9.5 s per
block and 12 s per slot. One later blip, 6 blocks behind around minute 84
(a run of 20 to 38 s steps with 6 to 7 peers), cleared in about 4 minutes.

Heal time by peers connected, all steps:

| peers | steps | heal p50 | heal p90 | within 12 s | incomplete |
|---|---|---|---|---|---|
| 1 | 49 | 15.4 s | 20.0 s | 18% | 3 |
| 2 | 3 | 11.5 s | 12.4 s | 67% | 0 |
| 3–4 | 58 | 10.1 s | 12.0 s | 90% | 0 |
| 5–6 | 278 | 8.6 s | 13.0 s | 86% | 0 |
| 7–8 | 324 | 6.5 s | 10.1 s | 94% | 0 |
| 9+ | 175 | 6.2 s | 8.4 s | 99% | 0 |

One peer cannot keep up, and a single drop then loses the step. From 3
peers it keeps pace. From 7 it has headroom. Losing peers degrades it
smoothly into a backlog, which it recovers once peers return. It never ran
out of servable root: the backlog peaked near 40 blocks, and roots stay
servable to 127.

### Why 6.7 s, and what would cut it

The heal time hardly depends on how much changed: the correlation of heal
time with node count is 0.26. It is 18 dependent waves of about 0.36 s
each, so it is bound by round trips. Requests take 254 ms (Geth) and
260 ms (Nethermind) at p50 from Taiwan. Each wave also waits for its
slowest request. Three changes would cut it, none of them tried here:

- **No old side.** A real healer has the old trie, so it sends half the
  requests and moves half the bytes. The number of waves is unchanged.
- **Pipelining.** Request a node's changed children as soon as it arrives,
  instead of waiting for the whole level. The wait for the slowest request
  in each wave (about 0.1 s of the 0.36) goes away.
- **Known changed keys.** `GetTrieNodes` asks by path, and the hash only
  verifies. With the block's changed keys from EIP-7928 block access lists
  (Glamsterdam), every node on every changed path can be asked for in one
  or two waves, then verified bottom-up. That is about 1 s per block
  instead of 18 round trips.

## Per epoch: volume, and per-block against batched

Four epoch-mode diffs completed:

| blocks diffed | account nodes | storage nodes | new MiB | MiB per block | diff time | peers |
|---|---|---|---|---|---|---|
| 22 | 34,342 | 42,511 | 24.3 | 1.10 | 117 s | 2 |
| 79 | 91,291 | 119,992 | 63.5 | 0.80 | 188 s | 4 |
| 10 | 20,189 | 22,732 | 13.8 | 1.38 | 83 s | 3 |
| 107 | 125,263 | 142,741 | 79.8 | 0.75 | 157 s | 2 |

Four more did not complete: their peers dropped mid-diff, and 3,000 to 9,000
needs were left unservable.

Batching saves writes: the upper trie nodes are rewritten once per diff
instead of once per block. Healed every block, the store takes **2.35 MiB of
new nodes per block** (about 17 GB a day). Healed across 79 to 107 blocks,
it takes **0.75 to 0.80 MiB per block** (about 5.5 GB a day). Per-block
freshness costs about 3× the bytes written, and per-block layers. Diffs of
about 80 blocks took 157 to 188 s with 2 to 4 peers, 24 levels and 1,377 to
1,698 requests.

## How old a root stays servable

Each peer was asked for the root node at fixed ages behind the head (epoch
mode, all cycles):

| client | ≤ 16 | 32 | 64 | 96–124 | 127 | 128 | ≥ 129 |
|---|---|---|---|---|---|---|---|
| Geth (10 peers) | 10/10 | 8/10 | 7/10 | 5–7/10 | 5/10 | 5/10 | 0/10 |
| Nethermind (2) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 |
| ethrex (1) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 |

The window is 127 to 128 blocks, about 25 minutes: Geth's 128 diff layers,
and the same depth elsewhere. No peer served a root 129 or more blocks
back. Some Geth peers did not serve even recent roots; a few were probably
still syncing. In practice a healer has about 25 minutes to finish a step
before its old root is gone from the network. After that the only way
back is a range fetch (`docs/delta-producer.md`, fallback).

## Finding peers

| run | hours | dialed | snap/1 accepted | of which behind | hello without snap/1 |
|---|---|---|---|---|---|
| epoch | 1.33 | 4,920 | 41 | 25 | 424 |
| per-block | 3.00 | 7,680 | 53 | 30 | 555 |
| epoch | 0.42 | 2,472 | 14 | 10 | 173 |
| **total** | 4.75 | 15,072 | 108 (0.72%) | 65 | 1,152 |

- **Refusals.** Most refusals are "too many peers" (1,762 in the first
  run). Next come timeouts and connection resets.
- **Who served.** Of the 108 peers that accepted, 65 were behind the head,
  most of them Geth v1.16.7 instances hours behind. Serving came from Geth
  v1.16 and v1.17 (99.3% of asked nodes per request, mean) and Nethermind
  v2.1 to v2.2 (99.9%). Besu answered three requests in about 4 s each.
  ethrex served roots.
- **Errors.** Request errors were rare in the per-block run: 9 timeouts, 2
  disconnects out of about 106,000 requests.
- **Local run.** From a laptop behind NAT (no inbound UDP), 15 minutes of
  dialing found no usable peer. The healer needs a reachable host.

Peer supply decides the outcome. At about 1 usable peer per 300 dials, a
healer needs to dial continuously to hold 6 to 10 peers. It also needs to
survive Geth's peer dropper, which disconnects a random peer every 3 to 7
minutes when Geth is full.

## What it means for the healer

- **Per-block is feasible without a node.** It takes 6 to 8 peers, a
  reachable VM, and round trips from wherever the peers are. The state is
  typically one slot behind the head (done 10 s after slot start, p50),
  and up to 2 slots behind 90% of the time.
- **Machine.** The probe recorded no CPU or memory figures. Its work is
  network waits and hashing a few MiB per block, so a smaller VM is likely
  enough. The download is about 2.4 MiB per block new (half
  of the probe's 4.7). A spot e2-small or fafo-0 is the next thing to try. Disk is
  dominated by the stored deltas: about 17 GB a day per-block, or 5.5 GB a
  day batched every ~80 blocks, before compaction.
- **Cadence is a choice.** Per-block costs 3× the writes of batching across
  about 80 blocks. One option: heal every block for the attested tier's
  freshness, but publish compacted layers every epoch or so.
- **Main risk.** Long peer droughts like the first 20 minutes here. A
  drought longer than 25 minutes means the healer falls behind past the
  servable window and must fall back to range fetches. Over 4.75 h this
  never came close: the worst backlog was 8 minutes.

## Spend

The VM existed for 4 h 57 min (09:04 to 14:02 UTC) as a spot e2-standard-2
with a 30 GB pd-balanced boot disk and an ephemeral IP: well under a
dollar at list spot prices. This figure is an estimate from list prices,
not a billing export. Inbound traffic is free. The VM, its disk and the
firewall rule `csl-eth-heal-probe-discv4` were deleted at 14:02 UTC. The
raw JSON lines (31 MB) are not in the repo.
