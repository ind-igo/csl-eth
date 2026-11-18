# What it costs to replicate the bucket

Cost note, 2026-11-17. Estimates from list prices, several taken from secondary sites (sources at the end); check them on the providers' own pricing pages before quoting. The measured numbers come from the tracker's log on `csl-eth-producer`.

## The question

The usual objection to serving Ethereum state from object storage is that it centralizes on whoever hosts the bucket. The files check themselves: every read hashes up to a state root the sync committee signed, so a host can stall a reader but never lie to one. A host is trusted for liveness only, and liveness is bought with copies. So the question is what copies cost, and how that compares with the full nodes that serve state today.

## What one copy needs (measured)

- **Size: about 360 GB.** The snapshot at block 26,422,083 is 351 GB (account nodes 94.3 GB, storage nodes 254.5 GB, code 2.46 GB). The layers since then add a few GB; the largest, everything since the snapshot, was 4.04 GB at its last merge and grows about 2.3 GB a day until a rebase.
- **Updates: about 20 GB a day, about 600 GB a month.** From the tracker's log: 36.8 GB uploaded over 12,833 blocks, about 2.9 MB a block, at about 7,200 blocks a day. That includes the merges' rewrites. A copy that did its own merging would pull only the per-block layers, roughly 14 GB a day (about 2 MB a block in recent steps).
- **Writes: about 15,000 to 50,000 files a day.** 12,301 files in the same span, plus manifests and head files.
- Replaced files are deleted after a grace period, so a copy stays near 360 GB rather than accumulating the 600 GB a month it receives.

## One copy, per month

| | Big cloud (GCS, S3), regional | Budget host (Backblaze B2) |
|---|---|---|
| Storage | $7–8 (0.36 TB at about $20–23/TB) | about $2.50 (at $6.95/TB) |
| Writes | $2–8 (at about $5 per million) | free |
| Upload into the copy | free | free |
| **Total, before feeding it** | **about $10–15** | **about $3** |

**Feeding the copy is the cost that matters.** 600 GB a month has to come from somewhere:

- from a host with free egress, or from other copies passing updates along: about $0;
- between regions of the same big cloud: $0.02/GB in North America and Europe, about $0.08/GB in Asia, so $12–48 a month;
- out of a big cloud to the internet, at about $0.08–0.12/GB: $50–70 a month, several times the storage.

Backblaze includes free egress up to three times the data stored, about 1 TB a month for a 360 GB copy: enough for each copy to feed one or two others. A tree of copies, each fed by a parent, keeps the feed near free.

## Thought experiment 1: one copy per million people

About 8,200 copies (8.2 billion people).

- Storage and writes: $25k a month on budget hosts, up to $125k on big clouds. **About $0.3–1.5M a year.**
- Fed naively, every copy pulling 600 GB a month out of one big-cloud bucket: about $400k a month more. Fed as a tree or from free-egress hosts: close to nothing.

## Thought experiment 2: every major cloud region

The six largest providers had 238 public regions in January 2026. About 240 copies:

- Storage and writes: about $2.5–3.5k a month.
- Feeding them across regions: $3–12k a month.
- **About $5–15k a month, $60–180k a year.**

## Against the full nodes that serve state now

- Ethereum has roughly 8,000 to 14,000 execution nodes, depending on the counter (ethernodes about 8,000–9,000; Etherscan about 11,800; other trackers higher).
- A full node costs about $60–100 a month on a dedicated server and $250–300 in the cloud. Our own estimate for one in the bucket's region was $250–283 (n2-standard-4 and 700 GiB pd-ssd; `docs/delta-producer.md`).
- The fleet is therefore roughly $1–3M a month.

| | Monthly | Equivalent |
|---|---|---|
| One copy | $3–15 | 1/20 to 1/100 of one full node |
| A copy in every major cloud region (~240) | $5–15k | 20–60 cloud full nodes |
| A copy per million people (~8,200) | $25–125k | 1/10 to 1/40 of the existing node fleet |

## What the comparison does and does not say

- **Copies do not replace nodes.** Nodes validate the chain; copies only serve its state. The fair comparison is the cost of serving state to light clients, which today falls on RPC providers or, through the P2P network, on full nodes that carry the load unpaid.
- **Serving cost scales with readers, not with copies.** More copies split the same traffic. A read moves tens to hundreds of KB (an account read about 80–100 KB; a busy contract's slot more while layers are unmerged), which is $5–10 per million reads on paid-egress hosts at today's sizes and about the request fees alone on free-egress ones.
- **Anyone can add a copy.** The files are named by hash and verify themselves, so any bucket, CDN or plain web server can serve them, without permission and without being trusted. The copy count is not ours to set.
- **One honest copy is enough.** A client that knows several hosts falls back from one that stalls or lies; the lie is caught by the hashes, the stall by a timeout.
- **The update producer is the other dependency.** Today it is the tracker, which needs no Ethereum node (about $60 a month since the VM became e2-standard-4). In the end state any full node publishes as a side effect (a reth ExEx). Both are open to anyone, but someone has to run one, and the post should say so.

## Sources

- [ethernodes.org: nodes by country](https://www.ethernodes.org/countries)
- [CoinLaw: Ethereum statistics 2026](https://coinlaw.io/ethereum-statistics/)
- [Coinspectator: Ethereum's real node count is 10,000 to 20,000](https://coinspectator.com/mainstream/2026/10/05/ethereum-is-far-and-away-the-most-decentralized-ledger-its-real-node-count-is-10000-to-20000/)
- [Upstash: Backblaze B2 pricing explained (October 2026)](https://upstash.com/blog/backblaze-b2-pricing-explained-2026)
- [egresscost.com: Backblaze B2](https://egresscost.com/backblaze-b2)
- [Google Cloud Storage pricing](https://cloud.google.com/storage/pricing)
- [Google Cloud Storage pricing announcements](https://cloud.google.com/storage/pricing-announce)
- [CloudZero: GCP storage pricing](https://www.cloudzero.com/blog/gcp-storage-pricing)
- [S&P Global: hyperscalers continue global data center expansion (February 2026)](https://www.spglobal.com/market-intelligence/en/news-insights/research/2026/02/hyperscalers-continue-global-data-center-expansion-despite-geopolitical-tensions)
