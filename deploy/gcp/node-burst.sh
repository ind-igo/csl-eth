#!/usr/bin/env bash
# The on-VM half of deploy/gcp/full-export.sh, run there as a transient
# systemd unit (csl-export). Lines starting "csl-export" are its progress,
# which full-export.sh relays.
#
# In: BLOCK_HASH BLOCK_NUMBER BLOCK_TS STATE_ROOT BUCKET, the code at
# /data/src and the verified head files at /data/head.
#
# 1. reth (release binary) and the exporter (built here) in parallel with
#    reth's minimal snapshot download into /data/reth.
# 2. reth syncs from the snapshot to exactly BLOCK_HASH over devp2p and exits.
# 3. The exporter streams HashedAccounts/HashedStorages into the bucket
#    layout under /data/out and refuses to write a manifest unless the root it
#    computes is STATE_ROOT.
# 4. Upload: immutable objects first, then full/head/*, then the pointer.
set -euo pipefail
: "${BLOCK_HASH:?}" "${BLOCK_NUMBER:?}" "${BLOCK_TS:?}" "${STATE_ROOT:?}" "${BUCKET:?}"
RETH_VERSION="${RETH_VERSION:-v2.11.0}"
say() { printf 'csl-export %s %s\n' "$(date -u +%H:%M:%S)" "$*"; }
mkdir -p "$HOME" /data/bin /data/out
export PATH="/data/bin:$HOME/.cargo/bin:$PATH"

# 1a. reth.
if [ ! -x /data/bin/reth ]; then
  curl -sSfL "https://github.com/paradigmxyz/reth/releases/download/$RETH_VERSION/reth-$RETH_VERSION-x86_64-unknown-linux-gnu.tar.gz" | tar -xz -C /data/bin reth
fi
# The release binary wants glibc 2.39+ (Debian 13, not 12): fail here, not
# an hour into the download.
v=$(/data/bin/reth --version 2>&1) || { say "reth does not run: $v"; exit 1; }
say "reth ${v%%$'\n'*}"

# 1b. The exporter, built while the snapshot downloads.
(
  command -v cargo >/dev/null || curl -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal
  cd /data/src/tools/export-reth
  CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release -q 2>&1 | tail -5
) > /data/build.log 2>&1 &
build=$!

# 1c. The snapshot.
if [ ! -f /data/reth/.downloaded ]; then
  say "downloading reth's minimal snapshot"
  t0=$(date +%s)
  /data/bin/reth download --chain mainnet --datadir /data/reth --minimal --non-interactive 2>&1 | grep -v '^\s*$' | tail -20
  touch /data/reth/.downloaded
  say "snapshot down in $(( $(date +%s) - t0 ))s, $(du -sh /data/reth | cut -f1)"
fi
if ! wait "$build"; then
  say "exporter build failed"; cat /data/build.log; exit 1
fi
say "exporter built"

# 2. Sync to the block and stop. The tip is a hash the head files proved, so
# the peers can only serve the chain that ends there or stall.
t0=$(date +%s)
say "syncing to block $BLOCK_NUMBER $BLOCK_HASH"
if ! /data/bin/reth node --chain mainnet --datadir /data/reth --minimal \
  --debug.tip "$BLOCK_HASH" --debug.terminate \
  --port 30303 --discovery.port 30303 --color never \
  > /data/sync.log 2>&1; then
  say "reth exited nonzero"; tail -40 /data/sync.log; exit 1
fi
say "sync done in $(( $(date +%s) - t0 ))s"

# 3. Export. The exporter checks the chain head in the DB is BLOCK_HASH and
# the computed root is STATE_ROOT, and writes the manifest last. Reading reth
# is page-fault latency, one fault in flight per thread: 16 workers on 8
# vCPUs keep the NVMe busy, and a 16 GiB budget leaves the rest of the
# 64 GB to the page cache over reth's database.
t0=$(date +%s)
/data/src/tools/export-reth/target/release/export-reth \
  --datadir /data/reth --block-hash "$BLOCK_HASH" --block-number "$BLOCK_NUMBER" \
  --timestamp "$BLOCK_TS" --state-root "$STATE_ROOT" --out /data/out \
  --scratch /data/scratch --memory-gib 16 --workers 16 \
  2>&1 | sed -u 's/^/csl-export export /'
say "export done in $(( $(date +%s) - t0 ))s, $(du -sh /data/out | cut -f1)"

# 4. Publish under full/: content-addressed objects (immutable) first, then
# the head files and the pointer (no-cache), so a reader never sees a
# pointer to something missing.
#
# The bulk goes through `gcloud storage cp`, not gcs-publish.sh: the runs
# are single objects of 94 and 254 GB, which one PUT under curl's
# --max-time can never finish (the first full run stalled there). gcloud
# streams them resumably. It can't use composite uploads here, since the
# VM's account has no bucket GET, so each run is one stream at 40 to
# 80 MB/s: mainnet's runs took 98 min and its 1.3M code blobs 46 min
# (2026-11-16). --no-clobber makes a rerun resume.
pub() { CSL_ETH_GCS_BUCKET="$BUCKET" /data/src/scripts/gcs-publish.sh "$@"; }
imm=(--no-clobber --cache-control 'public, max-age=31536000, immutable' --content-type application/octet-stream)
cd /data/out
snap=$(cat snapshots/latest)
t0=$(date +%s)
gcloud storage cp "${imm[@]}" "snapshots/$snap/"*.run "gs://$BUCKET/full/snapshots/$snap/"
say "runs up in $(( $(date +%s) - t0 ))s"
t0=$(date +%s)
if [ -d blobs ]; then gcloud storage cp -r "${imm[@]}" blobs "gs://$BUCKET/full/"; fi
say "blobs up in $(( $(date +%s) - t0 ))s"
pub put "full/snapshots/$snap/manifest.json" "snapshots/$snap/manifest.json"
cd /data/head
find . -type f -print0 | while IFS= read -r -d '' f; do pub put "full/head/${f#./}" "$f"; done
cd /data/out
prev=$(curl -sf "https://storage.googleapis.com/$BUCKET/full/snapshots/latest" || true)
pub put full/snapshots/latest snapshots/latest
say "published block $BLOCK_NUMBER at gs://$BUCKET/full/"

# Collect: keep the new snapshot and the one it replaced (readers that
# opened it a moment ago); remove older ones. Blobs are shared by hash and
# stay.
new=$(cat snapshots/latest)
for d in $(gcloud storage ls "gs://$BUCKET/full/snapshots/" 2>/dev/null | grep '/$'); do
  h=$(basename "$d")
  [ "$h" = "$new" ] || [ "$h" = "$prev" ] && continue
  gcloud storage rm -r -q "$d" && say "removed old snapshot $h"
done

# 5. The history the minimal node still holds (its last ~22,000 blocks of
# transactions and receipts, three days), anchored at the same verified
# block and published under full/history/. Two minutes of export and 11 GB
# on mainnet (2026-11-16). Best effort: the state above is the burst's job.
X=/data/src/tools/export-reth/target/release/export-reth
first=$($X history probe --datadir /data/reth | sed -n 's/.*"transactions_from":\([0-9]*\).*/\1/p')
if [ -n "$first" ] && rm -rf /data/hout && mkdir -p /data/hout \
  && $X history export --datadir /data/reth --block-number "$BLOCK_NUMBER" --block-hash "$BLOCK_HASH" \
    --first "$first" --out /data/hout --workers 16 2>&1 | sed -u 's/^/csl-export history /' \
  && [ -f /data/hout/history/latest ]; then
  (
    set -e
    cd /data/hout
    gcloud storage rsync -r "${imm[@]}" history/packs "gs://$BUCKET/full/history/packs"
    gcloud storage rsync -r "${imm[@]}" history/runs "gs://$BUCKET/full/history/runs"
    m="history/$(cat history/latest)/manifest.json"
    pub put "full/$m" "$m"
    pub put full/history/latest history/latest
  ) && say "published history $first..$BLOCK_NUMBER at gs://$BUCKET/full/history/" \
    || say "history publish failed; state is published"
else
  say "history export failed; state is published"
fi
