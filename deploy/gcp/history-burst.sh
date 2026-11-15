#!/usr/bin/env bash
# The on-VM half of deploy/gcp/history-export.sh, run there as a transient
# systemd unit (csl-history). Lines starting "csl-history" are its progress,
# which history-export.sh relays.
#
# In: BLOCK_HASH BLOCK_NUMBER BUCKET, the code at /data/src, the verified
# head files at /data/head, and optionally the Milestone H day's block cache
# at /data/hday-work.
#
# 1. reth (release binary) and the exporter (built here), while reth's
#    snapshot (state, headers, and transactions and receipts from genesis)
#    downloads into /data/reth and the era1 files for blocks below Byzantium
#    into /data/era1.
# 2. reth syncs from the snapshot to exactly BLOCK_HASH over devp2p, keeping
#    every transaction and receipt (no --minimal: reth.toml from the download
#    prunes neither), and exits.
# 3. With the day's cache: reth against it, block by block and file by file.
# 4. The exporter writes blocks 0..BLOCK_NUMBER to /data/out: runs and packs
#    (about 18k objects), then the manifest, then history/latest, only if
#    every block verified. The tx_lookup rows pass through scratch under
#    /data/out/history (about 160 GB) before they merge into two runs.
# 5. Upload: runs and packs (immutable) first, then history-full/head/*, the
#    manifest, and history/latest last.
set -euo pipefail
: "${BLOCK_HASH:?}" "${BLOCK_NUMBER:?}" "${BUCKET:?}"
RETH_VERSION="${RETH_VERSION:-v2.11.0}"
PREFIX=history-full
BYZANTIUM_ERA=533 # block 4,369,999 / 8,192
say() { printf 'csl-history %s %s\n' "$(date -u +%H:%M:%S)" "$*"; }
mkdir -p "$HOME" /data/bin /data/era1
export PATH="/data/bin:$HOME/.cargo/bin:$PATH"

# 1a. reth.
if [ ! -x /data/bin/reth ]; then
  curl -sSfL "https://github.com/paradigmxyz/reth/releases/download/$RETH_VERSION/reth-$RETH_VERSION-x86_64-unknown-linux-gnu.tar.gz" | tar -xz -C /data/bin reth
fi
v=$(/data/bin/reth --version 2>&1) || { say "reth does not run: $v"; exit 1; }
say "reth ${v%%$'\n'*}"

# 1b. The exporter, built while the snapshot downloads.
(
  command -v cargo >/dev/null || curl -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal
  cd /data/src/tools/export-reth
  CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release --locked -q 2>&1 | tail -5
) > /data/build.log 2>&1 &
build=$!

# 1c. Era1 files 0..533 (16.6 GB): only their receipts are used, each
# checked against reth's header, so the host is not trusted.
(
  curl -sSf https://era.ithaca.xyz/era1/index.html | grep -o 'mainnet-[0-9]\{5\}-[0-9a-f]\{8\}\.era1' | sort -u \
    | awk -F- -v max="$BYZANTIUM_ERA" '($2 + 0) <= max' > /data/era1.list
  [ "$(wc -l < /data/era1.list)" -eq $((BYZANTIUM_ERA + 1)) ] || { echo "era1 index lists $(wc -l < /data/era1.list) files"; exit 1; }
  cd /data/era1
  xargs -P 16 -I{} sh -c 'if [ ! -s {} ]; then curl -sSf --retry 5 -o {}.part https://era.ithaca.xyz/era1/{} && mv {}.part {}; fi' < /data/era1.list
) > /data/era1.log 2>&1 &
era1=$!

# 1d. The snapshot: state and headers always, transactions and receipts from
# genesis (about 1.2 TB down, 1.8 TB on disk; no senders, no changesets).
if [ ! -f /data/reth/.downloaded ]; then
  say "downloading reth's snapshot with transactions and receipts"
  t0=$(date +%s)
  /data/bin/reth download --chain mainnet --datadir /data/reth --with-txs --with-receipts --non-interactive 2>&1 | grep -v '^\s*$' | tail -20
  touch /data/reth/.downloaded
  say "snapshot down in $(( $(date +%s) - t0 ))s, $(du -sh /data/reth | cut -f1)"
fi
wait "$build" || { say "exporter build failed"; cat /data/build.log; exit 1; }
say "exporter built"
wait "$era1" || { say "era1 download failed"; tail -20 /data/era1.log; exit 1; }
say "era1 files: $(ls /data/era1/*.era1 | wc -l), $(du -sh /data/era1 | cut -f1)"
X=/data/src/tools/export-reth/target/release/export-reth

# 2. Sync to the block and stop, pruning nothing the download kept.
t0=$(date +%s)
say "syncing to block $BLOCK_NUMBER $BLOCK_HASH"
if ! /data/bin/reth node --chain mainnet --datadir /data/reth \
  --debug.tip "$BLOCK_HASH" --debug.terminate \
  --port 30303 --discovery.port 30303 --color never \
  > /data/sync.log 2>&1; then
  say "reth exited nonzero"; tail -40 /data/sync.log; exit 1
fi
say "sync done in $(( $(date +%s) - t0 ))s"
say "probe $($X history probe --datadir /data/reth)"

# 3. The day, if its cache came along: reth must give the same blocks and
# write the same files as the peer-built cache (which wrote the Milestone H
# bucket byte for byte).
if [ -d /data/hday-work/blocks ]; then
  $X history compare --datadir /data/reth --cache /data/hday-work --from 26415492 --to 26422691 \
    --out /data/hcmp --workers 16 2>/dev/null | sed -u 's/^/csl-history compare /' \
    || { say "reth disagrees with the day's cache"; exit 1; }
fi

# 4. Export. Reading reth is page faults over its static files, so 16
# workers on 8 vCPUs.
t0=$(date +%s)
$X history export --datadir /data/reth --block-number "$BLOCK_NUMBER" --block-hash "$BLOCK_HASH" \
  --first 0 --era1-dir /data/era1 --out /data/out --workers 16 --progress-secs 300 \
  2>&1 | sed -u 's/^/csl-history export /'
[ -f /data/out/history/latest ] || { say "export wrote no history/latest"; exit 1; }
say "export done in $(( $(date +%s) - t0 ))s, $(du -sh /data/out | cut -f1)"

# 5. Publish under history-full/: content-addressed objects (immutable) first,
# in bulk; then the head files, the manifest and the pointer (no-cache)
# through gcs-publish.sh, so a reader never sees a pointer to something
# missing. The bulk copy is resumable: rerunning it skips what is there.
pub() { CSL_ETH_GCS_BUCKET="$BUCKET" /data/src/scripts/gcs-publish.sh "$@"; }
imm=(--no-clobber --cache-control 'public, max-age=31536000, immutable' --content-type application/octet-stream)
cd /data/out
t0=$(date +%s)
gcloud storage rsync -r "${imm[@]}" history/packs "gs://$BUCKET/$PREFIX/history/packs"
say "packs up in $(( $(date +%s) - t0 ))s ($(ls history/packs | wc -l) files, $(du -sh history/packs | cut -f1))"
t0=$(date +%s)
gcloud storage rsync -r "${imm[@]}" history/runs "gs://$BUCKET/$PREFIX/history/runs"
say "runs up in $(( $(date +%s) - t0 ))s ($(ls history/runs | wc -l) files, $(du -sh history/runs | cut -f1))"
cd /data/head
find . -type f -print0 | while IFS= read -r -d '' f; do pub put "$PREFIX/head/${f#./}" "$f"; done
cd /data/out
m="history/$(cat history/latest)/manifest.json"
pub put "$PREFIX/$m" "$m"
pub put "$PREFIX/history/latest" history/latest
say "published blocks 0..$BLOCK_NUMBER at gs://$BUCKET/$PREFIX/"
