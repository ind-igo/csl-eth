#!/usr/bin/env bash
# All of mainnet's history as one burst: pick the newest finalized block the
# demo bucket's own head files prove, create a node VM with 24 local NVMe SSDs,
# fill reth's datadir from its snapshot with transactions and receipts from
# genesis, sync it to exactly that block, write the five history tables for
# blocks 0 to it (export-reth history export), publish them under
# gs://<bucket>/history-full/ with the head files frozen at that block, and
# delete the VM.
#
#   deploy/gcp/history-export.sh                  the whole burst
#   KEEP_VM=1 deploy/gcp/history-export.sh        leave the VM up afterwards
#   HDAY_WORK=<dir> deploy/gcp/history-export.sh  also compare reth with the
#     Milestone H day's block cache (blocks/ and anchor.json, 2.4 GB) first
#
# Trust: the block comes from head files verified here from the page's
# checkpoint; the exporter checks reth's hash at that block, and every block
# it writes must rebuild its header's roots and chain by parentHash to it.
# Receipts below Byzantium come from era1 files (era.ithaca.xyz), checked the
# same way against reth's headers. So neither reth's snapshot, its peers, the
# era1 host nor this VM is trusted for what gets published.
#
# Not run yet. The sizing behind it (docs/decisions.md, "the history tables
# from reth" and "history packs"): about 1.2 TB downloaded, 1.8 TB of reth on
# disk, 4 to 5 TB of output in about 18,000 objects (runs and one pack per
# period) and 0.3 TB of scratch for tx_lookup; about 8 to 12 hours, the
# export and the upload of the bytes about equal; hence 9 TB of disk, and 48
# hours as a ceiling.
#
# The VM is infra/burst.run.ts's stage "history": this script makes it with
# `bun run burst:up --stage history` and deletes it with `burst:down`, so
# nothing here creates or deletes infrastructure itself (gcloud is used for
# SSH through IAP and the bucket's objects only).
set -euo pipefail

PROJECT="${CSL_ETH_PROJECT:-csl-eth}"
env_file="$(cd "$(dirname "$0")/../.." && pwd)/infra/.env"
[ -f "$env_file" ] && . "$env_file"   # CSL_ETH_REGION (gitignored)
ZONE="${CSL_ETH_ZONE:-${CSL_ETH_REGION:+$CSL_ETH_REGION-b}}"
: "${ZONE:?set CSL_ETH_REGION in infra/.env, or CSL_ETH_ZONE}"
VM=csl-eth-history # the name infra/burst.run.ts gives the "history" stage's VM
BUCKET="${CSL_ETH_GCS_BUCKET:-csl-eth-demo}"
CHECKPOINT="${CSL_ETH_CHECKPOINT:-0x431b33af8452e2d644377405e69d4f382182ab906f31461190ca24cb3401d70b}"
export CSL_ETH_HISTORY_SSDS="${CSL_ETH_HISTORY_SSDS:-24}" # 375 GB each; read by infra/burst.run.ts
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }

# 1. The block: copy the bucket's head files, verify them here, and keep the
# copy, so the head published beside the history is exactly what was verified.
mkdir -p "$work/head/head"
gcloud storage cp -r "gs://$BUCKET/head/bootstrap" "gs://$BUCKET/head/finality" "$work/head/head/" >/dev/null
gcloud storage cp -r "gs://$BUCKET/head/updates" "$work/head/head/" >/dev/null 2>&1 || true
./target/release/csl-eth head verify --checkpoint "$CHECKPOINT" --bucket "$work/head" > "$work/head.json"
read -r hash number < <(python3 -c "import json,sys;d=json.load(open('$work/head.json'));print(d['block_hash'],d['block_number'])")
log "target: blocks 0 to $number ($hash)"

# 2. The VM: n2-highmem-8 with $CSL_ETH_HISTORY_SSDS local NVMe SSDs in RAID 0
# at /data, as infra/burst.run.ts describes it. GCE deletes it after 48 hours
# whatever happens here. An existing one (KEEP_VM=1 last time) is kept; one
# with another SSD count is replaced.
log "making $VM with $CSL_ETH_HISTORY_SSDS local SSDs (alchemy, stage history)"
cleanup_vm() {
  if [ "${KEEP_VM:-0}" = 1 ]; then log "KEEP_VM=1: $VM left running (delete: cd infra && bun run burst:down --stage history)"; return; fi
  log "deleting $VM (alchemy, stage history)"
  (cd infra && bun run burst:down --stage history) || log "delete failed: cd infra && bun run burst:down --stage history"
}
trap 'cleanup_vm; rm -rf "$work"' EXIT
(cd infra && bun run burst:up --stage history)

# SSH through IAP, as in apply.sh.
for i in $(seq 30); do
  gcloud compute ssh "$VM" --zone "$ZONE" --project "$PROJECT" --tunnel-through-iap --command true >/dev/null 2>&1 && break
  sleep 10
done
user=$(gcloud compute os-login describe-profile --project "$PROJECT" --format='value(posixAccounts[0].username)')
proxy="gcloud compute start-iap-tunnel $VM 22 --listen-on-stdin --zone $ZONE --project $PROJECT --verbosity=warning"
ssh_opts=(-i "$HOME/.ssh/google_compute_engine" -o "ProxyCommand=$proxy" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ServerAliveInterval=30)
ssh_cmd="ssh -i $HOME/.ssh/google_compute_engine -o 'ProxyCommand=$proxy' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
remote() { ssh "${ssh_opts[@]}" "$user@$VM" "$(printf '%q ' "$@")"; }
remote bash -c 'for i in $(seq 180); do mountpoint -q /data && command -v rsync >/dev/null && exit 0; sleep 5; done; exit 1'

# 3. The code, the head copy and (optionally) the day's block cache, then the
# burst itself on the VM, detached from this SSH session (it runs for a day).
remote mkdir -p /data/src /data/head
rsync -az -e "$ssh_cmd" --exclude target --exclude data --exclude node_modules --exclude browser/pkg --exclude browser/site --exclude browser/dist \
  ./ "$user@$VM:/data/src/"
rsync -az -e "$ssh_cmd" "$work/head/head/" "$user@$VM:/data/head/"
if [ -n "${HDAY_WORK:-}" ]; then
  log "copying the day's block cache from $HDAY_WORK"
  remote mkdir -p /data/hday-work
  rsync -a -e "$ssh_cmd" "$HDAY_WORK/anchor.json" "$HDAY_WORK/blocks" "$user@$VM:/data/hday-work/"
fi
remote sudo systemd-run --unit csl-history --uid "$user" -p LimitNOFILE=65536 --setenv HOME="/data/home-$user" \
  --setenv BLOCK_HASH="$hash" --setenv BLOCK_NUMBER="$number" \
  --setenv BUCKET="$BUCKET" /bin/bash /data/src/deploy/gcp/history-burst.sh
log "burst started on $VM (journalctl -u csl-history -f)"

# 4. Wait for it, printing its progress lines.
seen=0
while true; do
  sleep 120
  state=$(remote systemctl show csl-history -p ActiveState -p Result --value | tr '\n' ' ' || echo "unreachable")
  lines=$(remote bash -c "sudo journalctl -u csl-history --no-pager -o cat | grep '^csl-history' | tail -n +$((seen + 1))" || true)
  [ -n "$lines" ] && { echo "$lines"; seen=$((seen + $(echo "$lines" | wc -l))); }
  case "$state" in
    "inactive success"*) log "burst finished"; break ;;
    "failed"* | "inactive "*) log "burst failed: $state"; remote bash -c 'sudo journalctl -u csl-history --no-pager -o cat | tail -40' || true; exit 1 ;;
  esac
done

# 5. Check what was published, from the outside: the head verifies to the
# block, and history/latest names it.
./target/release/csl-eth head verify --checkpoint "$CHECKPOINT" --url "https://storage.googleapis.com/$BUCKET/history-full"
curl -sf "https://storage.googleapis.com/$BUCKET/history-full/history/latest"; echo
log "history 0..$number at https://storage.googleapis.com/$BUCKET/history-full"
