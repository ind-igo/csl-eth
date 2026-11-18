#!/usr/bin/env bash
# One full-state export, as a burst: pick the newest finalized block the
# demo bucket's own head files prove, create a node VM with local NVMe SSDs,
# start reth from its official snapshot, sync it to exactly that block, export
# the whole state into run files, check it against the block's state_root,
# publish it under gs://<bucket>/full/, and delete the VM.
#
#   deploy/gcp/full-export.sh            the whole burst
#   KEEP_VM=1 deploy/gcp/full-export.sh  leave the VM up afterwards (debugging)
#
# Trust: the block comes from head files verified here from the page's
# checkpoint, and the export must hash to that block's state_root, so neither
# reth's snapshot, its peers, nor this VM is trusted for what gets published.
# The page reads it at https://storage.googleapis.com/<bucket>/full with the
# head files frozen at that block: it verifies until the next sync-committee
# period begins (up to about 27 hours), so the export runs daily.
#
# The VM is not in infra/alchemy.run.ts: Alchemy cannot attach local SSDs, and
# it lives only for the burst. It uses the stack's network, the producer's
# service account (bucket writes only) and the "node" tag (devp2p firewall).
set -euo pipefail

PROJECT="${CSL_ETH_PROJECT:-csl-eth}"
env_file="$(cd "$(dirname "$0")/../.." && pwd)/infra/.env"
[ -f "$env_file" ] && . "$env_file"   # CSL_ETH_REGION (gitignored)
ZONE="${CSL_ETH_ZONE:-${CSL_ETH_REGION:+$CSL_ETH_REGION-b}}"
: "${ZONE:?set CSL_ETH_REGION in infra/.env, or CSL_ETH_ZONE}"
VM="${CSL_ETH_NODE_VM:-csl-eth-node}"
BUCKET="${CSL_ETH_GCS_BUCKET:-csl-eth-demo}"
CHECKPOINT="${CSL_ETH_CHECKPOINT:-0x431b33af8452e2d644377405e69d4f382182ab906f31461190ca24cb3401d70b}"
SA="csl-eth-producer@${PROJECT}.iam.gserviceaccount.com"
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }

# 1. The block: copy the bucket's head files, verify them here, and keep the
# copy, so the head published beside the export is exactly what was verified.
mkdir -p "$work/head/head"
gcloud storage cp -r "gs://$BUCKET/head/bootstrap" "gs://$BUCKET/head/finality" "$work/head/head/" >/dev/null
gcloud storage cp -r "gs://$BUCKET/head/updates" "$work/head/head/" >/dev/null 2>&1 || true
./target/release/csl-eth head verify --checkpoint "$CHECKPOINT" --bucket "$work/head" > "$work/head.json"
read -r hash number ts root < <(python3 -c "import json,sys;d=json.load(open('$work/head.json'));print(d['block_hash'],d['block_number'],d['timestamp'],d['state_root'])")
log "target: block $number $hash state_root $root"

# 2. The VM: n2-highmem-8 with four local NVMe SSDs (1.5 TB, RAID 0 at /data).
# GCE deletes it after 16 hours whatever happens here, so a lost laptop or
# a killed script cannot leave it running.
startup=$(cat <<'EOS'
#!/bin/bash
set -euo pipefail
if ! mountpoint -q /data; then
  apt-get update -q
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q mdadm build-essential clang libclang-dev pkg-config curl rsync git zstd
  devs=$(ls /dev/disk/by-id/google-local-nvme-ssd-* | sort)
  [ -e /dev/md0 ] || mdadm --create /dev/md0 --level=0 --raid-devices=$(echo "$devs" | wc -l) $devs --force --run
  mkfs.ext4 -q -F -m 0 -E lazy_itable_init=0,lazy_journal_init=0,discard /dev/md0
  mkdir -p /data && mount -o discard,noatime /dev/md0 /data && chmod 1777 /data
fi
EOS
)
if ! gcloud compute instances describe "$VM" --zone "$ZONE" --project "$PROJECT" >/dev/null 2>&1; then
  log "creating $VM"
  gcloud compute instances create "$VM" --project "$PROJECT" --zone "$ZONE" \
    --machine-type n2-highmem-8 \
    --local-ssd interface=NVME --local-ssd interface=NVME --local-ssd interface=NVME --local-ssd interface=NVME \
    --boot-disk-size 50GB --boot-disk-type pd-balanced \
    --image-family debian-13 --image-project debian-cloud \
    --network-interface "subnet=csl-eth" \
    --service-account "$SA" --scopes https://www.googleapis.com/auth/devstorage.read_write \
    --tags producer,node \
    --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
    --max-run-duration 16h --instance-termination-action DELETE \
    --metadata enable-oslogin=TRUE --metadata-from-file startup-script=<(echo "$startup") >/dev/null
fi
cleanup_vm() {
  if [ "${KEEP_VM:-0}" = 1 ]; then log "KEEP_VM=1: $VM left running"; return; fi
  log "deleting $VM"
  gcloud compute instances delete "$VM" --zone "$ZONE" --project "$PROJECT" --quiet >/dev/null || true
}
trap 'cleanup_vm; rm -rf "$work"' EXIT

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
remote bash -c 'for i in $(seq 120); do mountpoint -q /data && command -v rsync >/dev/null && exit 0; sleep 5; done; exit 1'

# 3. The code and the head copy, then the burst itself on the VM, detached
# from this SSH session (it runs for hours).
remote mkdir -p /data/src /data/head
rsync -az -e "$ssh_cmd" --exclude target --exclude data --exclude node_modules --exclude browser/pkg --exclude browser/site --exclude browser/dist \
  ./ "$user@$VM:/data/src/"
rsync -az -e "$ssh_cmd" "$work/head/head/" "$user@$VM:/data/head/"
remote sudo systemd-run --unit csl-export --uid "$user" -p LimitNOFILE=65536 --setenv HOME="/data/home-$user" \
  --setenv BLOCK_HASH="$hash" --setenv BLOCK_NUMBER="$number" --setenv BLOCK_TS="$ts" --setenv STATE_ROOT="$root" \
  --setenv BUCKET="$BUCKET" /bin/bash /data/src/deploy/gcp/node-burst.sh
log "burst started on $VM (journalctl -u csl-export -f)"

# 4. Wait for it, printing its progress lines.
seen=0
while true; do
  sleep 60
  state=$(remote systemctl show csl-export -p ActiveState -p Result --value | tr '\n' ' ' || echo "unreachable")
  lines=$(remote bash -c "sudo journalctl -u csl-export --no-pager -o cat | grep '^csl-export' | tail -n +$((seen + 1))" || true)
  [ -n "$lines" ] && { echo "$lines"; seen=$((seen + $(echo "$lines" | wc -l))); }
  case "$state" in
    "inactive success"*) log "burst finished"; break ;;
    "failed"* | "inactive "*) log "burst failed: $state"; remote bash -c 'sudo journalctl -u csl-export --no-pager -o cat | tail -40' || true; exit 1 ;;
  esac
done

# 5. Check what was published, from the outside.
./target/release/csl-eth head verify --checkpoint "$CHECKPOINT" --url "https://storage.googleapis.com/$BUCKET/full"
curl -sf "https://storage.googleapis.com/$BUCKET/full/snapshots/latest"; echo
log "full state at block $number: https://storage.googleapis.com/$BUCKET/index.html?bucket=https://storage.googleapis.com/$BUCKET/full&tier=finalized"
