#!/usr/bin/env bash
# Deploy the tracker to the GCP VM made by infra/alchemy.run.ts: rsync the
# code to /opt/csl-eth, build the release binary there, install the systemd
# unit and restart it onto the new binary. CSL_ETH_UNIT=csl-eth-producer
# installs the old slice producer instead.
#
#   deploy/gcp/apply.sh
#
# SSH goes through Identity-Aware Proxy as your Google account (OS Login);
# the first `gcloud compute ssh` registers your key. Never touches /data:
# /data/produce is the producer's state.
set -euo pipefail

VM="${CSL_ETH_VM:-csl-eth-producer}"
ZONE="${CSL_ETH_ZONE:-asia-east1-b}"
PROJECT="${CSL_ETH_PROJECT:-csl-eth}"
cd "$(dirname "$0")/../.."

# Register the key with OS Login (no-op after the first time) and learn the
# POSIX user it maps to.
UNIT="${CSL_ETH_UNIT:-csl-eth-track}"
gcloud compute ssh "$VM" --zone "$ZONE" --project "$PROJECT" --tunnel-through-iap --command true >/dev/null
user=$(gcloud compute os-login describe-profile --project "$PROJECT" --format='value(posixAccounts[0].username)')
proxy="gcloud compute start-iap-tunnel $VM 22 --listen-on-stdin --zone $ZONE --project $PROJECT --verbosity=warning"
ssh_opts=(-i "$HOME/.ssh/google_compute_engine" -o "ProxyCommand=$proxy" -o StrictHostKeyChecking=accept-new -o "HostKeyAlias=compute.$VM")
ssh_cmd="ssh -i $HOME/.ssh/google_compute_engine -o 'ProxyCommand=$proxy' -o StrictHostKeyChecking=accept-new -o HostKeyAlias=compute.$VM" # for rsync -e
# Each argument quoted once for the remote shell, which ssh hands one string.
remote() { ssh "${ssh_opts[@]}" "$user@$VM" "$(printf '%q ' "$@")"; }

# The startup script installs the build tools on first boot; wait for it.
remote bash -c 'for i in $(seq 60); do command -v cc >/dev/null && command -v rsync >/dev/null && mountpoint -q /data && exit 0; sleep 5; done; echo "startup script not finished" >&2; exit 1'
remote sudo chown "$user" /opt/csl-eth

rsync -az --stats -e "$ssh_cmd" \
  --exclude target --exclude data --exclude node_modules --exclude infra/node_modules \
  --exclude browser/pkg --exclude browser/site --exclude browser/dist --exclude browser/deploy/.cloudflare \
  ./ "$user@$VM:/opt/csl-eth/" | grep -E 'Number of regular files transferred' || true

# Rust as the deploying user, the toolchain the repo pins if it pins one.
remote bash -c 'command -v cargo >/dev/null || [ -x ~/.cargo/bin/cargo ] || curl -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal'
# git's own client for git dependencies (libgit2's TLS failed once here);
# the build's last lines only, but its exit status, not tail's.
remote bash -c 'set -o pipefail; cd /opt/csl-eth && CARGO_NET_GIT_FETCH_WITH_CLI=true nice ~/.cargo/bin/cargo build --release -p csl-eth-snap -j 2 2>&1 | tail -3'

remote sudo install -d -o csl -g csl /data/track /data/track/root /data/track/work
remote sudo install -m 0644 "/opt/csl-eth/deploy/gcp/$UNIT.service" "/etc/systemd/system/$UNIT.service"
remote sudo systemctl daemon-reload
if [ -n "${CSL_ETH_NO_START:-}" ]; then
  echo "built and installed; not started (CSL_ETH_NO_START)"
  exit 0
fi
remote sudo systemctl enable "$UNIT"
remote sudo systemctl restart "$UNIT"
remote systemctl --no-pager --lines 0 status "$UNIT" || true

cat <<EOT

Applied. On the VM:
  gcloud compute ssh $VM --zone $ZONE --tunnel-through-iap
  journalctl -u $UNIT -f
  tail -f /data/track/work/track.jsonl                # one JSON line per step
EOT
