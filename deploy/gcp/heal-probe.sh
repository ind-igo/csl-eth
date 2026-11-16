#!/usr/bin/env bash
# The healing probe on a temporary spot VM: create it, build the probe from
# GitHub on first boot and run it under systemd for a day; fetch its logs;
# delete everything it made.
#
#   deploy/gcp/heal-probe.sh up [branch]    # VM + firewall rule, starts on boot
#   deploy/gcp/heal-probe.sh status         # service state and line counts
#   deploy/gcp/heal-probe.sh fetch <dir>    # copy the JSON lines here
#   deploy/gcp/heal-probe.sh down           # delete the VM, its disk, the rule
#
# Everything it creates carries the name `csl-eth-heal-probe` and the label
# purpose=heal-probe, on the default network; it never touches the producer.
set -euo pipefail

PROJECT="${CSL_ETH_PROJECT:-csl-eth}"
ZONE="${CSL_ETH_ZONE:-asia-east1-b}"
VM=csl-eth-heal-probe
RULE=csl-eth-heal-probe-discv4
HOURS="${HEAL_PROBE_HOURS:-24}"
g() { gcloud --project "$PROJECT" "$@"; }

case "${1:-}" in
up)
  branch="${2:-heal-probe}"
  startup=$(mktemp)
  cat >"$startup" <<EOF
#!/bin/bash
# First boot only: tools, the repo, a release build, the service.
set -euxo pipefail
[ -x /opt/csl-eth/target/release/csl-eth ] && exit 0
apt-get update -q
apt-get install -y -q build-essential pkg-config git curl clang
export HOME=/root
curl -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal
git clone --depth 1 --branch $branch https://github.com/ind-igo/csl-eth /opt/csl-eth
cd /opt/csl-eth
CARGO_NET_GIT_FETCH_WITH_CLI=true /root/.cargo/bin/cargo build --release -p csl-eth-snap -j 2
mkdir -p /var/lib/heal-probe
cat >/etc/systemd/system/heal-probe.service <<'UNIT'
[Unit]
Description=csl-eth heal probe
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/bin/sh -c 'exec /opt/csl-eth/target/release/csl-eth heal-probe --out /var/lib/heal-probe/probe-\$\$(date +%%s).jsonl --max-secs $((HOURS * 3600)) --udp-port 30303'
Environment=RUST_LOG=info,discv4=warn,reth_dns_discovery=warn,hickory=warn
Restart=on-failure
RestartSec=30
Nice=5
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now heal-probe
EOF
  g compute firewall-rules describe "$RULE" >/dev/null 2>&1 ||
    g compute firewall-rules create "$RULE" --network default --direction INGRESS \
      --allow udp:30303 --source-ranges 0.0.0.0/0 --target-tags heal-probe \
      --description "heal probe discv4; delete with the VM"
  g compute instances create "$VM" --zone "$ZONE" --machine-type e2-standard-2 \
    --provisioning-model SPOT --instance-termination-action STOP \
    --image-family debian-13 --image-project debian-cloud \
    --boot-disk-size 30GB --boot-disk-type pd-balanced --boot-disk-auto-delete \
    --network default --tags heal-probe --labels purpose=heal-probe \
    --metadata-from-file startup-script="$startup"
  rm -f "$startup"
  ;;
status)
  g compute instances describe "$VM" --zone "$ZONE" --format='value(status)'
  g compute ssh "$VM" --zone "$ZONE" --command \
    'systemctl is-active heal-probe; sudo wc -l /var/lib/heal-probe/*.jsonl 2>/dev/null; sudo grep -h "\"ev\":\"cycle\"" /var/lib/heal-probe/*.jsonl 2>/dev/null | tail -2 | cut -c1-400; sudo journalctl -u google-startup-scripts --no-pager | tail -3'
  ;;
fetch)
  dir="${2:?fetch <dir>}"
  mkdir -p "$dir"
  g compute ssh "$VM" --zone "$ZONE" --command 'sudo tar -C /var/lib/heal-probe -czf /tmp/heal-probe.tgz .'
  g compute scp --zone "$ZONE" "$VM:/tmp/heal-probe.tgz" "$dir/"
  tar -C "$dir" -xzf "$dir/heal-probe.tgz"
  ls -la "$dir"
  ;;
down)
  g compute instances delete "$VM" --zone "$ZONE" --quiet || true
  g compute firewall-rules delete "$RULE" --quiet || true
  g compute instances list --filter="labels.purpose=heal-probe" --format='value(name)'
  g compute disks list --filter="name~heal-probe" --format='value(name)'
  ;;
*)
  sed -n '2,13p' "$0"
  exit 2
  ;;
esac
