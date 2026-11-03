#!/usr/bin/env bash
# Deploy the producer to fafo-0's k3s: rsync the code to ~/apps/csl-eth on the
# box, build the release binary there, then apply the namespace and Deployment and
# restart the pod onto the new binary.
#
#   deploy/k8s/apply.sh
#
# Never touches data/ on the box: data/produce is the producer's state.
# The Secret r2 is created once, by hand (see deployment.yaml).
set -euo pipefail

HOST="${CSL_ETH_HOST:-fafo-0}"
REMOTE="${CSL_ETH_REMOTE:-apps/csl-eth}"
KUBECTL="${KUBECTL:-kubectl}"
cd "$(dirname "$0")/../.."

ssh "$HOST" "mkdir -p $REMOTE/data/produce && test \"\$(id -u)\" = 1000 || { echo 'remote uid is not 1000; edit runAsUser in deploy/k8s/deployment.yaml' >&2; exit 1; }"
rsync -az --stats --exclude target --exclude data --exclude node_modules --exclude browser/pkg --exclude browser/site --exclude browser/deploy/.cloudflare ./ "$HOST:$REMOTE/" | grep -E 'files transferred|Number of regular files transferred' || true
ssh "$HOST" "cd $REMOTE && PATH=\$HOME/.cargo/bin:\$PATH nice cargo +stable build --release -p csl-eth-snap -j 3 2>&1 | tail -1"
ssh "$HOST" "$KUBECTL apply -f $REMOTE/deploy/k8s/namespace.yaml -f $REMOTE/deploy/k8s/deployment.yaml && $KUBECTL -n csl-eth rollout restart deploy/producer && $KUBECTL -n csl-eth rollout status deploy/producer --timeout=120s"

cat <<EOT

Applied. On $HOST:
  $KUBECTL -n csl-eth logs deploy/producer | grep '^{'     # one JSON line per cycle
  tail -f ~/$REMOTE/data/produce/produce.log
EOT
