#!/usr/bin/env bash
# Build the browser page and upload it into the Cloud Storage bucket beside
# the data (infra/alchemy.run.ts), where it is served at
# https://storage.googleapis.com/<bucket>/index.html and reads the bucket from
# its own origin.
#
#   deploy/gcp/site.sh
#
# Uploads only index.html, viz.html, dist/ and pkg/; never touches head/,
# snapshots/ or blobs/. Five-minute caching as on the Worker; the wasm is
# served as application/wasm so it compiles while streaming.
set -euo pipefail

bucket="${CSL_ETH_GCS_BUCKET:-csl-eth-demo}"
cd "$(dirname "$0")/../.."

./scripts/build-wasm.sh
(cd browser && bun install && bun run site)
site=browser/site
cc='public, max-age=300'

gcloud storage cp --cache-control="$cc" --content-type=text/html "$site/index.html" "$site/viz.html" "gs://$bucket/"
gcloud storage cp --cache-control="$cc" --content-type=text/javascript "$site"/dist/*.js "gs://$bucket/dist/"
gcloud storage cp --cache-control="$cc" --content-type=text/javascript "$site"/pkg/*.js "gs://$bucket/pkg/"
gcloud storage cp --cache-control="$cc" --content-type=application/json "$site"/dist/*.map "gs://$bucket/dist/"
gcloud storage cp --cache-control="$cc" --content-type=application/wasm "$site"/pkg/*.wasm "gs://$bucket/pkg/"

echo "https://storage.googleapis.com/$bucket/index.html?open"
