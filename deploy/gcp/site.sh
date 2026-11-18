#!/usr/bin/env bash
# Build the browser page and upload it into the Cloud Storage bucket beside
# the data (infra/alchemy.run.ts), where it is served at
# https://storage.googleapis.com/<bucket>/index.html and reads the full state
# under full/ from its own origin.
#
#   deploy/gcp/site.sh
#
# Uploads only index.html, viz.html (a copy, for old links), light.html and
# the redirect to it from its first name, dist/ and pkg/;
# never touches head/, snapshots/, blobs/ or full/. Five-minute caching. The
# text and the wasm are stored gzipped (`--gzip-local-all`): browsers get them
# compressed, which takes the 1.3 MB client module to about a third; the wasm
# keeps application/wasm so it compiles while streaming.
set -euo pipefail

bucket="${CSL_ETH_GCS_BUCKET:-csl-eth-demo}"
cd "$(dirname "$0")/../.."

./scripts/build-wasm.sh
(cd browser && bun install && bun run site)
site=browser/site
cc='public, max-age=300'
up() { gcloud storage cp --gzip-local-all --cache-control="$cc" "$@"; }

up --content-type=text/html "$site"/*.html "gs://$bucket/"
up --content-type=text/javascript "$site"/dist/*.js "gs://$bucket/dist/"
up --content-type=text/javascript "$site"/pkg/*.js "gs://$bucket/pkg/"
up --content-type=application/json "$site"/dist/*.map "gs://$bucket/dist/"
up --content-type=application/wasm "$site"/pkg/*.wasm "gs://$bucket/pkg/"
# Scripts of earlier pages (the two-page site's, the first TypeScript client's).
gcloud storage rm -q "gs://$bucket/dist/main.js" "gs://$bucket/dist/main.js.map" \
  "gs://$bucket/dist/mini.js" "gs://$bucket/dist/mini.js.map" 2>/dev/null || true

echo "https://storage.googleapis.com/$bucket/index.html"
