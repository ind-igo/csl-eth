#!/usr/bin/env bash
# The producer's publisher for a Cloud Storage bucket, run on a GCP VM
# (`csl-eth produce --publish scripts/gcs-publish.sh`). Same interface as
# r2-publish.sh and r2-s3-publish.sh:
#
#   gcs-publish.sh put <key> <file>    upload <file> as <key>
#   gcs-publish.sh delete <key>        delete <key>
#
# No key anywhere: the VM's service account's access token comes from the
# metadata server, and its only grant is object read/write on the bucket
# (infra/alchemy.run.ts). CSL_ETH_GCS_BUCKET overrides the bucket.
#
# Cache-Control matters here as it did not on R2: a public object without
# one may be cached by Google's edge for an hour, which would freeze the
# head. Pointers and the open period's update are rewritten in place, so
# they are no-cache; everything named by a hash never changes.
#
# Quiet on success; on failure the key and the answer go to stderr and the
# exit is nonzero.
set -uo pipefail

bucket="${CSL_ETH_GCS_BUCKET:-csl-eth-demo}"
base="https://storage.googleapis.com/${bucket}"
err=$(mktemp)
trap 'rm -f "$err"' EXIT

usage() {
  echo "usage: $0 put <key> <file> | $0 delete <key>" >&2
  exit 2
}

token() {
  curl -sS --max-time 10 -H 'Metadata-Flavor: Google' \
    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' |
    sed -n 's/.*"access_token" *: *"\([^"]*\)".*/\1/p'
}

# Seconds each try may take: 240, plus one per 10 MB of the upload, so a
# large file gets time at about a fifth of the VM's usual 40-80 MB/s. The
# tracker's own deadline for the call grows the same way (PUT_FLOOR_RATE in
# crates/snap/src/produce.rs).
max_time=240

gcs() {
  local t
  t=$(token)
  [ -n "$t" ] || { echo "no access token from the metadata server" >&2; return 1; }
  # The token goes to curl on stdin as a config line, never in argv.
  printf 'header = "Authorization: Bearer %s"\n' "$t" |
    curl -sS --config - --max-time "$max_time" --retry 2 --retry-all-errors \
      -o "$err" -w '%{http_code}' "$@"
}

case "${1:-}" in
  put)
    [ $# -eq 3 ] || usage
    key=$2
    file=$3
    [ -f "$file" ] || { echo "put $key: no such file: $file" >&2; exit 1; }
    max_time=$((240 + $(wc -c <"$file") / 10000000))
    # Rules by the key under a "full/" or "history-full/" prefix (the
    # full-state export, deploy/gcp/node-burst.sh, and the full history,
    # deploy/gcp/history-burst.sh, publish whole bucket layouts there).
    rel=${key#full/}
    rel=${rel#history-full/}
    case "$rel" in
      head/* | manifest.json | */manifest.json) ct=application/json ;;
      *) ct=application/octet-stream ;;
    esac
    case "$rel" in
      # runs/: layers' runs, named by their blake3 (csl-eth track).
      head/bootstrap/* | snapshots/0x*/* | snapshots/[0-9a-f]*/* | blobs/* | runs/*)
        cc='public, max-age=31536000, immutable' ;;
      # History: runs and packs are named by their blake3, a manifest by
      # the block its span ends at; none is ever rewritten.
      history/runs/* | history/packs/* | history/[0-9a-f]*/manifest.json)
        cc='public, max-age=31536000, immutable' ;;
      *) cc='no-cache' ;; # head/optimistic, finality, fcr, updates/<period>, snapshots/latest, history/latest
    esac
    code=$(gcs -X PUT -H "Content-Type: $ct" -H "Cache-Control: $cc" --upload-file "$file" "$base/$key")
    ;;
  delete)
    [ $# -eq 2 ] || usage
    key=$2
    code=$(gcs -X DELETE "$base/$key")
    [ "$code" = 404 ] && code=204 # already gone is done
    ;;
  *) usage ;;
esac

case "$code" in
  200 | 204) ;;
  *)
    echo "$1 $key: HTTP ${code:-none}: $(head -c 400 "$err")" >&2
    exit 1
    ;;
esac
