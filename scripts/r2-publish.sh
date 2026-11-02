#!/usr/bin/env bash
# The producer's publisher for the R2 bucket (`csl-eth produce --publish
# scripts/r2-publish.sh`):
#
#   r2-publish.sh put <key> <file>    upload <file> as <key>
#   r2-publish.sh delete <key>        delete <key>
#
# Head files and manifests go up as application/json, everything else as
# application/octet-stream. Quiet on success (cf prints an agent banner on
# stderr); on failure the key and cf's output go to stderr and the exit is
# nonzero, which fails the producer's step. CSL_ETH_R2_BUCKET overrides the
# bucket.
set -uo pipefail

bucket="${CSL_ETH_R2_BUCKET:-csl-eth-apac}"

usage() {
  echo "usage: $0 put <key> <file> | $0 delete <key>" >&2
  exit 2
}

case "${1:-}" in
  put)
    [ $# -eq 3 ] || usage
    key=$2
    file=$3
    [ -f "$file" ] || { echo "put $key: no such file: $file" >&2; exit 1; }
    case "$key" in
      head/* | manifest.json | */manifest.json) ct=application/json ;;
      *) ct=application/octet-stream ;;
    esac
    # cf answers a declined prompt with "Aborted." and may still exit 0.
    if ! out=$(cf r2 objects put "$key" --bucket-name "$bucket" --file "$file" --content-type "$ct" 2>&1) || grep -q '^Aborted' <<<"$out"; then
      echo "put $key: $out" >&2
      exit 1
    fi
    ;;
  delete)
    [ $# -eq 2 ] || usage
    key=$2
    # Without --force cf asks, and a non-interactive run answers "Aborted.".
    if ! out=$(cf r2 objects delete "$key" --bucket-name "$bucket" --force 2>&1) || grep -q '^Aborted' <<<"$out"; then
      echo "delete $key: $out" >&2
      exit 1
    fi
    ;;
  *) usage ;;
esac
