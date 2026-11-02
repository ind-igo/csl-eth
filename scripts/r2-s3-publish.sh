#!/usr/bin/env bash
# The producer's publisher for the R2 bucket over its S3 API, for hosts
# without a `cf` login (`csl-eth produce --publish scripts/r2-s3-publish.sh`).
# Same interface as r2-publish.sh:
#
#   r2-s3-publish.sh put <key> <file>    upload <file> as <key>
#   r2-s3-publish.sh delete <key>        delete <key>
#
# curl signs the requests itself (--aws-sigv4), so nothing else is needed.
# Credentials come from the environment: R2_ACCOUNT_ID, R2_ACCESS_KEY_ID,
# R2_SECRET_ACCESS_KEY (an R2 token scoped to the bucket: the access key is
# the token id, the secret is the SHA-256 of the token value).
# CSL_ETH_R2_BUCKET overrides the bucket. Quiet on success; on failure the
# key and R2's answer go to stderr and the exit is nonzero.
set -uo pipefail

bucket="${CSL_ETH_R2_BUCKET:-csl-eth-apac}"
: "${R2_ACCOUNT_ID:?R2_ACCOUNT_ID unset}" "${R2_ACCESS_KEY_ID:?R2_ACCESS_KEY_ID unset}" "${R2_SECRET_ACCESS_KEY:?R2_SECRET_ACCESS_KEY unset}"
base="https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com/${bucket}"

usage() {
  echo "usage: $0 put <key> <file> | $0 delete <key>" >&2
  exit 2
}

s3() {
  # The secret goes to curl on stdin as a config line, never in argv.
  printf 'user = "%s:%s"\n' "$R2_ACCESS_KEY_ID" "$R2_SECRET_ACCESS_KEY" |
    curl -sS --config - --aws-sigv4 "aws:amz:auto:s3" --max-time 240 \
      --retry 2 --retry-all-errors -o /dev/stderr -w '%{http_code}' "$@"
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
    code=$(s3 -X PUT -H "Content-Type: $ct" --upload-file "$file" "$base/$key" 2>/tmp/r2-s3-publish.$$)
    ;;
  delete)
    [ $# -eq 2 ] || usage
    key=$2
    code=$(s3 -X DELETE "$base/$key" 2>/tmp/r2-s3-publish.$$)
    ;;
  *) usage ;;
esac

case "$code" in
  200 | 204) rm -f /tmp/r2-s3-publish.$$ ;;
  *)
    echo "$1 $key: HTTP ${code:-none}: $(head -c 400 /tmp/r2-s3-publish.$$)" >&2
    rm -f /tmp/r2-s3-publish.$$
    exit 1
    ;;
esac
