#!/usr/bin/env bash
# A publisher into a local directory, for running `csl-eth produce`
# without touching R2: the same interface as r2-publish.sh.
#
#   CSL_ETH_PUBLISH_DIR=<dir> dir-publish.sh put <key> <file>
#   CSL_ETH_PUBLISH_DIR=<dir> dir-publish.sh delete <key>
#
# A file is copied in under a temporary name and renamed, so a reader of
# the directory never sees half of one.
set -euo pipefail

root="${CSL_ETH_PUBLISH_DIR:?set CSL_ETH_PUBLISH_DIR}"
case "${1:-}" in
  put)
    [ $# -eq 3 ]
    mkdir -p "$(dirname "$root/$2")"
    cp "$3" "$root/$2.part"
    mv "$root/$2.part" "$root/$2"
    ;;
  delete)
    [ $# -eq 2 ]
    rm -f "$root/$2"
    # Empty directories the key leaves, below the root only.
    d=$(dirname "$2")
    while [ "$d" != "." ] && rmdir "$root/$d" 2>/dev/null; do d=$(dirname "$d"); done
    ;;
  *)
    echo "usage: $0 put <key> <file> | $0 delete <key>" >&2
    exit 2
    ;;
esac
