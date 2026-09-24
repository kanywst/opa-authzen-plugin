#!/usr/bin/env bash
# Usage: fetch-sparse.sh URL COMMIT DIR PATH...
set -euo pipefail

url=$1 commit=$2 dir=$3
shift 3

if [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" = "$commit" ]; then
  exit 0
fi

rm -rf "$dir"
git init -q "$dir"
git -C "$dir" remote add origin "$url"
git -C "$dir" sparse-checkout set --no-cone "$@"
git -C "$dir" fetch -q --depth 1 origin "$commit"
git -C "$dir" checkout -q FETCH_HEAD
