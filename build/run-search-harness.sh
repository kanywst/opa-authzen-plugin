#!/usr/bin/env bash
# Usage: run-search-harness.sh BINARY SPEC_DIR
set -euo pipefail

bin=$1 spec=$2
port=${AUTHZEN_HARNESS_PORT:-18182}
# The harness's `yarn build` fails under TypeScript 7; compile only the runner.
typescript=typescript@5.9.3

script_dir="$(cd "$(dirname "$0")" && pwd -P)"
demo="$spec/interop/authzen-search-demo"
harness="$demo/test-harness"
work=$(mktemp -d)
pdp=
trap '[ -n "$pdp" ] && kill "$pdp" 2>/dev/null; rm -rf "$work"' EXIT

if curl -s -o /dev/null "http://127.0.0.1:$port/"; then
  echo "port $port is already in use; set AUTHZEN_HARNESS_PORT" >&2
  exit 1
fi

# users.json and records.json are top-level arrays, which OPA cannot load as data.
mkdir "$work/data"
node -e '
  const [users, records] = process.argv.slice(1).map(f => require(f));
  console.log(JSON.stringify({search_demo: {users, records}}));
' "$(cd "$demo/data" && pwd -P)/users.json" "$(cd "$demo/data" && pwd -P)/records.json" >"$work/data/data.json"

"$bin" run --server --addr "127.0.0.1:$port" \
  --config-file "$script_dir/search-harness-config.yaml" \
  "$script_dir/search-harness.rego" "$work/data/" >"$work/pdp.log" 2>&1 &
pdp=$!

for _ in $(seq 1 50); do
  curl -sf "http://127.0.0.1:$port/health" >/dev/null && break
  sleep 0.2
done
if ! curl -sf "http://127.0.0.1:$port/health" >/dev/null; then
  echo "PDP did not become healthy:" >&2
  cat "$work/pdp.log" >&2
  exit 1
fi

(
  cd "$harness"
  yarn install --frozen-lockfile --ignore-scripts --silent
  rm -rf build
  npx --yes -p "$typescript" tsc --target es2022 --module commonjs \
    --esModuleInterop --resolveJsonModule --skipLibCheck \
    --rootDir src --outDir build src/runner.ts
)

expected=$(cd "$harness/src" && node -p \
  "['subject', 'resource', 'action'].reduce((n, e) => n + require('./' + e + '/results.json').evaluation.length, 0)")

# The runner exits 0 regardless of results.
rc=0
out=$(node "$harness/build/runner.js" "http://127.0.0.1:$port" console 2>&1 |
  sed 's/\x1b\[[0-9;]*m//g') || rc=$?
echo "$out"
if [ "$rc" -ne 0 ]; then
  echo "==> runner exited $rc" >&2
  exit "$rc"
fi

pass=$(grep -c '^PASS' <<<"$out" || true)
bad=$(grep -cE '^(FAIL|ERROR)' <<<"$out" || true)
echo "==> interop Search harness: $pass/$expected passed, $bad failed"
[ "$bad" -eq 0 ] && [ "$pass" -eq "$expected" ]
