#!/usr/bin/env bash
# Run the AuthZEN working group's interop Todo harness
# (openid/authzen interop/authzen-todo-backend/test/runner.ts) against this
# plugin, loaded with the Todo policy and data from opa-authzen-interop.
# Usage: run-todo-harness.sh BINARY SPEC_DIR INTEROP_DIR
#
# The runner exits 0 whatever the results, so the verdict is read from its
# output: every case in the decisions file must print PASS.
set -euo pipefail

bin=$1 spec=$2 interop=$3
decisions=authorization-api-1_0-02
port=${AUTHZEN_HARNESS_PORT:-18181}
# The harness's own `yarn build` does not compile under the TypeScript 7 its
# package.json now resolves to, and its server sources fail type checking
# under 5.x. Compile only the runner, with a pinned 5.x.
typescript=typescript@5.9.3

script_dir="$(cd "$(dirname "$0")" && pwd -P)"
harness="$spec/interop/authzen-todo-backend"
log=$(mktemp)

# Something already answering on the port would be tested in place of $bin.
if curl -s -o /dev/null "http://127.0.0.1:$port/"; then
  echo "port $port is already in use; set AUTHZEN_HARNESS_PORT" >&2
  exit 1
fi

"$bin" run --server --addr "127.0.0.1:$port" \
  --config-file "$script_dir/todo-harness-config.yaml" \
  "$interop/policy/" "$interop/data/" >"$log" 2>&1 &
pdp=$!
trap 'kill "$pdp" 2>/dev/null || true; rm -f "$log"' EXIT

for _ in $(seq 1 50); do
  curl -sf "http://127.0.0.1:$port/health" >/dev/null && break
  sleep 0.2
done
if ! curl -sf "http://127.0.0.1:$port/health" >/dev/null; then
  echo "PDP did not become healthy:" >&2
  cat "$log" >&2
  exit 1
fi

(
  cd "$harness"
  yarn install --frozen-lockfile --ignore-scripts --silent
  rm -rf build
  npx --yes -p "$typescript" tsc --target es2022 --module commonjs \
    --esModuleInterop --resolveJsonModule --skipLibCheck \
    --rootDir . --outDir build test/runner.ts
  cp test/*.json build/test/
)

expected=$(cd "$harness/test" && node -p \
  "const d = require('./decisions-$decisions.json'); (d.evaluation || []).length + (d.evaluations || []).length")

rc=0
out=$(node "$harness/build/test/runner.js" "http://127.0.0.1:$port" "$decisions" console 2>&1 |
  sed 's/\x1b\[[0-9;]*m//g') || rc=$?
echo "$out"
if [ "$rc" -ne 0 ]; then
  echo "==> runner exited $rc" >&2
  exit "$rc"
fi

pass=$(grep -c '^PASS' <<<"$out" || true)
bad=$(grep -cE '^(FAIL|ERROR)' <<<"$out" || true)
echo "==> interop Todo harness ($decisions): $pass/$expected passed, $bad failed"
[ "$bad" -eq 0 ] && [ "$pass" -eq "$expected" ]
