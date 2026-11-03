#!/usr/bin/env bash
# Smoke test for the Kubernetes example on a kind cluster.
# Usage: ./test.sh  (KEEP_CLUSTER=1 leaves the cluster up)
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
cluster=${CLUSTER_NAME:-opa-authzen-example}
image=opa-authzen-plugin:k8s-example
port=${LOCAL_PORT:-18181}
ctx="kind-$cluster"
prev_ctx=$(kubectl config current-context 2>/dev/null || true)

created=0
pf_pid=
cleanup() {
  [ -n "$pf_pid" ] && kill "$pf_pid" 2>/dev/null || true
  if [ "$created" = 1 ] && [ "${KEEP_CLUSTER:-0}" != 1 ]; then
    kind delete cluster --name "$cluster"
  fi
}
trap cleanup EXIT

docker build -t "$image" "$root"

if ! kind get clusters | grep -qx "$cluster"; then
  kind create cluster --name "$cluster" --wait 120s
  created=1
  [ -z "$prev_ctx" ] || kubectl config use-context "$prev_ctx" >/dev/null
fi
kind load docker-image "$image" --name "$cluster"

kubectl kustomize "$here" |
  sed "s|image: ghcr.io/kanywst/opa-authzen-plugin:.*|image: $image|" |
  kubectl --context "$ctx" apply -f -
if [ "$created" = 0 ]; then
  kubectl --context "$ctx" -n authzen rollout restart deploy/opa-authzen
fi
kubectl --context "$ctx" -n authzen rollout status deploy/opa-authzen --timeout=120s

kubectl --context "$ctx" -n authzen port-forward svc/opa-authzen "$port:8181" >/dev/null &
pf_pid=$!
for _ in $(seq 30); do
  curl -sf "http://localhost:$port/health" >/dev/null && break
  sleep 1
done
curl -sf "http://localhost:$port/health" >/dev/null || {
  echo "port-forward did not come up" >&2
  exit 1
}

base="http://localhost:$port"
pass=0
fail=0

check() {
  local desc=$1 path=$2 body=$3 want=$4 got
  if [ -n "$body" ]; then
    got=$(curl -s -X POST -H 'Content-Type: application/json' -d "$body" "$base$path" || true)
  else
    got=$(curl -s "$base$path" || true)
  fi
  if printf '%s' "$got" | grep -qF -- "$want"; then
    echo "PASS: $desc"
    pass=$((pass + 1))
  else
    echo "FAIL: $desc (want $want, got $got)"
    fail=$((fail + 1))
  fi
}

echo "=== Kubernetes example smoke test ==="

check "metadata lists the evaluation endpoint" \
  /.well-known/authzen-configuration "" \
  '"access_evaluation_endpoint"'

check "admin can delete" /access/v1/evaluation \
  '{"subject":{"type":"user","id":"alice","properties":{"role":"admin"}},"resource":{"type":"document","id":"d1"},"action":{"name":"delete"}}' \
  '{"decision":true}'

check "user can read" /access/v1/evaluation \
  '{"subject":{"type":"user","id":"bob"},"resource":{"type":"document","id":"d1"},"action":{"name":"read"}}' \
  '{"decision":true}'

check "user cannot delete" /access/v1/evaluation \
  '{"subject":{"type":"user","id":"bob"},"resource":{"type":"document","id":"d1"},"action":{"name":"delete"}}' \
  '{"decision":false}'

check "batch applies defaults per item" /access/v1/evaluations \
  '{"subject":{"type":"user","id":"bob"},"resource":{"type":"document","id":"d1"},"evaluations":[{"action":{"name":"read"}},{"action":{"name":"delete"}}]}' \
  '{"evaluations":[{"decision":true},{"decision":false}]}'

echo ""
echo "Results: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
