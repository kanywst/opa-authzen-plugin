#!/bin/bash
# Start the opa-authzen-plugin PDP with the interop policy and data.
# Usage: ./scripts/start-pdp.sh [path-to-opa-authzen-plugin-binary]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="${1:-${PROJECT_DIR}/../../opa-authzen-plugin}"

if [ ! -f "$BINARY" ]; then
  echo "Error: opa-authzen-plugin binary not found at $BINARY"
  echo "Build it first: make build (at the repository root)"
  exit 1
fi

echo "Starting OPA AuthZEN PDP..."
echo "  Binary:  $BINARY"
echo "  Config:  $PROJECT_DIR/config.yaml"
echo "  Policy:  $PROJECT_DIR/policy/"
echo "  Data:    $PROJECT_DIR/data/"
echo "  AuthZEN: http://localhost:8181"
echo ""

exec "$BINARY" run \
  --server \
  --config-file="$PROJECT_DIR/config.yaml" \
  "$PROJECT_DIR/policy/" \
  "$PROJECT_DIR/data/"
