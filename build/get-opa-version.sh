#!/usr/bin/env bash
# Get OPA version from go.mod. Removes leading 'v'. Example: v1.15.1 -> 1.15.1
SCRIPT_DIR="$( cd "$(dirname "$0")" ; pwd -P )"
grep "open-policy-agent/opa" "$SCRIPT_DIR/../go.mod" | grep -vE 'module|replace' | tail -1 | awk '{print $2}' | cut -c 2-
