#!/usr/bin/env bash
# Get OPA version from go.mod. Removes leading 'v'. Example: v1.15.1 -> 1.15.1
# The version is located by shape, not field position, so this works both inside
# a require block and on a single-line require directive.
SCRIPT_DIR="$( cd "$(dirname "$0")" ; pwd -P )"
grep "open-policy-agent/opa " "$SCRIPT_DIR/../go.mod" | grep -vE 'module|replace' | tail -1 |
  awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^v[0-9]/) { print substr($i, 2); exit } }'
