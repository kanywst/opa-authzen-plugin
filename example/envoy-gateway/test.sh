#!/usr/bin/env bash
# Smoke test for the Envoy Gateway + AuthZEN integration example.
# Usage: ./test.sh
set -euo pipefail

BASE_URL="${1:-http://localhost:9000}"
PASS=0
FAIL=0

check() {
  local desc="$1" expected="$2" method="$3" path="$4" user="${5:-}"
  local args=(-s -o /dev/null -w '%{http_code}' -X "$method")
  if [ -n "$user" ]; then
    args+=(-H "X-User: $user")
  fi
  if [ "$method" = "POST" ] || [ "$method" = "PUT" ]; then
    args+=(-H "Content-Type: application/json" -d '{}')
  fi

  actual=$(curl "${args[@]}" "$BASE_URL$path")
  if [ "$actual" = "$expected" ]; then
    echo "PASS: $desc (HTTP $actual)"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $desc (expected $expected, got $actual)"
    FAIL=$((FAIL + 1))
  fi
}

echo "=== Envoy Gateway + AuthZEN smoke test ==="
echo ""

# All users can read todos
check "admin can read todos"          200 GET /todos      rick
check "viewer can read todos"         200 GET /todos      jerry

# All users can read users
check "admin can read user"           200 GET /users/rick rick

# Only admin/editor can create todos
check "admin can create todo"         201 POST /todos     rick
check "editor can create todo"        201 POST /todos     morty
check "viewer cannot create todo"     403 POST /todos     jerry

# Admin can delete any todo
check "admin can delete todo"         204 DELETE /todos/todo-1 rick

# Viewer cannot delete
check "viewer cannot delete todo"     403 DELETE /todos/todo-1 jerry

# No user header → denied
check "missing user header → denied"  403 GET /todos

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
