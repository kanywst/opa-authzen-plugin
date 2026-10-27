#!/bin/bash
# Local test script: end-to-end AuthZEN conformance checks against the PDP
# Usage: ./scripts/test-local.sh [pdp-url]
#
# Replays the AuthZEN interop Todo decision cases (single + batch evaluation)
# from decisions-authorization-api-1_0-01.json, plus the Search APIs and
# pagination, and additionally exercises the protocol surface the decision
# cases don't: evaluation semantics (Section 7.1.2.1), PDP metadata discovery
# (Section 9), X-Request-ID echo (Section 10.1.3), and transport-level error
# handling (Section 10.1, Section 11.7).

set -uo pipefail

PDP_URL="${1:-http://localhost:8181}"
PASS=0
FAIL=0
ERROR=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

test_evaluation() {
  local request="$1"
  local expected="$2"

  response=$(curl -s -w "\n%{http_code}" \
    -X POST "${PDP_URL}/access/v1/evaluation" \
    -H "Content-Type: application/json" \
    -d "$request" 2>/dev/null) || { echo -e "${YELLOW}ERROR${NC} Connection failed"; ERROR=$((ERROR+1)); return; }

  http_code=$(echo "$response" | tail -1)
  body=$(echo "$response" | sed '$d')

  if [ "$http_code" != "200" ]; then
    echo -e "${YELLOW}ERROR${NC} HTTP $http_code"
    ERROR=$((ERROR+1))
    return
  fi

  actual=$(echo "$body" | python3 -c "import sys,json; print(json.load(sys.stdin).get('decision', False))" 2>/dev/null)

  if [ "$actual" = "$expected" ]; then
    echo -e "${GREEN}PASS${NC} $(echo "$request" | python3 -c "import sys,json; r=json.load(sys.stdin); print(f'{r[\"action\"][\"name\"]} subject={r[\"subject\"][\"id\"][:12]}... -> {r.get(\"resource\",{}).get(\"properties\",{}).get(\"ownerID\",\"N/A\")}')")"
    PASS=$((PASS+1))
  else
    echo -e "${RED}FAIL${NC} Expected=$expected Actual=$actual"
    echo "  Request: $request"
    echo "  Response: $body"
    FAIL=$((FAIL+1))
  fi
}

test_evaluations() {
  local request="$1"
  local expected="$2"

  response=$(curl -s -w "\n%{http_code}" \
    -X POST "${PDP_URL}/access/v1/evaluations" \
    -H "Content-Type: application/json" \
    -d "$request" 2>/dev/null) || { echo -e "${YELLOW}ERROR${NC} Connection failed"; ERROR=$((ERROR+1)); return; }

  http_code=$(echo "$response" | tail -1)
  body=$(echo "$response" | sed '$d')

  if [ "$http_code" != "200" ]; then
    echo -e "${YELLOW}ERROR${NC} HTTP $http_code"
    ERROR=$((ERROR+1))
    return
  fi

  actual=$(echo "$body" | python3 -c "
import sys, json
data = json.load(sys.stdin)
evals = data.get('evaluations', [])
print(json.dumps([{'decision': e.get('decision', False)} for e in evals]))
" 2>/dev/null)

  if [ "$actual" = "$expected" ]; then
    echo -e "${GREEN}PASS${NC} [batch] $(echo "$request" | python3 -c "import sys,json; r=json.load(sys.stdin); print(f'{r[\"action\"][\"name\"]} subject={r[\"subject\"][\"id\"][:12]}... evaluations={len(r.get(\"evaluations\",[]))}')")"
    PASS=$((PASS+1))
  else
    echo -e "${RED}FAIL${NC} [batch] Expected=$expected Actual=$actual"
    echo "  Request: $request"
    echo "  Response: $body"
    FAIL=$((FAIL+1))
  fi
}

echo "=== AuthZEN Interop Test Suite ==="
echo "PDP URL: ${PDP_URL}"
echo ""

# --- Rick Sanchez (admin, evil_genius) ---
echo "--- Rick Sanchez (admin, evil_genius) ---"
RICK="CiRmZDA2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"

test_evaluation '{"subject":{"type":"user","id":"'$RICK'"},"action":{"name":"can_read_user"},"resource":{"type":"user","id":"beth@the-smiths.com"}}' "True"
test_evaluation '{"subject":{"type":"user","id":"'$RICK'"},"action":{"name":"can_read_user"},"resource":{"type":"user","id":"rick@the-citadel.com"}}' "True"
test_evaluation '{"subject":{"type":"user","id":"'$RICK'"},"action":{"name":"can_read_todos"},"resource":{"type":"todo","id":"todo-1"}}' "True"
test_evaluation '{"subject":{"type":"user","id":"'$RICK'"},"action":{"name":"can_create_todo"},"resource":{"type":"todo","id":"todo-1"}}' "True"
test_evaluation '{"subject":{"type":"user","id":"'$RICK'"},"action":{"name":"can_update_todo"},"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b92","properties":{"ownerID":"rick@the-citadel.com"}}}' "True"
test_evaluation '{"subject":{"type":"user","id":"'$RICK'"},"action":{"name":"can_update_todo"},"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b91","properties":{"ownerID":"morty@the-citadel.com"}}}' "True"
test_evaluation '{"subject":{"type":"user","id":"'$RICK'"},"action":{"name":"can_delete_todo"},"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b92","properties":{"ownerID":"rick@the-citadel.com"}}}' "True"
test_evaluation '{"subject":{"type":"user","id":"'$RICK'"},"action":{"name":"can_delete_todo"},"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b91","properties":{"ownerID":"morty@the-citadel.com"}}}' "True"

# --- Morty Smith (editor) ---
echo ""
echo "--- Morty Smith (editor) ---"
MORTY="CiRmZDE2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"

test_evaluation '{"subject":{"type":"user","id":"'$MORTY'"},"action":{"name":"can_read_user"},"resource":{"type":"user","id":"beth@the-smiths.com"}}' "True"
test_evaluation '{"subject":{"type":"user","id":"'$MORTY'"},"action":{"name":"can_read_user"},"resource":{"type":"user","id":"morty@the-citadel.com"}}' "True"
test_evaluation '{"subject":{"type":"user","id":"'$MORTY'"},"action":{"name":"can_read_todos"},"resource":{"type":"todo","id":"todo-1"}}' "True"
test_evaluation '{"subject":{"type":"user","id":"'$MORTY'"},"action":{"name":"can_create_todo"},"resource":{"type":"todo","id":"todo-1"}}' "True"
test_evaluation '{"subject":{"type":"user","id":"'$MORTY'"},"action":{"name":"can_update_todo"},"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b92","properties":{"ownerID":"rick@the-citadel.com"}}}' "False"
test_evaluation '{"subject":{"type":"user","id":"'$MORTY'"},"action":{"name":"can_update_todo"},"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b91","properties":{"ownerID":"morty@the-citadel.com"}}}' "True"
test_evaluation '{"subject":{"type":"user","id":"'$MORTY'"},"action":{"name":"can_delete_todo"},"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b92","properties":{"ownerID":"rick@the-citadel.com"}}}' "False"
test_evaluation '{"subject":{"type":"user","id":"'$MORTY'"},"action":{"name":"can_delete_todo"},"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b91","properties":{"ownerID":"morty@the-citadel.com"}}}' "True"

# --- Summer Smith (editor) ---
echo ""
echo "--- Summer Smith (editor) ---"
SUMMER="CiRmZDI2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"

test_evaluation '{"subject":{"type":"user","id":"'$SUMMER'"},"action":{"name":"can_read_user"},"resource":{"type":"user","id":"beth@the-smiths.com"}}' "True"
test_evaluation '{"subject":{"type":"user","id":"'$SUMMER'"},"action":{"name":"can_read_user"},"resource":{"type":"user","id":"summer@the-smiths.com"}}' "True"
test_evaluation '{"subject":{"type":"user","id":"'$SUMMER'"},"action":{"name":"can_read_todos"},"resource":{"type":"todo","id":"todo-1"}}' "True"
test_evaluation '{"subject":{"type":"user","id":"'$SUMMER'"},"action":{"name":"can_create_todo"},"resource":{"type":"todo","id":"todo-1"}}' "True"
test_evaluation '{"subject":{"type":"user","id":"'$SUMMER'"},"action":{"name":"can_update_todo"},"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b92","properties":{"ownerID":"rick@the-citadel.com"}}}' "False"
test_evaluation '{"subject":{"type":"user","id":"'$SUMMER'"},"action":{"name":"can_update_todo"},"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b93","properties":{"ownerID":"summer@the-smiths.com"}}}' "True"
test_evaluation '{"subject":{"type":"user","id":"'$SUMMER'"},"action":{"name":"can_delete_todo"},"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b92","properties":{"ownerID":"rick@the-citadel.com"}}}' "False"
test_evaluation '{"subject":{"type":"user","id":"'$SUMMER'"},"action":{"name":"can_delete_todo"},"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b93","properties":{"ownerID":"summer@the-smiths.com"}}}' "True"

# --- Beth Smith (viewer) ---
echo ""
echo "--- Beth Smith (viewer) ---"
BETH="CiRmZDM2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"

test_evaluation '{"subject":{"type":"user","id":"'$BETH'"},"action":{"name":"can_read_user"},"resource":{"type":"user","id":"beth@the-smiths.com"}}' "True"
test_evaluation '{"subject":{"type":"user","id":"'$BETH'"},"action":{"name":"can_read_user"},"resource":{"type":"user","id":"beth@the-smiths.com"}}' "True"
test_evaluation '{"subject":{"type":"user","id":"'$BETH'"},"action":{"name":"can_read_todos"},"resource":{"type":"todo","id":"todo-1"}}' "True"
test_evaluation '{"subject":{"type":"user","id":"'$BETH'"},"action":{"name":"can_create_todo"},"resource":{"type":"todo","id":"todo-1"}}' "False"
test_evaluation '{"subject":{"type":"user","id":"'$BETH'"},"action":{"name":"can_update_todo"},"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b92","properties":{"ownerID":"rick@the-citadel.com"}}}' "False"
test_evaluation '{"subject":{"type":"user","id":"'$BETH'"},"action":{"name":"can_update_todo"},"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b94","properties":{"ownerID":"beth@the-smiths.com"}}}' "False"
test_evaluation '{"subject":{"type":"user","id":"'$BETH'"},"action":{"name":"can_delete_todo"},"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b92","properties":{"ownerID":"rick@the-citadel.com"}}}' "False"
test_evaluation '{"subject":{"type":"user","id":"'$BETH'"},"action":{"name":"can_delete_todo"},"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b94","properties":{"ownerID":"beth@the-smiths.com"}}}' "False"

# --- Jerry Smith (viewer) ---
echo ""
echo "--- Jerry Smith (viewer) ---"
JERRY="CiRmZDQ2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"

test_evaluation '{"subject":{"type":"user","id":"'$JERRY'"},"action":{"name":"can_read_user"},"resource":{"type":"user","id":"beth@the-smiths.com"}}' "True"
test_evaluation '{"subject":{"type":"user","id":"'$JERRY'"},"action":{"name":"can_read_user"},"resource":{"type":"user","id":"jerry@the-smiths.com"}}' "True"
test_evaluation '{"subject":{"type":"user","id":"'$JERRY'"},"action":{"name":"can_read_todos"},"resource":{"type":"todo","id":"todo-1"}}' "True"
test_evaluation '{"subject":{"type":"user","id":"'$JERRY'"},"action":{"name":"can_create_todo"},"resource":{"type":"todo","id":"todo-1"}}' "False"
test_evaluation '{"subject":{"type":"user","id":"'$JERRY'"},"action":{"name":"can_update_todo"},"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b92","properties":{"ownerID":"rick@the-citadel.com"}}}' "False"
test_evaluation '{"subject":{"type":"user","id":"'$JERRY'"},"action":{"name":"can_update_todo"},"resource":{"type":"todo","id":"240d0db-8ff0-41ec-98b2-34a096273b95","properties":{"ownerID":"jerry@the-smiths.com"}}}' "False"
test_evaluation '{"subject":{"type":"user","id":"'$JERRY'"},"action":{"name":"can_delete_todo"},"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b92","properties":{"ownerID":"rick@the-citadel.com"}}}' "False"
test_evaluation '{"subject":{"type":"user","id":"'$JERRY'"},"action":{"name":"can_delete_todo"},"resource":{"type":"todo","id":"240d0db-8ff0-41ec-98b2-34a096273b95","properties":{"ownerID":"jerry@the-smiths.com"}}}' "False"

# --- Batch Evaluations (1_0-02) ---
echo ""
echo "--- Batch Evaluations ---"

test_evaluations '{"subject":{"type":"user","id":"'$RICK'"},"action":{"name":"can_update_todo"},"evaluations":[{"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b92","properties":{"ownerID":"rick@the-citadel.com"}}},{"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b95","properties":{"ownerID":"jerry@the-smiths.com"}}}]}' '[{"decision": true}, {"decision": true}]'

test_evaluations '{"subject":{"type":"user","id":"'$MORTY'"},"action":{"name":"can_update_todo"},"evaluations":[{"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b92","properties":{"ownerID":"rick@the-citadel.com"}}},{"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b91","properties":{"ownerID":"morty@the-citadel.com"}}}]}' '[{"decision": false}, {"decision": true}]'

test_evaluations '{"subject":{"type":"user","id":"'$JERRY'"},"action":{"name":"can_update_todo"},"evaluations":[{"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b92","properties":{"ownerID":"rick@the-citadel.com"}}},{"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b95","properties":{"ownerID":"jerry@the-smiths.com"}}}]}' '[{"decision": false}, {"decision": false}]'

# A batch request with no evaluations, or an empty array, behaves as a single
# Access Evaluation (Section 7.1), so the response is the singular shape:
# a top-level decision and no evaluations array (certification c-3-4-2/3).
test_evaluations_singular() {
  local label="$1" request="$2" expected="$3"

  response=$(curl -s -w "\n%{http_code}" \
    -X POST "${PDP_URL}/access/v1/evaluations" \
    -H "Content-Type: application/json" \
    -d "$request" 2>/dev/null) || { echo -e "${YELLOW}ERROR${NC} Connection failed [${label}]"; ERROR=$((ERROR+1)); return; }

  http_code=$(echo "$response" | tail -1)
  body=$(echo "$response" | sed '$d')

  if [ "$http_code" != "200" ]; then
    echo -e "${YELLOW}ERROR${NC} HTTP $http_code [${label}]"
    ERROR=$((ERROR+1))
    return
  fi

  result=$(BODY="$body" EXPECTED="$expected" python3 <<'EOF'
import json, os
r = json.loads(os.environ["BODY"])
want = os.environ["EXPECTED"] == "true"
print("ok" if "evaluations" not in r and r.get("decision") is want else "bad")
EOF
)

  if [ "$result" = "ok" ]; then
    echo -e "${GREEN}PASS${NC} ${label}"
    PASS=$((PASS+1))
  else
    echo -e "${RED}FAIL${NC} ${label}"
    echo "  Request: $request"
    echo "  Response: $body"
    FAIL=$((FAIL+1))
  fi
}

test_evaluations_singular "batch/no evaluations array answers singular (permit)" \
  '{"subject":{"type":"user","id":"'"$RICK"'"},"action":{"name":"can_read_todos"},"resource":{"type":"todo","id":"todo-1"}}' true

test_evaluations_singular "batch/empty evaluations array answers singular (deny)" \
  '{"subject":{"type":"user","id":"'"$BETH"'"},"action":{"name":"can_create_todo"},"resource":{"type":"todo","id":"todo-1"},"evaluations":[]}' false

# --- Search APIs (AuthZEN spec Section 8) ---
echo ""
echo "--- Search APIs ---"

# test_search_count posts to a Search endpoint and asserts the number of
# entries in `results`. Args: endpoint, request body, expected count, label.
test_search_count() {
  local endpoint="$1"
  local request="$2"
  local expected="$3"
  local label="$4"

  response=$(curl -s -w "\n%{http_code}" \
    -X POST "${PDP_URL}${endpoint}" \
    -H "Content-Type: application/json" \
    -d "$request" 2>/dev/null) || { echo -e "${YELLOW}ERROR${NC} Connection failed"; ERROR=$((ERROR+1)); return; }

  http_code=$(echo "$response" | tail -1)
  body=$(echo "$response" | sed '$d')

  if [ "$http_code" != "200" ]; then
    echo -e "${YELLOW}ERROR${NC} HTTP $http_code [${label}]"
    ERROR=$((ERROR+1))
    return
  fi

  actual=$(echo "$body" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('results', [])))" 2>/dev/null)

  if [ "$actual" = "$expected" ]; then
    echo -e "${GREEN}PASS${NC} ${label} -> ${actual} result(s)"
    PASS=$((PASS+1))
  else
    echo -e "${RED}FAIL${NC} ${label}: expected ${expected} results, got ${actual}"
    echo "  Request: $request"
    echo "  Response: $body"
    FAIL=$((FAIL+1))
  fi
}

# Subject Search: 5 users can can_read_user (anyone in data.users).
test_search_count "/access/v1/search/subject" \
  '{"subject":{"type":"user"},"action":{"name":"can_read_user"},"resource":{"type":"user","id":"beth@the-smiths.com"}}' \
  5 "subject_search/can_read_user"

# Subject Search: 3 users can can_create_todo (admin/editor only).
test_search_count "/access/v1/search/subject" \
  '{"subject":{"type":"user"},"action":{"name":"can_create_todo"},"resource":{"type":"todo","id":"todo-1"}}' \
  3 "subject_search/can_create_todo"

# Subject Search: only Rick can update a Rick-owned todo.
test_search_count "/access/v1/search/subject" \
  '{"subject":{"type":"user"},"action":{"name":"can_update_todo"},"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b92","properties":{"ownerID":"rick@the-citadel.com"}}}' \
  1 "subject_search/can_update_todo on Rick-owned"

# Resource Search: Rick (admin) can update every todo in data.
test_search_count "/access/v1/search/resource" \
  '{"subject":{"type":"user","id":"'$RICK'"},"action":{"name":"can_update_todo"},"resource":{"type":"todo"}}' \
  4 "resource_search/Rick can_update_todo"

# Resource Search: Morty can only update his own todo.
test_search_count "/access/v1/search/resource" \
  '{"subject":{"type":"user","id":"'$MORTY'"},"action":{"name":"can_update_todo"},"resource":{"type":"todo"}}' \
  1 "resource_search/Morty can_update_todo"

# Resource Search: Beth (viewer) can't update anything.
test_search_count "/access/v1/search/resource" \
  '{"subject":{"type":"user","id":"'$BETH'"},"action":{"name":"can_update_todo"},"resource":{"type":"todo"}}' \
  0 "resource_search/Beth can_update_todo"

# Resource Search: user-typed search returns all 5 known users (can_read_user
# is universal). Verifies that the rule selects the correct branch by
# input.resource.type.
test_search_count "/access/v1/search/resource" \
  '{"subject":{"type":"user","id":"'$RICK'"},"action":{"name":"can_read_user"},"resource":{"type":"user"}}' \
  5 "resource_search/Rick can_read_user (type=user)"

# Resource Search: an unmodeled type returns no results.
test_search_count "/access/v1/search/resource" \
  '{"subject":{"type":"user","id":"'$RICK'"},"action":{"name":"can_read_user"},"resource":{"type":"spaceship"}}' \
  0 "resource_search/unknown type returns empty"

# Action Search: Rick (admin) on a todo gets every todo-scoped action.
# can_read_user is excluded because the policy guards each rule by the
# action's expected resource type.
test_search_count "/access/v1/search/action" \
  '{"subject":{"type":"user","id":"'$RICK'"},"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b92","properties":{"ownerID":"rick@the-citadel.com"}}}' \
  4 "action_search/Rick on own todo (todo-scoped only)"

# Action Search: Rick (admin) on a user resource: only can_read_user is
# in scope. Catches cross-type leakage like surfacing can_update_todo
# against a user resource.
test_search_count "/access/v1/search/action" \
  '{"subject":{"type":"user","id":"'$RICK'"},"resource":{"type":"user","id":"beth@the-smiths.com"}}' \
  1 "action_search/Rick on user resource (user-scoped only)"

# Action Search: Morty on Rick's todo -> read_todos and create_todo only.
test_search_count "/access/v1/search/action" \
  '{"subject":{"type":"user","id":"'$MORTY'"},"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b92","properties":{"ownerID":"rick@the-citadel.com"}}}' \
  2 "action_search/Morty on Rick's todo"

# Action Search: Beth (viewer) on a todo -> can_read_todos only.
test_search_count "/access/v1/search/action" \
  '{"subject":{"type":"user","id":"'$BETH'"},"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b94","properties":{"ownerID":"beth@the-smiths.com"}}}' \
  1 "action_search/Beth on own todo"

# Resource Search: a todo-scoped action against a user-typed search must
# return zero results — the policy's per-rule resource-type guard stops
# the cross-type leakage that the unguarded version had.
test_search_count "/access/v1/search/resource" \
  '{"subject":{"type":"user","id":"'$RICK'"},"action":{"name":"can_read_todos"},"resource":{"type":"user"}}' \
  0 "resource_search/cross-type leak guarded"

# Subject Search: a non-user subject type must not fall through and
# enumerate data.users. Same cross-type guard as above, applied to the
# subject dimension.
test_search_count "/access/v1/search/subject" \
  '{"subject":{"type":"robot"},"action":{"name":"can_read_user"},"resource":{"type":"user","id":"beth@the-smiths.com"}}' \
  0 "subject_search/non-user type returns empty"

# Pagination: 5 known users / limit=3 -> page 1 returns 3 + a token, page 2
# returns the remaining 2 and an empty next_token. limit=3 is chosen so the
# whole result set is traversed in exactly two requests, letting the
# assertion below check completion semantics, not just partial coverage.
echo ""
echo "--- Search pagination ---"
page1_resp=$(curl -s -X POST "${PDP_URL}/access/v1/search/subject" \
  -H "Content-Type: application/json" \
  -d '{"subject":{"type":"user"},"action":{"name":"can_read_user"},"resource":{"type":"user","id":"beth@the-smiths.com"},"page":{"limit":3}}')
page1_count=$(echo "$page1_resp" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['results']))" 2>/dev/null)
page1_token=$(echo "$page1_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['page']['next_token'])" 2>/dev/null)
if [ "$page1_count" = "3" ] && [ -n "$page1_token" ]; then
  echo -e "${GREEN}PASS${NC} pagination/page-1 returned 3 + non-empty next_token"
  PASS=$((PASS+1))
else
  echo -e "${RED}FAIL${NC} pagination/page-1: count=$page1_count token=$page1_token"
  echo "  Response: $page1_resp"
  FAIL=$((FAIL+1))
fi

# Follow the token. The combined result set must contain all 5 distinct
# users and the response MUST advertise an empty next_token, i.e. the
# pagination sequence terminates exactly when the data is exhausted.
page2_resp=$(curl -s -X POST "${PDP_URL}/access/v1/search/subject" \
  -H "Content-Type: application/json" \
  -d "{\"subject\":{\"type\":\"user\"},\"action\":{\"name\":\"can_read_user\"},\"resource\":{\"type\":\"user\",\"id\":\"beth@the-smiths.com\"},\"page\":{\"limit\":3,\"token\":\"$page1_token\"}}")
# JSON bodies are passed via env vars so quotes/backslashes in PDP responses
# can't break the Python literal. The heredoc is single-quoted for the same
# reason on the shell side.
page2_check=$(PAGE1_RESP="$page1_resp" PAGE2_RESP="$page2_resp" python3 <<'EOF'
import json, os
p1 = json.loads(os.environ["PAGE1_RESP"])["results"]
p2 = json.loads(os.environ["PAGE2_RESP"])
ids = {r["id"] for r in p1 + p2["results"]}
next_token = p2.get("page", {}).get("next_token", None)
print("ok" if len(ids) == 5 and next_token == "" else "bad")
EOF
)
if [ "$page2_check" = "ok" ]; then
  echo -e "${GREEN}PASS${NC} pagination/page-2 closes the sequence (5 unique results, empty next_token)"
  PASS=$((PASS+1))
else
  echo -e "${RED}FAIL${NC} pagination/page-2 unexpected"
  echo "  Page 1: $page1_resp"
  echo "  Page 2: $page2_resp"
  FAIL=$((FAIL+1))
fi

# Pagination tamper: replay the page-1 token but with a different resource
# id (limit unchanged). The PDP must reject this with 400 because the
# entities bound to the token no longer match the new request.
tamper_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${PDP_URL}/access/v1/search/subject" \
  -H "Content-Type: application/json" \
  -d "{\"subject\":{\"type\":\"user\"},\"action\":{\"name\":\"can_read_user\"},\"resource\":{\"type\":\"user\",\"id\":\"different\"},\"page\":{\"limit\":3,\"token\":\"$page1_token\"}}")
if [ "$tamper_code" = "400" ]; then
  echo -e "${GREEN}PASS${NC} pagination/tamper detected (400)"
  PASS=$((PASS+1))
else
  echo -e "${RED}FAIL${NC} pagination/tamper expected 400, got $tamper_code"
  FAIL=$((FAIL+1))
fi

# --- Evaluation semantics (AuthZEN spec Section 7.1.2.1) ---
# options.evaluations_semantic controls short-circuiting. Morty can update a
# todo he owns (morty-owned -> true) but not one Rick owns (rick-owned ->
# false), so this true/false pair, ordered per semantic, is enough to show
# each behaviour distinctly via the length and contents of the result array.
echo ""
echo "--- Evaluation semantics ---"

MORTY_RICK_OWNED='{"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b92","properties":{"ownerID":"rick@the-citadel.com"}}}'
MORTY_OWNED='{"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b91","properties":{"ownerID":"morty@the-citadel.com"}}}'

# execute_all: every request runs; results returned in request order.
test_evaluations '{"subject":{"type":"user","id":"'"$MORTY"'"},"action":{"name":"can_update_todo"},"options":{"evaluations_semantic":"execute_all"},"evaluations":['"$MORTY_RICK_OWNED"','"$MORTY_OWNED"']}' '[{"decision": false}, {"decision": true}]'

# deny_on_first_deny: stops at the first deny (rick-owned), so one result only.
test_evaluations '{"subject":{"type":"user","id":"'"$MORTY"'"},"action":{"name":"can_update_todo"},"options":{"evaluations_semantic":"deny_on_first_deny"},"evaluations":['"$MORTY_RICK_OWNED"','"$MORTY_OWNED"']}' '[{"decision": false}]'

# permit_on_first_permit: stops at the first permit (morty-owned), one result.
test_evaluations '{"subject":{"type":"user","id":"'"$MORTY"'"},"action":{"name":"can_update_todo"},"options":{"evaluations_semantic":"permit_on_first_permit"},"evaluations":['"$MORTY_OWNED"','"$MORTY_RICK_OWNED"']}' '[{"decision": true}]'

# --- Decision context & Obligations Profile (Section 5.5.1 + profile) ---
echo ""
echo "--- Decision context & obligations ---"

MORTY_TODO="7240d0db-8ff0-41ec-98b2-34a096273b91"

# test_decision_context compares the response's OPTIONAL `context` member
# against an expected JSON object; an empty expected value asserts it is
# absent. Structural comparison, so key order does not matter.
test_decision_context() {
  local label="$1" request="$2" expected="$3"

  response=$(curl -s -w "\n%{http_code}" \
    -X POST "${PDP_URL}/access/v1/evaluation" \
    -H "Content-Type: application/json" \
    -d "$request" 2>/dev/null) || { echo -e "${YELLOW}ERROR${NC} Connection failed [${label}]"; ERROR=$((ERROR+1)); return; }

  http_code=$(echo "$response" | tail -1)
  body=$(echo "$response" | sed '$d')

  if [ "$http_code" != "200" ]; then
    echo -e "${YELLOW}ERROR${NC} HTTP $http_code [${label}]"
    ERROR=$((ERROR+1))
    return
  fi

  result=$(BODY="$body" EXPECTED="$expected" python3 <<'EOF'
import json, os
ctx = json.loads(os.environ["BODY"]).get("context")
exp = os.environ["EXPECTED"]
want = None if exp == "" else json.loads(exp)
print("ok" if ctx == want else "bad: " + json.dumps(ctx, sort_keys=True))
EOF
)

  if [ "$result" = "ok" ]; then
    echo -e "${GREEN}PASS${NC} ${label}"
    PASS=$((PASS+1))
  else
    echo -e "${RED}FAIL${NC} ${label}"
    echo "  Expected: ${expected:-<absent>}"
    echo "  Actual:   $result"
    FAIL=$((FAIL+1))
  fi
}

# Every decision carries a reason (Section 5.5.1).
test_decision_context "context/reason on permit" \
  '{"subject":{"type":"user","id":"'"$RICK"'"},"action":{"name":"can_read_todos"},"resource":{"type":"todo","id":"todo-1"}}' \
  '{"reason":"permitted"}'

test_decision_context "context/reason on deny" \
  '{"subject":{"type":"user","id":"'"$BETH"'"},"action":{"name":"can_create_todo"},"resource":{"type":"todo","id":"todo-1"}}' \
  '{"reason":"not_permitted"}'

test_decision_context "context/reason on unknown subject" \
  '{"subject":{"type":"user","id":"bm8tc3VjaC11c2Vy"},"action":{"name":"can_read_todos"},"resource":{"type":"todo","id":"todo-1"}}' \
  '{"reason":"unknown_subject"}'

# Obligation on a permit: Rick (admin) mutates a todo Morty owns, and the PEP
# declared it can execute `notification`, so the owner must be notified.
test_decision_context "obligations/notification issued on cross-owner update" \
  '{"subject":{"type":"user","id":"'"$RICK"'"},"action":{"name":"can_update_todo"},"resource":{"type":"todo","id":"'"$MORTY_TODO"'","properties":{"ownerID":"morty@the-citadel.com"}},"context":{"supported_obligations":["notification"]}}' \
  '{"reason":"permitted","negotiated_obligations":["notification"],"obligations":[{"id":"notify-owner-'"$MORTY_TODO"'","type":"notification","properties":{"recipient":"morty@the-citadel.com","event":"can_update_todo","actor":"rick@the-citadel.com"}}]}'

# PEP silent: no obligation, and an absent member stays absent rather than
# becoming an empty array.
test_decision_context "obligations/none when PEP declares nothing" \
  '{"subject":{"type":"user","id":"'"$RICK"'"},"action":{"name":"can_update_todo"},"resource":{"type":"todo","id":"'"$MORTY_TODO"'","properties":{"ownerID":"morty@the-citadel.com"}},"context":{}}' \
  '{"reason":"permitted"}'

# The plugin MUST drop a type it never advertised before the policy sees it,
# so the echoed set is exactly ["notification"]. Fails against an unfiltered
# PDP, which echoes carrier-pigeon back.
test_decision_context "obligations/unadvertised type filtered out" \
  '{"subject":{"type":"user","id":"'"$RICK"'"},"action":{"name":"can_update_todo"},"resource":{"type":"todo","id":"'"$MORTY_TODO"'","properties":{"ownerID":"morty@the-citadel.com"}},"context":{"supported_obligations":["notification","carrier-pigeon"]}}' \
  '{"reason":"permitted","negotiated_obligations":["notification"],"obligations":[{"id":"notify-owner-'"$MORTY_TODO"'","type":"notification","properties":{"recipient":"morty@the-citadel.com","event":"can_update_todo","actor":"rick@the-citadel.com"}}]}'

# `step-up` is a registered type but not advertised here, so it filters down
# to an empty array, which the profile keeps rather than deletes.
test_decision_context "obligations/declared set filtered to empty" \
  '{"subject":{"type":"user","id":"'"$RICK"'"},"action":{"name":"can_update_todo"},"resource":{"type":"todo","id":"'"$MORTY_TODO"'","properties":{"ownerID":"morty@the-citadel.com"}},"context":{"supported_obligations":["step-up"]}}' \
  '{"reason":"permitted","negotiated_obligations":[]}'

# Acting on your own todo creates no duty to notify anyone.
test_decision_context "obligations/none on own todo" \
  '{"subject":{"type":"user","id":"'"$RICK"'"},"action":{"name":"can_update_todo"},"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b92","properties":{"ownerID":"rick@the-citadel.com"}},"context":{"supported_obligations":["notification"]}}' \
  '{"reason":"permitted","negotiated_obligations":["notification"]}'

# Per-evaluation context on the batch endpoint: only the cross-owner one
# carries a duty.
batch_ctx_resp=$(curl -s -X POST "${PDP_URL}/access/v1/evaluations" \
  -H "Content-Type: application/json" \
  -d '{"subject":{"type":"user","id":"'"$RICK"'"},"action":{"name":"can_update_todo"},"context":{"supported_obligations":["notification"]},"evaluations":[{"resource":{"type":"todo","id":"7240d0db-8ff0-41ec-98b2-34a096273b92","properties":{"ownerID":"rick@the-citadel.com"}}},{"resource":{"type":"todo","id":"'"$MORTY_TODO"'","properties":{"ownerID":"morty@the-citadel.com"}}}]}')
batch_ctx_check=$(BODY="$batch_ctx_resp" python3 <<'EOF'
import json, os
evals = json.loads(os.environ["BODY"]).get("evaluations", [])
if len(evals) != 2:
    print("bad: expected 2 evaluations")
else:
    own, other = (e.get("context", {}) for e in evals)
    ok = (
        all(e.get("decision") is True for e in evals)
        and "obligations" not in own
        and [o["type"] for o in other.get("obligations", [])] == ["notification"]
    )
    print("ok" if ok else "bad: " + json.dumps(evals, sort_keys=True))
EOF
)
if [ "$batch_ctx_check" = "ok" ]; then
  echo -e "${GREEN}PASS${NC} obligations/per-evaluation context in batch"
  PASS=$((PASS+1))
else
  echo -e "${RED}FAIL${NC} obligations/per-evaluation context in batch"
  echo "  $batch_ctx_check"
  FAIL=$((FAIL+1))
fi

# --- PDP metadata & transport (AuthZEN spec Sections 9 & 10) ---
echo ""
echo "--- PDP metadata & transport ---"

# test_status asserts only the HTTP status code of a request, for the
# transport-level behaviours (Section 10) that the decision helpers above
# don't exercise.
test_status() {
  local label="$1" method="$2" path="$3" ctype="$4" body="$5" expected="$6"
  local args=(-s -o /dev/null -w "%{http_code}" -X "$method" "${PDP_URL}${path}")
  [ -n "$ctype" ] && args+=(-H "Content-Type: $ctype")
  [ -n "$body" ] && args+=(--data-raw "$body")
  local code
  code=$(curl "${args[@]}" 2>/dev/null) || { echo -e "${YELLOW}ERROR${NC} Connection failed [${label}]"; ERROR=$((ERROR+1)); return; }
  if [ "$code" = "$expected" ]; then
    echo -e "${GREEN}PASS${NC} $label (HTTP $code)"
    PASS=$((PASS+1))
  else
    echo -e "${RED}FAIL${NC} $label expected $expected, got $code"
    FAIL=$((FAIL+1))
  fi
}

VALID_EVAL='{"subject":{"type":"user","id":"'"$RICK"'"},"action":{"name":"can_read_todos"},"resource":{"type":"todo","id":"todo-1"}}'

# Well-known metadata document (Section 9): validate structure, not the host.
# Search endpoints are advertised because all three rules are configured.
# `capabilities` (Section 9.1.2), `supported_obligations` and the Access
# Request and Approval discovery members come from config.yaml.
if wk_resp=$(curl -s "${PDP_URL}/.well-known/authzen-configuration"); then
  wk_check=$(WK="$wk_resp" python3 <<'EOF'
import base64, json, os
try:
    m = json.loads(os.environ.get("WK", ""))
    if not isinstance(m, dict):
        raise ValueError("response is not a JSON object")
    checks = [
        ("access_evaluation_endpoint", "/access/v1/evaluation"),
        ("access_evaluations_endpoint", "/access/v1/evaluations"),
        ("search_subject_endpoint", "/access/v1/search/subject"),
        ("search_resource_endpoint", "/access/v1/search/resource"),
        ("search_action_endpoint", "/access/v1/search/action"),
    ]
    ok = isinstance(m.get("policy_decision_point"), str)
    ok = ok and all(isinstance(m.get(k), str) and m[k].endswith(suf) for k, suf in checks)
    caps = m.get("capabilities")
    ok = ok and isinstance(caps, list) and caps == ["urn:kanywst:authzen:capability:todo-interop"]
    ok = ok and m.get("supported_obligations") == ["notification"]
    # Access Request and Approval Profile discovery: advertised verbatim from
    # config, not derived from the request host like the endpoints above.
    ok = ok and m.get("access_request_endpoint") == "https://requests.example.com/access/v1/requests"
    ok = ok and m.get("jwks_uri") == "https://requests.example.com/access/v1/jwks"
    # Signed metadata (Section 9.1.3): published verbatim, with the REQUIRED
    # iss claim.
    sm = m.get("signed_metadata")
    ok = ok and isinstance(sm, str) and sm.count(".") == 2
    if ok:
        seg = sm.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
        ok = claims.get("iss") == "https://pdp.example.com"
    print("ok" if ok else "bad")
except Exception:
    print("bad")
EOF
)
  if [ "$wk_check" = "ok" ]; then
    echo -e "${GREEN}PASS${NC} well-known advertises endpoints, capabilities, obligations, access request, signed metadata (Section 9)"
    PASS=$((PASS+1))
  else
    echo -e "${RED}FAIL${NC} well-known metadata unexpected"
    echo "  Response: $wk_resp"
    FAIL=$((FAIL+1))
  fi
else
  echo -e "${YELLOW}ERROR${NC} Connection failed [well-known metadata]"
  ERROR=$((ERROR+1))
fi

# X-Request-ID echo (Section 10.1.3, MUST): the PDP returns the same id.
RID="e2e-$(date +%s)-abc"
if echoed_resp=$(curl -s -D - -o /dev/null -X POST "${PDP_URL}/access/v1/evaluation" \
  -H "Content-Type: application/json" -H "X-Request-ID: $RID" \
  --data-raw "$VALID_EVAL" 2>/dev/null); then
  echoed=$(printf "%s\n" "$echoed_resp" | tr -d '\r' | awk 'tolower($0) ~ /^x-request-id:/{val=$0; sub(/^[^:]+:[ \t]*/, "", val); print val}')
  if [ "$echoed" = "$RID" ]; then
    echo -e "${GREEN}PASS${NC} X-Request-ID echoed on response (Section 10.1.3)"
    PASS=$((PASS+1))
  else
    echo -e "${RED}FAIL${NC} X-Request-ID expected '$RID', got '$echoed'"
    FAIL=$((FAIL+1))
  fi
else
  echo -e "${YELLOW}ERROR${NC} Connection failed [X-Request-ID]"
  ERROR=$((ERROR+1))
fi

# Transport-level error handling (Section 10.1 / 10.1.2).
test_status "well-known GET returns 200"         GET  "/.well-known/authzen-configuration" ""                 ""            200
test_status "wrong Content-Type rejected"        POST "/access/v1/evaluation"              "text/plain"       "$VALID_EVAL" 400
# Media types are case-insensitive and tolerate whitespace (RFC 9110 8.3.1).
test_status "mixed-case Content-Type accepted"   POST "/access/v1/evaluation"              "Application/JSON" "$VALID_EVAL" 200
test_status "spaced Content-Type accepted"       POST "/access/v1/evaluation"              "application/json ; charset=utf-8" "$VALID_EVAL" 200
test_status "malformed JSON body rejected"       POST "/access/v1/evaluation"              "application/json" '{"subject":' 400
test_status "missing required resource rejected" POST "/access/v1/evaluation"              "application/json" '{"subject":{"type":"user","id":"'"$RICK"'"},"action":{"name":"can_read_todos"}}' 400

# Batch over the 100-evaluation limit must be rejected with 413 (Section 11.7).
over_body=$(RICK="$RICK" python3 <<'EOF'
import json, os
evals = [{"resource": {"type": "todo", "id": f"todo-{i}"}} for i in range(101)]
print(json.dumps({"subject": {"type": "user", "id": os.environ["RICK"]},
                  "action": {"name": "can_read_todos"}, "evaluations": evals}))
EOF
)
test_status "batch over 100 evaluations rejected" POST "/access/v1/evaluations" "application/json" "$over_body" 413

# --- Summary ---
echo ""
echo "=== Results ==="
TOTAL=$((PASS + FAIL + ERROR))
echo "Total: $TOTAL  Pass: $PASS  Fail: $FAIL  Error: $ERROR"

if [ "$FAIL" -eq 0 ] && [ "$ERROR" -eq 0 ]; then
  echo -e "${GREEN}All tests passed!${NC}"
  exit 0
else
  echo -e "${RED}Some tests failed.${NC}"
  exit 1
fi
