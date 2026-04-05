#!/usr/bin/env bash
# Get number of commits since the last OPA version bump in go.mod.
git config --global --add safe.directory /src 2>/dev/null
LINE=$(git grep -n "github.com/open-policy-agent/opa " go.mod | awk -F: '{ print $2 }')
GIT_SHA=$(git log -n 1 --pretty=format:%H -L "$LINE","$LINE":go.mod | head -1)
COMMITS=$(git rev-list "$GIT_SHA"..HEAD --count)
if [ "$COMMITS" -ne 0 ]; then
  echo "-$COMMITS"
fi
