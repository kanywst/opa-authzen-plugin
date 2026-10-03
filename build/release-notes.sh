#!/usr/bin/env bash
# Usage: release-notes.sh TAG [CHANGELOG]
#
# Prints the GitHub Release body for TAG: the release date, that version's
# CHANGELOG section verbatim, and the commands that verify its signed assets
# and image. post-tag.yaml hands the output to GoReleaser as --release-notes.
set -euo pipefail

tag=$1 changelog=${2:-CHANGELOG.md}
version=${tag#v}

heading=$(grep -m1 -E "^## \[$tag\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$" "$changelog" || true)
if [ -z "$heading" ]; then
  echo "no '## [$tag] - YYYY-MM-DD' heading in $changelog" >&2
  exit 1
fi
date=${heading##* - }

# The section runs from its heading to the next `---` rule.
section=$(awk -v h="$heading" '
  $0 == h { found = 1; next }
  found && /^---$/ { exit }
  found { print }
' "$changelog" | sed -e '/./,$!d')
if [ -z "$section" ]; then
  echo "the $tag section of $changelog is empty" >&2
  exit 1
fi

cat <<EOF
Released $date

$section

### Verifying this release

\`\`\`bash
cosign verify-blob checksums.txt \\
  --bundle checksums.txt.sigstore.json \\
  --certificate-identity-regexp '^https://github\.com/kanywst/opa-authzen-plugin/\.github/workflows/post-tag\.yaml@refs/tags/v' \\
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

sha256sum --check --ignore-missing checksums.txt

cosign verify ghcr.io/kanywst/opa-authzen-plugin:$version \\
  --certificate-identity-regexp '^https://github\.com/kanywst/opa-authzen-plugin/\.github/workflows/publish\.yaml@refs/tags/v' \\
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
\`\`\`
EOF
