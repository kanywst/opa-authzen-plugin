#!/usr/bin/env bash
set -x

usage() {
    echo "github-release.sh [--asset-dir=<path>] [--tag=<git tag>]"
}

TAG_NAME=${TAG_NAME:?"Error: TAG_NAME must be set"}
ASSET_DIR=${PWD:-"./"}

for i in "$@"; do
    case $i in
    --asset-dir=*)
        ASSET_DIR="${i#*=}"
        shift
        ;;
    --tag=*)
        TAG_NAME="${i#*=}"
        shift
        ;;
    *)
        usage
        exit 1
        ;;
    esac
done

ASSETS=()
for asset in "${ASSET_DIR}"/opa_authzen_*; do
    [ -e "$asset" ] || continue
    ASSETS+=("$asset")
done

RELEASE_NOTES="release-notes.md"
echo -e "${TAG_NAME}\n" > "${RELEASE_NOTES}"
echo -e "See the [CHANGELOG](CHANGELOG.md) for details." >> "${RELEASE_NOTES}"

if gh release view "${TAG_NAME}" > /dev/null 2>&1; then
    gh release upload "${TAG_NAME}" "${ASSETS[@]}"
else
    gh release create "${TAG_NAME}" "${ASSETS[@]}" -F "${RELEASE_NOTES}" --draft --title "${TAG_NAME}"
fi
