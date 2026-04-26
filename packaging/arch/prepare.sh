#!/usr/bin/env bash
# Render PKGBUILD from PKGBUILD.in, fill in checksums, and produce .SRCINFO.
#
# Usage:
#   ./prepare.sh                # use the latest GitHub release tag
#   ./prepare.sh 0.1.4          # pin a specific version
#   ./prepare.sh v0.1.4         # leading 'v' is accepted and stripped

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
TEMPLATE="$SCRIPT_DIR/PKGBUILD.in"
OUTPUT="$SCRIPT_DIR/PKGBUILD"
REPO_URL="https://github.com/mexus/pacrank"

if [[ ! -f "$TEMPLATE" ]]; then
    echo "error: PKGBUILD.in not found next to this script" >&2
    exit 1
fi

for cmd in curl updpkgsums makepkg sed; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "error: required command '$cmd' is not installed" >&2
        echo "  (updpkgsums and makepkg ship with pacman-contrib and pacman)" >&2
        exit 1
    fi
done

if [[ $# -ge 1 ]]; then
    version=${1#v}
else
    echo "fetching latest release tag from $REPO_URL ..."
    # /releases/latest 302-redirects to /releases/tag/vX.Y.Z; the resolved URL
    # is enough to extract the tag without parsing JSON.
    resolved=$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
        "$REPO_URL/releases/latest")
    tag=${resolved##*/}
    version=${tag#v}
    if [[ -z "$version" || "$version" == "latest" ]]; then
        echo "error: could not resolve latest release tag from $resolved" >&2
        exit 1
    fi
    echo "latest release: v$version"
fi

echo "rendering PKGBUILD with pkgver=$version"
sed "s/@PKGVER@/$version/g" "$TEMPLATE" > "$OUTPUT"

cd "$SCRIPT_DIR"

echo "running updpkgsums ..."
updpkgsums

echo "generating .SRCINFO ..."
makepkg --printsrcinfo > .SRCINFO

echo "done. PKGBUILD and .SRCINFO are ready in $SCRIPT_DIR"
