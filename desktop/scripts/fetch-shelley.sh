#!/bin/bash
# Download the Shelley binary for the current platform.
# Usage: bash scripts/fetch-shelley.sh
set -euo pipefail

REPO="boldsoftware/shelley"
DEST="$(dirname "$0")/../binaries"
mkdir -p "$DEST"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

# Map arch names
case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  arm64)   ARCH="arm64" ;;
esac

echo "Fetching latest Shelley release for ${OS}_${ARCH}..."

# Get the latest release tag
TAG=$(gh release view --repo "$REPO" --json tagName -q '.tagName' 2>/dev/null || echo "")

if [ -z "$TAG" ]; then
  echo "Could not determine latest release. Trying 'latest'..."
  TAG="latest"
fi

echo "Release: $TAG"

# Try to download the matching asset
PATTERN="shelley_${OS}_${ARCH}"
echo "Looking for asset matching: $PATTERN"

if gh release download "$TAG" --repo "$REPO" --pattern "*${PATTERN}*" --dir "$DEST" --clobber 2>/dev/null; then
  # Find and rename the downloaded file
  DOWNLOADED=$(ls "$DEST"/*${PATTERN}* 2>/dev/null | head -1)
  if [ -n "$DOWNLOADED" ]; then
    mv "$DOWNLOADED" "$DEST/shelley"
    chmod +x "$DEST/shelley"
    echo "Downloaded to $DEST/shelley"
    "$DEST/shelley" version 2>/dev/null || echo "(version check skipped)"
    exit 0
  fi
fi

# Fallback: try go install
echo "No pre-built binary found. Trying go install..."
if command -v go &>/dev/null; then
  GOBIN="$DEST" go install "github.com/$REPO/cmd/shelley@latest"
  chmod +x "$DEST/shelley"
  echo "Built and installed to $DEST/shelley"
  "$DEST/shelley" version 2>/dev/null || echo "(version check skipped)"
else
  echo "Error: go not found. Install Go or download Shelley manually."
  echo "  brew install boldsoftware/tap/shelley"
  echo "  # then: cp \$(which shelley) $DEST/shelley"
  exit 1
fi
