#!/bin/bash
# Generates .version file with format: <semver>+<git-short-sha>
# Called by: npm run build (via package.json), update.sh
# Output: .version file in project root

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PKG_VERSION=$(node -p "require('./package.json').version" 2>/dev/null || echo "0.0.0")
GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_DATE=$(git log -1 --format=%cd --date=format:'%Y-%m-%d' 2>/dev/null || echo "")

VERSION="${PKG_VERSION}+${GIT_SHA}"

echo "$VERSION" > .version
echo "Version: $VERSION (commit date: ${GIT_DATE:-unknown})"
