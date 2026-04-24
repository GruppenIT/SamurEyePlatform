#!/usr/bin/env bash
# SamurEye Phase 8 — iterate binaries.json and install every entry.
# Usage: install-binaries.sh [--manifest <path>] [--install-dir <path>]

set -Eeuo pipefail

MANIFEST_ARG="${MANIFEST:-}"
INSTALL_DIR_ARG="${INSTALL_DIR:-/opt/samureye}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)    MANIFEST_ARG="$2"; shift 2 ;;
    --install-dir) INSTALL_DIR_ARG="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 [--manifest <path>] [--install-dir <path>]"; exit 0 ;;
    *) echo "Flag desconhecida: $1" >&2; exit 1 ;;
  esac
done

# Default manifest location if not provided
if [[ -z "$MANIFEST_ARG" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  MANIFEST_ARG="$SCRIPT_DIR/binaries.json"
fi

export MANIFEST="$MANIFEST_ARG"
export INSTALL_DIR="$INSTALL_DIR_ARG"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/fetch-binary.sh"

for name in $(jq -r '.binaries | keys[]' "$MANIFEST"); do
  install_binary "$name"
done
