#!/usr/bin/env bash
# SamurEye Phase 8 — preserve staging + restore.
# Sourced by install.sh (--update). Requires PRESERVE_PATHS array + INSTALL_DIR.
#
# Required env: INSTALL_DIR
# Required bash array: PRESERVE_PATHS (defined at top of install.sh; exported or sourced)
# Exports: STAGING_DIR (populated by preserve_paths_to_staging)

set -Eeuo pipefail

if ! declare -F log >/dev/null 2>&1; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  NC='\033[0m'
  log()   { echo -e "${GREEN}[INFO]${NC} $*"; }
  warn()  { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
  error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
fi

: "${INSTALL_DIR:?INSTALL_DIR must be set}"

# Global state shared with caller
STAGING_DIR=""
declare -a MOVED_PATHS=()

# ── preserve_paths_to_staging ───────────────────────────────────────────
# Pitfall 8: use mktemp -d, not /tmp/samureye-preserve-$$.
# Pitfall 9: MUST be called BEFORE git reset / git clean — strict order.
preserve_paths_to_staging() {
  if [[ -z "${PRESERVE_PATHS+x}" ]]; then
    error "PRESERVE_PATHS array not defined — refusing to preserve"
    return 1
  fi
  STAGING_DIR="$(mktemp -d -t samureye-preserve-XXXXXX)"
  MOVED_PATHS=()
  local p src dest_parent
  for p in "${PRESERVE_PATHS[@]}"; do
    src="$INSTALL_DIR/$p"
    if [[ -e "$src" ]]; then
      dest_parent="$STAGING_DIR/$(dirname "$p")"
      mkdir -p "$dest_parent"
      if mv "$src" "$dest_parent/"; then
        MOVED_PATHS+=("$p")
        log "Preservado: $p -> $STAGING_DIR/$p"
      else
        error "Falha ao mover $p para staging em $STAGING_DIR"
        error "Staging preservado em: $STAGING_DIR"
        return 1
      fi
    fi
  done
  log "Staging em $STAGING_DIR (${#MOVED_PATHS[@]} paths preservados)"
}

# ── restore_paths_from_staging ──────────────────────────────────────────
# Pitfall 2: NEVER rm STAGING_DIR unless every mv back succeeded.
restore_paths_from_staging() {
  if [[ -z "$STAGING_DIR" || ! -d "$STAGING_DIR" ]]; then
    error "restore_paths_from_staging chamado sem staging valido"
    return 1
  fi
  local p src dest_parent
  for p in "${MOVED_PATHS[@]}"; do
    src="$STAGING_DIR/$p"
    dest_parent="$INSTALL_DIR/$(dirname "$p")"
    mkdir -p "$dest_parent"
    if ! mv "$src" "$dest_parent/"; then
      error "Falha ao restaurar $p"
      error "Artefato preservado em: $STAGING_DIR/$p  -- NAO APAGUE"
      error "STAGING_DIR completo: $STAGING_DIR"
      return 1
    fi
    log "Restaurado: $p (ownership intacto via mv)"
  done
  # All restored — safe to clean
  rm -rf "$STAGING_DIR"
  STAGING_DIR=""
  log "Todos os paths preservados foram restaurados"
}
