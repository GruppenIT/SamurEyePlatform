#!/usr/bin/env bash
# SamurEye Phase 8 — safe hard-reset gate + preserve staging stubs.
# Sourced by install.sh (--update) after Plan 04 wires it in.
#
# Required env: INSTALL_DIR
# Optional env: BRANCH (default "main"), GIT_TOKEN (PAT for private fetch)

set -Eeuo pipefail

# ── Logging (match install.sh) ──────────────────────────────────────────
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
: "${BRANCH:=main}"

# ── safe_reset_gate ─────────────────────────────────────────────────────
# Pre-mutation check. Aborts before ANY write to the tree.
# Exit 1 on: ahead-of-origin OR dirty tree (staged/unstaged/untracked).
# Exit 0 on: clean + synced.
safe_reset_gate() {
  cd "$INSTALL_DIR"

  # 1. Fetch origin/$BRANCH (read-only, does not touch working tree)
  log "Buscando atualizações de origin/$BRANCH..."
  if [[ -n "${GIT_TOKEN:-}" ]]; then
    # Mirror update.sh lines 173-181 — authenticated fetch for private repos
    local repo_url repo_host repo_path fetch_url
    repo_url="$(git remote get-url origin)"
    repo_host="$(echo "$repo_url" | sed -E 's|https?://([^/]+).*|\1|')"
    repo_path="$(echo "$repo_url" | sed -E 's|https?://[^/]+/(.*)|\1|')"
    fetch_url="https://x-access-token:${GIT_TOKEN}@${repo_host}/${repo_path}"
    if ! git fetch "$fetch_url" "$BRANCH" 2>/dev/null; then
      error "Falha ao buscar origin/$BRANCH (com GIT_TOKEN)"
      return 1
    fi
  else
    if ! git fetch origin "$BRANCH" 2>/dev/null; then
      error "Falha ao buscar origin/$BRANCH"
      return 1
    fi
  fi

  # 2. Detect commits ahead of origin/$BRANCH (INFRA-01 abort trigger #1)
  #    Uses git rev-list --count to count commits in HEAD not in origin/$BRANCH.
  local ahead
  ahead="$(git rev-list --count "origin/${BRANCH}..HEAD" 2>/dev/null || echo 0)"
  if [[ "$ahead" -gt 0 ]]; then
    error "Abort: $ahead commit(s) local(is) não-pushados ahead de origin/$BRANCH:"
    git log --oneline "origin/${BRANCH}..HEAD" >&2
    error "Resolva com um dos seguintes:"
    error "  git push origin $BRANCH            # preservar seus commits"
    error "  git reset --hard origin/$BRANCH    # descartar seus commits"
    return 1
  fi

  # 3. Detect dirty tree via git status --porcelain (INFRA-01 abort trigger #2)
  #    --porcelain includes staged, unstaged, AND untracked — unlike `git diff --quiet` (Pitfall 1).
  local porcelain
  porcelain="$(git status --porcelain)"
  if [[ -n "$porcelain" ]]; then
    error "Abort: working tree suja (arquivos modificados/staged/untracked):"
    echo "$porcelain" >&2
    error "Resolva com um dos seguintes:"
    error "  git stash -u                       # guardar alterações temporariamente"
    error "  git clean -fd && git checkout -- . # descartar alterações"
    error "  git status                          # inspecionar antes de decidir"
    return 1
  fi

  log "Safe-reset gate OK — árvore limpa e sincronizada com origin/$BRANCH"
}

# ── preserve_paths_to_staging / restore_paths_from_staging (STUBS) ──────
# Plan 04 replaces these with real implementations reading PRESERVE_PATHS from install.sh.
preserve_paths_to_staging() {
  error "preserve_paths_to_staging: NOT IMPLEMENTED — see Plan 04 (preserve-paths-expansion)"
  return 127
}

restore_paths_from_staging() {
  error "restore_paths_from_staging: NOT IMPLEMENTED — see Plan 04"
  return 127
}
