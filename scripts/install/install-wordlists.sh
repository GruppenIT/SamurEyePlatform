#!/usr/bin/env bash
# SamurEye Phase 8 — wordlist install/verify driven by wordlists.json (INFRA-04).
# Sourced by install.sh. Requires fetch-binary.sh already sourced (verify_sha256_strict).

set -Eeuo pipefail

if ! declare -F log >/dev/null 2>&1; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
  log()   { echo -e "${GREEN}[INFO]${NC} $*"; }
  warn()  { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
  error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
fi

: "${INSTALL_DIR:?INSTALL_DIR must be set}"

# Repo root (so `local` and `vendor/` lookups work regardless of caller cwd)
if [[ -z "${_WORDLIST_REPO_ROOT:-}" ]]; then
  _WORDLIST_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fi
: "${WORDLISTS_MANIFEST:=$_WORDLIST_REPO_ROOT/scripts/install/wordlists.json}"

# ── install_wordlists ───────────────────────────────────────────────────────
# Iterates .wordlists keys in WORDLISTS_MANIFEST; never fetches at runtime
# if a vendored copy exists (Pitfall 5 — CDN resilience).
install_wordlists() {
  mkdir -p "$INSTALL_DIR/wordlists"

  local name src install_to
  for name in $(jq -r '.wordlists | keys[]' "$WORDLISTS_MANIFEST"); do
    src=$(jq -r ".wordlists[\"$name\"].source"            "$WORDLISTS_MANIFEST")
    install_to=$(jq -r ".wordlists[\"$name\"].install_to" "$WORDLISTS_MANIFEST")

    case "$src" in
      local)
        local path sha abs_src
        path=$(jq -r ".wordlists[\"$name\"].path"   "$WORDLISTS_MANIFEST")
        sha=$(jq -r  ".wordlists[\"$name\"].sha256" "$WORDLISTS_MANIFEST")
        abs_src="$_WORDLIST_REPO_ROOT/$path"
        [[ -f "$abs_src" ]] || { error "Wordlist local ausente: $abs_src"; return 1; }
        verify_sha256_strict "$abs_src" "$sha" || return 1
        cp -a "$abs_src" "$INSTALL_DIR/$install_to"
        log "Wordlist $name copiada para $INSTALL_DIR/$install_to"
        ;;
      remote)
        local url sha extracted_sha vendor_path fmt member abs_vendor
        url=$(jq -r           ".wordlists[\"$name\"].url"              "$WORDLISTS_MANIFEST")
        sha=$(jq -r           ".wordlists[\"$name\"].sha256"           "$WORDLISTS_MANIFEST")
        extracted_sha=$(jq -r ".wordlists[\"$name\"].extracted_sha256" "$WORDLISTS_MANIFEST")
        vendor_path=$(jq -r   ".wordlists[\"$name\"].vendor_path"      "$WORDLISTS_MANIFEST")
        fmt=$(jq -r           ".wordlists[\"$name\"].format"           "$WORDLISTS_MANIFEST")
        member=$(jq -r        ".wordlists[\"$name\"].extract_member"   "$WORDLISTS_MANIFEST")

        abs_vendor="$_WORDLIST_REPO_ROOT/$vendor_path"
        if [[ -f "$abs_vendor" ]]; then
          log "Wordlist $name: usando cópia vendorada em $abs_vendor"
          verify_sha256_strict "$abs_vendor" "$extracted_sha" || return 1
          cp -a "$abs_vendor" "$INSTALL_DIR/$install_to"
          log "Wordlist $name instalada em $INSTALL_DIR/$install_to"
        else
          warn "Vendored copy ausente em $abs_vendor — baixando de $url"
          local tmp
          tmp=$(mktemp -t samureye-wl-XXXXXX)
          # shellcheck disable=SC2064
          trap "rm -f '$tmp'" RETURN
          fetch_archive "$url" "$tmp" || return 1
          verify_sha256_strict "$tmp" "$sha" || { rm -f "$tmp"; return 1; }
          case "$fmt" in
            tar.gz)
              tar -xzf "$tmp" -C "$INSTALL_DIR/wordlists/" "$member"
              ;;
            *)
              error "Formato desconhecido para wordlist $name: $fmt"
              rm -f "$tmp"
              return 1
              ;;
          esac
          # Move extracted member into exact install_to path if needed
          if [[ "$member" != "${install_to##*/}" ]]; then
            mv "$INSTALL_DIR/wordlists/$member" "$INSTALL_DIR/$install_to"
          fi
          verify_sha256_strict "$INSTALL_DIR/$install_to" "$extracted_sha" || return 1
          rm -f "$tmp"
        fi
        ;;
      *)
        error "source desconhecido para wordlist $name: $src"
        return 1
        ;;
    esac
  done
}
