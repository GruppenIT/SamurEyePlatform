#!/usr/bin/env bash
# SamurEye Phase 8 — binary fetch/verify/install primitives.
# Sourced by install.sh (--install/--update) and scripts/install/build-release.sh.
#
# Required env: INSTALL_DIR, MANIFEST
# Override points: FETCH_CURL (for testing), FETCH_RETRY (default 1)

set -Eeuo pipefail

# ── Logging (match install.sh conventions) ───────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()   { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

: "${INSTALL_DIR:?INSTALL_DIR must be set (e.g. /opt/samureye)}"
: "${MANIFEST:?MANIFEST must be set (path to binaries.json)}"
: "${FETCH_CURL:=curl}"
: "${FETCH_RETRY:=1}"

# ── verify_sha256_strict <file> <expected_hex> ──────────────────────────
# Strict string comparison — NEVER uses `sha256sum -c` (Pitfall 3).
verify_sha256_strict() {
  local file="$1" expected="$2" actual
  actual="$(sha256sum "$file" | awk '{print $1}')"
  if [[ "$actual" != "$expected" ]]; then
    error "Checksum mismatch for $file:"
    error "  expected=$expected"
    error "  actual=$actual"
    return 1
  fi
  log "SHA-256 verified: $actual"
}

# ── fetch_archive <url> <dest> ──────────────────────────────────────────
# Supports file:// (for tests) and https:// (production).
fetch_archive() {
  local url="$1" dest="$2"
  log "Baixando: $url"
  case "$url" in
    file://*)
      local src="${url#file://}"
      cp "$src" "$dest" || { error "Falha ao copiar fixture $src"; return 1; }
      ;;
    *)
      if ! "$FETCH_CURL" -fsSL --retry "$FETCH_RETRY" --retry-delay 3 -o "$dest" "$url"; then
        error "Falha ao baixar $url"
        rm -f "$dest"
        return 1
      fi
      ;;
  esac
}

# ── install_binary <name> ───────────────────────────────────────────────
install_binary() {
  local name="$1"
  local url expected_sha fmt member install_to tmp
  url=$(jq -r ".binaries[\"$name\"].url"                  "$MANIFEST")
  expected_sha=$(jq -r ".binaries[\"$name\"].sha256"      "$MANIFEST")
  fmt=$(jq -r ".binaries[\"$name\"].format"               "$MANIFEST")
  member=$(jq -r ".binaries[\"$name\"].binary_in_archive" "$MANIFEST")
  install_to=$(jq -r ".binaries[\"$name\"].install_to"    "$MANIFEST")

  # pip install requires a recognizable extension; use .tar.gz for pip_source
  local tmp_suffix=""
  if [[ "$fmt" == "pip_source" ]]; then
    tmp_suffix=".tar.gz"
  fi
  tmp=$(mktemp -t "samureye-fetch-XXXXXX${tmp_suffix}")
  # Always clean up temp on any exit from this function
  # shellcheck disable=SC2064
  trap "rm -f '$tmp'" RETURN

  fetch_archive "$url" "$tmp" || { rm -f "$tmp"; return 1; }

  if ! verify_sha256_strict "$tmp" "$expected_sha"; then
    rm -f "$tmp"
    return 1
  fi

  mkdir -p "$INSTALL_DIR/bin"

  case "$fmt" in
    zip)
      unzip -oj "$tmp" "$member" -d "$INSTALL_DIR/bin/" >/dev/null
      # Rename if install_to basename differs from member
      local dest_basename="${install_to##*/}"
      if [[ "$member" != "$dest_basename" ]]; then
        mv "$INSTALL_DIR/bin/$member" "$INSTALL_DIR/$install_to"
      fi
      chmod +x "$INSTALL_DIR/$install_to"
      ;;
    tar.gz)
      # Extract only the member; layout is "<prefix>/<member>"
      tar -xzf "$tmp" -C "$INSTALL_DIR/bin/" --strip-components=1 --wildcards "*/$member"
      local dest_basename="${install_to##*/}"
      if [[ "$member" != "$dest_basename" ]]; then
        mv "$INSTALL_DIR/bin/$member" "$INSTALL_DIR/$install_to"
      fi
      chmod +x "$INSTALL_DIR/$install_to"
      ;;
    pip_source)
      install_arjun_from_pip "$tmp"
      ;;
    *)
      error "Formato desconhecido: $fmt (binary $name)"
      return 1
      ;;
  esac

  log "$name instalado em $INSTALL_DIR/$install_to"
}

# ── install_arjun_from_pip <tarball_path> ────────────────────────────────
install_arjun_from_pip() {
  local tarball="$1" venv="$INSTALL_DIR/venv-security"

  # Pitfall 6: ensure python3-venv is present
  if ! python3 -c 'import venv' 2>/dev/null; then
    error "python3-venv indisponível — instale 'python3-venv' antes de install_binary arjun"
    return 1
  fi

  if [[ ! -d "$venv" ]]; then
    python3 -m venv "$venv"
  fi

  "$venv/bin/pip" install --quiet --upgrade pip
  "$venv/bin/pip" install --quiet "$tarball"

  # Shell wrapper in bin/ (absolute venv path — never relies on PATH)
  mkdir -p "$INSTALL_DIR/bin"
  cat > "$INSTALL_DIR/bin/arjun" <<WRAP
#!/bin/bash
exec "$venv/bin/arjun" "\$@"
WRAP
  chmod +x "$INSTALL_DIR/bin/arjun"
  log "arjun instalado em $venv (wrapper em bin/arjun)"
}
