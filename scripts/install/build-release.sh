#!/usr/bin/env bash
# SamurEye Phase 8 — release tarball builder (INFRA-05).
# Usage: build-release.sh <tag>
# Output: ./samureye-<tag>.tar.gz  (in the repo root directory)
#
# Layout produced inside the tarball:
#   samureye-<tag>/
#     app/              ← git archive of <tag> (falls back to HEAD for dev builds)
#     bin/              ← raw binary archives downloaded+SHA-verified (NOT extracted)
#                         katana_1.5.0_linux_amd64.zip
#                         httpx_1.9.0_linux_amd64.zip
#                         kiterunner_1.0.2_linux_amd64.tar.gz
#                         arjun-2.2.7.tar.gz
#     wordlists/
#       routes-large.kite         ← from vendor/wordlists/ (pre-extracted)
#       arjun-extended-pt-en.txt  ← from scripts/install/wordlists/
#     install.sh        ← copy of app/install.sh (user entry point)
#     MANIFEST.json     ← rewritten with local ./bin/ URLs, same SHAs

set -Eeuo pipefail

TAG="${1:?Usage: $0 <tag>}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BINARIES_MANIFEST="$REPO_ROOT/scripts/install/binaries.json"
WORDLISTS_MANIFEST="$REPO_ROOT/scripts/install/wordlists.json"

# ── Logging ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()   { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ── Dependency check ─────────────────────────────────────────────────────────
for cmd in git jq curl sha256sum tar; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    error "Dependência ausente: $cmd"
    exit 1
  fi
done

# ── Temp workspace ───────────────────────────────────────────────────────────
WORKPARENT="$(mktemp -d)"
WORKDIR="$WORKPARENT/samureye-$TAG"
cleanup() { rm -rf "$WORKPARENT"; }
trap cleanup EXIT

mkdir -p "$WORKDIR/app" "$WORKDIR/bin" "$WORKDIR/wordlists"

# ── 1. App source (git archive) ───────────────────────────────────────────────
cd "$REPO_ROOT"
if git rev-parse --verify --quiet "refs/tags/$TAG" >/dev/null 2>&1; then
  log "Arquivando tag $TAG"
  git archive --format=tar "$TAG" | tar -xC "$WORKDIR/app"
else
  warn "Tag '$TAG' não existe — usando HEAD (dev/test build)"
  git archive --format=tar HEAD | tar -xC "$WORKDIR/app"
fi

# ── 2. Download + verify each binary, save raw archive into bin/ ──────────────
# In --from-tarball mode, install_binary reads from file:// URLs pointing here.
log "Baixando e verificando binários..."
for name in $(jq -r '.binaries | keys[]' "$BINARIES_MANIFEST"); do
  url=$(jq -r ".binaries[\"$name\"].url"    "$BINARIES_MANIFEST")
  sha=$(jq -r ".binaries[\"$name\"].sha256" "$BINARIES_MANIFEST")
  fname="$(basename "$url")"
  dest="$WORKDIR/bin/$fname"

  log "Baixando $name → $fname"
  curl -fsSL --retry 2 --retry-delay 3 -o "$dest" "$url"
  actual="$(sha256sum "$dest" | awk '{print $1}')"
  if [[ "$actual" != "$sha" ]]; then
    error "Checksum mismatch para $name:"
    error "  esperado=$sha"
    error "  obtido  =$actual"
    exit 1
  fi
  log "$name OK (sha-256 verificado)"
done

# ── 3. Wordlists (vendored + local) ──────────────────────────────────────────
log "Copiando wordlists..."
cp -a "$REPO_ROOT/vendor/wordlists/routes-large.kite"                 "$WORKDIR/wordlists/routes-large.kite"
cp -a "$REPO_ROOT/scripts/install/wordlists/arjun-extended-pt-en.txt" "$WORKDIR/wordlists/arjun-extended-pt-en.txt"

# ── 4. install.sh at tarball root (user-facing entry point) ──────────────────
if [[ -f "$WORKDIR/app/install.sh" ]]; then
  cp -a "$WORKDIR/app/install.sh" "$WORKDIR/install.sh"
else
  error "install.sh não encontrado em app/ após git archive"
  exit 1
fi

# ── 5. MANIFEST.json (binaries + wordlists with local ./bin/ URLs) ───────────
log "Gerando MANIFEST.json..."

# Rewrite binary URLs: https://.../<file.zip> → ./bin/<file.zip>, SHAs unchanged.
jq --arg tag "$TAG" --arg date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '
  . + {release_tag: $tag, release_date: $date} |
  .binaries |= with_entries(
    .value.url = ("./bin/" + (.value.url | split("/") | last))
  )
' "$BINARIES_MANIFEST" > "$WORKDIR/MANIFEST.binaries.json"

# Rewrite wordlist entries: point URLs to ./wordlists/<name>, set source=tarball.
jq '
  .wordlists |= with_entries(
    .value |= (
      if .source == "local" then
        .url = ("./wordlists/" + (input_line_number | tostring)) |  # placeholder; replaced below
        .source = "tarball"
      elif .source == "remote" then
        .url = ("./wordlists/" + (.vendor_path | split("/") | last)) |
        .source = "tarball" |
        del(.vendor_path)
      else
        .
      end
    )
  )
' "$WORDLISTS_MANIFEST" > /dev/null  # dry run to detect syntax issues

# Simpler approach: build wordlists section with jq --argjson
jq -n \
  --argjson wl "$(cat "$WORDLISTS_MANIFEST")" \
  --arg     wdir "./wordlists/" \
  '
  { wordlists: ($wl.wordlists | with_entries(
      .value |= (
        if .source == "local" then
          .url = ($wdir + (.path | split("/") | last)) |
          .source = "tarball"
        elif .source == "remote" then
          .url = ($wdir + (.vendor_path | split("/") | last)) |
          .source = "tarball" |
          del(.vendor_path)
        else
          .
        end
      )
    ))
  }' > "$WORKDIR/MANIFEST.wordlists.json"

# Merge: binaries manifest + wordlists section → single MANIFEST.json
jq -s '.[0] * {wordlists: .[1].wordlists}' \
  "$WORKDIR/MANIFEST.binaries.json" \
  "$WORKDIR/MANIFEST.wordlists.json" \
  > "$WORKDIR/MANIFEST.json"

rm -f "$WORKDIR/MANIFEST.binaries.json" "$WORKDIR/MANIFEST.wordlists.json"

# ── 6. Pack tarball ───────────────────────────────────────────────────────────
OUT="$REPO_ROOT/samureye-$TAG.tar.gz"
( cd "$WORKPARENT" && tar -czf "$OUT" "samureye-$TAG" )

log "Release tarball: $OUT"
log "Tamanho: $(du -h "$OUT" | cut -f1)"
