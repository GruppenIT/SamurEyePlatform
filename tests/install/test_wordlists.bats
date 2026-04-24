#!/usr/bin/env bats
# INFRA-04 coverage — wordlist install with SHA verification and vendor-first preference.

load 'helpers'

setup() {
  export INSTALL_DIR="$BATS_TEST_TMPDIR/opt-samureye"
  mkdir -p "$INSTALL_DIR"
  export WORDLISTS_MANIFEST="$BATS_TEST_TMPDIR/wordlists.json"
  export FAKE_TAR="$REPO_ROOT/tests/install/fixtures/fake-routes-large.kite.tar.gz"
  export FAKE_TAR_SHA
  FAKE_TAR_SHA="$(sha256sum "$FAKE_TAR" | awk '{print $1}')"

  # fetch-binary.sh requires MANIFEST and INSTALL_DIR — set dummies so sourcing works
  # when install-wordlists.sh sources fetch-binary.sh for verify_sha256_strict/fetch_archive
  export MANIFEST="$WORDLISTS_MANIFEST"

  # Fake local wordlist
  export LOCAL_WL="$BATS_TEST_TMPDIR/local-wl.txt"
  echo "param1" > "$LOCAL_WL"
  echo "param2" >> "$LOCAL_WL"
  export LOCAL_SHA
  LOCAL_SHA="$(sha256sum "$LOCAL_WL" | awk '{print $1}')"

  # Extracted SHA for the fake tarball's routes-large.kite content
  FAKE_TAR_EXTRACTED_DIR=$(mktemp -d)
  tar -xzf "$FAKE_TAR" -C "$FAKE_TAR_EXTRACTED_DIR"
  export FAKE_EXTRACTED_SHA
  FAKE_EXTRACTED_SHA="$(sha256sum "$FAKE_TAR_EXTRACTED_DIR/routes-large.kite" | awk '{print $1}')"
  rm -rf "$FAKE_TAR_EXTRACTED_DIR"
}

@test "INFRA-04: local-source wordlist copies with valid SHA" {
  cat > "$WORDLISTS_MANIFEST" <<JSON
{ "version": 1, "wordlists": {
  "mywl.txt": { "source":"local","path":"$(realpath --relative-to="$REPO_ROOT" "$LOCAL_WL")","sha256":"$LOCAL_SHA","install_to":"wordlists/mywl.txt" }
}}
JSON
  run bash -c "source $REPO_ROOT/scripts/install/fetch-binary.sh 2>/dev/null; source $REPO_ROOT/scripts/install/install-wordlists.sh && install_wordlists"
  [ "$status" -eq 0 ]
  [ -f "$INSTALL_DIR/wordlists/mywl.txt" ]
  [ "$(cat "$INSTALL_DIR/wordlists/mywl.txt")" = "$(cat "$LOCAL_WL")" ]
}

@test "INFRA-04: local-source SHA mismatch aborts with expected/actual" {
  cat > "$WORDLISTS_MANIFEST" <<JSON
{ "version": 1, "wordlists": {
  "mywl.txt": { "source":"local","path":"$(realpath --relative-to="$REPO_ROOT" "$LOCAL_WL")","sha256":"00$(printf '0%.0s' {1..62})","install_to":"wordlists/mywl.txt" }
}}
JSON
  run bash -c "source $REPO_ROOT/scripts/install/fetch-binary.sh 2>/dev/null; source $REPO_ROOT/scripts/install/install-wordlists.sh && install_wordlists"
  [ "$status" -ne 0 ]
  [[ "$output" =~ "expected=" ]]
  [[ "$output" =~ "actual=" ]]
  [ ! -f "$INSTALL_DIR/wordlists/mywl.txt" ]
}

@test "INFRA-04: remote-source prefers vendored copy (no network)" {
  # Place vendored file in a temp "repo root" by using BATS_TEST_TMPDIR
  mkdir -p "$BATS_TEST_TMPDIR/vendor/wordlists"
  FAKE_TAR_EXTRACTED_DIR=$(mktemp -d)
  tar -xzf "$FAKE_TAR" -C "$FAKE_TAR_EXTRACTED_DIR"
  cp "$FAKE_TAR_EXTRACTED_DIR/routes-large.kite" "$BATS_TEST_TMPDIR/vendor/wordlists/routes-large.kite"
  rm -rf "$FAKE_TAR_EXTRACTED_DIR"

  cat > "$WORDLISTS_MANIFEST" <<JSON
{ "version": 1, "wordlists": {
  "routes-large.kite": {
    "source":"remote",
    "url":"file:///NONEXISTENT_URL",
    "sha256":"$FAKE_TAR_SHA",
    "extracted_sha256":"$FAKE_EXTRACTED_SHA",
    "format":"tar.gz",
    "extract_member":"routes-large.kite",
    "vendor_path":"vendor/wordlists/routes-large.kite",
    "install_to":"wordlists/routes-large.kite"
  }
}}
JSON
  # Override the repo-root resolver inside install-wordlists.sh by pre-setting _WORDLIST_REPO_ROOT
  run bash -c "_WORDLIST_REPO_ROOT='$BATS_TEST_TMPDIR'; source $REPO_ROOT/scripts/install/fetch-binary.sh 2>/dev/null; source $REPO_ROOT/scripts/install/install-wordlists.sh; install_wordlists"
  [ "$status" -eq 0 ]
  [ -f "$INSTALL_DIR/wordlists/routes-large.kite" ]
}

@test "INFRA-04: remote-source falls back to URL when vendor path absent" {
  mkdir -p "$BATS_TEST_TMPDIR/vendor/wordlists"  # empty — no vendored copy
  cat > "$WORDLISTS_MANIFEST" <<JSON
{ "version": 1, "wordlists": {
  "routes-large.kite": {
    "source":"remote",
    "url":"file://$FAKE_TAR",
    "sha256":"$FAKE_TAR_SHA",
    "extracted_sha256":"$FAKE_EXTRACTED_SHA",
    "format":"tar.gz",
    "extract_member":"routes-large.kite",
    "vendor_path":"vendor/wordlists/routes-large.kite",
    "install_to":"wordlists/routes-large.kite"
  }
}}
JSON
  run bash -c "_WORDLIST_REPO_ROOT='$BATS_TEST_TMPDIR'; source $REPO_ROOT/scripts/install/fetch-binary.sh 2>/dev/null; source $REPO_ROOT/scripts/install/install-wordlists.sh; install_wordlists"
  [ "$status" -eq 0 ]
  [ -f "$INSTALL_DIR/wordlists/routes-large.kite" ]
  # Verify extracted SHA matches
  actual=$(sha256sum "$INSTALL_DIR/wordlists/routes-large.kite" | awk '{print $1}')
  [ "$actual" = "$FAKE_EXTRACTED_SHA" ]
}

@test "INFRA-04: wordlists.json real manifest has extracted_sha256 for routes-large" {
  run jq -e '.wordlists["routes-large.kite"].extracted_sha256 | test("^[a-f0-9]{64}$")' "$REPO_ROOT/scripts/install/wordlists.json"
  [ "$status" -eq 0 ]
}
