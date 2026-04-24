#!/usr/bin/env bats
# INFRA-03 coverage — binary install + SHA-256 verification.

load 'helpers'

setup() {
  export INSTALL_DIR="$BATS_TEST_TMPDIR/opt-samureye"
  mkdir -p "$INSTALL_DIR/bin"
  export MANIFEST="$BATS_TEST_TMPDIR/manifest.json"

  export KATANA_FIX="$REPO_ROOT/tests/install/fixtures/fake-katana.zip"
  export KR_FIX="$REPO_ROOT/tests/install/fixtures/fake-kiterunner.tar.gz"
  export ARJUN_FIX="$REPO_ROOT/tests/install/fixtures/fake-arjun.tar.gz"

  export KATANA_SHA="$(sha256sum "$KATANA_FIX" | awk '{print $1}')"
  export KR_SHA="$(sha256sum "$KR_FIX"     | awk '{print $1}')"
  export ARJUN_SHA="$(sha256sum "$ARJUN_FIX"  | awk '{print $1}')"
}

# Replace global curl with a function that copies from the file:// URL to dest.
# fetch_archive() must be written in fetch-binary.sh to honor the FETCH_CURL override.
write_manifest_single() {
  local name="$1" url="$2" sha="$3" format="$4" member="$5"
  cat > "$MANIFEST" <<JSON
{ "version": 1, "binaries": { "$name": {
    "version":"0.0","url":"$url","sha256":"$sha","format":"$format","binary_in_archive":"$member","install_to":"bin/$name"
} } }
JSON
}

@test "INFRA-03: install_binary katana (zip, happy path) installs executable" {
  write_manifest_single katana "file://$KATANA_FIX" "$KATANA_SHA" zip katana
  run bash -c "source $REPO_ROOT/scripts/install/fetch-binary.sh && install_binary katana"
  [ "$status" -eq 0 ]
  [ -x "$INSTALL_DIR/bin/katana" ]
  [ "$($INSTALL_DIR/bin/katana)" = "fake-katana" ]
}

@test "INFRA-03: install_binary aborts on SHA-256 mismatch" {
  write_manifest_single katana "file://$KATANA_FIX" "deadbeef$(printf '0%.0s' {1..56})" zip katana
  run bash -c "source $REPO_ROOT/scripts/install/fetch-binary.sh && install_binary katana"
  [ "$status" -eq 1 ]
  [[ "$output" =~ "expected=" ]]
  [[ "$output" =~ "actual=" ]]
  [ ! -f "$INSTALL_DIR/bin/katana" ]
}

@test "INFRA-03: install_binary removes temp file after mismatch" {
  write_manifest_single katana "file://$KATANA_FIX" "00$(printf '0%.0s' {1..62})" zip katana
  run bash -c "source $REPO_ROOT/scripts/install/fetch-binary.sh && install_binary katana"
  [ "$status" -eq 1 ]
  run find /tmp -maxdepth 1 -name 'samureye-fetch-*' -type f
  [ -z "$output" ]
}

@test "INFRA-03: install_binary kiterunner (tar.gz, renames kr -> kiterunner)" {
  write_manifest_single kiterunner "file://$KR_FIX" "$KR_SHA" tar.gz kr
  run bash -c "source $REPO_ROOT/scripts/install/fetch-binary.sh && install_binary kiterunner"
  [ "$status" -eq 0 ]
  [ -x "$INSTALL_DIR/bin/kiterunner" ]
  [ "$($INSTALL_DIR/bin/kiterunner)" = "fake-kr" ]
}

@test "INFRA-03: install_binary arjun creates venv-security and shell wrapper" {
  write_manifest_single arjun "file://$ARJUN_FIX" "$ARJUN_SHA" pip_source arjun
  run bash -c "source $REPO_ROOT/scripts/install/fetch-binary.sh && install_binary arjun"
  [ "$status" -eq 0 ]
  [ -x "$INSTALL_DIR/venv-security/bin/arjun" ]
  [ -x "$INSTALL_DIR/bin/arjun" ]
  grep -q "venv-security/bin/arjun" "$INSTALL_DIR/bin/arjun"
}

@test "INFRA-03: install-binaries.sh iterates all 4 binaries from real manifest shape" {
  # Use the real binaries.json shape but swap URLs to local fixtures (httpx reuses katana fixture — same ZIP handling)
  cat > "$MANIFEST" <<JSON
{
  "version": 1,
  "binaries": {
    "katana":    {"version":"0","url":"file://$KATANA_FIX","sha256":"$KATANA_SHA","format":"zip","binary_in_archive":"katana","install_to":"bin/katana"},
    "httpx":     {"version":"0","url":"file://$KATANA_FIX","sha256":"$KATANA_SHA","format":"zip","binary_in_archive":"katana","install_to":"bin/httpx"},
    "kiterunner":{"version":"0","url":"file://$KR_FIX","sha256":"$KR_SHA","format":"tar.gz","binary_in_archive":"kr","install_to":"bin/kiterunner"},
    "arjun":     {"version":"0","url":"file://$ARJUN_FIX","sha256":"$ARJUN_SHA","format":"pip_source","binary_in_archive":"arjun","install_to":"bin/arjun"}
  }
}
JSON
  run bash "$REPO_ROOT/scripts/install/install-binaries.sh" --manifest "$MANIFEST" --install-dir "$INSTALL_DIR"
  [ "$status" -eq 0 ]
  [ -x "$INSTALL_DIR/bin/katana" ]
  [ -x "$INSTALL_DIR/bin/httpx" ]
  [ -x "$INSTALL_DIR/bin/kiterunner" ]
  [ -x "$INSTALL_DIR/bin/arjun" ]
}
