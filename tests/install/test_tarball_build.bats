#!/usr/bin/env bats
# INFRA-05 coverage — build-release.sh produces a complete, verified tarball.
# These tests download real binaries; skip with BATS_SKIP_NETWORK=1 if air-gapped.

load 'helpers'

# Use a predictable test tag across all tests in this file.
TEST_TAG="v0.0.0-bats-test"

# setup_file runs once before all tests in this file.
setup_file() {
    if [[ "${BATS_SKIP_NETWORK:-}" == "1" ]]; then return 0; fi
    export TARBALL_PATH="$REPO_ROOT/samureye-${TEST_TAG}.tar.gz"
    # Build the tarball once for the entire test file.
    bash "$REPO_ROOT/scripts/install/build-release.sh" "$TEST_TAG" >&2
}

# teardown_file runs once after all tests in this file.
teardown_file() {
    rm -f "$REPO_ROOT/samureye-${TEST_TAG}.tar.gz"
}

setup() {
    TARBALL_PATH="$REPO_ROOT/samureye-${TEST_TAG}.tar.gz"
}

# ── Test 1: tarball exists after build ────────────────────────────────────────
@test "INFRA-05: build-release.sh produces samureye-<tag>.tar.gz" {
    if [[ "${BATS_SKIP_NETWORK:-}" == "1" ]]; then skip "Network tests disabled"; fi
    [ -f "$TARBALL_PATH" ]
}

# ── Test 2: layout — app/, bin/, wordlists/, install.sh, MANIFEST.json ───────
@test "INFRA-05: tarball contains app/, bin/, wordlists/, install.sh, MANIFEST.json" {
    if [[ "${BATS_SKIP_NETWORK:-}" == "1" ]]; then skip "Network tests disabled"; fi
    [ -f "$TARBALL_PATH" ] || skip "Tarball not built"
    tar -tzf "$TARBALL_PATH" > "$BATS_TEST_TMPDIR/list.txt"
    grep -q "^samureye-${TEST_TAG}/app/"              "$BATS_TEST_TMPDIR/list.txt"
    grep -q "^samureye-${TEST_TAG}/bin/"              "$BATS_TEST_TMPDIR/list.txt"
    grep -q "^samureye-${TEST_TAG}/wordlists/"        "$BATS_TEST_TMPDIR/list.txt"
    grep -q "^samureye-${TEST_TAG}/install\.sh$"      "$BATS_TEST_TMPDIR/list.txt"
    grep -q "^samureye-${TEST_TAG}/MANIFEST\.json$"   "$BATS_TEST_TMPDIR/list.txt"
}

# ── Test 3: bin/ has all 4 binary archives ───────────────────────────────────
@test "INFRA-05: tarball bin/ contains all 4 binary archives" {
    if [[ "${BATS_SKIP_NETWORK:-}" == "1" ]]; then skip "Network tests disabled"; fi
    [ -f "$TARBALL_PATH" ] || skip "Tarball not built"
    local workdir
    workdir="$BATS_TEST_TMPDIR/extract-t3"
    mkdir -p "$workdir"
    tar -xzf "$TARBALL_PATH" -C "$workdir"
    local bindir="$workdir/samureye-${TEST_TAG}/bin"
    ls "$bindir"/katana_1.5.0_linux_amd64.zip
    ls "$bindir"/httpx_1.9.0_linux_amd64.zip
    ls "$bindir"/kiterunner_1.0.2_linux_amd64.tar.gz
    ls "$bindir"/arjun-2.2.7.tar.gz
}

# ── Test 4: SHA-256 of each binary in tarball matches MANIFEST ───────────────
@test "INFRA-05: each binary in tarball passes SHA verification" {
    if [[ "${BATS_SKIP_NETWORK:-}" == "1" ]]; then skip "Network tests disabled"; fi
    [ -f "$TARBALL_PATH" ] || skip "Tarball not built"
    local workdir
    workdir="$BATS_TEST_TMPDIR/extract-t4"
    mkdir -p "$workdir"
    tar -xzf "$TARBALL_PATH" -C "$workdir"
    local manifest="$workdir/samureye-${TEST_TAG}/MANIFEST.json"
    for name in katana httpx kiterunner arjun; do
        local expected url actual
        url=$(jq -r ".binaries[\"$name\"].url" "$manifest")
        expected=$(jq -r ".binaries[\"$name\"].sha256" "$manifest")
        actual=$(sha256sum "$workdir/samureye-${TEST_TAG}/${url#./}" | awk '{print $1}')
        [ "$actual" = "$expected" ]
    done
}

# ── Test 5: wordlists are bundled ────────────────────────────────────────────
@test "INFRA-05: tarball wordlists/ contains both wordlist files" {
    if [[ "${BATS_SKIP_NETWORK:-}" == "1" ]]; then skip "Network tests disabled"; fi
    [ -f "$TARBALL_PATH" ] || skip "Tarball not built"
    local workdir
    workdir="$BATS_TEST_TMPDIR/extract-t5"
    mkdir -p "$workdir"
    tar -xzf "$TARBALL_PATH" -C "$workdir"
    [ -f "$workdir/samureye-${TEST_TAG}/wordlists/routes-large.kite" ]
    [ -f "$workdir/samureye-${TEST_TAG}/wordlists/arjun-extended-pt-en.txt" ]
}

# ── Test 6: MANIFEST.json URLs rewritten to ./bin/<basename> ─────────────────
@test "INFRA-05: MANIFEST.json URLs rewritten to ./bin/" {
    if [[ "${BATS_SKIP_NETWORK:-}" == "1" ]]; then skip "Network tests disabled"; fi
    [ -f "$TARBALL_PATH" ] || skip "Tarball not built"
    local workdir
    workdir="$BATS_TEST_TMPDIR/extract-t6"
    mkdir -p "$workdir"
    tar -xzf "$TARBALL_PATH" -C "$workdir"
    local manifest="$workdir/samureye-${TEST_TAG}/MANIFEST.json"
    run jq -r '.binaries.katana.url' "$manifest"
    [[ "$output" =~ ^\./bin/katana_.*\.zip$ ]]
}

# ── Test 7: MANIFEST.json SHA-256 values preserved from original ─────────────
@test "INFRA-05: MANIFEST.json preserves original SHA-256 for katana" {
    if [[ "${BATS_SKIP_NETWORK:-}" == "1" ]]; then skip "Network tests disabled"; fi
    [ -f "$TARBALL_PATH" ] || skip "Tarball not built"
    local workdir
    workdir="$BATS_TEST_TMPDIR/extract-t7"
    mkdir -p "$workdir"
    tar -xzf "$TARBALL_PATH" -C "$workdir"
    local manifest="$workdir/samureye-${TEST_TAG}/MANIFEST.json"
    run jq -r '.binaries.katana.sha256' "$manifest"
    [ "$output" = "592890e5febaf5706d0a962d96299512418d6eccce6388cf1600e1f078ed359d" ]
}

# ── Test 8: tarball > 10 MB (routes-large.kite bundled) ──────────────────────
@test "INFRA-05: tarball size > 10 MB (routes-large.kite bundled)" {
    if [[ "${BATS_SKIP_NETWORK:-}" == "1" ]]; then skip "Network tests disabled"; fi
    [ -f "$TARBALL_PATH" ] || skip "Tarball not built"
    local size
    size=$(stat -c '%s' "$TARBALL_PATH")
    [ "$size" -gt 10485760 ]
}
