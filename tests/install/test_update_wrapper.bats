#!/usr/bin/env bats
# INFRA-05 coverage — update.sh wrapper: DEPRECATED banner + exec to install.sh --update.

load 'helpers'

# ── Test 1: DEPRECATED banner goes to stderr ──────────────────────────────────
@test "INFRA-05: update.sh prints DEPRECATED banner to stderr" {
    # Create a mock install.sh in a temp INSTALL_DIR so the exec doesn't fail
    local stage="$BATS_TEST_TMPDIR/mock-install-dir"
    mkdir -p "$stage"
    cat > "$stage/install.sh" <<'SH'
#!/bin/bash
exit 0
SH
    chmod +x "$stage/install.sh"

    # Run update.sh; capture stderr separately
    run env INSTALL_DIR="$stage" bash "$REPO_ROOT/update.sh" 2>&1 >/dev/null
    [[ "$output" =~ "DEPRECATED" ]]
}

# ── Test 2: delegates to install.sh --update (mocked), propagates exit code ──
@test "INFRA-05: update.sh delegates to install.sh --update and propagates exit code" {
    local stage="$BATS_TEST_TMPDIR/mock-delegate"
    mkdir -p "$stage"
    cat > "$stage/install.sh" <<'SH'
#!/bin/bash
echo "INSTALL_ARGS=$*"
echo "INSTALL_AUTO_CONFIRM=${AUTO_CONFIRM:-}"
echo "INSTALL_SKIP_BACKUP=${SKIP_BACKUP:-}"
echo "INSTALL_INSTALL_DIR=${INSTALL_DIR:-}"
exit 42
SH
    chmod +x "$stage/install.sh"

    run env INSTALL_DIR="$stage" AUTO_CONFIRM=true SKIP_BACKUP=true bash "$stage/update.sh" 2>/dev/null

    [ "$status" -eq 42 ]
    [[ "$output" =~ "INSTALL_ARGS=--update" ]]
    [[ "$output" =~ "INSTALL_AUTO_CONFIRM=true" ]]
    [[ "$output" =~ "INSTALL_SKIP_BACKUP=true" ]]
    [[ "$output" =~ "INSTALL_INSTALL_DIR=$stage" ]]
}

# ── Test 3: wrapper is < 50 lines (thin wrapper contract) ────────────────────
@test "INFRA-05: update.sh is under 50 lines (thin wrapper contract)" {
    local lines
    lines=$(wc -l < "$REPO_ROOT/update.sh")
    [ "$lines" -lt 50 ]
}

# ── Test 4: wrapper uses exec for process replacement (exit code propagation) ─
@test "INFRA-05: update.sh uses exec (process replacement for exit-code propagation)" {
    grep -Eq '^exec "[^"]+install\.sh" --update' "$REPO_ROOT/update.sh"
}

# ── Test 5: GIT_TOKEN env var is preserved ────────────────────────────────────
@test "INFRA-05: update.sh preserves GIT_TOKEN env var across exec" {
    local stage="$BATS_TEST_TMPDIR/mock-token"
    mkdir -p "$stage"
    cat > "$stage/install.sh" <<'SH'
#!/bin/bash
echo "GIT_TOKEN=${GIT_TOKEN:-UNSET}"
exit 0
SH
    chmod +x "$stage/install.sh"

    run env INSTALL_DIR="$stage" GIT_TOKEN="test-token-123" bash "$stage/update.sh" 2>/dev/null
    [ "$status" -eq 0 ]
    [[ "$output" =~ "GIT_TOKEN=test-token-123" ]]
}

# ── Test 6: wrapper must contain the word DEPRECATED in file ─────────────────
@test "INFRA-05: update.sh file contains DEPRECATED marker" {
    grep -c 'DEPRECATED' "$REPO_ROOT/update.sh" | grep -q '^[1-9]'
}
