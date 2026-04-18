#!/usr/bin/env bats
# INFRA-01 coverage — safe_reset_gate aborts before mutating the tree.

load 'helpers'

setup() {
  export TMP_REPO="$BATS_TEST_TMPDIR/repo"
  BARE="$(make_temp_repo "$TMP_REPO")"
  export INSTALL_DIR="$TMP_REPO"
  export BRANCH="main"
}

snapshot_tree() {
  # Deterministic snapshot of tree state (visible + git metadata we care about)
  ( cd "$INSTALL_DIR" && git status --porcelain; find . -maxdepth 2 -type f | sort | xargs sha256sum 2>/dev/null ) > "$BATS_TEST_TMPDIR/snapshot"
}

@test "INFRA-01: clean synced tree passes the gate" {
  run bash -c "source $REPO_ROOT/scripts/install/safe-reset.sh && safe_reset_gate"
  [ "$status" -eq 0 ]
  [[ "$output" =~ "Safe-reset gate OK" ]]
}

@test "INFRA-01: untracked file aborts with working-tree-suja and leaves file intact" {
  ( cd "$INSTALL_DIR" && echo "dirty" > untracked-file.txt )
  snapshot_tree
  run bash -c "source $REPO_ROOT/scripts/install/safe-reset.sh && safe_reset_gate"
  [ "$status" -eq 1 ]
  [[ "$output" =~ "working tree suja" ]]
  [[ "$output" =~ "untracked-file.txt" ]]
  [ -f "$INSTALL_DIR/untracked-file.txt" ]
  [ "$(cat "$INSTALL_DIR/untracked-file.txt")" = "dirty" ]
}

@test "INFRA-01: staged uncommitted file aborts" {
  ( cd "$INSTALL_DIR" && echo "staged" > new.txt && git add new.txt )
  run bash -c "source $REPO_ROOT/scripts/install/safe-reset.sh && safe_reset_gate"
  [ "$status" -eq 1 ]
  [[ "$output" =~ "working tree suja" ]]
}

@test "INFRA-01: unpushed commit aborts with ahead message and commit subject" {
  (
    cd "$INSTALL_DIR"
    echo "ahead" >> README.md
    git add README.md
    git commit -qm "unpushed-phase8-test-commit"
  )
  run bash -c "source $REPO_ROOT/scripts/install/safe-reset.sh && safe_reset_gate"
  [ "$status" -eq 1 ]
  [[ "$output" =~ "ahead" ]]
  [[ "$output" =~ "unpushed-phase8-test-commit" ]]
}

@test "INFRA-01: abort message contains exact recovery commands" {
  ( cd "$INSTALL_DIR" && echo "dirty" > untracked.txt )
  run bash -c "source $REPO_ROOT/scripts/install/safe-reset.sh && safe_reset_gate"
  [ "$status" -eq 1 ]
  [[ "$output" =~ "git stash -u" ]]
  [[ "$output" =~ "git status" ]]
}

@test "INFRA-01: ahead-abort message suggests git push origin \$BRANCH" {
  (
    cd "$INSTALL_DIR"
    echo "ahead" >> README.md && git add README.md && git commit -qm "ahead-test"
  )
  run bash -c "source $REPO_ROOT/scripts/install/safe-reset.sh && safe_reset_gate"
  [ "$status" -eq 1 ]
  [[ "$output" =~ "git push origin main" ]]
}

@test "INFRA-01: tree is not mutated after abort" {
  ( cd "$INSTALL_DIR" && echo "dirty" > untracked.txt )
  snapshot_tree
  PRE="$(cat "$BATS_TEST_TMPDIR/snapshot")"
  run bash -c "source $REPO_ROOT/scripts/install/safe-reset.sh && safe_reset_gate" || true
  snapshot_tree
  POST="$(cat "$BATS_TEST_TMPDIR/snapshot")"
  [ "$PRE" = "$POST" ]
}

@test "INFRA-01: safe_reset_gate respects BRANCH env var" {
  ( cd "$INSTALL_DIR" && git checkout -b release )
  ( cd "$INSTALL_DIR" && git push -q origin release )
  BRANCH=release run bash -c "source $REPO_ROOT/scripts/install/safe-reset.sh && safe_reset_gate"
  [ "$status" -eq 0 ]
}
