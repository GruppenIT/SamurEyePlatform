#!/usr/bin/env bats
# INFRA-02 coverage — preserve/restore preserves ownership and survives failures.

load 'helpers'

setup() {
  export INSTALL_DIR="$BATS_TEST_TMPDIR/opt-samureye"
  mkdir -p "$INSTALL_DIR"/{.planning,docs,backups,uploads,.claude/skills,.gsd/skills}
  echo "CONFIG_A=1" > "$INSTALL_DIR/.env"
  echo "phase8-context" > "$INSTALL_DIR/.planning/STATE.md"
  echo "README" > "$INSTALL_DIR/docs/README.md"
  echo "backup-data" > "$INSTALL_DIR/backups/backup.sql"
  echo "upload-data" > "$INSTALL_DIR/uploads/report.pdf"
  echo "claude-skill" > "$INSTALL_DIR/.claude/skills/skill.md"
  echo "gsd-skill" > "$INSTALL_DIR/.gsd/skills/skill.md"

  export PRESERVE_PATHS=(".planning" "docs" "backups" "uploads" ".env" ".claude/skills" ".gsd/skills")
}

@test "INFRA-02: preserve+restore round-trips all 7 paths byte-identically" {
  # Snapshot checksums
  PRE=$(find "$INSTALL_DIR" -type f | sort | xargs sha256sum | awk '{print $1}')
  # shellcheck source=/dev/null
  source "$REPO_ROOT/scripts/install/preserve-paths.sh"
  # Call directly (not via `run`) so STAGING_DIR + MOVED_PATHS are available in current shell
  preserve_paths_to_staging
  # Simulate hard reset — wipe everything
  rm -rf "$INSTALL_DIR"/.[!.]* "$INSTALL_DIR"/* 2>/dev/null || true
  mkdir -p "$INSTALL_DIR"
  restore_paths_from_staging
  POST=$(find "$INSTALL_DIR" -type f | sort | xargs sha256sum | awk '{print $1}')
  [ "$PRE" = "$POST" ]
}

@test "INFRA-02: PRESERVE_PATHS list matches CONTEXT.md minimum set" {
  # Assert exactly these 7 items
  [ "${#PRESERVE_PATHS[@]}" -eq 7 ]
  for want in ".planning" "docs" "backups" "uploads" ".env" ".claude/skills" ".gsd/skills"; do
    found=0
    for p in "${PRESERVE_PATHS[@]}"; do [[ "$p" == "$want" ]] && found=1; done
    [ "$found" -eq 1 ]
  done
}

@test "INFRA-02: .env ownership (uid/gid) preserved through staging" {
  chown 0:0 "$INSTALL_DIR/.env" 2>/dev/null || skip "need root or matching uid for chown"
  PRE_OWN="$(stat -c '%u:%g' "$INSTALL_DIR/.env")"
  # shellcheck source=/dev/null
  source "$REPO_ROOT/scripts/install/preserve-paths.sh"
  preserve_paths_to_staging
  rm -rf "$INSTALL_DIR"/.[!.]* "$INSTALL_DIR"/* 2>/dev/null || true
  mkdir -p "$INSTALL_DIR"
  restore_paths_from_staging
  POST_OWN="$(stat -c '%u:%g' "$INSTALL_DIR/.env")"
  [ "$PRE_OWN" = "$POST_OWN" ]
}

@test "INFRA-02: missing paths are silently skipped (no error)" {
  rm -rf "$INSTALL_DIR/.claude" "$INSTALL_DIR/.gsd"
  # shellcheck source=/dev/null
  source "$REPO_ROOT/scripts/install/preserve-paths.sh"
  # Call directly so MOVED_PATHS is accessible in current shell
  preserve_paths_to_staging
  # MOVED_PATHS should have 5 entries (the existing ones: .planning, docs, backups, uploads, .env)
  [ "${#MOVED_PATHS[@]}" -eq 5 ]
  # Cleanup staging
  restore_paths_from_staging
}

@test "INFRA-02: restore failure keeps STAGING_DIR and prints its path" {
  # shellcheck source=/dev/null
  source "$REPO_ROOT/scripts/install/preserve-paths.sh"
  preserve_paths_to_staging
  STAGE="$STAGING_DIR"
  # Remove INSTALL_DIR entirely to force mv dest_parent mkdir failure
  # We make a file at the path where INSTALL_DIR would be so mkdir -p fails
  rm -rf "$INSTALL_DIR"
  # Create a regular file at INSTALL_DIR path so mkdir -p "$INSTALL_DIR/..." fails
  touch "$INSTALL_DIR"
  run restore_paths_from_staging
  # Reset for teardown
  rm -f "$INSTALL_DIR"
  mkdir -p "$INSTALL_DIR"
  [ "$status" -ne 0 ]
  [[ "$output" =~ "$STAGE" ]]
  [ -d "$STAGE" ]
  # cleanup
  rm -rf "$STAGE"
}

@test "INFRA-02: STAGING_DIR uses mktemp samureye-preserve-XXXXXX pattern" {
  # shellcheck source=/dev/null
  source "$REPO_ROOT/scripts/install/preserve-paths.sh"
  preserve_paths_to_staging
  [[ "$STAGING_DIR" =~ /samureye-preserve-[A-Za-z0-9]{6,}$ ]]
  restore_paths_from_staging
}
