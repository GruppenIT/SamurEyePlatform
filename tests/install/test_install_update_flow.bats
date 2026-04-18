#!/usr/bin/env bats
# Smoke test: install.sh mode dispatch + preserve ordering.

load 'helpers'

@test "install.sh with no flags aborts with 'Escolha um modo'" {
  run bash "$REPO_ROOT/install.sh"
  [ "$status" -eq 1 ]
  [[ "$output" =~ "Escolha um modo" ]]
}

@test "install.sh --invalid aborts with 'Flag desconhecida'" {
  run bash "$REPO_ROOT/install.sh" --invalid
  [ "$status" -eq 1 ]
  [[ "$output" =~ "Flag desconhecida" ]]
}

@test "install.sh --from-tarball prints 'Plan 06' and exits 2" {
  run bash "$REPO_ROOT/install.sh" --from-tarball /tmp/fake.tar.gz
  [ "$status" -eq 2 ]
  [[ "$output" =~ "Plan 06" ]] || [[ "$output" =~ "nao implementado" ]]
}

@test "install.sh PRESERVE_PATHS array contains all 7 required paths" {
  grep -E '^readonly PRESERVE_PATHS=\(' "$REPO_ROOT/install.sh"
  for path in ".planning" "docs" "backups" "uploads" ".env" ".claude/skills" ".gsd/skills"; do
    grep -qF "\"$path\"" "$REPO_ROOT/install.sh" || {
      echo "PRESERVE_PATHS missing: $path" >&2
      false
    }
  done
}

@test "install.sh sources all three Wave 1 helper libraries" {
  grep -q 'source.*scripts/install/safe-reset.sh'     "$REPO_ROOT/install.sh"
  grep -q 'source.*scripts/install/preserve-paths.sh' "$REPO_ROOT/install.sh"
  grep -q 'source.*scripts/install/fetch-binary.sh'   "$REPO_ROOT/install.sh"
}

@test "install.sh run_safe_update calls gate -> preserve -> reset -> restore -> binaries in order" {
  # Extract run_safe_update body and verify call order via line numbers
  local body
  body="$(awk '/^run_safe_update\(\)/,/^}$/' "$REPO_ROOT/install.sh")"
  local gate_line preserve_line reset_line restore_line binary_line
  gate_line=$(echo "$body"      | grep -n 'safe_reset_gate'           | head -1 | cut -d: -f1)
  preserve_line=$(echo "$body"  | grep -n 'preserve_paths_to_staging' | head -1 | cut -d: -f1)
  reset_line=$(echo "$body"     | grep -n 'git reset --hard'          | head -1 | cut -d: -f1)
  restore_line=$(echo "$body"   | grep -n 'restore_paths_from_staging'| head -1 | cut -d: -f1)
  binary_line=$(echo "$body"    | grep -n 'install_binary'            | head -1 | cut -d: -f1)
  [ "$gate_line" -lt "$preserve_line" ]
  [ "$preserve_line" -lt "$reset_line" ]
  [ "$reset_line" -lt "$restore_line" ]
  [ "$restore_line" -lt "$binary_line" ]
}
