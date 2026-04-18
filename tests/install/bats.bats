#!/usr/bin/env bats
# Harness self-check — verifies bats can find helpers and fixtures.

load 'helpers'

@test "harness: REPO_ROOT resolves to repo with install.sh at top level" {
  [ -f "$REPO_ROOT/install.sh" ]
}

@test "harness: helpers.bash exports make_temp_repo" {
  run type make_temp_repo
  [ "$status" -eq 0 ]
  [[ "$output" =~ "function" ]]
}

@test "harness: helpers.bash exports assert_sha256_matches" {
  run type assert_sha256_matches
  [ "$status" -eq 0 ]
  [[ "$output" =~ "function" ]]
}

@test "harness: fixtures directory exists" {
  [ -d "$REPO_ROOT/tests/install/fixtures" ]
}

@test "harness: binaries.json manifest is valid JSON with all 4 binaries" {
  run jq -e '.binaries | length == 4' "$REPO_ROOT/scripts/install/binaries.json"
  [ "$status" -eq 0 ]
}
