#!/usr/bin/env bash
# Shared bats helpers for Phase 8 install tests.
# Source this at the top of every .bats file:  load 'helpers'

# Absolute path to the repo root (resolved from the helpers file location)
export REPO_ROOT
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# make_temp_repo <target_dir>
# Creates a bare "origin" and a working clone at <target_dir> with one commit.
# Prints the bare repo path to stdout (used as $BARE by callers).
make_temp_repo() {
  local dir="$1"
  local bare
  bare="$(mktemp -d)"
  git init --quiet --bare "$bare"
  git clone --quiet "$bare" "$dir"
  (
    cd "$dir"
    git config user.email "test@samureye.local"
    git config user.name  "Phase 8 Test"
    echo "v1" > README.md
    git add README.md
    git commit --quiet -m "init"
    git push --quiet origin HEAD:refs/heads/main
    git branch --set-upstream-to=origin/main main 2>/dev/null || true
  )
  echo "$bare"
}

# mock_curl_download <url> <dest> <content_file>
# Records the requested URL in $MOCK_CURL_LOG and copies <content_file> to <dest>.
mock_curl_download() {
  local url="$1" dest="$2" src="$3"
  : "${MOCK_CURL_LOG:=/tmp/mock-curl-log-$$}"
  printf '%s\n' "$url" >> "$MOCK_CURL_LOG"
  cp "$src" "$dest"
}

# assert_sha256_matches <file> <expected_hex>
assert_sha256_matches() {
  local file="$1" expected="$2"
  local actual
  actual="$(sha256sum "$file" | awk '{print $1}')"
  [[ "$actual" == "$expected" ]] || {
    echo "SHA-256 mismatch for $file: expected=$expected actual=$actual" >&2
    return 1
  }
}

# assert_file_not_mutated <file> <snapshot>
# Fails if <file> differs from <snapshot> (both must exist).
assert_file_not_mutated() {
  local file="$1" snap="$2"
  diff -q "$file" "$snap" >/dev/null 2>&1 || {
    echo "File mutated: $file (diff vs $snap below)" >&2
    diff "$file" "$snap" >&2 || true
    return 1
  }
}
