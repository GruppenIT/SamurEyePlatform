---
phase: 08-infrastructure-install
plan: 03
subsystem: infra
tags: [bash, bats, shellcheck, git, safe-reset, install]

# Dependency graph
requires:
  - phase: 08-01
    provides: tests/install/helpers.bash with make_temp_repo helper

provides:
  - "scripts/install/safe-reset.sh: sourceable bash library with safe_reset_gate() + preserve stubs"
  - "tests/install/test_safe_reset.bats: 8-test INFRA-01 bats coverage suite"
  - "safe_reset_gate() aborts on ahead-of-origin OR dirty tree (git status --porcelain)"
  - "preserve_paths_to_staging() / restore_paths_from_staging(): NOT IMPLEMENTED stubs for Plan 04"

affects:
  - 08-04-preserve-paths
  - 08-06-update-wrapper

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Safe hard-reset gate pattern: git fetch + rev-list --count + status --porcelain as pre-mutation check"
    - "TDD RED/GREEN cycle for bash shell scripts with bats-core"
    - "Sourceable bash library with declare -F guard for log/warn/error helpers"
    - "stub-and-label pattern: NOT IMPLEMENTED message with explicit Plan reference"

key-files:
  created:
    - scripts/install/safe-reset.sh
    - tests/install/test_safe_reset.bats
    - tests/install/helpers.bash
    - tests/install/fixtures/.gitkeep
  modified:
    - .planning/phases/08-infrastructure-install/08-VALIDATION.md

key-decisions:
  - "snapshot_tree excludes .git/ metadata — git fetch writes FETCH_HEAD inside .git/ which is NOT a working tree mutation per INFRA-01 semantics"
  - "safe_reset_gate uses return 1 (not exit 1) so sourcing the file in a subshell doesn't kill the parent process"
  - "Fetch is always performed first (read-only) before any abort check — mirrors update.sh lines 173-181 pattern"

patterns-established:
  - "Pattern: safe_reset_gate() — declare -F guard → fetch → rev-list --count ahead → status --porcelain dirty → log OK"
  - "Pattern: stubs with return 127 + explicit 'NOT IMPLEMENTED — see Plan N' messages"

requirements-completed:
  - INFRA-01

# Metrics
duration: 15min
completed: 2026-04-18
---

# Phase 08 Plan 03: Safe Hard-Reset Gate Summary

**Sourceable bash `safe_reset_gate()` aborts `install.sh --update` before any mutation — detects ahead-of-origin commits via `git rev-list --count` and dirty working tree via `git status --porcelain`, printing exact recovery commands (`git push`, `git stash -u`, `git status`)**

## Performance

- **Duration:** ~15 min
- **Started:** 2026-04-18T12:20:00Z
- **Completed:** 2026-04-18T12:38:14Z
- **Tasks:** 2 (TDD RED + GREEN)
- **Files modified:** 5

## Accomplishments

- Implemented `safe_reset_gate()` in `scripts/install/safe-reset.sh` — the single pre-mutation check that protects user work before `git reset --hard`
- 8 bats tests covering: clean pass, untracked abort, staged abort, ahead-of-origin abort, recovery message content, non-mutation guarantee, BRANCH env var override
- All 8 tests pass; shellcheck passes with zero errors
- Added `preserve_paths_to_staging()` and `restore_paths_from_staging()` stubs with explicit "NOT IMPLEMENTED — see Plan 04" messages so Plan 04 can land implementations without ambiguity

## Function Signatures

```bash
# Sourceable: source scripts/install/safe-reset.sh
# Required env: INSTALL_DIR
# Optional env: BRANCH (default "main"), GIT_TOKEN (PAT for authenticated fetch)

safe_reset_gate()
  # Returns 0: clean + synced with origin/$BRANCH
  # Returns 1 + stderr: $ahead commits ahead of origin/$BRANCH
  # Returns 1 + stderr: working tree suja (untracked/staged/modified files)
  # Side effect: ZERO — working tree is byte-identical before and after on abort

preserve_paths_to_staging()
  # STUB — returns 127 with "NOT IMPLEMENTED — see Plan 04"

restore_paths_from_staging()
  # STUB — returns 127 with "NOT IMPLEMENTED — see Plan 04"
```

## Abort Conditions

| Condition | Detection | Recovery hint in message |
|-----------|-----------|--------------------------|
| Commits ahead of origin | `git rev-list --count origin/$BRANCH..HEAD > 0` | `git push origin $BRANCH` |
| Dirty working tree (any) | `git status --porcelain` non-empty | `git stash -u`, `git status` |

## Recovery Messages (verbatim)

**Ahead-of-origin abort:**
```
Abort: N commit(s) local(is) não-pushados ahead de origin/main:
<git log --oneline output>
Resolva com um dos seguintes:
  git push origin main            # preservar seus commits
  git reset --hard origin/main    # descartar seus commits
```

**Dirty tree abort:**
```
Abort: working tree suja (arquivos modificados/staged/untracked):
<git status --porcelain output>
Resolva com um dos seguintes:
  git stash -u                       # guardar alterações temporariamente
  git clean -fd && git checkout -- . # descartar alterações
  git status                          # inspecionar antes de decidir
```

## Task Commits

1. **Task 1: test_safe_reset.bats (RED)** - `f306fa0` (test)
2. **Task 2: safe-reset.sh implementation (GREEN)** - `e524c34` (feat)

## Files Created/Modified

- `scripts/install/safe-reset.sh` — sourceable library: `safe_reset_gate()` + preserve stubs (min_lines: 90)
- `tests/install/test_safe_reset.bats` — 8 @test blocks, INFRA-01 coverage
- `tests/install/helpers.bash` — `make_temp_repo`, `mock_curl_download`, `assert_sha256_matches`, `assert_file_not_mutated`
- `tests/install/fixtures/.gitkeep` — directory stub for Plan 02+
- `.planning/phases/08-infrastructure-install/08-VALIDATION.md` — 08-03-01 command corrected to `test_safe_reset.bats`

## Decisions Made

- `snapshot_tree` in test excludes `.git/` metadata: `git fetch` writes `.git/FETCH_HEAD` which is git internal state, NOT a working tree mutation. The INFRA-01 requirement "working tree NOT mutated" refers to user files, not git plumbing metadata.
- `safe_reset_gate` uses `return 1` (not `exit 1`) so sourcing in a parent shell doesn't terminate the parent process on abort.
- Fetch always precedes abort checks — ensures `origin/$BRANCH` ref is current before `rev-list` comparison.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed snapshot_tree function to exclude .git/ metadata**
- **Found during:** Task 2 (GREEN phase, test 7 failing)
- **Issue:** `find . -maxdepth 2 -type f` in `snapshot_tree` included `.git/FETCH_HEAD` which is created by `git fetch`. The gate correctly performs a read-only fetch before checking abort conditions, but this added a new file to `.git/` causing the snapshot diff to fail falsely.
- **Fix:** Changed `find` to exclude `.git/` path: `find . -maxdepth 2 -not -path './.git/*' -type f`
- **Files modified:** `tests/install/test_safe_reset.bats`
- **Verification:** Test 7 now passes — PRE and POST snapshots are identical after dirty-tree abort
- **Committed in:** `e524c34` (Task 2 commit)

**2. [Rule 3 - Blocking] Created helpers.bash + installed bats/shellcheck (Plan 01 prereqs)**
- **Found during:** Task 1 start — helpers.bash missing, bats not installed
- **Issue:** Plan 08-03 depends on 08-01 (wave 0 foundation) which creates `tests/install/helpers.bash` and installs bats-core. Plan 08-01 had not yet been executed.
- **Fix:** Installed `bats 1.10.0` + `shellcheck` via apt; created `tests/install/helpers.bash` with `make_temp_repo`, `mock_curl_download`, `assert_sha256_matches`, `assert_file_not_mutated`; created `tests/install/fixtures/.gitkeep`
- **Files modified:** `tests/install/helpers.bash`, `tests/install/fixtures/.gitkeep`
- **Verification:** `bats tests/install/test_safe_reset.bats` runs successfully
- **Committed in:** `f306fa0` (Task 1 commit)

---

**Total deviations:** 2 auto-fixed (1 bug, 1 blocking dependency)
**Impact on plan:** Both fixes necessary for correctness and executability. No scope creep.

## Bats Pass Count

`bats tests/install/test_safe_reset.bats` → **8 tests, 0 failures**

## Issues Encountered

None beyond the two auto-fixed deviations above.

## Next Phase Readiness

- Plan 04 can source `scripts/install/safe-reset.sh` and replace `preserve_paths_to_staging()` / `restore_paths_from_staging()` stubs with real implementations
- Plan 06 (update.sh wrapper) can call `safe_reset_gate` as the first gate in `install.sh --update`
- `tests/install/helpers.bash` is available for all downstream bats test files (Plans 02-06)
- Note: Plan 08-01 (binaries.json + wordlists + bats harness) should still be formally executed to commit `bats.bats` + `wordlists.json` + `vendor/wordlists/.gitkeep` — partial prereqs were provided inline here

---
*Phase: 08-infrastructure-install*
*Completed: 2026-04-18*
