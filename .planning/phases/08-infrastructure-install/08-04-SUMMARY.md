---
phase: 08-infrastructure-install
plan: 04
subsystem: infra
tags: [bash, bats, shellcheck, install, preserve, git-reset, safe-update]

# Dependency graph
requires:
  - phase: 08-02
    provides: scripts/install/fetch-binary.sh, install_binary()
  - phase: 08-03
    provides: scripts/install/safe-reset.sh, safe_reset_gate()

provides:
  - "scripts/install/preserve-paths.sh: preserve_paths_to_staging() + restore_paths_from_staging() real implementations"
  - "install.sh v2.0.0: mode dispatcher (--install/--update/--from-tarball stub), PRESERVE_PATHS array, run_safe_update()"
  - "tests/install/test_preserve_paths.bats: 6 INFRA-02 bats tests"
  - "tests/install/test_install_update_flow.bats: 6 mode dispatch + ordering bats tests"

affects:
  - 08-05 (install_wordlists guarded call already in run_safe_update)
  - 08-06 (run_from_tarball stub ready to be replaced)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "PRESERVE_PATHS readonly array drives mv-based staging/restore — no tar, no cp, ownership preserved by mv semantics"
    - "mktemp -d -t samureye-preserve-XXXXXX (Pitfall 8: never hardcoded $$)"
    - "MOVED_PATHS global tracks what was actually moved — missing paths silently skipped"
    - "Restore failure keeps STAGING_DIR on disk, prints path verbatim to stderr (Pitfall 2)"
    - "EUID_OVERRIDE=root test hatch in check_root() for bats isolation"
    - "run_safe_update() strict call order: gate -> preserve -> git reset --hard -> git clean -fdx -> restore -> binaries"

key-files:
  created:
    - scripts/install/preserve-paths.sh
    - tests/install/test_preserve_paths.bats
    - tests/install/test_install_update_flow.bats
  modified:
    - install.sh

key-decisions:
  - "Bats tests calling preserve_paths_to_staging directly (not via `run`) so STAGING_DIR + MOVED_PATHS globals are accessible in test scope"
  - "Restore failure test: replace INSTALL_DIR with a regular file so mkdir -p fails, since chmod 000 is ineffective under root"
  - "Source block placed after log/warn/error definitions so declare -F guards in helper libraries trigger correctly"
  - "rebuild_app() extracted from install_application() so run_safe_update can reuse npm install + build without full infra setup"

# Metrics
duration: 29min
completed: 2026-04-18
---

# Phase 8 Plan 04: Preserve Paths + Install Mode Dispatch Summary

**Real `preserve_paths_to_staging`/`restore_paths_from_staging` wired into `install.sh --update` via `PRESERVE_PATHS` readonly array — gate -> preserve -> git reset -> restore -> binaries flow verified end-to-end with 12 new bats tests (31 total, 0 failures)**

## Performance

- **Duration:** ~29 min
- **Started:** 2026-04-18T12:47:57Z
- **Completed:** 2026-04-18T13:16:00Z
- **Tasks:** 2 (TDD)
- **Files modified:** 4

## Accomplishments

- Implemented `scripts/install/preserve-paths.sh` — replaces Plan 03 stubs with real `preserve_paths_to_staging()` and `restore_paths_from_staging()` using `mktemp -d -t samureye-preserve-XXXXXX`
- 6 INFRA-02 bats tests covering: round-trip byte identity, 7-path minimum set, uid/gid ownership, missing-path skip, restore-failure staging retention, mktemp pattern
- Revised `install.sh` to v2.0.0 — mode dispatcher (`--install`, `--update`, `--from-tarball` stub), `PRESERVE_PATHS` readonly array, sourcing of all three Wave 1 libraries
- `run_safe_update()` implements the strict ordering: `safe_reset_gate` -> `preserve_paths_to_staging` -> `git reset --hard origin/$BRANCH` -> `git clean -fdx` -> `restore_paths_from_staging` -> `install_binary` loop
- `rebuild_app()` extracted as shared function used by both install and update paths
- `run_from_tarball()` stub exits 2 with "Plan 06 required" message
- 6 bats tests for mode dispatch and ordering verification
- **All 31 phase tests pass; shellcheck -S error clean on both files**

## PRESERVE_PATHS Array (install.sh line 45)

```bash
readonly PRESERVE_PATHS=(
  ".planning"
  "docs"
  "backups"
  "uploads"
  ".env"
  ".claude/skills"
  ".gsd/skills"
)
```

## Key Line Numbers in install.sh (1477 total lines)

| Section | Line |
|---------|------|
| `readonly PRESERVE_PATHS=(` | 45 |
| Library source block | 66-79 |
| `run_install()` | 1311 |
| `rebuild_app()` | 1356 |
| `run_safe_update()` | 1389 |
| `run_from_tarball()` stub | 1442 |
| Mode dispatcher (main entry) | 1449 |

## Bats Test Count

| File | Tests |
|------|-------|
| bats.bats | 5 |
| test_binaries_install.bats | 6 |
| test_safe_reset.bats | 8 |
| test_preserve_paths.bats | 6 |
| test_install_update_flow.bats | 6 |
| **Total** | **31** |

## Task Commits

1. **Task 1: preserve-paths.sh + test_preserve_paths.bats** — `be4c7f1` (feat)
2. **Task 2: install.sh mode dispatch + run_safe_update** — `9f7e55c` (feat)

## Files Created/Modified

- `scripts/install/preserve-paths.sh` — 80 lines, real preserve/restore library
- `tests/install/test_preserve_paths.bats` — 6 INFRA-02 tests
- `tests/install/test_install_update_flow.bats` — 6 mode dispatch + ordering tests
- `install.sh` — 1477 lines (was 1327); mode dispatcher, PRESERVE_PATHS, run_safe_update, rebuild_app, run_from_tarball stub

## Decisions Made

- Bats tests use direct function calls (not `run`) when they need to access global state (`STAGING_DIR`, `MOVED_PATHS`) populated by the called function
- Restore failure test replaces INSTALL_DIR with a regular file so `mkdir -p` inside `restore_paths_from_staging` fails — `chmod 000` is ineffective under root
- Library source block placed after `log/warn/error` definitions so `declare -F log` guards in helper libraries correctly detect the parent-defined functions
- `rebuild_app()` extracted from `install_application()` to avoid duplicating npm install + build logic in `run_safe_update()`

## Plan 05 / Plan 06 Integration Points

- `run_safe_update()` step 7 has a guarded call: `if declare -F install_wordlists; then install_wordlists; fi` — Plan 05 simply needs to source its wordlist library in install.sh and define `install_wordlists()`
- `run_from_tarball()` is a stub that exits 2 — Plan 06 replaces it with the real tarball extraction logic

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Bats `run` wrapper isolates subshell globals — direct calls needed for state-sharing tests**
- **Found during:** Task 1 (test_preserve_paths.bats, tests 1, 4, 5)
- **Issue:** Tests called `run preserve_paths_to_staging` but `run` executes the function in a subshell, so `STAGING_DIR` and `MOVED_PATHS` globals were not accessible in the test body
- **Fix:** Changed to direct function calls (without `run`) when the test needs access to populated globals; used `run restore_paths_from_staging` only where exit status capture is needed
- **Files modified:** tests/install/test_preserve_paths.bats
- **Committed in:** be4c7f1 (Task 1)

**2. [Rule 1 - Bug] chmod 000 on INSTALL_DIR ineffective under root for restore failure test**
- **Found during:** Task 1 (test 5 - restore failure)
- **Issue:** `chmod 000 $INSTALL_DIR` does not prevent root from writing into the directory; `mkdir -p` succeeded even with 000 permissions
- **Fix:** Replaced directory with a regular file at `$INSTALL_DIR` path so `mkdir -p "$INSTALL_DIR/subdir"` fails with ENOTDIR regardless of uid
- **Files modified:** tests/install/test_preserve_paths.bats
- **Committed in:** be4c7f1 (Task 1)

---

**Total deviations:** 2 auto-fixed (both Rule 1 bugs in test implementation)
**Impact on plan:** Both fixes necessary for test correctness. No scope creep.

## Self-Check

- `scripts/install/preserve-paths.sh` exists: YES
- `tests/install/test_preserve_paths.bats` exists: YES
- `tests/install/test_install_update_flow.bats` exists: YES
- `install.sh` has `readonly PRESERVE_PATHS=`: YES (line 45)
- Commits `be4c7f1` and `9f7e55c` exist: YES
- All 31 bats tests pass: YES
- shellcheck -S error clean: YES

## Self-Check: PASSED

---
*Phase: 08-infrastructure-install*
*Completed: 2026-04-18*
