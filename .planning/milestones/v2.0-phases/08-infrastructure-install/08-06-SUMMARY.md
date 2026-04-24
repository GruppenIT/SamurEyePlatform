---
phase: 08-infrastructure-install
plan: "06"
subsystem: infra
tags: [bash, bats, shellcheck, tarball, release, offline-install, deprecation, sha256, update-wrapper]

# Dependency graph
requires:
  - phase: 08-02
    provides: scripts/install/fetch-binary.sh (install_binary, fetch_archive with file:// support)
  - phase: 08-04
    provides: install.sh mode dispatcher with run_from_tarball stub
  - phase: 08-05
    provides: vendor/wordlists/routes-large.kite (183MB), install-wordlists.sh

provides:
  - "scripts/install/build-release.sh: release tarball builder — samureye-<tag>.tar.gz with app/, bin/ (4 verified binaries), wordlists/, install.sh, MANIFEST.json (file:// URLs)"
  - "install.sh run_from_tarball: full offline install from tarball — no git clone, no curl, no apt; MANIFEST rewritten to file:// URLs for install_binary; wordlists copied directly"
  - "update.sh: 31-line deprecation wrapper — DEPRECATED banner to stderr, exec to install.sh --update, preserves all env vars and exit code for systemUpdateService chain"
  - "tests/install/test_tarball_build.bats: 8 INFRA-05 tests for tarball build (setup_file/teardown_file pattern)"
  - "tests/install/test_tarball_install.bats: 4 INFRA-05 tests for --from-tarball mode dispatch"
  - "tests/install/test_update_wrapper.bats: 6 INFRA-05 tests for update.sh wrapper behavior"

affects:
  - Phase 9+ code should reference binaries via $INSTALL_DIR/bin/<binary> absolute paths
  - AUTOUP milestone: update.sh will be removed; install.sh --update will be invoked directly
  - systemUpdateService.ts chain preserved: sudoers + systemd still invoke update.sh

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "setup_file/teardown_file pattern (bats 1.10.0) for one-time build shared across multiple tests"
    - "MANIFEST URL rewriting: ./bin/<name> → file://<rootdir>/bin/<name> enabling fetch_archive to work offline"
    - "exec-based wrapper preserves exit code AND env vars through process replacement — critical for systemd ExecMainStatus"
    - "Tarball wordlists copied directly in run_from_tarball (not via install_wordlists) since merged MANIFEST uses source=tarball which install_wordlists doesn't handle"

key-files:
  created:
    - scripts/install/build-release.sh
    - tests/install/test_tarball_build.bats
    - tests/install/test_tarball_install.bats
    - tests/install/test_update_wrapper.bats
  modified:
    - install.sh (run_from_tarball stub replaced with ~50-line implementation)
    - update.sh (686 lines → 31-line wrapper)
    - tests/install/test_install_update_flow.bats (stub test updated for new behavior)

key-decisions:
  - "Tarball wordlists copied directly in run_from_tarball via cp -a (not via install_wordlists) — merged MANIFEST has source=tarball which install-wordlists.sh does not handle; simpler to bypass the library for this path"
  - "setup_file/teardown_file used in test_tarball_build.bats — per-test teardown deleted the tarball before tests 2-8 could use it"
  - "update.sh test design uses real update.sh with INSTALL_DIR pointing at mock stage (not copied update.sh) — $REPO_ROOT/update.sh with file:// install.sh avoids bats tmpdir file-not-found issues"
  - "configure_sudoers and install_update_units already existed in install.sh's setup_systemd_services (lines ~880-901) — no need to add standalone functions; plan note was precautionary"

requirements-completed: [INFRA-05]

# Metrics
duration: 28min
completed: 2026-04-18
---

# Phase 8 Plan 06: Release Tarball Flow + update.sh Deprecation Summary

**Release tarball builder (124MB, 4 verified binaries + 183MB wordlists bundled) + offline --from-tarball install mode + 31-line update.sh deprecation wrapper — 54 bats tests and 55 vitest tests all passing**

## Performance

- **Duration:** ~28 min
- **Started:** 2026-04-18T18:20:52Z
- **Completed:** 2026-04-18T18:49:00Z
- **Tasks:** 2 (TDD × 2)
- **Files modified:** 7

## Accomplishments

- `scripts/install/build-release.sh`: builds `samureye-<tag>.tar.gz` (124MB sample) — git archive of app, 4 binary archives (SHA-256 verified: katana, httpx, kiterunner, arjun), both wordlists (routes-large.kite 183MB + arjun-extended-pt-en.txt), install.sh, MANIFEST.json (URLs rewritten to ./bin/ prefix, SHAs preserved)
- `install.sh run_from_tarball()`: replaces Plan 04 stub — extracts tarball, rewrites MANIFEST URLs to `file://<rootdir>/bin/...` for offline `install_binary` calls, copies wordlists from tarball/wordlists/ directly, calls `rebuild_app()`; handles fresh install and safe-update paths
- `update.sh`: 686 → 31 lines — deprecation wrapper printing DEPRECATED banner to stderr, then `exec "$INSTALL_DIR/install.sh" --update` which propagates exit code and preserves all env vars (AUTO_CONFIRM, SKIP_BACKUP, GIT_TOKEN, BRANCH, INSTALL_DIR) for systemUpdateService.ts chain
- 8 + 4 + 6 = 18 new bats tests (INFRA-05); full suite: 54 tests, 0 failures
- 55 vitest tests pass (systemUpdateService.test.ts + subscriptionService.test.ts non-regression)
- shellcheck -S error clean on all shell files

## Tarball Size

Sample tarball `samureye-v0.0.0-summary-check.tar.gz`: **124M**
- Breakdown: ~2MB (app source, git archive HEAD), ~100MB (4 binary archives), ~183MB (routes-large.kite) — compressed to 124MB total

## update.sh Line Count

**31 lines** (< 50 line contract)

## configure_sudoers / install_update_units in install.sh

These functions were already embedded in `setup_systemd_services()` at lines ~880-901 of install.sh (present since v1.0). `run_install` calls `setup_systemd_services`. The plan note to "move" them was a precaution — the code was already there. No change needed.

## systemUpdateService.test.ts Pass Status

PASSED — 22 tests. `subscriptionService.test.ts` also PASSED — 33 tests. Total: 55 vitest tests.

## Full Bats Test Count

| File | Tests |
|------|-------|
| bats.bats | 5 |
| test_binaries_install.bats | 6 |
| test_safe_reset.bats | 8 |
| test_preserve_paths.bats | 6 |
| test_install_update_flow.bats | 6 |
| test_wordlists.bats | 5 |
| test_tarball_build.bats | 8 |
| test_tarball_install.bats | 4 |
| test_update_wrapper.bats | 6 |
| **Total** | **54** |

## Note for Phase 9

`$INSTALL_DIR/bin/<binary>` paths are available and documented in `scripts/install/binaries.json` `install_to` field:
- `bin/katana`
- `bin/httpx`
- `bin/kiterunner`
- `bin/arjun`

Phase 9+ code should reference binaries via these absolute paths.

## Task Commits

1. **Task 1 RED — test_tarball_build.bats (8 tests)** — `a8538c3` (test)
2. **Task 1 GREEN — build-release.sh + updated tests** — `1b0fb26` (feat)
3. **Task 2 RED — test_tarball_install.bats + test_update_wrapper.bats** — `f5e73b8` (test)
4. **Task 2 GREEN — run_from_tarball + update.sh + test fixes** — `9219317` (feat)

## Files Created/Modified

- `scripts/install/build-release.sh` — 73 lines; tarball builder with SHA-256 verification per binary
- `tests/install/test_tarball_build.bats` — 8 INFRA-05 tests (setup_file/teardown_file pattern)
- `tests/install/test_tarball_install.bats` — 4 INFRA-05 tests (--from-tarball mode dispatch + extraction)
- `tests/install/test_update_wrapper.bats` — 6 INFRA-05 tests (DEPRECATED banner, delegation, env vars, exec)
- `install.sh` — run_from_tarball stub (~5 lines) replaced with real implementation (~50 lines)
- `update.sh` — 686 lines → 31-line deprecation wrapper
- `tests/install/test_install_update_flow.bats` — stub test updated for new run_from_tarball behavior

## Decisions Made

- **Tarball wordlists copied directly:** `cp -a "$rootdir/wordlists/." "$INSTALL_DIR/wordlists/"` in `run_from_tarball` instead of via `install_wordlists`. The merged MANIFEST sets `source=tarball` which `install-wordlists.sh` doesn't handle. Simpler to bypass the library for this install path.
- **setup_file/teardown_file pattern:** bats per-test `teardown()` deleted the tarball after test 1, causing tests 2-8 to skip. Fixed by using `setup_file`/`teardown_file` (bats 1.10.0+) so the tarball is built once for the whole file.
- **Test design for update.sh:** Run the real `$REPO_ROOT/update.sh` with `INSTALL_DIR` pointing at a mock stage containing a mock `install.sh`. Do NOT copy update.sh to the mock stage — this avoids bats tmpdir file creation race conditions.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] bats teardown deletes tarball between tests**
- **Found during:** Task 1 GREEN (tests 2-8 all skipping)
- **Issue:** Original `teardown()` ran after each test, deleting tarball after test 1; tests 2-8 found no tarball
- **Fix:** Changed to `setup_file()`/`teardown_file()` pattern — build once before all tests, clean once after all tests
- **Files modified:** tests/install/test_tarball_build.bats
- **Committed in:** 1b0fb26

**2. [Rule 1 - Bug] test_update_wrapper.bats tests 2/5 referenced non-existent $stage/update.sh**
- **Found during:** Task 2 GREEN (tests 2 and 5 failing with exit 127)
- **Issue:** Tests created `$stage/install.sh` but ran `bash "$stage/update.sh"` — file didn't exist in bats tmpdir
- **Fix:** Changed to run `bash "$REPO_ROOT/update.sh"` with `INSTALL_DIR="$stage"` so the real update.sh delegates to `$stage/install.sh`
- **Files modified:** tests/install/test_update_wrapper.bats
- **Committed in:** 9219317

**3. [Rule 1 - Bug] test_install_update_flow.bats test 14 checked stub behavior**
- **Found during:** Task 2 GREEN (full bats suite had 1 failure)
- **Issue:** Test asserted `exit 2` and `"Plan 06"` message from the old run_from_tarball stub — now replaced with real implementation
- **Fix:** Updated test to verify new behavior: missing tarball → exit 1 + "from-tarball" in output
- **Files modified:** tests/install/test_install_update_flow.bats
- **Committed in:** 9219317

---

**Total deviations:** 3 auto-fixed (all Rule 1 bugs in test implementation)
**Impact on plan:** All auto-fixes necessary for test correctness. No scope creep.

## Issues Encountered

- Katana binary URL returned transient 504 during first bats test run; resolved by re-running (CDN cache warmed up on second attempt)

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- Phase 8 INFRA-01..05 all implemented and tested
- `bats tests/install/` runs 54 tests, 0 failures
- CHECKPOINT: human VM verification required (see Plan 06 checkpoint task for steps)
- Phase 9+ can reference binaries via `$INSTALL_DIR/bin/<name>` (documented in binaries.json `install_to` field)

## Self-Check

- `scripts/install/build-release.sh` exists: YES (73 lines, chmod +x)
- `tests/install/test_tarball_build.bats` exists: YES (8 tests)
- `tests/install/test_tarball_install.bats` exists: YES (4 tests)
- `tests/install/test_update_wrapper.bats` exists: YES (6 tests)
- `install.sh` has real run_from_tarball: YES (not exit 2 stub)
- `update.sh` is 31 lines: YES
- `update.sh` contains exec line: YES
- Commits a8538c3, 1b0fb26, f5e73b8, 9219317 exist: YES
- All 54 bats tests pass: YES
- 55 vitest tests pass: YES
- shellcheck -S error clean: YES

## Self-Check: PASSED

---
*Phase: 08-infrastructure-install*
*Completed: 2026-04-18*
