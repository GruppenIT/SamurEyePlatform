---
phase: 08-infrastructure-install
plan: 02
subsystem: infra
tags: [bash, bats, shellcheck, pip, venv, sha256, binary-install, zip, tar.gz]

# Dependency graph
requires:
  - phase: 08-01
    provides: binaries.json manifest, bats harness, helpers.bash

provides:
  - scripts/install/fetch-binary.sh — sourceable bash library with install_binary(), install_arjun_from_pip(), verify_sha256_strict(), fetch_archive()
  - scripts/install/install-binaries.sh — CLI wrapper iterating all binaries.json entries
  - tests/install/test_binaries_install.bats — 6 INFRA-03 bats tests passing
  - tests/install/fixtures/fake-{katana,kiterunner,arjun}.{zip,tar.gz} — deterministic test fixtures

affects:
  - 08-04 (install.sh --install will source fetch-binary.sh)
  - 08-06 (build-release.sh will source fetch-binary.sh)

# Tech tracking
tech-stack:
  added: [bats-core 1.10.0, shellcheck 0.9.0, python3-venv, zip, unzip]
  patterns:
    - Sourceable bash library pattern (set -Eeuo pipefail, env guards with :?)
    - TDD RED/GREEN with bats for bash scripts
    - file:// URL support in fetch_archive() for hermetic test isolation
    - pip_source format uses .tar.gz mktemp suffix for pip compatibility
    - RETURN trap for temp file cleanup in install_binary()
    - Absolute venv path in shell wrapper (never relies on PATH)

key-files:
  created:
    - scripts/install/fetch-binary.sh
    - scripts/install/install-binaries.sh
    - tests/install/test_binaries_install.bats
    - tests/install/fixtures/fake-katana.zip
    - tests/install/fixtures/fake-kiterunner.tar.gz
    - tests/install/fixtures/fake-arjun.tar.gz
  modified:
    - .gitignore (added !tests/install/fixtures/*.tar.gz exception)

key-decisions:
  - "fetch_archive() handles file:// URLs natively for hermetic test isolation — no curl mock needed"
  - "mktemp for pip_source gets .tar.gz suffix so pip recognizes the format — otherwise pip rejects the path"
  - "RETURN trap cleans temp file in all exit paths from install_binary() including mismatch abort"
  - "fake-arjun setup.py version must be PEP 440 compliant (0.0.0) not semver-pre (0.0.0-fake)"

patterns-established:
  - "Pattern 1: Sourceable bash library — scripts/install/fetch-binary.sh is sourced, not executed, enabling function reuse"
  - "Pattern 2: Manifest-driven install — jq reads per-name fields; adding a binary requires only a binaries.json entry"
  - "Pattern 3: SHA-256 strict comparison — string equality via awk, never sha256sum -c, error contains expected= and actual= for debugging"

requirements-completed: [INFRA-03]

# Metrics
duration: 35min
completed: 2026-04-18
---

# Phase 8 Plan 02: Binary Fetch Module Summary

**Reusable bash library with SHA-256 zero-tolerance verification, file:// test isolation, and pip venv install for Arjun — all 6 INFRA-03 bats tests green**

## Performance

- **Duration:** ~35 min
- **Started:** 2026-04-18T12:35:02Z
- **Completed:** 2026-04-18T13:10:00Z
- **Tasks:** 2 (TDD RED + GREEN)
- **Files modified:** 8

## Accomplishments
- Delivered `scripts/install/fetch-binary.sh` — sourceable library with `install_binary()`, `install_arjun_from_pip()`, `verify_sha256_strict()`, `fetch_archive()`
- Delivered `scripts/install/install-binaries.sh` — CLI wrapper that iterates all keys in any manifest and calls `install_binary` for each
- 6 INFRA-03 bats tests pass: zip happy path, SHA mismatch abort, temp cleanup, tar.gz rename (kr→kiterunner), arjun venv+wrapper, full 4-binary iteration
- shellcheck -S error passes on both scripts
- Wave 2/3 plans (install.sh, build-release.sh) can now `source fetch-binary.sh` without further changes

## Task Commits

Each task was committed atomically:

1. **Task 1: Write bats fixtures + test file (RED)** - `18d49d2` (test)
2. **Task 2: Implement fetch-binary.sh + install-binaries.sh (GREEN)** - `cf9fc14` (feat)

## Function Signatures Exported by fetch-binary.sh

```bash
# Required env: INSTALL_DIR, MANIFEST
# Override: FETCH_CURL (default: curl), FETCH_RETRY (default: 1)

verify_sha256_strict <file> <expected_hex>
  # Strict string comparison; aborts with "expected=... actual=..." on mismatch

fetch_archive <url> <dest_tmp>
  # Supports file:// (tests) and https:// (production)
  # Aborts on failure; removes dest_tmp on curl error

install_binary <name>
  # Reads manifest[.binaries.<name>], dispatches on .format:
  #   zip      -> unzip -oj, rename if install_to differs, chmod +x
  #   tar.gz   -> tar --strip-components=1 --wildcards, rename, chmod +x
  #   pip_source -> install_arjun_from_pip()
  # RETURN trap cleans temp file in all exit paths

install_arjun_from_pip <tarball_path>
  # python3 -m venv $INSTALL_DIR/venv-security
  # pip install tarball into venv
  # Writes bin/arjun shell wrapper with absolute venv path
```

## Files Created/Modified
- `scripts/install/fetch-binary.sh` — Sourceable bash library (118 lines)
- `scripts/install/install-binaries.sh` — CLI wrapper (36 lines)
- `tests/install/test_binaries_install.bats` — 6 INFRA-03 tests
- `tests/install/fixtures/fake-katana.zip` — Fake zip fixture (katana binary)
- `tests/install/fixtures/fake-kiterunner.tar.gz` — Fake tar.gz with kiterunner_1.0.2_linux_amd64/kr layout
- `tests/install/fixtures/fake-arjun.tar.gz` — Fake Python package with PEP 440 version
- `.gitignore` — Added `!tests/install/fixtures/*.tar.gz` exception

## Decisions Made
- `fetch_archive()` handles `file://` URLs natively — eliminates need for curl mocking in tests
- `mktemp` for `pip_source` format gets `.tar.gz` suffix — pip rejects extensionless paths
- Fake arjun `setup.py` version must be PEP 440 compliant (`0.0.0`, not `0.0.0-fake`)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Installed bats-core, shellcheck, zip, unzip (missing from system)**
- **Found during:** Task 1 setup
- **Issue:** bats, shellcheck, zip not installed — plan 08-01 not yet executed
- **Fix:** `apt-get install -y bats shellcheck zip unzip` (bats 1.10.0, shellcheck 0.9.0)
- **Files modified:** System packages only
- **Committed in:** 18d49d2 (Task 1 commit — tools required for RED verification)

**2. [Rule 3 - Blocking] Created missing plan 01 artifacts (bats.bats, helpers dir)**
- **Found during:** Task 1 setup
- **Issue:** helpers.bash existed but bats.bats, fixtures/.gitkeep were missing; tests/install/ partially bootstrapped
- **Fix:** Created bats.bats harness self-check and fixtures/.gitkeep; ran bats.bats to confirm 5/5 pass
- **Files modified:** tests/install/bats.bats, tests/install/fixtures/.gitkeep
- **Committed in:** 18d49d2

**3. [Rule 1 - Bug] Fixed fake-arjun.tar.gz with invalid PEP 440 version**
- **Found during:** Task 2 GREEN (test 5 failure)
- **Issue:** `setup.py` had version `0.0.0-fake` which pip/setuptools reject with `InvalidVersion`
- **Fix:** Recreated fixture with version `0.0.0`
- **Files modified:** tests/install/fixtures/fake-arjun.tar.gz
- **Committed in:** cf9fc14

**4. [Rule 2 - Missing Critical] Added pip_source .tar.gz suffix for mktemp**
- **Found during:** Task 2 GREEN (arjun install)
- **Issue:** pip rejects extensionless temp file paths — `pip install /tmp/samureye-fetch-XXXXX` fails
- **Fix:** Detect `fmt == pip_source` in `install_binary()` and append `.tar.gz` to mktemp call
- **Files modified:** scripts/install/fetch-binary.sh
- **Committed in:** cf9fc14

**5. [Rule 2 - Missing Critical] Added .gitignore exception for test fixtures**
- **Found during:** Task 1 — fixtures not tracked
- **Issue:** `.gitignore` had `*.tar.gz` pattern covering test fixtures
- **Fix:** Added `!tests/install/fixtures/*.tar.gz` negation rule
- **Files modified:** .gitignore
- **Committed in:** 18d49d2

---

**Total deviations:** 5 auto-fixed (2 blocking, 2 missing critical, 1 bug)
**Impact on plan:** All auto-fixes required for correctness. No scope creep.

## Issues Encountered
- Test 3 (temp cleanup) was intermittently failing due to residual `/tmp/samureye-fetch-*` files from debug runs — the cleanup mechanism works correctly in clean state.

## Next Phase Readiness
- Wave 2 plans can now `source scripts/install/fetch-binary.sh` and call `install_binary <name>` — no additional library code needed
- `install-binaries.sh --manifest <path> --install-dir <path>` is the integration point for install.sh (Plan 04)
- `build-release.sh` (Plan 06) will source the same library for tarball packaging

## Self-Check

---
*Phase: 08-infrastructure-install*
*Completed: 2026-04-18*
