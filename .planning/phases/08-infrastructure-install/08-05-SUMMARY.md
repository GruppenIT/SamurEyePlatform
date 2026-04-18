---
phase: 08-infrastructure-install
plan: "05"
subsystem: infra
tags: [bash, bats, shellcheck, wordlists, vendor, sha256, kiterunner, wave-2]

# Dependency graph
requires:
  - phase: 08-01
    provides: scripts/install/wordlists.json (manifest schema + arjun-extended-pt-en.txt)
  - phase: 08-02
    provides: scripts/install/fetch-binary.sh (verify_sha256_strict, fetch_archive)
  - phase: 08-04
    provides: install.sh (mode dispatcher with run_install/run_safe_update, library source block)

provides:
  - "scripts/install/install-wordlists.sh: install_wordlists() — manifest-driven local+remote wordlist install with SHA-256 gating and vendor-first CDN resilience"
  - "vendor/wordlists/routes-large.kite: 183MB pre-extracted kiterunner wordlist vendored in-tree (extracted_sha256: 5cc2e88ac8f700c740ed934ba228edc66b268fef82a48466c5344e1fe8416ca3)"
  - "vendor/wordlists/routes-large.kite.tar.gz.sha256: tarball SHA audit trail"
  - "scripts/install/wordlists.json: updated with extracted_sha256 field for routes-large.kite"
  - "install.sh: sources install-wordlists.sh; direct install_wordlists() call in both run_install and run_safe_update"
  - "tests/install/test_wordlists.bats: 5 INFRA-04 bats tests (36 total suite, 0 failures)"

affects:
  - 08-06 (release-tarball) — include both wordlists in release tarball; both manifests now fully populated

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Vendor-first CDN resilience: install_wordlists prefers vendor/wordlists/<name> over remote URL; no network call when vendored copy present (Pitfall 5)"
    - "extracted_sha256 field in wordlists.json for extracted-file verification separate from tarball SHA"
    - "_WORDLIST_REPO_ROOT env var override enables hermetic bats test isolation without touching real repo files"
    - "mktemp -t samureye-wl-XXXXXX with trap RETURN cleanup for temp file safety in remote-fetch path"

key-files:
  created:
    - scripts/install/install-wordlists.sh
    - vendor/wordlists/routes-large.kite
    - vendor/wordlists/routes-large.kite.tar.gz.sha256
  modified:
    - install.sh
    - tests/install/test_wordlists.bats
    - scripts/install/wordlists.json

key-decisions:
  - "routes-large.kite vendored as 183MB plain file (not LFS) — user must confirm in-tree size is acceptable at checkpoint"
  - "extracted_sha256 field added to wordlists.json to verify the extracted .kite file independently of the tarball SHA"
  - "_WORDLIST_REPO_ROOT env override pattern allows bats tests to point install-wordlists.sh at a tmp dir with fake vendor files without modifying the real repo"
  - "Direct install_wordlists() calls replace Plan 04 guarded declare -F check now that the library is sourced unconditionally"

requirements-completed: [INFRA-04]

# Metrics
duration: ~20min (continuation from previous agent RED commit)
completed: 2026-04-18
---

# Phase 8 Plan 05: Wordlists Install Summary

**install_wordlists() driven by wordlists.json with vendor-first SHA-256 gating — routes-large.kite (183MB) vendored in-tree, arjun-extended-pt-en.txt copied locally, airgapped install succeeds with 0 network calls**

## Performance

- **Duration:** ~20 min (continuation — RED commit already existed at 96cbfbf)
- **Started:** 2026-04-18 (continuation from previous agent)
- **Completed:** 2026-04-18
- **Tasks:** 1 (TDD, GREEN phase)
- **Files modified:** 5

## Accomplishments

- `scripts/install/install-wordlists.sh` (92 lines) — sourceable bash library implementing `install_wordlists()` that iterates `wordlists.json`, handles `local` (copy + SHA verify) and `remote` (vendor-first + SHA verify, fallback to fetch+extract) source types
- `vendor/wordlists/routes-large.kite` (183MB) — pre-extracted kiterunner wordlist committed in-tree; `extracted_sha256: 5cc2e88ac8f700c740ed934ba228edc66b268fef82a48466c5344e1fe8416ca3` recorded in `wordlists.json`
- `vendor/wordlists/routes-large.kite.tar.gz.sha256` — tarball SHA audit trail (`e6f4d78f...`)
- `install.sh` wired: sources `install-wordlists.sh` after `fetch-binary.sh`; direct `install_wordlists()` call in both `run_install` (after `install_security_tools`) and `run_safe_update` (step 7, replacing Plan 04 guarded check)
- 5 INFRA-04 bats tests all passing; full suite 36 tests, 0 failures; shellcheck -S error clean

## Task Commits

1. **RED (prior agent):** `96cbfbf` — `test(08-05): add failing bats tests for INFRA-04 wordlist install`
2. **GREEN:** `50bca6b` — `feat(08-05): implement install-wordlists.sh + routes-large.kite vendoring (GREEN)`

## Files Created/Modified

- `scripts/install/install-wordlists.sh` — 92 lines; `install_wordlists()` function with local+remote source handling and SHA-256 gating
- `vendor/wordlists/routes-large.kite` — 183MB pre-extracted kiterunner wordlist vendored in-tree
- `vendor/wordlists/routes-large.kite.tar.gz.sha256` — tarball SHA audit trail (91 bytes)
- `scripts/install/wordlists.json` — added `extracted_sha256: 5cc2e88ac8f700c740ed934ba228edc66b268fef82a48466c5344e1fe8416ca3` to routes-large.kite entry
- `install.sh` — source line added at line 79; `install_wordlists` call added to `run_install` and `run_safe_update`
- `tests/install/test_wordlists.bats` — 5 INFRA-04 tests (was stub from RED commit; final implementation committed in GREEN)

## Decisions Made

- **183MB in-tree vendoring:** routes-large.kite is 183MB (plan estimated ~34MB based on tar.gz size — actual extracted file is much larger). File committed as plain git object (no LFS). User must confirm at checkpoint whether in-tree size is acceptable.
- **extracted_sha256 field:** Added to `wordlists.json` so install-time verification checks the extracted `.kite` file, not the tarball. This decouples the two SHA checks (tarball integrity vs extracted-file integrity).
- **_WORDLIST_REPO_ROOT override pattern:** install-wordlists.sh checks `if [[ -z "${_WORDLIST_REPO_ROOT:-}" ]]` before computing the value, enabling bats tests to inject a temp dir as the "repo root" without modifying real repo files.
- **Direct calls replace guarded declare -F:** Plan 04 left a guarded `if declare -F install_wordlists` check as a seam for Plan 05. This plan sources the library unconditionally and replaces the guard with a direct call.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] install-wordlists.sh uses conditional check for _WORDLIST_REPO_ROOT**
- **Found during:** Task 1 (test isolation for remote-source tests)
- **Issue:** Plan spec used direct assignment `_WORDLIST_REPO_ROOT="$(cd ...)"` which would override the pre-set env var in bats tests (tests need to set their own repo root to a tmp dir)
- **Fix:** Added `if [[ -z "${_WORDLIST_REPO_ROOT:-}" ]]; then ... fi` guard so env var pre-set by bats is honored
- **Files modified:** scripts/install/install-wordlists.sh
- **Verification:** Test 3 (remote-source prefers vendored copy) and Test 4 (fallback to URL) both pass using tmp dir as root
- **Committed in:** 50bca6b (GREEN commit)

---

**Total deviations:** 1 auto-fixed (Rule 3 blocking — test isolation)
**Impact on plan:** Essential for hermetic test isolation. No scope creep.

## Issues Encountered

None beyond the deviation above.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- INFRA-04 complete: `install.sh --update` on a network-fenced VM with `vendor/wordlists/routes-large.kite` present copies both wordlists to `$INSTALL_DIR/wordlists/` without any `curl`/`wget` call
- Plan 06 (release tarball) can now include both wordlists in the tarball by reading `wordlists.json` — `vendor_path` field points to each vendored file
- **AWAITING CHECKPOINT:** Human must confirm that a 183MB file committed as a plain git object is acceptable, or specify alternative strategy (LFS, external mirror, fetch-once-at-install)

---
*Phase: 08-infrastructure-install*
*Completed: 2026-04-18*
