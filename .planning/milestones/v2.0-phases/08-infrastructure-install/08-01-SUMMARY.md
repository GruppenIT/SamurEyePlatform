---
phase: 08-infrastructure-install
plan: "01"
subsystem: install-infrastructure
tags:
  - manifests
  - bats
  - wordlists
  - wave-0
  - pinned-binaries
dependency_graph:
  requires: []
  provides:
    - scripts/install/binaries.json
    - scripts/install/wordlists.json
    - scripts/install/wordlists/arjun-extended-pt-en.txt
    - tests/install/helpers.bash
    - tests/install/bats.bats
  affects:
    - 08-02 (safe-reset) — reads binaries.json via jq
    - 08-03 (preserve-paths) — uses bats harness + helpers
    - 08-04 (binary-install) — reads binaries.json for SHA-256 verification
    - 08-05 (wordlists-install) — reads wordlists.json for SHA-256 and install_to
    - 08-06 (release-tarball) — reads both manifests for MANIFEST.json generation
tech_stack:
  added:
    - bats-core 1.10.0 (system — was already installed)
    - shellcheck 0.9.0 (system — was already installed)
  patterns:
    - Pinned JSON manifests with SHA-256 as source of truth for reproducible installs
    - Committed-in-repo wordlist with computed SHA-256 stored in manifest
    - bats load 'helpers' pattern for shared test utilities across Phase 8 plans
key_files:
  created:
    - scripts/install/binaries.json
    - scripts/install/wordlists.json
    - scripts/install/wordlists/arjun-extended-pt-en.txt
    - scripts/install/wordlists/README.md
    - tests/install/bats.bats
    - vendor/wordlists/.gitkeep
  modified:
    - package.json (added test:install script)
decisions:
  - bats 1.10.0 already installed on system — no source build needed (plan specified 1.11 as target but 1.10 meets >= 1.10 requirement)
  - wordlist line count: 115 lines (exceeds 100-line minimum)
  - arjun-extended-pt-en.txt SHA-256: dc5ca8c739d2205d771a9409836107515291fc418495c9d9c54c1f1fdcbc47a9
metrics:
  duration: "~15 minutes"
  completed: "2026-04-18"
  tasks_completed: 2
  tasks_total: 2
  files_created: 6
  files_modified: 1
---

# Phase 8 Plan 01: Wave 0 Foundation (Manifests + bats harness) Summary

**One-liner:** Pinned JSON manifests for 4 binaries + 2 wordlists with SHA-256, committed pt-BR Arjun wordlist (115 lines), and bats-core test harness with shared helpers — Wave 0 foundation ready for all downstream Phase 8 plans.

## What Was Built

### Task 1: Pinned manifests and custom wordlist (commit 168fe3a)

**`scripts/install/binaries.json`** — Source of truth for 4 pinned binary versions and SHA-256s:

| Binary | Version | SHA-256 (first 16 chars) |
|--------|---------|--------------------------|
| katana | 1.5.0 | 592890e5febaf570... |
| httpx | 1.9.0 | 54c6c91d61d3b82b... |
| kiterunner | 1.0.2 | 6f0b70aabf747de5... |
| arjun | 2.2.7 | b193cdaf97bf7b0e... |

**`scripts/install/wordlists.json`** — Wordlist manifest:

| File | Source | SHA-256 (first 16 chars) |
|------|--------|--------------------------|
| routes-large.kite | remote (CDN) | e6f4d78f6e607d03... |
| arjun-extended-pt-en.txt | local (committed) | dc5ca8c739d2205d... |

**`scripts/install/wordlists/arjun-extended-pt-en.txt`** — 115-line SamurEye pt-BR + en parameter wordlist. Computed SHA-256: `dc5ca8c739d2205d771a9409836107515291fc418495c9d9c54c1f1fdcbc47a9` (stored in wordlists.json).

**`vendor/wordlists/.gitkeep`** — Staging directory ready for Plan 05 downloads.

### Task 2: bats harness and npm wiring (commit 023d994)

**`tests/install/bats.bats`** — 5-test harness self-check. All pass on clean checkout:
- REPO_ROOT resolves to repo with install.sh
- make_temp_repo function exported
- assert_sha256_matches function exported
- fixtures directory exists
- binaries.json has all 4 binaries

**`tests/install/helpers.bash`** — Shared helpers for all Phase 8 test plans:
- `make_temp_repo` — git bare + working clone with initial commit
- `mock_curl_download` — records URL in MOCK_CURL_LOG, copies content
- `assert_sha256_matches` — sha256sum verification with clear error messages
- `assert_file_not_mutated` — diff-based file mutation detection

**`package.json`** — Added `"test:install": "bats tests/install/"` to scripts.

**System tools:** bats 1.10.0 + shellcheck 0.9.0 already present on the system — no installation required.

## Verification Results

```
jq -e '.binaries | length == 4' scripts/install/binaries.json   → true
sha256sum match wordlists.json vs file                           → OK
bats tests/install/bats.bats                                     → 1..5 all OK
bats --version                                                   → Bats 1.10.0
shellcheck --version                                             → 0.9.0
vendor/wordlists/ directory exists                               → OK
```

## Downstream Readiness

All plans in Wave 1+ can now:
```bash
jq -r '.binaries.katana.sha256' scripts/install/binaries.json
# → 592890e5febaf5706d0a962d96299512418d6eccce6388cf1600e1f078ed359d

jq -r '.binaries.<name>.<field>' scripts/install/binaries.json
# → any field from binaries manifest

jq -r '.wordlists["arjun-extended-pt-en.txt"].sha256' scripts/install/wordlists.json
# → dc5ca8c739d2205d771a9409836107515291fc418495c9d9c54c1f1fdcbc47a9
```

## Deviations from Plan

### Auto-observed (no fix needed)

**bats version:** Plan specified installing bats-core 1.11.0 from source if system version < 1.10. System already had bats 1.10.0, which meets the >= 1.10 requirement. Source installation was skipped.

**Pre-existing test files:** `tests/install/helpers.bash` and `tests/install/test_safe_reset.bats` were already committed by a prior session (commit f306fa0 — test(08-03)). This plan's helpers.bash content matches the plan spec exactly. No conflict.

### User Setup Required (before Phase 11)

The `arjun-extended-pt-en.txt` wordlist seed (115 lines) needs user review before Phase 11 consumes it for API parameter discovery. See `scripts/install/wordlists/README.md` for update procedure if the content is edited.

## Checkpoint: Human Verification

**Status:** AWAITING — this is the blocking checkpoint at the end of Plan 08-01.

**What to verify:**
1. Open `scripts/install/wordlists/arjun-extended-pt-en.txt` in editor
2. Confirm seed list is acceptable OR edit + recompute SHA-256
3. If edited: update `scripts/install/wordlists.json` `.wordlists["arjun-extended-pt-en.txt"].sha256`
4. Re-run `bats tests/install/bats.bats` — must still pass

**Resume signal:** Type "approved" to confirm wordlist seed, or describe the edit and new SHA-256.

## Self-Check: PASSED

All created files confirmed on disk:
- scripts/install/binaries.json — FOUND
- scripts/install/wordlists.json — FOUND
- scripts/install/wordlists/arjun-extended-pt-en.txt — FOUND
- tests/install/bats.bats — FOUND
- vendor/wordlists/.gitkeep — FOUND

All commits confirmed:
- 168fe3a — FOUND (feat(08-01): create pinned manifests)
- 023d994 — FOUND (feat(08-01): install bats harness)
