---
phase: 8
slug: infrastructure-install
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-18
---

# Phase 8 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | bats-core 1.10+ for shell; vitest (already installed) for TS helpers |
| **Config file** | `tests/install/bats.bats` (Wave 0 creates) |
| **Quick run command** | `bats tests/install/` |
| **Full suite command** | `bats tests/install/ && npm test` |
| **Estimated runtime** | ~60 seconds |

---

## Sampling Rate

- **After every task commit:** Run `bats tests/install/` (quick)
- **After every plan wave:** Run full suite (`bats tests/install/ && npm test`)
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 08-01-01 | 01 | 0 | INFRA-01..05 | fixture | `test -f scripts/install/binaries.json` | ❌ W0 | ⬜ pending |
| 08-01-02 | 01 | 0 | INFRA-01..05 | fixture | `test -f tests/install/bats.bats` | ❌ W0 | ⬜ pending |
| 08-02-01 | 02 | 1 | INFRA-01 | unit | `bats tests/install/binaries.bats` | ❌ W0 | ⬜ pending |
| 08-02-02 | 02 | 1 | INFRA-01 | unit | `sha256sum -c scripts/install/binaries.sha256` | ❌ W0 | ⬜ pending |
| 08-03-01 | 03 | 1 | INFRA-01 | unit | `bats tests/install/test_safe_reset.bats` | ❌ W0 | ⬜ pending |
| 08-04-01 | 04 | 2 | INFRA-03 | unit | `bats tests/install/preserve-paths.bats` | ❌ W0 | ⬜ pending |
| 08-05-01 | 05 | 2 | INFRA-04 | fixture | `test -f vendor/wordlists/routes-large.kite` | ❌ W0 | ⬜ pending |
| 08-05-02 | 05 | 2 | INFRA-04 | fixture | `test -f vendor/wordlists/arjun-extended-pt-en.txt` | ❌ W0 | ⬜ pending |
| 08-06-01 | 06 | 3 | INFRA-05 | integration | `bats tests/install/tarball-build.bats` | ❌ W0 | ⬜ pending |
| 08-06-02 | 06 | 3 | INFRA-05 | manual | `bash scripts/install/build-release.sh` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `scripts/install/binaries.json` — pinned versions + SHA-256 manifest (Katana, Kiterunner, httpx, Arjun)
- [ ] `scripts/install/wordlists.json` — pinned wordlist manifest (routes-large.kite, arjun-extended-pt-en.txt)
- [ ] `tests/install/bats.bats` — bats-core harness bootstrap
- [ ] `tests/install/fixtures/` — fixtures for dirty-checkout, preserve-paths, tarball
- [ ] `bats-core` install verified via `command -v bats` (install if missing)
- [ ] `vendor/wordlists/arjun-extended-pt-en.txt` — user-provided wordlist seeded with SHA-256

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| End-to-end release tarball install on clean VM | INFRA-05 | Requires isolated VM with no prior state | 1) Spin Ubuntu 22.04 VM · 2) Copy tarball · 3) `bash install.sh --from-tarball release.tar.gz` · 4) Verify binaries run · 5) Verify preserved paths absent (fresh install) |
| `update.sh` deprecation notice visible to operator | INFRA-05 | Visual check on terminal stderr | `bash update.sh 2>&1 \| head -5` must contain "DEPRECATED" |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
