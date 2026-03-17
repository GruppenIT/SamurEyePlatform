---
phase: 6
slug: calibration-and-quality
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-17
---

# Phase 6 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Vitest ^4.0.18 |
| **Config file** | `vitest.config.ts` |
| **Quick run command** | `npx vitest run server/__tests__/scoringEngine.test.ts` |
| **Full suite command** | `npm test` |
| **Estimated runtime** | ~5 seconds |

---

## Sampling Rate

- **After every task commit:** Run `npx vitest run server/__tests__/scoringEngine.test.ts`
- **After every plan wave:** Run `npm test`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 10 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 06-01-01 | 01 | 1 | QUAL-01 | unit | `npx vitest run server/__tests__/edrAvScanner.test.ts` | ✅ | ⬜ pending |
| 06-01-02 | 01 | 1 | PARS-11 | snapshot | `npx vitest run server/__tests__/threatRuleSnapshots.test.ts` | ✅ | ⬜ pending |
| 06-01-03 | 01 | 1 | QUAL-02 | all | `npm test` | ✅ | ⬜ pending |
| 06-02-01 | 02 | 1 | THRT-06 | unit regression | `npx vitest run server/__tests__/scoringEngine.test.ts` | ❌ W0 | ⬜ pending |
| 06-02-02 | 02 | 1 | THRT-08 | unit regression | `npx vitest run server/__tests__/scoringEngine.test.ts` | ❌ W0 | ⬜ pending |
| 06-02-03 | 02 | 1 | THRT-09 | unit regression | `npx vitest run server/__tests__/scoringEngine.test.ts` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] Calibration regression tests in `server/__tests__/scoringEngine.test.ts` — covers THRT-06, THRT-08, THRT-09 (add to existing file)

*No new test files needed — tests are added to the existing `scoringEngine.test.ts`. No framework install needed — Vitest 4.0.18 already installed.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Calibration report accuracy | THRT-06/08/09 | Report content depends on live DB data | Run `npx tsx scripts/calibrate.ts` and verify report at `.planning/phases/06-calibration-and-quality/CALIBRATION-REPORT.md` |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 10s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
