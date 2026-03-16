---
phase: 2
slug: threat-engine-intelligence
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-16
---

# Phase 2 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Vitest ^4.0.18 |
| **Config file** | `vitest.config.ts` (project root) |
| **Quick run command** | `npm test -- --reporter=verbose` |
| **Full suite command** | `npm test` |
| **Estimated runtime** | ~15 seconds |

---

## Sampling Rate

- **After every task commit:** Run `npm test -- server/__tests__/threatRuleSnapshots.test.ts` (existing snapshots stay green)
- **After every plan wave:** Run `npm test` (full suite)
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 02-01-01 | 01 | 1 | THRT-01..10 | schema | `npm test -- server/__tests__/schemaMigrations.test.ts` | ❌ W0 | ⬜ pending |
| 02-02-01 | 02 | 2 | THRT-01 | unit | `npm test -- server/__tests__/threatGrouping.test.ts` | ❌ W0 | ⬜ pending |
| 02-02-02 | 02 | 2 | THRT-02 | unit | `npm test -- server/__tests__/threatGrouping.test.ts` | ❌ W0 | ⬜ pending |
| 02-02-03 | 02 | 2 | THRT-03 | unit | `npm test -- server/__tests__/threatGrouping.test.ts` | ❌ W0 | ⬜ pending |
| 02-02-04 | 02 | 2 | THRT-04 | unit | `npm test -- server/__tests__/threatGrouping.test.ts` | ❌ W0 | ⬜ pending |
| 02-02-05 | 02 | 2 | THRT-05 | unit (snapshot) | `npm test -- server/__tests__/threatRuleSnapshots.test.ts` | ✅ | ⬜ pending |
| 02-03-01 | 03 | 2 | THRT-06 | unit | `npm test -- server/__tests__/scoringEngine.test.ts` | ❌ W0 | ⬜ pending |
| 02-03-02 | 03 | 2 | THRT-07 | unit | `npm test -- server/__tests__/scoringEngine.test.ts` | ❌ W0 | ⬜ pending |
| 02-03-03 | 03 | 2 | THRT-08 | unit | `npm test -- server/__tests__/scoringEngine.test.ts` | ❌ W0 | ⬜ pending |
| 02-03-04 | 03 | 2 | THRT-09 | unit | `npm test -- server/__tests__/scoringEngine.test.ts` | ❌ W0 | ⬜ pending |
| 02-03-05 | 03 | 2 | THRT-10 | unit | `npm test -- server/__tests__/scoringEngine.test.ts` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `server/__tests__/threatGrouping.test.ts` — stubs for THRT-01, THRT-02, THRT-03, THRT-04; mock storage pattern from `threatRuleSnapshots.test.ts`
- [ ] `server/__tests__/scoringEngine.test.ts` — stubs for THRT-06, THRT-07, THRT-08, THRT-09, THRT-10; pure function tests, no DB dependency
- [ ] No new framework installs required — Vitest already configured

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Existing threats unchanged after grouping | THRT-05 | Requires pre-populated DB state | Seed threats, run grouping, verify correlation keys and status unchanged |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
