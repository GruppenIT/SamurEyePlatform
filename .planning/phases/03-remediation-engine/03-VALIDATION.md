---
phase: 3
slug: remediation-engine
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-16
---

# Phase 3 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | vitest ^4.0.18 |
| **Config file** | `vitest.config.ts` (root) |
| **Quick run command** | `npm test -- --reporter=verbose server/__tests__/recommendationEngine.test.ts` |
| **Full suite command** | `npm test` |
| **Estimated runtime** | ~15 seconds |

---

## Sampling Rate

- **After every task commit:** Run `npm test -- --reporter=verbose server/__tests__/recommendationEngine.test.ts`
- **After every plan wave:** Run `npm test`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 03-01-01 | 01 | 1 | REMD-01 | unit | `npm test -- server/__tests__/recommendationEngine.test.ts` | ❌ W0 | ⬜ pending |
| 03-01-02 | 01 | 1 | REMD-02 | unit | `npm test -- server/__tests__/recommendationEngine.test.ts` | ❌ W0 | ⬜ pending |
| 03-01-03 | 01 | 1 | REMD-03 | unit | `npm test -- server/__tests__/recommendationEngine.test.ts` | ❌ W0 | ⬜ pending |
| 03-01-04 | 01 | 1 | REMD-04 | unit | `npm test -- server/__tests__/recommendationEngine.test.ts` | ❌ W0 | ⬜ pending |
| 03-01-05 | 01 | 1 | REMD-05 | unit | `npm test -- server/__tests__/recommendationEngine.test.ts` | ❌ W0 | ⬜ pending |
| 03-02-01 | 02 | 1 | REMD-06 | unit | `npm test -- server/__tests__/recommendationEngine.test.ts` | ❌ W0 | ⬜ pending |
| 03-02-02 | 02 | 1 | REMD-07 | integration | `npm test -- server/__tests__/threatEngine.test.ts` | ✅ verify existing | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `server/__tests__/recommendationEngine.test.ts` — stubs for REMD-01 through REMD-06; follows scoringEngine.test.ts pattern (vi.mock for DB, pure function tests)
- [ ] `server/services/remediation-templates/types.ts` — shared types needed before any template file
- [ ] Schema migration: `status TEXT NOT NULL DEFAULT 'pending'` column on recommendations + unique index on `threat_id`

*Existing infrastructure: vitest configured, 14 test files in `server/__tests__/`, DB mocked via `vi.mock('../db', () => ({ db: {}, pool: {} }))`*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Portuguese command text accuracy | REMD-02 | Domain expertise needed for command correctness | Review template output for correct shell/PowerShell syntax |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
