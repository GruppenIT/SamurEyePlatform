---
phase: 5
slug: edr-timestamps
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-17
---

# Phase 5 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Vitest (already configured) |
| **Config file** | `vitest.config.ts` (root) |
| **Quick run command** | `npx vitest run server/__tests__/edrParser.test.ts` |
| **Full suite command** | `npx vitest run` |
| **Estimated runtime** | ~15 seconds |

---

## Sampling Rate

- **After every task commit:** Run `npx vitest run server/__tests__/edrParser.test.ts`
- **After every plan wave:** Run `npx vitest run`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 05-01-01 | 01 | 1 | PARS-09 | unit | `npx vitest run server/__tests__/edrParser.test.ts` | ✅ (needs new cases) | ⬜ pending |
| 05-01-02 | 01 | 1 | PARS-09 | unit | `npx vitest run server/__tests__/edrParser.test.ts` | ✅ (needs new cases) | ⬜ pending |
| 05-01-03 | 01 | 1 | PARS-09 | unit | `npx vitest run server/__tests__/edrParser.test.ts` | ✅ (needs new cases) | ⬜ pending |
| 05-01-04 | 01 | 1 | PARS-10 | unit/type | `npx tsc --noEmit` | ❌ W0 | ⬜ pending |
| 05-01-05 | 01 | 1 | PARS-10 | unit | `npx vitest run server/__tests__/edrDeployments.test.ts` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `server/__tests__/edrDeployments.test.ts` — unit tests for `insertEdrDeployment` and `getEdrDeploymentsByJourney` (covers PARS-10 storage layer)
- [ ] Snapshot regeneration after new timestamp fields added to `EdrFindingSchema` — run `npx vitest run --update-snapshots` after schema change

*Existing `edrParser.test.ts` covers schema validation tests but needs new `it()` blocks for timestamp field assertions — no new file required for PARS-09 parser tests.*

---

## Manual-Only Verifications

*All phase behaviors have automated verification.*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
