---
phase: 7
slug: edr-deployment-read-path
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-17
---

# Phase 7 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Vitest |
| **Config file** | vitest.config.ts |
| **Quick run command** | `npm run test -- server/__tests__/edrDeployments.test.ts` |
| **Full suite command** | `npm run test` |
| **Estimated runtime** | ~15 seconds |

---

## Sampling Rate

- **After every task commit:** Run `npm run test -- server/__tests__/edrDeployments.test.ts`
- **After every plan wave:** Run `npm run test`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 07-01-01 | 01 | 1 | PARS-10 | unit | `npm run test -- server/__tests__/edrDeployments.test.ts` | ❌ W0 | ⬜ pending |
| 07-01-02 | 01 | 1 | PARS-10 | unit | `npm run test -- server/__tests__/edrDeployments.test.ts` | ❌ W0 | ⬜ pending |
| 07-01-03 | 01 | 1 | PARS-10 | unit | `npm run test -- server/__tests__/edrDeployments.test.ts` | ❌ W0 | ⬜ pending |
| 07-02-01 | 02 | 2 | PARS-10 | manual | Browser verification of Sheet component | N/A | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `server/__tests__/edrDeployments.test.ts` — unit tests for `getEdrDeploymentsByJourneyWithHost` join query and API route validation
- [ ] Test stubs covering: returns rows with host details, returns 400 when journeyId missing, returns empty array for unknown journeyId

*Existing test infrastructure (Vitest, 298 passing tests) covers all other concerns.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Sheet opens with EDR deployment data when "View Results" clicked | PARS-10 | UI interaction requires browser | 1. Navigate to journeys page 2. Click "View Results" on a journey with EDR data 3. Verify Sheet slides in from right with summary stats and detail table |
| Detection badges show correct colors | PARS-10 | Visual styling | Verify green/red/gray badge variants render correctly |
| Empty state displays when no EDR deployments exist | PARS-10 | UI state | Click "View Results" on a journey without EDR data, verify empty state message |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
