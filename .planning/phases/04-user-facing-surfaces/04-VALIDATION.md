---
phase: 4
slug: user-facing-surfaces
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-16
---

# Phase 4 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | vitest (existing) + React Testing Library |
| **Config file** | `client/vite.config.ts` (vitest config) |
| **Quick run command** | `npx vitest run --reporter=verbose` |
| **Full suite command** | `npx vitest run && npm test` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `npx vitest run --reporter=verbose`
- **After every plan wave:** Run `npx vitest run && npm test`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 04-01-01 | 01 | 1 | UIFN-01 | unit | `npx vitest run` | ❌ W0 | ⬜ pending |
| 04-01-02 | 01 | 1 | UIFN-02 | unit | `npx vitest run` | ❌ W0 | ⬜ pending |
| 04-01-03 | 01 | 1 | UIFN-03 | unit | `npx vitest run` | ❌ W0 | ⬜ pending |
| 04-01-04 | 01 | 1 | UIFN-04 | unit | `npx vitest run` | ❌ W0 | ⬜ pending |
| 04-02-01 | 02 | 1 | UIAP-01 | unit | `npx vitest run` | ❌ W0 | ⬜ pending |
| 04-02-02 | 02 | 1 | UIAP-02 | unit | `npx vitest run` | ❌ W0 | ⬜ pending |
| 04-02-03 | 02 | 1 | UIAP-03 | unit | `npx vitest run` | ❌ W0 | ⬜ pending |
| 04-02-04 | 02 | 1 | UIAP-04 | unit | `npx vitest run` | ❌ W0 | ⬜ pending |
| 04-03-01 | 03 | 2 | UIDB-01 | unit | `npx vitest run` | ❌ W0 | ⬜ pending |
| 04-03-02 | 03 | 2 | UIDB-02 | unit | `npx vitest run` | ❌ W0 | ⬜ pending |
| 04-03-03 | 03 | 2 | UIDB-03 | unit | `npx vitest run` | ❌ W0 | ⬜ pending |
| 04-03-04 | 03 | 2 | UIDB-04 | unit | `npx vitest run` | ❌ W0 | ⬜ pending |
| 04-03-05 | 03 | 2 | UIDB-05 | unit | `npx vitest run` | ❌ W0 | ⬜ pending |
| 04-03-06 | 03 | 2 | UIDB-06 | unit | `npx vitest run` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `client/src/__tests__/threatDetail.test.tsx` — stubs for UIFN-01, UIFN-02
- [ ] `client/src/__tests__/threatList.test.tsx` — stubs for UIFN-03, UIFN-04
- [ ] `client/src/__tests__/actionPlan.test.tsx` — stubs for UIAP-01 through UIAP-04
- [ ] `client/src/__tests__/dashboard.test.tsx` — stubs for UIDB-01 through UIDB-06
- [ ] `client/src/__tests__/setup.ts` — shared test fixtures and mocks

*Existing infrastructure covers server-side tests. Client-side test stubs needed for Phase 4 UI components.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Visual hierarchy clarity | UIFN-01 | Subjective UX quality | Open threat detail, verify problem/impact/fix sections are visually distinct |
| Sparkline rendering | UIDB-04 | Canvas/SVG rendering | Open dashboard, verify trend line renders with date labels |
| Auto-refresh on job complete | UIDB-05 | Requires running scan | Start a journey, verify dashboard updates without page refresh |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
