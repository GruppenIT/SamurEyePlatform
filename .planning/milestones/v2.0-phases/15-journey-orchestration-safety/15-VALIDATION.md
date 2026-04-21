---
phase: 15
slug: journey-orchestration-safety
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-20
---

# Phase 15 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | vitest (confirmed via `vitest.config.ts`) |
| **Config file** | `/opt/samureye/vitest.config.ts` |
| **Quick run command** | `npx vitest run server/__tests__/journeyOrchestration.test.ts server/__tests__/rateLimiter.test.ts server/__tests__/abortRoute.test.ts server/__tests__/healthzTarget.test.ts --reporter=verbose` |
| **Full suite command** | `npx vitest run --reporter=verbose` |
| **Estimated runtime** | ~15 seconds |

---

## Sampling Rate

- **After every task commit:** Run quick run command above
- **After every plan wave:** Run `npx vitest run --reporter=verbose`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** ~15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 15-01-01 | 01 | 0 | JRNY-01..05, SAFE-01..06 | stub | `npx vitest run server/__tests__/journeyOrchestration.test.ts` | ❌ W0 | ⬜ pending |
| 15-01-02 | 01 | 0 | SAFE-01, SAFE-02 | stub | `npx vitest run server/__tests__/rateLimiter.test.ts` | ❌ W0 | ⬜ pending |
| 15-01-03 | 01 | 0 | JRNY-05 | stub | `npx vitest run server/__tests__/abortRoute.test.ts` | ❌ W0 | ⬜ pending |
| 15-01-04 | 01 | 0 | SAFE-05 | stub | `npx vitest run server/__tests__/healthzTarget.test.ts` | ❌ W0 | ⬜ pending |
| 15-02-01 | 02 | 1 | JRNY-01 | unit | `npx vitest run server/__tests__/journeyOrchestration.test.ts -t "JRNY-01"` | ❌ W0 | ⬜ pending |
| 15-02-02 | 02 | 1 | JRNY-02 | unit | `npx vitest run server/__tests__/journeyOrchestration.test.ts -t "JRNY-02"` | ❌ W0 | ⬜ pending |
| 15-03-01 | 03 | 2 | SAFE-01, SAFE-02 | unit | `npx vitest run server/__tests__/rateLimiter.test.ts` | ❌ W0 | ⬜ pending |
| 15-03-02 | 03 | 2 | SAFE-03 | unit | `npx vitest run server/__tests__/journeyOrchestration.test.ts -t "SAFE-03"` | ❌ W0 | ⬜ pending |
| 15-04-01 | 04 | 3 | JRNY-05 | unit | `npx vitest run server/__tests__/abortRoute.test.ts` | ❌ W0 | ⬜ pending |
| 15-04-02 | 04 | 3 | SAFE-04 | unit | `npx vitest run server/__tests__/journeyOrchestration.test.ts -t "SAFE-04"` | ❌ W0 | ⬜ pending |
| 15-04-03 | 04 | 3 | SAFE-05 | unit | `npx vitest run server/__tests__/healthzTarget.test.ts` | ❌ W0 | ⬜ pending |
| 15-04-04 | 04 | 3 | SAFE-06 | integration | `npx vitest run server/__tests__/journeyOrchestration.test.ts -t "SAFE-06"` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `server/__tests__/journeyOrchestration.test.ts` — stubs for JRNY-01, JRNY-02, JRNY-03, SAFE-03, SAFE-04, SAFE-06
- [ ] `server/__tests__/rateLimiter.test.ts` — stubs for SAFE-01, SAFE-02
- [ ] `server/__tests__/abortRoute.test.ts` — stub for JRNY-05
- [ ] `server/__tests__/healthzTarget.test.ts` — stub for SAFE-05

*All 4 files created with `it.todo` stubs per project Nyquist convention (established in Phases 12–14).*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Scheduler accepts api_security journey type | JRNY-04 | Requires live DB + scheduler service running; enum-level coverage validated by JRNY-01 unit test | Create a schedule via API with a journey of type `api_security`; verify no 400 validation error; verify schedule appears in GET /api/schedules |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
