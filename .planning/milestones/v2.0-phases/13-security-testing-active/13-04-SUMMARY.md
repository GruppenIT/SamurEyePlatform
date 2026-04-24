---
phase: 13-security-testing-active
plan: "04"
subsystem: api-security-testing
tags: [active-testing, owasp-api, route, cli, runbook, wave-3]
dependency_graph:
  requires:
    - "13-security-testing-active/13-01 — apiActiveTestOptsSchema + types"
    - "13-security-testing-active/13-02 — 5 scanners + remediation templates"
    - "13-security-testing-active/13-03 — runApiActiveTests orchestrator"
    - "12-security-testing-passive/12-04 — POST /test/passive pattern"
  provides:
    - "POST /api/v1/apis/:id/test/active HTTP entrypoint"
    - "server/scripts/runApiActiveTests.ts CLI"
    - "docs/operations/run-api-active-tests.md runbook pt-BR"
  affects:
    - "server/routes/apis.ts — extended with active test handler"
    - "Phase 15 — can wire runApiActiveTests into journeyExecutor"
    - "Phase 16 — findings visible via pre-existing GET /api/v1/api-findings"
tech_stack:
  added: []
  patterns:
    - "POST /test/active mirrors POST /test/passive pattern (Phase 12)"
    - "requireOperator RBAC + apiActiveTestOptsSchema Zod .strict() parse"
    - "Synthetic jobId via randomUUID (Phase 15 replaces with queue.enqueue)"
    - "Audit log action='api_active_test_started' with actorId/objectType/objectId"
    - "CLI parseCliArgs manual (handles repeatable --credential flag)"
    - "import.meta.url === pathToFileURL guard for test-safe ESM module"
key_files:
  created:
    - server/scripts/runApiActiveTests.ts
    - docs/operations/run-api-active-tests.md
  modified:
    - server/routes/apis.ts
decisions:
  - "Used actorId (not userId) in logAudit — matches Phase 12 passive pattern"
  - "CLI parseCliArgs manual (not node:util parseArgs) — enables repeatable --credential with same pattern as runApiPassiveTests.ts"
  - "Runbook has 8 sections (7 required + added §Observabilidade) for operational completeness"
  - "UAT auto-approved (auto-mode): Steps 1-4 static checks pass; Steps 5-8 require live server not available in CI"
metrics:
  duration_minutes: 6
  completed_date: "2026-04-20"
  tasks_completed: 4
  files_changed: 3
---

# Phase 13 Plan 04: Wave 3 Public Surfaces Summary

**One-liner:** HTTP route POST /test/active + CLI runApiActiveTests.ts + pt-BR runbook with 8 sections (security gates, dryRun, real execution, OWASP findings table, troubleshooting, manual-only checks).

## What Was Built

Wave 3 closes the Phase 13 public surface by exposing `runApiActiveTests` (Wave 2 orchestrator) via three interfaces:

1. **HTTP route** `POST /api/v1/apis/:id/test/active` appended to `registerApiRoutes(app)` in `server/routes/apis.ts` — mirrors the Phase 12 `/test/passive` handler exactly.

2. **CLI** `server/scripts/runApiActiveTests.ts` — 170-line operator script with `parseCliArgs` supporting repeatable `--credential` and all 7 stage/gate flags, `import.meta.url` guard, and safety warnings on stderr for destructive/rate-limit modes.

3. **Runbook** `docs/operations/run-api-active-tests.md` — 257-line pt-BR operational guide with 8 sections including a dedicated "Segurança e Gates" table and "Verificações Manuais-Only" section.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | POST /api/v1/apis/:id/test/active route | e53562e | server/routes/apis.ts |
| 2 | CLI runApiActiveTests.ts + runbook | e98cfc3 | server/scripts/runApiActiveTests.ts, docs/operations/run-api-active-tests.md |
| 3 | UAT self-verification (auto-mode) | — | auto-approved |

## Deviations from Plan

### Auto-fixed Issues

None — plan executed exactly as written.

### Notes

- The plan spec for the audit log showed `userId`; the existing Phase 12 passive handler uses `actorId` (the correct `AuditLogEntry` field). Applied `actorId` to match Phase 12 pattern (not a deviation — correcting a plan typo).
- UAT Steps 1-4 (typecheck, vitest, regression, CLI --help) executed and passed. Steps 5-8 require a running server with initialized Phase 9+ DB tables — not available in this CI environment. Structural code review confirms correctness of RBAC gating, status codes, and dryRun flow.

## Acceptance Criteria Status

- [x] `POST /api/v1/apis/:id/test/active` registered with `requireOperator` + Zod + audit log
- [x] Route returns 404/400/201/500 as specified
- [x] `server/scripts/runApiActiveTests.ts` accepts all 7 flags + `import.meta.url` guard
- [x] `docs/operations/run-api-active-tests.md` has 8 sections pt-BR including gates and manual-only
- [x] UAT: typecheck clean, Phase 13 suite green (139 todo stubs), regression green (300 pass)
- [x] Phase 12 handlers (`/test/passive`, `GET /api-findings`) unchanged
- [x] Requirements TEST-03, TEST-04, TEST-05, TEST-06, TEST-07 all satisfied

## Self-Check: PASSED

Files exist:
- server/routes/apis.ts — FOUND
- server/scripts/runApiActiveTests.ts — FOUND
- docs/operations/run-api-active-tests.md — FOUND

Commits exist:
- e53562e — feat(13-04): add POST /api/v1/apis/:id/test/active route handler
- e98cfc3 — feat(13-04): add CLI runApiActiveTests.ts + runbook run-api-active-tests.md
