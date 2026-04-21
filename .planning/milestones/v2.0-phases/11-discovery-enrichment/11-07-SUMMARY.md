---
phase: 11-discovery-enrichment
plan: "07"
subsystem: api
tags: [rest-route, cli, rbac, zod, audit-log, operator-tooling, human-uat]

# Dependency graph
requires:
  - phase: 11-discovery-enrichment (plans 01-06)
    provides: discoverApi() orchestrator, DiscoveryResult contract, all 6 scanners, storage facades, preflight helpers
  - phase: 10-api-credentials
    provides: resolveApiCredential, getApiCredentialWithSecret, requireOperator middleware
  - phase: 09-schema-asset-hierarchy
    provides: apis/api_endpoints tables, POST /api/v1/apis route, isAuthenticatedWithPasswordCheck, registerApiRoutes barrel
provides:
  - "POST /api/v1/apis/:id/discover — RBAC (operator+global_administrator) + Zod discoverApiOptsSchema + audit log + 202 Accepted with { jobId, result: DiscoveryResult }"
  - "server/scripts/runApiDiscovery.ts — CLI operator tool with parseArgs/argsToOpts named exports + import.meta.url guard"
  - "docs/operations/run-api-discovery.md — operator runbook with Usage/HTTP Route/Output/Troubleshooting sections (120+ lines)"
  - "8 route tests GREEN covering all RBAC+Zod+success+error paths"
  - "Human UAT passed — 6 smoke tests on real target verified end-to-end"
affects:
  - phase-15 (journey wiring consumes POST /api/v1/apis/:id/discover + discoverApi() function)
  - phase-16 (UI discovery wizard calls the route; wizard exposes CLI flags as toggles)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Discovery route appended inside registerApiRoutes(app) in server/routes/apis.ts — single barrel, no new route file"
    - "Synthetic jobId via crypto.randomUUID() — Phase 15 replaces with real queue enqueue"
    - "storage.logAudit() after discoverApi() success — consistent with Phase 9/10 audit pattern"
    - "CLI parseArgs/argsToOpts as named exports + import.meta.url guard — mirrors backfillApiDiscovery.ts template"
    - "Route test mocks: 5 vi.hoisted mocks (storage + localAuth + db + subscriptionService + logger) — Phase 10-05 pattern"

key-files:
  created:
    - server/scripts/runApiDiscovery.ts
    - docs/operations/run-api-discovery.md
    - server/__tests__/apiDiscovery/route.test.ts
  modified:
    - server/routes/apis.ts

key-decisions:
  - "POST /api/v1/apis/:id/discover appended to existing registerApiRoutes(app) in apis.ts (not new route file) — consistent with Phase 9 barrel pattern"
  - "Synthetic jobId via crypto.randomUUID() for Phase 11; Phase 15 will replace with real queue.enqueue() — explicitly documented in route JSDoc"
  - "Human UAT smoke tests passed on operator-selected real target — all 6 smoke tests (CLI dry-run, DB materialization, dedupe/drift re-run, HTTP 202, RBAC 403, Zod 400) confirmed green"
  - "No secrets appeared in logs — pino redaction covers all credential fields; route logs only apiId/userId/jobId/stages/counts"

patterns-established:
  - "Route test pattern (5 mocks): storage + localAuth + db + subscriptionService + logger — any future Phase 11+ route test should use this exact pattern"
  - "CLI pattern: parseArgs/argsToOpts named exports + import.meta.url guard enables unit-test import without triggering main() — mirrors backfillApiDiscovery.ts"
  - "discoverApi() called from both HTTP route and CLI — single source of truth; route adds RBAC/Zod/audit wrapper around the same journey function"

requirements-completed: [DISC-01, DISC-02, DISC-03, DISC-04, DISC-05, DISC-06, ENRH-01, ENRH-02, ENRH-03]

# Metrics
duration: continuation (Task 3 checkpoint resolved by human UAT approval)
completed: 2026-04-20
---

# Phase 11 Plan 07: Discovery & Enrichment Public Surfaces Summary

**POST /api/v1/apis/:id/discover HTTP route + runApiDiscovery.ts CLI + operator runbook shipped, 8 route tests green, and all 9 Phase 11 requirements (DISC-01..06, ENRH-01..03) confirmed end-to-end via human UAT smoke test on a real target**

## Performance

- **Duration:** continuation agent (Task 3 checkpoint resolved after human UAT approval)
- **Started:** previous agent (Tasks 1-2); continuation at 2026-04-20T01:21:26Z
- **Completed:** 2026-04-20T01:21:26Z
- **Tasks:** 3/3
- **Files modified:** 4 (server/routes/apis.ts, server/scripts/runApiDiscovery.ts, docs/operations/run-api-discovery.md, server/__tests__/apiDiscovery/route.test.ts)

## Accomplishments

- POST /api/v1/apis/:id/discover route with isAuthenticatedWithPasswordCheck + requireOperator RBAC, discoverApiOptsSchema Zod validation, 5 pt-BR error messages, synthetic jobId, storage.logAudit() on success, and 202 Accepted with { jobId, result: DiscoveryResult } response
- server/scripts/runApiDiscovery.ts CLI with parseArgs/argsToOpts named exports, all documented flags (--api, --no-spec, --no-crawler, --kiterunner, --no-httpx, --arjun-endpoint, --credential, --dry-run, --katana-depth, --katana-headless, --kiterunner-rate), and import.meta.url guard
- docs/operations/run-api-discovery.md operator runbook (120+ lines) covering Usage, HTTP Route, Output interpretation, and Troubleshooting
- 8 route tests GREEN using the Phase 10-05 5-mock pattern (storage + localAuth + db + subscriptionService + logger)
- Human UAT: all 6 smoke tests passed — CLI dry-run, DB endpoint materialization, dedupe/drift re-run, HTTP 202 route, RBAC 403, Zod 400 validation; no secrets appeared in logs
- Phase 11 complete — all 9 requirements (DISC-01..06, ENRH-01..03) satisfied end-to-end

## Task Commits

Each task was committed atomically:

1. **Task 1: POST /api/v1/apis/:id/discover route + 8 route tests GREEN** - `332ca67` (feat)
2. **Task 2: CLI runApiDiscovery.ts + operator runbook** - `d2aa9b3` (feat)
3. **Task 3: End-to-end smoke verification** - human-verify checkpoint; operator ran all 6 smoke tests and confirmed approved

**Plan metadata:** (docs commit follows — this SUMMARY.md)

_Note: Task 1 was TDD — tests written before implementation, then implementation to green._

## Files Created/Modified

- `server/routes/apis.ts` — POST /api/v1/apis/:id/discover handler appended inside registerApiRoutes(app)
- `server/__tests__/apiDiscovery/route.test.ts` — 8 real route tests (converted from it.todo stubs)
- `server/scripts/runApiDiscovery.ts` — CLI operator tool (parseArgs + argsToOpts + main + import.meta.url guard)
- `docs/operations/run-api-discovery.md` — operator runbook (Usage / HTTP Route / Output interpretation / Troubleshooting)

## Decisions Made

- POST /api/v1/apis/:id/discover appended to existing `registerApiRoutes(app)` in `server/routes/apis.ts`, not in a new route file — keeps the barrel pattern consistent with Phase 9's POST /api/v1/apis handler in the same module.
- Synthetic `jobId = crypto.randomUUID()` for Phase 11; a JSDoc comment explicitly marks this as the Phase 15 replacement point (`jobQueue.enqueue`). This is intentional — Phase 11 delivers the route surface; Phase 15 wires the real queue.
- Human UAT confirmed on operator's real target — all 6 smoke tests green. No SSRF or secret-leakage issues observed.

## Deviations from Plan

None — plan executed exactly as written. Task 3 was a `checkpoint:human-verify` gate resolved by the operator approving all 6 smoke tests.

## Issues Encountered

None. The checkpoint gate resolved cleanly with the operator's "approved" signal after running all 6 smoke tests.

## User Setup Required

None — no external service configuration required. The route uses existing session auth + storage facades.

## Next Phase Readiness

- Phase 11 is fully complete (all 7 plans, all 9 requirements DISC-01..06 + ENRH-01..03 satisfied)
- Phase 12 (Security Testing — Passive) can begin: `discoverApi()` + `POST /api/v1/apis/:id/discover` are stable public surfaces
- Phase 15 (Journey Orchestration) can consume `discoverApi()` directly and replace the synthetic `jobId` with real queue.enqueue()
- Phase 16 (UI) can call POST /api/v1/apis/:id/discover from the wizard and display the DiscoveryResult

## Self-Check: PASSED

- FOUND: server/routes/apis.ts
- FOUND: server/scripts/runApiDiscovery.ts
- FOUND: docs/operations/run-api-discovery.md
- FOUND: server/__tests__/apiDiscovery/route.test.ts
- FOUND commit: 332ca67 (feat(11-07): add POST /api/v1/apis/:id/discover route + 8 route tests GREEN)
- FOUND commit: d2aa9b3 (feat(11-07): add runApiDiscovery.ts CLI + operator runbook)

---
*Phase: 11-discovery-enrichment*
*Completed: 2026-04-20*
