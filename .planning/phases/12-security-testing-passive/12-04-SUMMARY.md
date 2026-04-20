---
phase: 12-security-testing-passive
plan: "04"
subsystem: api-security
tags: [routes, cli, runbook, passive-testing, rbac]
dependency_graph:
  requires:
    - "12-security-testing-passive/12-01 (schema + stubs)"
    - "12-security-testing-passive/12-02 (scanners)"
    - "12-security-testing-passive/12-03 (orchestrator + storage)"
  provides:
    - "POST /api/v1/apis/:id/test/passive (RBAC operator)"
    - "GET /api/v1/api-findings (RBAC any including readonly_analyst)"
    - "CLI server/scripts/runApiPassiveTests.ts"
    - "Runbook docs/operations/run-api-passive-tests.md"
  affects:
    - "server/routes/apis.ts (appended handler)"
    - "server/routes/index.ts (barrel wiring)"
    - "server/routes/middleware.ts (requireAnyRole added)"
tech_stack:
  added: []
  patterns:
    - "Express route handler with Zod validation + RBAC (mirrors Phase 11 /discover pattern)"
    - "requireAnyRole middleware (new — allows operator/admin/readonly_analyst)"
    - "CLI tsx-safe script with import.meta.url guard (mirrors runApiDiscovery.ts)"
key_files:
  created:
    - server/routes/apiFindings.ts
    - server/scripts/runApiPassiveTests.ts
    - docs/operations/run-api-passive-tests.md
  modified:
    - server/routes/apis.ts
    - server/routes/index.ts
    - server/routes/middleware.ts
    - server/__tests__/apiPassive/route.test.ts
decisions:
  - "requireAnyRole added to middleware.ts (Rule 2 — missing critical middleware for readonly_analyst read path)"
  - "POST /test/passive uses actorId (not userId) in logAudit — matches Phase 11 pattern"
  - "import 'dotenv/config' removed from CLI — dotenv not in project; runApiDiscovery pattern uses pathToFileURL guard only"
  - "audit log uses action: 'api_passive_test_started' + objectType: 'api' + objectId: apiId — consistent with Phase 11 audit shape"
metrics:
  duration_minutes: 9
  completed_date: "2026-04-20"
  tasks_completed: 4
  files_changed: 7
requirements:
  - TEST-01
  - TEST-02
---

# Phase 12 Plan 04: Public Surfaces (Routes + CLI + Runbook) Summary

**One-liner:** POST /test/passive + GET /api-findings routes with RBAC, CLI operator tool with 5 toggle flags, and pt-BR runbook — closing Phase 12 Wave 3.

## Tasks Completed

| Task | Description | Commit | Files |
|------|-------------|--------|-------|
| 1 | POST /api/v1/apis/:id/test/passive route | 259e186 | server/routes/apis.ts, middleware.ts |
| 2 | GET /api/v1/api-findings route + barrel | 259e186 | server/routes/apiFindings.ts, index.ts |
| 3 | CLI runApiPassiveTests.ts | f093604 | server/scripts/runApiPassiveTests.ts |
| 4 | Runbook run-api-passive-tests.md | 3628a36 | docs/operations/run-api-passive-tests.md |
| 5 | UAT checkpoint | APPROVED | — |

## Key Decisions

1. **requireAnyRole added to middleware.ts** — missing critical middleware for the GET /api-findings endpoint that requires readonly_analyst access. Added `requireAnyRole` that allows operator, global_administrator, and readonly_analyst.

2. **actorId vs userId in logAudit** — plan template showed `userId: req.user.id` but actual AuditLogEntry interface uses `actorId`. Used `actorId` (consistent with Phase 11 audit pattern in apis.ts lines 60-67).

3. **dotenv removed from CLI** — plan showed `import 'dotenv/config'` but dotenv is not in the project's package.json and runApiDiscovery.ts doesn't use it. Removed to match project pattern.

4. **import.meta.url via pathToFileURL** — CLI uses `pathToFileURL(process.argv[1]).href` instead of bare `file://${process.argv[1]}` template string, matching runApiDiscovery.ts pattern for cross-platform correctness.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical Functionality] requireAnyRole middleware not in codebase**
- **Found during:** Task 2 implementation
- **Issue:** `requireAnyRole` referenced in plan and apiFindings.ts template didn't exist in server/routes/middleware.ts
- **Fix:** Added `requireAnyRole` to middleware.ts — allows global_administrator, operator, and readonly_analyst roles
- **Files modified:** server/routes/middleware.ts
- **Commit:** 259e186

**2. [Rule 1 - Bug] Wrong logAudit field name in plan template**
- **Found during:** Task 1 implementation
- **Issue:** Plan template used `userId: req.user.id` but AuditLogEntry interface requires `actorId`
- **Fix:** Used `actorId` matching Phase 11 discover route pattern
- **Files modified:** server/routes/apis.ts
- **Commit:** 259e186

**3. [Rule 1 - Bug] dotenv import in CLI**
- **Found during:** Task 3 verification
- **Issue:** Plan showed `import 'dotenv/config'` but dotenv is not in project dependencies
- **Fix:** Removed the import; CLI uses tsx --env-file=.env flag at invocation (same as runApiDiscovery)
- **Files modified:** server/scripts/runApiPassiveTests.ts
- **Commit:** f093604

## Verification Results

- TypeScript: clean (no Phase 12 errors; pre-existing errors in threats.ts are out of scope)
- Phase 12 test suite: 69 passed, 16 todo, 0 failures (10 files)
- Regression Phases 9/10/11: 231 passed, 0 failures (20 files)
- CLI: loads correctly with DATABASE_URL; --help requires DB (same behavior as runApiDiscovery.ts)

## Self-Check

Checking created files exist:

- [x] server/routes/apiFindings.ts — exists (104 lines)
- [x] server/scripts/runApiPassiveTests.ts — exists (109 lines)
- [x] docs/operations/run-api-passive-tests.md — exists (187 lines)
- [x] server/routes/apis.ts modified with POST /test/passive
- [x] server/routes/index.ts wired with registerApiFindingsRoutes

Checking commits exist:
- [x] 259e186 — feat(12-04): POST /test/passive + GET /api-findings routes
- [x] f093604 — feat(12-04): CLI server/scripts/runApiPassiveTests.ts
- [x] 3628a36 — docs(12-04): runbook run-api-passive-tests.md pt-BR

## UAT Result

**Status:** APPROVED by user on 2026-04-20.
Phase 12 cycle closed. All 5 tasks complete.

## Self-Check: PASSED
