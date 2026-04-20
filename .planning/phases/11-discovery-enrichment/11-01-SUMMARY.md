---
phase: 11-discovery-enrichment
plan: 01
subsystem: testing
tags: [vitest, zod, drizzle, postgres, api-discovery, httpx, katana, kiterunner, arjun, graphql, openapi]

# Dependency graph
requires:
  - phase: 10-api-credentials
    provides: apiCredentials table + resolveApiCredential helper consumed by Phase 11 scanners
  - phase: 09-schema-asset-hierarchy
    provides: apiEndpoints pgTable with discoverySources + requiresAuth + specHash columns

provides:
  - "13 Nyquist test stubs (12 under server/__tests__/apiDiscovery/, 1 under shared/__tests__/) covering DISC-01..06 + ENRH-01..03"
  - "8 fixture files under server/__tests__/apiDiscovery/fixtures/ (OpenAPI 2.0/3.0/3.1 + GraphQL introspection + katana/httpx/kiterunner/arjun samples)"
  - "discoverApiOptsSchema Zod schema + DiscoverApiOpts type exported from shared/schema.ts"
  - "5 nullable httpx_* columns on apiEndpoints (httpxStatus, httpxContentType, httpxTech, httpxTls, httpxLastProbedAt)"
  - "ensureApiEndpointHttpxColumns() idempotent guard in database-init.ts wired from initializeDatabaseStructure()"

affects: [11-02-PLAN, 11-03-PLAN, 11-04-PLAN, 11-05-PLAN, 11-06-PLAN, 11-07-PLAN]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Nyquist stub pattern: it.todo stubs with void 0 + commented imports to suppress TS6133, matching Phase 10 pattern"
    - "TDD RED-GREEN cycle: test file updated first (failing), then implementation added (passing)"
    - "Zod .superRefine() for cross-field validation with pt-BR error messages"
    - "ensureXxx() idempotent guard pattern: ALTER TABLE ... ADD COLUMN IF NOT EXISTS, error swallowed, log.error on failure"

key-files:
  created:
    - server/__tests__/apiDiscovery/specFetch.test.ts
    - server/__tests__/apiDiscovery/openapi.test.ts
    - server/__tests__/apiDiscovery/graphql.test.ts
    - server/__tests__/apiDiscovery/katana.test.ts
    - server/__tests__/apiDiscovery/kiterunner.test.ts
    - server/__tests__/apiDiscovery/specHash.test.ts
    - server/__tests__/apiDiscovery/drift.test.ts
    - server/__tests__/apiDiscovery/httpx.test.ts
    - server/__tests__/apiDiscovery/arjun.test.ts
    - server/__tests__/apiDiscovery/orchestrator.test.ts
    - server/__tests__/apiDiscovery/dedupeUpsert.test.ts
    - server/__tests__/apiDiscovery/route.test.ts
    - shared/__tests__/discoverApiOptsSchema.test.ts
    - server/__tests__/apiDiscovery/fixtures/openapi-2.0.json
    - server/__tests__/apiDiscovery/fixtures/openapi-3.0.json
    - server/__tests__/apiDiscovery/fixtures/openapi-3.1.json
    - server/__tests__/apiDiscovery/fixtures/graphql-introspection.json
    - server/__tests__/apiDiscovery/fixtures/katana-jsonl.txt
    - server/__tests__/apiDiscovery/fixtures/httpx-json.txt
    - server/__tests__/apiDiscovery/fixtures/kiterunner-json.txt
    - server/__tests__/apiDiscovery/fixtures/arjun-output.json
  modified:
    - shared/schema.ts
    - server/storage/database-init.ts

key-decisions:
  - "Fixtures count is 8 (not 7 as plan body text said): plan frontmatter + files section listed 8 explicitly (3 OpenAPI + 1 GraphQL + 4 tool outputs); all 8 created"
  - "discoverApiOptsSchema uses .strict() on both root and stages sub-object to reject unknown fields at each level"
  - "superRefine cross-field validation for arjunEndpointIds emits pt-BR message per CONTEXT.md conventions"
  - "httpx_* columns added as additive nullable columns on existing apiEndpoints table; no migration file needed; ensureApiEndpointHttpxColumns() guard at boot"

patterns-established:
  - "Phase 11 Nyquist stub shape: describe + it.todo per requirement, void 0 + commented imports"
  - "Cross-field Zod validation via superRefine with pt-BR error messages"

requirements-completed: [DISC-01, DISC-02, DISC-03, DISC-04, DISC-05, DISC-06, ENRH-01, ENRH-02, ENRH-03]

# Metrics
duration: 15min
completed: 2026-04-20
---

# Phase 11 Plan 01: Wave 0 Nyquist Scaffolding + Schema Primitives Summary

**13 Nyquist it.todo test stubs + 8 tool fixtures + discoverApiOptsSchema Zod schema (8 assertions green) + 5 nullable httpx_* columns on apiEndpoints with idempotent ALTER TABLE guard**

## Performance

- **Duration:** ~15 min
- **Started:** 2026-04-20T00:31:18Z
- **Completed:** 2026-04-20T00:40:00Z
- **Tasks:** 3
- **Files modified:** 23

## Accomplishments

- 13 test stubs discovered by vitest (85 it.todo across DISC-01..06 and ENRH-01..03); suite stays green
- 8 real Zod assertions in discoverApiOptsSchema.test.ts passing (TDD GREEN cycle completed)
- 5 additive nullable httpx_* columns on apiEndpoints; ensureApiEndpointHttpxColumns() guard wired in initializeDatabaseStructure()
- Full test suite: 495 passing (487 baseline + 8 new Zod tests), no TypeScript errors

## Task Commits

Each task was committed atomically:

1. **Task 1: Create 13 Nyquist test stub files + 7 fixtures** - `e14d2bd` (feat)
2. **Task 2: Add discoverApiOptsSchema Zod schema to shared/schema.ts** - `36825bb` (feat, TDD GREEN)
3. **Task 3: Add 5 httpx_* columns to apiEndpoints + ensureApiEndpointHttpxColumns guard** - `2228a96` (feat)

## Files Created/Modified

- `server/__tests__/apiDiscovery/` (12 test files) - Nyquist it.todo stubs for all DISC-01..06 and ENRH-01..03 requirements
- `shared/__tests__/discoverApiOptsSchema.test.ts` - 8 real Zod assertions (TDD)
- `server/__tests__/apiDiscovery/fixtures/` (8 fixture files) - OpenAPI 2.0/3.0/3.1, GraphQL introspection, katana/httpx/kiterunner/arjun tool output samples
- `shared/schema.ts` - discoverApiOptsSchema + DiscoverApiOpts type; 5 new httpx_* nullable columns on apiEndpoints
- `server/storage/database-init.ts` - ensureApiEndpointHttpxColumns() function + call in initializeDatabaseStructure()

## Decisions Made

- **Fixtures count 8 vs plan text "7"**: Plan `<files>` section explicitly listed 8 fixture files (3 OpenAPI + 1 GraphQL + 4 tool output files). The "7" in the action prose was a typo. All 8 listed files were created.
- **discoverApiOptsSchema placement**: Added at end of shared/schema.ts (after NormalizedFindingSchema) per plan — avoids disrupting existing type inference order.
- **httpx_* columns**: Added directly to apiEndpoints pgTable definition (additive); boot-time guard suffices for dev; no drizzle migration file needed.

## Deviations from Plan

None - plan executed exactly as written (the "7 fixtures" vs "8 files" inconsistency in plan prose was resolved in favor of the explicit file list).

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All it.todo stubs in place; Plans 11-02..11-07 can replace them with real implementations
- discoverApiOptsSchema and DiscoverApiOpts type available for orchestrator imports
- httpx_* columns ready on apiEndpoints (guard ensures columns exist at boot)
- Fixture files provide realistic test data for parsers in Plans 11-03..11-06

---
*Phase: 11-discovery-enrichment*
*Completed: 2026-04-20*
