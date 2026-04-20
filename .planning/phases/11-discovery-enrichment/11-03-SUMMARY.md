---
phase: 11-discovery-enrichment
plan: 03
subsystem: api-discovery
tags: [openapi, graphql, swagger-parser, ssrf, tdd, vitest, spec-first]

# Dependency graph
requires:
  - phase: 11-01
    provides: Nyquist stubs (specFetch.test.ts, openapi.test.ts, graphql.test.ts) + OpenAPI/GraphQL fixture files
  - phase: 11-02
    provides: computeCanonicalHash from specHash.ts consumed by fetchAndParseSpec

provides:
  - "fetchAndParseSpec(baseUrl, authHeader?, signal) — iterates KNOWN_SPEC_PATHS, returns { spec, specUrl, specHash, specVersion } or null"
  - "specToEndpoints(spec, apiId) — maps dereferenced OpenAPI doc → InsertApiEndpoint[] with pathParams/queryParams/headerParams split"
  - "probeGraphQL(baseUrl, authHeader?, signal) — POSTs INTROSPECTION_QUERY to GRAPHQL_PATHS, returns { schema, endpointPath } or null"
  - "schemaToEndpoints(schema, apiId, endpointPath) — maps GraphQL schema → InsertApiEndpoint[] one row per query/mutation/subscription field"
  - "@apidevtools/swagger-parser@^12.1.0 installed (CVE-safe vs v11 SSRF)"
  - "20 real tests GREEN: 7 specFetch + 7 openapi + 6 graphql"

affects: [11-06-PLAN]

# Tech tracking
tech-stack:
  added:
    - "@apidevtools/swagger-parser@^12.1.0 (prod dep)"
    - "openapi-types@^12.1.3 (devDep)"
  patterns:
    - "TDD RED-GREEN cycle: test files written first (failing import), implementation added (all passing)"
    - "Same-origin $ref SSRF defense: custom resolve.http.read validates new URL(file.url).origin === specOrigin before fetch"
    - "vi.stubGlobal('fetch', vi.fn()) pattern for HTTP-dependent unit tests without network"
    - "Hard-coded INTROSPECTION_QUERY avoids graphql-js dep (~700KB savings)"

key-files:
  created:
    - server/services/scanners/api/openapi.ts
    - server/services/scanners/api/graphql.ts
  modified:
    - server/__tests__/apiDiscovery/specFetch.test.ts
    - server/__tests__/apiDiscovery/openapi.test.ts
    - server/__tests__/apiDiscovery/graphql.test.ts
    - package.json
    - package-lock.json

key-decisions:
  - "swagger-parser ^12.1.0 pinned (v11 had CVE-class SSRF via unguarded HTTP $ref resolution)"
  - "specToEndpoints accepts `unknown` (not typed OpenAPI.Document) to handle 2.0/3.0/3.1 without discriminated union complexity"
  - "Same-origin $ref check uses URL.origin comparison (includes scheme+host+port) — correct SSRF boundary"
  - "INTROSPECTION_QUERY hardcoded string literal (not graphql-js getIntrospectionQuery()) per CONTEXT.md decision to avoid dep"
  - "schemaToEndpoints: requestSchema stores { operationName, operationType, variables } per CONTEXT.md §GraphQL introspection"

# Metrics
duration: 4min
completed: 2026-04-20
---

# Phase 11 Plan 03: OpenAPI + GraphQL Scanner Modules Summary

**fetchAndParseSpec (SSRF-safe OpenAPI probe) + specToEndpoints (DISC-01/02) + probeGraphQL (GraphQL introspection) + schemaToEndpoints (DISC-03); swagger-parser ^12.1.0 installed; 20 tests GREEN**

## Performance

- **Duration:** ~4 min
- **Started:** 2026-04-20T00:49:53Z
- **Completed:** 2026-04-20T00:53:50Z
- **Tasks:** 2
- **Files modified:** 7

## Accomplishments

- `server/services/scanners/api/openapi.ts` (~140 lines): `fetchAndParseSpec` iterates 7 KNOWN_SPEC_PATHS with first-JSON-wins, custom same-origin `$ref` resolver blocks cross-origin SSRF, `computeCanonicalHash` integrated; `specToEndpoints` maps paths[p][method] → InsertApiEndpoint[] with param splitting
- `server/services/scanners/api/graphql.ts` (~140 lines): `probeGraphQL` POSTs INTROSPECTION_QUERY to 3 GRAPHQL_PATHS, short-circuits on `data.__schema`; `schemaToEndpoints` emits one row per query/mutation/subscription field with `requestSchema.{operationName, operationType, variables}`
- `@apidevtools/swagger-parser@^12.1.0` added to dependencies (CVE-safe); `openapi-types@^12.1.3` added to devDependencies
- 14 real tests in specFetch.test.ts + openapi.test.ts (replacing it.todo stubs) — all GREEN
- 6 real tests in graphql.test.ts (replacing it.todo stubs) — all GREEN
- Full suite: 531 tests passing (up from 511 baseline), no regressions

## Task Commits

1. **Task 1: swagger-parser install + openapi.ts + 14 tests** — `1940ce4` (feat)
2. **Task 2: graphql.ts + 6 tests** — `f5ecec8` (feat)

## Decisions Made

- `@apidevtools/swagger-parser@^12.1.0` pinned — v11 had unguarded HTTP $ref fetch (SSRF vector per RESEARCH.md)
- `specToEndpoints` parameter typed as `unknown` (not `OpenAPI.Document`) — avoids discriminated union complexity across 2.0/3.0/3.1; runtime checks applied
- INTROSPECTION_QUERY is a hardcoded string literal per CONTEXT.md decision (avoids graphql-js ~700KB dep)
- Same-origin check uses `URL.origin` (scheme+host+port) — precise SSRF boundary
- Tests use `vi.stubGlobal('fetch', vi.fn())` pattern matching existing project test conventions

## Deviations from Plan

None — plan executed exactly as written. Implementation matches the code template in the plan action sections.

## Issues Encountered

None.

## User Setup Required

None.

## Next Phase Readiness

- Plan 11-06 (orchestrator) can `import { fetchAndParseSpec, specToEndpoints } from './scanners/api/openapi'` and `import { probeGraphQL, schemaToEndpoints } from './scanners/api/graphql'`
- DISC-01, DISC-02, DISC-03 requirements now implementable via orchestrator calls
- Parallel plans 11-04 (katana) and 11-05 (httpx/kiterunner/arjun) unaffected — different files

## Self-Check: PASSED

- server/services/scanners/api/openapi.ts — FOUND
- server/services/scanners/api/graphql.ts — FOUND
- Commit 1940ce4 (Task 1) — FOUND
- Commit f5ecec8 (Task 2) — FOUND

---
*Phase: 11-discovery-enrichment*
*Completed: 2026-04-20*
