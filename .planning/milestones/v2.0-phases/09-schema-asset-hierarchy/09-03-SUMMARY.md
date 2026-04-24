---
phase: 09-schema-asset-hierarchy
plan: "03"
subsystem: storage
tags: [storage, facade, drizzle, database-init, idempotent, api-discovery, phase9]
dependency_graph:
  requires:
    - 09-02 (apis/apiEndpoints/apiFindings pgTables + type exports from shared/schema.ts)
  provides:
    - server/storage/apis.ts (getApi, listApis, listApisByParent, createApi, promoteApiFromBackfill)
    - server/storage/apiEndpoints.ts (listEndpointsByApi, createApiEndpoint, upsertApiEndpoint)
    - server/storage/apiFindings.ts (listFindingsByEndpoint, createApiFinding)
    - IStorage interface: 10 new method signatures (interface.ts)
    - DatabaseStorage class: 10 new method wires (index.ts)
    - ensureApiTables() in database-init.ts (3 enums + 3 tables + 9 indexes, idempotent)
  affects:
    - 09-04 (consumes storage.createApi, storage.promoteApiFromBackfill, storage.getAsset)
    - Phase 11 (consumes upsertApiEndpoint for discovery merge)
    - Phase 14 FIND-03 (consumes createApiFinding + promotedThreatId FK already declared)
tech_stack:
  added: []
  patterns:
    - Facade module per table (mirrors assets.ts / edrDeployments.ts convention)
    - Namespace import pattern: import * as apiOps from "./apis" wired as class members
    - onConflictDoNothing on UNIQUE (parentAssetId, baseUrl) for idempotent backfill
    - onConflictDoUpdate with SQL array_cat + unnest/DISTINCT for discoverySources merge
    - ensureApiTables() follows edr_deployments rowCount ?? 0 check-then-create pattern
    - sql.raw() for dynamic index names in loop (identifiers cannot be parameterized)
    - Quoted identifiers in both pg_indexes lookups AND CREATE statements (Pitfall 1)
key_files:
  created:
    - server/storage/apis.ts
    - server/storage/apiEndpoints.ts
    - server/storage/apiFindings.ts
  modified:
    - server/storage/interface.ts (6 type imports + 10 method signatures added)
    - server/storage/index.ts (3 namespace imports + 10 class member wires added)
    - server/storage/database-init.ts (ensureApiTables() function + await call in initializeDatabaseStructure)
decisions:
  - "sql.raw() used for api_findings index loop — identifiers cannot be SQL parameters, must be string interpolated"
  - "ensureApiTables() placed after edr_deployments block in initializeDatabaseStructure to maintain additive ordering"
  - "Error swallowed in ensureApiTables catch (log.error only) — matches existing edr_deployments pattern, keeps app booting"
metrics:
  duration_seconds: 269
  completed_date: "2026-04-18"
  tasks_completed: 3
  files_created: 3
  files_modified: 3
---

# Phase 9 Plan 03: Storage Layer for API Discovery Tables — Summary

**One-liner:** 3 storage facade modules (apis/apiEndpoints/apiFindings) + IStorage extension (10 signatures) + DatabaseStorage wiring (10 members) + idempotent ensureApiTables() guard creating 3 enums, 3 tables, and 9 indexes; `storage.createApi` callable from Plan 04.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Create 3 storage facade files | 971ce2b | server/storage/apis.ts, apiEndpoints.ts, apiFindings.ts |
| 2 | Extend IStorage interface + wire DatabaseStorage | 55792c2 | server/storage/interface.ts, index.ts |
| 3 | Add ensureApiTables() guard + call site | 3a090ee | server/storage/database-init.ts |

## Files Created

### server/storage/apis.ts

Exports:
- `getApi(id: string): Promise<Api | undefined>`
- `listApis(): Promise<Api[]>`
- `listApisByParent(parentAssetId: string): Promise<Api[]>`
- `createApi(data: InsertApi, userId: string): Promise<Api>` — forces `createdBy = userId`
- `promoteApiFromBackfill(parentAssetId, baseUrl, apiType, opts): Promise<Api | null>` — `onConflictDoNothing` on UNIQUE(parentAssetId, baseUrl), returns null on conflict

### server/storage/apiEndpoints.ts

Exports:
- `listEndpointsByApi(apiId: string): Promise<ApiEndpoint[]>`
- `createApiEndpoint(data: InsertApiEndpoint): Promise<ApiEndpoint>`
- `upsertApiEndpoint(data: InsertApiEndpoint): Promise<ApiEndpoint>` — `onConflictDoUpdate` on (apiId, method, path) with SQL `ARRAY(SELECT DISTINCT unnest(...))` merge for discoverySources

### server/storage/apiFindings.ts

Exports:
- `listFindingsByEndpoint(endpointId: string): Promise<ApiFinding[]>`
- `createApiFinding(data: InsertApiFinding): Promise<ApiFinding>` — logs identifiers only (no evidence blob)

## IStorage Signatures Added (interface.ts lines ~265-286)

```typescript
// API operations — Phase 9 HIER-01, HIER-02, HIER-03, HIER-04, FIND-01
getApi(id: string): Promise<Api | undefined>;
listApis(): Promise<Api[]>;
listApisByParent(parentAssetId: string): Promise<Api[]>;
createApi(data: InsertApi, userId: string): Promise<Api>;
promoteApiFromBackfill(
  parentAssetId: string,
  baseUrl: string,
  apiType: 'rest' | 'graphql' | 'soap',
  opts: { specUrl?: string; systemUserId: string },
): Promise<Api | null>;
listEndpointsByApi(apiId: string): Promise<ApiEndpoint[]>;
createApiEndpoint(data: InsertApiEndpoint): Promise<ApiEndpoint>;
upsertApiEndpoint(data: InsertApiEndpoint): Promise<ApiEndpoint>;
listFindingsByEndpoint(endpointId: string): Promise<ApiFinding[]>;
createApiFinding(data: InsertApiFinding): Promise<ApiFinding>;
```

## DatabaseStorage Wires Added (index.ts)

```typescript
// API operations — Phase 9 HIER-01, HIER-02, HIER-03, HIER-04, FIND-01
getApi = apiOps.getApi;
listApis = apiOps.listApis;
listApisByParent = apiOps.listApisByParent;
createApi = apiOps.createApi;
promoteApiFromBackfill = apiOps.promoteApiFromBackfill;
listEndpointsByApi = apiEndpointOps.listEndpointsByApi;
createApiEndpoint = apiEndpointOps.createApiEndpoint;
upsertApiEndpoint = apiEndpointOps.upsertApiEndpoint;
listFindingsByEndpoint = apiFindingOps.listFindingsByEndpoint;
createApiFinding = apiFindingOps.createApiFinding;
```

## ensureApiTables() Location

- **Function declared at:** database-init.ts line 151 (exported, before ensureSystemUserExists)
- **Called from:** database-init.ts line 139 (inside `initializeDatabaseStructure` try block)
- **Call order in initializeDatabaseStructure:**
  1. Line 14: `await ensureSystemUserExists()` — system user required as FK for apis.createdBy
  2. Lines 107-135: edr_deployments check-and-create block
  3. Line 139: `await ensureApiTables()` — Phase 9 API tables

## Cold Start Idempotency Path

On a fresh database with no `db:push` run:
1. App boots → `initializeDatabaseStructure()` runs
2. `ensureApiTables()` checks pg_type for 3 enums → creates each (api_type_enum, owasp_api_category, api_finding_status)
3. Checks pg_tables for `apis` → creates table with FKs and constraints
4. Checks pg_indexes for UQ_apis_parent_base_url → creates unique index
5. Checks pg_indexes for IDX_apis_parent_asset_id → creates index
6. Creates api_endpoints table + 2 indexes (UQ + IDX)
7. Creates api_findings table + 5 indexes (endpoint_id, job_id, owasp_category, severity, status)
8. Logs "ensureApiTables complete"

On second run (objects exist): all pg_type/pg_tables/pg_indexes checks return rowCount > 0, all creation steps are skipped, logs only status messages. No DDL mutations.

## Contract Exported for Plan 04

- `storage.createApi(data, userId)` — manual API registration (HIER-03)
- `storage.promoteApiFromBackfill(parentAssetId, baseUrl, apiType, opts)` — backfill dedup (HIER-04)
- `storage.getAsset(id)` — pre-existing, validates parent type = 'web_application'
- `storage.listApisByParent(parentAssetId)` — list APIs under an asset
- `storage.createApiEndpoint(data)` / `storage.upsertApiEndpoint(data)` — endpoint creation/merge

## Test State

- `server/__tests__/ensureApiTables.test.ts`: 9 it.todo stubs — compiles, todos pending (Plan 01 created stubs, flip to real tests in a future session)
- `server/__tests__/apiStorage.test.ts`: pending stubs — same status

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check: PASSED

- server/storage/apis.ts: FOUND
- server/storage/apiEndpoints.ts: FOUND
- server/storage/apiFindings.ts: FOUND
- server/storage/interface.ts: FOUND (modified)
- server/storage/index.ts: FOUND (modified)
- server/storage/database-init.ts: FOUND (modified)
- Commit 971ce2b (Task 1 — 3 facade files): FOUND
- Commit 55792c2 (Task 2 — IStorage + DatabaseStorage): FOUND
- Commit 3a090ee (Task 3 — ensureApiTables): FOUND
