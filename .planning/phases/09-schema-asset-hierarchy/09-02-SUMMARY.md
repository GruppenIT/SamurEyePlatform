---
phase: 09-schema-asset-hierarchy
plan: "02"
subsystem: shared/schema.ts
tags: [schema, drizzle, postgres, enums, zod, phase9, api-discovery]
dependency_graph:
  requires:
    - 09-01 (shared/owaspApiCategories.ts, shared/__tests__/evidenceSchema.test.ts)
  provides:
    - apis pgTable (HIER-01, HIER-03)
    - apiEndpoints pgTable (HIER-02)
    - apiFindings pgTable (FIND-01)
    - apiTypeEnum, owaspApiCategoryEnum, apiFindingStatusEnum pgEnums
    - apiFindingEvidenceSchema Zod schema
    - insertApiSchema, insertApiEndpointSchema, insertApiFindingSchema
    - ApiFindingEvidence interface, ApiFindingEvidenceInput type
  affects:
    - 09-03 (imports ensureApiTables targets from these table exports)
    - 09-04 (imports insertApiSchema for route, apis/apiEndpoints/apiFindings for backfill)
    - Phase 14 FIND-03 (promotedThreatId column already declared)
tech_stack:
  added:
    - check constraint (drizzle-orm/pg-core `check` import added)
  patterns:
    - pgEnum with _2023 suffix pin for OWASP version freeze
    - tri-valor nullable boolean (requiresAuth: NULL/true/false)
    - JSONB typed with Zod evidence schema (.strict() rejects unknown keys)
    - createInsertSchema(table, {fieldOverride}).omit({...}).extend({...}) composition
key_files:
  modified:
    - shared/schema.ts (3 enums + 3 tables + 1 Zod schema + 3 insertSchemas + 1 interface)
    - vitest.config.ts (added shared/**/*.test.ts to include glob)
    - .planning/phases/09-schema-asset-hierarchy/09-VALIDATION.md (task map updated)
decisions:
  - "threatSeverityEnum reused in apiFindings.severity — zero new severity enum (plan requirement)"
  - "check import added to pg-core imports (was missing; needed for CK_api_endpoints_method)"
  - "vitest.config.ts include extended to shared/**/*.test.ts (Rule 3 auto-fix — blocked test run)"
  - "ApiFindingEvidence declared as TypeScript interface + Zod schema both; interface for DB type, schema for runtime validation"
metrics:
  duration: "~5 minutes"
  completed: "2026-04-18"
  tasks_completed: 2
  files_modified: 3
---

# Phase 9 Plan 02: API Schema Additions to shared/schema.ts — Summary

**One-liner:** 3 pgEnums (api_type_enum, owasp_api_category, api_finding_status) + 3 pgTables (apis, api_endpoints, api_findings) + strict Zod evidence schema + 3 insertSchemas added to shared/schema.ts; evidenceSchema.test.ts 6/6 GREEN.

## What Was Built

### Enums Added (shared/schema.ts lines ~83-109)

| Enum | DB name | Values |
|------|---------|--------|
| `apiTypeEnum` | `api_type_enum` | `rest`, `graphql`, `soap` |
| `owaspApiCategoryEnum` | `owasp_api_category` | 10 `_2023`-suffixed OWASP Top 10 values |
| `apiFindingStatusEnum` | `api_finding_status` | `open`, `triaged`, `false_positive`, `closed` |

OWASP values: `api1_bola_2023`, `api2_broken_auth_2023`, `api3_bopla_2023`, `api4_rate_limit_2023`, `api5_bfla_2023`, `api6_business_flow_2023`, `api7_ssrf_2023`, `api8_misconfiguration_2023`, `api9_inventory_2023`, `api10_unsafe_consumption_2023`.

All 10 keys match `shared/owaspApiCategories.ts OWASP_API_CATEGORY_LABELS` keys (1:1).

### Tables Added (shared/schema.ts lines ~1213-1328)

**`apis` table** (HIER-01, HIER-03):
- `id` varchar PK, `parentAssetId` FK→assets.id CASCADE NOTULL, `baseUrl` text NOTULL
- `apiType` apiTypeEnum NOTULL, nullable: name/description/specUrl/specHash/specVersion/specLastFetchedAt
- `createdAt`/`updatedAt` defaultNow NOTULL, `createdBy` FK→users.id NOTULL
- `uniqueIndex("UQ_apis_parent_base_url")` on (parentAssetId, baseUrl)
- `index("IDX_apis_parent_asset_id")` on parentAssetId

**`apiEndpoints` table** (HIER-02):
- `id` varchar PK, `apiId` FK→apis.id CASCADE NOTULL, `method` text NOTULL, `path` text NOTULL
- `pathParams/queryParams/headerParams` jsonb typed arrays default [] NOTULL
- `requestSchema/responseSchema` jsonb nullable (Phase 11 populates)
- `requiresAuth` boolean NULLABLE (tri-valor: NULL/true/false)
- `discoverySources` text[] default ARRAY[]::text[] NOTULL
- `createdAt/updatedAt` defaultNow NOTULL
- `check("CK_api_endpoints_method", method IN ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'))`
- `uniqueIndex("UQ_api_endpoints_api_method_path")` on (apiId, method, path)
- `index("IDX_api_endpoints_api_id")` on apiId

**`apiFindings` table** (FIND-01):
- `id` varchar PK, `apiEndpointId` FK→api_endpoints.id CASCADE NOTULL
- `jobId` FK→jobs.id NULLABLE, `owaspCategory` owaspApiCategoryEnum NOTULL
- `severity` **threatSeverityEnum** NOTULL (existing enum reused), `status` apiFindingStatusEnum default 'open' NOTULL
- `title` text NOTULL, `description/remediation` nullable
- `riskScore` real NULLABLE, `evidence` jsonb typed ApiFindingEvidence default `'{}'::jsonb` NOTULL
- `promotedThreatId` FK→threats.id SET NULL NULLABLE (Phase 14 FIND-03 populates)
- `createdAt/updatedAt` defaultNow NOTULL
- 5 indexes: endpoint_id, job_id, owasp_category, severity, status

### Types Exported

```typescript
export type Api = typeof apis.$inferSelect;
export type InsertApi = typeof apis.$inferInsert;
export type ApiEndpoint = typeof apiEndpoints.$inferSelect;
export type InsertApiEndpoint = typeof apiEndpoints.$inferInsert;
export type ApiFinding = typeof apiFindings.$inferSelect;
export type InsertApiFinding = typeof apiFindings.$inferInsert;
export interface ApiFindingEvidence { ... }
export type ApiFindingEvidenceInput = z.infer<typeof apiFindingEvidenceSchema>;
```

### Zod Schemas Added (shared/schema.ts lines ~1340-1381)

- `apiFindingEvidenceSchema`: strict Zod, request+response required, bodySnippet max 8192
- `insertApiSchema`: createInsertSchema(apis).omit({id,createdAt,createdBy,updatedAt,specHash,specVersion,specLastFetchedAt}).extend({parentAssetId uuid, baseUrl url, apiType enum})
- `insertApiEndpointSchema`: createInsertSchema(apiEndpoints).omit({id,createdAt,updatedAt})
- `insertApiFindingSchema`: createInsertSchema(apiFindings, {evidence: apiFindingEvidenceSchema}).omit({id,createdAt,updatedAt,promotedThreatId,riskScore})

## Test Results

**`shared/__tests__/evidenceSchema.test.ts`:** 6/6 GREEN (Wave 0 RED → Wave 1 GREEN)

Tests verified:
1. accepts canonical minimal shape
2. accepts optional bodySnippet up to 8192 chars
3. rejects missing request
4. rejects missing response
5. rejects unknown top-level keys (.strict)
6. accepts optional extractedValues and context

## Contract Exported for Downstream Plans

**Plan 03** (ensureApiTables): imports `apis`, `apiEndpoints`, `apiFindings` table exports to verify DB has the 3 tables.

**Plan 04** (apisRoute + backfill): imports `insertApiSchema` for POST body validation; `apis`/`apiEndpoints`/`apiFindings` for storage facade queries; `apiFindingEvidenceSchema` for finding creation.

**Phase 14 FIND-03**: `promotedThreatId` column already declared (FK→threats SET NULL) — no additional migration needed.

## db:push Note

Running `npm run db:push` after this plan lands will apply:
- 3 new enums: `api_type_enum`, `owasp_api_category`, `api_finding_status`
- 3 new tables: `apis`, `api_endpoints`, `api_findings` with all indexes, FKs, and CHECK constraint

No manual migration file needed — drizzle-kit generates the DDL from the schema definitions.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] vitest.config.ts missing shared/ test glob**
- **Found during:** Task 2 verification (running `npx vitest run shared/__tests__/evidenceSchema.test.ts`)
- **Issue:** vitest.config.ts had `include: ['server/**/*.test.ts']` only; shared/ tests invisible
- **Fix:** Added `'shared/**/*.test.ts'` to the include array
- **Files modified:** vitest.config.ts
- **Commit:** 1f36184

## Self-Check: PASSED

- shared/schema.ts: FOUND
- vitest.config.ts: FOUND
- 09-02-SUMMARY.md: FOUND
- Commit 874ba5f (Task 1 — 3 pgEnums): FOUND
- Commit 1f36184 (Task 2 — tables + Zod + vitest fix): FOUND
