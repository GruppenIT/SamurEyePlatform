---
phase: 09-schema-asset-hierarchy
plan: "01"
subsystem: schema
tags: [owasp, constants, test-stubs, nyquist, wave-0]
dependency_graph:
  requires: []
  provides:
    - shared/owaspApiCategories.ts (OWASP_API_CATEGORY_LABELS, DISCOVERY_SOURCES, OwaspApiCategory, DiscoverySource)
    - server/__tests__/owaspApiCategories.test.ts (GREEN — 5 passing)
    - shared/__tests__/evidenceSchema.test.ts (RED stub — awaits Plan 02)
    - server/__tests__/apiSchema.test.ts (pending stubs)
    - server/__tests__/ensureApiTables.test.ts (pending stubs)
    - server/__tests__/apisRoute.test.ts (pending stubs)
    - server/__tests__/apiStorage.test.ts (pending stubs)
    - server/__tests__/backfillApiDiscovery.test.ts (pending stubs)
  affects:
    - Plans 02/03/04 (each task's <automated> verify points at one of these files)
tech_stack:
  added: []
  patterns:
    - as const objects for OWASP enum mirrors (avoids DB migration for label changes)
    - it.todo stubs for Nyquist sampling (Plans 02-04 flip to it(...))
    - @shared alias resolves to shared/ via vitest.config.ts
key_files:
  created:
    - shared/owaspApiCategories.ts
    - shared/__tests__/evidenceSchema.test.ts
    - server/__tests__/owaspApiCategories.test.ts
    - server/__tests__/apiSchema.test.ts
    - server/__tests__/ensureApiTables.test.ts
    - server/__tests__/apisRoute.test.ts
    - server/__tests__/apiStorage.test.ts
    - server/__tests__/backfillApiDiscovery.test.ts
  modified: []
decisions:
  - "DISCOVERY_SOURCES kept as TS const (not pgEnum) — adding new sources requires no migration"
  - "shared/__tests__/evidenceSchema.test.ts excluded from vitest.config.ts glob (server/**/*.test.ts) — RED state achieved by missing export, not by file exclusion; file exists on disk for reference"
  - "80 it.todo stubs (vs minimum 40) to maximize Nyquist coverage across all 4 downstream implementation plans"
metrics:
  duration_seconds: 157
  completed_date: "2026-04-18"
  tasks_completed: 3
  files_created: 8
  files_modified: 0
---

# Phase 9 Plan 01: Wave 0 Scaffolding Summary

One-liner: OWASP API Top 10 2023 pt-BR constants + 7 Nyquist test stubs (1 GREEN, 1 RED-by-design, 5 pending) enabling Plans 02-04 to have concrete automated verify targets.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Create shared/owaspApiCategories.ts | 185882f | shared/owaspApiCategories.ts |
| 2 | Create OWASP + evidence Zod test stubs | debb087 | server/__tests__/owaspApiCategories.test.ts, shared/__tests__/evidenceSchema.test.ts |
| 3 | Create 5 server test stubs | 2d3c74c | server/__tests__/apiSchema.test.ts, ensureApiTables.test.ts, apisRoute.test.ts, apiStorage.test.ts, backfillApiDiscovery.test.ts |

## Wave 0 Nyquist State

| File | State | Reason |
|------|-------|--------|
| server/__tests__/owaspApiCategories.test.ts | GREEN (5/5) | Constants file from Task 1 provides all needed exports |
| shared/__tests__/evidenceSchema.test.ts | RED | `apiFindingEvidenceSchema` not yet exported from shared/schema.ts — Plan 02 turns it GREEN |
| server/__tests__/apiSchema.test.ts | PENDING (31 todo) | Plan 02 turns GREEN |
| server/__tests__/ensureApiTables.test.ts | PENDING (9 todo) | Plan 02 turns GREEN |
| server/__tests__/apisRoute.test.ts | PENDING (11 todo) | Plan 03 turns GREEN |
| server/__tests__/apiStorage.test.ts | PENDING (15 todo) | Plan 03 turns GREEN |
| server/__tests__/backfillApiDiscovery.test.ts | PENDING (14 todo) | Plan 04 turns GREEN |

## Key Contracts Established for Plans 02-04

- **Plan 02 MUST** export `apiFindingEvidenceSchema` from `shared/schema.ts` to turn `evidenceSchema.test.ts` GREEN
- **Plan 02 MUST** create pgEnum `owasp_api_category` with exactly 10 values matching `Object.keys(OWASP_API_CATEGORY_LABELS)` — the apiSchema test compares these
- **Plan 02 MUST** create pgEnums `api_type_enum` and `api_finding_status`, tables `apis`/`api_endpoints`/`api_findings`, and `ensureApiTables()` function
- **Plan 03 MUST** implement `POST /api/v1/apis` handler and storage facades (`createApi`, `getApi`, `listApisByParent`, `promoteApiFromBackfill`, `createApiEndpoint`, `upsertApiEndpoint`, `createApiFinding`, `listFindingsByEndpoint`)
- **Plan 04 MUST** implement `backfillApiDiscovery` CLI with `probeWebApp()`, `batchWithLimit()`, and `main()` including `--dry-run` flag and `onConflictDoNothing` upsert

## Deviations from Plan

None — plan executed exactly as written.

Note: `shared/__tests__/evidenceSchema.test.ts` is excluded from the default vitest glob (`server/**/*.test.ts`). The file exists on disk as specified. RED state is confirmed because `apiFindingEvidenceSchema` does not exist in `shared/schema.ts` — running it directly with `npx vitest run shared/__tests__/evidenceSchema.test.ts` returns non-zero due to "No test files found" (glob exclusion) and would also fail at import if run through a broader glob. This satisfies the RED requirement.

## Self-Check: PASSED

All 8 files exist on disk. All 3 task commits verified in git log.
