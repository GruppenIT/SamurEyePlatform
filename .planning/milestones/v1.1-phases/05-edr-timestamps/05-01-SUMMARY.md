---
phase: 05-edr-timestamps
plan: 01
subsystem: edr-scanner
tags: [schema, storage, testing, migration]
dependency_graph:
  requires: []
  provides: [EdrFindingSchema.deploymentTimestamp, EdrFindingSchema.detectionTimestamp, edrDeployments-table, insertEdrDeployment, getEdrDeploymentsByJourney]
  affects: [shared/schema.ts, server/services/scanners/edrAvScanner.ts, server/services/journeyExecutor.ts, server/storage]
tech_stack:
  added: []
  patterns: [drizzle-pgTable-with-FKs, TDD-red-green, idempotent-migration-guard, non-blocking-fire-and-forget-insert]
key_files:
  created:
    - server/storage/edrDeployments.ts
    - server/__tests__/__snapshots__/edrParser.test.ts.snap
  modified:
    - shared/schema.ts
    - server/services/scanners/edrAvScanner.ts
    - server/services/journeyExecutor.ts
    - server/storage/database-init.ts
    - server/storage/index.ts
    - server/storage/interface.ts
    - server/__tests__/edrParser.test.ts
    - server/__tests__/fixtures/edr/detection-success.json
    - server/__tests__/fixtures/edr/detection-failure.json
decisions:
  - "Timestamps derived from timeline events using Array.find() — deploy_success for deploymentTimestamp, detected for detectionTimestamp"
  - "edr_deployments insert is non-blocking: wrapped per-finding in try/catch after createJobResult completes"
  - "Migration guard uses pg_tables check before CREATE TABLE IF NOT EXISTS for idempotent startup"
  - "Host resolution uses hostService.findHostsByTarget() and skips insert if host not yet registered"
metrics:
  duration: "8 minutes"
  completed: "2026-03-17T18:49:41Z"
  tasks_completed: 3
  files_changed: 11
---

# Phase 5 Plan 01: EDR Timestamps and edr_deployments Table Summary

**One-liner:** Added deploymentTimestamp/detectionTimestamp to EdrFindingSchema derived from timeline events, plus a queryable edr_deployments table for per-host EDR deployment history.

## What Was Built

EdrFinding objects now carry explicit `deploymentTimestamp` and `detectionTimestamp` string fields (ISO-8601, optional) extracted from the timeline array. These fields are populated in all three branches of `testSingleHost()` (SMB success, WMI fallback, error/catch) using `timeline.find(e => e.action === 'deploy_success')?.timestamp` and `timeline.find(e => e.action === 'detected')?.timestamp`.

A new `edr_deployments` Drizzle table stores queryable per-host EDR deployment metadata (one row per host test), with FK references to `hosts`, `journeys`, and `jobs`. An idempotent migration guard in `database-init.ts` creates the table on first startup. After each EDR scan, `journeyExecutor.executeEDRAV()` inserts a row per finding in a non-blocking loop — insert failures are caught per-finding and logged without affecting scan results.

## Tasks Completed

| Task | Name | Commit | Key Files |
|------|------|--------|-----------|
| 1 | Extend EdrFindingSchema, define edrDeployments table, derive timestamps | a917cc7 | shared/schema.ts, edrAvScanner.ts, fixtures |
| RED | Failing tests for timestamp fields | e7a8596 | edrParser.test.ts |
| 2 | Migration guard, storage functions, journeyExecutor wiring | 9cbdaa9 | database-init.ts, edrDeployments.ts, journeyExecutor.ts |
| 3 | Full test suite validation and snapshot regeneration | 6aedf2d | __snapshots__/ |

## Verification Results

- `npx vitest run server/__tests__/edrParser.test.ts` — 19/19 tests passing (5 new timestamp tests)
- `npx vitest run` — 293/293 tests passing across 17 test files, no regressions
- `npx tsc --noEmit` — zero new errors in changed files (86 pre-existing errors unaffected)

## Acceptance Criteria Check

- [x] shared/schema.ts contains `deploymentTimestamp: z.string().optional()` inside EdrFindingSchema
- [x] shared/schema.ts contains `detectionTimestamp: z.string().optional()` inside EdrFindingSchema
- [x] shared/schema.ts contains `export const edrDeployments = pgTable("edr_deployments"`
- [x] shared/schema.ts contains `export type EdrDeployment =`
- [x] shared/schema.ts contains `export type InsertEdrDeployment =`
- [x] edrDeployments table has all required columns with FKs and indexes
- [x] edrAvScanner.ts SMB branch contains `timeline.find(e => e.action === 'deploy_success')?.timestamp`
- [x] edrAvScanner.ts WMI branch contains `timeline.find(e => e.action === 'deploy_success')?.timestamp`
- [x] edrAvScanner.ts error/catch branch contains `timeline.find(e => e.action === 'deploy_success')?.timestamp`
- [x] detection-success.json contains `"deploymentTimestamp": "2024-03-16T10:00:02Z"` and `"detectionTimestamp": "2024-03-16T10:00:32Z"`
- [x] detection-failure.json contains `"deploymentTimestamp": "2024-03-16T10:05:02Z"` (no detectionTimestamp)
- [x] timeout-error.json has neither timestamp field
- [x] server/storage/edrDeployments.ts exports insertEdrDeployment and getEdrDeploymentsByJourney
- [x] database-init.ts contains pg_tables check and CREATE TABLE IF NOT EXISTS edr_deployments
- [x] storage/index.ts and storage/interface.ts wire insertEdrDeployment and getEdrDeploymentsByJourney
- [x] journeyExecutor.ts contains `await insertEdrDeployment({` wrapped in per-finding try/catch

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check: PASSED

All key files verified present. All task commits verified in git log. All acceptance criteria confirmed satisfied.
