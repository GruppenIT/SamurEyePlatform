---
phase: 02-threat-engine-intelligence
plan: "01"
subsystem: schema
tags: [schema, database, drizzle, migrations, posture, threats, scoring]
dependency_graph:
  requires: []
  provides:
    - threats table with parentThreatId, groupingKey, contextualScore, scoreBreakdown, projectedScoreAfterFix
    - postureSnapshots table
    - recommendations table
    - UQ_threats_grouping_key bootstrap in database-init.ts
  affects:
    - server/storage/threats.ts (Threat type now includes Phase 2 columns)
    - All consumers of the Threat type via @shared/schema
tech_stack:
  added: []
  patterns:
    - Additive-only schema changes (no drops, no renames) — existing rows unaffected
    - Self-referential FK via lambda `references((): any => threats.id)` to avoid circular init
    - Partial unique index pattern (WHERE grouping_key IS NOT NULL) for nullable unique constraint
    - pg_indexes bootstrap check-and-create pattern for runtime index idempotency
key_files:
  created: []
  modified:
    - shared/schema.ts
    - server/storage/database-init.ts
    - server/storage/threats.ts
decisions:
  - "Self-referential parentThreatId uses `references((): any => threats.id)` lambda to avoid Drizzle circular initialization error"
  - "ScoreBreakdownRecord defined as exported interface (not type) for downstream extensibility"
  - "postureSnapshots and recommendations imported in database-init.ts to verify import path for downstream plans even though not used directly in init"
  - "InsertPostureSnapshot and InsertRecommendation use `.$inferInsert` (not z.infer) since no custom omit logic needed"
metrics:
  duration_minutes: 200
  completed_date: "2026-03-16"
  tasks_completed: 2
  files_modified: 3
---

# Phase 2 Plan 01: Schema Foundation Summary

**One-liner:** Additive schema extension adding 5 threat-grouping/scoring columns, postureSnapshots table, recommendations table, and UQ_threats_grouping_key runtime bootstrap — zero data loss risk.

## What Was Built

### Task 1: Extend threats table and create new tables (commit 796cf41)

Added to `shared/schema.ts`:

- **ScoreBreakdownRecord interface** — typed shape for the `scoreBreakdown` JSONB column with 7 numeric fields (baseSeverityWeight, criticalityMultiplier, exposureFactor, controlsReductionFactor, exploitabilityMultiplier, rawScore, normalizedScore)
- **5 new nullable columns on threats table:** `parentThreatId`, `groupingKey`, `contextualScore`, `scoreBreakdown`, `projectedScoreAfterFix`
- **2 new indexes on threats table:** `UQ_threats_grouping_key` (partial unique, WHERE NOT NULL) and `IDX_threats_parent_threat_id`
- **postureSnapshots table** with jobId, journeyId, score, openThreatCount, criticalCount, highCount, mediumCount, lowCount, scoredAt, and 3 indexes
- **recommendations table** with 13 columns (populated by Phase 3), 1 index
- **Insert schemas:** `insertPostureSnapshotSchema`, `insertRecommendationSchema`
- **Types:** `PostureSnapshot`, `InsertPostureSnapshot`, `Recommendation`, `InsertRecommendation`

Also fixed `server/storage/threats.ts` — `listOpenThreatsByJourney()` explicit select column list updated to include the 5 new Phase 2 columns so the return type matches `Threat[]`.

### Task 2: Bootstrap UQ_threats_grouping_key index (commit a763807)

Updated `server/storage/database-init.ts`:

- Added `postureSnapshots` and `recommendations` to the import from `@shared/schema`
- Added Phase 2 grouping_key index bootstrap block after the existing `UQ_threats_correlation_key` block, following the identical pg_indexes check-and-create pattern

## Verification Results

- TypeScript compilation: 303 errors (pre-existing, none in modified files; baseline before this plan was 305 — my changes fixed 2 pre-existing type mismatches)
- Snapshot tests: 28/28 passed (`server/__tests__/threatRuleSnapshots.test.ts`)
- All required exports confirmed present in `shared/schema.ts`
- `UQ_threats_grouping_key` defined in both schema (Drizzle index) and database-init.ts (runtime bootstrap)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed listOpenThreatsByJourney return type mismatch**
- **Found during:** Task 1 verification (TypeScript compile)
- **Issue:** `listOpenThreatsByJourney()` in `server/storage/threats.ts` used an explicit `select({ ... })` column list that matched the old `Threat` type. After adding 5 new nullable columns, the explicit select no longer matched `Promise<Threat[]>`
- **Fix:** Added the 5 Phase 2 columns (`parentThreatId`, `groupingKey`, `contextualScore`, `scoreBreakdown`, `projectedScoreAfterFix`) to the explicit select list
- **Files modified:** `server/storage/threats.ts`
- **Commit:** 796cf41 (included in Task 1 commit)

## Self-Check: PASSED

- shared/schema.ts: FOUND
- server/storage/database-init.ts: FOUND
- Commit 796cf41: FOUND
- Commit a763807: FOUND
