---
phase: 15-journey-orchestration-safety
plan: "02"
subsystem: schema + database-init
tags: [schema, drizzle, pgEnum, database-init, journey, api_security, tdd]
dependency_graph:
  requires: [15-01]
  provides: [journeyTypeEnum-api_security, authorizationAck-column, ensureJourneyApiSecurityColumns]
  affects: [shared/schema.ts, server/storage/database-init.ts, client/src/types/index.ts]
tech_stack:
  added: []
  patterns: [boot-time idempotent guard (IF NOT EXISTS), Drizzle $inferSelect type inference, TDD RED-GREEN]
key_files:
  created: []
  modified:
    - shared/schema.ts
    - server/storage/database-init.ts
    - server/__tests__/journeyOrchestration.test.ts
    - client/src/types/index.ts
decisions:
  - "JourneyFormData client type updated to include api_security (Rule 1 — TypeScript enforced correctness)"
  - "ensureJourneyApiSecurityColumns() follows try/catch swallow pattern — matches ensureApiEndpointHttpxColumns"
  - "authorizationAck column added with DEFAULT false — existing journeys unaffected (attack_surface/ad_security/edr_av/web_application)"
metrics:
  duration: "3m"
  completed_date: "2026-04-20"
  tasks: 2
  files_modified: 4
requirements_satisfied: [JRNY-01, JRNY-02, JRNY-04]
---

# Phase 15 Plan 02: Journey Schema Extension (api_security + authorizationAck) Summary

**One-liner:** Extended journeyTypeEnum with `api_security` (5th value) + added `authorization_ack boolean NOT NULL DEFAULT false` column + idempotent boot-time guard `ensureJourneyApiSecurityColumns()`.

## What Was Built

### Task 1 — shared/schema.ts schema extension

**Before:**
```typescript
export const journeyTypeEnum = pgEnum('journey_type', ['attack_surface', 'ad_security', 'edr_av', 'web_application']);
// journeys table had no authorizationAck field
```

**After:**
```typescript
export const journeyTypeEnum = pgEnum('journey_type', ['attack_surface', 'ad_security', 'edr_av', 'web_application', 'api_security']);
// journeys table gains:
authorizationAck: boolean("authorization_ack").notNull().default(false),
```

`insertJourneySchema` (derived via `createInsertSchema(journeys)`) automatically includes `authorizationAck` as optional boolean — no explicit change needed to the `.omit({...})` block.

### Task 2 — server/storage/database-init.ts guard + call site

**New function (after `ensureApiEndpointHttpxColumns`):**
```typescript
export async function ensureJourneyApiSecurityColumns(): Promise<void> {
  try {
    await db.execute(sql`ALTER TYPE journey_type ADD VALUE IF NOT EXISTS 'api_security'`);
    await db.execute(sql`ALTER TABLE journeys ADD COLUMN IF NOT EXISTS authorization_ack boolean NOT NULL DEFAULT false`);
    log.info('ensureJourneyApiSecurityColumns complete');
  } catch (error) {
    log.error({ err: error }, 'ensureJourneyApiSecurityColumns error');
  }
}
```

**New call site in `initializeDatabaseStructure()` (after ensureApiEndpointHttpxColumns, line 148):**
```typescript
// Phase 15: journey_type enum extension + authorizationAck column (JRNY-01, JRNY-02)
await ensureJourneyApiSecurityColumns();
```

## Tests Promoted

| File | Describe | Before | After |
|------|----------|--------|-------|
| journeyOrchestration.test.ts | JRNY-01 | `it.todo` (1) | `it()` (1) |
| journeyOrchestration.test.ts | JRNY-02 | `it.todo` (2) | `it()` (2) |

Total: **3 it.todo -> 3 real it()**, all GREEN.

## Idempotency Confirmation

Both SQL statements use `IF NOT EXISTS`:
- `ALTER TYPE journey_type ADD VALUE IF NOT EXISTS 'api_security'` — Postgres 9.6+ supported. Re-running on a database where the value already exists is a no-op (no error).
- `ALTER TABLE journeys ADD COLUMN IF NOT EXISTS authorization_ack boolean NOT NULL DEFAULT false` — Same pattern. Existing rows get DEFAULT false applied at migration time; subsequent boots are no-ops.

The try/catch swallow pattern (no `throw error` in catch) ensures app boot continues even if an unexpected Postgres error occurs.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Updated JourneyFormData client type to include 'api_security'**
- **Found during:** Task 1 TypeScript verification
- **Issue:** `client/src/types/index.ts` line 48 had hardcoded union `'attack_surface' | 'ad_security' | 'edr_av' | 'web_application'` — TypeScript error at `client/src/pages/journeys.tsx` line 517
- **Fix:** Added `| 'api_security'` to the union in `JourneyFormData.type`
- **Files modified:** `client/src/types/index.ts`
- **Commit:** 6118575 (included in Task 1 commit)

## Self-Check: PASSED

- `shared/schema.ts` exists with `api_security` and `authorization_ack` — FOUND
- `server/storage/database-init.ts` has `ensureJourneyApiSecurityColumns` — FOUND
- `client/src/types/index.ts` updated with `api_security` — FOUND
- Task 1 commit: 6118575 — FOUND
- Task 2 commit: 4017b6f — FOUND
- JRNY-01: 1 test PASSED
- JRNY-02: 2 tests PASSED
