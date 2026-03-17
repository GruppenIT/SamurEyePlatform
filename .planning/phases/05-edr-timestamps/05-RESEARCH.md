# Phase 5: EDR Timestamps - Research

**Researched:** 2026-03-17
**Domain:** Drizzle ORM schema extension, Zod schema extension, TypeScript scanner integration
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Timestamp derivation**
- `deploymentTimestamp` = timestamp of the first `deploy_success` timeline event. Null if deployment failed.
- `detectionTimestamp` = timestamp of the `detected` timeline event (EICAR removed by EDR/AV). Null when `not_detected` or `timeout` — meaning no detection occurred.
- Both fields computed at parse time in `testSingleHost()` and stored on `EdrFinding` — not derived on-the-fly during reads.
- Add `deploymentTimestamp` and `detectionTimestamp` as optional string fields to `EdrFindingSchema`.

**Database table design**
- Table name: `edr_deployments`
- Rich metadata columns: `id`, `hostId` (FK to hosts), `journeyId` (FK to journeys), `jobId` (FK to jobs), `deploymentTimestamp`, `detectionTimestamp`, `deploymentMethod`, `detected` (boolean, nullable), `testDuration`, `createdAt`
- One row per test — re-scans of the same host create new rows, building a history
- Foreign key to `hosts` table for referential integrity and JOINs with host details

**Data population strategy**
- Insert into `edr_deployments` during scan execution, right after each host test completes in `EDRAVScanner`
- No backfill from existing JSONB artifacts — only new scans populate the table
- Failed deployments also get a row with null `deploymentTimestamp` and null `detectionTimestamp` — gives complete visibility into what was attempted
- Migration is additive: CREATE TABLE only, no existing data modified

**Query patterns**
- Primary query: by `journeyId` ("show all EDR deployment results for this journey") — index on `journeyId`
- Secondary index on `hostId` for cross-journey host lookups
- No new API endpoint — extend existing journey detail/findings routes to include `edr_deployments` data
- Data surfaces alongside existing EDR findings in current endpoints

### Claude's Discretion
- Exact Drizzle ORM table definition syntax and column types
- Migration file naming and structure
- How to wire the DB insert into the existing scanner flow
- Index naming conventions
- Error handling if DB insert fails during scan (should not block scan)

### Deferred Ideas (OUT OF SCOPE)
None — discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| PARS-09 | EDR findings include explicit `deploymentTimestamp` and `detectionTimestamp` fields per host | Zod schema extension with `.optional()` string fields; timeline parse logic in `testSingleHost()` using `.find()` on action enum |
| PARS-10 | EDR per-host deployment metadata stored in queryable database table (not buried in JSONB artifacts) | Drizzle `pgTable` definition for `edr_deployments`; `database-init.ts` pattern for additive CREATE TABLE IF NOT EXISTS; storage function for insert |
</phase_requirements>

---

## Summary

Phase 5 extends two things: the `EdrFindingSchema` Zod schema to carry two new optional timestamp fields, and the database to record a structured row per EDR test in a new `edr_deployments` table. All work is confined to `shared/schema.ts`, `server/services/scanners/edrAvScanner.ts`, and `server/storage/database-init.ts` (plus a new storage helper function).

The timestamp derivation logic is pure: both timestamps are extracted by searching the already-built `timeline` array for specific action values (`deploy_success` for deployment, `detected` for detection). This array is fully populated before the `EdrFinding` candidate object is constructed, so the logic can be added inline before the `EdrFindingSchema.safeParse()` call in each success branch.

The `edr_deployments` table follows an additive-only pattern established by prior phases — `database-init.ts` already bootstraps indexes and columns at startup using `CREATE TABLE IF NOT EXISTS` via `db.execute(sql`...`)`. The scanner gets the `hostId` by resolving the hostname through `hostService.discoverHostsFromFindings()`, which already runs in the calling `journeyExecutor.ts` after each scan. The DB insert in `testSingleHost()` must be non-blocking (try/catch, log on error, never rethrow).

**Primary recommendation:** Add timestamp fields to `EdrFindingSchema` first, update fixtures, then add the `edr_deployments` table definition to `shared/schema.ts`, the migration guard in `database-init.ts`, and the storage insert function — all as a single atomic plan.

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| drizzle-orm | already in project | Table definition, typed queries | Project ORM — all schema lives here |
| zod | already in project | Runtime schema validation | All finding schemas use Zod `.strip()` |
| drizzle-zod | already in project | Bridge between Drizzle tables and Zod insert schemas | Used by `createInsertSchema` in `shared/schema.ts` |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| drizzle-orm/pg-core | — | `pgTable`, `varchar`, `text`, `timestamp`, `boolean`, `integer`, `index` | All table definitions in this project |

**No new packages required.** All required libraries are already installed.

---

## Architecture Patterns

### Recommended Project Structure

No new directories. Changes are confined to:
```
shared/
└── schema.ts              # EdrFindingSchema extension + edrDeployments table definition

server/
├── services/scanners/
│   └── edrAvScanner.ts    # Timestamp derivation in testSingleHost() + DB insert
├── storage/
│   ├── database-init.ts   # CREATE TABLE IF NOT EXISTS migration guard
│   └── index.ts           # Export new insertEdrDeployment storage function
└── __tests__/
    └── edrParser.test.ts  # New test cases for deploymentTimestamp and detectionTimestamp fields
```

### Pattern 1: Additive Zod Schema Extension

**What:** Add `.optional()` fields to an existing `.strip()` schema without breaking backward compatibility.

**When to use:** Whenever EdrFinding needs new optional fields — the `.strip()` call means unknown fields on old data are silently dropped, and new optional fields on old data default to `undefined`.

**Example:**
```typescript
// In shared/schema.ts — extend EdrFindingSchema
export const EdrFindingSchema = BaseFindingSchema.extend({
  type: z.literal('edr_test'),
  hostname: z.string(),
  eicarRemoved: z.boolean().nullable(),
  testDuration: z.number(),
  deploymentMethod: z.string(),
  filePath: z.string().optional(),
  share: z.string().optional(),
  error: z.string().optional(),
  timeline: z.array(EdrTimelineEventSchema),
  sampleRate: z.number().optional(),
  detected: z.boolean().nullable(),
  // PARS-09: explicit per-host timestamps
  deploymentTimestamp: z.string().optional(),  // ISO-8601, from first deploy_success event
  detectionTimestamp: z.string().optional(),   // ISO-8601, from detected event; null when not detected
}).strip();
```

### Pattern 2: Timestamp Derivation from Timeline Array

**What:** Extract specific timestamps by searching the `timeline` array before constructing the finding candidate.

**When to use:** Inside `testSingleHost()`, in each branch that builds a `candidate` object, immediately before `EdrFindingSchema.safeParse(candidate)`.

**Example:**
```typescript
// In testSingleHost() — both success paths (SMB and WMI)
const deploymentTimestamp =
  timeline.find(e => e.action === 'deploy_success')?.timestamp ?? undefined;
const detectionTimestamp =
  timeline.find(e => e.action === 'detected')?.timestamp ?? undefined;

const candidate = {
  // ...existing fields...
  deploymentTimestamp,
  detectionTimestamp,
};
```

For the error/catch path, both will be `undefined` (no deploy_success or detected event gets pushed when deployment throws).

### Pattern 3: Additive Table Definition in shared/schema.ts

**What:** Define the new `edr_deployments` pgTable directly in `shared/schema.ts` following the existing pattern (see `threats` table at lines 266-305 for FK + index syntax).

**When to use:** All tables live in `shared/schema.ts`. Never define tables elsewhere.

**Example:**
```typescript
// In shared/schema.ts — after the hosts table (~line 221)
export const edrDeployments = pgTable("edr_deployments", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  hostId: varchar("host_id").references(() => hosts.id).notNull(),
  journeyId: varchar("journey_id").references(() => journeys.id).notNull(),
  jobId: varchar("job_id").references(() => jobs.id).notNull(),
  deploymentTimestamp: timestamp("deployment_timestamp"),      // null if deployment failed
  detectionTimestamp: timestamp("detection_timestamp"),        // null if not detected
  deploymentMethod: text("deployment_method").notNull(),       // 'smb' | 'wmi'
  detected: boolean("detected"),                               // nullable
  testDuration: integer("test_duration").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
}, (table) => [
  index("IDX_edr_deployments_journey_id").on(table.journeyId),
  index("IDX_edr_deployments_host_id").on(table.hostId),
]);

export type EdrDeployment = typeof edrDeployments.$inferSelect;
export type InsertEdrDeployment = typeof edrDeployments.$inferInsert;
```

**Note on timestamp column types:** The `deploymentTimestamp` and `detectionTimestamp` columns are stored as `timestamp` (PostgreSQL TIMESTAMPTZ) rather than text, since the values come from ISO-8601 strings that are naturally parsed by Drizzle. The `EdrFinding` Zod schema uses `z.string()` for these fields (ISO-8601 text) — conversion happens at the insert site.

### Pattern 4: Migration Guard in database-init.ts

**What:** The project uses `database-init.ts` as its migration mechanism — idempotent SQL executed at startup, guarded by existence checks.

**When to use:** Whenever a new table or column must be created without a migration file system. This is the established project pattern — there are no migration files in this repo.

**Example:**
```typescript
// In initializeDatabaseStructure() — database-init.ts
const edrDeploymentsCheck = await db.execute(sql`
  SELECT tablename FROM pg_tables
  WHERE schemaname = 'public' AND tablename = 'edr_deployments'
`);

if ((edrDeploymentsCheck.rowCount ?? 0) === 0) {
  log.info('creating edr_deployments table');
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS edr_deployments (
      id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid(),
      host_id VARCHAR NOT NULL REFERENCES hosts(id),
      journey_id VARCHAR NOT NULL REFERENCES journeys(id),
      job_id VARCHAR NOT NULL REFERENCES jobs(id),
      deployment_timestamp TIMESTAMPTZ,
      detection_timestamp TIMESTAMPTZ,
      deployment_method TEXT NOT NULL,
      detected BOOLEAN,
      test_duration INTEGER NOT NULL,
      created_at TIMESTAMPTZ DEFAULT now() NOT NULL
    )
  `);
  await db.execute(sql`
    CREATE INDEX "IDX_edr_deployments_journey_id" ON edr_deployments (journey_id)
  `);
  await db.execute(sql`
    CREATE INDEX "IDX_edr_deployments_host_id" ON edr_deployments (host_id)
  `);
  log.info('edr_deployments table created');
}
```

### Pattern 5: Non-Blocking DB Insert in Scanner

**What:** The scanner must never fail a host test because a DB insert threw. Insert is fire-and-observe, not fire-and-require.

**When to use:** Any scanner-side DB operation. Scan results are written to JSONB artifacts regardless; the `edr_deployments` row is supplemental structured data.

**Example:**
```typescript
// At the end of each success branch in testSingleHost() — after EdrFindingSchema.safeParse()
try {
  await insertEdrDeployment({
    hostId: resolvedHostId,       // see "hostId resolution" note below
    journeyId,
    jobId,
    deploymentTimestamp: deploymentTimestamp ? new Date(deploymentTimestamp) : null,
    detectionTimestamp: detectionTimestamp ? new Date(detectionTimestamp) : null,
    deploymentMethod: candidate.deploymentMethod,
    detected: candidate.detected ?? null,
    testDuration: candidate.testDuration,
  });
} catch (insertErr) {
  log.warn({ host: hostname, err: insertErr }, 'edr_deployments insert failed — scan result unaffected');
}
```

### Anti-Patterns to Avoid

- **Deriving timestamps on read:** The decision is "computed at parse time, stored on EdrFinding." Do not add derivation logic to route handlers or storage queries.
- **Blocking scan on DB insert failure:** The insert is supplemental; a DB error must never surface to the caller of `testSingleHost()`.
- **Storing timestamp as TEXT in edr_deployments:** Use `TIMESTAMPTZ` for queryability. The Zod schema uses `z.string()` because EdrFinding is JSON-serializable; conversion to `Date` happens only at insert time.
- **Adding a new API endpoint:** The decision is to extend existing journey detail/findings routes only.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Type-safe DB inserts | Custom SQL string for insert | `db.insert(edrDeployments).values(...)` | Drizzle typed insert catches column mismatches at compile time |
| Schema validation | Manual type checks | `EdrFindingSchema.safeParse()` already in place | Re-use existing parse call; add fields to schema only |
| Migration management | Custom migration runner | `database-init.ts` `CREATE TABLE IF NOT EXISTS` pattern | Already established; no migration files exist in the project |
| UUID generation | `crypto.randomUUID()` inline | `default(sql\`gen_random_uuid()\`)` in table definition | Consistent with all other tables in `shared/schema.ts` |

---

## Common Pitfalls

### Pitfall 1: testSingleHost() Has Two Success Branches

**What goes wrong:** The SMB success path and the WMI success path each build a `candidate` object independently. Adding timestamp derivation to only one branch means WMI deployments have null timestamps even when they succeeded.

**Why it happens:** The `testSingleHost()` method has branching structure: SMB success (lines ~261-278), WMI success (lines ~322-340), and error/catch (lines ~346-377). Each branch constructs its own candidate independently.

**How to avoid:** Add the `deploymentTimestamp`/`detectionTimestamp` derivation and the DB insert to ALL three branches. For the error/catch branch, both timestamps will be undefined (no deploy_success or detected events are added before the throw).

**Warning signs:** Test for WMI deployment fixture — if `deploymentTimestamp` is undefined when `deploymentMethod` is `'wmi'` and `deploy_success` is in the timeline, a branch was missed.

### Pitfall 2: hostId Is Not Available Inside testSingleHost()

**What goes wrong:** `testSingleHost()` receives a `hostname` string but not a `hostId` (database UUID). The `edr_deployments` table requires a `hostId` FK.

**Why it happens:** The method signature is `testSingleHost(hostname, credential, timeout)`. Host registration happens in `journeyExecutor.ts` via `hostService.discoverHostsFromFindings()`, which runs after scan results are collected — after `testSingleHost()` returns.

**How to avoid:** Two options:
1. Pass `journeyId` and `jobId` into `testSingleHost()` (or into `runEDRAVTest()`), perform the `edr_deployments` insert in `journeyExecutor.ts` after `runEDRAVTest()` returns and after hosts are registered. This keeps the scanner clean but requires iterating findings again.
2. Look up hostId by hostname inside the DB insert site using `hostService.findHostByName(hostname)`. This works only after `discoverHostsFromFindings()` has run.

**Recommended approach:** Insert into `edr_deployments` in `journeyExecutor.ts`, in the loop that processes findings after the scan completes (around line 860), once hosts are registered. This avoids threading DB context into the scanner and matches how other post-scan data is handled.

**Warning signs:** FK violation (`host_id` references `hosts(id)`) at insert time — the host row does not yet exist.

### Pitfall 3: Zod .strip() Strips New Fields From Existing Fixtures

**What goes wrong:** Adding `deploymentTimestamp` and `detectionTimestamp` to the schema is backward-compatible for `safeParse()` (optional fields, old data passes), but the existing snapshot tests will fail because the parsed output shape has changed.

**Why it happens:** `toMatchSnapshot()` in `edrParser.test.ts` captures the exact parsed output. Once new optional fields are added (even if undefined), the snapshot output changes — or more precisely, undefined fields are omitted, which is fine. But if fixtures are updated to include these fields, snapshots must be regenerated.

**How to avoid:** After updating fixtures to include the new timestamp fields, regenerate snapshots with `npx vitest --update-snapshots` (or `npx vitest -u`).

**Warning signs:** Snapshot test failures citing "received object does not match stored snapshot."

### Pitfall 4: database-init.ts Is Not Idempotent Without Existence Check

**What goes wrong:** Running `CREATE TABLE edr_deployments (...)` without `IF NOT EXISTS` or a prior existence check throws `relation "edr_deployments" already exists` on every subsequent server restart after the first.

**Why it happens:** `database-init.ts` runs at every server startup. The pattern used by other migrations is to check `pg_tables` or `pg_indexes` first.

**How to avoid:** Wrap the `CREATE TABLE` in an existence check (see Pattern 4 example above), or use `CREATE TABLE IF NOT EXISTS` directly — the `IF NOT EXISTS` form is safe without a prior check.

---

## Code Examples

### Timestamp Derivation (canonical timeline array shapes)

The three fixture files (`detection-success.json`, `detection-failure.json`, `timeout-error.json`) represent all possible timeline shapes:

| Fixture | deploy_success? | detected? | deploymentTimestamp | detectionTimestamp |
|---------|----------------|-----------|---------------------|--------------------|
| detection-success | yes (`10:00:02Z`) | yes (`10:00:32Z`) | `"2024-03-16T10:00:02Z"` | `"2024-03-16T10:00:32Z"` |
| detection-failure | yes (`10:05:02Z`) | no | `"2024-03-16T10:05:02Z"` | undefined |
| timeout-error | no | no | undefined | undefined |

```typescript
// Derivation logic — insert before candidate construction in each branch
const deploymentTimestamp =
  timeline.find(e => e.action === 'deploy_success')?.timestamp;
const detectionTimestamp =
  timeline.find(e => e.action === 'detected')?.timestamp;
```

### Drizzle Insert Pattern (from journeys.ts storage)

```typescript
// Pattern used throughout server/storage/journeys.ts
const [row] = await db
  .insert(edrDeployments)
  .values({
    hostId,
    journeyId,
    jobId,
    deploymentTimestamp: deploymentTimestamp ? new Date(deploymentTimestamp) : null,
    detectionTimestamp: detectionTimestamp ? new Date(detectionTimestamp) : null,
    deploymentMethod,
    detected: detected ?? null,
    testDuration,
  })
  .returning();
return row;
```

### Storage Function Signature

```typescript
// server/storage/index.ts (or a new edrDeployments.ts)
export async function insertEdrDeployment(
  data: InsertEdrDeployment
): Promise<EdrDeployment> {
  const [row] = await db.insert(edrDeployments).values(data).returning();
  return row;
}

export async function getEdrDeploymentsByJourney(
  journeyId: string
): Promise<EdrDeployment[]> {
  return await db
    .select()
    .from(edrDeployments)
    .where(eq(edrDeployments.journeyId, journeyId))
    .orderBy(desc(edrDeployments.createdAt));
}
```

---

## State of the Art

| Old Approach | Current Approach | Impact |
|--------------|-----------------|--------|
| Timestamps buried in JSONB `artifacts` column of `job_results` | Explicit columns in `edr_deployments` table | Queryable via SQL, joinable with `hosts` and `journeys` |
| No per-host deployment history | One row per test, re-scans append new rows | Cross-journey host EDR coverage visible over time |

---

## Open Questions

1. **hostId resolution timing**
   - What we know: `testSingleHost()` has no access to hostId; host registration happens in `journeyExecutor.ts` after the full scan
   - What's unclear: Whether to insert into `edr_deployments` inside the scanner (requiring a hostname→hostId lookup) or in `journeyExecutor.ts` after hosts are registered
   - Recommendation: Insert in `journeyExecutor.ts` after `runEDRAVTest()` returns and after `discoverHostsFromFindings()` runs — this avoids touching the scanner's core logic and matches the existing post-scan processing pattern. Planner should document this as the wiring decision.

2. **journeyId and jobId availability in scanner**
   - What we know: `runEDRAVTest()` only receives `credential`, `targets`, `sampleRate`, `timeout` — no job or journey context
   - What's unclear: If insert happens in `journeyExecutor.ts`, this is a non-issue; if insert happens in scanner, both IDs must be threaded in
   - Recommendation: Aligns with question 1 — insert in journeyExecutor, not in scanner.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Vitest (already configured) |
| Config file | `vitest.config.ts` (root) |
| Quick run command | `npx vitest run server/__tests__/edrParser.test.ts` |
| Full suite command | `npx vitest run` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| PARS-09 | `deploymentTimestamp` present and correct in detection-success fixture | unit | `npx vitest run server/__tests__/edrParser.test.ts` | ✅ (needs new cases) |
| PARS-09 | `deploymentTimestamp` present, `detectionTimestamp` absent in detection-failure fixture | unit | `npx vitest run server/__tests__/edrParser.test.ts` | ✅ (needs new cases) |
| PARS-09 | Both timestamps absent in timeout-error fixture | unit | `npx vitest run server/__tests__/edrParser.test.ts` | ✅ (needs new cases) |
| PARS-10 | `edr_deployments` table definition present in schema (type-check) | unit/type | `npx tsc --noEmit` | ❌ Wave 0 |
| PARS-10 | `insertEdrDeployment` storage function exists and accepts correct shape | unit | `npx vitest run server/__tests__/edrDeployments.test.ts` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `npx vitest run server/__tests__/edrParser.test.ts`
- **Per wave merge:** `npx vitest run`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `server/__tests__/edrDeployments.test.ts` — unit tests for `insertEdrDeployment` and `getEdrDeploymentsByJourney` (covers PARS-10 storage layer)
- [ ] Snapshot regeneration after new timestamp fields added to `EdrFindingSchema` — run `npx vitest run --update-snapshots` after schema change

*(Existing `edrParser.test.ts` covers the schema validation tests but needs new `it()` blocks for timestamp field assertions — no new file required for PARS-09 parser tests.)*

---

## Sources

### Primary (HIGH confidence)
- Direct code inspection: `shared/schema.ts` lines 1-17, 193-221, 266-305 — Drizzle table definition patterns, FK syntax, index syntax
- Direct code inspection: `server/services/scanners/edrAvScanner.ts` lines 199-378 — `testSingleHost()` structure, all three branches, timeline accumulation
- Direct code inspection: `server/storage/database-init.ts` — migration guard pattern using `pg_indexes`/`pg_tables` check + `db.execute(sql\`...\`)`
- Direct code inspection: `server/__tests__/edrParser.test.ts` — existing test coverage, snapshot tests, fixture shapes
- Direct code inspection: `server/__tests__/fixtures/edr/*.json` — all three fixture shapes confirming timeline event sequences
- Direct code inspection: `server/services/journeyExecutor.ts` lines 780-895 — where `runEDRAVTest()` is called and results processed

### Secondary (MEDIUM confidence)
- Drizzle ORM docs (verified by code patterns in project): `timestamp()`, `boolean()`, `integer()`, `varchar()`, `pgTable`, `.references()`, `index()` all confirmed present in existing schema definitions

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all libraries already in project, patterns confirmed by direct code inspection
- Architecture: HIGH — all patterns derived from existing code, no speculation required
- Pitfalls: HIGH — derived from actual code structure (dual SMB/WMI branches, missing hostId in scanner, snapshot tests)

**Research date:** 2026-03-17
**Valid until:** 2026-04-17 (stable domain — Drizzle and Zod patterns do not change rapidly)
