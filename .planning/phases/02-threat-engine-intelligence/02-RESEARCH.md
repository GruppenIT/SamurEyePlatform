# Phase 2: Threat Engine Intelligence - Research

**Researched:** 2026-03-16
**Domain:** TypeScript / Node.js — Drizzle ORM (PostgreSQL), threat grouping algorithms, contextual scoring engines
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Grouping model**
- Parent-child hierarchy in the threats table — a new parent threat row is created, child threats link via `parentThreatId`
- Parent severity equals highest severity among children (THRT-03)
- Parent status auto-derived from children: open if any child is open, mitigated if all mitigated, closed if all closed (THRT-04)
- No manual status changes on parent threats — they reflect aggregate child state

**Grouping keys by journey type**
- Attack Surface: one group per host + SERVICE_CATEGORIES category (admin, database, sharing, web, email, infrastructure)
- Attack Surface CVE: one parent per CVE ID across all affected hosts
- AD Security: group by adCheckCategory + domain
- EDR/AV: group by hostId

**Grouping timing**
- Post-processing step: all findings processed first as flat child threats (preserving current analyzeWithLifecycle flow), then `groupFindings()` runs to create/update parent threats
- Grouping happens after all findings for a job are processed — enables cross-host CVE grouping since all hosts are known

**Scoring formula**
- Contextual score = base severity (40%) × asset criticality (25%) × exposure context (20%) × compensating controls (15%)
- Score scale: 0-100 (100 = no threats, 0 = worst possible)
- Asset criticality: Domain Controller = critical (1.5x), Server/Firewall/Router = high (1.2x), Desktop/Workstation = standard (1.0x). Uses existing hostType
- Confirmed exploitability: 1.3x multiplier when nmap vuln scripts or nuclei confirm exploitability (THRT-09)
- Exposure context: Attack Surface = external (1.3x), AD Security = internal (1.0x), EDR/AV = endpoint (0.9x)
- Compensating controls (v1): EDR status as proxy — host passed EICAR test = 0.85x reduction, not tested or failed = 1.0x

**Score persistence**
- Score computed and stored at journey completion time (after grouping)
- `contextual_score` (numeric) and `score_breakdown` (JSONB) stored on each threat record
- `projected_score_after_fix` computed via subtract-and-recompute

**Posture snapshots**
- One `posture_snapshots` row written per completed job
- Dashboard reads posture_snapshots for trend sparkline
- Snapshot tied to specific job/journey for audit trail

**Simulate API**
- `POST /api/posture/simulate` with body `{ threatIds: ['id1', 'id2'] }` returns projected score if all listed threats are fixed
- Supports multi-threat batch simulation

### Claude's Discretion
- Exact grouping key format strings (e.g., `grp:as:host:admin` vs `group:attack_surface:host:admin`)
- Score normalization algorithm (how raw weighted scores map to 0-100 scale)
- posture_snapshots table schema details (columns, indexes)
- Internal helper function decomposition within scoringEngine.ts and groupFindings()
- How to efficiently query EDR test results for compensating controls factor
- Order of operations within the post-processing step

### Deferred Ideas (OUT OF SCOPE)
None — discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| THRT-01 | Related findings on the same host are consolidated into parent threat groups | Grouping engine section; parent-child schema migration pattern |
| THRT-02 | Grouping keys vary by journey type: host+serviceFamily, cveId, adCheckCategory, hostId | SERVICE_CATEGORIES map reuse; computeCorrelationKey pattern |
| THRT-03 | Parent threat severity equals highest severity among child findings | Drizzle aggregate query pattern; severity enum ordering |
| THRT-04 | Parent threat status is open if any child finding is open | Status derivation logic; aggregate child status query |
| THRT-05 | Existing correlation key format and stored threat history preserved | additive-only migration; parentThreatId nullable foreign key |
| THRT-06 | Contextual scoring weights base severity (40%), asset criticality (25%), exposure context (20%), controls (15%) | Scoring engine formula; normalization pattern |
| THRT-07 | Score breakdown stored as JSONB at persistence time | JSONB column pattern (evidence column already used this way) |
| THRT-08 | Host type (DC, server, workstation) factors into asset criticality multiplier | hostType enum; existing host enrichment data |
| THRT-09 | Confirmed exploitability increases score via multiplier | evidence.detectionMethod field; nmap_vuln type flag |
| THRT-10 | Each threat group has projected score impact | subtract-and-recompute posture simulation; posture_snapshots table |
</phase_requirements>

---

## Summary

Phase 2 extends the existing `ThreatEngineService` with two new capabilities layered on top of the current flat-threat upsert flow: a grouping engine that clusters child threats under parent threats, and a contextual scoring engine that computes weighted severity scores and persists them. Both capabilities are post-processing steps that run after `analyzeWithLifecycle()` completes — the existing correlation key flow for child threats is untouched (THRT-05 is preserved by design).

The codebase is well-prepared for this phase. `SERVICE_CATEGORIES` already classifies ports into the exact categories needed for Attack Surface grouping keys. The `computeCorrelationKey()` method already encodes the per-journey-type pattern for child threats — grouping keys are a parallel, coarser-grained version of the same concept applied at the parent level. The `evidence` JSONB column pattern is already established on the threats table and is the direct model for `score_breakdown`. The `hosts.type` enum already has `'domain'` as a value, enabling Domain Controller detection for criticality multipliers without any new data collection.

The primary challenge in this phase is schema migration (additive-only, no breaking changes), correct parent upsert semantics (idempotent grouping across re-runs), and numeric score normalization. The migrate-via-`db:push` pattern is established; `drizzle-kit push` applies all schema changes declared in `shared/schema.ts` directly to the running PostgreSQL database, and `database-init.ts` handles bootstrapping structural requirements that cannot be expressed as schema declarations.

**Primary recommendation:** Add `parentThreatId` and scoring columns to `threats` in `shared/schema.ts`, create `posture_snapshots` and `recommendations` tables, implement `groupFindings()` and `ScoringEngine` as TypeScript classes following the existing `ThreatEngineService` singleton pattern, and hook both into `processJobResults()` after the existing `runJourneyPostProcessing()` call.

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| drizzle-orm | ^0.39.1 | ORM + query builder for PostgreSQL | Already in use; all existing storage ops use it |
| drizzle-kit | ^0.31.9 | Schema migration via `db:push` | Already configured in `drizzle.config.ts` |
| zod | ^3.24.2 | Runtime schema validation | Already used for all Zod schemas in `shared/schema.ts` |
| drizzle-zod | ^0.7.0 | Auto-generates Zod insert schemas from Drizzle table defs | Already used for `insertThreatSchema` etc. |
| typescript | 5.6.3 | Type safety | Project standard |
| vitest | ^4.0.18 | Test framework | Already configured in `vitest.config.ts` |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| pino (via createLogger) | ^10.3.1 | Structured logging | All new service files must use `createLogger('scoringEngine')` pattern |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `db:push` for schema changes | Manual SQL migrations | Push is faster and idempotent for this codebase; raw SQL needed only for non-declarable constraints (as seen in `database-init.ts`) |
| JSONB for score_breakdown | Separate score_components table | JSONB is already established via `evidence` column; separate table adds joins without benefit at this scale |

**No new npm dependencies required for this phase.**

---

## Architecture Patterns

### Recommended Project Structure
```
server/
├── services/
│   ├── threatEngine.ts       # Extend: add groupFindings() method + call scoringEngine
│   └── scoringEngine.ts      # NEW: ScoringEngineService singleton class
├── storage/
│   └── threats.ts            # Extend: upsertParentThreat(), getChildThreats(), updateThreatScore()
│   └── posture.ts            # NEW: writePostureSnapshot(), getPostureHistory()
└── routes/
    └── dashboard.ts          # Extend: add POST /api/posture/simulate endpoint
shared/
└── schema.ts                 # Extend: threats columns + posture_snapshots + recommendations tables
```

### Pattern 1: Additive Schema Migration (Drizzle `db:push`)
**What:** New columns added to existing tables with `.default()` or nullable — never dropping or renaming existing columns.
**When to use:** All schema changes in this phase.

```typescript
// In shared/schema.ts — additive columns on threats table
export const threats = pgTable("threats", {
  // ... all existing columns preserved verbatim ...

  // Phase 2 additions — all nullable/defaulted so existing rows are unaffected
  parentThreatId: varchar("parent_threat_id").references((): any => threats.id), // self-referential FK
  contextualScore: real("contextual_score"),          // null until scoring engine runs
  scoreBreakdown: jsonb("score_breakdown").$type<{    // null until scoring engine runs
    baseSeverityWeight: number;
    criticalityMultiplier: number;
    exposureFactor: number;
    controlsReductionFactor: number;
    rawScore: number;
    normalizedScore: number;
  }>(),
  projectedScoreAfterFix: real("projected_score_after_fix"), // null until scoring engine runs
  groupingKey: text("grouping_key"),                 // null for ungrouped (child) threats, set for parents
});
```

**Key constraint:** `parentThreatId` is a nullable self-referential foreign key. In Drizzle, circular references require the `(): any => threats.id` pattern (lambda to avoid initialization order issues).

### Pattern 2: Parent Threat Upsert (Idempotent Grouping)
**What:** Each `groupFindings()` call must be safe to re-run on the same job. Parent threats are upserted by `groupingKey`, not created on every run.
**When to use:** `groupFindings()` implementation.

```typescript
// Grouping key format (Claude's discretion — recommend compact prefixed format)
// Attack Surface service group: "grp:as:{host}:{serviceCategory}"
// Attack Surface CVE group:     "grp:as:cve:{cveId}"
// AD Security group:            "grp:ad:{adCheckCategory}:{domain}"
// EDR/AV group:                 "grp:edr:{hostId}"

async function upsertParentThreat(
  groupingKey: string,
  data: InsertThreat
): Promise<{ threat: Threat; isNew: boolean }> {
  // Use same onConflictDoUpdate pattern as upsertThreat()
  const [threat] = await db
    .insert(threats)
    .values({ ...data, groupingKey })
    .onConflictDoUpdate({
      target: threats.groupingKey,          // requires unique index on grouping_key
      set: {
        severity: data.severity,            // Re-derive highest child severity
        status: data.status,               // Re-derive from children
        updatedAt: new Date(),
      },
    })
    .returning();
  return { threat, isNew: threat.createdAt === threat.updatedAt };
}
```

**Note:** A partial unique index on `grouping_key WHERE grouping_key IS NOT NULL` is needed — same pattern as the existing `UQ_threats_correlation_key` partial unique index. This should be declared in the schema table definition and bootstrapped via `database-init.ts` if needed.

### Pattern 3: Class-Based Singleton Service
**What:** All new service logic lives in a named class with a single exported instance.
**When to use:** `scoringEngine.ts`

```typescript
// Source: existing ThreatEngineService pattern in server/services/threatEngine.ts
class ScoringEngineService {
  private readonly log = createLogger('scoringEngine');

  computeContextualScore(threat: Threat, host: Host | null): ScoreBreakdown {
    // ...
  }

  async scoreAllThreatsForJob(jobId: string): Promise<void> {
    // ...
  }
}

export const scoringEngine = new ScoringEngineService();
```

### Pattern 4: JSONB Column for Structured Sub-data
**What:** Store typed structured data in a JSONB column using Drizzle's `.$type<T>()` generic annotation.
**When to use:** `score_breakdown` column — mirrors existing `evidence` column pattern.

```typescript
// Source: threats.evidence column declaration in shared/schema.ts (line 264)
scoreBreakdown: jsonb("score_breakdown").$type<ScoreBreakdownRecord>(),

// Query: Drizzle returns it as typed T automatically
const { scoreBreakdown } = await db.select({ scoreBreakdown: threats.scoreBreakdown })
  .from(threats).where(eq(threats.id, id));
// scoreBreakdown is typed as ScoreBreakdownRecord | null
```

### Pattern 5: Post-Processing Hook in processJobResults()
**What:** The existing `processJobResults()` method in `threatEngine.ts` is the correct integration point. New capabilities hook in after the current `runJourneyPostProcessing()` call.
**When to use:** Calling `groupFindings()` and `scoringEngine.scoreAllThreatsForJob()`.

```typescript
// Current structure in threatEngine.ts:
async processJobResults(jobId: string): Promise<Threat[]> {
  // ... existing setup ...
  const threats = await this.analyzeWithLifecycle(findings, journey.type, job.journeyId, jobId);
  await this.runJourneyPostProcessing(journey.type, job.journeyId, jobId, findings);
  // Phase 2: add after runJourneyPostProcessing
  await this.groupFindings(jobId, journey.type);
  await scoringEngine.scoreAllThreatsForJob(jobId);
  await scoringEngine.writePostureSnapshot(jobId, job.journeyId);
  return threats;
}
```

### Pattern 6: Severity Ordering for Max-Severity Derivation
**What:** PostgreSQL enum values have a declared order. Use explicit mapping for severity comparison in TypeScript.
**When to use:** Deriving parent severity from children (THRT-03).

```typescript
const SEVERITY_RANK: Record<string, number> = {
  low: 1, medium: 2, high: 3, critical: 4
};

function highestSeverity(severities: string[]): 'low' | 'medium' | 'high' | 'critical' {
  return severities.reduce((max, s) =>
    SEVERITY_RANK[s] > SEVERITY_RANK[max] ? s : max
  ) as 'low' | 'medium' | 'high' | 'critical';
}
```

### Anti-Patterns to Avoid
- **Re-creating parent threats on every job run:** Grouping key upsert must use `onConflictDoUpdate` — same technique as `upsertThreat()`. Creating duplicate parents breaks correlation history (THRT-05 violation).
- **Recomputing score at display time:** Score must be persisted to `contextual_score` and `score_breakdown` columns at journey completion. Never compute on the fly in GET endpoints (THRT-07 requirement).
- **Changing `correlationKey` on child threats:** Child threats keep their existing `as:svc:host:port` style correlation keys. The `groupingKey` is a separate column only set on parent records.
- **Breaking the `analyzeWithLifecycle()` flow:** The existing upsert flow for child threats must run unchanged before `groupFindings()`. The grouping layer reads completed child threats, it does not replace the child creation flow.
- **Self-referential FK without lambda:** `threats.id` referenced from `threats.parentThreatId` in the same table definition requires `(): any => threats.id` syntax in Drizzle — using a direct reference causes a circular initialization error.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Schema migration | Custom SQL ALTER TABLE scripts | `drizzle-kit push` (existing `db:push` npm script) | Already configured; handles column additions, type changes, and index creation idempotently |
| JSONB typed columns | Manual JSON.stringify/parse | Drizzle `jsonb().$type<T>()` | Type-safe at compile time; no serialization boilerplate |
| Unique constraint enforcement | Application-level uniqueness check | PostgreSQL partial unique index (same as `UQ_threats_correlation_key`) | DB-level enforcement is atomic and race-condition-safe |
| Zod schema for new table inserts | Hand-written validation | `createInsertSchema(posture_snapshots)` from drizzle-zod | Auto-derives from table columns; stays in sync automatically |
| Score aggregation query | JavaScript array reduce in memory | Single `SELECT MAX(severity), COUNT(*) FROM threats WHERE parent_threat_id = $1` query | Single round-trip; handles large datasets correctly |

**Key insight:** This codebase already has all infrastructure patterns established. The work is connecting existing patterns (JSONB evidence, onConflict upsert, singleton services, `createLogger`) to new business logic — not building new infrastructure.

---

## Common Pitfalls

### Pitfall 1: Self-Referential Foreign Key Circular Reference
**What goes wrong:** TypeScript error or Drizzle initialization failure when `parentThreatId` references the `threats` table from within the `threats` table definition.
**Why it happens:** Drizzle evaluates table definitions at module load time; the `threats` variable isn't initialized yet when the column definition references it.
**How to avoid:** Use the lambda/thunk pattern: `.references((): any => threats.id)` — the arrow function defers evaluation until after module initialization completes.
**Warning signs:** TypeScript compilation error mentioning "Block-scoped variable used before its declaration" or runtime `ReferenceError: Cannot access 'threats' before initialization`.

### Pitfall 2: Parent Threat `groupingKey` Unique Index — Same Bootstrap Problem as `correlationKey`
**What goes wrong:** `onConflictDoUpdate` on `groupingKey` fails with `ERROR: there is no unique or exclusion constraint matching the ON CONFLICT specification` on first deploy to an environment where `db:push` hasn't been run.
**Why it happens:** The partial unique index must exist in PostgreSQL before `onConflictDoUpdate` can target it. If schema push hasn't run, the index doesn't exist yet.
**How to avoid:** Add the index to `schema.ts` (Drizzle will create it on push). Also add a check-and-create guard in `database-init.ts` `initializeDatabaseStructure()` — mirroring the existing `UQ_threats_correlation_key` bootstrap pattern — for environments where schema push isn't re-run on upgrade.
**Warning signs:** `42P10` PostgreSQL error code (same error as the existing `correlationKey` fallback in `upsertThreat()`).

### Pitfall 3: EDR Compensating Controls Query — Cross-Journey Data Access
**What goes wrong:** When scoring an Attack Surface threat, EDR test results for that host live in a different job/journey's artifacts. A naive query for "did this host pass EICAR?" that only looks at the current job will always return "not tested" (1.0x — no reduction).
**Why it happens:** EDR/AV findings are stored in `job_results.artifacts.findings` for EDR/AV journey jobs. Attack Surface threats don't have direct access to EDR results.
**How to avoid:** Query `job_results` for the most recent EDR/AV job that includes the target hostname, or query the threat table for closed EDR threats matching the host (a closed `edr:hostname:eicar_test` correlation key means it passed). Recommendation: query `threats` table for `category = 'edr_av'` and `status = 'closed'` and `correlationKey LIKE 'edr:hostname:%'` — this is simpler than parsing job artifacts and uses already-indexed data.
**Warning signs:** All hosts always getting `controlsFactor = 1.0` (no EDR reduction applied).

### Pitfall 4: Score Normalization — Division by Zero and Boundary Conditions
**What goes wrong:** When there are no open threats or no hosts, the posture score calculation produces `NaN`, `Infinity`, or negative values.
**Why it happens:** Raw weighted score aggregation divides by threat count or host count; both can be zero on a fresh install.
**How to avoid:** Guard with explicit zero-threat case: if `openThreatCount === 0`, return `score = 100`. If all threats are closed/mitigated, posture is perfect. Also clamp final score to `Math.max(0, Math.min(100, score))`.
**Warning signs:** Dashboard showing `NaN%` or `Infinity` posture score.

### Pitfall 5: Parent Status Derivation — Status Enum Coverage
**What goes wrong:** Parent status logic that checks `status === 'closed'` misses threats in `status === 'accepted_risk'` or `status === 'hibernated'`, causing parents to remain `open` when all children are resolved.
**Why it happens:** The threat status enum has 6 values: `open | investigating | mitigated | closed | hibernated | accepted_risk`. "Resolved" states include `mitigated`, `closed`, and `accepted_risk`.
**How to avoid:** Define explicit sets: `ACTIVE_STATUSES = new Set(['open', 'investigating'])` and `INACTIVE_STATUSES = new Set(['mitigated', 'closed', 'hibernated', 'accepted_risk'])`. Parent is open if `children.some(c => ACTIVE_STATUSES.has(c.status))`.
**Warning signs:** Parent threats remaining `open` after all children are marked `accepted_risk`.

### Pitfall 6: `db:push` Drops Columns on Schema Simplification
**What goes wrong:** Running `drizzle-kit push` on a schema where an existing column is removed causes the column to be dropped in PostgreSQL, destroying existing data.
**Why it happens:** `drizzle-kit push` performs structural diffing and will issue `ALTER TABLE ... DROP COLUMN` for columns in the database not present in the schema.
**How to avoid:** Only add columns in Phase 2 — never remove any existing column from `threats` table. The constraint "additive only" is a project-wide decision (confirmed in STATE.md). If a column must be removed later, that requires a separate controlled migration, not a schema removal.
**Warning signs:** `drizzle-kit push` output showing "column dropped" in the diff preview.

---

## Code Examples

Verified patterns from existing codebase:

### Drizzle JSONB typed column (threats.evidence pattern)
```typescript
// Source: shared/schema.ts line 264
evidence: jsonb("evidence").$type<Record<string, any>>().default({}).notNull(),

// For score_breakdown — typed interface version:
scoreBreakdown: jsonb("score_breakdown").$type<{
  baseSeverityWeight: number;
  criticalityMultiplier: number;
  exposureFactor: number;
  controlsReductionFactor: number;
  rawScore: number;
  normalizedScore: number;
}>(),
```

### onConflictDoUpdate upsert pattern (existing upsertThreat)
```typescript
// Source: server/storage/threats.ts line 390
const [newThreat] = await db
  .insert(threats)
  .values({ ...threat, lastSeenAt: threat.lastSeenAt || new Date() })
  .onConflictDoUpdate({
    target: threats.correlationKey,
    set: {
      status: sql`'open'`,
      lastSeenAt: threat.lastSeenAt || new Date(),
      updatedAt: new Date(),
      evidence: threat.evidence,
    },
  })
  .returning();
```

### Partial unique index declaration in Drizzle schema
```typescript
// Source: shared/schema.ts line 281 — UQ_threats_correlation_key
uniqueIndex("UQ_threats_correlation_key")
  .on(table.correlationKey)
  .where(sql`correlation_key IS NOT NULL AND (status != 'closed' OR closure_reason != 'duplicate')`),

// For grouping_key — simpler partial index:
uniqueIndex("UQ_threats_grouping_key")
  .on(table.groupingKey)
  .where(sql`grouping_key IS NOT NULL`),
```

### SERVICE_CATEGORIES reuse for grouping key derivation
```typescript
// Source: server/services/threatEngine.ts line 81 — classifyServiceCategory()
// The existing classifyServiceCategory() method returns { category, label, severity }
// groupFindings() for Attack Surface reuses this directly:
const cat = this.classifyServiceCategory(childThreat.evidence.port, childThreat.evidence.service);
const groupingKey = `grp:as:${normalizeHost(childThreat.evidence.host)}:${cat.category}`;
```

### Database-init bootstrap for structural index creation
```typescript
// Source: server/storage/database-init.ts line 17-44 — UQ_threats_correlation_key bootstrap
// Pattern for any index that must exist before onConflictDoUpdate can use it:
const indexCheck = await db.execute(sql`
  SELECT indexname FROM pg_indexes
  WHERE tablename = 'threats' AND indexname = 'UQ_threats_grouping_key'
`);
if ((indexCheck.rowCount ?? 0) === 0) {
  await db.execute(sql`
    CREATE UNIQUE INDEX "UQ_threats_grouping_key"
    ON threats (grouping_key) WHERE grouping_key IS NOT NULL
  `);
}
```

### Drizzle self-referential FK (lambda pattern)
```typescript
// Pattern for self-referential column:
parentThreatId: varchar("parent_threat_id").references((): any => threats.id),
```

### Query children for parent status/severity derivation
```typescript
// Drizzle aggregate pattern for deriving parent attributes:
const children = await db
  .select({ severity: threats.severity, status: threats.status })
  .from(threats)
  .where(eq(threats.parentThreatId, parentId));

const maxSeverity = highestSeverity(children.map(c => c.severity));
const isAnyChildOpen = children.some(c => ['open', 'investigating'].includes(c.status));
const derivedStatus: ThreatStatus = isAnyChildOpen ? 'open' : 'mitigated';
```

### Recommended posture_snapshots table schema
```typescript
export const postureSnapshots = pgTable("posture_snapshots", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  jobId: varchar("job_id").references(() => jobs.id).notNull(),
  journeyId: varchar("journey_id").references(() => journeys.id).notNull(),
  score: real("score").notNull(),                 // 0-100
  openThreatCount: integer("open_threat_count").notNull(),
  criticalCount: integer("critical_count").notNull().default(0),
  highCount: integer("high_count").notNull().default(0),
  mediumCount: integer("medium_count").notNull().default(0),
  lowCount: integer("low_count").notNull().default(0),
  scoredAt: timestamp("scored_at").defaultNow().notNull(),
}, (table) => [
  index("IDX_posture_snapshots_job_id").on(table.jobId),
  index("IDX_posture_snapshots_journey_id").on(table.journeyId),
  index("IDX_posture_snapshots_scored_at").on(table.scoredAt),
]);
```

### Simulate endpoint pattern (Express route)
```typescript
// POST /api/posture/simulate
// Body: { threatIds: string[] }
// Response: { currentScore: number, projectedScore: number, delta: number }
app.post('/api/posture/simulate', isAuthenticatedWithPasswordCheck, async (req, res) => {
  const { threatIds } = req.body;
  // Load all open threats, filter out threatIds, recompute posture
  const allOpenThreats = await storage.getThreats({ status: 'open' });
  const remainingThreats = allOpenThreats.filter(t => !threatIds.includes(t.id));
  const currentScore = computePostureFromThreats(allOpenThreats);
  const projectedScore = computePostureFromThreats(remainingThreats);
  res.json({ currentScore, projectedScore, delta: projectedScore - currentScore });
});
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Flat threat list (one threat per finding) | Parent-child grouped threats | Phase 2 | Reduces noise; groups 3 open admin ports as 1 "Exposed Administration Services" parent |
| Raw CVSS-only severity | Contextual score (host criticality + exposure + controls) | Phase 2 | DC with RDP exposed scores higher than workstation with same service |
| Risk computed at display time from raw host.riskScore | Score persisted on threat record at job completion | Phase 2 | THRT-07: display never recomputes; audit trail preserved |
| `posture_score` computed ad-hoc from host_risk_history | `posture_snapshots` per completed job | Phase 2 | Dashboard trend becomes job-granular, not just daily average |

**Existing behavior preserved:**
- `analyzeWithLifecycle()` continues to create/upsert child threats with existing `correlationKey` format
- `computeCorrelationKey()` format strings unchanged
- `runJourneyPostProcessing()` auto-closure logic unchanged
- `recalculateHostRiskScore()` continues to run per child threat (hosts retain their risk scores)

---

## Open Questions

1. **`recommendations` table — empty in Phase 2 or with stub schema?**
   - What we know: CONTEXT.md mentions creating a `recommendations` table in plan 02-01. Phase 3 (REMD-01 to REMD-07) defines the full remediation content.
   - What's unclear: Whether Phase 2 should create the table with full Phase 3 columns (to avoid a second migration later) or just create a minimal stub.
   - Recommendation: Create the full `recommendations` table schema in Phase 2 with all columns Phase 3 will need (threatId FK, templateId, effortTag, roleRequired, etc.) — but leave it unpopulated. Avoids a Phase 3 schema migration. Planner should include this as a task in plan 02-01.

2. **Web Application journey grouping key for nuclei templates**
   - What we know: STATE.md flags "Grouping key strategy for Web Application journey needs validation against real scan output before THRT-02 implementation" as a concern.
   - What's unclear: Whether nuclei template tags or templateId cluster naturally into meaningful parent groups.
   - Recommendation: Plan 02-02 should implement Web Application grouping as `grp:wa:{host}:{templateTag}` using nuclei template tags (e.g., `cve`, `sqli`, `xss`). Flag this as a LOW-confidence area in plan 02-02 that should be validated against real scan output before merging.

3. **Score normalization algorithm**
   - What we know: Scoring formula weights are locked. Scale is 0-100.
   - What's unclear: Exact formula for mapping raw weighted scores to the 0-100 posture scale.
   - Recommendation: Use threat-count-weighted severity normalization: `postureScore = 100 - (sum of contextual_scores / maxPossibleScore * 100)` where `maxPossibleScore = threatCount * 100`. When `threatCount = 0`, `postureScore = 100`. This matches the existing `100 - avgRisk` pattern already used in `dashboard.ts` `/api/posture/score`.

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Vitest ^4.0.18 |
| Config file | `vitest.config.ts` (project root) |
| Quick run command | `npm test -- --reporter=verbose` |
| Full suite command | `npm test` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| THRT-01 | 3 open admin ports on same host produce 1 parent threat | unit | `npm test -- --reporter=verbose server/__tests__/threatGrouping.test.ts` | Wave 0 |
| THRT-02 | Grouping keys vary by journey type | unit | same file | Wave 0 |
| THRT-03 | Parent severity = max child severity | unit | `npm test -- server/__tests__/threatGrouping.test.ts` | Wave 0 |
| THRT-04 | Parent open if any child open; parent mitigated if all mitigated | unit | same file | Wave 0 |
| THRT-05 | Existing correlation keys unchanged after grouping | unit (snapshot) | `npm test -- server/__tests__/threatRuleSnapshots.test.ts` | Exists |
| THRT-06 | Score = base×0.4 + criticality×0.25 + exposure×0.2 + controls×0.15 | unit | `npm test -- server/__tests__/scoringEngine.test.ts` | Wave 0 |
| THRT-07 | score_breakdown stored as JSONB (verified via schema shape test) | unit | same file | Wave 0 |
| THRT-08 | DC host gets 1.5x multiplier; workstation gets 1.0x | unit | same file | Wave 0 |
| THRT-09 | nmap_vuln finding gets 1.3x exploitability multiplier | unit | same file | Wave 0 |
| THRT-10 | projectedScoreAfterFix reflects posture delta | unit | `npm test -- server/__tests__/scoringEngine.test.ts` | Wave 0 |

### Sampling Rate
- **Per task commit:** `npm test -- server/__tests__/threatRuleSnapshots.test.ts` (existing snapshots stay green)
- **Per wave merge:** `npm test` (full suite)
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `server/__tests__/threatGrouping.test.ts` — covers THRT-01, THRT-02, THRT-03, THRT-04; mock storage pattern from `threatRuleSnapshots.test.ts` (vi.mock('../db'), vi.mock('../storage'))
- [ ] `server/__tests__/scoringEngine.test.ts` — covers THRT-06, THRT-07, THRT-08, THRT-09, THRT-10; pure function tests, no DB dependency
- [ ] No new framework installs required — Vitest already configured

---

## Sources

### Primary (HIGH confidence)
- Direct codebase inspection: `server/services/threatEngine.ts` — full ThreatEngineService class, SERVICE_CATEGORIES, computeCorrelationKey(), analyzeWithLifecycle(), processJobResults()
- Direct codebase inspection: `shared/schema.ts` — threats table columns, existing JSONB evidence pattern, partial unique index declaration, enum types, relations
- Direct codebase inspection: `server/storage/threats.ts` — upsertThreat() onConflictDoUpdate pattern, upsertThreat() error fallback for 42P10
- Direct codebase inspection: `server/storage/database-init.ts` — structural index bootstrap pattern (UQ_threats_correlation_key)
- Direct codebase inspection: `server/routes/dashboard.ts` — existing /api/posture/score computation pattern
- Direct codebase inspection: `drizzle.config.ts` — migration configuration (`out: "./migrations"`, `dialect: "postgresql"`)
- Direct codebase inspection: `vitest.config.ts` — test framework configuration
- Direct codebase inspection: `.planning/config.json` — `workflow.nyquist_validation: true`

### Secondary (MEDIUM confidence)
- Direct codebase inspection: `server/services/hostService.ts` — hostType enum values including `'domain'` for DC detection; `determineHostType()` logic
- Direct codebase inspection: `server/services/scanners/edrAvScanner.ts` — EDR finding shape (`eicarRemoved`, `hostname` fields)
- Direct codebase inspection: `server/__tests__/threatRuleSnapshots.test.ts` — test mocking pattern (`vi.mock('../db')`, `vi.mock('../storage')`)

### Tertiary (LOW confidence)
- None — all findings verified directly from codebase

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — verified against package.json and all imports in existing files
- Architecture patterns: HIGH — derived directly from existing code patterns in threatEngine.ts and storage/threats.ts
- Pitfalls: HIGH — pitfalls 1, 2, 6 are verified against actual existing workarounds in the codebase (lambda FK pattern, 42P10 catch block, db:push additive-only constraint in STATE.md)

**Research date:** 2026-03-16
**Valid until:** 2026-04-16 (stable codebase; dependencies are locked versions)
