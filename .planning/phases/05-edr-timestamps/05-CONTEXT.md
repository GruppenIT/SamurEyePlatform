# Phase 5: EDR Timestamps - Context

**Gathered:** 2026-03-17
**Status:** Ready for planning

<domain>
## Phase Boundary

EDR findings surface per-host deployment and detection timestamps in structured, queryable form. Covers adding explicit timestamp fields to EdrFinding (PARS-09) and a dedicated database table for per-host EDR deployment metadata (PARS-10). No new scanner capabilities, no UI changes, no new journey types.

</domain>

<decisions>
## Implementation Decisions

### Timestamp derivation
- `deploymentTimestamp` = timestamp of the first `deploy_success` timeline event. Null if deployment failed.
- `detectionTimestamp` = timestamp of the `detected` timeline event (EICAR removed by EDR/AV). Null when `not_detected` or `timeout` — meaning no detection occurred.
- Both fields computed at parse time in `testSingleHost()` and stored on `EdrFinding` — not derived on-the-fly during reads.
- Add `deploymentTimestamp` and `detectionTimestamp` as optional string fields to `EdrFindingSchema`.

### Database table design
- Table name: `edr_deployments`
- Rich metadata columns: `id`, `hostId` (FK to hosts), `journeyId` (FK to journeys), `jobId` (FK to jobs), `deploymentTimestamp`, `detectionTimestamp`, `deploymentMethod`, `detected` (boolean, nullable), `testDuration`, `createdAt`
- One row per test — re-scans of the same host create new rows, building a history
- Foreign key to `hosts` table for referential integrity and JOINs with host details

### Data population strategy
- Insert into `edr_deployments` during scan execution, right after each host test completes in `EDRAVScanner`
- No backfill from existing JSONB artifacts — only new scans populate the table
- Failed deployments also get a row with null `deploymentTimestamp` and null `detectionTimestamp` — gives complete visibility into what was attempted
- Migration is additive: CREATE TABLE only, no existing data modified

### Query patterns
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

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements
- `.planning/REQUIREMENTS.md` — PARS-09 (timestamp fields) and PARS-10 (queryable table) definitions

### Schema and types
- `shared/schema.ts` lines 1204-1239 — `EdrTimelineEventSchema`, `EdrFindingSchema`, `EdrFinding` type definitions
- `shared/schema.ts` lines 193-200 — `jobResults` table (current JSONB artifacts storage)
- `shared/schema.ts` lines 202-210 — `hosts` table (FK target for edr_deployments)
- `shared/schema.ts` lines 266-305 — `threats` table (example of additive schema with indexes and FKs)

### Scanner implementation
- `server/services/scanners/edrAvScanner.ts` lines 199-378 — `testSingleHost()` method where timestamps are derived and DB insert will happen

### Test fixtures
- `server/__tests__/edrParser.test.ts` — existing EDR parser tests covering schema validation and fixture parsing
- `server/__tests__/fixtures/edr/detection-success.json` — fixture with deploy_success + detected timeline
- `server/__tests__/fixtures/edr/detection-failure.json` — fixture with not_detected timeline
- `server/__tests__/fixtures/edr/timeout-error.json` — fixture with timeout timeline

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `EdrFindingSchema` (shared/schema.ts): Already has timeline array — extend with deploymentTimestamp/detectionTimestamp optional fields
- `EdrTimelineEventSchema`: Defines the 6 action types used for timestamp derivation logic
- `BaseFindingSchema`: Base schema that EdrFindingSchema extends — has target, severity
- Drizzle ORM table definitions: Follow existing patterns in shared/schema.ts for table definition, FKs, indexes

### Established Patterns
- Additive schema changes only (PROJECT.md constraint) — CREATE TABLE, no ALTER on existing tables
- Zod `.strip()` on finding schemas — unknown fields stripped, new optional fields are backward-compatible
- `storage/journeys.ts`: Pattern for inserting job results — similar pattern for edr_deployments insert
- Scan execution flow: `EDRAVScanner.testSingleHost()` returns `EdrFinding` — insert happens here

### Integration Points
- `server/services/scanners/edrAvScanner.ts` `testSingleHost()` — where deploymentTimestamp/detectionTimestamp are computed and edr_deployments row is inserted
- `server/routes/journeys.ts` — where edr_deployments data will be exposed via existing endpoints
- `shared/schema.ts` — where new table definition and updated EdrFindingSchema live

</code_context>

<specifics>
## Specific Ideas

No specific requirements — open to standard approaches

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 05-edr-timestamps*
*Context gathered: 2026-03-17*
