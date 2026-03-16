---
phase: 02-threat-engine-intelligence
plan: 02
subsystem: threat-engine
tags: [grouping, parent-child, threat-hierarchy, tdd]
dependency_graph:
  requires: [02-01]
  provides: [groupFindings, upsertParentThreat, linkChildToParent, getChildThreats, deriveParentAttributes]
  affects: [processJobResults, threat-storage]
tech_stack:
  added: []
  patterns: [parent-child-upsert, grouping-key-routing, tdd-red-green]
key_files:
  created:
    - server/__tests__/threatGrouping.test.ts
  modified:
    - server/storage/threats.ts
    - server/services/threatEngine.ts
decisions:
  - "Grouping key uses grp: prefix to distinguish from correlationKey (as:/ad:/edr: namespaces)"
  - "groupFindings() queries ungrouped threats by jobId+isNull(parentThreatId) to be idempotent"
  - "normalizeHost extracted to private class method to share between computeCorrelationKey and computeGroupingKeyForThreat"
  - "Array.from(groups) used for Map iteration due to TS target compatibility requirement"
  - "Parent title derived in Portuguese (matching existing threat title language convention)"
metrics:
  duration_seconds: 12056
  completed_date: "2026-03-16"
  tasks_completed: 2
  files_changed: 3
  tests_added: 23
---

# Phase 2 Plan 02: Threat Grouping Engine Summary

**One-liner:** Parent-child threat hierarchy via journey-specific grouping keys with upsert-based idempotent parent creation.

## What Was Built

The threat grouping engine clusters child threats under parent records, transforming the flat threat list into a parent-child hierarchy. Three admin ports on the same host (SSH/RDP/VNC) now produce a single parent "Serviços Administração Expostos" with 3 child findings instead of 3 unrelated records.

### Storage Operations (`server/storage/threats.ts`)

- **`upsertParentThreat()`** — inserts or updates a parent threat using `onConflictDoUpdate` on `groupingKey`. Includes 42P10 fallback for environments without the partial unique index.
- **`linkChildToParent()`** — sets `parentThreatId` on a child. Never touches `correlationKey` (THRT-05 invariant).
- **`getChildThreats()`** — queries all threats with a given `parentThreatId`.
- **`deriveParentAttributes()`** — computes highest severity and aggregate status from children (used by future re-scoring).
- **`SEVERITY_RANK`** and **`ACTIVE_STATUSES`** module-level constants.

### Threat Engine (`server/services/threatEngine.ts`)

- **`normalizeHost()`** — extracted from closure inside `computeCorrelationKey` to a private class method.
- **`computeGroupingKeyForThreat()`** — journey-specific grouping key router:
  - `attack_surface`: `grp:as:cve:{CVE}` for CVE findings, `grp:as:{host}:{serviceCategory}` for ports
  - `ad_security`: `grp:ad:{adCheckCategory}:{domain}`
  - `edr_av`: `grp:edr:{hostId}`
  - `web_application`: `grp:wa:{host}:{tag}`
- **`deriveParentTitle()`** — human-readable parent titles from grouping key segments.
- **`deriveGroupSeverity()`** — highest severity among children.
- **`deriveGroupStatus()`** — `open` if any child is active, `mitigated` if all inactive.
- **`groupFindings(jobId, journeyType)`** — main orchestrator: queries ungrouped threats, buckets by key, upserts parents, links children.
- **`processJobResults()`** — wired: calls `groupFindings()` after `runJourneyPostProcessing()`.

### Tests (`server/__tests__/threatGrouping.test.ts`)

23 unit tests covering THRT-01 through THRT-05:
- THRT-01: 3 admin ports on same host → same grouping key
- THRT-02: Grouping key format by journey type (6 cases)
- THRT-03: Parent severity = highest child severity (4 cases)
- THRT-04: Parent status derivation (4 cases)
- THRT-05: Child correlationKeys unchanged
- Idempotency assertion (upsert pattern)
- All 4 storage function exports verified

## Decisions Made

1. **`grp:` prefix** distinguishes grouping keys from correlation keys (`as:/ad:/edr:` namespaces) — prevents any accidental overlap.
2. **Idempotency via jobId filter** — `groupFindings()` only fetches threats where `parentThreatId IS NULL` for this jobId, so re-runs skip already-grouped threats without creating duplicate parents.
3. **`normalizeHost` extracted** — the closure pattern inside `computeCorrelationKey` was refactored to a private method shared with `computeGroupingKeyForThreat`. `computeCorrelationKey` itself was NOT modified (per plan constraint).
4. **`Array.from(groups)` for Map iteration** — TS target does not support `for...of` on Map directly; `Array.from()` resolves the TS2802 error.
5. **Portuguese parent titles** — matches the existing convention in `createThreat` threat titles throughout the engine.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Schema and storage already committed by prior session**
- **Found during:** Task 1 — the `feat(02-01)` commit contained both `shared/schema.ts` extensions AND the storage operations (`upsertParentThreat`, etc.).
- **Fix:** Verified the implementations matched the plan spec exactly; proceeded directly to the test file (RED phase).
- **Result:** Plan 02-01 artifacts were present; plan 02-02 test/engine work was the remaining gap.

**2. [Rule 1 - Bug] Map iteration TS2802 error**
- **Found during:** Task 2 TypeScript compile check.
- **Fix:** Replaced `for (const [...] of groups)` with `for (const [...] of Array.from(groups))`.
- **Files modified:** `server/services/threatEngine.ts`

## Verification Results

```
Test Files  2 passed (2)
Tests       51 passed (51)
  - threatGrouping.test.ts   23 passed (THRT-01 through THRT-05)
  - threatRuleSnapshots.test.ts  28 passed (existing snapshots unchanged)
```

Existing snapshot tests unchanged — THRT-05 confirmed (no correlationKey regressions).

## Self-Check: PASSED

- `server/__tests__/threatGrouping.test.ts` — exists, 23 tests pass
- `server/storage/threats.ts` — contains `upsertParentThreat` (line 453)
- `server/services/threatEngine.ts` — contains `groupFindings` + `this.groupFindings` call in `processJobResults`
- Commits: `094fb85` (test RED), `796cf41` (storage GREEN), `5ece1ca` (engine)
