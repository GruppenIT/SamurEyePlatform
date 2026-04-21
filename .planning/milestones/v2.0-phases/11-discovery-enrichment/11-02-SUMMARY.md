---
phase: 11-discovery-enrichment
plan: 02
subsystem: api-discovery
tags: [vitest, drizzle, postgres, preflight, specHash, sha256, upsert, httpx, arjun, katana, kiterunner, processTracker]

# Dependency graph
requires:
  - phase: 11-01
    provides: Nyquist stubs (specHash.test.ts + dedupeUpsert.test.ts), httpx_* columns on apiEndpoints, discoverApiOptsSchema

provides:
  - "preflightApiBinary('katana'|'httpx'|'kiterunner'|'arjun') memoized per-process + resetApiBinaryPreflight() for tests"
  - "computeCanonicalHash(spec) + canonicalize(value) — recursive key-sort SHA-256 64-char hex"
  - "processTracker.register() typing widened to include katana/httpx/kiterunner/arjun"
  - "upsertApiEndpoints(apiId, rows[]) bulk upsert with COALESCE + ARRAY DISTINCT unnest"
  - "mergeHttpxEnrichment(endpointId, {...}) — updates only httpx_* columns"
  - "appendQueryParams(endpointId, params[]) — JS-side dedup by name"
  - "markEndpointsStale(apiId, endpointIds[]) — logging-only stub (lastSeenAt deferred)"
  - "updateApiSpecMetadata(apiId, {specUrl, specVersion, specHash}) — stamps specLastFetchedAt"
  - "16 real test assertions GREEN across preflight.test.ts (3), specHash.test.ts (7), dedupeUpsert.test.ts (6)"

affects: [11-03-PLAN, 11-04-PLAN, 11-05-PLAN, 11-06-PLAN, 11-07-PLAN]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Memoized binary preflight via Map<ApiBinaryName, PreflightResult> — mirrors nucleiPreflight.ts single-cache pattern but supports N binaries"
    - "Recursive key-sort canonicalization: Object.keys(obj).sort().reduce() — non-mutating deep walk"
    - "Bulk upsert heuristic: createdAt === updatedAt → insert, createdAt < updatedAt → update (timestamps set at insert time)"
    - "vi.hoisted() in-memory db mock for storage tests — onConflictDoUpdate simulated via endpoint store + timestamp heuristic"

key-files:
  created:
    - server/services/scanners/api/preflight.ts
    - server/services/scanners/api/specHash.ts
    - server/__tests__/apiDiscovery/preflight.test.ts
  modified:
    - server/services/processTracker.ts
    - server/storage/apiEndpoints.ts
    - server/storage/apis.ts
    - server/storage/interface.ts
    - server/storage/index.ts
    - server/__tests__/apiDiscovery/specHash.test.ts
    - server/__tests__/apiDiscovery/dedupeUpsert.test.ts

key-decisions:
  - "INSTALL_PATHS uses absolute /opt/samureye/bin/* first, falls back to PATH for dev environments — matches Phase 8 install.sh targets"
  - "kiterunner checks 'kr' before 'kiterunner' — matches binaries.json binary_in_archive: 'kr'"
  - "arjun uses venv-only path /opt/samureye/venv-security/bin/arjun — never on PATH"
  - "upsertApiEndpoints insert/update heuristic: createdAt === updatedAt means insert (both set to now() at insert time); updatedAt > createdAt means update (onConflictDoUpdate sets updatedAt: new Date())"
  - "dedupeUpsert.test.ts uses vi.hoisted() mock with in-memory endpoint store; update heuristic simulated by setting updatedAt = createdAt + 1ms"
  - "appendQueryParams dedup is JS-side (not SQL) — simpler + avoids complex JSONB SQL; single SELECT+UPDATE"
  - "markEndpointsStale is logging-only per CONTEXT.md decision (lastSeenAt column deferred to Phase 12 or later)"

# Metrics
duration: 5min
completed: 2026-04-20
---

# Phase 11 Plan 02: Shared Primitives (Preflight, SpecHash, Storage Extensions) Summary

**Memoized preflightApiBinary() for 4 API scanner binaries + computeCanonicalHash() recursive sha256 + 5 storage functions (upsertApiEndpoints/mergeHttpxEnrichment/appendQueryParams/markEndpointsStale/updateApiSpecMetadata) + 16 real tests GREEN (3 preflight + 7 specHash + 6 dedupeUpsert)**

## Performance

- **Duration:** ~5 min
- **Started:** 2026-04-20T00:42:53Z
- **Completed:** 2026-04-20T00:47:45Z
- **Tasks:** 3
- **Files modified:** 10

## Accomplishments

- `server/services/scanners/api/preflight.ts` — memoized preflightApiBinary() for katana/httpx/kiterunner/arjun with absolute path checks + PATH fallback; kiterunner tries 'kr' first; arjun uses venv path only
- `server/services/scanners/api/specHash.ts` — recursive canonicalize() + computeCanonicalHash() (SHA-256, 64-char hex); handles primitives, null, array order preservation, non-mutating
- `server/services/processTracker.ts` — ProcessInfo.name, ProcessUpdate.processName, and register() widened to `'nmap' | 'nuclei' | 'katana' | 'httpx' | 'kiterunner' | 'arjun'`
- `server/storage/apiEndpoints.ts` — 4 new functions: upsertApiEndpoints() with COALESCE + ARRAY DISTINCT unnest; mergeHttpxEnrichment() httpx-only update; appendQueryParams() JS-side dedup; markEndpointsStale() logging stub
- `server/storage/apis.ts` — updateApiSpecMetadata() stamps specLastFetchedAt=now()
- `server/storage/interface.ts` + `index.ts` — 5 new IStorage method signatures + DatabaseStorage wiring
- Wave 0 tests converted: specHash.test.ts (5 it.todo → 7 real it), dedupeUpsert.test.ts (6 it.todo → 6 real it)
- Full suite: 511 tests passing (16 new real tests); pre-existing actionPlanService.test.ts failure (DATABASE_URL) unchanged

## Task Commits

1. **Task 1: preflightApiBinary + processTracker widening** — `0e5a68d` (feat)
2. **Task 2: computeCanonicalHash + specHash tests** — `6013f6c` (feat)
3. **Task 3: storage extensions + dedupeUpsert tests** — `07417ac` (feat)

## Decisions Made

- INSTALL_PATHS: absolute /opt/samureye/bin/* paths checked first; kiterunner tries 'kr' before 'kiterunner'
- arjun venv-only path (never on PATH) per Phase 8 install.sh design
- Insert/update heuristic for upsertApiEndpoints: createdAt === updatedAt → insert
- appendQueryParams uses JS-side dedup (not SQL JSONB manipulation) for simplicity
- markEndpointsStale is logging-only (lastSeenAt column deferred per CONTEXT.md)

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

- dedupeUpsert.test.ts update path test initially failed because mock returned same-millisecond timestamps for both insert and update. Fixed by setting `updatedAt = createdAt + 1ms` in the update path of the mock to guarantee the createdAt !== updatedAt heuristic triggers correctly.

## User Setup Required

None.

## Next Phase Readiness

- Scanners in Plans 11-03..11-06 can `import { preflightApiBinary } from './preflight'`
- Orchestrator in Plan 11-06 can call `storage.upsertApiEndpoints(apiId, rows)`, `storage.mergeHttpxEnrichment(...)`, `storage.appendQueryParams(...)`, `storage.updateApiSpecMetadata(...)`
- openapi.ts (Plan 11-03) can import `computeCanonicalHash` from `./specHash`
- processTracker ready for new binary names without type errors

## Self-Check: PASSED

- server/services/scanners/api/preflight.ts — FOUND
- server/services/scanners/api/specHash.ts — FOUND
- server/__tests__/apiDiscovery/preflight.test.ts — FOUND
- Commit 0e5a68d (Task 1) — FOUND
- Commit 6013f6c (Task 2) — FOUND
- Commit 07417ac (Task 3) — FOUND

---
*Phase: 11-discovery-enrichment*
*Completed: 2026-04-20*
