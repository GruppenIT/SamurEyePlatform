---
phase: 16-ui-final-integration
plan: "02"
subsystem: backend-api
tags: [storage, routes, api-security, ui-integration, tdd]
dependency_graph:
  requires: ["16-01"]
  provides: [GET /api/v1/apis, "GET /api/v1/apis/:id/endpoints", "PATCH /api/v1/api-findings/:id", "GET /api/threats?source="]
  affects: [server/storage/apis.ts, server/storage/apiEndpoints.ts, server/storage/apiFindings.ts, server/storage/threats.ts, server/routes/apis.ts, server/routes/apiFindings.ts, server/routes/threats.ts]
tech_stack:
  added: []
  patterns: [LEFT JOIN COUNT drizzle, db.transaction patchApiFinding, requireAnyRole GET routes, patchFindingBodySchema .strict()]
key_files:
  created: []
  modified:
    - server/storage/apis.ts
    - server/storage/apiEndpoints.ts
    - server/storage/apiFindings.ts
    - server/storage/threats.ts
    - server/storage/interface.ts
    - server/storage/index.ts
    - server/routes/apis.ts
    - server/routes/apiFindings.ts
    - server/routes/threats.ts
    - server/services/threatPromotion.ts
    - tests/routes/apis-list.test.ts
    - tests/routes/apis-endpoints.test.ts
    - tests/routes/api-findings-false-positive.test.ts
    - tests/routes/threats-source-filter.test.ts
decisions:
  - "patchApiFinding returns {previous, current} so route layer calls logAudit after tx — matches existing POST /api/v1/apis audit log pattern"
  - "GET /api/v1/apis uses requireAnyRole (not requireOperator) — list is read-only, safe for readonly_analyst"
  - "listApisWithEndpointCount uses LEFT JOIN so APIs with 0 endpoints still appear with endpointCount=0"
  - "listEndpointsByApi ordering changed from desc(createdAt) to asc(path), asc(method) — deterministic for UI Collapsible grouping"
  - "threatPromotion.ts owaspCategory already present in evidence — plan only added documentation comment"
  - "GET /api/threats error message changed from 'Falha ao buscar ameaças' to 'Falha a buscar ameaças' — matches plan spec"
metrics:
  duration: "6 minutes"
  completed_date: "2026-04-20"
  tasks_completed: 2
  files_modified: 14
  tests_promoted: 19
  tests_todo_remaining: 15
---

# Phase 16 Plan 02: Backend API Endpoints for UI Integration Summary

4 backend endpoints/extensões entregues para consumo imediato pelos componentes React das Waves 2-4 da Phase 16.

## Objective Achieved

Entregou os 4 backend endpoints/extensões identificados como missing em 16-RESEARCH.md §Backend Gaps:
1. GET /api/v1/apis — lista APIs com endpointCount computado (UI-01)
2. GET /api/v1/apis/:id/endpoints — lista endpoints ordenados por path+method (UI-02)
3. PATCH /api/v1/api-findings/:id — marca finding como false_positive (UI-05)
4. GET /api/threats?source= — filtro opcional source adicionado (UI-03)

## Function Signatures Added to IStorage

```typescript
// Phase 16 UI-01: List APIs with computed endpoint count
listApisWithEndpointCount(): Promise<(Api & { endpointCount: number })[]>;

// Phase 16 UI-05: Patch api_finding (false positive toggle)
patchApiFinding(id: string, data: { falsePositive: boolean }): Promise<{ previous: ApiFinding; current: ApiFinding }>;

// Phase 16 UI-03: Extended signature (source is new)
getThreatsWithHosts(filters?: { severity?: string; status?: string; assetId?: string; hostId?: string; source?: string }): Promise<(Threat & { host?: Host })[]>;
```

## owaspCategory in threatPromotion Evidence

Confirmado que `owaspCategory` já estava presente na linha 165 de `server/services/threatPromotion.ts` no objeto `evidence`:

```typescript
evidence: {
  apiEndpointId: finding.apiEndpointId,
  owaspCategory: finding.owaspCategory,  // already present — Phase 16 UI-03 dependency
  findingIds: [finding.id],
},
```

Sem mudança de comportamento. Apenas comentário de documentação adicionado linkando à Phase 16.

## Tests Promoted vs Remaining Todo

### Promoted to real it() (19 total)

| File | Promoted | Remaining todo |
|------|----------|----------------|
| apis-list.test.ts | 4 | 3 |
| apis-endpoints.test.ts | 4 | 2 |
| api-findings-false-positive.test.ts | 6 | 2 |
| threats-source-filter.test.ts | 5 | 1 |

### Remaining it.todo

- Auth tests (401/403) — require mock variant for unauthenticated requests (deferred per plan)
- `readonly_analyst` role tests — require middleware mock variant
- Strict query param test for GET /api/v1/apis — not applicable (route takes no query params)
- `source filter composes with status filter` — deferred to Plan 03

## Deviations from Plan

None — plan executed exactly as written with one observation:

**Observation (not a deviation):** The `tests/routes/` directory and 5 stub files were already created by Plan 16-01 (Wave 0 Nyquist stubs). Plan 02 promoted them from `it.todo` to real `it()` as specified.

## Self-Check

- [x] listApisWithEndpointCount exported from server/storage/apis.ts
- [x] patchApiFinding exported from server/storage/apiFindings.ts
- [x] source?: string in getThreatsWithHosts (threats.ts + interface.ts)
- [x] Both functions wired in DatabaseStorage (index.ts)
- [x] GET /api/v1/apis handler in registerApiRoutes
- [x] GET /api/v1/apis/:id/endpoints handler in registerApiRoutes
- [x] PATCH /api/v1/api-findings/:id handler in registerApiFindingsRoutes
- [x] filters.source in threats route handler
- [x] 19 promoted tests GREEN (0 failed)
- [x] No new TypeScript errors introduced (89 errors before = 89 errors after, all pre-existing)
