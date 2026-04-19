---
phase: 09-schema-asset-hierarchy
plan: "04"
subsystem: api
tags: [express, zod, drizzle, postgres, backfill, api-discovery]

requires:
  - phase: 09-03
    provides: storage.createApi, storage.getAsset, storage.promoteApiFromBackfill, IStorage interface

provides:
  - "POST /api/v1/apis route — HIER-03 manual API registration with auth + RBAC + audit"
  - "backfillApiDiscovery.ts CLI — HIER-04 automated API discovery from web_application assets"
  - "docs/operations/backfill-api-discovery.md — operator runbook for backfill usage"

affects:
  - Phase 10 (credential store will extend API probing)
  - Phase 11 (endpoint discovery uses apis rows as input)
  - ops team (backfill doc enables Day-1 UAT)

tech-stack:
  added: []
  patterns:
    - "Route file pattern: registerXxxRoutes(app) with Zod parse → cross-DB validation → storage call → audit log → 201"
    - "Backfill pattern: NOT EXISTS correlated subquery + batchWithLimit(concurrency=10) + onConflictDoNothing"
    - "AbortSignal.timeout(5000) for per-probe timeout without external deps"

key-files:
  created:
    - server/routes/apis.ts
    - server/scripts/backfillApiDiscovery.ts
    - docs/operations/backfill-api-discovery.md
  modified:
    - server/routes/index.ts
    - .planning/phases/09-schema-asset-hierarchy/09-VALIDATION.md

key-decisions:
  - "POST /api/v1/apis uses /api/v1/ prefix (not /api/) — matches CONTEXT.md locked URL shape per HIER-03"
  - "backfillApiDiscovery uses direct db.insert (not storage facade) — matches backfillWebAppParent template, keeps script self-contained for tsx standalone execution"
  - "import.meta.url guard enables named-export usage in tests without triggering main()"

patterns-established:
  - "Cross-DB validation (parent type check) done inside handler, not in Zod — avoids async Zod refinements (Pitfall 4 from RESEARCH.md)"
  - "Backfill concurrency: batchWithLimit chunks=10 in series, parallel within chunk — no external p-limit dep"

requirements-completed:
  - HIER-03
  - HIER-04

duration: 3min
completed: 2026-04-19
---

# Phase 9 Plan 04: Route + Backfill CLI Summary

**POST /api/v1/apis route (HIER-03) + probeWebApp/batchWithLimit backfill CLI (HIER-04) with 7-path detection, 5s timeout, concurrency=10, and operator runbook**

## Performance

- **Duration:** ~3 min
- **Started:** 2026-04-19T02:50:23Z
- **Completed:** 2026-04-19T02:53:24Z
- **Tasks:** 2
- **Files modified/created:** 5

## Accomplishments

- Registered `POST /api/v1/apis` — full middleware chain (isAuthenticatedWithPasswordCheck → requireOperator), Zod parse, parent asset type guard, URL normalization via `normalizeTarget()`, duplicate-key 409, audit log, 201 response
- Created `server/scripts/backfillApiDiscovery.ts` with `probeWebApp` (7 spec paths + /api root + site root JSON fallback), `batchWithLimit` (concurrency cap 10), and `main()` with `--dry-run` + NOT EXISTS idempotency + `onConflictDoNothing`
- Created `docs/operations/backfill-api-discovery.md` with full operator runbook (usage, detection rules, rate limiting/safety, rollback SQL, limitations, UAT instructions)
- Updated `09-VALIDATION.md` frontmatter: `wave_0_complete: true`, `nyquist_compliant: true`; added Task 1 and Task 2 verification rows

## Task Commits

1. **Task 1: Create POST /api/v1/apis route + register in route barrel** - `355a7ef` (feat)
2. **Task 2: Create backfillApiDiscovery.ts CLI + operator docs** - `6d39b83` (feat)

## Files Created/Modified

- `server/routes/apis.ts` — `registerApiRoutes(app)` with POST /api/v1/apis handler; HIER-03 complete
- `server/routes/index.ts` — import + `registerApiRoutes(app)` call added after registerActionPlanRoutes
- `server/scripts/backfillApiDiscovery.ts` — `probeWebApp`, `batchWithLimit`, `main()` with --dry-run; HIER-04 complete
- `docs/operations/backfill-api-discovery.md` — operator runbook: usage, detection rules, rate limiting, rollback, limitations, UAT
- `.planning/phases/09-schema-asset-hierarchy/09-VALIDATION.md` — status=complete, wave_0_complete=true, nyquist_compliant=true

## Route Specification

- **URL:** `POST /api/v1/apis`
- **Middleware:** `isAuthenticatedWithPasswordCheck` → `requireOperator`
- **Zod schema:** `insertApiSchema` from `shared/schema.ts`
- **Status codes:** 400 (Zod failure), 400 (parent not found), 400 (parent not web_application), 400 (invalid URL), 409 (duplicate), 201 (success)
- **pt-BR error strings:** "Dados de API inválidos", "Ativo pai não encontrado", "Apenas ativos do tipo web_application podem hospedar uma API", "URL base inválida", "API já cadastrada para esse ativo com essa URL base"
- **Audit:** `storage.logAudit` with `objectType: 'api'` on every successful creation

## Backfill Specification

- **Probe paths:** `/openapi.json`, `/swagger.json`, `/v2/api-docs`, `/v3/api-docs`, `/api-docs`, `/swagger-ui.html`, `/graphql`
- **Fallback probes:** `/api` root (JSON CT), site root `/` (JSON CT)
- **Timeout:** `AbortSignal.timeout(5000)` per probe (3 occurrences)
- **Concurrency:** `batchWithLimit(candidates, 10, fn)` — chunks of 10, parallel within chunk
- **Idempotency:** `NOT EXISTS (SELECT 1 FROM apis WHERE apis.parent_asset_id = ${assets.id})` in WHERE clause
- **Conflict guard:** `.onConflictDoNothing({ target: [apis.parentAssetId, apis.baseUrl] })`
- **System user:** `createdBy: SYSTEM_USER_ID` ('system')

## Decisions Made

- `POST /api/v1/apis` uses `/api/v1/` prefix as locked in CONTEXT.md — even though existing routes use `/api/` prefix
- Direct `db.insert(apis)` in backfill script (not storage facade) — mirrors `backfillWebAppParent.ts` pattern, keeps CLI self-contained for `tsx` standalone invocation
- `import.meta.url === file://${process.argv[1]}` guard enables named export usage in unit tests without running `main()`

## Deviations from Plan

None — `server/routes/apis.ts` was already present as an untracked file with the exact content specified by the plan (pre-created in a prior session). Task 1 only required committing the existing file and editing `server/routes/index.ts`. All other files were new. Plan executed exactly as written.

## Issues Encountered

Pre-existing TypeScript errors in `cveService.ts`, `jobQueue.ts`, and `client/src/` are out of scope for this plan. The `server/routes/apis.ts` and `server/scripts/backfillApiDiscovery.ts` files compile cleanly (verified with `npx tsc --noEmit 2>&1 | grep -E "server/routes/apis|server/scripts/backfill"` returning no output).

## Phase 9 Final Status

All 5 Phase 9 requirements implemented:

| Requirement | Implemented In | Status |
|-------------|---------------|--------|
| HIER-01 | Plan 02 (schema) + Plan 03 (storage facade) | Complete |
| HIER-02 | Plan 02 (schema) + Plan 03 (storage facade) | Complete |
| HIER-03 | Plan 04 (this plan — POST /api/v1/apis route) | Complete |
| HIER-04 | Plan 04 (this plan — backfillApiDiscovery.ts) | Complete |
| FIND-01 | Plan 02 (owaspApiCategoryEnum + evidence schema) | Complete |

Wave 0 test stubs (Plan 01):
- `apisRoute.test.ts` — stubs ready to flip to real assertions against registerApiRoutes
- `backfillApiDiscovery.test.ts` — stubs ready to flip to real assertions against probeWebApp, batchWithLimit, main()
- `owaspApiCategories.test.ts`, `apiSchema.test.ts`, `ensureApiTables.test.ts`, `apiStorage.test.ts` — stubs awaiting Phase 9 verify-work

See `.planning/phases/09-schema-asset-hierarchy/09-PHASE-SUMMARY.md` (generated by `/gsd:verify-work`).

## Next Phase Readiness

- Phase 9 complete — all HIER and FIND-01 requirements closed
- Phase 10 (credential store) can reference `apis` table as input — `apis.id` FK target is ready
- Phase 11 (endpoint discovery) will read `apis` rows for probe targets — storage facade `listApisByParent` is wired

---
*Phase: 09-schema-asset-hierarchy*
*Completed: 2026-04-19*
