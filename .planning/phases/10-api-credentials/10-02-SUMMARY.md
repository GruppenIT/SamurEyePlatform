---
phase: 10-api-credentials
plan: 02
subsystem: database
tags: [drizzle, zod, pgenum, pgtable, discriminated-union, api-credentials, schema]

# Dependency graph
requires:
  - phase: 09-schema-asset-hierarchy
    provides: apis pgTable (FK target for api_credentials.apiId), pattern for pgEnum + pgTable + relations + insertSchema in shared/schema.ts
  - phase: 10-api-credentials
    provides: "[Plan 10-01] schema.test.ts stubs with factory + PEM constants (TDD RED consumer)"
provides:
  - "pgEnum api_auth_type (7 fixed auth types) in shared/schema.ts"
  - "pgTable api_credentials with common + per-type + crypto + audit columns + 3 indexes"
  - "apiCredentialsRelations (api, creator, updater)"
  - "insertApiCredentialSchema (z.discriminatedUnion with 7 strict variants + Armadilha 2 guard)"
  - "patchApiCredentialSchema (flat optional object, authType immutable)"
  - "PEM_REGEX shared constant for mTLS PEM validation"
  - "Exported types: ApiCredential, ApiCredentialSafe, ApiCredentialWithSecret, InsertApiCredential, PatchApiCredential, ApiAuthType"
affects: [10-04-storage, 10-05-route, 10-06-guard, phase-11-runtime]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Zod discriminated union + .strict() baseInsert (Armadilha 2): per-type fields omitted from base and re-added per variant so each variant rejects foreign-type fields"
    - "Additive-only schema changes: new enum + new table + new relations + new insertSchema + new types; zero modification to existing tables or schemas"
    - "TDD RED->GREEN within a single plan via shared/schema.ts exports consumed by server/__tests__/apiCredentials/schema.test.ts (Nyquist sampling expanded from 22 todo to 38 assertions)"

key-files:
  created: []
  modified:
    - shared/schema.ts
    - server/__tests__/apiCredentials/schema.test.ts

key-decisions:
  - "baseInsertApiCredential uses .strict() in addition to omitting per-type fields so Armadilha 2 (cross-type field rejection) is enforced unconditionally, not just when types are narrowed by TS"
  - "patchApiCredentialSchema is flat z.object (not discriminatedUnion.partial()) because Zod has no native .partial() for discriminated unions; authType intentionally excluded (immutable)"
  - "apiCredentialsRelations uses relationName qualifiers (apiCredentialCreator/apiCredentialUpdater) because the table has two FKs into users; without names Drizzle would conflate the relations"
  - "PatchApiCredential type + ApiAuthType type added as bonus exports (consumed by Plans 04/05/06) — kept in the same export block as the 5 types required by plan truths for single-source-of-truth"

patterns-established:
  - "Discriminated union + strict baseInsert: canonical way to do per-type Zod validation in this codebase"
  - "relationName for multi-FK tables: whenever a table has 2+ FKs to the same target, declare distinct relationName strings"

requirements-completed: [CRED-01, CRED-02]

# Metrics
duration: 7m
completed: 2026-04-19
---

# Phase 10 Plan 02: API Credentials Schema Summary

**apiAuthTypeEnum (7 fixed values) + apiCredentials pgTable (27 columns, 3 indexes, 3 FKs) + Zod discriminated union (7 strict variants) + patchSchema + 6 derived types — 189 linhas adicionadas a shared/schema.ts via dois commits TDD (RED->GREEN).**

## Performance

- **Duration:** 7m (447s)
- **Started:** 2026-04-19T14:21:20Z
- **Completed:** 2026-04-19T14:28:47Z
- **Tasks:** 2 (both TDD: RED->GREEN, no refactor needed)
- **Files modified:** 2 (shared/schema.ts, server/__tests__/apiCredentials/schema.test.ts)

## Accomplishments

- pgEnum `api_auth_type` with 7 fixed values in canonical order (api_key_header, api_key_query, bearer_jwt, basic, oauth2_client_credentials, hmac, mtls).
- pgTable `api_credentials` with 27 columns grouped into identity / mapping / crypto / per-type / audit; FK `apiId` -> `apis.id ON DELETE SET NULL`; FK `createdBy`/`updatedBy` -> `users.id`; 3 indexes (`IDX_api_credentials_api_id`, `IDX_api_credentials_priority`, `UQ_api_credentials_name_created_by`).
- `apiCredentialsRelations` covering `api`, `creator`, `updater` with distinct `relationName` qualifiers to disambiguate the two FKs into `users`.
- `insertApiCredentialSchema` as `z.discriminatedUnion("authType", ...)` with 7 variants, each built from `baseInsertApiCredential.strict()` so foreign-type fields are rejected (Armadilha 2 of RESEARCH).
- `patchApiCredentialSchema` as a flat `z.object` with every field optional (authType intentionally excluded).
- Six exported types: `ApiCredential`, `ApiCredentialSafe`, `ApiCredentialWithSecret`, `InsertApiCredential`, `PatchApiCredential`, `ApiAuthType`.
- 38 schema tests now GREEN (22 it.todo stubs promoted to real assertions + 8 new pgEnum/pgTable/indexes assertions + 4 patchSchema assertions + 4 type-shape assertions).

## Task Commits

Each task was committed atomically via TDD flow (test RED -> feat GREEN):

1. **Task 1: Adicionar apiAuthTypeEnum + apiCredentials pgTable + relations**
   - `adf44f8` (test) — RED: 8 new assertions for enum + table
   - `9d75334` (feat) — GREEN: schema additions in shared/schema.ts
2. **Task 2: Adicionar insertApiCredentialSchema (discriminated union) + patch + tipos derivados**
   - `06bbd68` (test) — RED: 22 todo stubs promoted + 4 patch + 4 type assertions
   - `07c4877` (feat) — GREEN: discriminated union + patch + types

**Plan metadata:** pending — will include 10-02-SUMMARY.md, STATE.md, ROADMAP.md, REQUIREMENTS.md

## Files Created/Modified

- `shared/schema.ts` — +189 lines across 3 insertion points:
  - Line 108-120: `apiAuthTypeEnum` (pgEnum api_auth_type, 7 values)
  - Line 1333-1395: `apiCredentials` pgTable + `apiCredentialsRelations`
  - Line 1398-1507: `baseInsertApiCredential`, `PEM_REGEX`, `insertApiCredentialSchema`, `patchApiCredentialSchema`, and 6 derived types
- `server/__tests__/apiCredentials/schema.test.ts` — 22 it.todo promoted to it() assertions + 16 new assertions (38 total GREEN)

## Decisions Made

- **`.strict()` on baseInsertApiCredential:** Omitting per-type fields from the base is necessary (Armadilha 2) but not sufficient at runtime — Zod tolerates unknown keys by default, so `apiKeyHeaderName` passed to a `bearer_jwt` payload would be silently dropped. Adding `.strict()` makes the variant actively reject it, which is the behavior the stub `"rejeita cross-type: bearer_jwt + apiKeyHeaderName presente"` requires.
- **`patchApiCredentialSchema` flat, not per-type:** Zod discriminated unions have no native `.partial()`. Two options: (1) implement 7 partial variants and force clients to send `authType`, or (2) flat `z.object` where every field is optional and the route enforces "passed fields match the authType of the existing row." Option 2 chosen because PATCH should not require authType (it's immutable) and keeps the route logic in one place.
- **`ApiAuthType` + `PatchApiCredential` extra exports:** Plan's must_haves require only 4 types; adding these two saves downstream plans (04/05) from re-deriving them and keeps the type surface centralized.
- **relationName for the two FKs into users:** `createdBy` and `updatedBy` both point to `users.id`; without named relations Drizzle would conflate them. Precedent: none of the existing tables in the project have two FKs to `users`, so this is a new pattern worth documenting.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Added `.strict()` to baseInsertApiCredential**
- **Found during:** Task 2 (Zod variant implementation)
- **Issue:** The plan's `<action>` block (linhas 265-287) specified the baseInsert with `.omit({...})` but not `.strict()`. Without `.strict()`, Zod silently drops unknown keys rather than rejecting them, which would leave the test `"rejeita cross-type: bearer_jwt + apiKeyHeaderName presente"` failing even though Armadilha 2 of the RESEARCH was addressed.
- **Fix:** Appended `.strict()` after `.omit({...})`. This is strictly additive (no API change) and fulfills the behavioral contract the plan lists in `<behavior>` Test 3.
- **Files modified:** `shared/schema.ts` (linha 1420)
- **Verification:** Test `"rejeita cross-type: bearer_jwt + apiKeyHeaderName presente (Armadilha 2)"` passes; same behavior confirmed via other valid payloads (all 7 positive cases still pass with `.strict()`).
- **Committed in:** `07c4877` (Task 2 GREEN commit)

**2. [Rule 2 - Missing Critical] Added 2 extra types to exports (ApiAuthType, PatchApiCredential)**
- **Found during:** Task 2 (tipos derivados)
- **Issue:** The plan truth list only enumerates 4 types (`ApiCredential`, `ApiCredentialSafe`, `ApiCredentialWithSecret`, `InsertApiCredential`), but the plan's own `<action>` block (linhas 370-381) requests `ApiAuthType` and `PatchApiCredential`. Downstream plans (04 storage, 05 route) will consume these directly.
- **Fix:** Added both exports. No schema change, only two additional type aliases.
- **Files modified:** `shared/schema.ts` (linhas 1500, 1501)
- **Verification:** Types resolve correctly in schema.test.ts (InsertApiCredential test passes); TS still reports 75 pre-existing errors (unchanged count, no new apiCredential-related errors).
- **Committed in:** `07c4877` (Task 2 GREEN commit)

---

**Total deviations:** 2 auto-fixed (2 missing critical — Rule 2)
**Impact on plan:** Both auto-fixes implement plan behavioral contracts that the truth list partially under-specified. No scope expansion. Zero production surface outside `shared/schema.ts`.

## Issues Encountered

- **Import location of `getTableColumns`:** Initial RED attempt imported `getTableColumns` from `drizzle-orm/pg-core`, where it does not exist. Corrected to `drizzle-orm` (main barrel). Resolved inside Task 1 RED test iteration — not a deviation, part of normal TDD feedback loop.
- **Pre-existing `actionPlanService.test.ts` failure:** Documented in `.planning/phases/10-api-credentials/deferred-items.md` (since Plan 10-01). Unrelated to this plan; `npm run test` still reports this single pre-existing failure. Our `server/__tests__/apiCredentials` suite: 72 passing + 64 todo, zero regressions.

## User Setup Required

None — schema additions only. `drizzle-kit push` is deferred to Plan 10-06 (boot-time guard) so no DB action is required at this plan boundary.

## Next Phase Readiness

- **Plan 10-04 (storage facade)** can now `import { apiCredentials, insertApiCredentialSchema, type ApiCredential, type ApiCredentialSafe, type InsertApiCredential } from '@shared/schema'`.
- **Plan 10-05 (route)** can consume `insertApiCredentialSchema` and `patchApiCredentialSchema` directly; `ApiAuthType` available as a union literal type.
- **Plan 10-06 (guard)** can reference `apiAuthTypeEnum.enumName` (`"api_auth_type"`) for its `pg_type` existence check, and the 3 index names directly.
- **Wave 0 stubs** (storage.test.ts, route.test.ts, resolveCredential.test.ts, guard.test.ts) remain 64 it.todo — downstream plans will promote them incrementally.

## Self-Check: PASSED

Files verified to exist:
- FOUND: /opt/samureye/shared/schema.ts
- FOUND: /opt/samureye/server/__tests__/apiCredentials/schema.test.ts

Commits verified:
- FOUND: adf44f8 (Task 1 RED — test: failing tests for pgEnum + pgTable)
- FOUND: 9d75334 (Task 1 GREEN — feat: apiAuthTypeEnum + apiCredentials pgTable + relations)
- FOUND: 06bbd68 (Task 2 RED — test: failing tests for Zod union + patch + types)
- FOUND: 07c4877 (Task 2 GREEN — feat: insertApiCredentialSchema + patchApiCredentialSchema + 6 types)

Suite verified:
- `npm run test -- server/__tests__/apiCredentials/schema.test.ts`: exit 0, 38 passed (0 todo), 22ms
- `npm run test -- server/__tests__/apiCredentials`: exit 0, 72 passed + 64 todo, 863ms
- Full `npm run test`: 416 passed + 144 todo, 1 pre-existing failure (actionPlanService — deferred)
- `npx tsc --noEmit`: 75 pre-existing errors (unchanged count); zero errors matching `/apiCredential|api_auth_type|insertApiCredential|patchApiCredential/`

---
*Phase: 10-api-credentials*
*Completed: 2026-04-19*
