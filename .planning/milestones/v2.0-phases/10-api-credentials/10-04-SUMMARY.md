---
phase: 10-api-credentials
plan: 04
subsystem: storage-facade
tags: [storage-facade, encryption-reuse, drizzle, url-pattern-matching, boot-guard, pgenum, idempotent-migration, wave-2]

# Dependency graph
requires:
  - phase: 10-api-credentials
    provides: "[Plan 10-02] apiCredentials pgTable, apiAuthTypeEnum, insertApiCredentialSchema, patchApiCredentialSchema, ApiCredential/Safe/WithSecret/InsertApiCredential/PatchApiCredential/ApiAuthType types"
  - phase: 10-api-credentials
    provides: "[Plan 10-03] matchUrlPattern(pattern, url), isValidUrlPattern(pattern), decodeJwtExp(jwt) — pure helpers in server/services/credentials/"
  - phase: 09-schema-asset-hierarchy
    provides: encryptionService (KEK/DEK) reuse, storage/apis.ts template, ensureApiTables guard template
provides:
  - "server/storage/apiCredentials.ts — domain facade with 7 exported functions + SAFE_FIELDS constant"
  - "server/storage/database-init.ts::ensureApiCredentialTables — idempotent runtime guard invoked after ensureApiTables() in initializeDatabaseStructure"
  - "IStorage interface extended with 7 new signatures; DatabaseStorage class wired via namespace import"
  - "32 GREEN tests via in-memory db mock (20 storage + 12 resolve) + 9 GREEN guard tests = 41 new tests"
affects: [10-05-route, phase-11-runtime]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "In-memory db mock via vi.hoisted() — allows TDD for storage facade without DATABASE_URL (same module mock approach as threatGrouping.test.ts, but with a builder-style drizzle shim to exercise select/insert/update/delete chains)"
    - "SAFE_FIELDS explicit column projection — replicates getCredentials() pattern in assets.ts:180; list/get/resolve return ApiCredentialSafe (secretEncrypted/dekEncrypted excluded); getApiCredentialWithSecret is the ONLY path that returns encrypted fields"
    - "stripSecretFields helper — removes input-wrapper fields (secret, mtlsCert/Key/Ca) before db.insert/update so only real columns hit the DB"
    - "Resolution algorithm: priority ASC → specificity DESC (literals count) → createdAt ASC; filter via matchUrlPattern() in JS after fetching candidates by (apiId OR isNull)"
    - "Idempotent boot guard pattern (Phase 9 template): pg_type/pg_tables/pg_indexes lookups gate each CREATE; errors logged via log.error but NOT rethrown (fallback mode)"

key-files:
  created:
    - server/storage/apiCredentials.ts
  modified:
    - server/storage/database-init.ts
    - server/storage/interface.ts
    - server/storage/index.ts
    - server/__tests__/apiCredentials/storage.test.ts
    - server/__tests__/apiCredentials/resolveCredential.test.ts
    - server/__tests__/apiCredentials/guard.test.ts

key-decisions:
  - "Kept and adapted the previous executor's uncommitted in-memory db mock (502 lines in storage.test.ts) — it matched the project's mock patterns (threatGrouping.test.ts / mfaService.test.ts) more pragmatically than spinning up a real DB for TDD; refactored via vi.hoisted() to fix vitest hoisting (Rule 1 bug: vi.mock factory cannot reference top-level TDZ vars)"
  - "stripSecretFields typed as Omit — preserves input shape at call-site for type-safety without casting every DB insert to any"
  - "updateApiCredential fetches current row via getApiCredentialWithSecret to determine authType — required because patch payload does NOT carry authType (immutable per Plan 10-02 schema decision)"
  - "Resolution algorithm implements specificity via literal-count (pattern.replace(/\\*/g, '').length) — trivial, deterministic, avoids regex complexity; matches CONTEXT.md §CRED-04 spec exactly"

patterns-established:
  - "vi.hoisted() for vitest mocks that need shared state: wrap ALL references (builders, store, column proxies) inside a single hoisted block so the mock factory can access them at factory-execution time"
  - "Re-encrypt-on-rotation in updateApiCredential: hasNewSecret gate (secret || mtlsCert || mtlsKey || mtlsCa) drives both the encryptCredential() call and the bearerExpiresAt re-derivation for bearer_jwt"

requirements-completed: [CRED-01, CRED-02, CRED-03, CRED-04]

# Metrics
duration: 28m
completed: 2026-04-19
---

# Phase 10 Plan 04: Storage Facade + Boot Guard + IStorage Wiring Summary

**Wave 2 persistence layer complete: 7-function storage facade (server/storage/apiCredentials.ts, ~230 lines) with encryptionService reuse + matchUrlPattern/decodeJwtExp consumption, idempotent boot guard (ensureApiCredentialTables, ~100 lines) invoked after ensureApiTables(), and 7 new IStorage signatures + DatabaseStorage namespace wiring. 41 new tests GREEN (20 storage + 12 resolve + 9 guard) via in-memory db mock. Plan 05 (route) now only needs Zod parse + storage call.**

## Performance

- **Duration:** 28m (1663s)
- **Started:** 2026-04-19T18:20:56Z
- **Completed:** 2026-04-19T18:48:39Z
- **Tasks:** 3 (2 TDD, 1 wiring-only)
- **Files modified/created:** 4 production files, 3 test files

## Accomplishments

- **`server/storage/apiCredentials.ts` (NEW — 250 lines):**
  - `SAFE_FIELDS` constant (25 explicit columns, excludes secretEncrypted/dekEncrypted)
  - `listApiCredentials(filter?: { apiId?, authType? })` → ApiCredentialSafe[]
  - `getApiCredential(id)` → ApiCredentialSafe | undefined
  - `getApiCredentialWithSecret(id)` → ApiCredentialWithSecret | undefined (INTERNAL — for Phase 11+ executor)
  - `createApiCredential(input, userId)` — encrypts via `encryptionService.encryptCredential()`, composite JSON for mTLS, derives `bearerExpiresAt` via `decodeJwtExp()` for `bearer_jwt`
  - `updateApiCredential(id, patch, userId)` — re-encrypts when new secret/cert/key/ca provided; fetches current authType to build mTLS JSON or plain string
  - `deleteApiCredential(id)` — hard delete via db.delete
  - `resolveApiCredential(apiId, endpointUrl)` — CRED-04 algorithm: candidates are scoped (apiId match OR isNull) + URL-filter via matchUrlPattern, sorted by priority ASC → specificity (literal count) DESC → createdAt ASC
- **`server/storage/database-init.ts` (+100 lines):**
  - New `ensureApiCredentialTables()` function (lines 348-439) with pg_type/pg_tables/pg_indexes gating on enum + table + 3 indexes
  - Invocation added at line 142 (immediately after `await ensureApiTables();` in `initializeDatabaseStructure`), preserving FK ordering (apis → api_credentials)
- **`server/storage/interface.ts` (+14 lines):** 5 new type imports + 7 IStorage signatures
- **`server/storage/index.ts` (+10 lines):** namespace import + 7 class-field attribute assignments
- **Test coverage:**
  - `storage.test.ts`: 20 tests (7 round-trip + mTLS composite + 3 sanitization + 2 bearerExpiresAt + 2 UNIQUE + 1 FK + 3 update/delete)
  - `resolveCredential.test.ts`: 12 tests (priority/specificity/createdAt tie-breaks, apiId scope, null shape, facade consumer)
  - `guard.test.ts`: 9 tests (idempotency for enum/table/3 indexes, 2 fallback modes, 1 boot ordering source-inspection)
- **Full suite:** 457 passed + 107 todo (+41 tests over baseline), pre-existing `actionPlanService.test.ts` DATABASE_URL failure unchanged (deferred).

## Task Commits

Each task was committed atomically via TDD flow (test RED → feat GREEN), plus a follow-up wiring commit:

1. **Task 1 RED: failing tests for storage + resolveCredential** — `cda82d8`
2. **Task 1 GREEN: apiCredentials storage facade (8 functions + SAFE_FIELDS)** — `0966f35`
3. **Task 2 RED: failing tests for ensureApiCredentialTables guard** — `f7fa723`
4. **Task 2 GREEN: ensureApiCredentialTables guard + invoke in boot** — `e1091df`
5. **Task 3: wire apiCredentials into IStorage and DatabaseStorage** — `e5b0ecb`

**Plan metadata:** pending — will include 10-04-SUMMARY.md, STATE.md, ROADMAP.md, REQUIREMENTS.md

## Files Created/Modified

- **`server/storage/apiCredentials.ts`** — 250 lines, exports 7 functions + SAFE_FIELDS (internal const).
- **`server/storage/database-init.ts`** — 2 insertion points:
  - line 142: `await ensureApiCredentialTables();` added right after line 140 `await ensureApiTables();`
  - lines 348-439: new function `ensureApiCredentialTables()` before `ensureSystemUserExists()` (which starts at line 441 after insertion)
- **`server/storage/interface.ts`** — 2 insertion points:
  - lines 49-53: added 5 type imports (ApiCredentialSafe, ApiCredentialWithSecret, InsertApiCredential, PatchApiCredential, ApiAuthType)
  - lines 293-301: added 7 IStorage signatures in new "Phase 10 — API Credentials operations" block
- **`server/storage/index.ts`** — 2 insertion points:
  - line 16: `import * as apiCredentialOps from "./apiCredentials";`
  - lines 211-218: added 7 attribute assignments in new "Phase 10 — API Credentials (CRED-01..04)" block
- **`server/__tests__/apiCredentials/storage.test.ts`** — 502 lines (refactored from prior executor's partial; migrated all mock state inside `vi.hoisted()` block to fix vitest TDZ error)
- **`server/__tests__/apiCredentials/resolveCredential.test.ts`** — 383 lines, promoted 8 it.todo stubs to 12 real tests with a self-contained mock and `seedCred()` helper
- **`server/__tests__/apiCredentials/guard.test.ts`** — 196 lines, promoted 9 it.todo stubs to 9 real tests with `vi.fn()` execute spy + pattern-match response scheme

## Decisions Made

- **Adapted prior executor's partial work instead of resetting:** The previous executor left ~467 lines of in-memory db mock scaffolding in `storage.test.ts`. Inspection showed it aligned with the project's mock pattern (`threatGrouping.test.ts` mocks `../db`) and covered the plan's behavior matrix. Keeping saved ~15-20 minutes of re-authoring. One bug was auto-fixed (Rule 1): the `vi.mock()` factory referenced top-level vars (`apiCredentialsCols`, builders, `store`) that are in the temporal dead zone when vitest hoists the mock; wrapping everything in `vi.hoisted(() => {...})` fixed it.
- **In-memory mock over real DB for TDD:** The Plan's `<action>` cited `apiStorage.test.ts` as template — but that file is only `it.todo` stubs; the project has no real-DB integration tests available outside DATABASE_URL-dependent suites. The mock approach unblocks TDD while preserving exact API semantics (chainable builder, projection-aware returning, UNIQUE+FK simulation).
- **Resolution algorithm specificity by literal count:** `pattern.replace(/\*/g, '').length` is the simplest possible specificity metric, and it matches CONTEXT.md's rationale "mais literais ganha". Two patterns matching the same URL have deterministic ordering even with identical priority+createdAt.
- **updateApiCredential fetches current via getApiCredentialWithSecret:** Required because (a) patch payload lacks `authType` (immutable per Plan 10-02), and (b) mTLS path needs to build `JSON.stringify({cert,key,ca})` from patch fields, which looks identical to non-mTLS in terms of patch fields alone. Fetching establishes authType.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] vi.mock factory TDZ with top-level mock helpers**
- **Found during:** Task 1 GREEN (first run of `npm run test -- storage.test.ts resolveCredential.test.ts`)
- **Issue:** The previous executor's mock used top-level `const apiCredentialsCols = colProxy(...)`, `const store = {...}`, and top-level `function buildSelectBuilder()`, all of which were referenced inside `vi.mock('drizzle-orm', ...)` and `vi.mock('../../db', ...)` factories. Vitest hoists `vi.mock()` calls ABOVE the top-level consts, so the factory ran into a `ReferenceError: Cannot access 'apiCredentialsCols' before initialization` on every test run.
- **Fix:** Wrapped ALL mock helpers (store, reset fn, column proxy, 4 builder fns, cond constructors) inside a single `vi.hoisted(() => {...})` block in both `storage.test.ts` and `resolveCredential.test.ts`. Exposed `store` and `resetStore` as re-exports outside the hoist for test-body access. The mock factories now read from `mockState.*` references that are guaranteed to be initialized before hoisting.
- **Files modified:** `server/__tests__/apiCredentials/storage.test.ts`, `server/__tests__/apiCredentials/resolveCredential.test.ts`
- **Verification:** 32 tests GREEN (20 storage + 12 resolve)
- **Committed in:** `0966f35` (Task 1 GREEN; fix + implementation together because the RED phase already had the bug in the committed test file — the implementation couldn't be verified without the fix)

### Adaptation Decision (not a deviation)

- **Kept (adapted) prior executor's partial work:** The uncommitted ~467 lines in `storage.test.ts` were pragmatic and covered the plan's behavior matrix. Rather than resetting and re-authoring in a different style (e.g. using `process.env.DATABASE_URL` + `beforeEach` truncate), I refactored the existing scaffolding (Rule 1 fix above) and extended `resolveCredential.test.ts` with the same pattern for consistency. This matches the "preferred — matches existing project mock patterns" guidance in the task prompt.

---

**Total deviations:** 1 auto-fixed (Rule 1 — vitest hoisting bug in the inherited test file)
**Impact on plan:** All acceptance criteria met; 41 new tests GREEN; typecheck count unchanged (75 pre-existing, zero new apiCredential-related errors); full suite +41 tests over baseline (457 vs 416) with no regressions.

## Issues Encountered

- **Pre-existing test failure:** `server/services/__tests__/actionPlanService.test.ts` requires DATABASE_URL (failure unrelated to Plan 10-04, documented in `.planning/phases/10-api-credentials/deferred-items.md` since Plan 10-01).
- **Pre-existing TS error:** `server/storage/index.ts(128,3): TS2416 Property 'getThreatStatusHistory' in type 'DatabaseStorage' is not assignable to the same property in base type 'IStorage'.` Confirmed identical before and after Plan 10-04 changes (stash/compare). Unrelated to api_credentials.

## User Setup Required

None — in-memory mock for tests; boot guard will create DB objects on first app start after merge; `drizzle-kit push` also works (guard is idempotent-safe after push).

## Next Phase Readiness

- **Plan 10-05 (POST /api/v1/api-credentials route):** Consumes `storage.createApiCredential`, `storage.listApiCredentials`, `storage.getApiCredential`, `storage.updateApiCredential`, `storage.deleteApiCredential`; parses body via `insertApiCredentialSchema` (Plan 10-02) or `patchApiCredentialSchema`; calls `isValidUrlPattern` (Plan 10-03) before insert.
- **Phase 11 runtime:** Consumes `storage.resolveApiCredential(apiId, endpointUrl)` + `storage.getApiCredentialWithSecret(id)` → `encryptionService.decryptCredential(secretEncrypted, dekEncrypted)` → inject per-authType into outgoing HTTP request.

## Self-Check: PASSED

Files verified to exist:
- FOUND: /opt/samureye/server/storage/apiCredentials.ts
- FOUND: /opt/samureye/server/storage/database-init.ts (modified, ensureApiCredentialTables added at lines 348-439)
- FOUND: /opt/samureye/server/storage/interface.ts (modified, +14 lines)
- FOUND: /opt/samureye/server/storage/index.ts (modified, +10 lines)
- FOUND: /opt/samureye/server/__tests__/apiCredentials/storage.test.ts (502 lines)
- FOUND: /opt/samureye/server/__tests__/apiCredentials/resolveCredential.test.ts (383 lines)
- FOUND: /opt/samureye/server/__tests__/apiCredentials/guard.test.ts (196 lines)

Commits verified:
- FOUND: cda82d8 (Task 1 RED — test: failing tests for storage facade + resolveApiCredential)
- FOUND: 0966f35 (Task 1 GREEN — feat: apiCredentials storage facade (8 functions + SAFE_FIELDS))
- FOUND: f7fa723 (Task 2 RED — test: failing tests for ensureApiCredentialTables guard)
- FOUND: e1091df (Task 2 GREEN — feat: ensureApiCredentialTables guard + invoke in boot)
- FOUND: e5b0ecb (Task 3 — feat: wire apiCredentials into IStorage and DatabaseStorage)

Suite verified:
- `npm run test -- server/__tests__/apiCredentials`: 113 passing + 27 todo (route.test.ts — next plan) in 1.27s
- `npm run test`: 457 passed + 107 todo + 1 pre-existing failure (actionPlanService DATABASE_URL); no regressions
- `npx tsc --noEmit`: 75 errors (exactly matches pre-plan baseline); zero new apiCredential-related errors

Acceptance criteria:
- Grep `export async function listApiCredentials\(|getApiCredential\(|getApiCredentialWithSecret\(|createApiCredential\(|updateApiCredential\(|deleteApiCredential\(|resolveApiCredential\(`: **7 matches** in apiCredentials.ts (all 7 public fns)
- Grep `const SAFE_FIELDS = \{`: **1 match** (line 24)
- Grep `encryptionService.encryptCredential`: **2 matches** (createApiCredential + updateApiCredential re-encrypt path)
- Grep `decodeJwtExp(`: **2 matches** (create bearer_jwt + update bearer_jwt rotate)
- Grep `matchUrlPattern(`: **2 matches** (resolveApiCredential filter + comment)
- Grep `JSON.stringify({`: **2 matches** (extractSecret mtls + updateApiCredential mtls re-encrypt)
- Grep `ensureApiCredentialTables`: **3 matches** in database-init.ts (invocation + fn def + log message)
- Order check: `await ensureApiCredentialTables();` at line 142 > `await ensureApiTables();` at line 139 ✓
- Grep `CREATE TYPE api_auth_type AS ENUM`: **1 match** (line 357)
- Grep `CREATE TABLE IF NOT EXISTS api_credentials`: **1 match** (line 376)
- Grep `hmac_signed_headers TEXT\[\]`: **1 match** (line 397)
- Grep `api_id VARCHAR REFERENCES apis\(id\) ON DELETE SET NULL`: **1 match** (line 383)
- Grep `import \* as apiCredentialOps`: **1 match** in index.ts (line 16)
- Grep `(listApiCredentials|getApiCredential|...|resolveApiCredential) = apiCredentialOps\.`: **7 matches** in index.ts (lines 212-218)
- Grep `it\.todo` in 3 test files: **0 matches** (all promoted to real tests)

---
*Phase: 10-api-credentials*
*Completed: 2026-04-19*
