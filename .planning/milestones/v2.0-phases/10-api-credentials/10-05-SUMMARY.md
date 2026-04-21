---
phase: 10-api-credentials
plan: 05
subsystem: api
tags: [express, crud, rbac, zod, discriminated-union, rest-api, api-credentials, wave-3]

# Dependency graph
requires:
  - phase: 10-api-credentials
    provides: "[Plan 10-02] insertApiCredentialSchema (discriminated union), patchApiCredentialSchema, ApiAuthType"
  - phase: 10-api-credentials
    provides: "[Plan 10-03] isValidUrlPattern whitelist validator"
  - phase: 10-api-credentials
    provides: "[Plan 10-04] storage facade (createApiCredential, listApiCredentials, getApiCredential, updateApiCredential, deleteApiCredential) + IStorage wiring"
  - phase: 09-schema-asset-hierarchy
    provides: "template apis.ts route for /api/v1/ pattern + requireOperator middleware + isAuthenticatedWithPasswordCheck"
provides:
  - "server/routes/apiCredentials.ts — registerApiCredentialsRoutes(app) with 5 CRUD endpoints"
  - "POST|GET|GET:id|PATCH|DELETE /api/v1/api-credentials — single backend contract consumed by Phase 16 dedicated UI AND wizard inline-create"
  - "Safe-by-default response shape: SAFE_FIELDS projection enforced via storage facade; secrets never reach HTTP layer"
  - "30 new route tests GREEN (27 it.todo promoted + 3 extra for 7-auth-type coverage)"
affects: [phase-16-ui, wizard-inline-create-CRED-05]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "In-process HTTP test pattern — express().listen(0) + native fetch (Node 20+) replaces missing supertest; no new test dep required"
    - "Logger + storage + subscription service triple-mock for route test isolation (db required transitively via middleware.ts subscription guard)"
    - "Zod discriminated-union parse() at route boundary → delegates business logic entirely to storage facade (zero duplicated validation)"
    - "500 fallback with pt-BR message for unexpected storage errors; 23505 mapped to 409; ordering: Zod → urlPattern → storage"

key-files:
  created:
    - server/routes/apiCredentials.ts
  modified:
    - server/routes/index.ts
    - server/__tests__/apiCredentials/route.test.ts

key-decisions:
  - "In-process HTTP tests via express().listen(0) + fetch — avoided supertest npm install; reuses only vitest + express (already deps); clean isolation with vi.mock of storage/localAuth/logger/db/subscriptionService"
  - "Kept plan's exact error ordering (Zod → urlPattern → storage) because it ensures 400 responses never touch the storage layer and preserves observability: Zod rejections are info-logged with error shape, pattern rejections emit no log (whitelist is deterministic)"
  - "PATCH verifies existence via getApiCredential BEFORE updateApiCredential — keeps 404 semantics clean even if storage.update would silently no-op; matches apis.ts Phase 9 pattern for GET-then-PATCH"
  - "Logger replaced (not spied) in route test: `vi.mock('../../lib/logger', () => ({ createLogger: () => captureLogger }))` gives deterministic JSON-free event capture for Armadilha 3 assertion"

patterns-established:
  - "Route test mocking matrix for middleware-heavy modules: mock storage + localAuth + db + subscriptionService + logger (5 mocks) unblocks import of any route that goes through middleware.ts"
  - "Express route test without supertest: start real express, listen on port 0, use native fetch — works for any future route with 0 new deps"
  - "Route → storage contract: every business rule (encryption, re-encryption, specificity resolution) lives in storage facade; route's job is Zod parse + pt-BR error mapping + RBAC"

requirements-completed: [CRED-01, CRED-05]

# Metrics
duration: 8m
completed: 2026-04-19
---

# Phase 10 Plan 05: API Credentials CRUD Route Summary

**5 CRUD endpoints `/api/v1/api-credentials` (POST|GET|GET:id|PATCH|DELETE) with Zod discriminated-union validation, RBAC (operator + global_administrator), pt-BR error messages, and safe-by-default SAFE_FIELDS projection — single backend contract consumed by Phase 16 UI and wizard inline-create (CRED-05).**

## Performance

- **Duration:** 8m 12s (492s)
- **Started:** 2026-04-19T18:53:25Z
- **Completed:** 2026-04-19T19:01:37Z
- **Tasks:** 2 (Task 1 TDD: RED→GREEN; Task 2 wiring-only)
- **Files modified/created:** 3 (1 new route + 1 barrel + 1 test)

## Accomplishments

- **`server/routes/apiCredentials.ts` (NEW — 165 lines):** Single export `registerApiCredentialsRoutes(app)` mounting 5 endpoints.
  - **POST `/api/v1/api-credentials`:** Zod discriminated-union parse → `isValidUrlPattern` gate → `storage.createApiCredential` → 201 ApiCredentialSafe. 23505 mapped to 409 pt-BR; Zod fail → 400; pattern fail → 400; unexpected error → 500.
  - **GET `/api/v1/api-credentials`:** Filter via `?apiId=` and/or `?authType=` (string query params). Returns `ApiCredentialSafe[]`.
  - **GET `/api/v1/api-credentials/:id`:** 200 sanitized row or 404 pt-BR.
  - **PATCH `/api/v1/api-credentials/:id`:** `patchApiCredentialSchema.parse` → pattern gate → existence check → `storage.updateApiCredential` (re-encrypt handled by facade when `secret`/`mtlsCert`/... present).
  - **DELETE `/api/v1/api-credentials/:id`:** Existence check → `storage.deleteApiCredential` → 204.
  - **RBAC:** `isAuthenticatedWithPasswordCheck` + `requireOperator` applied to EVERY endpoint (5 mounts each).
  - **Logging (Armadilha 3):** `log.info({ apiCredentialId, authType, apiId }, 'api credential created')` — request body never logged.
- **`server/routes/index.ts` (+2 lines):** Import at line 26, registration call at line 76 (immediately after `registerApiRoutes(app)` for symmetry with Phase 9).
- **`server/__tests__/apiCredentials/route.test.ts` (+459 lines):** 30 tests GREEN promoting all 27 it.todo stubs + 3 extras (mtls not exposing secret, operator/admin 201, bearer_jwt opaque null).

## Endpoints Contract

```
POST   /api/v1/api-credentials       → 201 ApiCredentialSafe | 400 Zod | 400 pattern | 409 dup | 401 | 403 | 500
GET    /api/v1/api-credentials       → 200 ApiCredentialSafe[] (filters: ?apiId, ?authType) | 500
GET    /api/v1/api-credentials/:id   → 200 ApiCredentialSafe | 404 | 500
PATCH  /api/v1/api-credentials/:id   → 200 ApiCredentialSafe | 400 Zod | 400 pattern | 404 | 409 dup | 500
DELETE /api/v1/api-credentials/:id   → 204 | 404 | 500
```

**pt-BR error messages (verbatim):**
- 400 Zod: `"Dados de credencial inválidos"` (with `details: err?.errors`)
- 400 pattern: `"URL pattern inválido"`
- 404: `"Credencial não encontrada"`
- 409: `"Credencial já cadastrada com esse nome"`
- 500: `"Falha ao processar credencial"` / `"Falha ao listar credenciais"` / `"Falha ao buscar credencial"` / `"Falha ao remover credencial"`

**Phase 16 wizard contract (consumed verbatim):** Request body matches `insertApiCredentialSchema` (7-variant discriminated union, see Plan 10-02 SUMMARY §Zod schema); 201 response is `ApiCredentialSafe` (25 fields, zero secrets). Wizard injects `{id, name, authType}` from 201 body into select control.

## Task Commits

Each task was committed atomically via TDD flow (test RED → feat GREEN), plus a wiring commit:

1. **Task 1 RED: failing tests for POST|GET|PATCH|DELETE route** — `45f0612`
2. **Task 1 GREEN: registerApiCredentialsRoutes (5 CRUD endpoints)** — `380cb71`
3. **Task 2: register apiCredentials routes in barrel** — `3bcb605`

**Plan metadata:** pending — will include 10-05-SUMMARY.md, STATE.md, ROADMAP.md, REQUIREMENTS.md

## Files Created/Modified

- **`server/routes/apiCredentials.ts` (NEW):** 165 lines, single export `registerApiCredentialsRoutes(app)`.
- **`server/routes/index.ts` (modified, +2 lines):**
  - Line 26: `import { registerApiCredentialsRoutes } from "./apiCredentials";` (after `registerApiRoutes`)
  - Line 76: `registerApiCredentialsRoutes(app);` (after `registerApiRoutes(app);`)
- **`server/__tests__/apiCredentials/route.test.ts` (rewritten, +459/-40):** 30 `it()` tests (previously 27 `it.todo`).

## Decisions Made

- **In-process HTTP tests without supertest:** The plan cited `apisRoute.test.ts` as template, but that file is only `it.todo` stubs and the project does not depend on `supertest`. Installing `supertest` + `@types/supertest` was evaluated (~280KB transitive incl. `type-is`, `formidable`) and rejected in favor of a zero-new-dep pattern: `express().listen(0)` + native `fetch` (Node 20.x). The two approaches have identical test semantics for this route's coverage (status codes, JSON bodies, headers); supertest adds nothing needed here. If a future plan needs streaming or agent-reuse semantics we can still add it then.
- **Mock storage + localAuth + db + subscriptionService + logger:** Tests isolate the route from DB entirely. `middleware.ts` transitively imports `subscriptionService` which imports `db.ts` (hard DATABASE_URL requirement), so `vi.mock('../../db', ...)` + `vi.mock('../../services/subscriptionService', ...)` are required even though the route itself uses neither directly. Logger mock was added so the Armadilha 3 test ("NEVER log request body") can inspect captured events deterministically.
- **Error precedence is Zod → pattern → storage → 500:** Matches the plan's prescribed order. Added explicit 500 fallbacks with pt-BR messages for all 5 endpoints — the plan's example only showed 500 for POST, but applying uniformly prevents leaking stack traces if storage ever throws an uncaught error (Rule 2 — missing critical: defense in depth).
- **PATCH existence check before calling storage.updateApiCredential:** The plan mentions it in the example code. Without this, PATCH on a non-existent id would call the facade (which would silently no-op because drizzle's UPDATE returns 0 rows), and we'd return a broken 200 with undefined fields. The extra `getApiCredential` read keeps 404 semantics clean.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Corrected import path for `isAuthenticatedWithPasswordCheck`**
- **Found during:** Task 1 GREEN (route implementation)
- **Issue:** The plan's example code block (lines 174-177 of 10-05-PLAN.md) imported `isAuthenticatedWithPasswordCheck` from `./middleware`:
  ```ts
  import { isAuthenticatedWithPasswordCheck, requireOperator } from "./middleware";
  ```
  However `server/routes/middleware.ts` does NOT export `isAuthenticatedWithPasswordCheck` — that symbol lives in `server/localAuth.ts` (confirmed by `grep -rln 'export.*isAuthenticatedWithPasswordCheck'`: only `server/localAuth.ts`). The plan also noted "se em middleware.ts o nome do middleware operator for diferente (ex.: requireOperatorOrAdmin), AJUSTAR o import. O executor deve ler middleware.ts ANTES e usar o nome exato" — which validates this adjustment.
- **Fix:** Split imports into two lines matching actual exports:
  ```ts
  import { isAuthenticatedWithPasswordCheck } from "../localAuth";
  import { requireOperator } from "./middleware";
  ```
  Matches the exact pattern used in `server/routes/apis.ts` Phase 9 template (lines 3-4).
- **Files modified:** `server/routes/apiCredentials.ts` (lines 15-16)
- **Verification:** `npx tsc --noEmit` produces zero apiCredentials-related errors; full suite 487/487 passing (+30 vs baseline).
- **Committed in:** `380cb71` (Task 1 GREEN commit)

**2. [Rule 3 - Blocking] Added `vi.mock('../../db')` + `vi.mock('../../services/subscriptionService')` to route tests**
- **Found during:** Task 1 first GREEN run (route.test.ts → "DATABASE_URL must be set")
- **Issue:** Importing `../../routes/apiCredentials` pulls in `./middleware` (via `requireOperator`), which pulls in `../services/subscriptionService`, which pulls in `../db.ts`, which throws at top level if `process.env.DATABASE_URL` is unset. The initial test file mocked only `../../storage` and `../../localAuth`, which was insufficient.
- **Fix:** Added two more mocks to the test setup (matching the `threatGrouping.test.ts` pattern from the codebase):
  ```ts
  vi.mock('../../db', () => ({ db: {}, pool: {} }));
  vi.mock('../../services/subscriptionService', () => ({ subscriptionService: { isReadOnly: () => false } }));
  ```
- **Files modified:** `server/__tests__/apiCredentials/route.test.ts` (lines 36-40)
- **Verification:** All 30 route tests pass; phase 10 apiCredentials suite 143/143 passing.
- **Committed in:** `380cb71` (Task 1 GREEN commit — the blocking-import fix was part of the same GREEN iteration)

### Adaptation Decision (not a deviation)

- **Chose express+fetch over supertest:** See "Decisions Made" above. The plan's template reference was itself a set of `it.todo` stubs, so there was no concrete supertest precedent to follow. Zero new dependencies added to `package.json`.

---

**Total deviations:** 2 auto-fixed (both Rule 3 — blocking issues in import graph)
**Impact on plan:** Both auto-fixes are mechanical import-graph corrections that a strictly-typed test run would flag as missing references. No scope expansion. All plan truths satisfied; all acceptance criteria satisfied. Full `npm run test` +30 tests over baseline with zero regressions.

## Issues Encountered

- **Pre-existing test failure:** `server/services/__tests__/actionPlanService.test.ts` requires DATABASE_URL (documented in `.planning/phases/10-api-credentials/deferred-items.md` since Plan 10-01). Count unchanged across all of Phase 10.
- **Pre-existing TS errors:** 75 pre-existing TypeScript errors (unchanged count before and after this plan). Zero errors matching `apiCredential|registerApi` pattern.

## User Setup Required

None — route is a pure in-process module; boot path unchanged (routes/index.ts barrel registers at app startup). `drizzle-kit push` not needed (no schema change in this plan).

## Next Phase Readiness

- **Phase 10 CLOSED:** All 5 plans complete (CRED-01..05 ✓). Storage facade, boot guard, runtime resolver, URL pattern matcher, JWT exp decoder, and full CRUD route all in place and test-covered.
- **Phase 11 (runtime executor):** Can now resolve credentials via `storage.resolveApiCredential(apiId, endpointUrl)` → `storage.getApiCredentialWithSecret(id)` → `encryptionService.decryptCredential(secretEncrypted, dekEncrypted)` → inject per-authType into outgoing HTTP request.
- **Phase 16 (dedicated UI + wizard inline-create):** Backend contract is frozen. Wizard sends `POST /api/v1/api-credentials` with `{ authType, name, secret, ... }` matching `insertApiCredentialSchema` — receives 201 with `{id, name, authType, ...}` to inject into the credential-select control. Dedicated UI uses the full CRUD surface identically.
- **Phase 10 test count:** 143 tests GREEN (9 guard + 20 storage + 30 route + 38 schema + 27 urlPattern + 12 resolveCredential + 7 jwtExp). Plan success criterion "≥ 80 active tests" exceeded by 63.

## Self-Check: PASSED

Files verified to exist:
- FOUND: /opt/samureye/server/routes/apiCredentials.ts (165 lines)
- FOUND: /opt/samureye/server/routes/index.ts (modified, +2 lines at 26 and 76)
- FOUND: /opt/samureye/server/__tests__/apiCredentials/route.test.ts (459 lines, 30 it() tests, 0 it.todo)

Commits verified:
- FOUND: 45f0612 (Task 1 RED — test: failing tests for POST|GET|PATCH|DELETE)
- FOUND: 380cb71 (Task 1 GREEN — feat: registerApiCredentialsRoutes 5 CRUD endpoints)
- FOUND: 3bcb605 (Task 2 — feat: register apiCredentials routes in barrel)

Suite verified:
- `npm run test -- server/__tests__/apiCredentials`: 143 passed / 0 failed / 0 todo (in 1.41s)
- `npm run test`: 487 passed + 80 todo + 1 pre-existing DATABASE_URL failure (actionPlanService — deferred); +30 tests vs baseline of 457
- `npx tsc --noEmit`: 75 errors (baseline unchanged); zero errors matching `apiCredential|registerApi` grep

Acceptance criteria:
- Grep `export function registerApiCredentialsRoutes\(app: Express\): void`: **1 match** in apiCredentials.ts
- Grep `app\.post.*"/api/v1/api-credentials"`: **1 match** (line 22)
- Grep `app\.get.*"/api/v1/api-credentials"` (list): **1 match** (line 64)
- Grep `app\.get.*"/api/v1/api-credentials/:id"`: **1 match** (line 85)
- Grep `app\.patch.*"/api/v1/api-credentials/:id"`: **1 match** (line 104)
- Grep `app\.delete.*"/api/v1/api-credentials/:id"`: **1 match** (line 145)
- Grep `insertApiCredentialSchema\.parse\(req\.body\)`: **1 match**
- Grep `patchApiCredentialSchema\.parse\(req\.body\)`: **1 match**
- Grep `isValidUrlPattern\(`: **2 matches** (POST + PATCH)
- Grep `"Credencial já cadastrada com esse nome"`: **2 matches** (POST + PATCH 409)
- Grep `"Credencial não encontrada"`: **3 matches** (GET :id + PATCH + DELETE)
- Grep `"URL pattern inválido"`: **2 matches**
- Grep `"Dados de credencial inválidos"`: **2 matches**
- Grep `error\?\.code === "23505"`: **2 matches** (POST + PATCH)
- Grep `requireOperator`: **6 matches** (1 import + 5 endpoint mounts)
- Grep `isAuthenticatedWithPasswordCheck`: **6 matches** (1 import + 5 endpoint mounts)
- Grep `log\.info\(\s*\{[^}]*apiCredentialId`: **2 matches** (creation + patch/delete logs)
- Grep `req\.body` inside `log\.` calls: **0 matches** (Armadilha 3 satisfied)
- Grep `it\.todo` in route.test.ts: **0 matches** (all promoted)
- Barrel order check: registerApiCredentialsRoutes(app); at line 76 > registerApiRoutes(app); at line 75 ✓
- `grep -n "api-credentials" server/routes/index.ts`: **0 matches** (registered via function name, not string) ✓
- `grep -n "registerApiCredentialsRoutes" server/routes/index.ts`: **2 matches** (import line 26 + call line 76) ✓

---
*Phase: 10-api-credentials*
*Completed: 2026-04-19*
