---
phase: 10-api-credentials
verified: 2026-04-19T19:10:00Z
status: human_needed
must_haves_verified: 5/5
re_verification:
  previous_status: none
  previous_score: null
  gaps_closed: []
  gaps_remaining: []
  regressions: []
human_verification:
  - test: "Boot-time idempotent guard — start the server against a fresh Postgres and confirm api_credentials enum + table + 3 indexes são criados; reiniciar o app e confirmar zero erros (CREATE IF NOT EXISTS idempotente)"
    expected: "Log `ensureApiCredentialTables complete` aparece duas vezes (boot 1 cria, boot 2 no-op). Nenhum erro em `pg_indexes`/`pg_type`."
    why_human: "Requer Postgres real + ciclo de boot; mocks de teste cobrem a lógica de branching, mas sequência após `ensureApiTables()` no boot só é observável num ambiente integrado."
  - test: "CRED-05 — create-inline e retrieve pelo mesmo cliente HTTP (simulando o wizard do Phase 16)"
    expected: "`POST /api/v1/api-credentials` retorna 201 com `ApiCredentialSafe` (sem secret*); `GET /api/v1/api-credentials` inclui a credencial recém-criada de imediato (sem refresh de página)."
    why_human: "Phase 10 entrega o contrato backend; UI real do wizard só existe no Phase 16. Smoke test de contract compliance de `curl` pode ser feito sem UI."
  - test: "End-to-end cross-user — criar `Stripe API` como operator A e como operator B; ambos devem suceder (UQ(name, createdBy) e não UQ(name) global)"
    expected: "Dois 201s distintos, IDs diferentes, mesmos nomes preservados. Repetir como A retorna 409."
    why_human: "Requer 2 sessões reais de usuário; tests de rota mockam auth para single user."
---

# Phase 10: API Credentials Verification Report

**Phase Goal:** Ship a credential store for the 7 supported API auth types that reuses the platform's existing KEK/DEK encryption, with URL-pattern mapping and priority resolution so the engine picks the right credential per endpoint.

**Verified:** 2026-04-19T19:10:00Z
**Status:** human_needed (all automated verifications passed; 3 items deferred to integration-level manual checks)
**Re-verification:** No — initial verification
**Source of truth:** ROADMAP.md §"Phase 10: API Credentials" Success Criteria + REQUIREMENTS.md CRED-01..05 + per-plan `must_haves` frontmatter.

---

## Goal Achievement

### Observable Truths (derived from ROADMAP Success Criteria + plan must_haves)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | User can store a credential for each of the 7 auth types via the CRUD route | ✓ VERIFIED | `insertApiCredentialSchema` = `z.discriminatedUnion("authType", [...7 variantes])` em `shared/schema.ts:1424-1467`; rota `POST /api/v1/api-credentials` em `server/routes/apiCredentials.ts:22-61` aceita qualquer variante; 30 route tests + 38 schema tests GREEN cobrem os 7 types |
| 2 | Credentials at rest are encrypted reusando o KEK/DEK existente — zero nova crypto | ✓ VERIFIED | `server/storage/apiCredentials.ts:14` `import { encryptionService }`; `createApiCredential` linha 120-121 chama `encryptionService.encryptCredential(secretToEncrypt)`; mTLS concatena em JSON antes de criptografar (linhas 90-95); zero arquivo novo em `server/services/encryption.ts` |
| 3 | Credentials são retornadas SEMPRE sanitizadas (sem secret*/dek*) via facade; getWithSecret é interno | ✓ VERIFIED | `SAFE_FIELDS` explicit list em `server/storage/apiCredentials.ts:24-49` NÃO inclui secret_encrypted/dek_encrypted; `getApiCredential`, `listApiCredentials`, `resolveApiCredential`, `createApiCredential`, `updateApiCredential` usam `SAFE_FIELDS`; só `getApiCredentialWithSecret` (linha 78) retorna shape completo via `db.select()` sem projeção |
| 4 | User pode mapear cada credencial a um URL pattern (glob) e o engine resolve apenas matching | ✓ VERIFIED | Coluna `urlPattern text NOT NULL DEFAULT '*'` em `shared/schema.ts:1343`; helper `matchUrlPattern(pattern, url)` em `server/services/credentials/matchUrlPattern.ts:12-21`; `isValidUrlPattern` em linha 27 valida no POST; `resolveApiCredential(apiId, endpointUrl)` em `server/storage/apiCredentials.ts:214-240` aplica `matchUrlPattern` aos candidatos |
| 5 | Quando múltiplas credenciais casam o mesmo URL, prioridade determina seleção (priority ASC → specificity → createdAt) | ✓ VERIFIED | `priority integer NOT NULL DEFAULT 100` em `shared/schema.ts:1344`; algoritmo implementado em `server/storage/apiCredentials.ts:228-237`: `a.priority - b.priority` primeiro, depois `countLiterals(b)-countLiterals(a)` (specificity), depois `aTime - bTime` (createdAt ASC); 12 tests em `resolveCredential.test.ts` GREEN |
| 6 | User pode criar credencial inline durante wizard (mesma rota POST) | ✓ VERIFIED (backend contract) | `POST /api/v1/api-credentials` em `server/routes/apiCredentials.ts:22-61` retorna 201 + `ApiCredentialSafe` (sem secret); é a ÚNICA rota de criação (zero código duplicado para wizard); UI real é Phase 16 (VALIDATION.md linha 67: "Deferido — validar SC5 apenas via rota POST + refetch backend no Phase 10"). Backend pronto para consumo do wizard |

**Score:** 6/6 truths verified (considerando Success Criteria do ROADMAP + must_haves dos 5 plans).

### Required Artifacts (from plans' must_haves)

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `shared/schema.ts` | apiAuthTypeEnum + apiCredentials pgTable + insertApiCredentialSchema discriminated union + tipos | ✓ VERIFIED | enum em linhas 113-121 (7 valores em ordem fixa); table em 1335-1375 com indexes + FK apiId→apis(SET NULL) + FK createdBy/updatedBy→users + UQ(name, createdBy); discriminated union em 1424-1467 (7 variantes); tipos em 1498-1507 (`ApiCredential`, `ApiCredentialSafe`, `ApiCredentialWithSecret`, `InsertApiCredential`, `PatchApiCredential`, `ApiAuthType`) |
| `server/services/credentials/matchUrlPattern.ts` | matchUrlPattern + isValidUrlPattern | ✓ VERIFIED | 31 linhas, 2 exports, função pura; 27 tests GREEN em urlPattern.test.ts |
| `server/services/credentials/decodeJwtExp.ts` | decodeJwtExp | ✓ VERIFIED | 23 linhas, 1 export; retorna `Date | null` sem lançar; 7 tests GREEN em jwtExp.test.ts |
| `server/storage/apiCredentials.ts` | Facade com 7 funções | ✓ VERIFIED | 240 linhas; exports: `listApiCredentials`, `getApiCredential`, `getApiCredentialWithSecret`, `createApiCredential`, `updateApiCredential`, `deleteApiCredential`, `resolveApiCredential` (todas as 7); `SAFE_FIELDS` explicit list exclui secret*/dek*; 20 tests GREEN em storage.test.ts |
| `server/storage/database-init.ts` | ensureApiCredentialTables() idempotente | ✓ VERIFIED | Função em linhas 348-439; checa `pg_type` antes de criar enum, `pg_tables` antes de criar table, `pg_indexes` antes de cada index; **wired** em linha 142 (`await ensureApiCredentialTables()` APÓS `ensureApiTables()`); 9 tests GREEN em guard.test.ts validando caminhos idempotentes + error path |
| `server/storage/interface.ts` | IStorage com 7 assinaturas | ✓ VERIFIED | Linhas 294-300 contêm todos os 7 signatures na interface `IStorage` |
| `server/storage/index.ts` | DatabaseStorage namespace import + method wiring | ✓ VERIFIED | linha 16: `import * as apiCredentialOps from "./apiCredentials"`; linhas 212-218: 7 propriedades atribuídas em DatabaseStorage |
| `server/routes/apiCredentials.ts` | 5 endpoints CRUD + registerApiCredentialsRoutes | ✓ VERIFIED | 164 linhas; export único `registerApiCredentialsRoutes(app)` com POST, GET list, GET :id, PATCH, DELETE; todos com `isAuthenticatedWithPasswordCheck + requireOperator` middleware chain; 30 tests GREEN em route.test.ts |
| `server/routes/index.ts` | Barrel com registro | ✓ VERIFIED | linha 26: `import { registerApiCredentialsRoutes } from "./apiCredentials"`; linha 76: `registerApiCredentialsRoutes(app)` invocado junto aos demais módulos |
| 6 test files + factory helper | Nyquist infra (Wave 0) | ✓ VERIFIED | Todos os 6 test files existem + factory em `server/__tests__/helpers/apiCredentialFactory.ts` (154 linhas, expõe `createTestApiCredential`, `URL_PATTERN_MATRIX`, `TEST_PEM_CERT`, `TEST_PEM_KEY`); **143 tests passam, 0 skipped, 0 `it.todo` não promovidos** |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|----|--------|---------|
| `shared/schema.ts apiCredentials.apiId` | `shared/schema.ts apis.id` | `references(() => apis.id, { onDelete: "set null" })` | ✓ WIRED | linha 1345 |
| `shared/schema.ts apiCredentials.createdBy/updatedBy` | `shared/schema.ts users.id` | `references(() => users.id)` | ✓ WIRED | linhas 1369-1370 |
| `server/storage/apiCredentials.ts createApiCredential` | `server/services/encryption.ts` | `encryptionService.encryptCredential()` | ✓ WIRED | linha 121 (create) + linha 181 (update re-encrypt) |
| `server/storage/apiCredentials.ts resolveApiCredential` | `server/services/credentials/matchUrlPattern.ts` | `import { matchUrlPattern }` | ✓ WIRED | linha 15 import, linha 225 uso |
| `server/storage/apiCredentials.ts createApiCredential` | `server/services/credentials/decodeJwtExp.ts` | `import { decodeJwtExp }` para bearer_jwt | ✓ WIRED | linha 16 import, linha 126 uso (create) + linha 186 (update) |
| `server/storage/database-init.ts initializeDatabaseStructure` | `ensureApiCredentialTables()` | `await` invocation APÓS `ensureApiTables()` | ✓ WIRED | linha 142, imediatamente após linha 139 `await ensureApiTables()` |
| `server/storage/index.ts DatabaseStorage` | `server/storage/apiCredentials.ts` | `import * as apiCredentialOps` | ✓ WIRED | linha 16 + atribuições 212-218 |
| `server/routes/apiCredentials.ts` | `@shared/schema` | `import { insertApiCredentialSchema, patchApiCredentialSchema, type ApiAuthType }` | ✓ WIRED | linhas 8-12 |
| `server/routes/apiCredentials.ts` | `storage` (DatabaseStorage) | `storage.createApiCredential/.listApiCredentials/...` | ✓ WIRED | 5 call sites (linhas 45, 75, 91, 125, 155) |
| `server/routes/apiCredentials.ts` | `server/services/credentials/matchUrlPattern.ts` | `import { isValidUrlPattern }` | ✓ WIRED | linha 13 + linhas 39, 117 (POST + PATCH gate) |
| `server/routes/index.ts` | `server/routes/apiCredentials.ts` | import + register call | ✓ WIRED | linhas 26, 76 |
| `server/lib/logger.ts` pino redaction | `secretEncrypted`, `dekEncrypted`, `authorization`, `secret` | paths pré-existentes cobrem payloads novos | ✓ WIRED | linhas 29, 33-34, 38, 52, 55-56 (paths `secret`, `*.secretEncrypted`, `*.dekEncrypted`, `authorization`) |

**All 12 critical links WIRED.** Nenhum link orfão, parcial ou NOT_WIRED.

### Requirements Coverage

| Requirement | Source Plan(s) | Description | Status | Evidence |
|-------------|---------------|-------------|--------|----------|
| **CRED-01** | 01, 02, 04, 05 | User can store API credentials with 7 auth types | ✓ SATISFIED | Schema discriminated union (7 variants) + storage facade + rota POST validam e persistem as 7 variantes (truths #1, #2) |
| **CRED-02** | 01, 02, 04 | System encrypts credentials reusing KEK/DEK pattern (no new crypto) | ✓ SATISFIED | `encryptionService.encryptCredential()` chamado em `server/storage/apiCredentials.ts:121`; zero crypto nova introduzida; colunas `secretEncrypted`/`dekEncrypted` em schema; mTLS via JSON.stringify antes de encryptCredential (truth #2) |
| **CRED-03** | 01, 03, 04 | User maps each credential to URL pattern (glob/prefix); engine applies only matching | ✓ SATISFIED | Coluna `urlPattern` + helper `matchUrlPattern(pattern, url)` + `isValidUrlPattern` na rota; `resolveApiCredential` filtra candidatos via `matchUrlPattern` (truth #4) |
| **CRED-04** | 01, 03, 04 | User can prioritize credentials when multiple match same URL | ✓ SATISFIED | Coluna `priority integer DEFAULT 100` + algoritmo em `resolveApiCredential` (priority ASC → specificity → createdAt ASC); 12 tests GREEN (truth #5) |
| **CRED-05** | 01, 05 | User can create credential inline during journey wizard | ✓ SATISFIED (backend-only) | `POST /api/v1/api-credentials` é única rota; Phase 10 entrega contract backend; UI real Phase 16 (documentado em 10-VALIDATION.md:67 como deferido). Rota devolve `ApiCredentialSafe` imediatamente utilizável por select do wizard (truth #6) |

**Orphaned requirements:** NENHUM. REQUIREMENTS.md linha 188 declara "Phase 10 (API Credentials): 5 (CRED-01..05)" e linhas 138-142 mapeiam cada CRED-0X para Phase 10; todos os 5 IDs aparecem em pelo menos um plan `requirements:` field (CRED-01 em 4 plans, CRED-02 em 3, CRED-03 em 3, CRED-04 em 3, CRED-05 em 2). Plan 10-01 cobre todos os 5 (infra Nyquist).

### Anti-Patterns Scan

Executado scan em todos os arquivos novos/modificados do phase (shared/schema.ts região 113-1507; server/services/credentials/; server/storage/apiCredentials.ts; server/storage/database-init.ts região Phase 10; server/storage/interface.ts; server/storage/index.ts; server/routes/apiCredentials.ts; server/routes/index.ts; 7 test files; factory):

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| — | — | — | — | **Nenhum anti-pattern encontrado.** Zero TODO/FIXME/PLACEHOLDER no código de produção do phase. Zero `return null`/`return {}` vazios. Zero console.log. Zero `it.todo` remanescente em test files (1 ocorrência em `schema.test.ts:1` é referência em comentário de cabeçalho, não stub ativo — arquivo tem 38 tests GREEN). Zero `it.skip`/`describe.skip`. |

### Test Run Summary

**Phase 10 suite (`npm run test -- server/__tests__/apiCredentials`):**
```
Test Files  7 passed (7)
Tests       143 passed (143)
Duration    1.52s
```
Files: `schema.test.ts` (38), `storage.test.ts` (20), `route.test.ts` (30), `urlPattern.test.ts` (27), `resolveCredential.test.ts` (12), `guard.test.ts` (9), `jwtExp.test.ts` (7). **100% GREEN.**

**Full suite (`npm run test`):**
```
Test Files  1 failed | 30 passed | 5 skipped (36)
Tests       487 passed | 80 todo (567)
```
- 1 failed: `server/services/__tests__/actionPlanService.test.ts` — falha **pré-existente**, causada por `DATABASE_URL` não-setado em ambiente; documentada em `.planning/phases/10-api-credentials/deferred-items.md` como deferida (predates Phase 10 em commit `5a0e05e`).
- 80 todo: stubs Nyquist de OUTRAS phases (Phase 9 apisRoute, backfillApiDiscovery, ensureApiTables etc); fora do escopo.
- **Zero regressão Phase 10.**

### Human Verification Required

Embora todos os checks automatizados passem, 3 itens se beneficiam de validação manual por limitação de cobertura via unit/mock:

#### 1. Boot-time idempotency integration

- **Test:** Iniciar o servidor contra Postgres limpo e depois reiniciar sem limpar.
- **Expected:** No 1º boot: logs `creating api_auth_type enum`, `creating api_credentials table`, 3x `creating api_credentials index`, `ensureApiCredentialTables complete`. No 2º boot: apenas `ensureApiCredentialTables complete` (no-op em enum/table/indexes já existentes).
- **Why human:** `guard.test.ts` cobre todos os branches (enum/table/indexes existentes vs ausentes, erro simulado) via mock de `db.execute`, mas a sequência real pós-`ensureApiTables()` em ambiente integrado requer Postgres real.

#### 2. CRED-05 inline-create flow (contract-level)

- **Test:** `curl -X POST /api/v1/api-credentials` com payload dos 7 auth types, seguido de `curl GET /api/v1/api-credentials` confirmando inclusão imediata.
- **Expected:** Cada POST retorna 201 + `ApiCredentialSafe` (ZERO `secretEncrypted`/`dekEncrypted`/`secret`/`mtlsCert`/`mtlsKey`/`mtlsCa` no response body); GET subsequente retorna nova credencial com projeção SAFE idêntica.
- **Why human:** UI real do wizard é Phase 16; backend contract precisa ser smoke-tested antes de Phase 11/16 dependerem dele. VALIDATION.md já documenta como deferido para validação HTTP direta.

#### 3. UQ(name, createdBy) cross-user semantics

- **Test:** Com 2 usuários distintos (operator A e operator B), criar `"Stripe API"` em ambos; depois tentar criar novamente com cada um.
- **Expected:** Ambos os primeiros POSTs retornam 201 (ids distintos, nome duplicado permitido entre usuários); segundos POSTs com mesmo nome+mesmo createdBy retornam 409 pt-BR "Credencial já cadastrada com esse nome".
- **Why human:** Route tests mockam autenticação single-user; só integração real com 2 sessões valida a semântica de "nome único POR USUÁRIO" (UQ_api_credentials_name_created_by).

### Gaps Summary

**Nenhum gap bloqueante.** Todos os 6 observable truths derived do ROADMAP Success Criteria estão VERIFIED; todos os 10 artifacts (schema, 2 helpers, facade, guard, interface, DatabaseStorage, rota, barrel, testes/factory) estão presentes, substantivos e wired; todos os 12 key links verificados; todos os 5 requirements CRED-01..05 satisfeitos; zero anti-pattern; 143 tests dedicados + 487 total GREEN.

Os 3 itens humanos são **validações de integração** que complementam (não substituem) a cobertura automatizada — um boot real contra Postgres, um smoke test HTTP end-to-end do contrato de wizard, e uma verificação cross-user de unique constraint. Nenhum deles indica ausência de código; são verificações de ambiente que caem fora do escopo de unit/route tests por design.

**Status final:** `human_needed` — phase entregou integralmente o que o ROADMAP prometeu, com 3 checkpoints recomendados para sign-off operacional antes de liberar Phase 11.

---

_Verified: 2026-04-19T19:10:00Z_
_Verifier: Claude Opus 4.7 (gsd-verifier)_
