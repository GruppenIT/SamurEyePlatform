# Phase 12: Security Testing — Passive - Context

**Gathered:** 2026-04-20
**Status:** Ready for planning

<domain>
## Phase Boundary

Entregar o **primeiro batch de testes de segurança stateless** do OWASP API Top 10 (2023), consumindo endpoints já descobertos e enriquecidos pelo Phase 11 e gerando rows em `api_findings`.

Escopo do Phase 12:
- **TEST-01 (unauth)** — Nuclei com tags oficiais `misconfig,exposure,graphql,cors` contra todos os endpoints descobertos, sem credenciais, gerando findings API8 (Misconfiguration) e API9 (Inventory).
- **TEST-02 (authed)** — Auth-failure tests in-house TypeScript para os 4 vetores: JWT `alg: none`, `kid` injection, token reuse (expirado), API key leakage em response body; gerando findings API2.
- **API9 Inventory signals** — Phase 12 interpreta diretamente sinais já persistidos pelo Phase 11 (spec público exposto, GraphQL introspection aberta, endpoints vindos apenas de `kiterunner` sem contraparte em spec) e gera findings API9 antes do Nuclei rodar.
- **Entrypoint trip-leg** — função `runApiPassiveTests(apiId, opts, jobId?)` + rota interna `POST /api/v1/apis/:id/test/passive` + CLI de operador.
- **Internal read path** — `GET /api/v1/api-findings` com filtros por API/endpoint/category/severity/status/job.
- **dryRun determinístico** — fixtures locais (JSONL Nuclei + respostas JWT/leakage mockadas) satisfazem success criteria #4 sem dependência de `/healthz/api-test-target` (Phase 15).

**Fora de escopo deste phase (em outras phases):**
- Testes stateful cross-identity: BOLA/BFLA/BOPLA/rate-limit/SSRF → Phase 13 (TEST-03..07).
- Sanitização formal de evidence (redação de headers auth, PII CPF/CNPJ/email/credit-card, truncagem final) → Phase 14 (FIND-02). Phase 12 aplica defensive naming (`bodySnippet`, cap 8KB via Zod) mas não é o owner da sanitização.
- Promoção para `threats` e WebSocket events → Phase 14 (FIND-03, FIND-04).
- Enum `api_security` em `journey_type`, wiring no journeyExecutor, abort via `/jobs/:id/abort`, authorization ack, rate ceiling de 50 req/s, audit log formal, endpoint `/healthz/api-test-target` → Phase 15 (JRNY + SAFE).
- UI de findings filter por `source=api_security`, curl reproduction, false-positive marking → Phase 16.

Phase 12 é **runtime de testing passivo** — delivery de 2 scanners novos (`nucleiApi.ts` + `authFailure.ts`) + orquestrador (`journeys/apiPassiveTests.ts`) + interface pública (função + rota + CLI) + read path de findings + API9 inventory signal generator. A journey `api_security` end-to-end só existe após Phase 15 wirar.

</domain>

<decisions>
## Implementation Decisions

### Templates Nuclei + API8/API9 scope

- **Tags oficiais estritamente**: `-tags misconfig,exposure,graphql,cors` (exatamente o que TEST-01 lista no REQUIREMENTS). Sem severity mínima — Nuclei classifica. Sem adição de `tech`/`fingerprint` (evita ruído falso positivo).
- **Granularidade: 1 spawn Nuclei por API**. Phase 12 constrói lista absoluta `baseUrl + endpoint.path` para todos os `api_endpoints` da API, passa via stdin/`-l` para Nuclei. Um único processo child por API; Nuclei internamente itera. Respeita rate cap defensivo global e reduz pressão no `processTracker`.
- **Templates oficiais apenas** — reusa `/tmp/nuclei/nuclei-templates` gerenciado pelo `nucleiPreflight.ts` existente. NÃO versiona templates custom dentro do repo (reduz custo de manutenção; Phase 13 pode adicionar se gap identificado).
- **API9 Inventory via query direta em `apis`/`api_endpoints`** (NÃO via log scraping do Phase 11):
  - Checa `apis.specUrl IS NOT NULL AND apis.specHash IS NOT NULL` E o fetch original foi unauth — sinal de **spec publicamente exposto** → finding `api9_inventory_2023` severity `medium`, title `"Especificação de API exposta publicamente"`.
  - Checa `apis.apiType='graphql'` com endpoints discovered via spec (introspection sucedeu) → finding `api9_inventory_2023` severity `medium`, title `"GraphQL introspection habilitado em produção"`.
  - Checa `api_endpoints` onde `discoverySources = ['kiterunner']` (exclusivo, sem spec/crawler) com httpxStatus ∈ {200, 401, 403} → finding `api9_inventory_2023` severity `low` por endpoint, title `"Endpoint oculto descoberto por brute-force"`.
  - Sinal "specPubliclyExposed" é inferido por Phase 12 via heurística: `specLastFetchedAt IS NOT NULL` + query de logs é **fora de escopo** (acoplamento frágil). O fato do spec ter sido persistido sem cred é inferência suficiente — se Phase 11 precisou de cred, o spec não é público no contexto OWASP API9.
  - Esses findings rodam ANTES do Nuclei scan; separam origem (query DB vs scanner output) e evitam dependência de order.

### Auth-failure tests (TEST-02 / API2)

- **Implementação in-house TypeScript** — mesmo padrão que PROJECT.md Key Decision para BOLA/BFLA/BOPLA: vectors que requerem cred real e inspeção stateful de response não cabem em templates estáticos de Nuclei. Módulo `server/services/scanners/api/authFailure.ts`.
- **Escopo de endpoints**: apenas endpoints com `requiresAuth=true` E `resolveApiCredential()` retorna cred compatível (bearer_jwt/api_key_header/api_key_query). Endpoints com `requiresAuth IN (NULL, false)` = skip + log. Endpoints sem cred resolvível = skip + log (não gera finding; ausência de cred ≠ finding de auth).
- **Cobertura por auth type**:
  - JWT alg:none / kid injection / token reuse: somente `bearer_jwt` (precisa JWT real para manipular).
  - API key leakage: `api_key_header` e `api_key_query` (observa se valor da cred vaza em response body de OUTROS endpoints da mesma API — heurística: faz request autenticado em endpoint A, lê response; se string do API key aparece em body, gera finding).
  - OAuth2 `bearer_jwt` emitido por Phase 11 mint: **fora de escopo Phase 12** (runtime-minted token; Phase 15 pode estender).
- **Os 4 vetores detalhados**:
  1. **JWT alg:none**: decodifica JWT original → re-emite com header `{"alg":"none"}` + payload original + signature vazia → substitui cred no request → se response `status < 400` e inclui dados protegidos: finding severity `critical`. Evidence `extractedValues = { jwtAlg: 'none', originalAlg: 'RS256'|'HS256'|... }`.
  2. **kid injection**: parse header JWT → substitui `kid` por payloads clássicos (`../etc/passwd`, `' OR '1'='1`, `http://attacker.com/jwks`) → request → se `status < 400`: finding severity `high`. Evidence `extractedValues = { kidValue: 'path-traversal-attempted', originalKid: '<mascarado>' }`.
  3. **token reuse**: extrai `exp` do JWT via `decodeJwtExp` (Phase 10 helper); se token tem `exp < now()`, faz request com JWT expirado; se `status < 400`: finding severity `high`. Se JWT opaco/sem exp: skip + log. Evidence `extractedValues = { tokenExpiredAt: ISO, acceptedAt: ISO }`.
  4. **API key leakage**: para `api_key_*`, faz GET autenticado em até 5 endpoints GET da API; escaneia cada response body por presença da string da cred decriptada (`getApiCredentialWithSecret`); se match: finding severity `high`. Evidence `extractedValues = { leakedKeyPrefix: 'sk_abc***', leakedInEndpointId: '<uuid>' }` (mascara tudo após char 3).
- **Extracted values sanitização de cred**: NUNCA armazenar token/key completo em `evidence.extractedValues`. Mascarar em call site (prefix de 3 chars + `***`). Phase 14 reforça globalmente; Phase 12 aplica defensive-by-default para cobertura parcial até lá.
- **Rate cap em auth-failure**: max 4 requests por endpoint (1 por vetor aplicável), 1s delay entre requests por endpoint, respeita ceiling de 10 req/s global.

### Entrypoint + contract + dryRun + preflight

- **Phase 12 expõe 3 superfícies** (espelhando Phase 11):
  1. **Função pura** `runApiPassiveTests(apiId, opts, jobId?): Promise<PassiveTestResult>` em `server/services/journeys/apiPassiveTests.ts`.
  2. **Rota interna** `POST /api/v1/apis/:id/test/passive` (RBAC `global_administrator` + `operator`, body aceita `opts`).
  3. **CLI** `server/scripts/runApiPassiveTests.ts --api=<id> [--no-nuclei] [--no-auth-failure] [--dry-run] [--credential=<id>]` + doc `docs/operations/run-api-passive-tests.md`.
- **Shape do `opts`** (Zod em `shared/schema.ts`):
  ```ts
  type ApiPassiveTestOpts = {
    stages: {
      nucleiPassive?: boolean;    // default true — TEST-01 Nuclei misconfig/exposure/graphql/cors
      authFailure?: boolean;       // default true — TEST-02 JWT + leakage (in-house TS)
      api9Inventory?: boolean;     // default true — sinais DB-derived
    };
    credentialIdOverride?: string;  // força cred específica em vez de resolve
    endpointIds?: string[];         // subset opcional; default = todos endpoints da API
    dryRun?: boolean;               // default false
    nuclei?: {
      rateLimit?: number;           // default 10 req/s (-rl)
      timeoutSec?: number;          // default 10s por request (-timeout)
    };
  };
  ```
- **PassiveTestResult shape** (contrato público consumido por Phase 15):
  ```ts
  type PassiveTestResult = {
    apiId: string;
    stagesRun: Array<'nuclei_passive' | 'auth_failure' | 'api9_inventory'>;
    stagesSkipped: Array<{ stage: string; reason: string }>;
    findingsCreated: number;
    findingsUpdated: number;  // dedupe path
    findingsByCategory: Record<string, number>;  // { api8_misconfiguration_2023: 3, api9_inventory_2023: 2, api2_broken_auth_2023: 1 }
    findingsBySeverity: Record<string, number>;  // { critical: 1, high: 2, medium: 3 }
    cancelled: boolean;
    dryRun: boolean;
    durationMs: number;
  };
  ```
- **dryRun determinístico com fixtures locais**:
  - Fixtures em `server/__tests__/fixtures/api-passive/`:
    - `nuclei-passive-mock.jsonl` — 3-5 findings Nuclei representativos (1 misconfig, 1 exposure, 1 graphql, 1 cors).
    - `jwt-alg-none-response.json`, `jwt-kid-injection-response.json`, `jwt-expired-response.json`, `api-key-leakage-body.json` — mocks de response para auth-failure.
  - `opts.dryRun=true`: NÃO spawn Nuclei, NÃO faz HTTP request real. `authFailure` lê fixtures; `nucleiPassive` lê `nuclei-passive-mock.jsonl` e processa como se fosse output real; `api9Inventory` roda normal (é query DB, não emite tráfego).
  - Findings são inseridos com flag `isDryRun` em log.info apenas (sem coluna nova); row em `api_findings` é criada normalmente mas título prefixado com `[DRY-RUN] `. Isso satisfaz success criteria #4 (reprodutível, determinístico) sem mudança de schema nem bloqueio em Phase 15.
  - Fixtures versionadas no repo, SHA hash implícito via git (sem checksum explícito — não é binário).
- **Preflight** — reusa `preflightNuclei` existente direto:
  - `nucleiPassive` stage: chama `preflightNuclei(log)` antes de spawn. Se `ok=false`: skipa stage + `log.error` + prossegue `authFailure` (que não precisa de Nuclei).
  - `authFailure` stage: sem preflight (não tem binário externo; usa `fetch` nativo + `crypto`).
  - `api9Inventory`: sem preflight (query DB).
- **Defensive defaults**:
  - Nuclei: `-rl 10` (10 req/s) + `-timeout 10` + `-retries 0` + `-silent` + `-jsonl` (streaming).
  - Timeout total por API: 30 minutos (SIGTERM graceful via `processTracker`; SIGKILL após 5s se não responde).
  - `AbortController` atrelado ao `jobId` via `processTracker.registerProcess(jobId, child)` — padrão Phase 11.
  - APIs processadas sequencialmente dentro de um job (simples; Phase 15 pode paralelizar).
- **Cancelamento cooperativo**: check `jobQueue.isJobCancelled(jobId)` antes de cada stage e entre endpoints em `authFailure`. Findings já persistidos permanecem (padrão Phase 11 "resultados parciais persistem em cancel").

### Findings dedupe + evidence + remediation + read path

- **Dedupe chave: `(apiEndpointId, owaspCategory, title)`**:
  - Se existe row com essa tripla onde `status != 'closed'`: **update** — re-popula `evidence` com última execução, atualiza `jobId` para a run atual, `updatedAt=now`, preserva `status` corrente. NÃO cria nova row.
  - Se existe mas `status='closed'`: **cria nova row** (issue reabriu).
  - Se não existe: **insert** normal.
  - Implementação em `storage/apiFindings.ts` novo método `upsertApiFindingByKey(endpointId, category, title, data): Promise<{ finding, action: 'inserted'|'updated' }>`.
  - Mantém histórico sem inflar tabela; Phase 14 sanitization decide final do `evidence` replay.
- **Evidence para Nuclei hits**: mapear `NucleiFindingSchema` (já existe em `shared/schema.ts` para v1.0 vulnScanner) para `ApiFindingEvidence`:
  - `evidence.request = { method: nuclei.request.method, url: nuclei.matched-at, headers: nuclei.request.headers, bodySnippet: nuclei.request.body?.slice(0, 8192) }`
  - `evidence.response = { status: nuclei.response.status, headers: nuclei.response.headers, bodySnippet: nuclei.response.body?.slice(0, 8192) }`
  - `evidence.extractedValues = { matcherName: nuclei['matcher-name'], extractedResults: nuclei['extracted-results'], templateId: nuclei['template-id'] }`
  - `evidence.context = nuclei.info.description` (descrição da template).
  - Zod schema `apiFindingEvidenceSchema` existente já valida (strict, max 8KB em bodySnippet). Reusa sem mudança.
- **Severity mapping**:
  - Nuclei: mapeia `info | low | medium | high | critical` direto para `threatSeverityEnum` (v1.0). `info` → `low`.
  - Auth-failure: alg:none → `critical`; kid/reuse → `high`; leakage → `high`.
  - API9 inventory: spec exposto / introspection aberta → `medium`; endpoint oculto → `low`.
- **Remediation pt-BR**: constantes em `shared/apiRemediationTemplates.ts`:
  ```ts
  export const API_REMEDIATION_TEMPLATES = {
    api8_misconfiguration_2023: 'Revise as configurações de segurança do servidor...',
    api9_inventory_2023: {
      spec_exposed: 'Restrinja o acesso à especificação OpenAPI/Swagger...',
      graphql_introspection: 'Desabilite GraphQL introspection em produção...',
      hidden_endpoint: 'Remova ou autentique endpoints não documentados...',
    },
    api2_broken_auth_2023: {
      alg_none: 'Rejeite explicitamente tokens com alg=none...',
      kid_injection: 'Valide o campo kid contra uma allowlist...',
      token_reuse: 'Implemente validação de exp e blocklist de tokens revogados...',
      api_key_leakage: 'Nunca inclua valores de API keys em response bodies...',
    },
  } as const;
  ```
  Simetria com os 25 templates de remediação existentes (v1.0). Phase 14 pode estender/sanitizar globalmente.
- **riskScore**: mantém NULL no Phase 12. Phase 14 promove high/critical para `threats` e popula via scoringEngine.
- **Read path — `GET /api/v1/api-findings`**:
  - Query params: `?apiId=<uuid>` OR `?endpointId=<uuid>`, `?owaspCategory=<enum>`, `?severity=<enum>`, `?status=<enum>`, `?jobId=<uuid>`, `?limit=<int>` (default 50), `?offset=<int>`.
  - Pelo menos um de `apiId`/`endpointId`/`jobId` é obrigatório (evita full table scan).
  - RBAC: `global_administrator` + `operator` + `readonly_analyst` (incluir readonly porque é read-only).
  - Retorna `ApiFinding[]` direto (schema sanitizado — não há secrets em `api_findings` nativamente; evidence pode conter dados; Phase 14 formaliza sanitização).
  - Estende storage com `listApiFindings(filter): Promise<ApiFinding[]>` + `listFindingsByEndpoint` existente fica.

### Claude's Discretion

- Nomes exatos de funções internas nos scanners (`runNucleiPassive`, `parseNucleiJsonl`, `forgeJwtAlgNone`, `injectKid`, etc).
- Estrutura interna do `PassiveTestResult` (planner pode adicionar campos sem breaking).
- Formato exato das fixtures mock (planner define shape JSONL/JSON).
- Lista exata de títulos pt-BR para findings API9 (3 variantes: spec exposto, introspection, endpoint oculto).
- Se `api9Inventory` vira stage separada no orchestrator ou função helper chamada antes do loop de endpoints.
- Mensagens pt-BR exatas de erro em rota/CLI.
- Cobertura Nyquist Wave 0: sugestão de 8 testes — nuclei args builder, jsonl→evidence mapper, api9 inventory query, jwt alg:none forge, kid injection payloads, token reuse skip-opaque, api key leakage heuristic, dedupe upsert.
- Se cria `runApiPassiveTests` no mesmo arquivo que `discoverApi` ou separado (sugere separado: `journeys/apiPassiveTests.ts`).
- Exato shape da Zod schema `apiPassiveTestOptsSchema` (onde mora: `shared/schema.ts` para uso client-future ou server-only).
- Ordem exata de imports, header de arquivos (segue CONVENTIONS.md).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Milestone spec
- `.planning/ROADMAP.md` §"Phase 12: Security Testing — Passive" (linhas 124-138) — goal + 4 success criteria + dependências
- `.planning/REQUIREMENTS.md` §"Security Testing (TEST)" (linhas 41-49) — TEST-01, TEST-02 completos
- `.planning/REQUIREMENTS.md` §"Findings & Threat Integration (FIND)" (FIND-01) — shape de `api_findings` que Phase 12 popula
- `.planning/REQUIREMENTS.md` §"Safety & Guard-rails (SAFE)" — SAFE-01 (rate cap 10 req/s defensive), SAFE-05 (dry-run target — Phase 15 owns), SAFE-06 (logs sem secrets)
- `.planning/PROJECT.md` §"Constraints" — "Schema changes must be additive", "Backward compatibility"
- `.planning/PROJECT.md` §"Key Decisions" — "BOLA/BFLA/BOPLA in-house TypeScript" (mesmo racional aplica para auth-failure tests)

### Phase 9 CONTEXT carry-forward
- `.planning/phases/09-schema-asset-hierarchy/09-CONTEXT.md` — decisões vivas:
  - `api_findings` schema completo (colunas: apiEndpointId, jobId, owaspCategory, severity, status, title, description, remediation, riskScore, evidence JSONB, promotedThreatId)
  - `ApiFindingEvidence` interface + `apiFindingEvidenceSchema` Zod (strict, bodySnippet max 8KB)
  - `owaspApiCategoryEnum` com suffix `_2023` (api2/api8/api9 são os 3 usados por Phase 12)
  - `apiFindingStatusEnum`: `open | triaged | false_positive | closed`
  - `threatSeverityEnum` reusado (`low | medium | high | critical`)
  - `insertApiFindingSchema` exclui `promotedThreatId`/`riskScore` (Phase 14)
  - Pattern `ensureApiTables` guard idempotente

### Phase 10 CONTEXT carry-forward
- `.planning/phases/10-api-credentials/10-CONTEXT.md` — decisões vivas:
  - `resolveApiCredential(apiId, endpointPath): Promise<ApiCredentialSafe | null>` helper — Phase 12 usa para match cred → endpoint
  - `getApiCredentialWithSecret(id)` — único método que retorna secret decriptado; Phase 12 é consumidor legítimo (executor)
  - `decodeJwtExp(jwt): number | undefined` em `server/services/credentials/decodeJwtExp.ts` — usado para token reuse test
  - `matchUrlPattern(url, pattern): boolean` — utilizado transitivamente por `resolveApiCredential`
  - 7 auth types; Phase 12 só age sobre `bearer_jwt`, `api_key_header`, `api_key_query`
  - pino redaction cobre `secretEncrypted`, `dekEncrypted`, `authorization` automaticamente

### Phase 11 CONTEXT carry-forward
- `.planning/phases/11-discovery-enrichment/11-CONTEXT.md` — decisões vivas:
  - `DiscoverApiOpts`/`DiscoveryResult` como template do shape de `ApiPassiveTestOpts`/`PassiveTestResult`
  - Pattern de orquestrador `journeys/apiDiscovery.ts` com stages sequenciais + stagesSkipped + cancelled + durationMs
  - Pattern de scanner-per-tool em `server/services/scanners/api/`
  - `processTracker.registerProcess(jobId, child)` + SIGTERM graceful + SIGKILL 5s
  - `jobQueue.isJobCancelled(jobId)` para cancelamento cooperativo
  - "Resultados parciais persistem em cancel" — padrão replicado
  - `requiresAuth` tri-valor (NULL=não probado, true=401/403, false=open) — Phase 12 filtra `requiresAuth=true` para TEST-02
  - `discoverySources` text[] com valores `'spec' | 'crawler' | 'kiterunner' | 'manual'` — Phase 12 query para API9 inventory signals

### Schema atual
- `shared/schema.ts:94-109` — `owaspApiCategoryEnum` + `apiFindingStatusEnum`
- `shared/schema.ts:1225-1239` — `ApiFindingEvidence` interface
- `shared/schema.ts:1242-1317` — `apis` + `api_endpoints` tables (incluindo httpx enrichment columns)
- `shared/schema.ts:1319-1347` — `apiFindings` table + tipos `ApiFinding`, `InsertApiFinding`
- `shared/schema.ts:1546-1562` — `apiFindingEvidenceSchema` Zod
- `shared/schema.ts:1581-1586` — `insertApiFindingSchema`
- `shared/schema.ts` — `NucleiFindingSchema` (v1.0 vulnScanner) para mapear JSONL output de Nuclei

### Nuclei integration (v1.0 patterns)
- `server/services/journeys/nucleiPreflight.ts` — preflight memoizado (binary check + templates dir + auto-update). **Reusa direto** para Phase 12.
- `server/services/scanners/vulnScanner.ts` linhas ~114-180 — pattern `nucleiScanUrl` — JSONL streaming, `-silent -jsonl -rl -timeout`, spawn + processTracker. Template 1:1 para `runNucleiPassive`.
- `shared/schema.ts` `NucleiFindingSchema` — Zod schema para output JSONL Nuclei (reusa para parse).
- https://docs.projectdiscovery.io/tools/nuclei/usage — flags oficiais `-tags`, `-l`, `-rl`, `-timeout`, `-severity`, `-jsonl`, `-silent`.
- https://owasp.org/API-Security/editions/2023/en/0x11-t10/ — categorias oficiais API2/API8/API9.

### Scanner + spawn patterns
- `server/services/scanners/api/preflight.ts` (Phase 11) — pattern de `preflightApiBinary` memoizado; Phase 12 pode reusar ou adicionar preflight próprio se necessário.
- `server/services/scanners/api/katana.ts`, `httpx.ts`, `kiterunner.ts` — exemplos mais recentes de spawn + AbortSignal + JSONL parse.
- `server/services/processTracker.ts` — `registerProcess(jobId, child)` + SIGTERM graceful.
- `server/services/journeyExecutor.ts` — pattern de progress callback + cancelation check.

### Storage + schema
- `server/storage/apiFindings.ts` (Phase 9) — já tem `createApiFinding` + `listFindingsByEndpoint`. Phase 12 estende com `upsertApiFindingByKey` + `listApiFindings(filter)`.
- `server/storage/apis.ts` + `server/storage/apiEndpoints.ts` — usados para query de API9 inventory signals.
- `server/storage/apiCredentials.ts` — `resolveApiCredential` + `getApiCredentialWithSecret`.
- `server/storage/interface.ts` — `IStorage` ganha `upsertApiFindingByKey` + `listApiFindings`.

### Route + CLI patterns
- `server/routes/apis.ts` (Phase 9 + Phase 11) — template de rota Zod + RBAC + storage + log.info + 201. `POST /api/v1/apis/:id/discover` (Phase 11) é template direto para `POST /api/v1/apis/:id/test/passive`.
- `server/routes/apiCredentials.ts` (Phase 10) — template de `GET /api/v1/api-credentials` com filtros query params — template para `GET /api/v1/api-findings`.
- `server/routes/index.ts` — barrel onde registrar rotas.
- `server/scripts/runApiDiscovery.ts` (Phase 11) — template de CLI standalone.
- `docs/operations/run-api-discovery.md` (Phase 11) — template de runbook pt-BR.

### Crypto + JWT
- `server/services/credentials/decodeJwtExp.ts` (Phase 10) — parse base64url JWT payload.
- `node:crypto` — `crypto.createHmac`, `createSign`, base64url encode/decode — usados para forjar JWT alg:none (signature vazia).
- `jose` ou `jsonwebtoken` **não são adicionados** — Phase 12 faz manipulação manual de header/payload via `Buffer.from(..., 'base64url')` (evita nova dep).

### Convenções
- `.planning/codebase/CONVENTIONS.md` — naming, import order, error handling pt-BR, `createLogger('componentName')`.
- `.planning/codebase/STRUCTURE.md` — organização `server/services/`, `server/routes/`, `server/storage/`, `server/scripts/`.
- `.planning/codebase/TESTING.md` — padrão Vitest + mocks.
- `.planning/codebase/STACK.md` — TypeScript 5.6.3, Express 4, Drizzle 0.39, Zod 3.24, Vitest 4.

### Logging + redaction
- `server/lib/logger.ts` — pino redaction paths cobrem `secretEncrypted`, `dekEncrypted`, `authorization` (aplicável para JWT logs).
- SAFE-06: logs estruturados JSON nunca incluem request bodies, credentials, tokens. Phase 12 loga `{ apiId, endpointId, findingId, owaspCategory, severity }` — sem bodies nem secrets.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`api_findings` table + `ApiFindingEvidence` + `apiFindingEvidenceSchema`** (`shared/schema.ts:1319-1347`, `:1225-1239`, `:1546-1562`) — Phase 9 deixou shape completo; Phase 12 apenas popula. **Nenhuma alteração estrutural** necessária.
- **`storage/apiFindings.ts`** (Phase 9) — `createApiFinding` + `listFindingsByEndpoint` prontos. Phase 12 adiciona `upsertApiFindingByKey` + `listApiFindings(filter)`.
- **`nucleiPreflight.ts`** (v1.0) — memoizado, binary + templates + auto-update. **Reusa sem mudança** para TEST-01.
- **`vulnScanner.ts::nucleiScanUrl`** (v1.0) — spawn + JSONL streaming + processTracker + timeout. Template 1:1.
- **`NucleiFindingSchema`** (`shared/schema.ts`) — Zod para parse de JSONL output.
- **`resolveApiCredential` + `getApiCredentialWithSecret`** (Phase 10) — cred resolution para TEST-02.
- **`decodeJwtExp`** (Phase 10) — decodifica `exp` claim para token reuse test.
- **`processTracker.registerProcess(jobId, child)`** — cancelamento cooperativo.
- **`jobQueue.isJobCancelled(jobId)`** — check cooperativo entre stages.
- **`DiscoverApiOpts`/`DiscoveryResult`** (Phase 11) — templates para `ApiPassiveTestOpts`/`PassiveTestResult`.
- **`journeys/apiDiscovery.ts`** (Phase 11) — template completo de orquestrador com stages.
- **`scanners/api/preflight.ts`** (Phase 11) — pattern de preflight memoizado (reusável se Phase 12 adicionar preflight próprio).
- **Wordlists vendorizadas** não são usadas por Phase 12 (specific para discovery).
- **`createLogger('journeys:apiPassiveTests')`** + pino redaction automática.

### Established Patterns
- **Scanner-per-tool** em `server/services/scanners/api/` — Phase 12 adiciona 2 arquivos: `nucleiApi.ts` + `authFailure.ts`.
- **Orchestrator journey** em `server/services/journeys/<capability>.ts` — Phase 12 adiciona `apiPassiveTests.ts` paralelo a `apiDiscovery.ts`.
- **Zod schema para `opts`** em `shared/schema.ts` — `apiPassiveTestOptsSchema`.
- **Storage facade extension** — novos métodos em `apiFindings.ts` + IStorage + DatabaseStorage.
- **Route registration barrel** — adiciona handler em `apis.ts` (POST /:id/test/passive) + novo arquivo `apiFindings.ts` para GET /api/v1/api-findings (simetria com `apiCredentials.ts`).
- **CLI standalone** `tsx --env-file=.env` + `import.meta.url` guard + argv parse.
- **pt-BR em mensagens, EN em código**.
- **Fixtures em `server/__tests__/fixtures/`** para dryRun determinístico.

### Integration Points
- **`shared/schema.ts`** — adicionar `apiPassiveTestOptsSchema` Zod (toggles + dryRun + overrides).
- **`server/services/scanners/api/nucleiApi.ts`** (novo) — wrapper Nuclei para TEST-01: `-tags misconfig,exposure,graphql,cors -l <stdin endpoint list> -rl 10 -timeout 10 -jsonl -silent`. Parse JSONL via `NucleiFindingSchema`, mapeia para `InsertApiFinding`.
- **`server/services/scanners/api/authFailure.ts`** (novo) — 4 funções exportadas: `forgeJwtAlgNone(jwt)`, `injectKid(jwt, payload)`, `checkTokenReuse(jwt, endpoint)`, `detectApiKeyLeakage(apiKey, responses[])`. Cada uma retorna `Partial<InsertApiFinding>` ou null.
- **`server/services/scanners/api/api9Inventory.ts`** (novo; OU inline em `apiPassiveTests.ts`) — query `apis`/`api_endpoints` e gera findings DB-derived.
- **`server/services/journeys/apiPassiveTests.ts`** (novo) — orquestrador: stages `nucleiPassive`, `authFailure`, `api9Inventory` + finalize + cancel.
- **`server/storage/apiFindings.ts`** (Phase 9) — estender com `upsertApiFindingByKey(endpointId, category, title, data)`, `listApiFindings(filter)`.
- **`server/storage/interface.ts`** — IStorage ganha 2 assinaturas.
- **`server/storage/index.ts`** — DatabaseStorage wira.
- **`server/routes/apis.ts`** (estender) — adicionar handler `POST /api/v1/apis/:id/test/passive` (RBAC + Zod + body = `apiPassiveTestOptsSchema` + chama `runApiPassiveTests`).
- **`server/routes/apiFindings.ts`** (novo) + `registerApiFindingsRoutes(app)` — `GET /api/v1/api-findings` com filtros.
- **`server/routes/index.ts`** — registrar `registerApiFindingsRoutes(app)`.
- **`server/scripts/runApiPassiveTests.ts`** (novo) — CLI operador.
- **`docs/operations/run-api-passive-tests.md`** (novo) — runbook pt-BR.
- **`shared/apiRemediationTemplates.ts`** (novo) — constantes pt-BR para api2/api8/api9.
- **`server/__tests__/fixtures/api-passive/`** (nova pasta) — 5 fixtures JSON/JSONL.
- **`server/__tests__/`** — Nyquist stubs (Wave 0): ~8 testes.

### Constraints Aplicáveis
- PROJECT.md "Schema changes must be additive" — satisfeito (Phase 12 não adiciona colunas; só popula `api_findings` existente).
- PROJECT.md "Backward compatibility" — satisfeito (zero mudança em executors existentes).
- SAFE-06 "Logs estruturados sem secrets" — satisfeito via pino redaction + logs estruturados com IDs e contagens apenas.
- SAFE-01 "rate cap 10 req/s default, 50 absolute ceiling" — Phase 12 implementa 10 QPS default em Nuclei (`-rl 10`) + 1 req/s por endpoint em authFailure; ceiling absoluto é responsabilidade do Phase 15.
- SAFE-03 "DELETE/PUT/PATCH destructive gating" — Phase 12 é passivo (Nuclei misconfig/exposure/graphql/cors não são destrutivos; authFailure usa método original do endpoint). Phase 13 lida com destructive gate explícito.
- SAFE-05 "dry-run target" — Phase 12 aceita `opts.dryRun` via fixtures locais; `/healthz/api-test-target` externo fica para Phase 15.

</code_context>

<specifics>
## Specific Ideas

- **"Nuclei é para stateless, TS in-house é para stateful"** — nomenclatura que guia decisão: Nuclei cobre API8/API9 (misconfig estático), TS in-house cobre API2 (JWT manipulation precisa contexto cred). PROJECT.md Key Decision para BOLA/BFLA/BOPLA se aplica aqui.
- **API9 inventory via DB query é carry-forward do Phase 11** — Phase 11 CONTEXT explicitamente diz "Phase 11 só CRIA rows + enriquece. NÃO cria `api_findings`. Logar sinais". Phase 12 é o consumidor natural desses sinais via query direta (não log scraping).
- **Mask-at-source para extractedValues com cred** — mesmo com Phase 14 sanitization futura, defensive-by-default: nunca escrever cred completo em evidence. `leakedKeyPrefix: 'sk_abc***'` em vez de `leakedKey: 'sk_abc123xyz456'`. Phase 14 pode reforçar; Phase 12 não confia.
- **Dedupe chave `(endpointId, category, title)`** — título é determinístico por tipo de finding (ex: `"JWT aceita alg=none"`, `"Especificação de API exposta publicamente"`). Template-id de Nuclei não é chave ideal porque mesma template pode gerar títulos diferentes conforme matched pattern.
- **Título pt-BR reusado como dedupe key é aceitável** — mudança de título em versão futura do código rompe dedupe (cria findings duplicados). Aceitamos: títulos são estáveis, mudanças raras. Alternativa (template-id ou vector) era mais complexa sem ganho proporcional.
- **`[DRY-RUN]` prefix em título para findings dryRun** — evita contaminação de read path real sem mudar schema. Operador pode filtrar via `?title:startsWith=[DRY-RUN]` futuro (ou query manual).
- **Nuclei `-rl 10` é per-Nuclei-run, não global** — Phase 15 SAFE-01 impõe 50 req/s absoluto globalmente. Se Phase 12 roda 2 APIs paralelo (não rodamos hoje, mas futuro), cada uma faria 10 = 20 total. Phase 15 decide governance.
- **`bearer_jwt` OAuth2-minted fora de escopo Phase 12** — Phase 11 faz mint em runtime, cache in-memory. Esse JWT efêmero não é cred persistida de Phase 10; Phase 12 não tenta manipulá-lo. Phase 15 orchestration pode orquestrar cross-phase se necessário.
- **"Internal read path" em success criteria #3 = rota GET interna** — não UI (Phase 16). RBAC incluído `readonly_analyst` (usuário que audita sem mutar). Shape `ApiFinding[]` direto sem transformação; Phase 14 sanitization centraliza evidence.
- **Fixtures versionadas sem checksum** — não são binários, git SHA cobre. Diferente de wordlists (Phase 8) que são binários grandes com SHA-256 explicit.
- **`apiPassiveTests.ts` NÃO reusa `apiDiscovery.ts`** — orchestração é parecida, mas domínios são distintos (descobrir vs testar). Compartilhar abstraction é prematuro.

</specifics>

<deferred>
## Deferred Ideas

- **Paralelismo entre APIs em um job** — Phase 12 sequencial. Phase 15 orchestration pode paralelizar se ganho real for medido.
- **Templates Nuclei custom OWASP API-específicos** — se gap aparecer em Phase 13, adicionar `server/resources/nuclei-api-templates/` vendored. Por ora: só oficiais.
- **Rate limit por-API granular** — hoje é global via Nuclei `-rl`. Per-API rate limit com token bucket é Phase 15 (SAFE-01 global).
- **`riskScore` populado por Phase 12** — NULL até Phase 14 scoringEngine + promoção para threats.
- **Sanitização formal de `evidence`** — redação de headers Authorization/Cookie, PII CPF/CNPJ/email/credit-card, truncagem final — owner Phase 14 (FIND-02). Phase 12 aplica `bodySnippet` cap 8KB via Zod.
- **Promoção para `threats` table + dedup cross-journey** — Phase 14 (FIND-03).
- **WebSocket events durante execução** — Phase 14 (FIND-04).
- **Retry automático em Nuclei stage falha** — Phase 12 skipa com log. Backoff + retry é melhoria futura.
- **Suporte a mais auth types no JWT tests** — hoje só `bearer_jwt`. Se usuário tem app custom que valida JWT em query param ou header custom, não cobrimos. Adicionar aditivamente se demanda real.
- **API6 Business Flow e API10 Unsafe Consumption** — explicitamente fora de v2.0 (REQUIREMENTS.md §"Future"). Phase 12 não gera findings dessas categorias.
- **Throttling adaptativo baseado em response time** — útil para alvos lentos. Hoje: static rate + timeout. Melhoria futura.
- **OAuth2 token forjado (alg:none no token mintado)** — Phase 11 mint é efêmero; Phase 12 não testa tokens minted. Aditivo se surgir demanda.
- **Inspeção de JWT em cookies/body além de Authorization header** — hoje só Authorization header. Se app usa cookie `access_token`, não cobrimos. Aditivo.
- **HMAC replay attack** — não é auth-failure passivo clássico; requer múltiplos requests com mesma assinatura. Phase 13 (rate-limit/stateful) pode absorver.
- **API key entropy analysis** — detectar API keys com baixa entropia (adivinháveis). Além de leakage. Aditivo.
- **Tabela de "dryRun runs" separada** — em vez de prefix `[DRY-RUN]` no título. Overkill agora; aditivo se auditoria exigir.
- **Alerting / notification de findings critical** — Phase 14 WebSocket + Phase 15 orchestration podem dispatch.
- **Multi-version comparative testing** — rodar mesmo teste em múltiplas versions da API. Deferred/out-of-scope.

</deferred>

---

*Phase: 12-security-testing-passive*
*Context gathered: 2026-04-20*
