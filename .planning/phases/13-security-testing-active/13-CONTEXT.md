# Phase 13: Security Testing — Active - Context

**Gathered:** 2026-04-20 (via `/gsd:discuss-phase 13 --auto`)
**Status:** Ready for planning

<domain>
## Phase Boundary

Entregar o **segundo batch de testes de segurança do OWASP API Top 10 (2023)** — os 5 vetores **stateful** que Nuclei não expressa — consumindo endpoints descobertos no Phase 11, reaproveitando credenciais do Phase 10 e gerando rows em `api_findings` com dedupe já implementado no Phase 12.

Escopo do Phase 13:
- **TEST-03 (BOLA, API1)** — cross-identity object-access com ≥2 credenciais distintas; captura request pair como evidence.
- **TEST-04 (BFLA, API5)** — baixa-privilégio tenta acesso admin-level (path + método); finding quando status < 400.
- **TEST-05 (BOPLA / Mass Assignment, API3)** — injeta chaves sensíveis em body de PUT/PATCH; detecta reflection.
- **TEST-06 (Rate-Limit absence, API4)** — burst N requests **opt-in**; finding quando nem `429` nem `Retry-After` observados.
- **TEST-07 (SSRF, API7)** — Nuclei `-tags ssrf` + interactsh habilitado apenas em params cujo value aceita URL.
- **Entrypoint trip-leg** — função `runApiActiveTests(apiId, opts, jobId?)` + rota `POST /api/v1/apis/:id/test/active` + CLI de operador + runbook pt-BR.
- **Fixtures para dryRun** — mocks determinísticos para cada vetor em `server/__tests__/fixtures/api-active/`.

**Fora de escopo deste phase (em outras phases):**
- Sanitização formal de evidence (redação de headers auth, PII CPF/CNPJ/email, truncagem final) → Phase 14 (FIND-02).
- Promoção para `threats` e WebSocket events → Phase 14 (FIND-03, FIND-04).
- Enum `api_security` em `journey_type`, wiring no journeyExecutor, abort via `/jobs/:id/abort`, authorization ack, rate ceiling absoluto de 50 req/s, destructive gate global (SAFE-03), audit log formal → Phase 15 (JRNY + SAFE).
- UI de findings filter por `source=api_security` + curl reproduction + false-positive marking → Phase 16.

Phase 13 é **runtime de testing ativo/stateful** — delivery de 5 scanners novos (`bola.ts` + `bfla.ts` + `bopla.ts` + `rateLimit.ts` + `ssrfNuclei.ts`) + orquestrador (`journeys/apiActiveTests.ts`) + interface pública (função + rota + CLI) + fixtures dryRun + runbook. A journey `api_security` end-to-end só existe após Phase 15 wirar.

</domain>

<decisions>
## Implementation Decisions

### BOLA (TEST-03 / API1) — Cross-identity object access

- **Cred pairing strategy**: coletar todas credenciais que resolvem para a API em questão (via `resolveApiCredential` estendido OU `listApiCredentialsForApi`). Cap rígido `maxCredentials = 4` → até C(4,2) = **6 pares únicos**. Pares ordenados sem repetição `(A,B)` — NÃO rodar `(B,A)` espelhado (cobertura idêntica, dobra custo).
- **Scope de endpoints**: apenas `method='GET'` com `requiresAuth=true`. PUT/DELETE são fora (SAFE-03 + BFLA domain). POST idempotentes ficam deferred (maioria é mutação).
- **Object ID enumeration — 2-passo**:
  1. **Harvest**: com cred A, faz GET em endpoints "list-like" (path sem `{id}` / termina em plural ou `/list`). Extrai até **3 IDs únicos** de `response.body` via heurística: scan JSON por campos `id`, `uuid`, `pk` e coleta primeiros 3 valores string/number. Se resposta não é JSON ou sem IDs → skipa endpoint + log.
  2. **Cross-access**: para cada ID harvestado, substitui `{id}` no path-template (ou anexa `?id=<val>` se endpoint não tem template) e faz GET com cred B.
- **Finding criterion**: cred B obtém `status < 400` E `response.body.length > 0` E body não é "erro de autorização" (heurística: não contém `"forbidden"`, `"unauthorized"`, `"permission denied"` case-insensitive). Severity **high**. Evidence `extractedValues = { credentialAId: '<uuid>', credentialBId: '<uuid>', objectId: '<harvested-id>', endpointPath: '/users/{id}' }`.
- **Request budget por API**: `maxCredentials(4) × maxIDsPerEndpoint(3) × endpointsCount`. Para 50 endpoints GET = 600 requests max (hard ceiling). Rate cap 10 req/s → ~1 min por API. Aceitável.
- **Evidence é o PAIR de requests** (success criteria #1): `evidence.request` = cred B request; `evidence.response` = cred B response; `evidence.extractedValues` carrega ref ao cred A request (apiCredentialIdA + harvest endpoint). Simplifica Zod schema (não estende `ApiFindingEvidence` com array de requests — mantém shape existente do Phase 9).

### BFLA (TEST-04 / API5) — Admin privilege escalation

- **Low-priv identification — 3 sinais combinados** (OR-logic, qualquer match qualifica):
  1. `apiCredentials.priority` mais alto entre creds da API (maior `priority` int = menos privilégio na convenção do Phase 10).
  2. `apiCredentials.description` contains `readonly`/`read-only`/`viewer`/`limited` (case-insensitive).
  3. Fallback: se apenas 1 cred existe, loga warn "BFLA requer ≥2 creds com privilégios distintos" e skipa stage (não gera falso positivo).
- **Admin endpoints heuristic — 2 filtros combinados**:
  - **Path match**: regex `/(admin|manage|management|system|internal|sudo|superuser|root|console)(\b|\/|$)/i` contra `api_endpoints.path`.
  - **Method-based (opt-in via destructive gate)**: `POST`/`PUT`/`PATCH`/`DELETE` em endpoints NÃO admin-path. Default: **desabilitado** (requer `opts.destructiveEnabled=true`); só `GET` em admin-path por padrão.
- **Test procedure**: para cada endpoint admin-path qualificado, faz request com cada cred low-priv; se `status < 400` E não é redirect para login (`3xx` sem `Location: /login`): finding severity **high**. Evidence `extractedValues = { credentialId: '<uuid>', priorityLevel: 3, matchedPattern: 'admin', endpointPath: '/admin/users' }`.
- **Skip conditions**:
  - Se cred low-priv também passa em endpoints non-admin com mesma auth flag → sinal de cred "universal" (não é low-priv). Log + skip + não gera finding.
  - Se todas creds retornam mesmo status em endpoint admin → RBAC pode não estar implementado (sinal de API5, mas sem contraste → severity **medium**, não high).
- **Request budget por API**: `lowPrivCreds × adminEndpoints`. Cap em 100 requests total por API (se exceder, prioriza endpoints com menor response size esperado — heurística proxy).

### BOPLA / Mass Assignment (TEST-05 / API3) — Sensitive property injection

- **Target methods**: `PUT` + `PATCH` apenas (per success criteria #3). `POST` de criação é fora (não é "update com schema desconhecido"; é create com expectativa de payload livre).
- **Destructive gate obrigatório**: `opts.destructiveEnabled=false` default → stage inteiro skipa com log. Operador que habilita assume responsabilidade. Phase 15 reforça globalmente (SAFE-03).
- **Payload strategy — 2 passos**:
  1. **Base body discovery**: faz GET no recurso alvo (mesmo path sem método) → captura response body como seed. Se GET falha (404, 401): skip endpoint + log (sem schema conhecido, teste não confiável).
  2. **Injection**: parse JSON do seed; **adiciona** (não substitui) cada chave da lista curada em request body PUT/PATCH. 1 request por chave (para isolar qual chave reflete).
- **Lista curada (10 chaves sensíveis, determinística)**:
  ```ts
  const BOPLA_SENSITIVE_KEYS = [
    'is_admin', 'isAdmin', 'admin',
    'role', 'roles', 'permissions',
    'superuser', 'owner',
    'verified', 'email_verified',
  ] as const;
  ```
  Valores injetados: booleanos → `true`, strings → `'admin'`, arrays → `['admin']`. Tipos inferidos do seed quando chave já existe (raro); caso contrário, default `true`/`'admin'`.
- **Reflection detection**: após injection, faz GET novamente no mesmo recurso. Finding quando:
  - `status < 400` no PUT/PATCH E
  - GET subsequente retorna body contendo a chave injetada E valor ≥ seed value (privilege escalation real).
  - Detection via key-path deep compare (não regex textual — evita falso positivo quando chave já existia no seed).
- **Severity**: **critical** se chave é `is_admin`/`role`/`superuser` E reflection confirmada; **high** para outras chaves da lista. Evidence `extractedValues = { injectedKey: 'is_admin', originalValue: false, reflectedValue: true, endpointPath: '/users/{id}' }`.
- **Fallback sem JSON response**: se seed body não é JSON parseável → skip endpoint + log. Mass assignment em forms/XML fora de escopo Phase 13.
- **Request budget por API**: `endpointsPutPatch × 10_keys × 2 (PUT + verify GET) = endpointsPutPatch × 20`. Cap em 200 requests por API.

### Rate-Limit absence (TEST-06 / API4) — Burst detection

- **Opt-in obrigatório**: `opts.stages.rateLimit=false` default. UI wizard (Phase 16) apresenta checkbox com warning; Phase 13 respeita flag.
- **Burst parameters** (configuráveis via `opts.rateLimit`):
  - `burstSize`: default `20`, max `50` (hard ceiling Phase 13; SAFE-01 Phase 15 reforça 50 absolute).
  - `windowMs`: default `2000` (2 segundos).
  - Implementação via `Promise.all` de N requests em paralelo — não sequencial. O ponto é saturar; sequencial com delay defeita o teste.
- **Target endpoints**: apenas `method='GET'` com `requiresAuth=true` E `httpxStatus === 200` (endpoint conhecidamente funcional). Pula endpoints 404/500 (teste não informativo).
- **Amostra de endpoints**: **1 endpoint por API** por padrão (o primeiro GET+200 na ordem alfabética de path). `opts.rateLimit.endpointIds?: string[]` permite override explícito (array de até 5 endpoints). Rationale: bursting 50 endpoints × 20 reqs = 1000 requests é destrutivo; 1 endpoint amostra ~20 reqs.
- **Detection criteria — ALL of the following** (conservative):
  - Nenhuma response tem `status === 429`.
  - Nenhuma response tem header `Retry-After`.
  - Nenhuma response tem header matching regex `/^x-ratelimit-/i` (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset).
  - ≥ 90% das responses têm `status < 400` (confirma que endpoint aceitou carga, não falhou por outra razão).
- **Severity**: **medium** (rate-limit absence é sinal, não exploração imediata). Evidence `extractedValues = { burstSize: 20, successCount: 20, throttledCount: 0, hasRetryAfter: false, hasXRateLimitHeaders: false, windowMs: 2000, endpointPath: '/users' }`.
- **Credential**: usa cred resolvida para o endpoint (mesma de TEST-02/03/04). Unauth burst é deferido — ratelimit em public endpoints cai em SAFE-01 governance, não em API4.
- **Safety net**: delay de 30s entre burst tests (se operador rodar múltiplas APIs) para evitar alvos compartilhando infra sendo DoS-unintentionally.

### SSRF (TEST-07 / API7) — Nuclei + interactsh

- **Scope extremamente seletivo**: apenas params cujo value é URL-like. Identificação via 3 heurísticas (OR):
  1. Name match: regex `/^(url|redirect|redirect_uri|callback|callback_url|webhook|webhook_url|target|dest|destination|endpoint|uri|link|image_url|avatar_url|src|href|next|continue|returnTo|return_to|return)$/i` contra `name` em `query_params`/`request_params`/`request_schema`.
  2. Type match: `type === 'url'` ou `format === 'uri'` ou `format === 'url'` no schema.
  3. Example value match: `example` parse como URL via `new URL()` sem throw → qualifica.
- **Nuclei config**:
  - Tags: `-tags ssrf` (apenas templates oficiais SSRF).
  - **Interactsh habilitado** — REMOVE `-ni` flag usado em Phase 12. Passa `-interactsh-url <URL>` quando `INTERACTSH_URL` env var presente; senão usa default público `oast.me` (ProjectDiscovery).
  - Config: `-rl 10` (10 req/s), `-timeout 30` (SSRF precisa janela maior para OOB callback), `-retries 0`, `-silent`, `-jsonl`.
  - `-interactions-poll-duration 5s -interactions-wait 10s -interactions-retries-count 3` (defaults defensivos para OOB polling).
- **Templates oficiais apenas**: reusa `/tmp/nuclei/nuclei-templates`. SSRF-specific templates ficam implicitamente em `/tmp/nuclei/nuclei-templates/http/vulnerabilities/generic/ssrf/` (Nuclei resolve automaticamente com `-tags`).
- **Target URL construction**: para cada param URL-qualificado, constrói request-alvo tornando o param injectable. Formato: `baseUrl + endpointPath?paramName={{interactsh-url}}` (Nuclei substitui `{{interactsh-url}}` no runtime).
- **Finding criterion**: Nuclei JSONL reporta `interaction=true` OU `extracted-results` contém callback URL match. Severity mapa direto do Nuclei (`info`→`low`, outros 1:1).
- **Evidence**: `evidence.request = { method, url, headers, bodySnippet (com interactsh URL no param) }`; `evidence.response = {...}`; `evidence.extractedValues = { paramName: 'webhook_url', interactsh_interaction_type: 'dns'|'http', interactshUrl: '<mascarado-prefix>***' }`.
- **Credential injection**: SSRF stage **roda autenticado** (cred via `resolveApiCredential`) porque endpoints SSRF geralmente são pós-login (callbacks, webhooks). Unauth SSRF de public endpoints é coberto por TEST-01 (Phase 12 Nuclei misconfig pode capturar casos públicos).
- **Self-hosted interactsh opção**: `INTERACTSH_URL` env var (e.g., `https://oast.internal.samureye/`) permite deployment air-gapped. Phase 13 não fornece self-hosted server; docs de runbook apontam para `https://github.com/projectdiscovery/interactsh` para setup.

### Orchestrator + shared infrastructure

- **Phase 13 expõe 3 superfícies** (idêntico Phase 12):
  1. **Função pura** `runApiActiveTests(apiId, opts, jobId?): Promise<ActiveTestResult>` em `server/services/journeys/apiActiveTests.ts`.
  2. **Rota interna** `POST /api/v1/apis/:id/test/active` (RBAC `global_administrator` + `operator`).
  3. **CLI** `server/scripts/runApiActiveTests.ts --api=<id> [--no-bola|--no-bfla|--no-bopla|--no-ssrf] [--rate-limit] [--destructive] [--dry-run] [--credential=<id>...]` + `docs/operations/run-api-active-tests.md`.
- **Shape do `opts`** (Zod `apiActiveTestOptsSchema` em `shared/schema.ts`):
  ```ts
  type ApiActiveTestOpts = {
    stages: {
      bola?: boolean;         // default true
      bfla?: boolean;         // default true
      bopla?: boolean;        // default true (mas requer destructiveEnabled)
      rateLimit?: boolean;    // default false (opt-in explícito)
      ssrf?: boolean;         // default true
    };
    destructiveEnabled?: boolean;   // default false — gate para BOPLA + BFLA method-based
    credentialIds?: string[];       // override explícito; default = resolveAllForApi(apiId)
    endpointIds?: string[];         // subset; default = todos
    dryRun?: boolean;               // default false
    rateLimit?: {
      burstSize?: number;           // default 20, max 50
      windowMs?: number;            // default 2000
      endpointIds?: string[];       // default = 1 GET+200 por API
    };
    ssrf?: {
      interactshUrl?: string;       // default: env INTERACTSH_URL ou 'oast.me'
    };
    bola?: {
      maxCredentials?: number;      // default 4, max 6
      maxIdsPerEndpoint?: number;   // default 3, max 5
    };
  };
  ```
- **`ActiveTestResult` shape** (contrato público para Phase 15):
  ```ts
  type ActiveTestResult = {
    apiId: string;
    stagesRun: Array<'bola' | 'bfla' | 'bopla' | 'rate_limit' | 'ssrf'>;
    stagesSkipped: Array<{ stage: string; reason: string }>;
    findingsCreated: number;
    findingsUpdated: number;       // dedupe upsert path
    findingsByCategory: Record<string, number>;
    findingsBySeverity: Record<string, number>;
    cancelled: boolean;
    dryRun: boolean;
    durationMs: number;
    credentialsUsed: number;       // quantas creds participaram (útil para telemetry)
  };
  ```
- **Ordem sequencial** dos stages: `bola → bfla → bopla → rate_limit → ssrf`. Cada stage falha independente sem abortar pipeline (log + skip). Justificativa: stages não compartilham estado; ordem é estável para fixtures dryRun determinísticas.
- **Cancelamento cooperativo**: check `jobQueue.isJobCancelled(jobId)` entre cada stage E entre cada endpoint dentro de stages longos (BOLA pairing loop). Pattern idêntico Phase 11/12 — resultados parciais persistem.
- **Preflight**: reusa `preflightNuclei()` apenas antes do stage SSRF. Outros stages usam `fetch` nativo + `crypto` (sem binário externo; sem preflight).
- **Request budget global por API** (cap absoluto): `BOLA(600) + BFLA(100) + BOPLA(200) + RateLimit(100) + SSRF(~50 via Nuclei interno) ≈ 1050 requests max`. Timeout total por API: **45 minutos** (vs 30 do Phase 12; Nuclei SSRF com interactsh poll é mais lento).
- **Defensive defaults aplicados antes de enviar para scanners**: Zod schema aplica `.strict()` + cap via `.max()`/`.min()` nos inteiros. Planner garante que valores fora do ceiling são rejeitados com erro pt-BR na rota.

### Findings dedupe + evidence + remediation

- **Dedupe reusa `upsertApiFindingByKey(endpointId, category, title, data)`** (Phase 12 já implementou em `storage/apiFindings.ts` com transação). Chave `(apiEndpointId, owaspCategory, title)` continua válida — títulos Phase 13 são determinísticos por vetor.
- **Títulos pt-BR determinísticos** (dedupe-safe):
  - BOLA: `"Acesso não autorizado a objeto via credencial secundária"`
  - BFLA: `"Privilégio administrativo acessível via credencial de baixo privilégio"`
  - BOPLA: `"Campo sensível aceito em PUT/PATCH sem validação ({{key}})"` — `{{key}}` é substituído por chave injetada; mantém dedupe por chave específica.
  - Rate-limit: `"Ausência de rate-limiting em endpoint autenticado"`
  - SSRF: `"SSRF confirmado via interação out-of-band em parâmetro {{paramName}}"` — paramName substituído.
- **Severity mapping**:
  - BOLA: `high` (cross-identity object read confirmada).
  - BFLA: `high` se RBAC contrastante (low-priv acessa + outra cred recusa); `medium` se RBAC ausente (ambíguo).
  - BOPLA: `critical` para chaves `is_admin`/`role`/`superuser`; `high` para outras.
  - Rate-limit: `medium` (sinal, não exploração imediata).
  - SSRF: mapa Nuclei direto (`info`→`low`).
- **Remediation pt-BR**: estende `shared/apiRemediationTemplates.ts` (Phase 12 já criou) com 5 novas entries:
  ```ts
  api1_bola_2023: 'Implemente verificação de autorização por objeto (object-level ACL) antes de servir recursos. Nunca confie apenas no ID fornecido pelo cliente — valide que o principal autenticado tem permissão no objeto específico.',
  api3_bopla_2023: 'Use allow-list explícita de campos aceitáveis em PUT/PATCH. Rejeite ou ignore silenciosamente propriedades sensíveis (role, is_admin, permissions) mesmo se presentes no payload.',
  api4_rate_limit_2023: 'Implemente rate limiting com respostas 429 Too Many Requests + header Retry-After. Use limites diferenciados por tier de usuário e endpoint.',
  api5_bfla_2023: 'Aplique autorização por função (role-based access control) em todos endpoints administrativos. Valide privilégios no backend mesmo quando a UI não expõe a ação — nunca confie no cliente.',
  api7_ssrf_2023: 'Valide URLs fornecidas pelo usuário contra allow-list explícita de destinos. Bloqueie ranges privados (RFC 1918), localhost, link-local, e cloud metadata endpoints (169.254.169.254). Use client HTTP dedicado sem seguir redirects para metadata.',
  ```
- **`riskScore`**: mantém NULL (Phase 14 owner).
- **Evidence mask-at-source**: mesmo padrão Phase 12. NUNCA armazenar token/key completo em extractedValues. Mascarar prefix-3 + `***`. Phase 14 reforça globalmente.

### dryRun fixtures + Nyquist coverage

- **Fixtures em `server/__tests__/fixtures/api-active/`** (5 arquivos mínimos):
  - `bola-crossaccess-response.json` — mock de response com body contendo dados "alheios" ao cred B.
  - `bfla-admin-success.json` — response 200 em endpoint admin-path.
  - `bopla-reflection-before.json` + `bopla-reflection-after.json` — par de responses mostrando injection reflected.
  - `rate-limit-burst-responses.json` — array de 20 responses, todas 200, sem 429/Retry-After/X-RateLimit-*.
  - `ssrf-nuclei-interaction.jsonl` — 1 linha JSONL Nuclei com `interaction=true` + `interactsh-server` match.
- **`opts.dryRun=true`**: NÃO faz HTTP request real nem spawn Nuclei. Cada stage lê sua fixture e processa como se fosse output real. Findings inseridos com título prefixado `[DRY-RUN]` (padrão Phase 12).
- **Nyquist Wave 0**: **15 test stubs mínimos** (espelha Phase 12 com 5 vetores adicionais):
  - `shared/schema.ts`: `apiActiveTestOptsSchema` → 3 testes (defaults, cap ceiling, destructive gate).
  - `bola.ts`: 3 testes (pair generation, ID harvest, cross-access finding).
  - `bfla.ts`: 2 testes (low-priv identification heuristics, admin path regex).
  - `bopla.ts`: 2 testes (seed GET + injection + reflection verify, destructive gate skip).
  - `rateLimit.ts`: 2 testes (burst parallelism, all-3-signals detection).
  - `ssrfNuclei.ts`: 2 testes (param URL-like identification, interactsh URL injection).
  - `apiActiveTests.ts` (orchestrator): 1 teste (stages order + cancel + dryRun).

### Claude's Discretion

- Nomes exatos de funções internas nos scanners (`harvestObjectIds`, `pairCredentials`, `detectReflection`, `buildBurst`, `identifyUrlParams`, etc).
- Estrutura interna do `ActiveTestResult` (planner pode adicionar campos sem breaking).
- Formato exato das fixtures (shape JSON/JSONL).
- Mensagens pt-BR exatas de erro em rota/CLI.
- Se `api1`/`api3`/`api4`/`api5`/`api7` inventory signals em Phase 13 vs Phase 12 (Phase 13 não faz inventory-DB-query; só testing).
- Ordem exata de imports, header de arquivos (segue CONVENTIONS.md).
- Se `harvestObjectIds` vira util compartilhado ou inline no BOLA.
- Exato shape da tabela de path-template parser (`{id}` vs `:id` vs `<id>`).
- Decisão de usar `p-limit` vs `Promise.all` em burst (Promise.all é simples; p-limit é defensivo).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Milestone spec
- `.planning/ROADMAP.md` §"Phase 13: Security Testing — Active" — goal + 5 success criteria + dependências
- `.planning/REQUIREMENTS.md` §"Security Testing (TEST)" — TEST-03, TEST-04, TEST-05, TEST-06, TEST-07 completos
- `.planning/REQUIREMENTS.md` §"Findings & Threat Integration (FIND)" (FIND-01) — shape de `api_findings` que Phase 13 popula
- `.planning/REQUIREMENTS.md` §"Safety & Guard-rails (SAFE)" — SAFE-01 (rate cap 10 req/s defensive + 50 absolute ceiling Phase 15 owner), SAFE-03 (destructive gating), SAFE-05 (dry-run target — Phase 15 owns), SAFE-06 (logs sem secrets)
- `.planning/PROJECT.md` §"Constraints" — "Schema changes must be additive", "Backward compatibility"
- `.planning/PROJECT.md` §"Key Decisions" — "BOLA/BFLA/BOPLA in-house TypeScript" (decisão load-bearing de Phase 13)

### Phase 9 CONTEXT carry-forward
- `.planning/phases/09-schema-asset-hierarchy/09-CONTEXT.md` — decisões vivas:
  - `owaspApiCategoryEnum` já contém `api1_bola_2023`, `api3_bopla_2023`, `api4_rate_limit_2023`, `api5_bfla_2023`, `api7_ssrf_2023` (ver `shared/schema.ts:94-102`).
  - `api_findings` schema completo já suporta as 5 novas categorias sem nenhuma mudança estrutural.
  - `ApiFindingEvidence` interface + `apiFindingEvidenceSchema` Zod (strict, bodySnippet max 8KB) cobre shape de evidence que Phase 13 popula.
  - `apiFindingStatusEnum`: `open | triaged | false_positive | closed` — Phase 13 só cria `open`.
  - `threatSeverityEnum` reusado (`low | medium | high | critical`).
  - `insertApiFindingSchema` exclui `promotedThreatId`/`riskScore` (Phase 14 owner).

### Phase 10 CONTEXT carry-forward
- `.planning/phases/10-api-credentials/10-CONTEXT.md` — decisões vivas:
  - `resolveApiCredential(apiId, endpointPath): Promise<ApiCredentialSafe | null>` — Phase 13 estende uso: além de resolver 1 cred, precisa **listar todas** que matcham (novo helper `listApiCredentialsForApi(apiId)` em Phase 13 OU extensão de `resolveApiCredential` — planner decide).
  - `getApiCredentialWithSecret(id)` — Phase 13 é consumidor legítimo (executor) para extrair secrets decriptados para BOLA/BFLA/BOPLA.
  - `apiCredentials.priority` int — Phase 13 usa para ranking low-priv vs high-priv (BFLA stage).
  - `apiCredentials.description` text — Phase 13 usa como sinal para low-priv detection (heurística "readonly"/"viewer").
  - 7 auth types — Phase 13 só age sobre `bearer_jwt`, `api_key_header`, `api_key_query`, `basic` (creds que injetam header/query simples em fetch). `hmac`/`oauth2`/`mtls` são suportados transitivamente via cred pipeline já construído em Phase 11 (katana autenticado), mas **Phase 13 não re-implementa signing** — se cred requer HMAC/mTLS, stage skipa com log.
  - pino redaction cobre `secretEncrypted`, `dekEncrypted`, `authorization` automaticamente.

### Phase 11 CONTEXT carry-forward
- `.planning/phases/11-discovery-enrichment/11-CONTEXT.md` — decisões vivas:
  - `DiscoverApiOpts`/`DiscoveryResult` como template do shape de `ApiActiveTestOpts`/`ActiveTestResult`.
  - Pattern de orquestrador `journeys/apiDiscovery.ts` com stages sequenciais + stagesSkipped + cancelled + durationMs.
  - Pattern de scanner-per-tool em `server/services/scanners/api/`.
  - `processTracker.registerProcess(jobId, child)` + SIGTERM graceful + SIGKILL 5s.
  - `jobQueue.isJobCancelled(jobId)` para cancelamento cooperativo.
  - "Resultados parciais persistem em cancel" — padrão replicado.
  - `requiresAuth` tri-valor (NULL=não probado, true=401/403, false=open) — Phase 13 filtra `requiresAuth=true` para TEST-03/04 (BOLA/BFLA precisam endpoints autenticados).
  - `api_endpoints.query_params`/`request_params`/`request_schema` JSONB shape `{ name, type?, required?, example? }` — Phase 13 SSRF stage lê para identificar URL-like params.

### Phase 12 CONTEXT carry-forward (DIRETAMENTE aplicável)
- `.planning/phases/12-security-testing-passive/12-CONTEXT.md` — decisões vivas:
  - **Pattern de entrypoint trip-leg** (função + rota + CLI + runbook) replicado **integralmente** para Phase 13 (trocar "passive" → "active").
  - `upsertApiFindingByKey(endpointId, category, title, data)` em `server/storage/apiFindings.ts` — **Phase 13 reusa sem estender**. Mesma key `(endpointId, category, title)`, mesma lógica dedupe.
  - `listApiFindings(filter)` em `server/storage/apiFindings.ts` — read path do Phase 12 serve também findings Phase 13 (mesma tabela).
  - `API_REMEDIATION_TEMPLATES` em `shared/apiRemediationTemplates.ts` — Phase 13 **estende** com 5 novas entries (api1/api3/api4/api5/api7). Não cria arquivo novo.
  - Shape `PassiveTestResult` — template direto para `ActiveTestResult`.
  - Pattern fixtures `server/__tests__/fixtures/api-passive/` → replica em `api-active/`.
  - Pattern dryRun com `[DRY-RUN]` prefix no título.
  - **Decisão `NucleiFinding` camelCase** — aplica também para Phase 13 SSRF stage (parse JSONL usa `matchedAt`, `templateId`).
  - Pattern `decodeJwtExp` retorna `Date | null` — não aplicável direto em Phase 13 (não faz JWT manipulation), mas contexto útil se BFLA-JWT variante surgir.

### Schema atual (shared/schema.ts)
- `shared/schema.ts:94-102` — `owaspApiCategoryEnum` com todos 10 valores OWASP 2023 (Phase 13 usa 5: api1/api3/api4/api5/api7).
- `shared/schema.ts:1225-1239` — `ApiFindingEvidence` interface.
- `shared/schema.ts:1242-1317` — `apis` + `api_endpoints` tables (Phase 13 consome).
- `shared/schema.ts:1319-1347` — `apiFindings` table + tipos `ApiFinding`, `InsertApiFinding`.
- `shared/schema.ts:1546-1562` — `apiFindingEvidenceSchema` Zod.
- `shared/schema.ts:1581-1586` — `insertApiFindingSchema`.
- `shared/schema.ts` (Phase 12) — `apiPassiveTestOptsSchema` + `PassiveTestResult` — templates.
- `shared/schema.ts` — `NucleiFindingSchema` para parse JSONL Nuclei SSRF.

### Nuclei integration (Phase 12 + v1.0 patterns)
- `server/services/journeys/nucleiPreflight.ts` — preflight memoizado. **Reusa direto** para SSRF stage.
- `server/services/scanners/api/nucleiApi.ts` (Phase 12) — template de wrapper Nuclei com JSONL streaming + processTracker + `-silent -jsonl -rl -timeout`. Phase 13 SSRF adapta: muda `-tags ssrf`, REMOVE `-ni`, ADICIONA `-interactsh-url <URL>`.
- `server/services/scanners/vulnScanner.ts:130` — linha `-ni` existente (currently disable). Phase 13 SSRF precisa NÃO passar essa flag no SSRF stage específico (não é global).
- https://docs.projectdiscovery.io/tools/nuclei/usage — flags `-tags`, `-l`, `-rl`, `-timeout`, `-severity`, `-jsonl`, `-silent`, `-interactsh-url`, `-interactions-poll-duration`, `-interactions-wait`, `-interactions-retries-count`.
- https://docs.projectdiscovery.io/tools/interactsh — server self-hosted setup, client library, OOB interaction types (DNS/HTTP/SMTP).
- https://owasp.org/API-Security/editions/2023/en/0x11-t10/ — categorias oficiais API1/API3/API4/API5/API7.

### Scanner + spawn patterns
- `server/services/scanners/api/nucleiApi.ts` (Phase 12) — template mais recente e próximo.
- `server/services/scanners/api/authFailure.ts` (Phase 12) — template de scanner in-house TypeScript com `fetch` nativo (sem binário externo). Padrão direto para BOLA/BFLA/BOPLA/rateLimit.
- `server/services/scanners/api/preflight.ts` — pattern de `preflightApiBinary` memoizado.
- `server/services/processTracker.ts` — `registerProcess(jobId, child)` + SIGTERM graceful.
- `server/services/journeyExecutor.ts` — pattern de progress callback + cancelation check.

### Storage + schema (reuse Phase 12)
- `server/storage/apiFindings.ts` (Phase 9+12) — `upsertApiFindingByKey` + `listApiFindings`. **Phase 13 consome sem estender**.
- `server/storage/apiCredentials.ts` (Phase 10) — `resolveApiCredential` + `getApiCredentialWithSecret`. Phase 13 pode adicionar `listApiCredentialsForApi(apiId)` se não existir (planner decide — pode ser inline no orquestrador com `db.select().from(apiCredentials).where(...)`).
- `server/storage/apis.ts` + `server/storage/apiEndpoints.ts` — query endpoints para stages (filtros `requiresAuth`, `method`, `httpxStatus`).
- `server/storage/interface.ts` — sem mudança (já tem assinaturas Phase 12 necessárias).

### Route + CLI patterns (replica Phase 12)
- `server/routes/apis.ts` (Phase 11+12) — template direto: handler `POST /api/v1/apis/:id/test/passive` existe; Phase 13 adiciona handler `POST /api/v1/apis/:id/test/active` no mesmo arquivo.
- `server/routes/apiFindings.ts` (Phase 12) — read path **já serve findings Phase 13** (mesma tabela, mesmos filtros). **Sem mudança.**
- `server/routes/index.ts` — sem mudança (barrel já registra `registerApiFindingsRoutes`).
- `server/scripts/runApiPassiveTests.ts` (Phase 12) — template 1:1 para `runApiActiveTests.ts`.
- `docs/operations/run-api-passive-tests.md` (Phase 12) — template 1:1 para `run-api-active-tests.md`.

### Fetch + stateful testing
- `node:undici` ou `fetch` nativo Node 18+ — usado por Phase 12 `authFailure.ts`. Phase 13 usa mesmo para BOLA/BFLA/BOPLA/rateLimit.
- `Promise.all([...])` para rate-limit burst — simples; `p-limit` não é necessário nesse caso (burst é proposital).
- Path-template parsing: regex `/\{(\w+)\}/g` cobre `{id}` OpenAPI. Swagger 2.0 usa mesmo formato. Express-style `:id` não aparece em API-externa (cliente-side).

### Convenções
- `.planning/codebase/CONVENTIONS.md` — naming, import order, error handling pt-BR, `createLogger('componentName')`.
- `.planning/codebase/STRUCTURE.md` — organização `server/services/scanners/api/`, `server/services/journeys/`, `server/routes/`, `server/storage/`, `server/scripts/`.
- `.planning/codebase/TESTING.md` — padrão Vitest + mocks + `vi.hoisted()` TDZ guard.
- `.planning/codebase/STACK.md` — TypeScript 5.6.3, Express 4, Drizzle 0.39, Zod 3.24, Vitest 4, Node 20+.

### Logging + redaction
- `server/lib/logger.ts` — pino redaction paths cobrem `secretEncrypted`, `dekEncrypted`, `authorization`.
- SAFE-06 vigor: Phase 13 loga `{ apiId, endpointId, credentialIdA, credentialIdB, findingId, owaspCategory, severity, stage }`. Nunca bodies de request/response, nunca valores harvestados de IDs, nunca interactsh callback URLs não-mascaradas.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`api_findings` table + evidence schema + category enum** (`shared/schema.ts`) — todos os 5 valores OWASP já existem no enum. **Zero alteração de schema.**
- **`upsertApiFindingByKey` + `listApiFindings`** (`server/storage/apiFindings.ts` Phase 12) — dedupe transacional pronto; read path pronto. **Zero extensão de storage facade para findings.**
- **`resolveApiCredential` + `getApiCredentialWithSecret`** (Phase 10) — cred resolution; Phase 13 pode precisar `listApiCredentialsForApi` novo OU inline query.
- **`nucleiPreflight.ts` + padrão de spawn em `nucleiApi.ts`** — template pronto para SSRF stage (só muda `-tags ssrf`, remove `-ni`, adiciona interactsh flags).
- **`authFailure.ts` (Phase 12)** — padrão 1:1 para scanners in-house TS de Phase 13 (fetch nativo, header injection, response parse).
- **`apiPassiveTests.ts` orchestrator (Phase 12)** — template direto para `apiActiveTests.ts`.
- **Fixtures pattern `server/__tests__/fixtures/api-passive/`** — replica em `api-active/`.
- **`POST /api/v1/apis/:id/test/passive` route (Phase 12)** — template direto para `POST /api/v1/apis/:id/test/active`.
- **`runApiPassiveTests.ts` CLI (Phase 12)** — template direto.
- **`API_REMEDIATION_TEMPLATES`** (Phase 12) — **estende** com 5 entries; não cria novo arquivo.
- **`processTracker` + `jobQueue.isJobCancelled`** — cancelamento cooperativo pronto.
- **Nyquist test structure** `server/__tests__/apiPassive/` (Phase 12) — replica em `server/__tests__/apiActive/`.
- **Vitest mock patterns com `vi.hoisted()`** — pattern carry-forward Phase 10/12.

### Established Patterns
- **Scanner-per-tool/vector** em `server/services/scanners/api/` — Phase 13 adiciona **5 arquivos**: `bola.ts`, `bfla.ts`, `bopla.ts`, `rateLimit.ts`, `ssrfNuclei.ts`.
- **Orchestrator journey** em `server/services/journeys/<capability>.ts` — Phase 13 adiciona `apiActiveTests.ts` paralelo a `apiPassiveTests.ts`.
- **Zod schema em `shared/schema.ts`** — `apiActiveTestOptsSchema` com `.strict()` root e sub-objeto `stages`.
- **Storage facade NÃO estendida** para findings — reusa Phase 12 methods.
- **Credential listing** pode adicionar 1 método novo em `apiCredentials.ts` storage: `listApiCredentialsForApi(apiId): Promise<ApiCredentialSafe[]>` (planner decide se é novo método vs inline query em BOLA).
- **Route registration** — adiciona handler em `apis.ts` (POST /:id/test/active). Não cria arquivo novo.
- **CLI standalone** `tsx --env-file=.env` + `import.meta.url` guard + argv parse + `--help`.
- **pt-BR em mensagens, EN em código**.
- **Fixtures em `server/__tests__/fixtures/`** para dryRun determinístico.

### Integration Points
- **`shared/schema.ts`** — adicionar `apiActiveTestOptsSchema` Zod + `ActiveTestResult` interface.
- **`shared/apiRemediationTemplates.ts`** (Phase 12) — **estender** com 5 entries (api1/api3/api4/api5/api7). Preservar entries Phase 12 existentes.
- **`server/services/scanners/api/bola.ts`** (novo) — 2-3 funções: `pairCredentials(creds)`, `harvestObjectIds(cred, endpoint)`, `testCrossAccess(credA, credB, endpoint, ids)`.
- **`server/services/scanners/api/bfla.ts`** (novo) — `identifyLowPrivCreds(creds)`, `matchAdminEndpoint(endpoint)`, `testPrivEscalation(lowCred, endpoint)`.
- **`server/services/scanners/api/bopla.ts`** (novo) — `fetchSeedBody(endpoint, cred)`, `injectSensitiveKey(body, key)`, `verifyReflection(endpoint, cred, key)`.
- **`server/services/scanners/api/rateLimit.ts`** (novo) — `buildBurst(endpoint, cred, burstSize)`, `detectThrottling(responses)`.
- **`server/services/scanners/api/ssrfNuclei.ts`** (novo) — `identifyUrlParams(endpoints)`, `runSsrfNuclei(targets, opts, jobId?)` — adapta `nucleiApi.ts` de Phase 12.
- **`server/services/journeys/apiActiveTests.ts`** (novo) — orquestrador: stages `bola → bfla → bopla → rate_limit → ssrf` + finalize + cancel + dryRun.
- **`server/routes/apis.ts`** (estender Phase 11+12) — adicionar handler `POST /api/v1/apis/:id/test/active` (RBAC + Zod + body = `apiActiveTestOptsSchema`).
- **`server/scripts/runApiActiveTests.ts`** (novo) — CLI operador.
- **`docs/operations/run-api-active-tests.md`** (novo) — runbook pt-BR.
- **`server/__tests__/fixtures/api-active/`** (nova pasta) — 5-6 fixtures.
- **`server/__tests__/apiActive/`** (nova pasta) — 15 Nyquist test stubs (15 `it.todo` → GREEN via Waves 1-3).

### Constraints Aplicáveis
- PROJECT.md "Schema changes must be additive" — **satisfeito** (zero mudança estrutural; só popula `api_findings` existente).
- PROJECT.md "Backward compatibility" — **satisfeito** (zero mudança em executors existentes Phase 12).
- SAFE-06 "Logs estruturados sem secrets" — satisfeito via pino redaction + logs estruturados com IDs + contagens. interactsh URLs mascaradas em logs.
- SAFE-01 "rate cap 10 req/s default, 50 absolute ceiling" — Phase 13 implementa 10 QPS default em Nuclei (`-rl 10`) + `p-limit` 10 em stages TS (BOLA/BFLA/BOPLA); rate-limit stage intencionalmente satura (burst propósito do teste). Phase 15 reforça ceiling global.
- SAFE-03 "DELETE/PUT/PATCH destructive gating" — Phase 13 **implementa gate local** via `opts.destructiveEnabled=false` default. Afeta BOPLA (PUT/PATCH intrínseco) + BFLA method-based. Phase 15 reforça globalmente via journey config.
- SAFE-05 "dry-run target" — Phase 13 aceita `opts.dryRun` via fixtures locais; `/healthz/api-test-target` externo fica Phase 15.
- SAFE-06 sensível a interactsh: Phase 13 loga apenas prefixo `oast_abc***` de interactsh URLs; nunca logs completos (privacy de canal OOB).

</code_context>

<specifics>
## Specific Ideas

- **"5 vetores, 5 scanners, 1 orchestrator"** — nomenclatura mnemônica. Cada scanner isolado + testável independente. Orchestrator apenas compõe + gerencia state shared (creds, cancelation).
- **BOLA é "stateful twin de BFLA"** — mesma infra de cred pairing, mas BOLA foca em object-ID cross-access (API1) e BFLA foca em endpoint-path/method access (API5). Separação estrita: BOLA nunca tenta admin path; BFLA nunca harvest IDs.
- **BOPLA é **subset** de BFLA em alguns frameworks** — OWASP 2023 consolidou BOPLA em API3 distinto. Phase 13 mantém como stages separadas: BFLA testa "posso acessar?", BOPLA testa "posso escrever campos proibidos?".
- **Rate-limit absence NÃO é ataque** — é sinal de posture. Severity medium reflete isso. Operador decide se quer testar (flag opt-in default OFF).
- **Interactsh é externo por padrão** — Phase 13 não exige self-hosted. `oast.me` (ProjectDiscovery público) funciona out-of-box. Air-gapped environments configuram `INTERACTSH_URL` env — runbook documenta.
- **Mask-at-source é carry-forward Phase 12** — aplicável a interactsh URLs (prefix-3 + ***), object IDs harvestados (primeiro char + ***), apiKeys em BFLA context (já coberto Phase 10 pino redaction).
- **`destructiveEnabled` é gate local, não global** — Phase 15 SAFE-03 introduz gate journey-level (authorization ack). Phase 13 expõe gate próprio para operador CLI/API direto sem journey. Dois layers = defense in depth.
- **Títulos determinísticos com `{{key}}`/`{{paramName}}` substitution** — para BOPLA/SSRF, título contém parâmetro específico. Dedupe por `(endpointId, category, title_com_param)` — variante da chave injeta chave no título. Isso intencionalmente **NÃO deduplica** entre chaves/params diferentes no mesmo endpoint (BOPLA em `is_admin` é finding diferente de BOPLA em `role`; ambos devem persistir).
- **BOLA pair ordering matters** — `(A,B)` testa "A vê objeto de B". Como sabemos qual cred é "da vítima" vs "atacante"? Ambos são potenciais vítimas. Logo, geramos pares ordenados: `(A,B)` harvest-de-A tested-com-B; para testar reverso (B vê objeto de A), precisa par `(B,A)` separado. **Phase 13 roda só metade** (`A→B` para todo par não-ordenado) para economizar budget; se operador quer full cross, roda 2ª vez com `credentialIds` reverso.
- **BFLA method-based testing é hard-disabled por default** — testar PUT/PATCH/DELETE em endpoints non-admin-path requer `destructiveEnabled=true`. Justificativa: DELETE em `/users/{id}` com baixo-privilégio pode literalmente deletar usuário da vítima. Gate explícito protege.
- **Rate-limit burst só em 1 endpoint por API** — default conservador. Testar burst em 50 endpoints do API seria DoS involuntário. Operador deliberadamente seleciona endpoints via `opts.rateLimit.endpointIds`.
- **SSRF stage único que usa interactsh** — outros stages de Phase 13 não exigem callback externo. Mantém Nuclei `-ni` (no-interactsh) nos stages Phase 12 (nucleiApi.ts unchanged) e habilita apenas em `ssrfNuclei.ts`.
- **Fixtures 5-6 arquivos máximo** — Phase 12 usou 5; Phase 13 tem 5 vetores. Sobrecarregar fixtures vs cobrir edge cases é balance; 1 per vetor + 1 pair para BOPLA (before+after) = 6 arquivos. Suficiente.

</specifics>

<deferred>
## Deferred Ideas

- **BOLA com IDs inferidos de múltiplas fontes** — hoje harvest só de list-endpoints. Inferir IDs de query params de request history seria mais rico; deferido.
- **BOLA reverso automático `(A,B)` + `(B,A)` no mesmo run** — hoje metade do grafo. Flag `opts.bola.bidirectional=true` adicionável.
- **BOPLA com campos custom fornecidos pelo operador** — hoje lista curada de 10. Permitir `opts.bopla.additionalKeys: string[]` aditivo.
- **Rate-limit burst crescente** — hoje burst fixo N=20. Sofisticação: ramp-up (5→10→20→50) para identificar threshold. Deferido.
- **SSRF com payloads cloud-metadata** — hoje Nuclei templates oficiais cobrem `169.254.169.254` etc. Se gap, templates custom `ssrf/cloud-metadata-*.yaml` são aditivos.
- **SSRF com DNS rebinding** — Nuclei não cobre natively. Deferido para threat-model maduro.
- **Full BFLA matrix** (todas creds × todos métodos × todos admin paths) — explosão combinatória. Phase 13 cap em 100 requests; full matrix pode ser opt-in `opts.bfla.fullMatrix=true` deferido.
- **Authorization header manipulation em BFLA** — forjar role claim em JWT (estende Phase 12 alg:none) — caso híbrido BFLA + broken auth. Deferido; Phase 14 pode unificar.
- **Race-condition-based authorization bypass** — fora de escopo Phase 13 (não está em TEST-*). Phase 13 é sequencial por design.
- **Performance profiling dos stages** — `durationMs` no result é agregado. Per-stage duration útil para tuning; aditivo.
- **Paralelismo entre APIs em 1 job** — sequencial hoje (Phase 11/12 padrão). Phase 15 orchestration decide.
- **Auto-retry em transient failures** — hoje fail-fast stage-level. Retry com backoff + jitter é melhoria futura.
- **Correlação BOLA ↔ BOPLA** — se BOLA sucede em `/users/{id}`, BOPLA automaticamente testa PUT no mesmo ID. Cross-stage inference útil; deferido.
- **`api6_unrestricted_access_sensitive_flows_2023` (Business Flow, API6)** — explicitamente fora v2.0 (REQUIREMENTS.md §"Future FLOW-01"). Phase 13 não gera findings dessa categoria.
- **`api10_unsafe_consumption_third_party_apis_2023`** — fora v2.0. Deferred.
- **Audit trail de testing decisions** — qual cred rodou em qual endpoint, qual payload injetado. Phase 15 SAFE-04 introduz audit_log formal; Phase 13 loga via pino mas não popula tabela.
- **Template Nuclei custom OWASP API-específico** — Phase 12 deferrou; se gap em Phase 13, adicionar `server/resources/nuclei-api-templates/` vendored.
- **Interactsh self-hosted auto-setup** — runbook documenta manual; Phase 15 ou post-v2.0 pode scriptar.
- **BOPLA em POST (create) endpoints** — mass assignment clássico também ocorre em create. Phase 13 escopou para PUT/PATCH per success criteria #3. POST é deferred aditivo.

</deferred>

---

*Phase: 13-security-testing-active*
*Context gathered: 2026-04-20 via /gsd:discuss-phase 13 --auto*
</content>
</invoke>