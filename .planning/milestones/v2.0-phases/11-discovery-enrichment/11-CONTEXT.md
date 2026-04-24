# Phase 11: Discovery & Enrichment - Context

**Gathered:** 2026-04-19
**Status:** Ready for planning

<domain>
## Phase Boundary

Entregar o **pipeline de descoberta e enriquecimento de endpoints de API**, populando `apis` e `api_endpoints` (tabelas do Phase 9) para consumo das phases de testing (12-13).

Escopo do Phase 11:
- **Spec-first probing + parsing** (DISC-01, DISC-02): probe de paths conhecidos (`/openapi.json`, `/swagger.json`, `/v2/api-docs`, `/v3/api-docs`, `/api-docs`, `/swagger-ui.html`, `/docs/openapi`) + parse nativo via `@apidevtools/swagger-parser` (OpenAPI 2.0/3.0/3.1).
- **GraphQL introspection** (DISC-03): POST standard introspection query em `/graphql`, `/api/graphql`, `/query`.
- **Katana crawling** (DISC-04): XHR/JS/form extraction para surface endpoints invocados por SPA.
- **Kiterunner brute-force opt-in** (DISC-05): usa `wordlists/routes-large.kite` vendorizado.
- **specHash + drift detection** (DISC-06).
- **httpx enrichment** (ENRH-01, ENRH-02): status, tech-detect, content-type, TLS + `requiresAuth` tri-valor.
- **Arjun parameter discovery opt-in** (ENRH-03): só em endpoints GET user-selected, wordlist `wordlists/arjun-extended-pt-en.txt`.
- **Entrypoint trip-leg**: função `discoverApi(apiId, opts, jobId?)` + rota interna `POST /api/v1/apis/:id/discover` + CLI de operador.

**Fora de escopo deste phase (em outras phases):**
- Roteamento no journeyExecutor + enum `api_security` em `journey_type` → Phase 15 (JRNY-01).
- Sanitização de evidence, promoção para `threats`, WebSocket events → Phase 14.
- Testes de segurança (Nuclei misconfigs, BOLA, BFLA, BOPLA, rate-limit, SSRF) → Phases 12-13.
- Rate cap global (SAFE-01), destructive gating (SAFE-03), audit log (SAFE-04), dry-run target (SAFE-05), authorization ack (JRNY-02) → Phase 15.
- UI da página `/journeys/api`, wizard, findings filter → Phase 16.
- Auto-update de binários → deferido (AUTOUP post-v2.0).

Phase 11 é **runtime de pipeline** — delivery de scanners (`server/services/scanners/api/`) + orquestrador (`server/services/journeys/apiDiscovery.ts`) + interface pública (função + rota + CLI). A journey `api_security` end-to-end só existe após Phase 15 wirar.

</domain>

<decisions>
## Implementation Decisions

### Orquestração + dedupe

- **Ordem sequencial das etapas** por API: `spec-first → katana crawler → kiterunner brute-force → httpx enrichment → arjun parameter discovery`. Cada stage falha independente sem abortar pipeline (log + skip).
- **Crawler e Kiterunner SEMPRE rodam se toggle ligado**, mesmo após spec-first succeed. Justificativa: spec raramente é completa (SPAs têm endpoints XHR não-documentados, brute-force acha endpoints ocultos — cobertura API9 Improper Inventory).
- **Dedupe via UQ `(api_id, method, path)` + append em `discoverySources`**: se endpoint já existe, append fonte nova (`['spec']` → `['spec','crawler']`), atualiza enrichment fields (`requiresAuth`, schemas) e **preserva** `requestSchema`/`responseSchema` do spec se já populados (spec é mais rico que crawler/brute-force).
- **Rerun idempotente — manter stale endpoints + flag via log**: endpoints que existiam mas não foram redescobertos permanecem em `api_endpoints` (FK CASCADE de `api_findings` protege histórico). Drift logado como `log.info({ apiId, endpointIdsNotSeen }, 'stale endpoints preserved')`. Adicionar coluna `lastSeenAt` é **deferred** (não faz parte do Phase 9; futuro aditivo).
- **Drift do `specHash`**: Phase 11 apenas loga `log.warn({ apiId, oldHash, newHash }, 'spec drift detected')` + re-parseia spec (upsert normal). NÃO cria finding API9 aqui (responsabilidade de Phase 12/13 se decidirem gerar).

### Scanners + spawn + preflight

- **Organização**: um arquivo por ferramenta em `server/services/scanners/api/`:
  - `katana.ts`, `httpx.ts`, `kiterunner.ts`, `arjun.ts`, `openapi.ts`, `graphql.ts` (6 arquivos).
  - Orquestrador em `server/services/journeys/apiDiscovery.ts` importa os 6.
  - Simetria com `scanners/networkScanner.ts`/`vulnScanner.ts` existentes; cada scanner isolado e testável.
- **Output capture híbrido**:
  - katana (`-jsonl`), httpx (`-json`), kiterunner (`-o json`) → streaming stdout JSONL + split por `\n` + `JSON.parse` por linha (evita OOM em crawl grande).
  - arjun não tem stdout estruturado → `arjun -oJ <tempfile>` em `/tmp/api-discovery-<jobId>/arjun-<endpointId>.json`, lê no fim, `unlink` após parse.
  - openapi/graphql → HTTP fetch direto (nada de spawn externo).
- **Preflight lazy + memoizado por binário**, padrão `nucleiPreflight.ts`:
  - `preflightApiBinary('katana' | 'httpx' | 'kiterunner' | 'arjun')` — memoizado per-process, roda `which <bin>` na 1ª invocação, cacheia resultado.
  - Se binário faltar: **skipa a stage + log.error + continua pipeline** (discovery parcial > abort). Não bloqueia boot.
  - NÃO cria `api_findings` por binário ausente (responsabilidade fora do Phase 11).
- **Timeout + concorrência**:
  - **APIs processadas sequencialmente** dentro de um job (simples, previsível; Phase 15 pode paralelizar futuramente).
  - Timeouts default por tool: spec-fetch **10s**, katana **120s**, kiterunner **300s**, httpx **30s por batch**, arjun **60s por endpoint**.
  - Cancelamento via `AbortController` atrelado ao `jobId` + `processTracker` (padrão do projeto). SIGTERM graceful; SIGKILL após 5s se não responde.
  - **Resultados parciais persistem em cancel** — endpoints já gravados em `api_endpoints` permanecem (valioso para retry).

### Spec-first + GraphQL + auth

- **Spec fetch — unauth first, retry com cred em 401/403**:
  - 1ª tentativa sem credencial. Se 200 + JSON válido: parseia + loga `specPubliclyExposed=true` (sinal de API9 para downstream).
  - Se 401/403: retry com `resolveApiCredential(apiId, specPath)`. Se retorna cred compatível (api_key_header/bearer_jwt/basic/oauth2), usa. Se cred incompatível (hmac/mtls/api_key_query), skipa retry + log.
  - Loga `log.info({ apiId, specUrl, authUsed: boolean }, 'spec fetched')`.
- **`$ref` externos em OpenAPI**:
  - `@apidevtools/swagger-parser.dereference()` para locais (automático).
  - `$ref` HTTP externos: **apenas same-origin** do spec (URL parse + host compare). SSRF-safe: spec malicioso apontando para `169.254.169.254/metadata` é rejeitado.
  - Se `$ref` externo falha fetch/resolve: log warn + continua com spec parcial.
- **Escolha entre múltiplos specs 200**: primeira URL válida que parseia com sucesso, na ordem do REQUIREMENTS (`/openapi.json` → `/swagger.json` → `/v3/api-docs` → `/v2/api-docs` → `/api-docs` → `/swagger-ui.html` → `/docs/openapi`). URL vencedora → `apis.specUrl`. Outras URLs encontradas logadas (sinal de API9 inventory).
- **`specVersion`** extraído do próprio spec (`openapi: "3.1.0"` ou `swagger: "2.0"`); GraphQL: string fixa `"GraphQL"`.
- **`specHash`**: SHA-256 do JSON **canônico** — `crypto.createHash('sha256').update(JSON.stringify(spec, Object.keys(spec).sort()))` — garante que whitespace/key-order não falseia drift. Armazenado em `apis.specHash` + `specLastFetchedAt`.
- **GraphQL introspection**:
  - POST `application/json` + body `{ query: 'query IntrospectionQuery { __schema { ... } }' }` (standard full query).
  - Paths em ordem: `/graphql`, `/api/graphql`, `/query`.
  - Unauth first, retry com cred em 401/403 (mesma lógica do REST).
  - **Schema → endpoints**: 1 row em `api_endpoints` por operation (query/mutation/subscription) com:
    - `method = 'POST'` (GraphQL via HTTP POST)
    - `path = '/graphql'` (ou path descoberto) + usa a coluna `path`, não inflar
    - **TBD no planner**: onde persistir o operation name. Opção: `requestSchema.operationName` no JSONB. Planner decide.
    - `requestSchema` JSONB: `{ operationName, operationType, variables: [...] }`
    - `discoverySources = ['spec']`

### Entrypoint + opt-ins + enrichment

- **Phase 11 expõe 3 superfícies**:
  1. **Função pura** `discoverApi(apiId, opts, jobId?): Promise<DiscoveryResult>` em `server/services/journeys/apiDiscovery.ts` — consumida por Phase 15 journey executor.
  2. **Rota interna** `POST /api/v1/apis/:id/discover` (RBAC `global_administrator` + `operator`, body aceita `opts`) — trigger manual pela UI antes de journey completa (Phase 16 pode usar).
  3. **CLI** `server/scripts/runApiDiscovery.ts --api=<id> [--no-crawler] [--kiterunner] [--arjun-endpoint=<id>...]` para debug/dry-run de operador.
- **Shape do `opts`** (Zod schema em `shared/schema.ts` ou `server/services/journeys/apiDiscovery.ts`):
  ```ts
  type DiscoverApiOpts = {
    stages: {
      spec?: boolean;        // default true
      crawler?: boolean;     // default true
      kiterunner?: boolean;  // default false (opt-in)
      httpx?: boolean;       // default true
      arjun?: boolean;       // default false (opt-in)
    };
    arjunEndpointIds?: string[]; // IDs já existentes em api_endpoints (obrigatório se stages.arjun=true)
    credentialIdOverride?: string; // força usar cred específica em vez do resolve
    dryRun?: boolean;           // default false — se true, roda só spec + httpx, pula crawler/kiterunner/arjun
    katana?: { headless?: boolean; depth?: number }; // overrides defensivos
    kiterunner?: { rateLimit?: number };             // override default 10 QPS
  };
  ```
- **httpx enrichment — probe em 2 passos quando aplicável**:
  - Passo 1 (sempre): probe **unauth** → captura status, tech-detect, content-type, TLS info. Preenche:
    - `requiresAuth = true` se status ∈ {401, 403}
    - `requiresAuth = false` se status ∈ {200, 201, 204, 3xx}
    - `requiresAuth = NULL` se outros (5xx, timeout) — preserva tri-valor
  - Passo 2 (condicional): se `requiresAuth === true` E `resolveApiCredential()` retorna cred compatível → 2ª probe auth. Atualiza status real + TLS (mesma row).
  - Campos persistidos em `api_endpoints` (novas colunas via Phase 11 aditivo? OU em campo livre?): **checkpoint para planner** — REQUIREMENTS diz "status, tech-detect, content-type, TLS info". Schema atual do Phase 9 não previu colunas dedicadas. **Decisão**: adicionar colunas aditivas em `api_endpoints` (plan will define exact shape: `httpxStatus int`, `httpxContentType text`, `httpxTech text[]`, `httpxTls jsonb`, `httpxLastProbedAt timestamp`). Guard idempotente em `database-init.ts`.
- **Arjun — user-selected via `arjunEndpointIds` no opts**:
  - Phase 11 recebe lista de `api_endpoints.id` para rodar Arjun. Valida que cada ID existe + `method === 'GET'` + `apiId` matches.
  - Wordlist default: `wordlists/arjun-extended-pt-en.txt` (vendorizada Phase 8). Path absoluto injetado via env/config.
  - Parâmetros descobertos fazem **merge append** em `api_endpoints.query_params` JSONB (não substitui). Dedupe por `name`.
  - Phase 16 wizard exibe checklist de endpoints GET e passa IDs selecionados para Phase 15, que chama `discoverApi` com `opts.arjunEndpointIds`.
- **Katana — depth 3, same-origin, headless opt-in**:
  - Default: `-d 3`, `-fs rdn` (root-domain-name — *.registrable-domain), `-jc` (JS regex crawl sem headless).
  - Headless via `opts.katana.headless=true` → adiciona `-headless -system-chrome=false`. Requer Chrome instalado; Phase 11 loga warn se headless solicitado mas `which chromium-browser` falha.
  - `-timeout 10` por request, output `-jsonl`.
  - Escopo output: `-em xhr,fetch,websocket,ajax,form` (filtra para inputs relevantes a API).
- **Katana crawling autenticado — só auth-types compatíveis com header injection**:
  - `api_key_header`, `bearer_jwt`, `basic`: passa via `-H 'Authorization: Bearer ...'` / `-H '<headerName>: <value>'`. Decripta via `getApiCredentialWithSecret`.
  - `oauth2_client_credentials`: Phase 11 faz mint do token via POST no `tokenUrl` (client_credentials grant) **antes** do crawl, cache in-memory por `expires_in - 30s`, passa bearer resultante. Se mint falha → log + unauth crawl.
  - `mtls`: gera tempfile cert/key em `/tmp/api-discovery-<jobId>/mtls-<credId>.{cert,key,ca}` + `-ca-cert/-client-cert/-client-key` do katana; limpa após run.
  - `api_key_query`: **skip auth** + log warn (katana não re-escreve URL per request para injetar query).
  - `hmac`: **skip auth** + log warn (assinatura por-request incompatível com spawn de crawler).
- **Kiterunner — rate cap 10 QPS default, override via opts**:
  - `kr scan -w wordlists/routes-large.kite -x 10` (10 QPS). `opts.kiterunner.rateLimit?: number` aceita override.
  - **Sem hard ceiling aqui** — Phase 15 (SAFE-01) impõe ceiling de 50 QPS globalmente. Phase 11 é defensive-by-default.
  - Status codes considerados "hit": **2xx, 3xx, 401, 403** (401/403 = endpoint existe mas protegido → valioso para ENRH-02).
  - Output `-o json` streaming JSONL.

### DiscoveryResult shape (retornado por `discoverApi`)

```ts
type DiscoveryResult = {
  apiId: string;
  stagesRun: Array<'spec' | 'crawler' | 'kiterunner' | 'httpx' | 'arjun'>;
  stagesSkipped: Array<{ stage: string; reason: string }>;  // binário ausente, toggle off, etc
  endpointsDiscovered: number;       // novos inserts
  endpointsUpdated: number;          // existing updated (append discoverySources / enrichment)
  endpointsStale: string[];          // endpointIds não vistos nesse run
  specFetched?: { url: string; version: string; hash: string; driftDetected: boolean };
  cancelled: boolean;
  durationMs: number;
};
```

### Logging estrutura

- **Por stage**: `log.info({ apiId, stage, jobId, ...metrics }, 'stage complete')`.
- **Redação automática** via pino já cobre `secretEncrypted`, `dekEncrypted`, `authorization` (herdado do projeto).
- **Nunca logar** bodies de request/response, tokens OAuth mintados, valores de params descobertos. Só contagens + IDs.

### Claude's Discretion

- Nomes exatos de funções internas nos scanners (`runKatana`, `runHttpx`, etc).
- Estrutura interna do `DiscoveryResult` (planner pode refinar campos adicionais).
- Shape exato das colunas httpx em `api_endpoints` (planner + researcher).
- Formato dos tempfiles (nome, path, cleanup strategy com `try/finally`).
- Escolha entre `p-limit` vs `for-await` para loops internos de endpoints.
- Nyquist test stubs (Wave 0): sugestão de ~8 testes — spec-fetch auth retry, $ref same-origin guard, specHash canonical hash, GraphQL introspection parse, dedupe append discoverySources, httpx tri-valor requiresAuth, arjun endpointIds validation, cancellation persists partial.
- Mensagens pt-BR exatas para erros em rota/CLI.
- Ordem de imports, header de arquivos, etc (segue CONVENTIONS.md).
- Se `operationName` do GraphQL vira coluna dedicada em `api_endpoints` ou fica em `requestSchema.operationName`.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Milestone spec
- `.planning/ROADMAP.md` §"Phase 11: Discovery & Enrichment" (linhas 104-119) — goal + 5 success criteria + dependências
- `.planning/REQUIREMENTS.md` §"Discovery (DISC)" (linhas 26-33) — DISC-01..DISC-06 completos
- `.planning/REQUIREMENTS.md` §"Enrichment (ENRH)" (linhas 35-39) — ENRH-01..ENRH-03
- `.planning/REQUIREMENTS.md` §"Safety & Guard-rails (SAFE)" (linhas 65-73) — SAFE-01 (rate cap) carry-forward constraint de Phase 15
- `.planning/PROJECT.md` §"Constraints" — "Schema changes must be additive", "Backward compatibility"
- `.planning/PROJECT.md` §"Key Decisions" — "BOLA/BFLA/BOPLA in-house TypeScript", "auxiliary binaries via release tarball"

### Phase 9 CONTEXT carry-forward
- `.planning/phases/09-schema-asset-hierarchy/09-CONTEXT.md` — decisões vivas:
  - `apis` table shape (colunas `specHash`, `specVersion`, `specLastFetchedAt`, `specUrl` já criadas nulláveis)
  - `api_endpoints.discoverySources text[]` + TS const (sem pgEnum — adicionar valor não exige migration)
  - `api_endpoints.requiresAuth` boolean **nullable** com semântica tri-valor (NULL=não probado, true=401/403, false=2xx)
  - `UQ (api_id, method, path)` — dedupe aqui
  - `request_params`/`query_params`/`header_params` JSONB com shape `{ name, type?, required?, example? }`
  - Pattern de backfill CLI em `server/scripts/backfillWebAppParent.ts` + doc `docs/operations/backfill-webapp-parent.md` (template para CLI de Phase 11)
  - `ensureApiTables()` em `database-init.ts` (template para novas colunas httpx se precisar guard)
  - Drizzle `db:push` + storage facade padrão (`server/storage/apis.ts`, `apiEndpoints.ts`)

### Phase 10 CONTEXT carry-forward
- `.planning/phases/10-api-credentials/10-CONTEXT.md` — decisões vivas:
  - `resolveApiCredential(apiId, endpointPath): Promise<ApiCredentialSafe | null>` — helper disponível em `server/storage/apiCredentials.ts`
  - `getApiCredentialWithSecret(id)` — **único método** que retorna secret decriptado (executor de Phase 11 é o consumidor legítimo)
  - `matchUrlPattern(url, pattern): boolean` em `server/services/credentials/matchUrlPattern.ts` — regex glob `*` (não cruza `/`)
  - `decodeJwtExp(jwt): number | undefined` em `server/services/credentials/decodeJwtExp.ts` — útil para Bearer JWT caching
  - 7 auth types: `api_key_header`, `api_key_query`, `bearer_jwt`, `basic`, `oauth2_client_credentials`, `hmac`, `mtls`
  - mTLS secret format: `JSON.stringify({ cert, key, ca? })` dentro de `secretEncrypted`; decrypt devolve string → `JSON.parse` no consumer
  - HMAC genérico (não AWS SigV4): `hmacKeyId`, `hmacAlgorithm`, `hmacSignatureHeader`, `hmacSignedHeaders text[]`, `hmacCanonicalTemplate text nullable`
  - OAuth2 token caching é responsabilidade do **Phase 11 runtime** (in-memory, `expires_in - 30s` TTL, NUNCA persistido)

### Phase 8 infra carry-forward
- `scripts/install/binaries.json` — versões/checksums pinados de katana 1.5.0, httpx 1.9.0, kiterunner 1.0.2, arjun 2.2.7
- `scripts/install/wordlists.json` — checksums de `routes-large.kite` + `arjun-extended-pt-en.txt`
- Binários instalados em `/opt/samureye/bin/{katana,httpx,kiterunner,arjun}` (ou `$PATH` após install.sh)
- Wordlists em `wordlists/routes-large.kite`, `wordlists/arjun-extended-pt-en.txt`
- Arjun roda em venv: `venv-security/bin/arjun` (pip_source install)

### Binários — docs oficiais
- https://github.com/projectdiscovery/katana — flags `-d`, `-fs`, `-jc`, `-em`, `-jsonl`, `-headless`, `-H`
- https://github.com/projectdiscovery/httpx — flags `-json`, `-tls-probe`, `-tech-detect`, `-title`, `-status-code`
- https://github.com/assetnote/kiterunner — subcomando `scan`, flag `-w`, `-x` (QPS), `-o json`
- https://github.com/s0md3v/Arjun — flags `-u`, `-oJ`, `-w`, `-m` (method), `-t` (threads)
- https://www.npmjs.com/package/@apidevtools/swagger-parser — `.parse()`, `.dereference()`, `.validate()`

### Scanner + spawn patterns
- `server/services/scanners/vulnScanner.ts` — pattern completo de spawn + streaming stdout + process tracking + timeout
- `server/services/scanners/networkScanner.ts` — pattern de nmap wrapper com cancelamento
- `server/services/journeys/nucleiPreflight.ts` — template exato de preflight memoizado per-process com auto-update fallback (adaptar: cada binário tem seu próprio preflight)
- `server/services/processTracker.ts` — integração para `registerProcess(jobId, child)` + SIGTERM graceful
- `server/services/journeyExecutor.ts` — pattern de progress callback + cancelation check via `jobQueue.isJobCancelled(jobId)`

### OpenAPI / GraphQL parsing
- `node_modules/@apidevtools/swagger-parser` — API: `SwaggerParser.parse(urlOrObj)` + `.dereference()` com `resolve: { http: boolean }` options
- GraphQL introspection query oficial: https://spec.graphql.org/October2021/#sec-Introspection

### Storage + schema
- `shared/schema.ts` linhas 1241-1299 — `apis` + `api_endpoints` tables (já populadas pelo Phase 9)
- `server/storage/apis.ts` + `server/storage/apiEndpoints.ts` — facades existentes (Phase 11 adiciona métodos de upsert em massa)
- `server/storage/database-init.ts` — `ensureApiTables` para adicionar colunas httpx via `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` se necessário
- `server/storage/apiCredentials.ts` — `resolveApiCredential`, `getApiCredentialWithSecret`
- `server/storage/interface.ts` — `IStorage` ganha novos métodos: `upsertApiEndpoints`, `markEndpointStale?`

### Route + CLI patterns
- `server/routes/apis.ts` — template de rota Phase 9 (Zod + RBAC + storage + log.info + 201)
- `server/routes/index.ts` — barrel onde registrar `registerApiDiscoveryRoutes(app)` (ou adicionar handler em `apis.ts`)
- `server/scripts/backfillApiDiscovery.ts` + `docs/operations/backfill-api-discovery.md` — template do Phase 9 para CLI + doc

### Convenções
- `.planning/codebase/CONVENTIONS.md` — naming, import order, error handling pt-BR, `createLogger('componentName')`
- `.planning/codebase/STRUCTURE.md` linhas 104-117 — estrutura `server/services/scanners/`
- `.planning/codebase/TESTING.md` — padrão Vitest + mocks

### Logging + redaction
- `server/lib/logger.ts` — pino redaction paths já cobrem `secretEncrypted`, `dekEncrypted`, `authorization` (aplicável a Phase 11)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`apis` + `api_endpoints` tables** (`shared/schema.ts:1241-1299`) — Phase 9 deixou todas as colunas que Phase 11 popula (specUrl, specHash, specVersion, specLastFetchedAt, discoverySources, requiresAuth). **Nenhuma alteração estrutural** exceto possivelmente novas colunas httpx aditivas.
- **`resolveApiCredential` + `getApiCredentialWithSecret`** (`server/storage/apiCredentials.ts` Phase 10) — entrega cred decriptada para authenticated probing.
- **`matchUrlPattern` + `decodeJwtExp`** (`server/services/credentials/`) — helpers stateless prontos.
- **`encryptionService`** (`server/services/encryption.ts`) — só consumido via `getApiCredentialWithSecret`; não precisa importar diretamente.
- **`processTracker`** (`server/services/processTracker.ts`) — registro de child processes por jobId + cancelamento cooperativo.
- **`jobQueue.isJobCancelled(jobId)`** (`server/services/jobQueue.ts`) — verificação cooperativa de cancel (padrão `journeyExecutor.ts`).
- **`nucleiPreflight.ts`** (`server/services/journeys/`) — template 1:1 para preflight dos 4 binários novos; só trocar nome do bin e templates-check.
- **`spawn` + JSONL streaming** pattern em `vulnScanner.ts` — exemplo de stdout line-split + JSON.parse por linha.
- **`createLogger('scope')`** — logger scoped com pino redaction herdada.
- **`server/scripts/backfillWebAppParent.ts`** — template de CLI standalone (`tsx --env-file=.env`, argv parse, import.meta.url guard).
- **Wordlists vendorizadas** em `wordlists/routes-large.kite` + `wordlists/arjun-extended-pt-en.txt` (Phase 8 — verificados por SHA-256).

### Established Patterns
- **Scanner per tool** em `server/services/scanners/<tool>Scanner.ts` — Phase 11 subpasta `scanners/api/` para os 6 novos (katana, httpx, kiterunner, arjun, openapi, graphql).
- **Journey orchestrator** em `server/services/journeys/<capability>.ts` — Phase 11 adiciona `apiDiscovery.ts` aqui (simetria com `nucleiPreflight.ts` e `urls.ts`).
- **spawn + processTracker + cancelation** — pattern em todos os scanners existentes.
- **Storage facade com upsert por chave natural** — `apiEndpoints.ts` ganha `upsertApiEndpoints(apiId, endpoints[]): Promise<{ inserted, updated }>` usando `ON CONFLICT (api_id, method, path)`.
- **Route registration barrel** — `registerApiDiscoveryRoutes(app)` em `server/routes/index.ts` (ou handler adicional em `apis.ts`).
- **Zod schema para `opts`** — colocar em `shared/schema.ts` (consumível pelo client se Phase 16 precisar) ou `server/services/journeys/apiDiscovery.ts` (server-only).
- **CLI pattern** `--api=<id> [--flag]` com `import.meta.url` guard (padrão `backfillApiDiscovery.ts` já existe).
- **pt-BR em mensagens, EN em código**.
- **Timeouts via AbortController** — pattern em `nucleiPreflight` + `systemUpdateService`.

### Integration Points
- **`shared/schema.ts`** — adicionar Zod `discoverApiOptsSchema` (toggles + arjunEndpointIds + overrides); possivelmente novas colunas httpx em `apiEndpoints` (aditivo).
- **`server/services/scanners/api/`** (nova subpasta) — 6 arquivos novos (katana, httpx, kiterunner, arjun, openapi, graphql).
- **`server/services/journeys/apiDiscovery.ts`** (novo) — orquestrador que importa os 6 scanners + cria DiscoveryResult.
- **`server/storage/apiEndpoints.ts`** (Phase 9) — estender com `upsertApiEndpoints`, `appendDiscoverySource`, `markEndpointsNotSeenSince?` (TBD se vira lastSeenAt).
- **`server/storage/apis.ts`** (Phase 9) — estender com `updateApiSpecMetadata(apiId, { specUrl, specVersion, specHash, specLastFetchedAt })`.
- **`server/storage/interface.ts`** — `IStorage` ganha assinaturas novas.
- **`server/storage/database-init.ts`** — se colunas httpx em `api_endpoints` são aditivas, adicionar guard em `ensureApiTables` (ou nova função `ensureApiEndpointEnrichmentColumns`).
- **`server/routes/apis.ts` ou novo `server/routes/apiDiscovery.ts`** — `POST /api/v1/apis/:id/discover` (RBAC admin+operator, body=`discoverApiOptsSchema`).
- **`server/routes/index.ts`** — registrar rota (ou acrescentar handler em apis.ts registrado).
- **`server/scripts/runApiDiscovery.ts`** (novo) — CLI operador para debug.
- **`docs/operations/run-api-discovery.md`** (novo) — doc paralela a `backfill-api-discovery.md`.
- **`server/__tests__/`** — Nyquist stubs (Wave 0): 8 testes sugeridos.

### Constraints Aplicáveis
- PROJECT.md "Schema changes must be additive" — satisfeito (colunas httpx em api_endpoints são aditivas; guards idempotentes).
- PROJECT.md "Backward compatibility" — satisfeito (nenhum write em `credentials` legada; nenhum change em executors existentes).
- SAFE-06 "Logs estruturados sem secrets" — satisfeito via pino redaction + log.info com contagens/IDs apenas.
- SAFE-01 "rate cap 10 req/s default, 50 absolute ceiling" — **Phase 11 implementa 10 QPS default em Kiterunner**; ceiling absoluto é responsabilidade do Phase 15 (não imposto aqui).
- SAFE-03 "DELETE/PUT/PATCH destructive gating" — Phase 11 é discovery-only (GET/POST para introspection/crawl). NÃO toca métodos destrutivos. Safe.
- SAFE-05 "dry-run target" — Phase 11 aceita `opts.dryRun` já pensando no `/healthz/api-test-target` que Phase 15 vai criar.

</code_context>

<specifics>
## Specific Ideas

- **"Spec-first é fonte autoritativa, crawler/brute-force são cobertura API9"** — nomenclatura que guia decisões: spec é rich (schemas, params tipados), outras fontes são reach (surface descoberta, sem schema). Dedupe preserva schemas do spec mesmo quando crawler encontra o mesmo endpoint.
- **`requiresAuth` tri-valor é sinal OWASP** — NULL significa "não probado", não "sem auth". Phase 12/13 devem respeitar (não rodar BOLA sem saber se endpoint exige auth).
- **Specs publicamente expostos = API9 sinal** — `specPubliclyExposed=true` em logs serve como evidência para Phase 12 (Nuclei API9 templates).
- **OAuth2 mint no Phase 11 não é persistido** — espelha decisão do Phase 10 (token cache in-memory, `expires_in - 30s`). Phase 15 pode centralizar cache entre stages/APIs; Phase 11 faz cache per-run.
- **`routes-large.kite` 183MB é realidade aceita** — está vendorizado como plain git object (decisão Phase 8). Kiterunner consome direto; não descomprimir.
- **Arjun opt-in de verdade** — default false mesmo quando credenciais estão disponíveis. Rodar Arjun em 100 endpoints = minutos. Só quando usuário seleciona endpoints GET específicos no wizard.
- **Phase 11 discovery ≠ Phase 12/13 testing** — Phase 11 só CRIA rows em `api_endpoints` + enriquece. Não cria `api_findings`. Logar sinais (spec public, drift, kiterunner 401s) mas deixar finding generation pra downstream.
- **Scanner-per-tool isola mocks** — tests de `katana.ts` não precisam mockar httpx; pattern facilita Nyquist sampling.
- **DiscoveryResult é contrato público** — Phase 15/16 dependem desse shape. Adicionar campos é aditivo; remover é breaking.
- **Same-origin $ref é defense-in-depth** — swagger-parser não bloqueia SSRF por default; wrapper custom valida host contra `new URL(specUrl).host` antes de dereferenciar.

</specifics>

<deferred>
## Deferred Ideas

- **Coluna `lastSeenAt` em `api_endpoints`** para marcar stale em reruns — Phase 9 não previu; se demanda real, adicionar aditivo no Phase 12 ou later.
- **SOAP WSDL discovery** — PROJECT.md menciona SOAP como `apiType` mas REQUIREMENTS/DISC só cobre OpenAPI + GraphQL. SOAP fica como `apiType='soap'` manual (Phase 9 já suporta no enum) sem discovery automático; v3.0 pode adicionar wsdl parser.
- **Auto-schedule de re-discovery** — rodar discovery em cron para detectar drift. Phase 15 orchestration decide.
- **`operationId` em `api_endpoints`** (OpenAPI field) — útil para correlação spec-to-endpoint; adicionar aditivamente se Phase 12/13 precisar.
- **Multi-version spec tracking** — histórico de `specHash` com timeline de mudanças; DISC-06 só pede detecção binária.
- **Paralelismo entre APIs em um job** (p-limit 2-3) — Phase 11 sequencial; Phase 15 pode paralelizar orquestração de journey.
- **`firstDiscoveredAt` em `api_endpoints`** — útil para drift analytics; aditivo futuro.
- **Headless Chrome via install.sh** — `opts.katana.headless=true` exige Chrome; install.sh v2.0 não garante. Phase 11 loga warn e degrada; auto-instalação fica pra AUTOUP.
- **Retry automático em stage falha** — Phase 11 skipa stage que falha. Retry com backoff poderia melhorar robustez; depois.
- **Validation que `apiType === 'rest'` vs `graphql'` no spec detectado** — se parent API tem `apiType='rest'` mas descobrimos GraphQL endpoint, atualizar ou warn? Phase 11 só adiciona; mismatch é deferred.
- **Batch discovery** — `POST /api/v1/apis/discover` (plural) para N APIs. Não requerido por DISC-*.
- **Per-tool retry quota** — Kiterunner às vezes trava em connect; retry com N=2 antes de skipar. Hoje é fail-fast.
- **Custom Nuclei templates para API9 Inventory direto do Phase 11** — se descobrir spec público + GraphQL introspection aberta, dispararia finding. Phase 12 faz isso.
- **Validação de CORS no httpx enrichment** — relevante para API8/CORS testing no Phase 12; não é do discovery.
- **Endpoint-level credential override** — hoje `credentialIdOverride` é per-API. Per-endpoint seria granular demais; rode discoveries separadas se precisar.

</deferred>

---

*Phase: 11-discovery-enrichment*
*Context gathered: 2026-04-19*
