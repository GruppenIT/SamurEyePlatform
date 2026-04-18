# Phase 9: Schema & Asset Hierarchy - Context

**Gathered:** 2026-04-18
**Status:** Ready for planning

<domain>
## Phase Boundary

Persistir o modelo de dados completo de APIs como migrações aditivas:
- `apis` (HIER-01, HIER-03) — tabela first-class sob `parentAssetId → assets.id`
- `api_endpoints` (HIER-02) — endpoints detalhados com params, schemas, auth, sources
- `api_findings` (FIND-01) — findings com categoria OWASP API Top 10 2023

Mais um script CLI de backfill (HIER-04) que probe os `web_application` assets existentes e auto-promove os que expõem indicadores de API, e um endpoint interno `POST /api/v1/apis` para registro manual.

**Fora de escopo deste phase (em outros phases):**
- Lógica de discovery/crawler/kiterunner/httpx/Arjun (Phase 11)
- Execução dos testes de segurança (Phases 12-13)
- Sanitização de evidence, promoção para `threats`, WebSocket events (Phase 14)
- Credenciais de API (Phase 10)
- Journey executor e wizard (Phases 15-16)

Phase 9 é puramente de dados: schemas + um script + um endpoint de registro.

</domain>

<decisions>
## Implementation Decisions

### Tabela `apis` (HIER-01, HIER-03)
- **`apiType` enum**: `rest`, `graphql`, `soap` — pgEnum `api_type_enum`. Cobre ROADMAP goal; SOAP inclusive mesmo sem DISC-* próprio porque aparece em integrações B2B legadas. Migration futura se faltar valor.
- **Required no registro manual**: `parentAssetId` (FK obrigatório) + `baseUrl` (text absoluto) + `apiType`. `name`, `description`, `specUrl` são opcionais e enriquecíveis por discovery.
- **Colunas de spec (criadas nulláveis no Phase 9, populadas no Phase 11)**:
  - `specHash` (text) — SHA-256 do spec para detectar drift (DISC-06)
  - `specVersion` (text) — ex: "OpenAPI 3.1.0", "GraphQL"
  - `specLastFetchedAt` (timestamp)
  - `specUrl` (text) — URL do spec descoberto/manual
  - Rationale: uma migration só para todo o ciclo de vida de APIs, evita aditiva dupla no Phase 11.
- **Uniqueness**: `UNIQUE (parent_asset_id, base_url)` — permite mesma baseUrl sob parents distintos; bloqueia duplicata sob o mesmo web_application. 409 Conflict no POST.
- **Colunas de auditoria** (convenção do projeto): `createdAt`, `createdBy` (FK → users.id), `updatedAt`.
- **Validação do parentAssetId**: registro manual deve validar que o parent é `type='web_application'` (erro 400 caso contrário). Backfill nunca cria fora dessa condição porque probes só rodam em web_applications.

### Tabela `api_endpoints` (HIER-02)
- **Params em 3 JSONBs separados**: `path_params`, `query_params`, `header_params`. Cada um é array de `{ name: string, type?: string, required?: boolean, example?: unknown }`. Facilita queries por categoria e Arjun enriquece só `query_params`.
- **`method`**: text + CHECK constraint `IN ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS')`. Evita pgEnum migration se OWASP/stdlib adicionar método no futuro.
- **`requiresAuth`**: boolean **nullable**. Semântica tri-valor explícita:
  - `NULL` — não probado ainda
  - `true` — 401/403 sem credenciais (ENRH-02 populará)
  - `false` — confirmado aberto
- **`discoverySources`**: `text[]` (array) com valores documentados em constante TS: `spec`, `crawler`, `kiterunner`, `manual`. Um endpoint pode ter múltiplas fontes concordantes. Sem pgEnum — adicionar valor (ex: `arjun`) não requer migration.
- **`requestSchema` / `responseSchema`**: 2 colunas JSONB nulláveis com sub-schema OpenAPI raw (ou equivalente GraphQL introspection). Crawler/Kiterunner deixam NULL; spec-first preenche.
- **FK**: `api_id → apis.id` obrigatório, `ON DELETE CASCADE`.
- **Uniqueness sugerida** (a confirmar no planning): `UNIQUE (api_id, method, path)` — mesmo endpoint com mesmo método é um registro só.

### Tabela `api_findings` (FIND-01)
- **Categoria OWASP**: pgEnum `owasp_api_category` com valores `api1_bola_2023`, `api2_broken_auth_2023`, `api3_bopla_2023`, `api4_rate_limit_2023`, `api5_bfla_2023`, `api6_business_flow_2023`, `api7_ssrf_2023`, `api8_misconfiguration_2023`, `api9_inventory_2023`, `api10_unsafe_consumption_2023`. Suffix `_2023` pin explicita versão OWASP — se 2027 sair, nova enum paralela (não substitui).
- **Labels pt-BR** ficam em constante TS (ex: `shared/owaspApiCategories.ts`), fora da enum.
- **`severity`**: reusa `threatSeverityEnum` existente (`low | medium | high | critical`). Zero nova enum; facilita promoção para `threats` (FIND-03 no Phase 14).
- **`riskScore`**: `real` nullable (0-100). Populado por scoringEngine quando finding for promovido; mantido NULL para findings passivos de baixa severidade.
- **`evidence`**: JSONB com shape documentado (type-safe via Zod):
  ```
  {
    request:  { method, url, headers?, bodySnippet? },
    response: { status, headers?, bodySnippet? },
    extractedValues?: Record<string, unknown>, // ex: { jwtAlg: "none", leakedKey: "sk_***" }
    context?: string // texto livre com interpretação
  }
  ```
  Campos `bodySnippet` (não `body`) deixam explícito que Phase 14 truncará para 8KB (FIND-02). Sanitização de headers/PII não é do Phase 9.
- **FKs e relacionamentos**:
  - `apiEndpointId → api_endpoints.id` — obrigatório, `ON DELETE CASCADE`.
  - `jobId → jobs.id` — nullable (manual findings não têm job).
  - `promotedThreatId → threats.id` — nullable, `ON DELETE SET NULL`. Criado **já no Phase 9**; Phase 14 popula quando promover high/critical. Evita migration dupla.
- **Campos de base**: `title`, `description`, `remediation` (text pt-BR inline — templates vêm depois se necessário), `status` (pgEnum `api_finding_status` — `open`, `triaged`, `false_positive`, `closed`), `createdAt`, `updatedAt`.
- **UI-05 `false_positive` flag**: status `false_positive` é valor da enum; integração com `auditLog` fica no Phase 16.

### Backfill `backfillApiDiscovery.ts` (HIER-04)
- **Trigger**: script CLI on-demand (`npx tsx --env-file=.env server/scripts/backfillApiDiscovery.ts [--dry-run]`). Mesmo padrão de `backfillWebAppParent.ts`. Zero impacto no boot ou no install.sh.
- **Idempotência**: só processa `assets.type='web_application'` que **não** têm API filha (JOIN + NOT EXISTS). Re-runs são safe.
- **Detecção** (qualquer sinal promove):
  1. HEAD/GET em paths conhecidos de spec — `/openapi.json`, `/swagger.json`, `/v2/api-docs`, `/v3/api-docs`, `/api-docs`, `/swagger-ui.html`, `/graphql` — se responde 200 com JSON, auto-promove com `specUrl` preenchido, `apiType` inferido (spec Swagger/OpenAPI → `rest`, `/graphql` → `graphql`).
  2. GET em `/api` — se responde 2xx com Content-Type `application/json`, promove como `rest`, sem `specUrl`.
  3. Content-Type da raiz — se `/` responde `application/json`, promove como `rest`, sem `specUrl`.
- **Promoção**: cria row em `apis` com `discoverySources` ainda NÃO existe em `apis` (só `api_endpoints`); para `apis`, registrar no log que foi "backfill". Endpoint específicos ficam para o Phase 11 descobrir.
- **False positives**: aceitáveis nessa fase — usuário pode deletar o `apis` row manualmente. Custo-benefício favorece recall.
- **Documentação**: `docs/operations/backfill-api-discovery.md` (paralelo ao existente `docs/operations/backfill-webapp-parent.md`).
- **Rate limiting**: probes respeitam timeout de 5s por request, max 10 probes concorrentes — evita castigar o alvo. Sem credentials no backfill (Phase 10 ainda não entrou).

### Registro manual `POST /api/v1/apis` (HIER-03)
- **Rota**: top-level `POST /api/v1/apis`. Espelha `/api/v1/assets`, `/api/v1/credentials` (convenção do projeto).
- **Body**: `{ parentAssetId, baseUrl, apiType, name?, description?, specUrl? }`.
- **Validação Zod**:
  - `parentAssetId`: deve existir e ter `type='web_application'`
  - `baseUrl`: URL absoluta parseável por `new URL()` (reusar `normalizeTarget` de `server/services/journeys/urls.ts`)
  - `apiType`: um dos valores do enum
- **RBAC**: `global_administrator` + `operator` (espelha `POST /api/v1/assets`).
- **Duplicatas**: `UNIQUE (parent_asset_id, base_url)` → driver retorna erro, route traduz para HTTP 409 Conflict com mensagem pt-BR clara.
- **Response**: 201 com a linha criada; não expande endpoints (endpoints são populados por discovery).
- **Logging**: `log.info({ apiId, parentAssetId, baseUrl, apiType }, 'api registered manually')`.

### Migration pattern (todas as 3 tabelas + 2 enums)
- **Drizzle `db:push`** continua sendo o mecanismo de schema sync (CONVENÇÃO do projeto, drizzle.config.ts).
- **Guard idempotente** em `server/storage/database-init.ts` — nova seção `ensureApiTables()` que:
  1. Checa `pg_tables` para `apis`, `api_endpoints`, `api_findings` — só cria se não existem (via `db.execute(sql\`CREATE TABLE IF NOT EXISTS ...\`)` ou confia no `db:push` já ter rodado).
  2. Checa `pg_indexes` para indexes expected (IDX + UNIQUE).
  3. Checa `pg_type` para pgEnums `api_type_enum`, `owasp_api_category`, `api_finding_status`.
  4. Loga status de cada check (pattern atual: `log.info({ hasXYZ }, '...')`).
- **Precedente exato**: `edr_deployments` em `database-init.ts` (Phase 7).
- **Zero down migration** — aditivo puro.

### Claude's Discretion
- Nomes exatos de colunas (snake_case DB, camelCase TS — convenção Drizzle do projeto)
- Nomes exatos dos indexes (seguir padrão `IDX_<table>_<col>`, `UQ_<table>_<col>`)
- Ordem exata das colunas nas tabelas (agrupar relacionadas, auditoria no fim)
- Estrutura final do Zod schema para body do POST (pode usar `createInsertSchema` do `drizzle-zod` ou manual)
- Organização de arquivos em `server/storage/` (uma `apis.ts` que contém apis + endpoints + findings, ou três arquivos separados — sugere-se 3 pela simetria com `threats.ts`/`assets.ts`)
- Forma final da função Storage facade (getApiById, listApisByParent, createApi, promoteApiFromBackfill, etc.)
- Módulo de constantes pt-BR do OWASP (nome do arquivo, export shape)
- Forma exata das probes no backfill (fetch com AbortController por timeout, concorrência com p-limit ou Promise.allSettled em batches)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Milestone spec
- `.planning/ROADMAP.md` §"Phase 9: Schema & Asset Hierarchy" — goal + 5 success criteria + dependências
- `.planning/REQUIREMENTS.md` §"Asset Hierarchy (HIER)" — HIER-01..HIER-04 completos
- `.planning/REQUIREMENTS.md` §"Findings & Threat Integration" (FIND-01) — shape do api_findings
- `.planning/PROJECT.md` §"Key Decisions" — linha 120: "apis as separate table (not asset_type='api')"; linha 119: v2.0 reverses "no new journey types"
- `.planning/PROJECT.md` §"Constraints" — "Schema changes must be additive"

### Schema atual e padrões existentes
- `shared/schema.ts` — fonte única de schema. Seções relevantes:
  - Linhas 34-82: todos os pgEnums (asset, journey, threat, severity) — padrão para criar novas enums
  - Linhas 107-117: `assets` table + `IDX_assets_parent` — parentAssetId self-reference
  - Linhas 240-257: `edr_deployments` table — precedente mais próximo (aditiva, FKs, índices)
  - Linhas 302-341: `threats` table — reusa `threatSeverityEnum`, `evidence` JSONB, partial unique indexes
  - Linhas 408-418: `auditLog` — integração prevista para FIND-03 e UI-05 (referência, não tocado no Phase 9)
- `drizzle.config.ts` — `db:push` é o mecanismo de sync; migrations pasta existe mas guard de idempotência é em runtime

### Padrão de migration idempotente
- `server/storage/database-init.ts` — linhas 15-50: `pg_indexes` check antes de criar índice unique; linhas 52-75: pattern repetido para segundo índice. **Exatamente esse padrão** se aplica ao `ensureApiTables()`.

### Padrão de backfill CLI
- `server/scripts/backfillWebAppParent.ts` — template completo: `--dry-run` flag, logging console, idempotência via `WHERE parent IS NULL`, zero mutação destrutiva
- `docs/operations/backfill-webapp-parent.md` — template para `docs/operations/backfill-api-discovery.md`

### Storage facade e rotas
- `server/storage/assets.ts` — padrão de storage (getAssets, getAsset, getAssetsByType, create com auto-link, update, delete). `inferParentHostForWebApp` é template para auto-promoção no backfill.
- `server/storage/interface.ts` — `IStorage` interface central que precisa ganhar métodos para APIs (ex: `getApisByParent`, `createApi`, `createApiFinding`)
- `server/storage/threats.ts` — 636 linhas, exemplo de storage facade grande (promoteToThreat, dedupe, upserts) — referência estrutural
- `server/routes/` — padrão de route (validação Zod, RBAC middleware, try/catch com log.error + mensagem pt-BR em 500)

### Convenções do projeto
- `.planning/codebase/CONVENTIONS.md` — naming (PascalCase types, camelCase vars, snake_case DB cols), import order, error handling em pt-BR, logging via `createLogger('componentName')`
- `server/services/journeys/urls.ts` — `normalizeTarget()` para normalizar URLs de entrada no POST

### OWASP API Top 10 2023 (para labels pt-BR)
- https://owasp.org/API-Security/editions/2023/en/0x11-t10/ — categorias oficiais API1..API10 com descrições e exemplos (referência para constantes TS com títulos pt-BR)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`threatSeverityEnum`** (`shared/schema.ts:52`) — reusar em `api_findings.severity` sem criar enum nova.
- **`assets.parentAssetId`** self-reference e `IDX_assets_parent` — o modelo de hierarquia já existe; `apis.parentAssetId` segue o mesmo padrão conceitual mas aponta para `assets.id` diretamente.
- **`edr_deployments` migration guard** em `database-init.ts` — template exato para `ensureApiTables()`.
- **`backfillWebAppParent.ts`** — script inteiro é o template para `backfillApiDiscovery.ts`. Até o log format e a semântica de `--dry-run` replicam.
- **`inferParentHostForWebApp()`** em `server/storage/assets.ts:72` — padrão de auto-link por URL hostname que inspira o backfill de API (probe URL-based, consulta DB, cria FK).
- **`normalizeTarget()`** em `server/services/journeys/urls.ts` — normaliza URL de entrada (adiciona porta explícita); reusar na validação Zod do POST /api/v1/apis.
- **`createLogger('storage')` e `createLogger('routes:...')`** — logging scoped com redação automática.
- **`pino` redaction paths** (`server/lib/logger.ts`) — `secretEncrypted`, `dekEncrypted`, `authorization` já são redacted; nenhum campo de `api_findings.evidence` precisa logging especial se usar `log.info({ apiId }, ...)` em vez de logar o evidence inteiro.

### Established Patterns
- **Drizzle + `shared/schema.ts` centralizada + `@shared/*` alias**: schema novo adiciona na mesma arquitetura.
- **Storage facade em `server/storage/<domain>.ts`**: sugere-se `server/storage/apis.ts`, `server/storage/apiEndpoints.ts`, `server/storage/apiFindings.ts` (um por tabela, simetria com `threats.ts`/`assets.ts`). Interface em `server/storage/interface.ts` ganha novos métodos.
- **Route registration barrel**: `server/routes/index.ts` importa e chama `register*Routes(app)`. Adicionar `server/routes/apis.ts` + `registerApiRoutes(app)`.
- **Zod validation no route + Drizzle schema**: `createInsertSchema` do `drizzle-zod` é o pattern atual (ver `shared/schema.ts` uso de Zod junto com Drizzle).
- **pt-BR em mensagens de erro, inglês em code**: `res.status(409).json({ message: "API já cadastrada para esse ativo" })`.
- **RBAC middleware** (padrão existente em routes): bloqueia antes de validar body.

### Integration Points
- **`server/storage/database-init.ts`** — adicionar `ensureApiTables()` chamado no boot (após `ensureSystemUserExists()`).
- **`server/storage/interface.ts`** — `IStorage` ganha assinaturas novas. Pattern de "inline return type" (ver nota no PROJECT.md sobre evitar circular import) aplicável se surgir cycle.
- **`server/routes/index.ts`** — registrar `registerApiRoutes(app)` junto aos outros.
- **`server/scripts/`** — nova localização para `backfillApiDiscovery.ts`, consistente com `backfillWebAppParent.ts` e `normalizeWebAppPorts.ts`.
- **`docs/operations/`** — nova doc `backfill-api-discovery.md` (paralelo ao existente).
- **`shared/owaspApiCategories.ts`** (novo arquivo) — constante com labels pt-BR + links OWASP para cada categoria. Consumido por UI (Phase 16) e por finding writers (Phase 12-13).

</code_context>

<specifics>
## Specific Ideas

- **Labels pt-BR do OWASP** ficam em constante TS separada (não na enum), permitindo i18n futura sem migration. Sugestão de shape:
  ```ts
  export const OWASP_API_CATEGORY_LABELS = {
    api1_bola_2023: { titulo: "Quebra de Autorização em Nível de Objeto", referenciaOwasp: "https://..." },
    // ...
  } as const;
  ```
- **Backfill é estritamente não-mutável para alvos externos** — apenas HTTP GET/HEAD. Nunca POST/PUT em targets de backfill. Log explícito ao probar: `log.info({ webAppId, probePath }, 'probing')`.
- **`evidence.bodySnippet`** (não `body`) deixa explícito que Phase 14 vai truncar — naming defensivo.
- **Reaproveitar `edr_deployments` como referência viva**: qualquer planner deve ler `shared/schema.ts:240-257` e `database-init.ts` para entender o padrão antes de codar.
- **Zod `createInsertSchema`** do `drizzle-zod` é o caminho preferencial para body do POST. Se precisar custom (parentAssetId cross-table validation), refinar com `.refine()`.
- **Storage facade para promotedThreatId**: a mutação vem do Phase 14, mas a coluna + FK + ON DELETE SET NULL é tudo criado agora. Zero risco.
- **Backfill não cria `api_endpoints`** — só `apis` rows. Endpoints ficam para discovery real (Phase 11). O backfill é "reconhecimento do alvo", não "descoberta profunda".

</specifics>

<deferred>
## Deferred Ideas

- **Soft-delete / archived flag em `apis`** — se surgir demanda de histórico, adicionar aditivamente; não é parte do Phase 9.
- **Tabela `api_schemas` com hash-dedup** — otimização de storage para schemas compartilhados; overkill agora.
- **`firstDiscoveredAt` / `lastSeenAt` em `api_endpoints`** — útil para drift detection; adicionar aditivamente no Phase 11 se o executor precisar.
- **Tags em `apis` (tags jsonb espelhando assets)** — não requerido por HIER; futuro nice-to-have.
- **Auto-re-run do backfill em schedule** — Phase 9 deixa só CLI; auto-schedule via cron se vira demanda real (adicionar no Phase 15 como opção de journey).
- **Multi-version spec tracking** (histórico de `specHash` com timeline) — útil mas fora de escopo; DISC-06 só pede detecção de drift binária.
- **Constraint cross-table**: `apis.parentAssetId` referencia `assets.id`, mas não há CHECK SQL para `assets.type='web_application'`. Validação é no route/service. Adicionar trigger futuro se necessário.
- **`operationId` opcional em `api_endpoints`** — aparece em OpenAPI; se o Phase 11 precisar para correlação, adicionar aditivamente.
- **Versionamento de OWASP (2027 futura)** — quando sair nova edição, nova pgEnum paralela (não substituir). Fora de escopo agora.

</deferred>

---

*Phase: 09-schema-asset-hierarchy*
*Context gathered: 2026-04-18*
