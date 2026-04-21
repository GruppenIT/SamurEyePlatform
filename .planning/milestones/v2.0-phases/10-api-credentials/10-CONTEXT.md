# Phase 10: API Credentials - Context

**Gathered:** 2026-04-19
**Status:** Ready for planning

<domain>
## Phase Boundary

Entregar o **credential store** para os 7 auth types suportados de APIs:
`api_key_header`, `api_key_query`, `bearer_jwt`, `basic`, `oauth2_client_credentials`, `hmac`, `mtls`.

Escopo do Phase 10:
- Nova tabela `api_credentials` (isolada da `credentials` legada ssh/wmi/omi/ad).
- Reuso **exclusivo** da crypto KEK/DEK existente (`server/services/encryption.ts`) — nenhuma primitiva nova.
- Mapeamento 1:1 por credencial com `urlPattern` (glob) + `priority` integer.
- Rota CRUD `POST|GET|PATCH|DELETE /api/v1/api-credentials` (reusa para criação inline no wizard).
- Storage facade `server/storage/apiCredentials.ts` + método no `IStorage` + registro em `DatabaseStorage`.
- Guard idempotente `ensureApiCredentialTables()` em `server/storage/database-init.ts`.

**Fora de escopo deste phase (outras phases):**
- Runtime de uso da credencial — quem chama encrypt/decrypt durante discovery/testing é Phase 11/12/13.
- Token caching de OAuth2 (in-memory no Phase 11).
- UI da página dedicada de API credentials e integração no wizard UI (Phase 16).
- Audit log de criação de credencial (Phase 15/16 — SAFE-04 consolida audit).
- Promoção a threats, WebSocket events (Phase 14).

Phase 10 é **backend puro**: 1 tabela + 1 facade + 1 rota + integração no `IStorage`.

</domain>

<decisions>
## Implementation Decisions

### Tabela `api_credentials` (CRED-01, CRED-02)

- **Tabela nova e isolada** — NÃO estender `credentials` existente (ssh/wmi/omi/ad). Razão: auth types de API têm shape diferente demais; risco de regressão em `getCredentials()` que hoje exclui secret*; mantém Phase 10 aditivo puro sem tocar fluxos v1.0.
- **Nova pgEnum `api_auth_type`**: `['api_key_header', 'api_key_query', 'bearer_jwt', 'basic', 'oauth2_client_credentials', 'hmac', 'mtls']` — ordem fixa para evitar renumeração OWASP-style futura.
- **Colunas comuns**:
  - `id` (varchar PK uuid) — padrão Drizzle
  - `name` (text, notNull) — label amigável no select do wizard
  - `description` (text, nullable)
  - `authType` (api_auth_type enum, notNull)
  - `urlPattern` (text, notNull, default `'*'`) — vide Área 2
  - `priority` (integer, notNull, default 100) — menor = mais prioridade (estilo CSS/nginx)
  - `apiId` (varchar, FK → `apis.id`, ON DELETE SET NULL, **nullable**) — null = credencial global por pattern
  - `secretEncrypted` (text, notNull) — AES-256-GCM via `encryptionService.encryptCredential()`
  - `dekEncrypted` (text, notNull) — DEK cifrada com KEK
  - `createdAt`, `updatedAt` (timestamp defaultNow)
  - `createdBy`, `updatedBy` (varchar FK → users.id)
- **Colunas específicas não-secretas por auth type** (nullable, validadas por Zod discriminated union no insertSchema):
  - `apiKeyHeaderName` (text) — para `api_key_header`
  - `apiKeyQueryParam` (text) — para `api_key_query`
  - `basicUsername` (text) — para `basic`
  - `bearerExpiresAt` (timestamp) — para `bearer_jwt` (backend decodifica `exp` claim no POST)
  - `oauth2ClientId` (text), `oauth2TokenUrl` (text), `oauth2Scope` (text), `oauth2Audience` (text) — para `oauth2_client_credentials`
  - `hmacKeyId` (text), `hmacAlgorithm` (text enum `HMAC-SHA1|HMAC-SHA256|HMAC-SHA512`), `hmacSignatureHeader` (text), `hmacSignedHeaders` (text[]), `hmacCanonicalTemplate` (text)
  - (mTLS não precisa de coluna adicional — cert+key+ca vão concatenados no secret, ver abaixo)
- **Indexes**:
  - `IDX_api_credentials_api_id` — lookup por API
  - `IDX_api_credentials_priority` — ordenação
  - `UQ_api_credentials_name_created_by` — nomes únicos por usuário (evita confusão no select)
- **Sem CHECK constraints cross-field** — validação de shape fica em Zod discriminated union no route; simplifica migration.

### Secret storage (CRED-02)

- **Secret sempre string única** passada para `encryptionService.encryptCredential(secret: string)` — reusa API existente sem mudança. Resultado: `{ secretEncrypted, dekEncrypted }` armazenados nas colunas.
- **Multi-part secrets (mTLS) concatenados em JSON**:
  - Body do POST aceita `mtlsCert: string`, `mtlsKey: string`, `mtlsCa?: string` (PEMs).
  - Route serializa `JSON.stringify({ cert, key, ca })` → `encryptCredential()`.
  - Ao decrypt: `JSON.parse(decryptCredential(...))` retorna objeto.
- **Mapeamento secret por auth type** (input do POST → o que vai em `secretEncrypted`):
  - `api_key_header`: o API key string cru
  - `api_key_query`: o API key string cru
  - `bearer_jwt`: o JWT completo
  - `basic`: a senha (username vai em `basicUsername`, plain)
  - `oauth2_client_credentials`: `oauth2ClientSecret` (client secret)
  - `hmac`: o `secretKey` (keyId vai em `hmacKeyId`, plain)
  - `mtls`: `JSON.stringify({ cert, key, ca? })`
- **Validação PEM (mTLS)**: Zod regex `/-----BEGIN [A-Z ]+-----[\s\S]+-----END [A-Z ]+-----/` em `mtlsCert`/`mtlsKey`/`mtlsCa` no insertSchema.
- **Response sanitization**: `getApiCredentials()` e `getApiCredential()` SEMPRE excluem `secretEncrypted`/`dekEncrypted` por padrão (espelha `getCredentials()` em `server/storage/assets.ts:180`). Existe método interno `getApiCredentialWithSecret(id)` restrito a uso do executor em Phase 11.

### URL pattern + mapping + priority (CRED-03, CRED-04)

- **1:1 na `api_credentials`** — `urlPattern` e `priority` são colunas da credencial, sem junction table. Se usuário precisa da mesma cred em 2 patterns distintos, clona a credencial. Simplicidade > flexibilidade prematura.
- **Sintaxe do pattern**: glob apenas com `*`. Exemplos válidos:
  - `*` (match all)
  - `https://api.empresa.com/*`
  - `*.prod.example.com/*`
  - `https://api.example.com/v2/admin/*`
- **Conversão pattern → regex**:
  - `*` na porção de path = `[^/?#]*` (não cruza `/`)
  - `*` na porção de host = `[^/]*`
  - `.*` só explicitamente (escape literal de `.`)
  - Implementação como helper em `server/services/credentials/matchUrlPattern.ts` (Phase 10 entrega o helper; consumidor é Phase 11).
- **Alvo do match**: URL absoluta composta `${api.baseUrl}${endpoint.path}` — sempre endpoint-level.
  - Ex: `api.baseUrl = https://api.corp.com`, `endpoint.path = /v2/users/{id}` → match target = `https://api.corp.com/v2/users/{id}`.
  - Path params (`{id}`) permanecem literais no matching (não são expandidos).
- **Algoritmo de resolução** (implementado como helper `resolveApiCredential(apiId, endpointPath): ApiCredential | null` em Phase 10; usado por Phase 11):
  1. Candidatos: `api_credentials` com `apiId === targetApiId OR apiId IS NULL` cujo `urlPattern` casa com URL alvo.
  2. Ordenar por `priority ASC` (menor número = mais prioridade).
  3. Tie-break 1: specificity — contar caracteres literais no pattern (menos `*`, mais literais = mais específico = ganha).
  4. Tie-break 2: `createdAt ASC` (mais antigo ganha — determinismo).
  5. Retorna TOP 1 ou `null`.
- **Validação do pattern no POST**: rejeitar padrões inválidos (ex: `**` seguido ambíguo; caracteres regex escapados; vazio). Regex `/^[a-zA-Z0-9:/.*?=&_\-{}~!$'()+,;%@#]+$/` como whitelist conservadora.

### Criação inline no wizard (CRED-05)

- **Mesma rota do CRUD**: `POST /api/v1/api-credentials`. Zero código duplicado; wizard chama a rota normal e recebe 201.
- **Response 201 retorna credencial sanitizada**: `{ id, name, authType, urlPattern, priority, apiId, description, createdAt, createdBy }` (sem secret*/dek*). Shape idêntico ao `GET /api/v1/api-credentials/:id` default.
  - Wizard usa para injetar no select: `{id, name, authType}` é suficiente.
- **Backend aceita todos 7 types inline** — Phase 10 não restringe. Se Phase 16 decidir esconder mTLS no wizard por UX, é decisão da UI, não do backend.
- **`apiId` sempre opcional no POST** — Phase 16 UI do wizard pré-seta `apiId` com a API corrente do step anterior, mas usuário pode deixar null.
- **Idempotência**: POST com mesmo `(name, createdBy)` retorna 409 Conflict (constraint UQ). Mensagem pt-BR: `"Credencial já cadastrada com esse nome"`.

### Auth-type specifics

- **OAuth2 client credentials**:
  - Phase 10 armazena só config + secret: `{ oauth2ClientId, oauth2ClientSecret (→ secretEncrypted), oauth2TokenUrl, oauth2Scope?, oauth2Audience? }`.
  - Token caching é responsabilidade do Phase 11 (runtime) — in-memory, `expires_in - 30s` TTL, nunca persistido.
  - Phase 10 NÃO faz chamada de teste ao token endpoint.
- **mTLS**:
  - Body do POST recebe `{ mtlsCert, mtlsKey, mtlsCa? }` como strings PEM distintas.
  - Serializa `JSON.stringify({ cert: mtlsCert, key: mtlsKey, ca: mtlsCa })` → `encryptCredential()`.
  - Validação Zod regex PEM em cada campo antes de concatenar.
  - Decrypt: `JSON.parse(decryptCredential(...))` entrega `{ cert, key, ca? }` para Phase 11 configurar `https.Agent`.
- **HMAC** genérico configurável (não hard-coded AWS SigV4):
  - Campos não-secretos: `hmacKeyId`, `hmacAlgorithm` (`HMAC-SHA1|HMAC-SHA256|HMAC-SHA512`), `hmacSignatureHeader` (default `Authorization`), `hmacSignedHeaders` (text[] de headers a assinar, ex: `['host','x-date','content-type']`), `hmacCanonicalTemplate` (text nullable — Phase 11 usa se presente, caso contrário aplica template default).
  - Secret: `hmacSecretKey` vai em `secretEncrypted`.
  - Implementação do signing é Phase 11; Phase 10 só armazena.
- **Bearer JWT**:
  - `secret` = JWT completo (em `secretEncrypted`).
  - Backend decodifica `exp` claim no POST (parse base64url, JSON.parse) e popula `bearerExpiresAt` se existir `exp`. Se decode falha, aceita mesmo assim (JWT pode ser opaco ou não-standard).
  - Phase 11 runtime alerta/skipa se `bearerExpiresAt < now()`; não refresca automaticamente.
- **Basic auth**:
  - `basicUsername` plain em coluna (não é secret).
  - Password em `secretEncrypted`.
  - Phase 11 monta `Basic ${base64(username:password)}` em runtime.
- **api_key_header / api_key_query**:
  - `apiKeyHeaderName` (ex: `X-API-Key`) ou `apiKeyQueryParam` (ex: `api_key`) em coluna plain.
  - Valor do API key em `secretEncrypted`.

### Migration pattern

- **Drizzle `db:push`** para sync de schema (convenção do projeto).
- **Guard idempotente** em `server/storage/database-init.ts` → nova função `ensureApiCredentialTables()`:
  1. Checa `pg_type` para enum `api_auth_type` (cria se ausente).
  2. Checa `pg_tables` para `api_credentials` (cria via `CREATE TABLE IF NOT EXISTS` se ausente).
  3. Checa `pg_indexes` para cada index esperado (cria se ausente via loop, seguindo padrão do Phase 9 `ensureApiTables`).
- **Invocada no boot após `ensureApiTables()`** (sequência: assets → apis → api_credentials).
- **Precedente exato**: `ensureApiTables()` criado em Phase 9 (`server/storage/database-init.ts`).

### Storage facade

- **Arquivo**: `server/storage/apiCredentials.ts` (simetria com `apis.ts`, `apiEndpoints.ts`, `apiFindings.ts` do Phase 9).
- **Namespace import**: `import * as apiCredOps from "./apiCredentials"` em `server/storage/index.ts`, membros da `DatabaseStorage`.
- **Métodos expostos**:
  - `listApiCredentials(filter?: { apiId?: string; authType?: ApiAuthType }): Promise<ApiCredentialSafe[]>` — sanitizado (sem secret*)
  - `getApiCredential(id): Promise<ApiCredentialSafe | undefined>` — sanitizado
  - `getApiCredentialWithSecret(id): Promise<ApiCredentialWithSecret | undefined>` — **interno**, usado só pelo executor (Phase 11+)
  - `createApiCredential(input: InsertApiCredential, userId): Promise<ApiCredentialSafe>` — encrypta secret via `encryptionService.encryptCredential()`
  - `updateApiCredential(id, patch, userId): Promise<ApiCredentialSafe>` — re-encrypta se patch inclui secret
  - `deleteApiCredential(id): Promise<void>`
  - `resolveApiCredential(apiId: string, endpointPath: string): Promise<ApiCredentialSafe | null>` — helper de resolução (algoritmo acima)

### Route `POST|GET|PATCH|DELETE /api/v1/api-credentials`

- **Arquivo**: `server/routes/apiCredentials.ts` + export `registerApiCredentialsRoutes(app)`.
- **Registro**: `server/routes/index.ts` chama `registerApiCredentialsRoutes(app)` junto aos outros.
- **RBAC**: `global_administrator` + `operator` (mesmo nível de `POST /api/v1/apis` Phase 9).
- **Endpoints**:
  - `POST /api/v1/api-credentials` → 201 com `ApiCredentialSafe`; 409 se nome duplicado.
  - `GET /api/v1/api-credentials` → lista sanitizada, filtros opcionais `?apiId=`, `?authType=`.
  - `GET /api/v1/api-credentials/:id` → 200 sanitizado; 404 se não existe.
  - `PATCH /api/v1/api-credentials/:id` → 200 sanitizado; valida Zod partial.
  - `DELETE /api/v1/api-credentials/:id` → 204.
- **Validação Zod discriminated union** por `authType` — cada variante exige seus campos específicos e rejeita extras. Base schema via `createInsertSchema` + `.omit` + `.extend` com discriminated.
- **Mensagens pt-BR** em erros (padrão do projeto).
- **Logging**: `log.info({ apiCredentialId, authType, apiId }, 'api credential created')` — nunca logar secret, nome, pattern detalhado (já redacted via pino path `secretEncrypted`, `dekEncrypted`).

### Zod schema shape

Esboço (planner refina):

```ts
// shared/schema.ts
export const apiAuthTypeEnum = pgEnum('api_auth_type', [...]);

const baseInsertApiCredentialSchema = createInsertSchema(apiCredentials).omit({
  id: true, secretEncrypted: true, dekEncrypted: true,
  createdAt: true, updatedAt: true, createdBy: true, updatedBy: true,
  bearerExpiresAt: true, // derivado do JWT
});

export const insertApiCredentialSchema = z.discriminatedUnion("authType", [
  baseInsertApiCredentialSchema.extend({
    authType: z.literal("api_key_header"),
    apiKeyHeaderName: z.string().min(1),
    secret: z.string().min(1), // API key
  }),
  // ... 6 outras variantes
  baseInsertApiCredentialSchema.extend({
    authType: z.literal("mtls"),
    mtlsCert: z.string().regex(/-----BEGIN [A-Z ]+-----[\s\S]+-----END [A-Z ]+-----/),
    mtlsKey: z.string().regex(/-----BEGIN [A-Z ]+-----[\s\S]+-----END [A-Z ]+-----/),
    mtlsCa: z.string().regex(/.../).optional(),
  }),
]);
```

### Claude's Discretion

- Nomes exatos de colunas (snake_case DB, camelCase TS — Drizzle convention)
- Ordem de colunas na tabela (agrupar: comuns → per-type → auditoria)
- Nomes exatos dos indexes (padrão `IDX_api_credentials_<col>`, `UQ_api_credentials_<cols>`)
- Estrutura final do Zod discriminated union (planner pode refinar shape)
- Separação de arquivos: `server/services/credentials/` vs `server/lib/credentials/` para helpers (`matchUrlPattern`, `resolveApiCredential`, `decodeJwtExp`)
- Mensagens exatas pt-BR de erro
- Cobertura de testes Nyquist (Wave 0 no plan): sugestão de 7 testes — insertSchema discriminated union, encryption round-trip, pattern matching, priority resolution, guard idempotency, route RBAC, inline wizard response shape

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Milestone spec
- `.planning/ROADMAP.md` §"Phase 10: API Credentials" (linhas 86-101) — goal + 5 success criteria + dependências
- `.planning/REQUIREMENTS.md` §"API Credentials (CRED)" (linhas 17-23) — CRED-01..CRED-05 completos
- `.planning/REQUIREMENTS.md` §"Segurança (SAFE)" (linhas 67-72) — SAFE-04 (audit log de credential IDs), SAFE-06 (logs estruturados sem secrets) afetam route/logging
- `.planning/PROJECT.md` §"Constraints" — "Schema changes must be additive", "Backward compatibility: Existing journey definitions and credentials must continue working"

### Phase 9 CONTEXT carry-forward
- `.planning/phases/09-schema-asset-hierarchy/09-CONTEXT.md` — decisões vivas:
  - Drizzle `db:push` + `database-init.ts` guard (`ensureApiTables` → template pra `ensureApiCredentialTables`)
  - Storage facade `server/storage/<domain>.ts` + `IStorage` + `DatabaseStorage`
  - Route `registerXxxRoutes(app)` + barrel `server/routes/index.ts`
  - RBAC `global_administrator + operator`
  - Zod `createInsertSchema` do drizzle-zod
  - `UNIQUE` constraint → 409 Conflict no route
  - Mensagens pt-BR, código EN
  - pino redaction `secretEncrypted`, `dekEncrypted`, `authorization` (já cobre api_credentials)

### Crypto e secrets
- `server/services/encryption.ts` — `encryptionService.encryptCredential(secret: string)` / `decryptCredential(secretEncrypted, dekEncrypted)`. **REUSAR SEM MUDANÇA**. AES-256-GCM, KEK do `ENCRYPTION_KEK` env var, DEK random por credencial.
- `server/lib/logger.ts` — pino redaction paths já cobrem `secretEncrypted`, `dekEncrypted`, `authorization`.

### Schema atual (templates)
- `shared/schema.ts` linhas 38: `credentialTypeEnum` — template de pgEnum (usa `_2023` suffix? não aqui, mas segue padrão de criar nova enum)
- `shared/schema.ts` linhas 147-159: tabela `credentials` — shape de referência (tem `secretEncrypted`, `dekEncrypted`, FK `createdBy`, indexes implícitos)
- `shared/schema.ts` linhas 180-190: `journey_credentials` junction table com `priority` int — padrão para priority column (default 1, notNull)
- `shared/schema.ts` linhas 877-884: `insertCredentialSchema` — template de `omit({ secretEncrypted, dekEncrypted })` + `.extend({ secret: z.string() })`

### Storage facade (template)
- `server/storage/assets.ts` linhas 180-210 — `getCredentials()` com explicit field list que exclui secret*/dek*. **Padrão exato a espelhar** para `listApiCredentials()`.
- `server/storage/index.ts` — `DatabaseStorage` class com namespace imports por domain.
- `server/storage/interface.ts` — `IStorage` interface onde adicionar método signatures.
- `server/storage/apis.ts` (Phase 9) — facade mais recente como template de organização (header, imports, funções exportadas).

### Route pattern
- Phase 9 `server/routes/apis.ts` — template mais próximo. Padrão: Zod parse → cross-DB validation → storage call → audit log → 201.
- `server/routes/index.ts` — barrel onde registrar `registerApiCredentialsRoutes(app)`.

### Database guard pattern
- `server/storage/database-init.ts` — `ensureApiTables()` (Phase 9) é o precedente direto. Checa `pg_type` enum, `pg_tables`, `pg_indexes` com quoted identifiers via `sql.raw()` para identifier dinâmico.

### Convenções do projeto
- `.planning/codebase/CONVENTIONS.md` — naming, import order, error handling pt-BR, logging `createLogger('componentName')`.
- `.planning/codebase/ARCHITECTURE.md` linhas 142-146 — **"Credential Encryption"**: DEK/KEK pattern documentado, AES-256-GCM.
- `.planning/codebase/STRUCTURE.md` linhas 140-155 — organização de `server/storage/`, `server/routes/`, `server/services/`.

### RBAC e middleware
- Rotas existentes em `server/routes/` — padrão de `requireAdmin` / `requireOperator` middlewares (ver uso em `/api/v1/credentials` ssh/wmi).
- `server/routes/apis.ts` (Phase 9) — RBAC de referência.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`encryptionService`** em `server/services/encryption.ts` — API pronta: `encryptCredential(secret: string)` / `decryptCredential(secretEncrypted, dekEncrypted)`. Zero mudança. Suficiente para CRED-02 sem nova crypto.
- **`credentialTypeEnum`** em `shared/schema.ts:38` — precedente de pgEnum de tipo de credencial. Nova enum `api_auth_type` segue exato mesmo padrão (não reusa — tipos diferentes).
- **`credentials` table** (`shared/schema.ts:147-159`) — template estrutural. `api_credentials` copia: `secretEncrypted`, `dekEncrypted`, `createdBy` FK, `createdAt defaultNow`.
- **`journey_credentials.priority integer default 1 notNull`** (`shared/schema.ts:185`) — padrão exato para nossa coluna `priority` (usar default 100 em vez de 1 pra dar espaço de manobra).
- **`getCredentials()` em `server/storage/assets.ts:180`** — padrão canônico de "list com explicit field list excluindo secret*". Copiar assinatura para `listApiCredentials()`.
- **`insertCredentialSchema` em `shared/schema.ts:877-884`** — template de `createInsertSchema().omit({ secret*, dek* }).extend({ secret: z.string() })`. Nosso `insertApiCredentialSchema` segue a mesma forma mas com discriminated union.
- **`ensureApiTables()` em `server/storage/database-init.ts`** (Phase 9) — template idêntico para `ensureApiCredentialTables()`.
- **`server/storage/apis.ts`** (Phase 9) — facade-pattern mais recente, estrutura ideal.
- **`server/routes/apis.ts`** (Phase 9) — route-pattern mais recente: Zod parse + RBAC + storage call + log.info + 201.
- **pino redaction** (`server/lib/logger.ts`) — redaction paths já incluem `secretEncrypted`, `dekEncrypted`, `authorization` — nenhuma configuração nova necessária.

### Established Patterns
- **Drizzle + `shared/schema.ts` centralizada + `@shared/*` alias** — schema novo entra no mesmo arquivo, seção nova.
- **Facade por domain em `server/storage/<domain>.ts`** — `apiCredentials.ts` simétrico com `apis.ts`/`apiEndpoints.ts`/`apiFindings.ts` do Phase 9.
- **Route registration barrel** em `server/routes/index.ts` — `registerApiCredentialsRoutes(app)` entra junto aos outros.
- **Zod discriminated union** — usado em outras partes do schema? Ver `shared/schema.ts` attack surface params / notification schema — padrão existe.
- **pt-BR em mensagens, EN em código** — `res.status(409).json({ message: "Credencial já cadastrada com esse nome" })`.
- **RBAC middleware** — `requireAdmin`/`requireOperator` antes da validação do body.
- **Secret separation** — storage retorna shape safe por default; método com secret só para uso interno do executor.

### Integration Points
- **`shared/schema.ts`** — adicionar: `apiAuthTypeEnum`, `apiCredentials` pgTable, `apiCredentialsRelations` (many-to-one com `apis` e `users`), `insertApiCredentialSchema` (discriminated union), types `ApiCredential`, `ApiCredentialSafe`, `ApiCredentialWithSecret`.
- **`server/storage/database-init.ts`** — nova função `ensureApiCredentialTables()` chamada após `ensureApiTables()`.
- **`server/storage/apiCredentials.ts`** — novo arquivo facade (8 funções).
- **`server/storage/interface.ts`** — `IStorage` ganha 7 assinaturas (list, get, getWithSecret, create, update, delete, resolve).
- **`server/storage/index.ts`** — `DatabaseStorage` wira namespace import.
- **`server/routes/apiCredentials.ts`** — novo arquivo de rota.
- **`server/routes/index.ts`** — registrar `registerApiCredentialsRoutes(app)`.
- **`server/services/credentials/`** (nova pasta sugerida) — helpers: `matchUrlPattern.ts`, `decodeJwtExp.ts`. `resolveApiCredential` pode ficar em `server/storage/apiCredentials.ts` porque faz query.
- **`shared/__tests__/`** — Nyquist test stubs (Wave 0): 7 testes (enum, discriminated union, encryption roundtrip, pattern match, priority resolution, guard idempotency, route RBAC).

### Constraints Aplicáveis
- PROJECT.md "Schema changes must be additive" — satisfeito (tabela nova, zero alter em tabela existente).
- PROJECT.md "Backward compatibility: Existing journey definitions and credentials must continue working" — satisfeito (zero toque em `credentials` legada).
- SAFE-06 "Logs estruturados sem secrets" — satisfeito (pino redaction já cobre + logger usa `{ apiCredentialId, authType }` em vez de objeto cred inteiro).
- SAFE-04 "audit_log com credential IDs (nunca secrets)" — Phase 10 loga via `log.info`; integração formal com `auditLog` table é Phase 15 (SAFE-04 consolidado lá).

</code_context>

<specifics>
## Specific Ideas

- **Secret unificado via JSON para mTLS** — `JSON.stringify({ cert, key, ca })` antes de `encryptCredential()`. Reuso total da API de crypto. No decrypt, `JSON.parse`. Naming: o método retorna sempre string, consumidor decide se parseia.
- **Priority "menor = mais" (CSS/nginx)** — documentar no helper e no insertSchema `.describe()`. Default 100 deixa espaço pra 50/25 mais prioritárias e 200/500 menos.
- **`bearerExpiresAt` backend-derived** — parse `exp` do JWT payload no POST. Se decode falha (JWT opaco), aceitar sem `bearerExpiresAt`. Não retornar erro.
- **HMAC genérico sem profiles hard-coded** — planner NÃO deve criar enum de profiles (AWS, Azure, Hawk). Campos livres cobrem tudo; runtime (Phase 11) interpreta.
- **OAuth2 token NUNCA persistido** — token cache é in-memory no Phase 11. Mesmo Redis-like seria overkill pro single-appliance.
- **Nome único por usuário (não global)** — `UQ(name, createdBy)` permite que 2 operadores criem `"Stripe API"` independentemente. Se quiser singleton global, usuário usa nome distinto.
- **Validação de pattern no POST, não no runtime** — se pattern é inválido, 400 Bad Request no POST. Runtime confia que o pattern armazenado é válido.
- **`api_credentials.apiId → apis.id ON DELETE SET NULL`** — deletar API não deleta credenciais (ficam globais). Deletar API é intencional; credenciais podem ter reuso pra novas APIs similares.

</specifics>

<deferred>
## Deferred Ideas

- **Audit log formal de operações CRUD de credencial** — Phase 10 usa `log.info` simples. Integração com tabela `auditLog` consolida em Phase 15 (SAFE-04).
- **Connection test endpoint** (`POST /api/v1/api-credentials/:id/test`) — valida que a credencial realmente autentica contra target. Útil pro UX mas requer runtime HTTP. Phase 11 ou Phase 16.
- **OAuth2 refresh_token flow** (auth_code, pkce) — Phase 10 só suporta `oauth2_client_credentials`. Se futuro precisar, nova variante no enum.
- **Credential rotation / versioning** — manter histórico de secrets, forçar rotação periódica. Overkill agora.
- **Tags em `api_credentials`** — análogo a assets. Nice-to-have; adicionar aditivamente se UX pedir.
- **Soft-delete / archived flag** — se precisar preservar histórico, adicionar aditivamente.
- **Cred multi-tenant isolation via organization** — hoje só `createdBy` FK; se v3.0 trouxer tenants, escopo expande.
- **KEK rotation** — `encryptCredential` usa KEK do env; rotação requer re-encrypt de todos DEKs. Fora de escopo; ADR futuro.
- **Batch POST** — `POST /api/v1/api-credentials:batch` pra criar múltiplas de uma vez. Não requerido por CRED-*.
- **Per-credential ACL (quem pode ver/usar)** — hoje RBAC no nível da rota. Restrição por credencial específica é feature maior.
- **HMAC profiles pré-definidos** (AWS SigV4, Azure Shared Key, Hawk) — se UX do Phase 16 pedir wizard guiado por profile, adicionar enum `hmac_profile` opcional que popula os 5 campos genéricos automaticamente.
- **Multi-credential fallback (tenta #1, se 401 tenta #2)** — rotation automático. Runtime concern (Phase 11).
- **Multi-pattern por credencial** (junction table `api_credential_mappings`) — hoje 1:1. Se demanda real surgir, add aditivamente.
- **Regex nos patterns** (power user) — glob é suficiente. Regex pode ser adicionado via flag `patternType` futuro.

</deferred>

---

*Phase: 10-api-credentials*
*Context gathered: 2026-04-19*
