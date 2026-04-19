# Phase 10: API Credentials - Research

**Pesquisado em:** 2026-04-19
**Domínio:** Credential store para 7 auth types de API — backend puro (tabela + facade + rota)
**Confiança geral:** HIGH

---

<user_constraints>
## Restrições do Usuário (de CONTEXT.md)

### Decisões Bloqueadas

- **Tabela `api_credentials` nova e isolada** — NÃO estender `credentials` existente (ssh/wmi/omi/ad)
- **Nova pgEnum `api_auth_type`** com 7 valores fixos: `api_key_header`, `api_key_query`, `bearer_jwt`, `basic`, `oauth2_client_credentials`, `hmac`, `mtls`
- **Crypto reutilizada sem mudança**: `encryptionService.encryptCredential(secret: string)` / `decryptCredential(secretEncrypted, dekEncrypted)` — zero nova primitiva
- **Mapeamento 1:1**: `urlPattern` (glob) + `priority` (integer) como colunas da própria credencial (sem junction table)
- **`db:push` + guard idempotente `ensureApiCredentialTables()`** em `server/storage/database-init.ts`, chamada após `ensureApiTables()`, seguindo padrão exato do Phase 9
- **Rota CRUD**: `POST|GET|PATCH|DELETE /api/v1/api-credentials` — mesma rota usada para criação inline no wizard (CRED-05)
- **RBAC**: `global_administrator + operator` (mesmo nível de `POST /api/v1/apis` do Phase 9)
- **Secret multi-part para mTLS**: `JSON.stringify({ cert, key, ca? })` antes de `encryptCredential()`
- **Sanitização default**: `listApiCredentials()` e `getApiCredential()` SEMPRE excluem `secretEncrypted`/`dekEncrypted`; método interno `getApiCredentialWithSecret(id)` reservado para executor (Phase 11+)
- **409 Conflict** em nome duplicado `(name, createdBy)` com mensagem pt-BR: `"Credencial já cadastrada com esse nome"`
- **Priority "menor número = mais prioridade"** (padrão CSS/nginx), default 100
- **`bearerExpiresAt` derivado no backend**: parse base64url do JWT `exp` claim no POST; se falhar, aceita sem erro
- **HMAC genérico sem profiles hard-coded** — campos livres; Phase 11 interpreta
- **OAuth2 token NUNCA persistido** — cache in-memory é responsabilidade do Phase 11
- **`apiId ON DELETE SET NULL` (nullable)** — deletar API não deleta credenciais
- **Mensagens de erro em pt-BR, código em EN** (padrão do projeto)
- **Logs nunca incluem secret** — pino redaction já cobre `secretEncrypted`, `dekEncrypted`

### Área de Discrição do Claude

- Nomes exatos de colunas (snake_case DB, camelCase TS — Drizzle convention)
- Ordem de colunas na tabela (agrupar: comuns → por-tipo → auditoria)
- Nomes exatos dos indexes (padrão `IDX_api_credentials_<col>`, `UQ_api_credentials_<cols>`)
- Estrutura final do Zod discriminated union (planner pode refinar shape)
- Separação de arquivos: `server/services/credentials/` vs inline em `server/storage/apiCredentials.ts` para helpers (`matchUrlPattern`, `decodeJwtExp`)
- Mensagens exatas pt-BR de erro
- Cobertura de testes Nyquist (Wave 0): sugestão de 7 testes

### Ideias Adiadas (FORA DO ESCOPO)

- Audit log formal com tabela `audit_log` — Phase 10 usa apenas `log.info`; integração em Phase 15 (SAFE-04)
- Endpoint de teste de conexão `POST /api/v1/api-credentials/:id/test`
- OAuth2 refresh_token flow (auth_code, pkce)
- Credential rotation / versioning
- Tags em `api_credentials`
- Soft-delete / archived flag
- Cred multi-tenant via organization
- KEK rotation
- Batch POST
- Per-credential ACL
- HMAC profiles pré-definidos (AWS SigV4, Azure Shared Key, Hawk)
- Multi-credential fallback automático (tenta #1, se 401 tenta #2)
- Multi-pattern por credencial (junction table)
- Regex nos patterns (power user)
</user_constraints>

---

<phase_requirements>
## Requisitos do Phase

| ID | Descrição | Suporte da Pesquisa |
|----|-----------|---------------------|
| CRED-01 | Usuário pode armazenar credenciais de API com os 7 auth types | Tabela `api_credentials` com `api_auth_type` pgEnum; discriminated union Zod valida shape por tipo |
| CRED-02 | Sistema criptografa credenciais reutilizando o padrão KEK/DEK existente (sem nova lógica crypto) | `encryptionService.encryptCredential(secret: string)` em `server/services/encryption.ts` — API verificada, zero mudança necessária |
| CRED-03 | Usuário mapeia cada credencial a um URL pattern (glob/prefix) para o engine aplicar somente nos endpoints correspondentes | `urlPattern` coluna text na tabela; helper `matchUrlPattern.ts` com conversão glob → regex; algoritmo de resolução documentado |
| CRED-04 | Usuário pode priorizar credenciais quando múltiplas casam com o mesmo URL | Coluna `priority integer` (menor = mais prioridade); algoritmo de tie-break: priority ASC → specificity → createdAt ASC |
| CRED-05 | Usuário pode criar credencial inline durante o wizard de jornada | Mesma rota `POST /api/v1/api-credentials`; resposta 201 retorna shape `ApiCredentialSafe` imediatamente disponível para o select do wizard |
</phase_requirements>

---

## Resumo

O Phase 10 é **backend puro**: uma tabela nova `api_credentials`, um facade em `server/storage/apiCredentials.ts`, uma rota em `server/routes/apiCredentials.ts`, e integração no guard de inicialização `database-init.ts`. Todos os padrões já existem no codebase — o Phase 9 entregou os templates exatos que este phase deve seguir.

A crypto está pronta e não muda: `encryptionService.encryptCredential(secret: string)` retorna `{ secretEncrypted, dekEncrypted }` que vão para as colunas da tabela. O pino redaction já cobre ambas as colunas. Não há nenhum novo serviço de criptografia a construir.

O diferencial arquitetural deste phase em relação aos anteriores é o **Zod discriminated union** — 7 variantes, cada uma exigindo campos específicos e rejeitando extras. A resolução de credencial por URL pattern e priority também precisa de um helper dedicado (`matchUrlPattern.ts` + algoritmo de resolução), mas esses helpers são produzidos aqui e apenas **consumidos** no Phase 11 (runtime).

**Recomendação primária:** Seguir o template `server/storage/apis.ts` (Phase 9) para o facade e `server/routes/apis.ts` para a rota. O guard `ensureApiCredentialTables()` é clone direto de `ensureApiTables()`. Criar Wave 0 com 7 `it.todo` stubs antes de qualquer implementação.

---

## Stack Padrão

### Core (verificado no codebase)

| Biblioteca | Versão verificada | Papel | Por que padrão no projeto |
|------------|-------------------|-------|---------------------------|
| `drizzle-orm` | já instalada (Phase 9 usou) | ORM + query builder | Convenção estabelecida do projeto — `shared/schema.ts` centralizado |
| `drizzle-zod` | já instalada | `createInsertSchema()` | Padrão de todos os schemas de inserção do projeto |
| `zod` | já instalada | Validação discriminated union | `z.discriminatedUnion()` — usado em notificationPolicy, adSecurityParams |
| `node:crypto` | built-in Node.js | AES-256-GCM via `EncryptionService` | Zero nova dependência — reuso de `server/services/encryption.ts` |
| `pino` | já instalada | Logging estruturado com redaction | Padrão SAFE-06; redaction paths já cobrem `secretEncrypted`, `dekEncrypted` |

### Suporte

| Biblioteca | Papel | Quando usar |
|------------|-------|-------------|
| `express` | HTTP routing | `registerApiCredentialsRoutes(app: Express)` |
| `drizzle-orm/pg-core` | `pgEnum`, `pgTable`, `text`, `integer`, `timestamp`, `varchar` | Definição do schema |

### Alternativas consideradas

| Padrão adotado | Alternativa | Tradeoff |
|---------------|-------------|----------|
| Glob com conversão para regex | Regex direto no pattern | Glob é mais seguro para input do usuário; regex abre surface de ReDoS |
| 1:1 urlPattern na credencial | Junction table `api_credential_mappings` | Simplicidade; multi-pattern pode ser adicionado aditivamente se demanda surgir |
| `JSON.stringify` para mTLS multi-part | Colunas separadas para cert/key/ca | Reuso total da API `encryptCredential(string)` sem nenhuma mudança |

### Instalação

Nenhum novo pacote necessário. Todos os pacotes já estão instalados.

---

## Padrões de Arquitetura

### Estrutura de Arquivos a Criar

```
shared/
└── schema.ts                           # MODIFICAR — adicionar apiAuthTypeEnum, apiCredentials table,
                                        # apiCredentialsRelations, insertApiCredentialSchema,
                                        # tipos ApiCredential, ApiCredentialSafe, ApiCredentialWithSecret

server/
├── storage/
│   ├── database-init.ts                # MODIFICAR — adicionar ensureApiCredentialTables()
│   ├── apiCredentials.ts               # CRIAR — facade com 8 funções
│   ├── interface.ts                    # MODIFICAR — IStorage ganha 7 assinaturas
│   └── index.ts                        # MODIFICAR — DatabaseStorage wira import
├── routes/
│   ├── apiCredentials.ts               # CRIAR — 5 endpoints CRUD
│   └── index.ts                        # MODIFICAR — registerApiCredentialsRoutes(app)
└── services/
    └── credentials/
        ├── matchUrlPattern.ts          # CRIAR — helper glob → regex + match
        └── decodeJwtExp.ts             # CRIAR — parse base64url do exp claim

shared/
└── __tests__/
    └── apiCredentialSchema.test.ts     # CRIAR — Wave 0 stubs (Nyquist)

server/
└── __tests__/
    ├── ensureApiCredentialTables.test.ts  # CRIAR — Wave 0 stubs
    ├── apiCredentialsRoute.test.ts        # CRIAR — Wave 0 stubs
    ├── matchUrlPattern.test.ts            # CRIAR — Wave 0 stubs
    └── apiCredentialStorage.test.ts       # CRIAR — Wave 0 stubs
```

### Padrão 1: pgEnum + pgTable em `shared/schema.ts`

**O que:** Declarar `apiAuthTypeEnum` como nova pgEnum (não reutilizar `credentialTypeEnum`), seguido da tabela `apiCredentials`.

**Quando usar:** Sempre que um novo tipo discriminador de domínio precisa ser persistido.

**Exemplo (baseado no padrão existente — `shared/schema.ts:38` e `:147`):**
```typescript
// Fonte: shared/schema.ts, linhas 38 e 147 — padrão verificado
export const apiAuthTypeEnum = pgEnum('api_auth_type', [
  'api_key_header',
  'api_key_query',
  'bearer_jwt',
  'basic',
  'oauth2_client_credentials',
  'hmac',
  'mtls',
]);

export const apiCredentials = pgTable('api_credentials', {
  // --- identidade ---
  id: varchar('id').primaryKey().default(sql`gen_random_uuid()`),
  name: text('name').notNull(),
  description: text('description'),
  authType: apiAuthTypeEnum('auth_type').notNull(),

  // --- mapeamento ---
  urlPattern: text('url_pattern').notNull().default('*'),
  priority: integer('priority').notNull().default(100),
  apiId: varchar('api_id').references(() => apis.id, { onDelete: 'set null' }),

  // --- crypto ---
  secretEncrypted: text('secret_encrypted').notNull(),
  dekEncrypted: text('dek_encrypted').notNull(),

  // --- campos por auth type (nullable, validados por Zod) ---
  apiKeyHeaderName: text('api_key_header_name'),
  apiKeyQueryParam: text('api_key_query_param'),
  basicUsername: text('basic_username'),
  bearerExpiresAt: timestamp('bearer_expires_at'),
  oauth2ClientId: text('oauth2_client_id'),
  oauth2TokenUrl: text('oauth2_token_url'),
  oauth2Scope: text('oauth2_scope'),
  oauth2Audience: text('oauth2_audience'),
  hmacKeyId: text('hmac_key_id'),
  hmacAlgorithm: text('hmac_algorithm'), // HMAC-SHA1 | HMAC-SHA256 | HMAC-SHA512
  hmacSignatureHeader: text('hmac_signature_header'),
  hmacSignedHeaders: text('hmac_signed_headers').array(),
  hmacCanonicalTemplate: text('hmac_canonical_template'),

  // --- auditoria ---
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
  createdBy: varchar('created_by').references(() => users.id).notNull(),
  updatedBy: varchar('updated_by').references(() => users.id),
}, (table) => [
  index('IDX_api_credentials_api_id').on(table.apiId),
  index('IDX_api_credentials_priority').on(table.priority),
  uniqueIndex('UQ_api_credentials_name_created_by').on(table.name, table.createdBy),
]);
```

### Padrão 2: Zod discriminated union para `insertApiCredentialSchema`

**O que:** Um schema Zod que aceita exatamente os campos necessários para cada `authType` e rejeita campos de outros tipos.

**Quando usar:** POST e PATCH da rota de credenciais.

**Exemplo (baseado em `shared/schema.ts:876-884` — padrão verificado):**
```typescript
// Fonte: shared/schema.ts:876 — padrão insertCredentialSchema
const baseInsert = createInsertSchema(apiCredentials).omit({
  id: true,
  secretEncrypted: true,
  dekEncrypted: true,
  createdAt: true,
  updatedAt: true,
  createdBy: true,
  updatedBy: true,
  bearerExpiresAt: true, // derivado do JWT exp no backend
});

export const insertApiCredentialSchema = z.discriminatedUnion('authType', [
  baseInsert.extend({
    authType: z.literal('api_key_header'),
    apiKeyHeaderName: z.string().min(1, "Nome do header é obrigatório"),
    secret: z.string().min(1, "API key é obrigatória"),
  }),
  baseInsert.extend({
    authType: z.literal('api_key_query'),
    apiKeyQueryParam: z.string().min(1, "Parâmetro de query é obrigatório"),
    secret: z.string().min(1, "API key é obrigatória"),
  }),
  baseInsert.extend({
    authType: z.literal('bearer_jwt'),
    secret: z.string().min(1, "JWT é obrigatório"),
  }),
  baseInsert.extend({
    authType: z.literal('basic'),
    basicUsername: z.string().min(1, "Username é obrigatório"),
    secret: z.string().min(1, "Senha é obrigatória"),
  }),
  baseInsert.extend({
    authType: z.literal('oauth2_client_credentials'),
    oauth2ClientId: z.string().min(1, "Client ID é obrigatório"),
    oauth2TokenUrl: z.string().url("Token URL inválida"),
    oauth2Scope: z.string().optional(),
    oauth2Audience: z.string().optional(),
    secret: z.string().min(1, "Client secret é obrigatório"),
  }),
  baseInsert.extend({
    authType: z.literal('hmac'),
    hmacKeyId: z.string().min(1, "Key ID é obrigatório"),
    hmacAlgorithm: z.enum(['HMAC-SHA1', 'HMAC-SHA256', 'HMAC-SHA512']),
    hmacSignatureHeader: z.string().default('Authorization'),
    hmacSignedHeaders: z.array(z.string()).default([]),
    hmacCanonicalTemplate: z.string().optional(),
    secret: z.string().min(1, "HMAC secret key é obrigatória"),
  }),
  baseInsert.extend({
    authType: z.literal('mtls'),
    mtlsCert: z.string().regex(
      /-----BEGIN [A-Z ]+-----[\s\S]+-----END [A-Z ]+-----/,
      "Certificado PEM inválido"
    ),
    mtlsKey: z.string().regex(
      /-----BEGIN [A-Z ]+-----[\s\S]+-----END [A-Z ]+-----/,
      "Chave PEM inválida"
    ),
    mtlsCa: z.string().regex(
      /-----BEGIN [A-Z ]+-----[\s\S]+-----END [A-Z ]+-----/,
      "CA PEM inválida"
    ).optional(),
  }),
]);
```

### Padrão 3: Storage facade — `server/storage/apiCredentials.ts`

**O que:** Arquivo de facade por domínio, simétrico com `server/storage/apis.ts`.

**Quando usar:** Toda operação de banco que envolva `api_credentials`.

**Exemplo (baseado em `server/storage/apis.ts` — template verificado):**
```typescript
// Fonte: server/storage/apis.ts — padrão verificado Phase 9
import { db } from '../db';
import { apiCredentials, type ApiCredential, type ApiCredentialSafe } from '@shared/schema';
import { encryptionService } from '../services/encryption';
import { eq, asc, and, isNull, or } from 'drizzle-orm';
import { createLogger } from '../lib/logger';

const log = createLogger('storage:api-credentials');

// Campos seguros (sem secret*/dek*) — espelha getCredentials() em assets.ts:180
const SAFE_FIELDS = {
  id: apiCredentials.id,
  name: apiCredentials.name,
  description: apiCredentials.description,
  authType: apiCredentials.authType,
  urlPattern: apiCredentials.urlPattern,
  priority: apiCredentials.priority,
  apiId: apiCredentials.apiId,
  // campos por tipo (nullable, safe)
  apiKeyHeaderName: apiCredentials.apiKeyHeaderName,
  // ... demais campos não-secretos
  createdAt: apiCredentials.createdAt,
  updatedAt: apiCredentials.updatedAt,
  createdBy: apiCredentials.createdBy,
};

export async function listApiCredentials(
  filter?: { apiId?: string; authType?: string }
): Promise<ApiCredentialSafe[]> {
  return db.select(SAFE_FIELDS).from(apiCredentials)
    .orderBy(asc(apiCredentials.priority));
}

export async function createApiCredential(
  input: InsertApiCredential,
  userId: string,
): Promise<ApiCredentialSafe> {
  // Extrair o secret do input antes de persistir
  const { secret, mtlsCert, mtlsKey, mtlsCa, ...rest } = input as any;

  // Determinar o valor a criptografar
  const secretToEncrypt = input.authType === 'mtls'
    ? JSON.stringify({ cert: mtlsCert, key: mtlsKey, ca: mtlsCa })
    : secret;

  const { secretEncrypted, dekEncrypted } = encryptionService.encryptCredential(secretToEncrypt);

  // Derivar bearerExpiresAt se JWT
  let bearerExpiresAt: Date | undefined;
  if (input.authType === 'bearer_jwt') {
    bearerExpiresAt = decodeJwtExp(secret) ?? undefined;
  }

  const [created] = await db.insert(apiCredentials)
    .values({ ...rest, secretEncrypted, dekEncrypted, bearerExpiresAt, createdBy: userId })
    .returning(SAFE_FIELDS);

  log.info({ apiCredentialId: created.id, authType: created.authType, apiId: created.apiId }, 'api credential created');
  return created;
}

// Método interno — restrito ao executor (Phase 11+)
export async function getApiCredentialWithSecret(id: string): Promise<ApiCredentialWithSecret | undefined> {
  const [cred] = await db.select().from(apiCredentials).where(eq(apiCredentials.id, id));
  return cred;
}
```

### Padrão 4: Guard `ensureApiCredentialTables()` em `database-init.ts`

**O que:** Função idempotente que cria enum, tabela e indexes se ausentes. Segue exatamente `ensureApiTables()` do Phase 9.

**Quando usar:** Chamada no boot após `ensureApiTables()`.

**Estrutura verificada em `server/storage/database-init.ts:151-339`:**
```typescript
// Padrão verificado: ensureApiTables() — Phase 9
export async function ensureApiCredentialTables(): Promise<void> {
  try {
    // 1. Enum api_auth_type
    const enumCheck = await db.execute(sql`
      SELECT typname FROM pg_type WHERE typname = 'api_auth_type'
    `);
    if ((enumCheck.rowCount ?? 0) === 0) {
      await db.execute(sql`
        CREATE TYPE api_auth_type AS ENUM (
          'api_key_header','api_key_query','bearer_jwt','basic',
          'oauth2_client_credentials','hmac','mtls'
        )
      `);
    }

    // 2. Tabela api_credentials (CREATE TABLE IF NOT EXISTS)
    const tableCheck = await db.execute(sql`
      SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = 'api_credentials'
    `);
    if ((tableCheck.rowCount ?? 0) === 0) {
      await db.execute(sql`CREATE TABLE IF NOT EXISTS api_credentials (...)`);
    }

    // 3. Indexes via loop (sql.raw para identifiers)
    for (const [idxName, ddl] of INDEXES) {
      const idxCheck = await db.execute(sql`
        SELECT indexname FROM pg_indexes
        WHERE tablename = 'api_credentials' AND indexname = ${idxName}
      `);
      if ((idxCheck.rowCount ?? 0) === 0) {
        await db.execute(sql.raw(ddl));
      }
    }
  } catch (error) {
    log.error({ err: error }, 'ensureApiCredentialTables error');
    // Não relançar — app continua em modo fallback (padrão Phase 9)
  }
}
```

### Padrão 5: Helper `matchUrlPattern.ts`

**O que:** Converte glob para regex e testa URL alvo. Produzido no Phase 10, consumido no Phase 11.

**Quando usar:** `resolveApiCredential()` usa internamente; Phase 11 runtime também poderá chamar diretamente.

**Algoritmo de conversão glob → regex (definido em CONTEXT.md):**
```typescript
// server/services/credentials/matchUrlPattern.ts
export function matchUrlPattern(pattern: string, url: string): boolean {
  // Escapa todos os caracteres regex exceto *
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&') // escapa regex especiais
    .replace(/\*/g, '[^/]*');              // * = qualquer coisa exceto /

  const regex = new RegExp(`^${escaped}$`);
  return regex.test(url);
}

// Validação de pattern aceita no POST (whitelist conservadora)
const VALID_PATTERN = /^[a-zA-Z0-9:/.*?=&_\-{}~!$'()+,;%@#]+$/;
export function isValidUrlPattern(pattern: string): boolean {
  if (!pattern || pattern.length === 0) return false;
  if (pattern.includes('**')) return false; // ambíguo
  return VALID_PATTERN.test(pattern);
}
```

### Padrão 6: Algoritmo `resolveApiCredential()`

**Algoritmo completo (fonte: CONTEXT.md, linhas 98-103):**
```typescript
// server/storage/apiCredentials.ts
export async function resolveApiCredential(
  apiId: string,
  endpointUrl: string, // ${api.baseUrl}${endpoint.path}
): Promise<ApiCredentialSafe | null> {
  // Candidatos: credenciais do apiId OU globais (apiId IS NULL)
  const candidates = await db.select(SAFE_FIELDS)
    .from(apiCredentials)
    .where(or(eq(apiCredentials.apiId, apiId), isNull(apiCredentials.apiId)))
    .orderBy(asc(apiCredentials.priority), asc(apiCredentials.createdAt));

  // Filtrar por pattern match
  const matching = candidates.filter(c => matchUrlPattern(c.urlPattern, endpointUrl));

  if (matching.length === 0) return null;

  // Tie-break 1: priority ASC (já ordenado)
  // Tie-break 2: specificity (mais literais = mais específico)
  // Tie-break 3: createdAt ASC (já ordenado)
  const countLiterals = (p: string) => p.replace(/\*/g, '').length;
  matching.sort((a, b) => {
    if (a.priority !== b.priority) return a.priority - b.priority;
    const specDiff = countLiterals(b.urlPattern) - countLiterals(a.urlPattern);
    if (specDiff !== 0) return specDiff;
    return a.createdAt < b.createdAt ? -1 : 1;
  });

  return matching[0];
}
```

### Padrão 7: Helper `decodeJwtExp.ts`

**O que:** Decodifica o claim `exp` do JWT para popular `bearerExpiresAt`. Falha silenciosa (JWT opaco ou não-standard).

```typescript
// server/services/credentials/decodeJwtExp.ts
export function decodeJwtExp(jwt: string): Date | null {
  try {
    const parts = jwt.split('.');
    if (parts.length < 2) return null;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (typeof payload.exp !== 'number') return null;
    return new Date(payload.exp * 1000);
  } catch {
    return null; // JWT opaco ou mal-formado — aceitar sem bearerExpiresAt
  }
}
```

### Anti-Padrões a Evitar

- **Logar o objeto credencial inteiro**: usar `{ apiCredentialId, authType, apiId }` — nunca o objeto completo
- **Retornar `secretEncrypted`/`dekEncrypted` em respostas de rota**: o facade é a única barreira; a rota nunca deve burlar o tipo `ApiCredentialSafe`
- **Usar `**` em patterns**: ambíguo; rejeitar no POST com 400
- **Persistir token OAuth2**: cache in-memory é Phase 11 — Phase 10 armazena só `oauth2ClientSecret`
- **Validação cross-field via CHECK constraint no DB**: manter em Zod discriminated union; migration aditiva fica simples
- **`ALTER TYPE` em enum Postgres**: nunca mutar `api_auth_type`; criar nova enum se OWASP futuro exigir variante

---

## Não Construir do Zero

| Problema | Não Construir | Usar em vez disso | Por que |
|----------|---------------|-------------------|---------|
| Criptografia AES-256-GCM | Implementação própria | `encryptionService.encryptCredential()` em `server/services/encryption.ts` | Testado, auditado, com AAD e autenticação GCM; reinventar introduz bugs sutis |
| Logging com redaction | Filtro manual de secrets | `createLogger()` + pino redaction (REDACT_PATHS já cobre `secretEncrypted`, `dekEncrypted`) | Redaction em serialização é zero-copy e infalível em relação a filtragem manual |
| Sanitização de campos de resposta | Lógica manual de `delete obj.secretEncrypted` | Explicit field list na query com `db.select(SAFE_FIELDS)` | Padrão verificado em `getCredentials()` (`assets.ts:180`); `delete` é mutação perigosa |
| Schema de DB | Migration SQL manual | `db:push` + guard idempotente `ensureApiCredentialTables()` | Padrão estabelecido; guard suporta hot-reload em produção sem downtime |
| Validação de shape por auth type | Switch/if-else na rota | `z.discriminatedUnion('authType', [...])` | Zod garante exhaustiveness e mensagens pt-BR consistentes |

**Insight chave:** O Phase 10 é aditivo puro — nenhuma linha de código existente precisa ser alterada exceto para registrar o novo módulo. O risco de regressão é praticamente zero se os padrões forem seguidos.

---

## Armadilhas Comuns

### Armadilha 1: Identifiers não-quoted no guard de banco

**O que dá errado:** `CREATE INDEX IDX_api_credentials_api_id ON ...` (sem aspas) falha no Postgres se o nome do index ou tabela contiver maiúsculas ou underscores em contextos case-sensitive.

**Por que acontece:** Postgres case-folds identifiers não-quoted para lowercase; nomes com maiúsculas exigem aspas.

**Como evitar:** Usar `sql.raw(`CREATE INDEX "${idxName}" ON api_credentials (${column})`)` — padrão exato de `ensureApiTables()` linha 329 em `database-init.ts`.

**Sinal de alerta:** Erro `relation "IDX_Api_Credentials_..." does not exist` no boot.

### Armadilha 2: `baseInsert` contém campos de outros auth types (nullable) no discriminated union

**O que dá errado:** Se o `baseInsert` incluir campos como `apiKeyHeaderName` (nullable), o Zod aceita qualquer campo para qualquer variante, tornando a discriminação inócua.

**Por que acontece:** `createInsertSchema()` gera campos nullable para todas as colunas nullable da tabela — incluindo as de outros auth types.

**Como evitar:** Omitir **todos** os campos por-tipo no `baseInsert`:
```typescript
const baseInsert = createInsertSchema(apiCredentials).omit({
  id: true, secretEncrypted: true, dekEncrypted: true,
  createdAt: true, updatedAt: true, createdBy: true, updatedBy: true,
  bearerExpiresAt: true,
  // campos por tipo — omitir do base, adicionar só na variante correta:
  apiKeyHeaderName: true, apiKeyQueryParam: true, basicUsername: true,
  oauth2ClientId: true, oauth2TokenUrl: true, oauth2Scope: true, oauth2Audience: true,
  hmacKeyId: true, hmacAlgorithm: true, hmacSignatureHeader: true,
  hmacSignedHeaders: true, hmacCanonicalTemplate: true,
});
```

**Sinal de alerta:** POST com `authType: 'bearer_jwt'` aceita `apiKeyHeaderName` sem rejeitar.

### Armadilha 3: Secret do mTLS exposto no log antes de criptografar

**O que dá errado:** `log.info({ body: req.body }, 'creating credential')` expõe `mtlsCert`, `mtlsKey` (PEMs com chave privada) no log.

**Por que acontece:** O pino redaction cobre `secret`, `secretEncrypted`, `dekEncrypted` mas NÃO cobre `mtlsCert`, `mtlsKey`, `mtlsCa` por padrão.

**Como evitar:** Na rota, logar apenas IDs e tipos; nunca o body completo. `log.info({ authType: body.authType, apiId: body.apiId }, 'credential received')`.

**Sinal de alerta:** PEM strings visíveis nos logs de desenvolvimento.

### Armadilha 4: `resolveApiCredential` retorna credencial com secret (sem sanitização)

**O que dá errado:** Se `resolveApiCredential()` usar `db.select()` sem `SAFE_FIELDS`, retorna `secretEncrypted` e `dekEncrypted` em contextos onde só o shape safe é esperado.

**Por que acontece:** Copiar o padrão do `getApiCredentialWithSecret()` interno sem adaptar os campos.

**Como evitar:** `resolveApiCredential()` usa `db.select(SAFE_FIELDS)`. Somente `getApiCredentialWithSecret()` usa `db.select()` completo.

**Sinal de alerta:** TypeScript type-error se o retorno for tipado como `ApiCredentialSafe` e os campos secret aparecerem.

### Armadilha 5: `db:push` não cria a enum `api_auth_type` se o Drizzle já tiver mapeado o schema

**O que dá errado:** Em ambiente de CI ou produção, `db:push` pode falhar se o schema já existe parcialmente ou se a ordem de criação de tipos não for respeitada.

**Por que acontece:** pgEnums precisam existir antes da tabela que as referencia.

**Como evitar:** O guard `ensureApiCredentialTables()` sempre cria a enum **antes** da tabela; é executado no boot antes do primeiro request chegar — dupla proteção com `db:push`.

---

## Exemplos de Código

### Encryption round-trip para mTLS (padrão verificado)

```typescript
// Fonte: server/services/encryption.ts — verificado, zero mudança
const mtlsSecret = JSON.stringify({ cert: mtlsCert, key: mtlsKey, ca: mtlsCa });
const { secretEncrypted, dekEncrypted } = encryptionService.encryptCredential(mtlsSecret);

// Decrypt (Phase 11):
const raw = encryptionService.decryptCredential(secretEncrypted, dekEncrypted);
const { cert, key, ca } = JSON.parse(raw);
// → configurar https.Agent({ cert, key, ca })
```

### Sanitização explícita de campos (padrão verificado)

```typescript
// Fonte: server/storage/assets.ts:180 — padrão exato a espelhar
const SAFE_FIELDS = {
  id: apiCredentials.id,
  name: apiCredentials.name,
  authType: apiCredentials.authType,
  urlPattern: apiCredentials.urlPattern,
  priority: apiCredentials.priority,
  apiId: apiCredentials.apiId,
  description: apiCredentials.description,
  // campos por tipo (not null):
  apiKeyHeaderName: apiCredentials.apiKeyHeaderName,
  apiKeyQueryParam: apiCredentials.apiKeyQueryParam,
  basicUsername: apiCredentials.basicUsername,
  bearerExpiresAt: apiCredentials.bearerExpiresAt,
  oauth2ClientId: apiCredentials.oauth2ClientId,
  oauth2TokenUrl: apiCredentials.oauth2TokenUrl,
  oauth2Scope: apiCredentials.oauth2Scope,
  oauth2Audience: apiCredentials.oauth2Audience,
  hmacKeyId: apiCredentials.hmacKeyId,
  hmacAlgorithm: apiCredentials.hmacAlgorithm,
  hmacSignatureHeader: apiCredentials.hmacSignatureHeader,
  hmacSignedHeaders: apiCredentials.hmacSignedHeaders,
  hmacCanonicalTemplate: apiCredentials.hmacCanonicalTemplate,
  // auditoria:
  createdAt: apiCredentials.createdAt,
  updatedAt: apiCredentials.updatedAt,
  createdBy: apiCredentials.createdBy,
  updatedBy: apiCredentials.updatedBy,
  // NÃO incluir: secretEncrypted, dekEncrypted
};
```

### Rota POST (padrão verificado — `server/routes/apis.ts`)

```typescript
// Fonte: server/routes/apis.ts — template verificado Phase 9
app.post('/api/v1/api-credentials', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
  let body: z.infer<typeof insertApiCredentialSchema>;
  try {
    body = insertApiCredentialSchema.parse(req.body);
  } catch (err: any) {
    log.info({ err }, 'api credential rejected by Zod');
    return res.status(400).json({ message: "Dados de credencial inválidos", details: err?.errors });
  }

  try {
    const cred = await storage.createApiCredential(body, req.user.id);
    log.info({ apiCredentialId: cred.id, authType: cred.authType }, 'api credential created via route');
    return res.status(201).json(cred);
  } catch (error: any) {
    if (error?.code === '23505') {
      return res.status(409).json({ message: "Credencial já cadastrada com esse nome" });
    }
    log.error({ err: error }, 'failed to create api credential');
    return res.status(500).json({ message: "Falha ao cadastrar credencial" });
  }
});
```

---

## Estado da Arte

| Abordagem anterior | Abordagem atual | Quando mudou | Impacto |
|-------------------|-----------------|--------------|---------|
| `credentials` única tabela para todos os tipos | Tabela separada `api_credentials` | Phase 10 (esta fase) | Isolamento total; zero risco de regressão em `getCredentials()` |
| Sem mapeamento de URL | `urlPattern` glob + `priority` int na própria credencial | Phase 10 (esta fase) | Engine pode resolver a credencial certa por endpoint |
| Crypto nova por feature | Reuso de `encryptionService` (AES-256-GCM KEK/DEK) | Desde Phase 1 do projeto | Zero nova superfície de ataque |

**Deprecated/desatualizado:**
- Usar `credentials` legada para API auth types: tipos incompatíveis de shape; causaria regressão em rotas existentes

---

## Perguntas em Aberto

1. **`hmacSignedHeaders` como `text[]` no Postgres**
   - O que sabemos: Drizzle suporta `.array()` via `text('col').array()` — mas `db:push` pode exigir que o tipo seja `TEXT[]` no DDL do guard manual
   - O que está incerto: Se `sql`` CREATE TABLE ... hmac_signed_headers TEXT[] ... `` precisa de cast explícito ou o Drizzle resolve
   - Recomendação: Planner deve verificar o DDL gerado por `db:push` e garantir que o guard manual use `TEXT[]` (plural) — precedente em `api_endpoints.discovery_sources TEXT[] NOT NULL DEFAULT ARRAY[]::text[]` confirmado em `database-init.ts:257`

2. **`bearerExpiresAt` com JWT opaco**
   - O que sabemos: Se `decodeJwtExp()` falhar, o campo fica `null` e o POST retorna 201 sem erro
   - O que está incerto: Nenhum; a decisão está bloqueada no CONTEXT.md
   - Recomendação: Implementar exatamente conforme CONTEXT.md — sem erro, sem campo

3. **Validação de `urlPattern` no PATCH parcial**
   - O que sabemos: PATCH usa Zod partial do schema de inserção
   - O que está incerto: O discriminated union `.partial()` no Zod pode ter comportamento inesperado — `z.discriminatedUnion().partial()` não existe nativamente; seria necessário um schema de patch separado
   - Recomendação: Criar `patchApiCredentialSchema` como objeto flat com todos campos opcionais (exceto `authType` que não deve ser mutável); o planner deve definir se `authType` pode ser alterado no PATCH ou não

---

## Arquitetura de Validação (Nyquist)

> `workflow.nyquist_validation: true` em `.planning/config.json` — seção obrigatória.

### Framework de Testes

| Propriedade | Valor |
|-------------|-------|
| Framework | vitest (configurado em `vitest.config.ts`) |
| Arquivo de config | `/opt/samureye/vitest.config.ts` |
| Inclui | `server/**/*.test.ts`, `shared/**/*.test.ts` |
| Comando rápido | `npx vitest run --reporter=verbose` |
| Suite completa | `npx vitest run` |

### Mapa Requisitos → Testes

| ID | Comportamento | Tipo de Teste | Comando | Arquivo existe? |
|----|---------------|---------------|---------|-----------------|
| CRED-01 | `insertApiCredentialSchema` aceita cada um dos 7 auth types com campos corretos | unit | `npx vitest run shared/__tests__/apiCredentialSchema.test.ts` | ❌ Wave 0 |
| CRED-01 | `insertApiCredentialSchema` rejeita auth type desconhecido | unit | `npx vitest run shared/__tests__/apiCredentialSchema.test.ts` | ❌ Wave 0 |
| CRED-01 | `insertApiCredentialSchema` rejeita campos de auth type errado (e.g., `apiKeyHeaderName` em `bearer_jwt`) | unit | `npx vitest run shared/__tests__/apiCredentialSchema.test.ts` | ❌ Wave 0 |
| CRED-01 | Validação PEM regex aceita cert válido e rejeita string simples | unit | `npx vitest run shared/__tests__/apiCredentialSchema.test.ts` | ❌ Wave 0 |
| CRED-02 | Encryption round-trip: encrypt → decrypt retorna string original | unit | `npx vitest run server/__tests__/encryption.test.ts` | ✅ já existe |
| CRED-02 | mTLS: `JSON.stringify({cert,key,ca})` → encrypt → decrypt → `JSON.parse` retorna objeto com 3 campos | unit | `npx vitest run server/__tests__/apiCredentialStorage.test.ts` | ❌ Wave 0 |
| CRED-02 | `listApiCredentials()` nunca retorna campos `secretEncrypted`/`dekEncrypted` | unit | `npx vitest run server/__tests__/apiCredentialStorage.test.ts` | ❌ Wave 0 |
| CRED-02 | `getApiCredentialWithSecret()` retorna `secretEncrypted` e `dekEncrypted` | unit | `npx vitest run server/__tests__/apiCredentialStorage.test.ts` | ❌ Wave 0 |
| CRED-03 | `matchUrlPattern('*', 'https://any.url/path')` retorna true | unit | `npx vitest run server/__tests__/matchUrlPattern.test.ts` | ❌ Wave 0 |
| CRED-03 | `matchUrlPattern('https://api.corp.com/*', 'https://api.corp.com/v2/users')` retorna true | unit | `npx vitest run server/__tests__/matchUrlPattern.test.ts` | ❌ Wave 0 |
| CRED-03 | `matchUrlPattern('https://api.corp.com/*', 'https://other.com/v2')` retorna false | unit | `npx vitest run server/__tests__/matchUrlPattern.test.ts` | ❌ Wave 0 |
| CRED-03 | `isValidUrlPattern('**')` retorna false | unit | `npx vitest run server/__tests__/matchUrlPattern.test.ts` | ❌ Wave 0 |
| CRED-04 | `resolveApiCredential()` retorna credencial com menor `priority` quando múltiplas casam | unit | `npx vitest run server/__tests__/apiCredentialStorage.test.ts` | ❌ Wave 0 |
| CRED-04 | Tie-break: mesma priority → mais específica (mais literais no pattern) ganha | unit | `npx vitest run server/__tests__/apiCredentialStorage.test.ts` | ❌ Wave 0 |
| CRED-04 | Tie-break: mesma priority e specificity → mais antiga ganha | unit | `npx vitest run server/__tests__/apiCredentialStorage.test.ts` | ❌ Wave 0 |
| CRED-04 | `resolveApiCredential()` retorna `null` quando nenhuma credencial casa | unit | `npx vitest run server/__tests__/apiCredentialStorage.test.ts` | ❌ Wave 0 |
| CRED-05 | `POST /api/v1/api-credentials` retorna 201 com shape `ApiCredentialSafe` (sem secret*/dek*) | integration | `npx vitest run server/__tests__/apiCredentialsRoute.test.ts` | ❌ Wave 0 |
| CRED-05 | `POST /api/v1/api-credentials` retorna 409 em nome duplicado | integration | `npx vitest run server/__tests__/apiCredentialsRoute.test.ts` | ❌ Wave 0 |
| CRED-05 | `POST /api/v1/api-credentials` retorna 403 para `read_only` | integration | `npx vitest run server/__tests__/apiCredentialsRoute.test.ts` | ❌ Wave 0 |
| CRED-05 | `POST /api/v1/api-credentials` retorna 401 para unauthenticated | integration | `npx vitest run server/__tests__/apiCredentialsRoute.test.ts` | ❌ Wave 0 |
| CRED-01..05 | `ensureApiCredentialTables()` é idempotente — segunda execução é no-op sem erro | integration | `npx vitest run server/__tests__/ensureApiCredentialTables.test.ts` | ❌ Wave 0 |
| CRED-01..05 | `ensureApiCredentialTables()` não relança erro (app continua em fallback mode) | unit | `npx vitest run server/__tests__/ensureApiCredentialTables.test.ts` | ❌ Wave 0 |

### Taxa de Amostragem

- **Por commit de task:** `npx vitest run server/__tests__/apiCredentialStorage.test.ts shared/__tests__/apiCredentialSchema.test.ts server/__tests__/matchUrlPattern.test.ts`
- **Por merge de wave:** `npx vitest run`
- **Gate do phase:** Suite completa verde antes de `/gsd:verify-work`

### Gaps do Wave 0 (arquivos a criar antes da implementação)

- [ ] `shared/__tests__/apiCredentialSchema.test.ts` — cobre CRED-01 (discriminated union, PEM regex, todos 7 tipos)
- [ ] `server/__tests__/matchUrlPattern.test.ts` — cobre CRED-03 (glob match, isValid, edge cases)
- [ ] `server/__tests__/apiCredentialStorage.test.ts` — cobre CRED-02, CRED-04 (encryption round-trip mTLS, sanitização, resolução de priority)
- [ ] `server/__tests__/apiCredentialsRoute.test.ts` — cobre CRED-05 (201 shape, 409, RBAC 403/401)
- [ ] `server/__tests__/ensureApiCredentialTables.test.ts` — cobre guard idempotency + fallback

*(Arquivo `server/__tests__/encryption.test.ts` já existe e cobre o round-trip básico de CRED-02 — não duplicar)*

---

## Fontes

### Primário (confiança HIGH — código verificado no codebase)

- `server/services/encryption.ts` — API `encryptCredential()` / `decryptCredential()` verificada linha a linha
- `server/storage/database-init.ts:151-339` — padrão `ensureApiTables()` verificado; template exato para `ensureApiCredentialTables()`
- `server/storage/assets.ts:180-196` — padrão `getCredentials()` com explicit field list; template para `listApiCredentials()`
- `server/storage/apis.ts` — facade mais recente (Phase 9); template para `apiCredentials.ts`
- `server/routes/apis.ts` — rota mais recente (Phase 9); template para `apiCredentials.ts`
- `server/routes/index.ts` — barrel de rotas verificado; ponto de integração de `registerApiCredentialsRoutes`
- `server/storage/index.ts` — `DatabaseStorage` verificado; padrão de namespace imports por domínio
- `server/lib/logger.ts` — REDACT_PATHS verificados; `secretEncrypted`, `dekEncrypted` já cobertos
- `shared/schema.ts:38,147,180,876` — padrões de pgEnum, pgTable, priority column, insertSchema.omit()
- `vitest.config.ts` — configuração de testes verificada; `shared/**/*.test.ts` incluído

### Secundário (confiança MEDIUM — documentação de projeto)

- `.planning/phases/10-api-credentials/10-CONTEXT.md` — decisões de design detalhadas; usadas como fonte autoritativa
- `.planning/REQUIREMENTS.md:17-23` — CRED-01..CRED-05 verificados

### Terciário (confiança LOW — não foram necessários)

Nenhuma pesquisa externa foi necessária. Todo o conhecimento relevante está no codebase e na documentação do projeto.

---

## Metadados

**Breakdown de confiança:**
- Stack padrão: HIGH — todos os pacotes verificados no codebase existente
- Padrões de arquitetura: HIGH — baseados em código verificado do Phase 9
- Armadilhas: HIGH — identificadas a partir de código real (`database-init.ts`, `schema.ts`)
- Helper glob→regex: MEDIUM — algoritmo simples, mas comportamento de edge cases (`*.host.*`) deve ser validado nos testes de Wave 0

**Data da pesquisa:** 2026-04-19
**Válido até:** 2026-05-19 (stack estável; sem dependências externas novas)
