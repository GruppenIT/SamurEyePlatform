# Phase 9: Schema & Asset Hierarchy - Research

**Researched:** 2026-04-18
**Domain:** Drizzle ORM schema additions (apis / api_endpoints / api_findings), idempotent runtime guard, CLI backfill, REST registration endpoint — all inside the existing Express + Drizzle + Postgres stack of SamurEye.
**Confidence:** HIGH

## Summary

Phase 9 is purely a *data* phase: it adds three tables (`apis`, `api_endpoints`, `api_findings`), three pgEnums (`api_type_enum`, `owasp_api_category`, `api_finding_status`), one CLI backfill script (`backfillApiDiscovery.ts`), one REST route (`POST /api/v1/apis`), one constants module (`shared/owaspApiCategories.ts`), and one runtime idempotency guard (`ensureApiTables()` in `database-init.ts`). No new runtime logic, no discovery, no test execution — those land in Phases 11-14. The schema is aditivo puro and compatible with `drizzle-kit push`.

CONTEXT.md has already locked every structural decision (enums, FKs, uniqueness, evidence shape, backfill probe list, rate-limiting, POST body). The planner's job is to sequence the *files* — not redesign. This research confirms the locked decisions against the live codebase (`shared/schema.ts`, `database-init.ts`, `backfillWebAppParent.ts`, `routes/assets.ts`, `routes/credentials.ts`, `storage/index.ts`, `storage/interface.ts`), verifies drizzle-orm 0.39.1 + drizzle-zod 0.7.0 support the chosen patterns, and surfaces a handful of non-obvious pitfalls (pg_indexes lowercasing quirk, check() constraint syntax for drizzle 0.39, IStorage barrel fan-out, circular FK between api_findings↔threats, evidence bodySnippet defensive naming).

**Primary recommendation:** Execute as 4 waves — Wave 0 (constants + Zod helpers + test fixtures), Wave 1 (schema + pgEnums in `shared/schema.ts`, tests for enums + insertSchema), Wave 2 (storage facades + interface + database-init guard), Wave 3 (route + backfill CLI + docs). Keep every commit additivo; do not touch existing tables, existing enums, or the threats facade.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Table `apis` (HIER-01, HIER-03)**
- **`apiType` enum**: `rest`, `graphql`, `soap` — pgEnum `api_type_enum`.
- **Required no registro manual**: `parentAssetId` (FK obrigatório) + `baseUrl` (text absoluto) + `apiType`. `name`, `description`, `specUrl` são opcionais.
- **Colunas de spec (criadas nulláveis agora, populadas no Phase 11)**: `specHash` (text), `specVersion` (text), `specLastFetchedAt` (timestamp), `specUrl` (text).
- **Uniqueness**: `UNIQUE (parent_asset_id, base_url)`.
- **Colunas de auditoria**: `createdAt`, `createdBy` (FK → users.id), `updatedAt`.
- **Validação do parentAssetId**: registro manual deve validar que o parent é `type='web_application'` (erro 400 caso contrário).

**Table `api_endpoints` (HIER-02)**
- **Params em 3 JSONBs separados**: `path_params`, `query_params`, `header_params` — array de `{ name, type?, required?, example? }`.
- **`method`**: text + CHECK `IN ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS')`.
- **`requiresAuth`**: boolean **nullable** com semântica tri-valor: NULL (não probado), true (401/403), false (aberto).
- **`discoverySources`**: `text[]` com valores `spec`, `crawler`, `kiterunner`, `manual` documentados em constante TS.
- **`requestSchema` / `responseSchema`**: 2 colunas JSONB nulláveis.
- **FK**: `api_id → apis.id` obrigatório, `ON DELETE CASCADE`.
- **Uniqueness sugerida**: `UNIQUE (api_id, method, path)`.

**Table `api_findings` (FIND-01)**
- **Categoria OWASP**: pgEnum `owasp_api_category` com 10 valores sufixados `_2023` (api1_bola_2023, api2_broken_auth_2023, api3_bopla_2023, api4_rate_limit_2023, api5_bfla_2023, api6_business_flow_2023, api7_ssrf_2023, api8_misconfiguration_2023, api9_inventory_2023, api10_unsafe_consumption_2023).
- **Labels pt-BR** em constante TS separada (`shared/owaspApiCategories.ts`).
- **`severity`**: reusa `threatSeverityEnum`.
- **`riskScore`**: `real` nullable (0-100).
- **`evidence`**: JSONB com shape `{ request: {method, url, headers?, bodySnippet?}, response: {status, headers?, bodySnippet?}, extractedValues?, context? }` — Zod-validado.
- **FKs**: `apiEndpointId → api_endpoints.id` obrigatório `ON DELETE CASCADE`; `jobId → jobs.id` nullable; `promotedThreatId → threats.id` nullable `ON DELETE SET NULL` (coluna criada agora, populada no Phase 14).
- **Campos de base**: `title`, `description`, `remediation` (text pt-BR inline), `status` (pgEnum `api_finding_status` = `open | triaged | false_positive | closed`), `createdAt`, `updatedAt`.

**Backfill `backfillApiDiscovery.ts` (HIER-04)**
- Script CLI on-demand (`npx tsx --env-file=.env server/scripts/backfillApiDiscovery.ts [--dry-run]`).
- Idempotência: só processa `assets.type='web_application'` que NÃO têm API filha (NOT EXISTS).
- Detecção: spec paths (`/openapi.json`, `/swagger.json`, `/v2/api-docs`, `/v3/api-docs`, `/api-docs`, `/swagger-ui.html`, `/graphql`); `/api` JSON; root `/` JSON Content-Type.
- Promoção: cria row em `apis`; `apiType` inferido (`rest` ou `graphql`); `specUrl` preenchido quando spec detectado.
- False positives aceitáveis. Sem credentials.
- Rate limiting: timeout 5s/request, max 10 probes concorrentes.
- Doc: `docs/operations/backfill-api-discovery.md`.

**Registro manual `POST /api/v1/apis` (HIER-03)**
- Body: `{ parentAssetId, baseUrl, apiType, name?, description?, specUrl? }`.
- Zod: `parentAssetId` deve existir e ter `type='web_application'`; `baseUrl` URL absoluta (reusar `normalizeTarget`); `apiType` do enum.
- RBAC: `global_administrator` + `operator` (espelha `POST /api/v1/assets`).
- Duplicata: driver retorna erro, route traduz para 409 Conflict com mensagem pt-BR.
- Response 201 com linha criada. Log pt-BR via pino.

**Migration pattern**
- Drizzle `db:push` continua sendo o mecanismo.
- Guard idempotente `ensureApiTables()` em `server/storage/database-init.ts` — replicar padrão de `edr_deployments` (pg_tables/pg_indexes/pg_type checks).
- Zero down migration — aditivo puro.

### Claude's Discretion
- Nomes exatos de colunas (snake_case DB, camelCase TS — Drizzle)
- Nomes exatos dos indexes (padrão `IDX_<table>_<col>`, `UQ_<table>_<col>`)
- Ordem exata das colunas nas tabelas (agrupar relacionadas, auditoria no fim)
- Estrutura final do Zod schema para body do POST (createInsertSchema vs manual)
- Organização de arquivos em `server/storage/` (3 arquivos separados preferencial, simétrico a threats.ts)
- Forma final da função Storage facade (getApiById, listApisByParent, createApi, promoteApiFromBackfill, etc.)
- Módulo de constantes pt-BR do OWASP (shape do export)
- Forma exata das probes no backfill (fetch+AbortController vs p-limit)

### Deferred Ideas (OUT OF SCOPE)
- Soft-delete / archived flag em `apis`
- Tabela `api_schemas` com hash-dedup
- `firstDiscoveredAt` / `lastSeenAt` em `api_endpoints`
- Tags em `apis` (jsonb espelhando assets)
- Auto-re-run do backfill em schedule
- Multi-version spec tracking (histórico de specHash)
- Constraint cross-table SQL (validação `parentAssetId → web_application` fica no route/service)
- `operationId` opcional em `api_endpoints`
- Versionamento de OWASP 2027 — nova enum paralela quando sair
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| HIER-01 | System persists `apis` as a first-class table with `parentAssetId → assets.id` under an existing `web_application` asset | `apis` table schema (§Architecture Patterns → Schema additions) — FK `parent_asset_id → assets.id` with ON DELETE CASCADE; UNIQUE (parent_asset_id, base_url). Precedent: `assets.parentAssetId` self-ref in shared/schema.ts:112. |
| HIER-02 | System persists `api_endpoints` with `apiId → apis.id`, capturing method, path, params (path/query/header), request/response schemas, auth requirement, and discovery sources | `api_endpoints` table (§Architecture Patterns → Schema additions) — 3 JSONB param columns, method CHECK constraint, requiresAuth tri-valor nullable boolean, discoverySources text[], requestSchema/responseSchema JSONB. |
| HIER-03 | User can manually register an API under an existing web_application asset via an internal endpoint and see it persisted | `POST /api/v1/apis` route pattern (§Code Examples → Route). Zod via `createInsertSchema(apis).omit({id, createdAt, createdBy, updatedAt, specHash, specLastFetchedAt}).refine(...)`. RBAC via `requireOperator`. Reuses `normalizeTarget()` from server/services/journeys/urls.ts. 409 on duplicate via Postgres error code 23505. |
| HIER-04 | System backfills existing web_application assets by probing for API indicators and auto-promoting detected ones | `backfillApiDiscovery.ts` script (§Code Examples → Backfill). Template = `backfillWebAppParent.ts`. fetch() with AbortSignal.timeout(5000); simple batching or p-limit-style semaphore for concurrency=10. NOT EXISTS subquery for idempotency. |
| FIND-01 | System persists findings in `api_findings` with OWASP API Top 10 2023 category, severity, evidence, remediation, risk score | `api_findings` table (§Architecture Patterns → Schema additions). `owasp_api_category` pgEnum with 10 values suffixed `_2023`. Reuses `threatSeverityEnum`. JSONB evidence with Zod-enforced shape. Labels in `shared/owaspApiCategories.ts`. `promotedThreatId` column created now (populated Phase 14). |
</phase_requirements>

## Standard Stack

### Core (already in the project — DO NOT install anything new)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `drizzle-orm` | **0.39.1** (pinned in package.json) | ORM + schema DSL + migration driver | Project-wide canonical ORM; exposes `pgTable`, `pgEnum`, `index`, `uniqueIndex`, `check`, `sql` — everything Phase 9 needs |
| `drizzle-zod` | **0.7.0** (pinned) | Generates Zod schema from Drizzle table for route validation | Used by every existing insert schema in shared/schema.ts (`createInsertSchema(assets)`, etc.) |
| `zod` | 3.24.2 | Schema validation in routes | Standard for every POST/PATCH body in `server/routes/` |
| `drizzle-kit` | 0.31.9 (dev) | `db:push` mechanism | Called via `npm run db:push`; also used for `drizzle-kit studio` in dev |
| `pg` | 8.16.3 | Postgres driver | Used by `db.execute(sql\`...\`)` in database-init.ts |
| `pino` | 10.3.1 | Structured logging with automatic redaction | `createLogger('routes:apis')`, `createLogger('storage')` |
| `express` | 4.21.2 | HTTP framework | Route pattern in `server/routes/*.ts` |
| `tsx` | 4.19.1 (dev) | TypeScript script runner | Used by backfill CLI: `npx tsx --env-file=.env server/scripts/backfillApiDiscovery.ts` |
| `vitest` | 4.0.18 (dev) | Test runner (Nyquist validation) | Existing pattern: `server/__tests__/*.test.ts` |

**Version verification (2026-04-18):**
- Registry `drizzle-orm` latest: `0.45.2` — project pins 0.39.1; **do not bump** during Phase 9 (non-additive risk).
- Registry `drizzle-zod` latest: `0.8.3` — project pins 0.7.0; stay pinned.
- Registry `zod` latest: `4.3.6` — project pins 3.24.2; stay pinned.
- Registry `pino` latest: `10.3.1` — project already on latest.

### Supporting (Node built-ins — no install)

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `node:crypto` | built-in (Node 20.16) | `crypto.randomUUID()` fallback if needed — but NOT needed (we use `gen_random_uuid()` in Postgres) | N/A |
| `AbortSignal.timeout()` | built-in (Node 20+) | Per-request timeout in backfill probes | Backfill HTTP probes — `fetch(url, { signal: AbortSignal.timeout(5000) })` |
| `globalThis.fetch` | built-in (Node 18+) | HTTP probes in backfill | Backfill — NOT `node-fetch`, use native |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| 3 separate storage files (`apis.ts`, `apiEndpoints.ts`, `apiFindings.ts`) | 1 unified `apis.ts` | Simpler imports, but asymmetric with `threats.ts`/`assets.ts` pattern. **Keep 3 files per CONTEXT § Claude's Discretion.** |
| `createInsertSchema` + `.refine` | Hand-written `z.object({...})` | createInsertSchema auto-tracks schema changes; hand-written drifts. **Keep createInsertSchema + extend/refine** per project convention (shared/schema.ts:843-857). |
| pgEnum `http_method_enum` for method | text + CHECK constraint | Enum requires migration to add new methods (CONNECT, TRACE). CHECK allows aditivo via ALTER TABLE ... DROP/ADD CHECK. **CONTEXT locked CHECK.** |
| `p-limit` npm package | Manual semaphore via Promise.allSettled batches | p-limit adds a dep for one use site. **Use manual batching** — small closure in `backfillApiDiscovery.ts`. |
| `node-fetch` | Native `globalThis.fetch` | Native is built-in Node 20, zero dep. **Use native.** |
| `swagger-parser` in Phase 9 | N/A | Explicitly out of scope — parsing is Phase 11. Backfill only detects JSON content-type, not spec structure. |

**Installation (none required):**
```bash
# All dependencies already declared in package.json and locked.
# Phase 9 adds ZERO new dependencies.
```

## Architecture Patterns

### Recommended Project Structure

```
shared/
├── schema.ts                    # +3 pgEnums, +3 tables, +3 insertSchemas, +types (EDIT)
└── owaspApiCategories.ts        # NEW — pt-BR labels + OWASP URLs (const map)

server/
├── storage/
│   ├── apis.ts                  # NEW — facade: getApi, listApisByParent, createApi, ...
│   ├── apiEndpoints.ts          # NEW — facade: listEndpointsByApi, createEndpoint, ...
│   ├── apiFindings.ts           # NEW — facade: listFindingsByEndpoint, createFinding, ...
│   ├── database-init.ts         # EDIT — add ensureApiTables() + call from init
│   ├── interface.ts             # EDIT — IStorage gains ~12 method signatures
│   └── index.ts                 # EDIT — DatabaseStorage class wires new facades
├── routes/
│   ├── apis.ts                  # NEW — registerApiRoutes(app); POST /api/v1/apis
│   └── index.ts                 # EDIT — import + call registerApiRoutes
├── scripts/
│   └── backfillApiDiscovery.ts  # NEW — CLI probe-and-promote
└── __tests__/
    ├── owaspApiCategories.test.ts  # NEW (Nyquist) — 10 labels + URLs
    ├── insertApiSchema.test.ts     # NEW (Nyquist) — Zod happy path / invalid URL / bad enum
    ├── apiEvidence.test.ts         # NEW (Nyquist) — evidence JSONB Zod shape
    └── ensureApiTables.test.ts     # NEW (Nyquist) — pg_tables / pg_type / pg_indexes introspection

docs/
└── operations/
    └── backfill-api-discovery.md   # NEW — sibling to backfill-webapp-parent.md
```

### Pattern 1: Drizzle pgTable with composite UNIQUE and CHECK

**What:** Declare tables with relational integrity (FKs), indexes, composite uniqueness, and CHECK constraints — all inside the schema definition.
**When to use:** Every new table in Phase 9.
**Example:**
```typescript
// Source: shared/schema.ts existing patterns (edrDeployments:240-257, threats:302-341)
//         + drizzle-orm 0.39.1 docs verified via Context7
import { pgTable, varchar, text, timestamp, jsonb, integer, boolean, real,
         index, uniqueIndex, pgEnum, check } from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";

export const apiTypeEnum = pgEnum('api_type_enum', ['rest', 'graphql', 'soap']);
export const owaspApiCategoryEnum = pgEnum('owasp_api_category', [
  'api1_bola_2023', 'api2_broken_auth_2023', 'api3_bopla_2023',
  'api4_rate_limit_2023', 'api5_bfla_2023', 'api6_business_flow_2023',
  'api7_ssrf_2023', 'api8_misconfiguration_2023', 'api9_inventory_2023',
  'api10_unsafe_consumption_2023',
]);
export const apiFindingStatusEnum = pgEnum('api_finding_status',
  ['open', 'triaged', 'false_positive', 'closed']);

export const apis = pgTable("apis", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  parentAssetId: varchar("parent_asset_id")
    .references(() => assets.id, { onDelete: 'cascade' }).notNull(),
  baseUrl: text("base_url").notNull(),
  apiType: apiTypeEnum("api_type").notNull(),
  name: text("name"),
  description: text("description"),
  specUrl: text("spec_url"),
  specHash: text("spec_hash"),
  specVersion: text("spec_version"),
  specLastFetchedAt: timestamp("spec_last_fetched_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  createdBy: varchar("created_by").references(() => users.id).notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
}, (table) => [
  uniqueIndex("UQ_apis_parent_base_url").on(table.parentAssetId, table.baseUrl),
  index("IDX_apis_parent_asset_id").on(table.parentAssetId),
]);

export type Api = typeof apis.$inferSelect;
export type InsertApi = typeof apis.$inferInsert;
```

**Anti-patterns (avoid):**
- Declaring a separate CHECK constraint when an enum suffices (e.g., `apiType` is enum, good). For `method` the CONTEXT explicitly chose CHECK over enum — deliberate, keep it.
- Forgetting `onDelete: 'cascade'` on `api_id → apis.id` and `api_endpoint_id → api_endpoints.id` FKs. Deleting an API must cascade through all children.

### Pattern 2: Runtime idempotent guard (`ensureApiTables`)

**What:** Runtime check in `database-init.ts` that verifies tables/enums/indexes exist and creates them with `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`. Runs on every boot; safe to re-run.
**When to use:** After `db:push` (which does the heavy lifting), as a belt-and-suspenders check for on-premise appliances where `db:push` may not be run consistently. Pattern lives next to the existing `edr_deployments` guard (database-init.ts:107-136).

**Example:**
```typescript
// Source: server/storage/database-init.ts:107-136 (edr_deployments precedent)
export async function ensureApiTables(): Promise<void> {
  // 1. Check if table exists
  const apisCheck = await db.execute(sql`
    SELECT tablename FROM pg_tables
    WHERE schemaname = 'public' AND tablename = 'apis'
  `);
  if ((apisCheck.rowCount ?? 0) === 0) {
    log.info('creating apis table');
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS apis (
        id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid(),
        parent_asset_id VARCHAR NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
        base_url TEXT NOT NULL,
        api_type api_type_enum NOT NULL,
        name TEXT, description TEXT, spec_url TEXT,
        spec_hash TEXT, spec_version TEXT, spec_last_fetched_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
        created_by VARCHAR NOT NULL REFERENCES users(id),
        updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
      )
    `);
    await db.execute(sql`CREATE UNIQUE INDEX "UQ_apis_parent_base_url" ON apis (parent_asset_id, base_url)`);
    await db.execute(sql`CREATE INDEX "IDX_apis_parent_asset_id" ON apis (parent_asset_id)`);
    log.info('apis table created');
  }

  // 2. Check pgEnum existence
  const enumCheck = await db.execute(sql`
    SELECT typname FROM pg_type WHERE typname = 'api_type_enum'
  `);
  log.info({ hasApiTypeEnum: (enumCheck.rowCount ?? 0) > 0 }, 'api_type_enum status');

  // ... repeat for api_endpoints, api_findings, owasp_api_category, api_finding_status
}
```

**Call site:**
```typescript
// In initializeDatabaseStructure() — append after edr_deployments block:
await ensureApiTables();
```

**Anti-pattern:** Do NOT throw on failure inside the guard. Existing pattern (`try { ... } catch (error) { log.error(...); /* don't throw */ }`) keeps the app booting in fallback mode. Follow it.

### Pattern 3: Route with Zod + RBAC + pt-BR errors

**What:** Express route that gates on `isAuthenticatedWithPasswordCheck` + `requireOperator`, validates body with Zod schema from `@shared/schema`, calls `storage.*`, writes audit log, returns pt-BR error messages.
**When to use:** `POST /api/v1/apis`.

**Example:**
```typescript
// Source: server/routes/assets.ts:43-64 + server/routes/credentials.ts:23-61
import type { Express } from "express";
import { storage } from "../storage";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { requireOperator } from "./middleware";
import { insertApiSchema } from "@shared/schema";
import { createLogger } from '../lib/logger';

const log = createLogger('routes:apis');

export function registerApiRoutes(app: Express) {
  app.post('/api/v1/apis', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const body = insertApiSchema.parse(req.body);

      // Validate parent exists and is web_application
      const parent = await storage.getAsset(body.parentAssetId);
      if (!parent) {
        return res.status(400).json({ message: "Ativo pai não encontrado" });
      }
      if (parent.type !== 'web_application') {
        return res.status(400).json({
          message: "Apenas ativos do tipo web_application podem hospedar uma API"
        });
      }

      // Normalize baseUrl
      const normalized = normalizeTarget(body.baseUrl);
      if (!normalized) {
        return res.status(400).json({ message: "URL base inválida" });
      }

      const api = await storage.createApi({ ...body, baseUrl: normalized }, userId);

      await storage.logAudit({
        actorId: userId, action: 'create', objectType: 'api',
        objectId: api.id, before: null, after: api,
      });

      log.info({ apiId: api.id, parentAssetId: body.parentAssetId,
                baseUrl: normalized, apiType: body.apiType }, 'api registered manually');
      res.status(201).json(api);
    } catch (error: any) {
      // Postgres unique_violation = 23505
      if (error?.code === '23505') {
        return res.status(409).json({
          message: "API já cadastrada para esse ativo com essa URL base"
        });
      }
      log.error({ err: error }, 'failed to create api');
      res.status(400).json({ message: "Falha ao cadastrar API" });
    }
  });
}
```

**Anti-patterns:**
- Catching Zod errors at status 500 — they're user-input errors, return 400 with `error.errors` digested to pt-BR.
- Validating uniqueness at application layer (`SELECT ... WHERE ...`) then inserting — race condition. Let the UNIQUE index + error code 23505 handle it.

### Pattern 4: Storage facade + IStorage extension

**What:** One function per operation, `db` at top, typed by `$inferSelect`/`$inferInsert`. Exported functions referenced by the `DatabaseStorage` class in `storage/index.ts`. Interface `IStorage` lists all method signatures.
**When to use:** Every new table operation.

**Example:**
```typescript
// server/storage/apis.ts  (NEW)
// Source: pattern from server/storage/assets.ts + server/storage/edrDeployments.ts
import { db } from "../db";
import { apis, type Api, type InsertApi } from "@shared/schema";
import { eq, desc, and, sql } from "drizzle-orm";
import { createLogger } from '../lib/logger';

const log = createLogger('storage');

export async function getApi(id: string): Promise<Api | undefined> {
  const [api] = await db.select().from(apis).where(eq(apis.id, id));
  return api;
}

export async function listApisByParent(parentAssetId: string): Promise<Api[]> {
  return await db.select().from(apis)
    .where(eq(apis.parentAssetId, parentAssetId))
    .orderBy(desc(apis.createdAt));
}

export async function createApi(data: InsertApi, userId: string): Promise<Api> {
  const [created] = await db.insert(apis)
    .values({ ...data, createdBy: userId })
    .returning();
  return created;
}

export async function promoteApiFromBackfill(
  parentAssetId: string, baseUrl: string, apiType: 'rest' | 'graphql' | 'soap',
  opts: { specUrl?: string; systemUserId: string }
): Promise<Api | null> {
  // Idempotent: onConflictDoNothing keyed on (parent_asset_id, base_url)
  const [created] = await db.insert(apis)
    .values({
      parentAssetId, baseUrl, apiType,
      specUrl: opts.specUrl ?? null,
      createdBy: opts.systemUserId,
    })
    .onConflictDoNothing({ target: [apis.parentAssetId, apis.baseUrl] })
    .returning();
  return created ?? null;
}
```

**Anti-patterns:**
- Importing `createApi` in `routes/apis.ts` directly — always go through `storage.createApi`. Keeps mocking + interface contract stable.
- Forgetting to extend `IStorage` in `server/storage/interface.ts` AND wire the method in `DatabaseStorage` class in `server/storage/index.ts`. Both files must change; TypeScript won't let you skip either.

### Pattern 5: Backfill CLI (probe → promote)

**What:** Standalone script runnable via `tsx`, parses `--dry-run`, logs with `console.log` (not pino — one-shot CLI), exits 0/1.
**When to use:** HIER-04 backfill.

**Example skeleton:**
```typescript
// server/scripts/backfillApiDiscovery.ts (NEW)
// Template: server/scripts/backfillWebAppParent.ts
import { db } from "../db";
import { assets, apis } from "@shared/schema";
import { eq, and, sql, notExists } from "drizzle-orm";

const SPEC_PATHS = [
  '/openapi.json', '/swagger.json', '/v2/api-docs',
  '/v3/api-docs', '/api-docs', '/swagger-ui.html', '/graphql',
];
const PROBE_TIMEOUT_MS = 5000;
const CONCURRENCY = 10;

type Detection = {
  apiType: 'rest' | 'graphql' | 'soap';
  specUrl?: string;
};

async function probeWebApp(baseUrl: string): Promise<Detection | null> {
  // 1. Spec paths (HEAD then GET)
  for (const p of SPEC_PATHS) {
    const url = new URL(p, baseUrl).toString();
    try {
      const res = await fetch(url, {
        method: 'GET', signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
        redirect: 'follow',
      });
      if (!res.ok) continue;
      const ct = res.headers.get('content-type') ?? '';
      if (p === '/graphql') return { apiType: 'graphql', specUrl: url };
      if (ct.includes('application/json')) return { apiType: 'rest', specUrl: url };
    } catch { /* timeout or network — continue */ }
  }
  // 2. /api root
  try {
    const apiRoot = new URL('/api', baseUrl).toString();
    const res = await fetch(apiRoot, { method: 'GET', signal: AbortSignal.timeout(PROBE_TIMEOUT_MS) });
    if (res.ok && (res.headers.get('content-type') ?? '').includes('application/json')) {
      return { apiType: 'rest' };
    }
  } catch {}
  // 3. Root JSON
  try {
    const res = await fetch(baseUrl, { method: 'GET', signal: AbortSignal.timeout(PROBE_TIMEOUT_MS) });
    if (res.ok && (res.headers.get('content-type') ?? '').includes('application/json')) {
      return { apiType: 'rest' };
    }
  } catch {}
  return null;
}

// Concurrency limiter — no npm dep
async function batchWithLimit<T, R>(items: T[], limit: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const results: R[] = [];
  for (let i = 0; i < items.length; i += limit) {
    const chunk = items.slice(i, i + limit);
    const settled = await Promise.all(chunk.map(fn));
    results.push(...settled);
  }
  return results;
}

async function main() {
  const dryRun = process.argv.includes('--dry-run');
  console.log(`[backfill-api-discovery] starting — dry-run=${dryRun}`);

  // Load web_apps with NO api children (NOT EXISTS).
  const candidates = await db.select({ id: assets.id, value: assets.value })
    .from(assets)
    .where(and(
      eq(assets.type, 'web_application' as any),
      // Using raw sql() for NOT EXISTS subquery — drizzle helper also exists.
      sql`NOT EXISTS (SELECT 1 FROM apis WHERE apis.parent_asset_id = ${assets.id})`
    ));

  console.log(`[backfill-api-discovery] candidates=${candidates.length}`);

  let promoted = 0, skipped = 0;
  await batchWithLimit(candidates, CONCURRENCY, async (wa) => {
    const detection = await probeWebApp(wa.value);
    if (!detection) { skipped++; return; }
    if (dryRun) {
      console.log(`  DRY-RUN: would promote ${wa.value} → apiType=${detection.apiType}${detection.specUrl ? ` specUrl=${detection.specUrl}` : ''}`);
      promoted++;
      return;
    }
    try {
      await db.insert(apis).values({
        parentAssetId: wa.id, baseUrl: wa.value, apiType: detection.apiType,
        specUrl: detection.specUrl ?? null, createdBy: 'system',
      }).onConflictDoNothing();
      console.log(`  ✅ promoted ${wa.value} → ${detection.apiType}`);
      promoted++;
    } catch (err) {
      console.error(`  ⚠️  failed to insert api for ${wa.value}:`, err);
      skipped++;
    }
  });

  console.log(`[backfill-api-discovery] DONE promoted=${promoted} skipped=${skipped} mode=${dryRun ? 'dry-run' : 'live'}`);
  process.exit(0);
}

main().catch(err => { console.error('[backfill-api-discovery] fatal', err); process.exit(1); });
```

**Anti-patterns:**
- Using pino in a CLI — the on-premise operator wants readable stdout, not JSON.
- Relying on `Promise.allSettled` with no limit — against 1000 targets you'll spam the network. Use batch-with-limit.
- Forgetting the `'system'` user fallback (`createdBy: 'system'`). The system user is seeded by `ensureSystemUserExists()`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| HTTP request in backfill | Axios or node-fetch | Native `fetch` (Node 20.16) | Zero deps; supports AbortSignal natively. |
| Per-probe timeout | Manual `setTimeout`+race | `AbortSignal.timeout(5000)` | Built-in Node 20; cleaner signature. |
| Concurrency limit | p-limit npm package | Inline `batchWithLimit()` closure | One use site; no dep surface. |
| URL validation | Custom regex | `new URL(...)` + existing `normalizeTarget()` | Matches `server/services/journeys/urls.ts` logic already in use. |
| UNIQUE enforcement | `SELECT` then `INSERT` | Postgres UNIQUE index + `error.code === '23505'` | Race-condition-free. |
| Idempotent upsert in backfill | Pre-query check | `.onConflictDoNothing({target: [...]})` | One DB round-trip. |
| UUID generation | `crypto.randomUUID()` in app code | Postgres `gen_random_uuid()` default | Keeps schema self-describing. |
| Migration file | Hand-edit `./migrations/*.sql` | `drizzle-kit push` + runtime `ensureApiTables()` guard | Project already standardized on push + runtime guard. |
| Zod from scratch | Hand-crafted `z.object({...})` for apis | `createInsertSchema(apis).omit({...}).extend({...}).refine(...)` | Auto-tracks schema drift; matches shared/schema.ts convention (~25 existing usages). |

**Key insight:** Phase 9 is an *additive* data phase in a mature codebase. Every "how do I do X" question has precedent in the repo. Deviating = scope creep.

## Common Pitfalls

### Pitfall 1: `pg_indexes` is case-sensitive on the quoted `indexname`
**What goes wrong:** `database-init.ts` checks `WHERE indexname = 'UQ_apis_parent_base_url'` but the CREATE INDEX was unquoted (`CREATE UNIQUE INDEX UQ_apis_parent_base_url ...`) — Postgres lowercased it to `uq_apis_parent_base_url` and the check never matches, so the guard re-runs and throws `relation already exists`.
**Why it happens:** Postgres folds unquoted identifiers to lowercase; `pg_indexes.indexname` stores the folded name.
**How to avoid:** Always quote indexname in CREATE: `CREATE UNIQUE INDEX "UQ_apis_parent_base_url" ON apis ...` (matching existing precedent in database-init.ts:37, 66, 90). Then the `WHERE indexname = 'UQ_apis_parent_base_url'` check matches exactly.
**Warning signs:** Boot logs show "creating X" on every restart, even after first successful boot.

### Pitfall 2: `pgEnum` values are immutable without migration
**What goes wrong:** Someone "adds" a value to `owaspApiCategoryEnum` array in shared/schema.ts expecting `db:push` to pick it up. Silent no-op — the Postgres enum type stays at 10 values; inserts with the new value fail with `invalid input value for enum`.
**Why it happens:** Postgres enum mutation requires `ALTER TYPE x ADD VALUE 'y'`, which must be in its own transaction. `drizzle-kit push` detects enum changes inconsistently.
**How to avoid:** Never mutate an existing enum. For OWASP 2027, introduce a new enum `owasp_api_category_2027` — CONTEXT already locks this decision. For `api_type_enum`, if SOAP needs expansion, create a new pgEnum and add a column; never re-order the existing one.
**Warning signs:** `invalid input value for enum` at runtime; `db:push` that reports "nothing to do" despite code change.

### Pitfall 3: Circular FK between `api_findings.promotedThreatId` ↔ `threats`
**What goes wrong:** `api_findings.promotedThreatId → threats.id` makes the two tables depend on each other if one later adds `threats.apiFindingId → api_findings.id` (Phase 14 *might* do this). Drizzle introspection order becomes finicky; `DROP TABLE` order becomes critical.
**Why it happens:** Mutual references create a "which one do I create first" cycle.
**How to avoid:** Keep the reference one-way. `api_findings.promotedThreatId` NULL-able with `ON DELETE SET NULL` is fine — `threats` has no reverse FK; Phase 14 should add a `sourceTable` + `sourceId` pair on `threats` (polymorphic) rather than a typed FK back. Flag this to the Phase 14 planner.
**Warning signs:** `DROP TABLE threats CASCADE` fails; `pg_dump` ordering warnings.

### Pitfall 4: `createInsertSchema` + `.omit()` + `.refine()` behavior in drizzle-zod 0.7
**What goes wrong:** Chaining `createInsertSchema(apis).omit({...}).refine(...)` works, but the error message of a `.refine()` is a single string — you can't attach per-field errors out-of-the-box like with `z.object().superRefine()`.
**Why it happens:** drizzle-zod returns a `ZodObject` whose `.refine()` just decorates it; multi-field errors need `.superRefine()` or post-parse validation.
**How to avoid:** For the `parentAssetId → web_application` cross-DB check, do NOT put it inside the Zod schema. Do it in the route after `.parse()` returns (pattern in §Code Examples → Route). The Zod schema validates *shape*, the route validates *semantics*.
**Warning signs:** Zod error objects with just `{ message: "..." }` and no `path` array when you expected path-level errors.

### Pitfall 5: `db.execute(sql\`...\`)` does NOT return typed rows
**What goes wrong:** `const result = await db.execute(sql\`SELECT tablename ...\`); if (result.rowCount === 0)` — but drizzle 0.39 wraps pg result, so on some drivers `rowCount` may be `null` (not 0) for DDL/SELECT distinction.
**Why it happens:** `db.execute` is a thin pg wrapper; `rowCount` follows node-postgres semantics (`null` when unknown).
**How to avoid:** Always use `(result.rowCount ?? 0) === 0` — matches the existing pattern in database-init.ts (lines 24, 59, 80, 113). Do NOT use `!result.rowCount` (falsy on both null and 0 — but less explicit).
**Warning signs:** Inconsistent guard behavior between pg-node versions.

### Pitfall 6: Backfill `NOT EXISTS` subquery with Drizzle
**What goes wrong:** Writing `sql\`NOT EXISTS (SELECT 1 FROM apis WHERE apis.parent_asset_id = ${assets.id})\`` — if `assets.id` reference isn't interpolated as a column, it binds as a string literal.
**Why it happens:** Drizzle's `sql` tag distinguishes raw SQL from parameterized values; column references need special handling.
**How to avoid:** Use Drizzle's `notExists` helper:
```typescript
import { notExists } from "drizzle-orm";
.where(and(
  eq(assets.type, 'web_application'),
  notExists(db.select().from(apis).where(eq(apis.parentAssetId, assets.id)))
))
```
Or accept the raw SQL with explicit column reference: `sql\`NOT EXISTS (SELECT 1 FROM apis WHERE apis.parent_asset_id = assets.id)\``. Both work; the `notExists` helper is more type-safe.
**Warning signs:** SQL runs but matches nothing (or everything) because the subquery correlates against a string.

### Pitfall 7: `fetch` redirects + timeout interaction
**What goes wrong:** `/swagger.json` redirects to `/docs/` → `/docs/index.html`; a timeout that applies only to the first request cancels before the redirect fetches.
**Why it happens:** `AbortSignal.timeout(5000)` tracks wall-clock from signal creation; redirects consume that budget.
**How to avoid:** Treat 5s as a total-request budget (acceptable). If a target redirects and takes >5s, it's too slow to probe in a backfill anyway — skip it. Document this in the CLI log output: `timeout after 5s (redirects included)`.
**Warning signs:** Slow web_app targets reported as "no api indicator" when they do have a spec.

### Pitfall 8: `onConflictDoNothing` + `.returning()`
**What goes wrong:** Backfill calls `.onConflictDoNothing().returning()` and expects the existing row back on conflict — but `onConflictDoNothing` returns an empty array, not the existing row.
**Why it happens:** It's `DO NOTHING`, not `DO UPDATE SET ... RETURNING`.
**How to avoid:** Accept `undefined` from the `[created] = await ...` destructuring. Log "already exists" and move on. If the caller needs the existing row, do a follow-up `SELECT`. For the backfill, we don't need it.
**Warning signs:** Backfill logs "promoted X" but API count doesn't go up (silently ignored).

### Pitfall 9: `promotedThreatId FK` on empty threats
**What goes wrong:** Someone tests with an empty `threats` table; inserting an `api_findings` with `promotedThreatId = <random uuid>` violates FK (expected), but a NULL insert path isn't tested.
**Why it happens:** Phase 9 never sets `promotedThreatId`; Phase 14 will. Tests that omit this field must prove NULL is accepted.
**How to avoid:** Nyquist test: explicit test `insertApiFinding omits promotedThreatId → persists NULL`.
**Warning signs:** Phase 14 integration break because Phase 9 accidentally made the column `notNull`.

## Code Examples

### Adding pgEnum values in schema.ts

```typescript
// Source: shared/schema.ts:34-82 existing precedent
export const apiTypeEnum = pgEnum('api_type_enum', ['rest', 'graphql', 'soap']);

export const owaspApiCategoryEnum = pgEnum('owasp_api_category', [
  'api1_bola_2023',
  'api2_broken_auth_2023',
  'api3_bopla_2023',
  'api4_rate_limit_2023',
  'api5_bfla_2023',
  'api6_business_flow_2023',
  'api7_ssrf_2023',
  'api8_misconfiguration_2023',
  'api9_inventory_2023',
  'api10_unsafe_consumption_2023',
]);

export const apiFindingStatusEnum = pgEnum('api_finding_status', [
  'open', 'triaged', 'false_positive', 'closed',
]);
```

### `api_endpoints` table with CHECK constraint

```typescript
// Source: drizzle-orm 0.39.1 check() helper — verified in node_modules/drizzle-orm/pg-core/checks.d.cts
import { check } from "drizzle-orm/pg-core";

export const apiEndpoints = pgTable("api_endpoints", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  apiId: varchar("api_id").references(() => apis.id, { onDelete: 'cascade' }).notNull(),
  method: text("method").notNull(),
  path: text("path").notNull(),
  pathParams: jsonb("path_params").$type<Array<{name: string; type?: string; required?: boolean; example?: unknown}>>().default([]).notNull(),
  queryParams: jsonb("query_params").$type<Array<{name: string; type?: string; required?: boolean; example?: unknown}>>().default([]).notNull(),
  headerParams: jsonb("header_params").$type<Array<{name: string; type?: string; required?: boolean; example?: unknown}>>().default([]).notNull(),
  requestSchema: jsonb("request_schema").$type<Record<string, unknown>>(),
  responseSchema: jsonb("response_schema").$type<Record<string, unknown>>(),
  requiresAuth: boolean("requires_auth"), // NULL / true / false
  discoverySources: text("discovery_sources").array().$type<Array<'spec'|'crawler'|'kiterunner'|'manual'>>().notNull().default(sql`ARRAY[]::text[]`),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
}, (table) => [
  uniqueIndex("UQ_api_endpoints_api_method_path").on(table.apiId, table.method, table.path),
  index("IDX_api_endpoints_api_id").on(table.apiId),
  check("CK_api_endpoints_method",
    sql`${table.method} IN ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS')`),
]);
```

### `api_findings` table

```typescript
export const apiFindings = pgTable("api_findings", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  apiEndpointId: varchar("api_endpoint_id").references(() => apiEndpoints.id, { onDelete: 'cascade' }).notNull(),
  jobId: varchar("job_id").references(() => jobs.id),
  owaspCategory: owaspApiCategoryEnum("owasp_category").notNull(),
  severity: threatSeverityEnum("severity").notNull(),
  status: apiFindingStatusEnum("status").default('open').notNull(),
  title: text("title").notNull(),
  description: text("description"),
  remediation: text("remediation"),
  riskScore: real("risk_score"), // 0-100, null until scored
  evidence: jsonb("evidence").$type<ApiFindingEvidence>().default({} as any).notNull(),
  promotedThreatId: varchar("promoted_threat_id").references(() => threats.id, { onDelete: 'set null' }),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
}, (table) => [
  index("IDX_api_findings_endpoint_id").on(table.apiEndpointId),
  index("IDX_api_findings_job_id").on(table.jobId),
  index("IDX_api_findings_owasp_category").on(table.owaspCategory),
  index("IDX_api_findings_severity").on(table.severity),
  index("IDX_api_findings_status").on(table.status),
]);

export type ApiFinding = typeof apiFindings.$inferSelect;
export type InsertApiFinding = typeof apiFindings.$inferInsert;
```

### Evidence JSONB Zod shape (shared between route, backfill, future Phase 14)

```typescript
// shared/schema.ts — export alongside insertApiFindingSchema
export const apiFindingEvidenceSchema = z.object({
  request: z.object({
    method: z.string().min(1),
    url: z.string().url(),
    headers: z.record(z.string()).optional(),
    bodySnippet: z.string().max(8192).optional(), // Phase 14 FIND-02 truncates to 8KB
  }),
  response: z.object({
    status: z.number().int().min(100).max(599),
    headers: z.record(z.string()).optional(),
    bodySnippet: z.string().max(8192).optional(),
  }),
  extractedValues: z.record(z.unknown()).optional(),
  context: z.string().optional(),
}).strict();

export type ApiFindingEvidence = z.infer<typeof apiFindingEvidenceSchema>;

export const insertApiFindingSchema = createInsertSchema(apiFindings, {
  evidence: apiFindingEvidenceSchema,
}).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  promotedThreatId: true,
  riskScore: true,
});
```

### `insertApiSchema` for route body

```typescript
// shared/schema.ts
export const insertApiSchema = createInsertSchema(apis).omit({
  id: true, createdAt: true, createdBy: true, updatedAt: true,
  specHash: true, specVersion: true, specLastFetchedAt: true,
}).extend({
  // Re-state required for clarity; createInsertSchema already inferred these from notNull().
  parentAssetId: z.string().uuid("ID de ativo pai inválido"),
  baseUrl: z.string().url("URL base inválida"),
  apiType: z.enum(['rest', 'graphql', 'soap']),
});
```

### OWASP pt-BR labels constant

```typescript
// shared/owaspApiCategories.ts (NEW)
// Source URLs verified 2026-04-18 via owasp.org/API-Security/editions/2023/en/0x11-t10/
export const OWASP_API_CATEGORY_LABELS = {
  api1_bola_2023: {
    codigo: "API1:2023",
    titulo: "Quebra de Autorização em Nível de Objeto",
    tituloIngles: "Broken Object Level Authorization",
    referenciaOwasp: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
  },
  api2_broken_auth_2023: {
    codigo: "API2:2023",
    titulo: "Autenticação Quebrada",
    tituloIngles: "Broken Authentication",
    referenciaOwasp: "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
  },
  api3_bopla_2023: {
    codigo: "API3:2023",
    titulo: "Quebra de Autorização em Nível de Propriedade do Objeto",
    tituloIngles: "Broken Object Property Level Authorization",
    referenciaOwasp: "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
  },
  api4_rate_limit_2023: {
    codigo: "API4:2023",
    titulo: "Consumo Irrestrito de Recursos",
    tituloIngles: "Unrestricted Resource Consumption",
    referenciaOwasp: "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
  },
  api5_bfla_2023: {
    codigo: "API5:2023",
    titulo: "Quebra de Autorização em Nível de Função",
    tituloIngles: "Broken Function Level Authorization",
    referenciaOwasp: "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
  },
  api6_business_flow_2023: {
    codigo: "API6:2023",
    titulo: "Acesso Irrestrito a Fluxos de Negócio Sensíveis",
    tituloIngles: "Unrestricted Access to Sensitive Business Flows",
    referenciaOwasp: "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
  },
  api7_ssrf_2023: {
    codigo: "API7:2023",
    titulo: "Server Side Request Forgery (SSRF)",
    tituloIngles: "Server Side Request Forgery",
    referenciaOwasp: "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
  },
  api8_misconfiguration_2023: {
    codigo: "API8:2023",
    titulo: "Configuração Incorreta de Segurança",
    tituloIngles: "Security Misconfiguration",
    referenciaOwasp: "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
  },
  api9_inventory_2023: {
    codigo: "API9:2023",
    titulo: "Gestão de Inventário Inadequada",
    tituloIngles: "Improper Inventory Management",
    referenciaOwasp: "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
  },
  api10_unsafe_consumption_2023: {
    codigo: "API10:2023",
    titulo: "Consumo Inseguro de APIs",
    tituloIngles: "Unsafe Consumption of APIs",
    referenciaOwasp: "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
  },
} as const;

export type OwaspApiCategory = keyof typeof OWASP_API_CATEGORY_LABELS;

export const DISCOVERY_SOURCES = ['spec', 'crawler', 'kiterunner', 'manual'] as const;
export type DiscoverySource = typeof DISCOVERY_SOURCES[number];
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| OWASP API Top 10 2019 | OWASP API Top 10 2023 | 2023 | 3 new categories (API3 BOPLA, API6 Business Flows, API10 Unsafe Consumption); API10 Logging removed. Phase 9 must use 2023. |
| `node-fetch` / `axios` in Node scripts | Native `fetch` + `AbortSignal.timeout()` | Node 18 (fetch), Node 20+ (timeout) | Project is on Node 20.16; both are available — no deps. |
| `setTimeout`+race for HTTP timeouts | `AbortSignal.timeout(ms)` | Node 17.3 / ubiquitous in 20 | Cleaner API, built-in. |
| drizzle-kit migrations folder | `db:push` + runtime guard | Project decision (see drizzle.config.ts + database-init.ts) | SamurEye is appliance-deployed; push is simpler than versioned migrations for single-tenant installs. |
| Hand-written Zod for DB inputs | `createInsertSchema` from drizzle-zod | Project convention, ~25 insertSchemas in shared/schema.ts | Schema drift auto-detected at compile time. |

**Deprecated/outdated:**
- `node-fetch` — replaced by native `fetch` in Node 18+; not in the project.
- OWASP API Top 10 2019 categories (API10 Insufficient Logging) — replaced by 2023 edition.
- External UUID generation in application code — replaced by `gen_random_uuid()` in Postgres default.

## Open Questions

1. **Should `apis` have a `discoverySource` column?**
   - What we know: CONTEXT § "Backfill" says the backfill creates row in `apis` with `discoverySources` "ainda NÃO existe em `apis` (só em `api_endpoints`); para `apis`, registrar no log que foi 'backfill'". Meaning: no column on `apis` tracking who created it.
   - What's unclear: Phase 11 may want to know "was this API manual, backfilled, or spec-discovered?" to prioritize re-scan frequency.
   - Recommendation: Defer. Phase 11 can add a nullable column aditivamente if it surfaces as a need. For Phase 9, rely on `log.info({ source: 'backfill' | 'manual' }, '...')` and an eventual auditLog row.

2. **Does the backfill need to respect the existing `inferParentHostForWebApp` chain?**
   - What we know: web_app asset already has `parentAssetId → host`. Backfill creates `apis.parentAssetId → web_app_asset`. Chain: host ← web_app ← api.
   - What's unclear: Does UI (Phase 16) expect to traverse the chain from host all the way to api, or only from web_app?
   - Recommendation: Phase 9 just creates the row; getAssetsTree (already in storage/assets.ts:19) will need a Phase 16 extension to include apis. Flag to Phase 16 planner.

3. **Can `backfill` legally probe targets at runtime without user acknowledgment (JRNY-02)?**
   - What we know: JRNY-02 ("authorization acknowledgment") is a Phase 15 requirement for *journeys*. The backfill is a CLI operated by the on-premise admin.
   - What's unclear: Is there an implicit consent model for assets the user already registered as web_applications?
   - Recommendation: The backfill only sends GET/HEAD to assets *already registered by the user*. The registration IS the consent. Document this in `docs/operations/backfill-api-discovery.md` as a legal-posture statement. No blocker for Phase 9.

4. **Should the route validate that `specUrl` lives under the same origin as `baseUrl`?**
   - What we know: CONTEXT § "Registro manual" doesn't specify.
   - What's unclear: A user could submit `baseUrl=https://api.x.com:443` and `specUrl=https://evil.com/openapi.json` — probably wrong, but not security-critical at Phase 9.
   - Recommendation: Do NOT enforce. Some APIs legitimately host specs on CDNs. If a Phase 11 concern arises, add a Zod `.refine()` later.

5. **Does `ensureApiTables` need to run BEFORE or AFTER `ensureSystemUserExists`?**
   - What we know: `ensureSystemUserExists` runs first (database-init.ts:14). `apis.createdBy` FKs to users. Backfill uses `createdBy: 'system'`.
   - Recommendation: AFTER. Order: `ensureSystemUserExists → existing checks → ensureApiTables`. Matches dependency direction.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Vitest 4.0.18 |
| Config file | `vitest.config.ts` |
| Quick run command | `npm test -- <pattern>` (e.g. `npm test -- apis`) |
| Full suite command | `npm test` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| HIER-01 | Schema declares `apis` with UNIQUE(parent_asset_id, base_url) + FK to assets | unit (schema introspection) | `npm test -- ensureApiTables` | ❌ Wave 0 |
| HIER-01 | `apis` row insert rejects duplicate (parent_asset_id, base_url) with code 23505 | integration (DB) | `npm test -- apis.storage` | ❌ Wave 0 |
| HIER-02 | Schema declares `api_endpoints` with all 8 required columns (method, path, 3 params jsonb, 2 schemas jsonb, requiresAuth, discoverySources) | unit (schema introspection via information_schema.columns) | `npm test -- ensureApiTables` | ❌ Wave 0 |
| HIER-02 | `api_endpoints.method` CHECK rejects `'FOO'` | integration (DB) | `npm test -- apiEndpoints.storage` | ❌ Wave 0 |
| HIER-02 | `api_endpoints.requiresAuth` accepts NULL / true / false (tri-valor) | integration (DB) | `npm test -- apiEndpoints.storage` | ❌ Wave 0 |
| HIER-03 | `POST /api/v1/apis` happy path — 201 + returns row | integration (supertest or direct handler call) | `npm test -- routes.apis` | ❌ Wave 0 |
| HIER-03 | `POST /api/v1/apis` rejects duplicate — 409 with pt-BR message | integration | `npm test -- routes.apis` | ❌ Wave 0 |
| HIER-03 | `POST /api/v1/apis` rejects parent != web_application — 400 | integration | `npm test -- routes.apis` | ❌ Wave 0 |
| HIER-03 | `POST /api/v1/apis` rejects invalid baseUrl — 400 Zod error | unit (insertApiSchema) | `npm test -- insertApiSchema` | ❌ Wave 0 |
| HIER-03 | `POST /api/v1/apis` requires operator RBAC — 403 for read_only | integration | `npm test -- routes.apis` | ❌ Wave 0 |
| HIER-04 | Backfill `--dry-run` does not mutate DB | integration (script invocation + row count assertion) | `npm test -- backfillApiDiscovery` | ❌ Wave 0 |
| HIER-04 | Backfill skips web_apps that already have ≥1 api (NOT EXISTS) | integration | `npm test -- backfillApiDiscovery` | ❌ Wave 0 |
| HIER-04 | Backfill promotes when fetch mock returns JSON Content-Type on `/api` | unit (probeWebApp extracted) | `npm test -- backfillProbe` | ❌ Wave 0 |
| HIER-04 | Backfill respects concurrency=10 (semaphore enforced) | unit (batchWithLimit) | `npm test -- backfillProbe` | ❌ Wave 0 |
| HIER-04 | Backfill respects 5s timeout | unit (AbortSignal) | `npm test -- backfillProbe` | ❌ Wave 0 |
| FIND-01 | `api_findings` schema has all columns (11 listed) | unit (schema introspection) | `npm test -- ensureApiTables` | ❌ Wave 0 |
| FIND-01 | `apiFindingEvidenceSchema` accepts canonical shape and rejects extras | unit | `npm test -- apiEvidence` | ❌ Wave 0 |
| FIND-01 | `apiFindingEvidenceSchema` accepts missing optional fields (bodySnippet, headers, extractedValues, context) | unit | `npm test -- apiEvidence` | ❌ Wave 0 |
| FIND-01 | `api_findings.promotedThreatId` accepts NULL | integration | `npm test -- apiFindings.storage` | ❌ Wave 0 |
| FIND-01 | `api_findings.owaspCategory` accepts all 10 enum values | unit | `npm test -- owaspApiCategories` | ❌ Wave 0 |
| FIND-01 | `OWASP_API_CATEGORY_LABELS` has 10 entries matching enum values | unit | `npm test -- owaspApiCategories` | ❌ Wave 0 |
| FIND-01 | `OWASP_API_CATEGORY_LABELS` URLs all resolve to owasp.org/... | unit (URL parsing, no network) | `npm test -- owaspApiCategories` | ❌ Wave 0 |
| HIER-01..FIND-01 | `ensureApiTables()` runs without error on already-provisioned DB (idempotency) | integration | `npm test -- ensureApiTables` | ❌ Wave 0 |
| HIER-01..FIND-01 | `ensureApiTables()` introspects via pg_tables + pg_type + pg_indexes correctly | integration | `npm test -- ensureApiTables` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `npm test -- <relevant-pattern>` — e.g. `npm test -- apis` runs all apis-related tests in <15s.
- **Per wave merge:** `npm test` full suite (~60s).
- **Phase gate:** Full suite green + manual sanity run of `npx tsx --env-file=.env server/scripts/backfillApiDiscovery.ts --dry-run` against a dev DB.

### Wave 0 Gaps

All test files are new. No existing test infrastructure covers Phase 9 concerns.

- [ ] `server/__tests__/ensureApiTables.test.ts` — introspects pg_tables, pg_type, pg_indexes; asserts tables + enums + indexes created idempotently. Covers HIER-01, HIER-02, FIND-01 schema shape.
- [ ] `server/__tests__/insertApiSchema.test.ts` — Zod happy path + invalid URL + bad enum + missing required. Covers HIER-03.
- [ ] `server/__tests__/apiEvidence.test.ts` — `apiFindingEvidenceSchema` accepts canonical shape, rejects unknown keys (`.strict()`), permits optional fields. Covers FIND-01 shape.
- [ ] `server/__tests__/owaspApiCategories.test.ts` — 10 labels, URLs match `owasp.org`, keys match enum values. Covers FIND-01 labels.
- [ ] `server/__tests__/routes.apis.test.ts` — POST happy path (201), duplicate (409), bad parent (400), invalid URL (400), RBAC (403). Uses `supertest` against an Express app instance OR direct handler invocation with mocked storage. Covers HIER-03.
- [ ] `server/__tests__/apis.storage.test.ts` — createApi, listApisByParent, promoteApiFromBackfill, onConflictDoNothing. Integration (real DB). Covers HIER-01.
- [ ] `server/__tests__/apiEndpoints.storage.test.ts` — create endpoint with all 3 param JSONB arrays, CHECK rejection of bad method, requiresAuth tri-valor. Covers HIER-02.
- [ ] `server/__tests__/apiFindings.storage.test.ts` — create finding with evidence JSONB, promotedThreatId NULL, all 10 OWASP categories, all 4 statuses. Covers FIND-01.
- [ ] `server/__tests__/backfillApiDiscovery.test.ts` — probeWebApp extracted + batchWithLimit + dry-run flag + NOT EXISTS query. Uses `vi.mock(globalThis.fetch)` to simulate target responses. Covers HIER-04.

**Framework install:** none — vitest already installed and configured. No new dev deps.

**Supertest note:** Not currently in `package.json`. Two options:
1. Add `supertest` as a devDependency (introduces one dep just for Phase 9 route tests).
2. Invoke the handler directly with mock `req`/`res` objects (pattern not yet established in repo, but straightforward).
Recommend option 2 — avoid new deps. Pattern:
```typescript
const req = { user: {id: 'user-x', role: 'operator'}, body: {...} } as any;
const res = { status: vi.fn().mockReturnThis(), json: vi.fn(), send: vi.fn() } as any;
await handlerFn(req, res);
expect(res.status).toHaveBeenCalledWith(201);
```

## Sources

### Primary (HIGH confidence)

- **`/opt/samureye/shared/schema.ts`** — pgEnums (lines 34-82), assets table (107-117), edrDeployments (240-257), threats (302-341), createInsertSchema usages (843-857 and ~20 more sites). Canonical project conventions.
- **`/opt/samureye/server/storage/database-init.ts`** — runtime idempotent guard pattern (`ensureSystemUserExists` 14, pg_indexes check 17-45, edr_deployments creation 107-136). EXACT template for `ensureApiTables()`.
- **`/opt/samureye/server/scripts/backfillWebAppParent.ts`** — backfill CLI template: `--dry-run`, console.log, process.exit, isNull filter, mutation only when not dry-run.
- **`/opt/samureye/server/services/journeys/urls.ts`** — `normalizeTarget()` + `detectWebScheme()`. Reused by POST /api/v1/apis route.
- **`/opt/samureye/server/storage/assets.ts`** — facade pattern (getAssets, getAssetsTree, createAsset, inferParentHostForWebApp) — inspiration for apis storage + backfill probe logic.
- **`/opt/samureye/server/storage/interface.ts`** — IStorage interface; Phase 9 adds ~12 method signatures between lines ~265-280.
- **`/opt/samureye/server/storage/index.ts`** — DatabaseStorage class barrel; Phase 9 adds ~12 method wires.
- **`/opt/samureye/server/storage/threats.ts`** — storage facade at scale (636 lines); structural reference only.
- **`/opt/samureye/server/routes/assets.ts`** + **`/opt/samureye/server/routes/credentials.ts`** — Route pattern with RBAC, Zod via createInsertSchema, pt-BR errors, audit log.
- **`/opt/samureye/server/routes/middleware.ts`** — `requireOperator`, `patchAssetSchema` patterns.
- **`/opt/samureye/server/routes/index.ts`** — barrel `registerApiRoutes(app)` wire site.
- **`/opt/samureye/drizzle.config.ts`** — confirms `db:push` mechanism.
- **`/opt/samureye/.planning/codebase/CONVENTIONS.md`** — naming, error handling, pt-BR messages, import order, logger creation.
- **`/opt/samureye/.planning/codebase/TESTING.md`** — Vitest 4.0.18, `server/__tests__/*.test.ts`, global mode.
- **`/opt/samureye/package.json`** — verified versions: drizzle-orm@0.39.1, drizzle-zod@0.7.0, zod@3.24.2, pino@10.3.1, vitest@4.0.18.
- **`/opt/samureye/node_modules/drizzle-orm/pg-core/checks.d.cts`** — confirms `check(name, value: SQL)` is exported in installed 0.39.1.
- **npm registry** (`npm view ... version` 2026-04-18) — latest drizzle-orm 0.45.2, drizzle-zod 0.8.3, zod 4.3.6, pino 10.3.1.
- **owasp.org/API-Security/editions/2023/en/0x11-t10/** — official 10 categories with slugs (0xa1 through 0xaa) for URL construction in OWASP_API_CATEGORY_LABELS.

### Secondary (MEDIUM confidence)

- **orm.drizzle.team/docs/zod** — createInsertSchema composition (omit+extend+refine chains). Confirmed patterns match project usage.
- **orm.drizzle.team/docs/indexes-constraints** — uniqueIndex composite, check() helper syntax. Cross-verified against installed 0.39.1 type defs.

### Tertiary (LOW confidence)

- None — all load-bearing claims cross-verified against either the live codebase, installed node_modules, or owasp.org primary source.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all versions verified against installed package.json + node_modules; nothing is being newly introduced.
- Architecture: HIGH — every pattern (pgTable, pgEnum, runtime guard, storage facade, Express route) has an existing precedent in the codebase cited by line number.
- Pitfalls: HIGH — derived from reading the live database-init.ts guard patterns, drizzle-orm 0.39.1 type defs, and Postgres enum mutation semantics.
- OWASP category URLs: HIGH — fetched from owasp.org primary source 2026-04-18.
- pt-BR OWASP translations: MEDIUM — Claude-authored translations faithful to official English. Planner should review; a bilingual operator may refine titles (e.g. "BOLA" is widely kept in English in pt-BR security materials).

**Research date:** 2026-04-18
**Valid until:** 2026-05-18 (30 days — stable ecosystem, no major drizzle-orm / drizzle-zod / OWASP changes expected)

---

*Phase 9 is a boring, additive, precedent-rich schema phase. The riskiest bit is getting the runtime guard quoted-identifier exactly right. Everything else is copy-paste from existing patterns.*
