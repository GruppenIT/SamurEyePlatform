# Phase 11: Discovery & Enrichment - Research

**Researched:** 2026-04-19
**Domain:** API discovery pipeline (spec-first OpenAPI/GraphQL parsing, Katana crawling, Kiterunner brute-force, httpx enrichment, Arjun parameter discovery)
**Confidence:** HIGH (verified against official binary docs + npm registry + existing codebase patterns)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Orquestração + dedupe:**
- Ordem sequencial das etapas por API: `spec-first → katana crawler → kiterunner brute-force → httpx enrichment → arjun parameter discovery`. Cada stage falha independente sem abortar pipeline (log + skip).
- Crawler e Kiterunner SEMPRE rodam se toggle ligado, mesmo após spec-first succeed (cobertura API9 Improper Inventory).
- Dedupe via UQ `(api_id, method, path)` + append em `discoverySources`. Spec é autoritativo: preserva `requestSchema`/`responseSchema` se já populados.
- Rerun idempotente — manter stale endpoints + flag via log (`log.info({ apiId, endpointIdsNotSeen }, 'stale endpoints preserved')`). Coluna `lastSeenAt` é DEFERRED.
- Drift do `specHash`: apenas `log.warn({ apiId, oldHash, newHash }, 'spec drift detected')` + re-parseia spec (upsert normal). NÃO cria finding aqui.

**Scanners + spawn + preflight:**
- Um arquivo por ferramenta em `server/services/scanners/api/`: `katana.ts`, `httpx.ts`, `kiterunner.ts`, `arjun.ts`, `openapi.ts`, `graphql.ts` (6 arquivos).
- Orquestrador em `server/services/journeys/apiDiscovery.ts` importa os 6.
- Output capture: stdout JSONL streaming (katana/httpx/kiterunner), tempfile para arjun em `/tmp/api-discovery-<jobId>/arjun-<endpointId>.json`, HTTP fetch direto para openapi/graphql.
- Preflight lazy + memoizado por binário (padrão `nucleiPreflight.ts`). Binário faltante → skip stage + log.error + continua pipeline (NÃO bloqueia boot, NÃO cria finding).
- APIs processadas sequencialmente dentro de um job. Timeouts: spec-fetch 10s, katana 120s, kiterunner 300s, httpx 30s/batch, arjun 60s/endpoint.
- Cancelamento via `AbortController` + `processTracker` + SIGTERM graceful / SIGKILL após 5s.
- Resultados parciais persistem em cancel.

**Spec-first + GraphQL + auth:**
- Spec fetch: unauth first, retry com cred em 401/403 (compatível: api_key_header/bearer_jwt/basic/oauth2; incompatível skipa retry: hmac/mtls/api_key_query).
- Logar `specPubliclyExposed=true` quando sucesso unauth.
- `$ref` externos: APENAS same-origin do spec (SSRF defense). Falha no fetch → continua com spec parcial + warn.
- Escolha entre múltiplos specs: primeira URL que parseia com sucesso na ordem `/openapi.json` → `/swagger.json` → `/v3/api-docs` → `/v2/api-docs` → `/api-docs` → `/swagger-ui.html` → `/docs/openapi`.
- `specVersion` extraído do próprio spec (`openapi: "3.1.0"` ou `swagger: "2.0"`); GraphQL: `"GraphQL"`.
- `specHash`: SHA-256 do JSON canônico (`JSON.stringify(spec, Object.keys(spec).sort())`).
- GraphQL introspection: POST `application/json` com standard full query; paths `/graphql`, `/api/graphql`, `/query`; unauth first + retry cred; schema → 1 row por operation (method='POST', path=descoberto, `requestSchema` com `{ operationName, operationType, variables }`).

**Entrypoint + opt-ins + enrichment:**
- 3 superfícies:
  1. **Função pura** `discoverApi(apiId, opts, jobId?): Promise<DiscoveryResult>` em `server/services/journeys/apiDiscovery.ts`.
  2. **Rota interna** `POST /api/v1/apis/:id/discover` (RBAC `global_administrator` + `operator`).
  3. **CLI** `server/scripts/runApiDiscovery.ts --api=<id> [--no-crawler] [--kiterunner] [--arjun-endpoint=<id>...]`.
- Shape do `opts`: Zod schema com `stages: {spec?, crawler?, kiterunner?, httpx?, arjun?}`, `arjunEndpointIds?`, `credentialIdOverride?`, `dryRun?`, `katana?: { headless?, depth? }`, `kiterunner?: { rateLimit? }`.
- **httpx enrichment em 2 passos**: (1) unauth → preenche `requiresAuth` tri-valor (true em 401/403, false em 2xx/3xx, NULL em 5xx/timeout). (2) Se `requiresAuth===true` E cred compatível → re-probe auth + atualiza mesma row.
- **Novas colunas aditivas** em `api_endpoints` (decisão escopada ao planner refinar exact shape): `httpxStatus int`, `httpxContentType text`, `httpxTech text[]`, `httpxTls jsonb`, `httpxLastProbedAt timestamp`. Guard idempotente em `database-init.ts`.
- **Arjun user-selected** via `arjunEndpointIds`: Phase 11 valida cada ID existe + `method === 'GET'` + `apiId` matches. Wordlist `wordlists/arjun-extended-pt-en.txt`. Parâmetros fazem merge append em `api_endpoints.query_params` JSONB (dedupe por `name`).
- **Katana**: depth 3, `-fs rdn`, `-jc`, `-timeout 10`, `-jsonl`, `-xhr` + `-fx` (extração XHR e forms). `-headless` opt-in (requer Chrome; log warn se não disponível).
- **Katana crawling autenticado — compatível com header injection**: `api_key_header`, `bearer_jwt`, `basic` via `-H`. `oauth2_client_credentials` mint antes do crawl + cache per-run (`expires_in - 30s`), passa bearer. `mtls` via tempfiles em `/tmp/api-discovery-<jobId>/mtls-<credId>.{cert,key,ca}` + flags cert/key katana. `api_key_query` e `hmac` skipam auth + warn.
- **Kiterunner**: `kr scan -w wordlists/routes-large.kite -o json`. Status "hit": 2xx, 3xx, 401, 403. Streaming JSONL.

**DiscoveryResult shape (contrato público):** `{ apiId, stagesRun, stagesSkipped: [{stage, reason}], endpointsDiscovered, endpointsUpdated, endpointsStale: string[], specFetched?: {url, version, hash, driftDetected}, cancelled, durationMs }`.

**Logging estrutura:**
- `log.info({ apiId, stage, jobId, ...metrics }, 'stage complete')`.
- Redação automática via pino cobre `secretEncrypted`, `dekEncrypted`, `authorization`.
- NUNCA logar bodies, tokens OAuth mintados, valores de params descobertos. Só contagens + IDs.

### Claude's Discretion

- Nomes exatos de funções internas nos scanners (`runKatana`, `runHttpx`, etc).
- Estrutura interna do `DiscoveryResult` — campos adicionais podem ser acrescentados (aditivo).
- Shape exato das colunas httpx em `api_endpoints` (researcher recomenda abaixo; planner confirma).
- Formato dos tempfiles (nome, path, cleanup strategy com `try/finally`).
- Escolha entre `p-limit` vs `for-await` para loops internos de endpoints.
- Nyquist test stubs (Wave 0): ~8 testes sugeridos.
- Mensagens pt-BR exatas para erros em rota/CLI.
- Ordem de imports, header de arquivos (segue CONVENTIONS.md).
- Se `operationName` do GraphQL vira coluna dedicada em `api_endpoints` ou fica em `requestSchema.operationName`.

### Deferred Ideas (OUT OF SCOPE)

- Coluna `lastSeenAt` em `api_endpoints` (aditivo futuro em Phase 12 ou later).
- SOAP WSDL discovery (v3.0 adiciona parser).
- Auto-schedule de re-discovery (Phase 15 decide).
- `operationId` em `api_endpoints` (aditivo futuro se Phase 12/13 precisar).
- Multi-version spec tracking com timeline de mudanças.
- Paralelismo entre APIs em um job (`p-limit 2-3`).
- `firstDiscoveredAt` em `api_endpoints`.
- Headless Chrome via install.sh (Phase 11 degrada com warn).
- Retry automático em stage falha.
- Validation `apiType === 'rest'` vs `graphql` no spec detectado.
- Batch discovery `POST /api/v1/apis/discover` (plural).
- Per-tool retry quota (hoje fail-fast).
- Custom Nuclei templates API9 direto do Phase 11.
- Validação de CORS no httpx enrichment.
- Endpoint-level credential override (hoje per-API).
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| DISC-01 | Probe spec-first paths (`/openapi.json`, `/swagger.json`, `/v2/api-docs`, `/v3/api-docs`, `/api-docs`, `/swagger-ui.html`, `/docs/openapi`) and parse the result | `scanners/api/openapi.ts` usa `fetch` nativo + `@apidevtools/swagger-parser.parse()`. Lista de paths fixa + short-circuit na primeira URL válida. |
| DISC-02 | Parse OpenAPI 2.0 / 3.0 / 3.1 natively via `@apidevtools/swagger-parser`, extracting every endpoint with full schema | `SwaggerParser.dereference()` aceita 2.0/3.0/3.1. Iteração sobre `spec.paths[p][method]` gera 1 row em `api_endpoints` com `requestSchema`/`responseSchema` dereferenciados. |
| DISC-03 | GraphQL introspection against `/graphql`, `/api/graphql`, `/query` capturing schema when enabled | `scanners/api/graphql.ts` POST com `getIntrospectionQuery()` (query standard do graphql-js) ou string literal embutida. Cada operation (query/mutation/subscription) vira 1 row. |
| DISC-04 | Katana crawling com XHR/JS/form extraction para SPA endpoints | `scanners/api/katana.ts` spawn `katana -jsonl -xhr -fx -jc -d 3 -fs rdn -timeout 10`. Streaming stdout JSONL + append `discoverySources=['crawler']`. |
| DISC-05 | Kiterunner opt-in brute-force com `routes-large.kite` | `scanners/api/kiterunner.ts` spawn `kr scan <target> -w wordlists/routes-large.kite -o json -x 5 -j 100 --success-status-codes 200,201,204,301,302,401,403`. Default OFF em `opts.stages.kiterunner`. |
| DISC-06 | Compute and store `specHash` per fetch to detect drift | `crypto.createHash('sha256').update(canonicalJsonStringify(spec))`. Upsert em `apis.specHash` + `apis.specLastFetchedAt`. Compare com row existente antes de write → log.warn se mudou. |
| ENRH-01 | httpx probing captures status, tech-detect, content-type, TLS | `scanners/api/httpx.ts` spawn `httpx -json -sc -td -ct -tls-grab -silent`. Input URLs via stdin (batched). Streaming JSON line-parse. |
| ENRH-02 | `requiresAuth=true` when unauth call returns 401/403 | Passo 1 httpx unauth: mapeia status → tri-valor (`true` em {401,403}, `false` em {200,201,204,3xx}, `NULL` em 5xx/timeout). |
| ENRH-03 | Arjun param discovery opt-in em GET endpoints selecionados; attach params ao endpoint | `scanners/api/arjun.ts` spawn `arjun -u <url> -w wordlists/arjun-extended-pt-en.txt -oJ <tempfile> -m GET -t 10 -T 15`. Parse JSON output (dict keyed by URL) + merge em `query_params` JSONB. |
</phase_requirements>

## Summary

Phase 11 ships the runtime pipeline that populates `apis.specHash`/`specVersion`/`specLastFetchedAt` and `api_endpoints` rows (created empty by Phase 9) plus new httpx enrichment columns. It wraps five external binaries (Katana, httpx, Kiterunner, Arjun via pip venv) and one npm library (`@apidevtools/swagger-parser`) behind six scanner modules (`server/services/scanners/api/{katana,httpx,kiterunner,arjun,openapi,graphql}.ts`) orchestrated by `server/services/journeys/apiDiscovery.ts`. Each scanner follows the project's established spawn + `processTracker` + cancelable-Promise pattern already used by `vulnScanner.ts` and `networkScanner.ts`. Preflight per binary is memoized per-process (pattern from `nucleiPreflight.ts`); missing binaries cause stage skip, not pipeline abort.

Two discrepancies in CONTEXT.md were found and corrected by this research: (1) Katana flag for XHR/form extraction is `-xhr` + `-fx`, **not** `-em xhr,fetch,websocket,ajax,form` (CONTEXT.md §Katana). `-em` is extension-match. (2) Kiterunner's `-x` flag is `max-connection-per-host` (default 3, recommended 5-10), **not** a QPS rate limiter. True rate limiting comes via `--delay` duration + `-j max-parallel-hosts`. CONTEXT.md decision "`-x 10` (10 QPS)" is incorrect; planner should treat `-x 5 -j 100` as the defensive default and document that actual QPS depends on target RTT. Neither discrepancy invalidates the overall architecture, but both require flag-level correction when writing task actions.

**Primary recommendation:** Follow the scanner-per-tool module structure verbatim from `vulnScanner.ts` (spawn + processTracker + AbortController + JSONL line-split); isolate `@apidevtools/swagger-parser` behind a thin `scanners/api/openapi.ts` facade so the same module handles both fetch and parse and never leaks a cross-origin `$ref` through. Memoize binary preflight 1:1 with `nucleiPreflight.ts`.

## Standard Stack

### Core (new dependencies)
| Library | Version (verified 2026-04-19) | Purpose | Why Standard |
|---------|-------------------------------|---------|--------------|
| `@apidevtools/swagger-parser` | `12.1.0` (released 2026-01-24) | Parse + dereference OpenAPI 2.0 / 3.0 / 3.1 | Canonical OSS parser in the OpenAPI ecosystem; used by Swagger UI, Stoplight, Redocly. v12 fixed CVE-class SSRF via internal URL resolution — MUST use v12+. |
| `openapi-types` | peer of swagger-parser (`>=7`) | TypeScript types for parsed OpenAPI documents | Official type package from the same org; enables typed iteration over `paths`/`operations`. |

### Existing deps already in the project
| Library | Version | Used For |
|---------|---------|----------|
| `pino` + `pino-pretty` | `10.3.1` / `13.1.3` | Structured logging with redaction (already covers `authorization`, `secretEncrypted`) |
| `zod` + `drizzle-zod` | `3.24.2` / `0.7.0` | `discoverApiOptsSchema` validation for route + CLI |
| `drizzle-orm` | `0.39.1` | Storage facade upserts via `onConflictDoUpdate` (pattern exists in `apiEndpoints.ts`) |
| `crypto` (node builtin) | N/A | SHA-256 canonical spec hash |
| `vitest` | `4.0.18` | Nyquist stubs + mocks |

### Binaries (installed by Phase 8, pinned in `scripts/install/binaries.json`)
| Binary | Pinned Version | SHA-256 | Install Path |
|--------|----------------|---------|--------------|
| katana | 1.5.0 | `592890e5febaf5706d0a962d96299512418d6eccce6388cf1600e1f078ed359d` | `/opt/samureye/bin/katana` (or `/usr/local/bin/katana` after install.sh) |
| httpx | 1.9.0 | `54c6c91d61d3b82ba79f93633df04bb547f0c954d9d9b0fb8bcedf158f85ff2f` | `/opt/samureye/bin/httpx` |
| kiterunner | 1.0.2 | `6f0b70aabf747de592445a690281897eebbc45927e9264185d34ffb11637613b` | `/opt/samureye/bin/kiterunner` (binary is named `kr`) |
| arjun | 2.2.7 | `b193cdaf97bf7b0e8cd91a41da778639e01fd9738d5f666a8161377f475ce72e` | `venv-security/bin/arjun` |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `@apidevtools/swagger-parser` | `@readme/openapi-parser` | Fork of apidevtools; adds 3.1 improvements but less mature. Apidevtools now supports 3.1. Stick with canonical. |
| `graphql-js.getIntrospectionQuery()` | Hard-coded introspection query string | graphql-js adds ~700KB. A string literal covers the standard query and avoids a new dep. **Decision: hard-code** (see Code Examples §GraphQL introspection). |
| `p-limit` for concurrency | `for await` sequential | CONTEXT locks sequential processing of APIs; loops inside a stage (e.g. httpx batch of 100 endpoints) can use simple `for` with chunking. `p-limit` is a discretion item. |
| Canonical JSON for specHash | `crypto.createHash + JSON.stringify(spec)` raw | Key order varies by source → false drift. MUST use canonical form: `JSON.stringify(spec, Object.keys(spec).sort())` is insufficient (only top-level). Recommend recursive canonicalization (see Code Examples §specHash). |

**Installation:**
```bash
npm install @apidevtools/swagger-parser
# openapi-types is peer-installed as transitive; explicit install optional for dev ergonomics:
npm install --save-dev openapi-types
```

**Version verification (run during Wave 0):**
```bash
npm view @apidevtools/swagger-parser version           # → 12.1.0 (verified 2026-04-19)
/opt/samureye/bin/katana -version                      # → 1.5.0
/opt/samureye/bin/httpx -version                       # → 1.9.0
/opt/samureye/bin/kiterunner version                   # → 1.0.2 (binary is named `kr`)
/opt/samureye/venv-security/bin/arjun --version        # → 2.2.7
```

## Architecture Patterns

### Recommended Project Structure

```
server/
├── services/
│   ├── scanners/
│   │   ├── api/                          # NEW subpackage
│   │   │   ├── katana.ts                 # spawn wrapper + JSONL stream
│   │   │   ├── httpx.ts                  # spawn wrapper + JSON line parse
│   │   │   ├── kiterunner.ts             # spawn wrapper + JSON output parse
│   │   │   ├── arjun.ts                  # spawn wrapper + tempfile JSON read
│   │   │   ├── openapi.ts                # fetch + swagger-parser (no spawn)
│   │   │   ├── graphql.ts                # fetch + introspection (no spawn)
│   │   │   └── preflight.ts              # memoized per-binary preflight (katana/httpx/kiterunner/arjun)
│   │   └── vulnScanner.ts                # existing — spawn pattern template
│   └── journeys/
│       ├── apiDiscovery.ts               # NEW orchestrator — imports all 6 scanners
│       └── nucleiPreflight.ts            # existing — memoization template
├── routes/
│   └── apis.ts                           # EXTENDED — adds POST /api/v1/apis/:id/discover
├── scripts/
│   └── runApiDiscovery.ts                # NEW CLI
└── storage/
    ├── apis.ts                           # EXTENDED — updateApiSpecMetadata
    ├── apiEndpoints.ts                   # EXTENDED — upsertApiEndpoints (bulk), mergeHttpxEnrichment, appendQueryParams
    └── database-init.ts                  # EXTENDED — ensureApiEndpointHttpxColumns guard

shared/
└── schema.ts                             # EXTENDED — discoverApiOptsSchema + new httpx columns on apiEndpoints

docs/operations/
└── run-api-discovery.md                  # NEW operator runbook
```

### Pattern 1: Spawn + processTracker + timeout + graceful kill
**What:** Every binary invocation follows the same lifecycle: register with `processTracker(jobId, name, child, stage)`, enforce `maxWaitTime` via `setTimeout` that triggers SIGTERM → SIGKILL after 5s, resolve on close code 0.
**When to use:** All four binary scanners (katana, httpx, kiterunner, arjun).
**Example:**
```typescript
// Source: server/services/scanners/vulnScanner.ts:382-440 (verbatim pattern)
import { spawn } from 'child_process';
import { processTracker } from '../../processTracker';

async function spawnCommand(
  command: string,
  args: string[],
  context: { jobId?: string; processName: string; stage: string; maxWaitTime: number },
): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    if (!child.pid) return reject(new Error('Failed to get process PID'));

    let stdout = '';
    let stderr = '';
    if (context.jobId) processTracker.register(context.jobId, context.processName, child, context.stage);
    child.stdout?.on('data', (d) => (stdout += d.toString()));
    child.stderr?.on('data', (d) => (stderr += d.toString()));

    const timer = setTimeout(() => {
      if (context.jobId && child.pid) processTracker.kill(context.jobId, child.pid);
      else { child.kill('SIGTERM'); setTimeout(() => child.kill('SIGKILL'), 5000); }
      reject(new Error(`timeout after ${context.maxWaitTime}ms`));
    }, context.maxWaitTime);

    child.on('close', (code) => { clearTimeout(timer); code === 0 ? resolve(stdout) : reject(new Error(stderr)); });
  });
}
```

### Pattern 2: JSONL streaming parser (avoids OOM on huge crawls)
**What:** Accumulate stdout buffer, split on `\n`, `JSON.parse` each complete line, discard trailing partial chunk.
**When to use:** katana `-jsonl`, httpx `-json`, kiterunner `-o json` (all produce newline-delimited JSON).
**Example:**
```typescript
// Source: adapted from common JSONL pattern; project uses accumulated stdout in vulnScanner.ts:442+
function parseJsonlStream(stdout: string): unknown[] {
  const results: unknown[] = [];
  for (const line of stdout.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try { results.push(JSON.parse(trimmed)); }
    catch { /* log.debug but swallow — partial line or non-JSON stderr-mix */ }
  }
  return results;
}
```

### Pattern 3: Memoized per-process preflight
**What:** Cache the result of a `which <binary>` check + optional setup (templates download for nuclei; N/A for others). First call pays the cost, subsequent calls return cached result. Reset helper for tests.
**When to use:** Every binary (katana, httpx, kiterunner, arjun). One preflight function per binary OR one shared `preflightApiBinary(name)`.
**Example:**
```typescript
// Source: server/services/journeys/nucleiPreflight.ts:21-47 (verbatim pattern)
let cached: Map<string, { ok: boolean; reason?: string }> = new Map();

export async function preflightApiBinary(
  name: 'katana' | 'httpx' | 'kiterunner' | 'arjun',
  log: { info: (m: string) => void; error: (m: string) => void },
): Promise<{ ok: boolean; reason?: string }> {
  const hit = cached.get(name);
  if (hit) return hit;
  // arjun lives in venv; others on PATH
  const binPath = name === 'arjun' ? '/opt/samureye/venv-security/bin/arjun' : name === 'kiterunner' ? 'kr' : name;
  const { spawnSync } = await import('child_process');
  const res = spawnSync('which', [binPath.startsWith('/') ? binPath : binPath], { encoding: 'utf8' });
  const ok = res.status === 0;
  const result = ok ? { ok: true } : { ok: false, reason: `${name} not found on PATH` };
  cached.set(name, result);
  if (!ok) log.error(`❌ ${name} binary not available — stage will be skipped`);
  return result;
}

export function resetApiBinaryPreflight(): void { cached.clear(); }
```

### Pattern 4: Upsert with text[] dedupe on discoverySources
**What:** Phase 9 already established — `onConflictDoUpdate` target `(api_id, method, path)` with SQL expression `ARRAY(SELECT DISTINCT unnest(discovery_sources || ARRAY[...]))` to merge sources.
**When to use:** Every endpoint write from every stage (spec, crawler, kiterunner).
**Example:**
```typescript
// Source: server/storage/apiEndpoints.ts:26-44 (existing — extend with bulk variant)
export async function upsertApiEndpoint(data: InsertApiEndpoint): Promise<ApiEndpoint> {
  const [row] = await db.insert(apiEndpoints)
    .values(data)
    .onConflictDoUpdate({
      target: [apiEndpoints.apiId, apiEndpoints.method, apiEndpoints.path],
      set: {
        discoverySources: sql`(SELECT ARRAY(SELECT DISTINCT unnest(
          ${apiEndpoints.discoverySources} || ${data.discoverySources ?? sql`ARRAY[]::text[]`}
        )))`,
        updatedAt: new Date(),
      },
    })
    .returning();
  return row;
}
// NEW for Phase 11: upsertApiEndpoints(apiId, endpoints[]) — wraps loop or VALUES multi-row insert.
```

### Pattern 5: Preserve richer data on re-discover (spec > crawler > brute-force)
**What:** When upserting, preserve `requestSchema`/`responseSchema` if already non-null (spec wrote them; crawler shouldn't overwrite with null).
**When to use:** `upsertApiEndpoint` variants for crawler/kiterunner sources.
**Example:**
```typescript
// Recommended extension (not yet in codebase):
onConflictDoUpdate({
  target: [apiEndpoints.apiId, apiEndpoints.method, apiEndpoints.path],
  set: {
    discoverySources: sql`(SELECT ARRAY(SELECT DISTINCT unnest(...)))`,
    // COALESCE preserves existing non-null; null from crawler/kiterunner → keep spec data
    requestSchema: sql`COALESCE(${apiEndpoints.requestSchema}, ${data.requestSchema ?? null})`,
    responseSchema: sql`COALESCE(${apiEndpoints.responseSchema}, ${data.responseSchema ?? null})`,
    requiresAuth: sql`COALESCE(${apiEndpoints.requiresAuth}, ${data.requiresAuth ?? null})`,
    updatedAt: new Date(),
  },
})
```

### Anti-Patterns to Avoid

- **Blocking stdout accumulation for multi-MB crawls:** Don't `await child.stdout.text()` — katana on a large SPA emits 10s of MB. Use `on('data', ...)` accumulation + JSONL line-parse. Already established in `vulnScanner.ts:420-425`.
- **Passing raw user-controlled URLs to `SwaggerParser.dereference()` without same-origin check on `$ref`:** CVE-class SSRF. A malicious spec can reference `http://169.254.169.254/latest/meta-data/` and exfil cloud metadata. swagger-parser v12 mitigated internal URL resolution but **you still MUST filter HTTP `$ref` to same-origin** via the `resolve.http` option or a custom resolver (see Pitfalls §1).
- **Hard-coded binary paths in production code:** Use `which` via preflight; fall through PATH. `backfillApiDiscovery.ts` template shows venv resolution for arjun.
- **Logging raw spec bodies or introspection responses:** Includes API docs + schema fragments that can contain `example` values with PII/tokens. Log only counts + IDs. pino redaction won't help — no wildcard depth match.
- **Storing OAuth2 tokens in the database:** Phase 10 decision — tokens stay in-memory only, TTL = `expires_in - 30s`. Phase 11 inherits: cache per `discoverApi(...)` call, drop on return.
- **Calling `getApiCredentialWithSecret()` outside Phase 11 executor:** Phase 10 limited this function to the discovery runtime. Storage facade otherwise returns `ApiCredentialSafe` (no secret). The orchestrator is the sole legit caller.
- **Assuming OpenAPI 3.1 is a superset of 3.0:** 3.1 drops `nullable: true` in favor of `type: ['string', 'null']`, changes `exclusiveMinimum` semantics, and removes some keywords. swagger-parser handles parsing but `requestSchema` JSONB shape will differ — downstream Phase 12/13 must be tolerant. Flag this in `specVersion` column.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| OpenAPI 2.0/3.0/3.1 parsing | Custom JSON walker that understands `$ref`, `allOf`, `oneOf`, discriminators | `@apidevtools/swagger-parser.dereference()` | Circular refs, external refs, inheritance, nullable semantics differ per version. 10,000+ edge cases. |
| GraphQL introspection query | Partial introspection (just types, just queries) | Full standard introspection query (hard-coded literal from graphql.org spec) | Partial queries miss interfaces, unions, enums, directives; Phase 12 will need them for Nuclei templates. |
| Crawler for SPA XHR/fetch endpoints | DOM walker + fetch interception via puppeteer scripts | `katana -xhr -fx -jc` | Katana implements headless hybrid crawling, JS AST parsing, AJAX hook instrumentation. |
| Route brute-force against APIs | For-loop over wordlist + `fetch` | `kr scan -w routes-large.kite` | Kiterunner's `.kite` format is a protobuf-compiled trie that does path-mutation-aware brute-force (not just GET/{word}) and handles HTTP/2 + connection reuse. |
| Tech fingerprinting + TLS grab | Custom `tls.connect` + header parsing | `httpx -td -tls-grab` | httpx ships with embedded wappalyzer dataset + TLS CN/SAN extraction + cert chain parsing. Zero maintenance. |
| Hidden parameter discovery | Random parameter fuzzer | `arjun -w arjun-extended-pt-en.txt` | Arjun uses response-length + response-body delta heuristics with chunked binary search — far more accurate than naive fuzzing. |
| Canonical JSON for SHA-256 | `JSON.stringify(spec)` directly | Recursive key-sorted stringifier (see Code Examples §specHash) | `Object.keys(spec).sort()` only sorts top-level; nested objects preserve original order → false drift. |
| URL parsing / same-origin check | Regex / string split | `new URL(url).origin` + strict string compare | Handles port, implicit 80/443, IPv6, userinfo. Node builtin is canonical. |
| SHA-256 | Custom crypto | `crypto.createHash('sha256')` | Node builtin. |

**Key insight:** The four binaries + swagger-parser together cover ~95% of discovery surface. Hand-rolling any replacement costs thousands of hours on edge cases that upstream maintainers have already burned in. Phase 11 is 85% glue (spawn + storage + orchestration), 15% validation (schemas, same-origin refs, tri-valor mapping).

## Common Pitfalls

### Pitfall 1: SwaggerParser SSRF via malicious `$ref`
**What goes wrong:** Attacker-controlled OpenAPI spec contains `"$ref": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"`. `SwaggerParser.dereference(url)` follows it by default, exfiltrating cloud metadata via `$ref` resolution.
**Why it happens:** swagger-parser's default `resolve.http.read` allows any URL. v12 fixed internal-URL DNS rebinding issues but same-origin enforcement is NOT the default.
**How to avoid:** Pass a custom `resolve.http.read` that parses the candidate URL and rejects anything whose `origin !== new URL(specUrl).origin`:
```typescript
const specOrigin = new URL(specUrl).origin;
const parsed = await SwaggerParser.dereference(specUrl, {
  resolve: {
    http: {
      read: async (file) => {
        if (new URL(file.url).origin !== specOrigin) {
          log.warn({ specUrl, refUrl: file.url }, 'rejected cross-origin $ref');
          throw new Error('cross-origin $ref blocked (SSRF defense)');
        }
        // fallback to default fetch
        const res = await fetch(file.url);
        return await res.text();
      },
    },
  },
});
```
**Warning signs:** Logs showing spec fetch succeeded against baseUrl X but dereference made outbound requests to Y ≠ X.

### Pitfall 2: Katana flag confusion (`-em` ≠ XHR extraction)
**What goes wrong:** CONTEXT.md suggested `-em xhr,fetch,websocket,ajax,form`. This is invalid — `-em` is **extension-match** (filters by `.php`, `.html`, etc.), not extraction type.
**Why it happens:** Easy to conflate with `-field-scope` or other matchers.
**How to avoid:** Use the correct flags: `-xhr` (alias `-xhr-extraction`) for AJAX/XHR capture, `-fx` (alias `-form-extraction`) for HTML forms, `-jc` for JS endpoint parsing. Example command:
```bash
katana -u https://target.example.com \
  -d 3 -fs rdn -jc -xhr -fx \
  -timeout 10 -jsonl -silent \
  -H "Authorization: Bearer ${TOKEN}"
```
**Warning signs:** Empty crawler output despite SPA presence; only seeing `response_type=document` in JSONL.

### Pitfall 3: Kiterunner `-x` is connections-per-host, not QPS
**What goes wrong:** CONTEXT.md locks "10 QPS default via `-x 10`". This is wrong — `-x 10` opens 10 parallel TCP connections to each host, which yields anywhere from 10-50 req/s depending on target RTT.
**Why it happens:** Name collision — many tools use `-x` for rate limiting.
**How to avoid:** Real rate control is `--delay 100ms` (between requests to single host) + `-j max-parallel-hosts`. Defensive default should be `-x 5 -j 100` per upstream README. For a hard ~10 req/s ceiling, use `-x 3 --delay 300ms`. Document this discrepancy in the task action — the **10 QPS promise belongs to Phase 15 (SAFE-01) applying a global governor**, not to Phase 11's kiterunner invocation alone.
**Warning signs:** Target returning many 429s or being knocked offline during brute-force; Phase 15 ceiling (50 req/s) would appear to be exceeded.

### Pitfall 4: Arjun JSON output is dict-keyed-by-URL, not an array
**What goes wrong:** Code assumes `-oJ output.json` returns `[{url, params, ...}]`. Actual format is `{"https://host/path": {"method": "GET", "params": ["..."], "headers": {...}}}` (dict keyed by URL).
**Why it happens:** The wiki doesn't document the schema explicitly; third-party blog posts are inconsistent.
**How to avoid:** Confirmed by inspecting `arjun/core/exporter.py`: output is `Object.entries(json).map(([url, {method, params, headers}]) => ...)`. Validate with a Zod schema:
```typescript
const ArjunOutputSchema = z.record(z.string(), z.object({
  method: z.string(),
  params: z.array(z.string()),
  headers: z.record(z.string(), z.string()).optional(),
}));
```
And run a smoke test during Wave 0 that spawns `arjun -u https://httpbin.org/get -oJ /tmp/arjun.json` and asserts the top-level is an object, not an array.
**Warning signs:** `TypeError: result.forEach is not a function` or Zod union mismatches.

### Pitfall 5: `specHash` false drift from key order
**What goes wrong:** Two fetches of the same spec produce different hashes because `JSON.parse` preserves insertion order that server-side templating varied. `log.warn('spec drift detected')` fires every run → alert fatigue.
**Why it happens:** `JSON.stringify(spec, Object.keys(spec).sort())` only sorts top-level; nested objects keep insertion order.
**How to avoid:** Recursive canonical stringifier:
```typescript
function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.keys(value as Record<string, unknown>)
      .sort()
      .reduce((acc, k) => ({ ...acc, [k]: canonicalize((value as Record<string, unknown>)[k]) }), {});
  }
  return value;
}
const specHash = crypto.createHash('sha256')
  .update(JSON.stringify(canonicalize(spec)))
  .digest('hex');
```
**Warning signs:** `driftDetected: true` on specs nobody edited; hash changes correlate with server restarts (key-order randomization).

### Pitfall 6: GraphQL introspection not always over HTTP POST
**What goes wrong:** Some GraphQL servers accept introspection only via GET (`?query=...`) or only via specific `content-type: application/json` header. Hard-coding `POST { body: JSON.stringify({query: ...}) }` misses ~5% of servers.
**Why it happens:** graphql-over-http spec allows both methods; implementations differ.
**How to avoid:** Try POST with `Content-Type: application/json`. On 405 Method Not Allowed, retry with GET + query param. On `Content-Type: application/graphql`, retry with raw body (no JSON wrapper).
**Warning signs:** Introspection fails on public test targets like `https://countries.trevorblades.com/graphql`.

### Pitfall 7: Arjun's `--delay` sets threads=1
**What goes wrong:** Setting `--delay 100ms` to be polite drops throughput to single-threaded (Arjun intentionally serializes when delay is set). A 1000-parameter scan takes 15+ minutes.
**Why it happens:** By design (Arjun wiki: "delay between requests (sets threads to 1)").
**How to avoid:** If rate control is needed, use `--stable` (1 thread + 6-12s delay) for extreme politeness, or `--ratelimit 10` (requests per second, separate flag). Default for Phase 11: no delay, `-t 10`, `-T 15` (timeout).
**Warning signs:** Arjun runs taking minutes-per-endpoint instead of seconds.

### Pitfall 8: httpx tri-valor mapping misses 5xx
**What goes wrong:** Code maps `status >= 400 && status < 500 → requiresAuth=true`. Treats 500 as `requiresAuth=false` implicitly. But 500 just means "endpoint broken", not "no auth required". Downstream Phase 12/13 will run BOLA against a broken endpoint and produce noise.
**Why it happens:** Binary bucketing of status codes.
**How to avoid:** Explicit tri-valor:
```typescript
function mapRequiresAuth(status: number): boolean | null {
  if (status === 401 || status === 403) return true;
  if (status === 200 || status === 201 || status === 204) return false;
  if (status >= 300 && status < 400) return false;  // redirects imply open
  return null;  // 4xx-other, 5xx, timeout, network error → unknown
}
```
**Warning signs:** `api_endpoints.requires_auth = false` on endpoints that return 500 on initial probe.

### Pitfall 9: tempfile leakage on cancellation
**What goes wrong:** Arjun writes to `/tmp/api-discovery-<jobId>/arjun-<endpointId>.json`. If `AbortController.abort()` triggers SIGKILL mid-write, the file lingers. Repeat runs produce `/tmp` bloat.
**Why it happens:** No `try/finally` unlink; cleanup only on happy-path close(0).
**How to avoid:** Always wrap spawn in try/finally that `unlinkSync` the tempfile, even on reject. Use `mkdtempSync` + recursive rmdir at end of discoverApi call.
**Warning signs:** `df -h /tmp` shows disk fill-up after repeated runs.

## Code Examples

Verified patterns from official sources + existing codebase:

### OpenAPI spec fetch + parse with same-origin `$ref` guard
```typescript
// Source: @apidevtools/swagger-parser v12.1 docs (https://apidevtools.com/swagger-parser/options.html)
//         + security hardening for Pitfall 1 SSRF
import SwaggerParser from '@apidevtools/swagger-parser';
import type { OpenAPI } from 'openapi-types';
import { createLogger } from '../../../lib/logger';

const log = createLogger('scanners:api:openapi');

const KNOWN_SPEC_PATHS = [
  '/openapi.json', '/swagger.json', '/v3/api-docs',
  '/v2/api-docs', '/api-docs', '/swagger-ui.html', '/docs/openapi',
];

export async function fetchAndParseSpec(
  baseUrl: string,
  authHeader: string | undefined,
  signal: AbortSignal,
): Promise<{ spec: OpenAPI.Document; specUrl: string; specHash: string; specVersion: string } | null> {
  for (const path of KNOWN_SPEC_PATHS) {
    const url = new URL(path, baseUrl).toString();
    try {
      const res = await fetch(url, {
        headers: authHeader ? { Authorization: authHeader } : {},
        signal,
      });
      if (!res.ok) continue;
      const ct = res.headers.get('content-type') ?? '';
      if (!ct.includes('json') && !path.endsWith('.html')) continue;
      const rawJson = await res.json();

      const specOrigin = new URL(url).origin;
      const spec = await SwaggerParser.dereference(rawJson as OpenAPI.Document, {
        resolve: {
          http: {
            read: async (file: { url: string }) => {
              if (new URL(file.url).origin !== specOrigin) {
                log.warn({ specUrl: url, refUrl: file.url }, 'rejected cross-origin $ref');
                throw new Error('cross-origin $ref blocked');
              }
              const r = await fetch(file.url, { signal });
              return await r.text();
            },
          },
        },
      });

      const specVersion = extractVersion(spec);
      const specHash = computeCanonicalHash(spec);
      return { spec, specUrl: url, specHash, specVersion };
    } catch (err) {
      log.debug({ err, url }, 'spec fetch/parse failed, trying next path');
    }
  }
  return null;
}

function extractVersion(spec: OpenAPI.Document): string {
  if ('openapi' in spec && typeof spec.openapi === 'string') return spec.openapi;
  if ('swagger' in spec && typeof (spec as { swagger: unknown }).swagger === 'string') {
    return (spec as { swagger: string }).swagger;
  }
  return 'unknown';
}
```

### Canonical specHash (deep key-sort)
```typescript
// Addresses Pitfall 5 false drift.
import crypto from 'crypto';

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return Object.keys(obj).sort().reduce<Record<string, unknown>>((acc, k) => {
      acc[k] = canonicalize(obj[k]);
      return acc;
    }, {});
  }
  return value;
}

export function computeCanonicalHash(spec: unknown): string {
  return crypto.createHash('sha256').update(JSON.stringify(canonicalize(spec))).digest('hex');
}
```

### GraphQL introspection (hard-coded standard query)
```typescript
// Source: https://graphql.org/learn/introspection/ + graphql-js getIntrospectionQuery() output
// Using literal avoids adding graphql dep (~700KB).
const INTROSPECTION_QUERY = `
  query IntrospectionQuery {
    __schema {
      queryType { name }
      mutationType { name }
      subscriptionType { name }
      types {
        ...FullType
      }
      directives {
        name
        description
        locations
        args { ...InputValue }
      }
    }
  }
  fragment FullType on __Type {
    kind
    name
    description
    fields(includeDeprecated: true) {
      name
      description
      args { ...InputValue }
      type { ...TypeRef }
      isDeprecated
      deprecationReason
    }
    inputFields { ...InputValue }
    interfaces { ...TypeRef }
    enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
    possibleTypes { ...TypeRef }
  }
  fragment InputValue on __InputValue {
    name description type { ...TypeRef } defaultValue
  }
  fragment TypeRef on __Type {
    kind name
    ofType {
      kind name
      ofType {
        kind name
        ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } }
      }
    }
  }
`;

const GRAPHQL_PATHS = ['/graphql', '/api/graphql', '/query'];

export async function probeGraphQL(
  baseUrl: string,
  authHeader: string | undefined,
  signal: AbortSignal,
): Promise<{ schema: unknown; endpointPath: string } | null> {
  for (const path of GRAPHQL_PATHS) {
    const url = new URL(path, baseUrl).toString();
    const res = await fetch(url, {
      method: 'POST',
      signal,
      headers: {
        'Content-Type': 'application/json',
        ...(authHeader ? { Authorization: authHeader } : {}),
      },
      body: JSON.stringify({ query: INTROSPECTION_QUERY }),
    });
    if (!res.ok) continue;
    const body = await res.json() as { data?: { __schema?: unknown }; errors?: unknown[] };
    if (body.data?.__schema) return { schema: body.data.__schema, endpointPath: path };
  }
  return null;
}
```

### Katana spawn (corrected flags)
```bash
# Source: https://docs.projectdiscovery.io/tools/katana/usage (verified 2026-04-19)
# CORRECTED: -xhr -fx -jc (NOT -em xhr,fetch,...)
katana \
  -u https://target.example.com \
  -d 3 \
  -fs rdn \
  -jc \
  -xhr \
  -fx \
  -timeout 10 \
  -jsonl \
  -silent \
  -H "Authorization: Bearer ${TOKEN}"
# Optional headless:
#   -hl -sc       (requires Chrome on PATH)
```

### httpx spawn + JSONL parse
```typescript
// Source: https://github.com/projectdiscovery/httpx README
// Input URLs via stdin (one per line). Output JSONL.
const args = [
  '-json',
  '-silent',
  '-sc',            // -status-code
  '-ct',            // -content-type
  '-td',            // -tech-detect
  '-tls-grab',      // TLS cert info in output.tls
  '-timeout', '10',
  '-rl', '50',      // rate-limit 50 req/s (Phase 15 will apply global ceiling)
];
const child = spawn('httpx', args, { stdio: ['pipe', 'pipe', 'pipe'] });
child.stdin.write(urls.join('\n') + '\n');
child.stdin.end();
// parse stdout JSONL: each line has { url, status_code, content_type, tech: [...], tls: { ... } }
```

### Kiterunner spawn (corrected rate-limit semantics)
```bash
# Source: https://github.com/assetnote/kiterunner (verified 2026-04-19)
# -x = max-connection-per-host (NOT QPS); --delay duration for between-request pacing.
# Defensive default: -x 5 -j 100 per upstream guidance.
kr scan https://target.example.com \
  -w /opt/samureye/wordlists/routes-large.kite \
  -o json \
  -x 5 \
  -j 100 \
  --success-status-codes 200,201,204,301,302,401,403 \
  --fail-status-codes 404,501,502
# To hard-cap ~10 req/s for a single host: -x 3 --delay 300ms
```

### Arjun spawn + tempfile JSON parse
```typescript
// Source: https://github.com/s0md3v/Arjun/wiki/Usage + exporter.py inspection
// Output format: { "<url>": { "method": "GET", "params": ["..."], "headers": {...} } }
import { mkdtemp, readFile, rm } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';

async function runArjun(url: string, wordlist: string, jobId: string): Promise<string[]> {
  const dir = await mkdtemp(join(tmpdir(), `api-discovery-${jobId}-`));
  const outFile = join(dir, 'arjun.json');
  try {
    await spawnCommand(
      '/opt/samureye/venv-security/bin/arjun',
      ['-u', url, '-w', wordlist, '-oJ', outFile, '-m', 'GET', '-t', '10', '-T', '15'],
      { jobId, processName: 'arjun', stage: `arjun ${url}`, maxWaitTime: 60_000 },
    );
    const raw = await readFile(outFile, 'utf8');
    const parsed = JSON.parse(raw) as Record<string, { method: string; params: string[] }>;
    const entry = parsed[url] ?? Object.values(parsed)[0];
    return entry?.params ?? [];
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
```

### Recommended httpx enrichment columns (Schema decision for planner)
```typescript
// shared/schema.ts — aditivo to apiEndpoints
// Planner finalizes; these match Phase 9 additive pattern.
httpxStatus: integer("httpx_status"),
httpxContentType: text("httpx_content_type"),
httpxTech: text("httpx_tech").array().$type<string[]>(),  // array of detected techs
httpxTls: jsonb("httpx_tls").$type<{
  host?: string;
  port?: number;
  tls_version?: string;
  cipher?: string;
  not_after?: string;
  not_before?: string;
  subject_cn?: string;
  subject_san?: string[];
  issuer_cn?: string;
}>(),
httpxLastProbedAt: timestamp("httpx_last_probed_at"),
```

And the matching guard in `database-init.ts`:
```typescript
export async function ensureApiEndpointHttpxColumns(): Promise<void> {
  try {
    await db.execute(sql`
      ALTER TABLE api_endpoints
        ADD COLUMN IF NOT EXISTS httpx_status INTEGER,
        ADD COLUMN IF NOT EXISTS httpx_content_type TEXT,
        ADD COLUMN IF NOT EXISTS httpx_tech TEXT[],
        ADD COLUMN IF NOT EXISTS httpx_tls JSONB,
        ADD COLUMN IF NOT EXISTS httpx_last_probed_at TIMESTAMP
    `);
    log.info('ensureApiEndpointHttpxColumns complete');
  } catch (error) {
    log.error({ err: error }, 'ensureApiEndpointHttpxColumns error');
  }
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `@apidevtools/swagger-parser` v11.x | v12.0+ required for SSRF CVE fix | 2025-06 | MUST pin `^12.1.0`; older versions have known-vulnerable HTTP `$ref` resolver. |
| Katana `-em` for content extraction | `-em` is extension-match; use `-xhr` + `-fx` for XHR/form | 2023+ | CONTEXT.md §Katana correction. |
| Hardcoding introspection query | graphql-js `getIntrospectionQuery()` helper | 2018+ | We avoid graphql-js dep; hardcoded literal is canonical and stable (query is spec-frozen). |
| OpenAPI 3.0 as "current" | OpenAPI 3.1 is current (aligned with JSON Schema 2020-12) | 2021-02 | swagger-parser v12 handles 3.1; `type: ['string', 'null']` replaces `nullable: true`. |
| nuclei graphql templates for introspection detection | Phase 11 handles introspection natively; nuclei covers misconfigs (Phase 12) | Intentional split | Phase 11 uses schema; Phase 12 uses templates. No overlap. |
| Kiterunner `.txt` wordlists | `.kite` protobuf compiled (2-10x faster) | 2021 | `routes-large.kite` vendored in Phase 8. Use `-w <.kite file>` directly. |

**Deprecated/outdated:**
- `openapi-sampler` for example generation — not needed in Phase 11 (Phase 13 BOPLA may use).
- `swagger-tools` (npm) — abandoned in favor of `@apidevtools/swagger-parser`.
- Kiterunner `-A` assetnote-wordlist shortcut — requires CDN access; we vendor instead.

## Open Questions

1. **Should `operationName` for GraphQL get a dedicated column or live in `requestSchema.operationName`?**
   - What we know: Phase 9 schema has `requestSchema` JSONB; CONTEXT.md flags this as planner discretion.
   - What's unclear: Phase 12/13 BOLA/BFLA tests will need fast lookup by operation. Index on JSONB is expensive.
   - Recommendation: **Keep in `requestSchema.operationName`** for Phase 11; if Phase 12/13 discovers indexing pain, add column aditivamente. Matches CONTEXT.md "aditivo > migration".

2. **Rate limit semantics for Kiterunner: document the discrepancy between CONTEXT.md "10 QPS" and actual `-x`/`--delay` behavior.**
   - What we know: `-x` is connections-per-host, real rate = f(connections, RTT).
   - What's unclear: Does CONTEXT.md's "10 QPS" requirement satisfy SAFE-01 from Phase 15?
   - Recommendation: Planner documents in task action that Phase 11 passes `-x 5 -j 100 --delay 0` defensive-by-default and leaves the global 10-req/s ceiling to Phase 15's governor layer. Update CONTEXT.md comment to reflect corrected semantics.

3. **Should `scanners/api/preflight.ts` be ONE shared file or FOUR per-binary files?**
   - What we know: `nucleiPreflight.ts` is a single file for one binary; the Phase 11 pattern mirrors but has 4 binaries.
   - What's unclear: A single shared file is more DRY; 4 files isolate tests.
   - Recommendation: **Single shared `preflight.ts` with `preflightApiBinary(name)` function** — memoization map keyed by binary name. Test coverage via parametrized tests. Matches CONTEXT.md "simetria com nuclei" + cleaner.

4. **OAuth2 token cache scope: per-`discoverApi()` call or shared across the job?**
   - What we know: Phase 10 defers cache responsibility to Phase 11 runtime.
   - What's unclear: If a job invokes `discoverApi` for 10 APIs sharing one OAuth provider, redundant mints waste tokens.
   - Recommendation: **Per-call in Phase 11**; Phase 15 may hoist to job-scope. Document in `apiDiscovery.ts` JSDoc.

5. **What `success-status-codes` / `fail-status-codes` for Kiterunner?**
   - What we know: CONTEXT.md says "2xx, 3xx, 401, 403 = hit".
   - What's unclear: Kiterunner default fail codes = `404,400,401,501,502,426,411` — 401 is in defaults.
   - Recommendation: Explicit `--success-status-codes 200,201,204,301,302,401,403 --fail-status-codes 404,501,502,400` override. Mention in task action.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Vitest 4.0.18 |
| Config file | `/opt/samureye/vitest.config.ts` (env `node`, includes `server/**/*.test.ts` + `shared/**/*.test.ts`, testTimeout 10s) |
| Quick run command | `npm test -- server/__tests__/<file>.test.ts` |
| Full suite command | `npm test` |
| Watch mode | `npm run test:watch` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| DISC-01 | Spec-path probing iterates known paths + short-circuits on first 200+JSON | unit | `npm test -- server/__tests__/apiDiscovery/specFetch.test.ts` | ❌ Wave 0 |
| DISC-01 | Spec fetch retries with cred on 401/403 when cred compatible | unit (mock fetch) | same file | ❌ Wave 0 |
| DISC-02 | swagger-parser dereferences OpenAPI 2.0 / 3.0 / 3.1 fixture specs | unit (fixtures) | `npm test -- server/__tests__/apiDiscovery/openapi.test.ts` | ❌ Wave 0 |
| DISC-02 | `$ref` external URL same-origin rejection | unit | same file | ❌ Wave 0 |
| DISC-03 | GraphQL introspection POST + schema→endpoints mapping | unit (mock fetch) | `npm test -- server/__tests__/apiDiscovery/graphql.test.ts` | ❌ Wave 0 |
| DISC-04 | Katana stdout JSONL parse + discoverySources=['crawler'] | unit (fixture JSONL stream) | `npm test -- server/__tests__/apiDiscovery/katana.test.ts` | ❌ Wave 0 |
| DISC-05 | Kiterunner opt-in (default off) + JSON output parse | unit | `npm test -- server/__tests__/apiDiscovery/kiterunner.test.ts` | ❌ Wave 0 |
| DISC-06 | `specHash` canonical (deep key-sort) stable across key-order variants | unit (pure function) | `npm test -- server/__tests__/apiDiscovery/specHash.test.ts` | ❌ Wave 0 |
| DISC-06 | Drift detection logs warn + re-parses | unit (mock storage) | `npm test -- server/__tests__/apiDiscovery/drift.test.ts` | ❌ Wave 0 |
| ENRH-01 | httpx JSON-per-line parse + extract status/tech/TLS | unit | `npm test -- server/__tests__/apiDiscovery/httpx.test.ts` | ❌ Wave 0 |
| ENRH-02 | tri-valor `requiresAuth` mapping (401/403→true, 2xx/3xx→false, 5xx/timeout→null) | unit (pure function) | same file | ❌ Wave 0 |
| ENRH-03 | Arjun input validation (only GET + apiId match) + JSON output parse (dict-keyed) + merge into query_params | unit + integration | `npm test -- server/__tests__/apiDiscovery/arjun.test.ts` | ❌ Wave 0 |
| (cross-cutting) | Orchestrator: stage skip on binary missing (preflight false) continues pipeline | unit (mock preflight) | `npm test -- server/__tests__/apiDiscovery/orchestrator.test.ts` | ❌ Wave 0 |
| (cross-cutting) | Cancellation via AbortController persists partial endpoints | integration (in-memory storage) | same file | ❌ Wave 0 |
| (cross-cutting) | Dedupe: append `discoverySources`, preserve `requestSchema` via COALESCE | unit (storage) | `npm test -- server/__tests__/apiDiscovery/dedupeUpsert.test.ts` | ❌ Wave 0 |
| (cross-cutting) | `discoverApiOptsSchema` Zod validates all branches | unit | `npm test -- shared/discoverApiOptsSchema.test.ts` | ❌ Wave 0 |
| (cross-cutting) | Route `POST /api/v1/apis/:id/discover` RBAC admin+operator, validates opts | route (in-process express) | `npm test -- server/__tests__/apiDiscovery/route.test.ts` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `npm test -- server/__tests__/apiDiscovery/<changed>.test.ts` (target: < 5s)
- **Per wave merge:** `npm test -- server/__tests__/apiDiscovery/` + `npm test -- shared/discoverApiOptsSchema.test.ts` (target: < 15s)
- **Phase gate:** Full `npm test` green before `/gsd:verify-work` (current baseline: 487 passing, expecting +20-30 new)

### Wave 0 Gaps

- [ ] Directory: `server/__tests__/apiDiscovery/` (new subdirectory)
- [ ] `server/__tests__/apiDiscovery/specFetch.test.ts` — covers DISC-01 (path iteration + auth retry)
- [ ] `server/__tests__/apiDiscovery/openapi.test.ts` — covers DISC-02 (2.0/3.0/3.1 fixtures + SSRF guard)
- [ ] `server/__tests__/apiDiscovery/graphql.test.ts` — covers DISC-03 (introspection parse + operations→endpoints)
- [ ] `server/__tests__/apiDiscovery/katana.test.ts` — covers DISC-04 (JSONL parse + discoverySources append)
- [ ] `server/__tests__/apiDiscovery/kiterunner.test.ts` — covers DISC-05 (opt-in default + JSON output)
- [ ] `server/__tests__/apiDiscovery/specHash.test.ts` — covers DISC-06 (canonical hash stability)
- [ ] `server/__tests__/apiDiscovery/drift.test.ts` — covers DISC-06 (log.warn + re-parse)
- [ ] `server/__tests__/apiDiscovery/httpx.test.ts` — covers ENRH-01 + ENRH-02 (tri-valor + JSON parse)
- [ ] `server/__tests__/apiDiscovery/arjun.test.ts` — covers ENRH-03 (endpoint ID validation + dict-keyed JSON + merge)
- [ ] `server/__tests__/apiDiscovery/orchestrator.test.ts` — cross-cutting (preflight skip + cancellation)
- [ ] `server/__tests__/apiDiscovery/dedupeUpsert.test.ts` — cross-cutting (storage upsert semantics)
- [ ] `server/__tests__/apiDiscovery/route.test.ts` — cross-cutting (RBAC + Zod validation)
- [ ] `shared/discoverApiOptsSchema.test.ts` — cross-cutting (Zod schema exhaustive)
- [ ] `server/__tests__/apiDiscovery/fixtures/openapi-2.0.json` — sample OpenAPI 2.0 spec (PetStore-like)
- [ ] `server/__tests__/apiDiscovery/fixtures/openapi-3.0.json` — sample OpenAPI 3.0 spec
- [ ] `server/__tests__/apiDiscovery/fixtures/openapi-3.1.json` — sample OpenAPI 3.1 spec (uses `type: ['string','null']`)
- [ ] `server/__tests__/apiDiscovery/fixtures/graphql-introspection.json` — sample `__schema` response
- [ ] `server/__tests__/apiDiscovery/fixtures/katana-jsonl.txt` — sample katana JSONL stream
- [ ] `server/__tests__/apiDiscovery/fixtures/httpx-json.txt` — sample httpx JSON lines
- [ ] `server/__tests__/apiDiscovery/fixtures/kiterunner-json.txt` — sample kiterunner JSON output
- [ ] `server/__tests__/apiDiscovery/fixtures/arjun-output.json` — sample Arjun dict-keyed output
- [ ] Framework install: not needed — vitest already present; no new framework required.

## Sources

### Primary (HIGH confidence)

- **`@apidevtools/swagger-parser` npm registry** — version 12.1.0 (published 2026-01-24) verified via `npm view @apidevtools/swagger-parser version`
- **`@apidevtools/swagger-parser` official options docs** — https://apidevtools.com/swagger-parser/options.html (resolve.http custom reader, dereference options, circular refs)
- **Katana usage docs** — https://docs.projectdiscovery.io/tools/katana/usage (confirmed `-xhr`, `-fx`, `-jc`, `-jsonl`, `-fs`, `-hl`, `-H`, `-em` semantics)
- **Katana README** — https://github.com/projectdiscovery/katana (flag groups OUTPUT/SCOPE/FILTER/HEADLESS/CONFIG)
- **httpx README** — https://github.com/projectdiscovery/httpx (`-json`, `-td`, `-ct`, `-sc`, `-tls-grab`, `-H`, `-rl`, `-timeout` defaults)
- **Kiterunner repo** — https://github.com/assetnote/kiterunner (`kr scan` flags, `-x` = max-connection-per-host NOT QPS, `--delay`, `-j`)
- **Kiterunner issue #29 (throttling/delay)** — https://github.com/assetnote/kiterunner/issues/29 (authoritative on `-x` semantics and the 5-10 range recommendation)
- **Arjun wiki usage** — https://github.com/s0md3v/Arjun/wiki/Usage (flag table verified: `-oJ`, `--ratelimit`, `--stable`, `-t`, `-T`, `-c`, `-d` threads=1 gotcha)
- **Arjun exporter.py** — https://github.com/s0md3v/Arjun/blob/master/arjun/core/exporter.py (JSON output schema is dict keyed by URL)
- **GraphQL introspection spec** — https://spec.graphql.org/October2021/#sec-Introspection (canonical `__schema`/`__type`/`__Directive` shape)
- **GraphQL introspection learn page** — https://graphql.org/learn/introspection/ (standard query structure)
- **Project codebase** — `server/services/scanners/vulnScanner.ts`, `server/services/journeys/nucleiPreflight.ts`, `server/storage/apiEndpoints.ts`, `server/services/processTracker.ts`, `server/services/jobQueue.ts` (established patterns)
- **Project planning** — `.planning/phases/11-discovery-enrichment/11-CONTEXT.md`, Phase 9 and Phase 10 CONTEXT.md (carry-forward decisions)

### Secondary (MEDIUM confidence — WebSearch verified against official docs)

- swagger-parser CHANGELOG mentions CVE fix in v12.0.0 (search result; not fetched directly) — recommend verifying at https://github.com/APIDevTools/swagger-parser/blob/main/CHANGELOG.md before finalizing dependency lock.
- `-fs rdn` semantics for "root domain + subdomains" — verified both in search result and katana docs.
- `graphql-js` `getIntrospectionQuery()` exists since 2018; literal is derived from that function's output.

### Tertiary (LOW confidence — flagged for validation)

- Exact HTTP return status on kiterunner success vs fail status codes: search result lists defaults as `404,400,401,501,502,426,411` but doesn't fully enumerate — a planner should validate empirically during Wave 0 via a smoke test against a known target.
- Arjun `--ratelimit` behavior (does it interact with `--stable`?) — docs unclear; recommend testing if rate control is needed.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — swagger-parser v12.1.0 verified via npm; binaries pinned by Phase 8 with SHA-256.
- Architecture: HIGH — all four patterns (spawn, JSONL, preflight, upsert) have verbatim templates in existing Phase 9-10 code.
- Pitfalls: HIGH — SSRF, flag confusion, rate-limit semantics, tri-valor mapping all confirmed against upstream docs + codebase. Pitfall 6 (GraphQL GET vs POST) MEDIUM — based on spec tolerance but not empirically tested against Samureye test target.
- Code examples: HIGH — all examples based on existing code patterns or verified docs.
- Validation architecture: HIGH — vitest baseline verified, file list derived from scanners-per-tool structure.

**Research date:** 2026-04-19
**Valid until:** 2026-05-19 (30 days — pinned binaries + pinned npm version; re-verify if Phase 12+ bumps swagger-parser)

**Corrections to CONTEXT.md (surface to planner):**
1. Katana extraction flags: replace `-em xhr,fetch,websocket,ajax,form` with `-xhr -fx -jc` (verified against official docs).
2. Kiterunner rate limit: `-x 10` is NOT 10 QPS; it's 10 TCP connections per host. Defensive default should be `-x 5 -j 100`; true QPS ceiling belongs to Phase 15 SAFE-01 governor.
3. `specHash` canonicalization: single-level `Object.keys(spec).sort()` is insufficient; use recursive canonicalize (Pitfall 5 + Code Example §specHash).
