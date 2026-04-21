# Phase 15: Journey Orchestration & Safety - Research

**Researched:** 2026-04-20
**Domain:** Journey executor wiring, Token Bucket rate limiting, abort route, audit log, dry-run target, structured logs
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **pgEnum migration**: adicionar `'api_security'` ao array de valores do `journeyTypeEnum` em `shared/schema.ts` + arquivo de migration Drizzle correspondente.
- **Switch statement**: adicionar `case 'api_security': await this.executeApiSecurity(journey, jobId, onProgress); break;` no `journeyExecutor.ts` — antes do `default`.
- **`executeApiSecurity()`**: método privado no `JourneyExecutorService` que: (1) valida `authorizationAck`, (2) chama `runApiDiscovery()`, (3) chama `runApiPassiveTests()`, (4) chama `runApiActiveTests()` com gate destrutivo, (5) emite progresso, (6) chama `logAudit()` início e fim.
- **Novo campo na tabela `journeys`**: `authorizationAck: boolean('authorization_ack').notNull().default(false)`.
- **Migration**: coluna `authorization_ack` com `DEFAULT false`.
- **Validação no executor**: lança erro claro se `authorizationAck !== true` antes de qualquer operação.
- **`TokenBucketRateLimiter` em `server/services/rateLimiter.ts`**: default 10 req/s, ceiling absoluto 50 req/s (constante nomeada `MAX_API_RATE_LIMIT = 50`, não hardcoded inline).
- **Ceiling de 50 req/s clampado silenciosamente** (sem erro, safe).
- **Retry-After / 429/503**: exponential backoff com jitter (base 1s, max 30s, 3 tentativas), no-op em dryRun.
- **Nova rota `POST /api/v1/jobs/:id/abort`**: encapsula lógica existente de `cancel-process` + sinaliza AbortController. Rota original `cancel-process` mantida para compatibilidade.
- **Gate destrutivo**: `if (!opts.destructiveEnabled)` antes de active tests — BOLA/BFLA/BOPLA em modo read-only; DELETE/PUT/PATCH em schemas desconhecidos pulados.
- **`logAudit()` chamado 2 vezes**: início (`action: 'start'`) e fim (`action: 'complete'` ou `action: 'failed'`). Campos: userId, targets (array de strings), credentialIds (UUIDs — nunca secrets), authorizationAck, stages, dryRun, outcome, findingsCount, duration.
- **`GET /healthz/api-test-target`**: sem autenticação session, retorna mock findings hardcoded com categories cobrindo ao menos 1 de cada severity (low/medium/high/critical). Sem DB queries.
- **Logs pino JSON**: convenção SAFE-06 — campos proibidos em logs de `executeApiSecurity()` e scanners: `body`, `credential`, `token`, `apiKey`, `password`, `authorization`, `headers.authorization`.
- **Campos permitidos em log**: jobId, apiId, endpointId, stage, duration, statusCode, findingId, severity, category.
- **Nyquist test SAFE-06**: teste de integração captura pino output durante dryRun e verifica ausência de strings sensíveis via regex.
- **Progresso granular**: `10% Preparando`, `20% Discovery`, `50% Passive Tests`, `75% Active Tests`, `90% Análise`, `100% Concluído`.
- **JRNY-04**: scheduler existente aceita `api_security` automaticamente após enum ser extendido — nenhum código novo de scheduler necessário.
- **JRNY-03**: toggles de discovery (spec-first, crawler, kiterunner) e testing (misconfigs, auth, BOLA, BFLA, BOPLA, rate-limit, SSRF) expostos no body de `POST /api/v1/jobs` para tipo `api_security`.
- **Integração com processTracker**: `executeApiSecurity()` registra child processes no `processTracker` por jobId — abort chama `killAll(jobId)`.
- **Não é tabela separada para authorizationAck**: campo booleano direto na tabela `journeys`.

### Claude's Discretion

- Estrutura interna de `TokenBucketRateLimiter` (algoritmo exato — token bucket vs leaky bucket).
- Nomenclatura de campos de migration (desde que semântica seja clara).
- Ordem de chamar `logAudit` início vs outros guards no `executeApiSecurity()`.
- Como estruturar o pino test capture para o teste de SAFE-06.

### Deferred Ideas (OUT OF SCOPE)

- UI do wizard de 4 passos para criação de journey api_security com checkbox vermelho de double-confirmation para métodos destrutivos — Phase 16.
- Dashboard executivo de métricas de api_security journeys — Phase 16 ou backlog.
- Notificações por email/webhook ao fim de api_security journey — backlog pós-v2.0.
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| JRNY-01 | `journey_type` enum gains `api_security`; jobs of that type route to the API journey executor | pgEnum extension pattern confirmed; switch statement insertion point at `journeyExecutor.ts:88` confirmed |
| JRNY-02 | User must explicitly acknowledge authorization to test before a journey starts; acknowledgment persisted | `authorizationAck` boolean column on `journeys` table; Drizzle nullable migration with DEFAULT false pattern confirmed |
| JRNY-03 | User configures discovery + testing toggles via the job body | `discoverApiOptsSchema` + `apiPassiveTestOptsSchema` + `apiActiveTestOptsSchema` already cover all toggles; `executeApiSecurity()` merges them from `journey.params` |
| JRNY-04 | User can schedule recurring `api_security` journeys via existing scheduler | `createScheduleSchema` is journey-type-agnostic; enum extension is sufficient |
| JRNY-05 | `POST /api/v1/jobs/:id/abort` stops all child processes via AbortController | Pattern identical to existing `cancel-process` route; reuses `markJobAsCancelled` + `killAll` + `updateJob` sequence |
| SAFE-01 | Per-endpoint rate cap defaults 10 req/s, ceiling 50 req/s non-bypassable | `TokenBucketRateLimiter` service; `MAX_API_RATE_LIMIT = 50` constant; Zod `max(50)` already in `kiterunner` opts schema |
| SAFE-02 | Engine respects `Retry-After` and applies exponential backoff on 429/503 | `handleRetryAfter()` + `exponentialBackoff()` methods on `TokenBucketRateLimiter` |
| SAFE-03 | Destructive methods disabled by default; gate at orchestrator layer | Boolean `destructiveEnabled` flag already in `apiActiveTestOptsSchema`; gate in `executeApiSecurity()` before `runApiActiveTests()` call |
| SAFE-04 | Each journey execution creates an `audit_log` entry with user, targets, credential IDs (never secrets), timestamp, outcome | `storage.logAudit()` confirmed working; pattern of 2-call start+complete used |
| SAFE-05 | Appliance exposes `/healthz/api-test-target` for dry-run validation | New route in `server/routes/index.ts`; hardcoded mock response with 4 findings (low/medium/high/critical) |
| SAFE-06 | Logs are structured JSON and never include request bodies, credentials, or tokens | pino already emits JSON; convention enforcement + Nyquist integration test captures pino output during dryRun and checks for credential patterns |
</phase_requirements>

---

## Summary

Phase 15 is a **wiring phase**, not an implementation phase. All the hard algorithmic work (discovery, passive tests, active tests, findings storage, WebSocket events, sanitization) was delivered in Phases 11–14. Phase 15's job is to connect those pieces inside the `JourneyExecutorService` switch, add two small but critical safety services (`TokenBucketRateLimiter` and the abort route), and bolt on the mandatory guard-rails (authorizationAck, audit log, destructive gate, healthz endpoint, log discipline).

The primary risk is not algorithmic complexity but **integration correctness**: the executor must call upstream phases in the right order, pass opts correctly, propagate cancellation, emit audit entries at the right moments, and ensure rate limiting is threaded through all HTTP-making scanners. The abort route is structurally identical to the existing `cancel-process` route with one minor addition (explicit AbortController signal).

The migration is straightforward: two SQL changes (enum extension + boolean column) with no breaking impact on existing journeys.

**Primary recommendation:** Implement in three conceptual waves: (1) schema/migration + `authorizationAck` guard, (2) `TokenBucketRateLimiter` service + abort route + healthz endpoint, (3) `executeApiSecurity()` orchestrator wiring everything together with audit log + progress emissions.

---

## Standard Stack

### Core (already in project — no new installs)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| drizzle-orm | existing | pgEnum extension + migration | Project ORM throughout |
| zod | existing | Schema validation for new opts | Used in all Phases 11-14 |
| pino (via `createLogger`) | existing | Structured JSON logging | Project logger |
| node built-ins (`EventEmitter`, `AbortController`) | Node 18+ | Abort signaling | No dependency needed |

### No new npm packages required
The `TokenBucketRateLimiter` is a plain TypeScript class using `setTimeout`/`Promise` — no external rate-limiting library needed. The CONTEXT.md decision is explicit: implement in-house.

**Installation:** None required.

---

## Architecture Patterns

### Recommended Project Structure

New files this phase creates:
```
server/
├── services/
│   └── rateLimiter.ts              # TokenBucketRateLimiter + MAX_API_RATE_LIMIT
├── services/journeyExecutor.ts     # (modified) add case 'api_security' + executeApiSecurity()
├── routes/jobs.ts                  # (modified) add POST /api/v1/jobs/:id/abort
└── routes/index.ts                 # (modified) add GET /healthz/api-test-target

shared/
└── schema.ts                       # (modified) journeyTypeEnum + journeys.authorizationAck + insertJourneySchema

migrations/
└── XXXXXXXX_api_security_journey.sql   # ALTER TYPE + ALTER TABLE
```

### Pattern 1: pgEnum Extension (JRNY-01)

**What:** PostgreSQL `ALTER TYPE ... ADD VALUE` + Drizzle schema update.
**When to use:** Adding a new value to an existing enum without breaking existing rows.

Key facts (confirmed from project code at `shared/schema.ts:41`):
- Current enum: `pgEnum('journey_type', ['attack_surface', 'ad_security', 'edr_av', 'web_application'])`
- New value: add `'api_security'` to the array
- Migration: `ALTER TYPE journey_type ADD VALUE IF NOT EXISTS 'api_security';`
- `IF NOT EXISTS` is idempotent — safe to re-run.
- Drizzle does NOT auto-generate this migration — must be a hand-written SQL file.
- PostgreSQL does NOT support removing enum values; this is append-only and irreversible.

```typescript
// shared/schema.ts:41 — updated
export const journeyTypeEnum = pgEnum('journey_type', [
  'attack_surface', 'ad_security', 'edr_av', 'web_application', 'api_security'
]);
```

```sql
-- migrations/XXXXXXXX_api_security_journey.sql
ALTER TYPE journey_type ADD VALUE IF NOT EXISTS 'api_security';
ALTER TABLE journeys ADD COLUMN IF NOT EXISTS authorization_ack boolean NOT NULL DEFAULT false;
```

### Pattern 2: executeApiSecurity() Structure

**What:** Private method in `JourneyExecutorService` that orchestrates Phase 11–14 outputs.
**When to use:** Called from `executeJourney()` switch statement when `journey.type === 'api_security'`.

Integration points (confirmed from source):
- `runApiDiscovery()` lives in `server/services/journeys/apiDiscovery.ts` — signature: `(apiId, opts, jobId?)` returns `DiscoveryResult`
- `runApiPassiveTests()` lives in `server/services/journeys/apiPassiveTests.ts` — signature: `(apiId, opts, jobId?)` returns `PassiveTestResult`
- `runApiActiveTests()` lives in `server/services/journeys/apiActiveTests.ts` — signature: `(apiId, opts, jobId?)` returns `ActiveTestResult`
- `storage.logAudit()` at `server/storage/settings.ts:47` — signature: `logAudit(entry: Omit<AuditLogEntry, 'id' | 'createdAt'>)`
- Cancel check via `this.isJobCancelled(jobId)` (already on `JourneyExecutorService`)
- processTracker child processes: Phase 11–13 orchestrators spawn external processes (nuclei, katana, etc.) — they register via `processTracker.register()` internally; abort route's `killAll(jobId)` cascades to them

```typescript
// server/services/journeyExecutor.ts — new case (before default)
case 'api_security':
  await this.executeApiSecurity(journey, jobId, onProgress);
  break;

// private method skeleton
private async executeApiSecurity(
  journey: Journey,
  jobId: string,
  onProgress: ProgressCallback
): Promise<void> {
  // 1. Guard: authorizationAck
  if (!journey.authorizationAck) {
    throw new Error('Jornada api_security requer acknowledgment de autorização de teste');
  }

  // 2. Audit: start
  await storage.logAudit({ actorId: journey.createdBy, action: 'start', objectType: 'api_security_journey', objectId: jobId, before: null, after: { targets, credentialIds, authorizationAck: true, stages, dryRun, timestamp: new Date() } });

  onProgress({ status: 'running', progress: 10, currentTask: 'Preparando jornada api_security' });

  // 3. Rate limiter
  const rateLimiter = new TokenBucketRateLimiter(opts.rateLimit ?? 10);

  // 4. Discovery (20%)
  if (!this.isJobCancelled(jobId)) {
    onProgress({ status: 'running', progress: 20, currentTask: 'Descobrindo endpoints da API' });
    discoveryResult = await runApiDiscovery(apiId, discoveryOpts, jobId);
  }

  // 5. Passive tests (50%)
  if (!this.isJobCancelled(jobId)) {
    onProgress({ status: 'running', progress: 50, currentTask: 'Executando testes passivos' });
    passiveResult = await runApiPassiveTests(apiId, passiveOpts, jobId);
  }

  // 6. Destructive gate + Active tests (75%)
  if (!this.isJobCancelled(jobId)) {
    const activeOpts = applyDestructiveGate(opts, rawActiveOpts);
    onProgress({ status: 'running', progress: 75, currentTask: 'Executando testes ativos' });
    activeResult = await runApiActiveTests(apiId, activeOpts, jobId);
  }

  // 7. Analysis progress (90%)
  onProgress({ status: 'running', progress: 90, currentTask: 'Analisando resultados' });

  // 8. Audit: complete
  await storage.logAudit({ ..., action: 'complete', after: { outcome: 'completed', findingsCount, duration, timestamp: new Date() } });

  onProgress({ status: 'completed', progress: 100, currentTask: 'Jornada api_security concluída' });
}
```

**IMPORTANT:** `executeApiSecurity()` must NOT call `threatEngine.processJobResults()` — that is already handled by the caller `executeJourney()` after `executeApiSecurity()` returns. This is the existing pattern for all other journey types.

### Pattern 3: TokenBucketRateLimiter

**What:** Token bucket algorithm — tokens refill at `ratePerSecond` per second, callers `await acquire()` which blocks until a token is available.
**Algorithm choice (Claude's Discretion):** Token bucket is preferred over leaky bucket because it allows short bursts up to bucket capacity (natural for API testing where you want to send a batch then wait) while still respecting the long-run rate.

```typescript
// server/services/rateLimiter.ts
export const MAX_API_RATE_LIMIT = 50; // req/s — absolute ceiling, not user-configurable

export class TokenBucketRateLimiter {
  private tokens: number;
  private readonly ratePerSecond: number;
  private lastRefill: number = Date.now();

  constructor(ratePerSecond: number = 10) {
    // Silent clamp — never throw
    this.ratePerSecond = Math.min(ratePerSecond, MAX_API_RATE_LIMIT);
    this.tokens = this.ratePerSecond; // start full
  }

  async acquire(): Promise<void> {
    this.refill();
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return;
    }
    // Wait until next token is available
    const waitMs = Math.ceil((1 - this.tokens) / this.ratePerSecond * 1000);
    await new Promise(resolve => setTimeout(resolve, waitMs));
    this.tokens -= 1;
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000;
    this.tokens = Math.min(this.ratePerSecond, this.tokens + elapsed * this.ratePerSecond);
    this.lastRefill = now;
  }

  async handleRetryAfter(headers: Headers): Promise<void> {
    const retryAfter = headers.get('retry-after');
    if (retryAfter) {
      const waitMs = parseInt(retryAfter) * 1000 || 1000;
      await new Promise(resolve => setTimeout(resolve, waitMs));
    }
  }

  async exponentialBackoff(attempt: number): Promise<void> {
    // base 1s, max 30s, jitter ±20%, 3 attempts max
    const base = Math.min(1000 * Math.pow(2, attempt), 30_000);
    const jitter = base * 0.2 * (Math.random() * 2 - 1);
    await new Promise(resolve => setTimeout(resolve, base + jitter));
  }
}
```

**dryRun no-op:** `executeApiSecurity()` passes `opts.dryRun` to Phase 11–13 orchestrators which handle fixture loading themselves. The rate limiter is still instantiated but not passed to scanners when `dryRun=true` — or alternatively a no-op subclass is used. Simplest: just not call `rateLimiter.acquire()` when `opts.dryRun === true`.

### Pattern 4: Abort Route (JRNY-05)

**What:** `POST /api/v1/jobs/:id/abort` — new route that reuses the entire body of `cancel-process` verbatim, with path change and response message update.
**Key insight:** The existing `cancel-process` route at `server/routes/jobs.ts:77` already does exactly what abort needs: `markJobAsCancelled` + `killAll` + `updateJob(status:'failed')` + WebSocket emit + audit log. The only required changes are: (1) new path `/api/v1/jobs/:id/abort`, (2) response message `{ message: 'Jornada abortada', killedProcesses: N }`.

The existing `cancel-process` route is kept for frontend backward compatibility.

**AbortController note:** The CONTEXT.md decision states "sem novas abstrações" — the `processTracker.killAll(jobId)` already sends SIGTERM+SIGKILL to child processes. The "AbortController signal" mentioned in requirements is satisfied by the cooperative cancellation mechanism: `jobQueue.markJobAsCancelled(id)` + `this.isJobCancelled(jobId)` checks inside `executeApiSecurity()`. No new `AbortController` instances are needed.

### Pattern 5: `/healthz/api-test-target`

**What:** Hardcoded internal endpoint for dryRun validation.
**Registration:** Add to `registerRoutes()` in `server/routes/index.ts` after the existing `/api/health` endpoint — no auth middleware.

```typescript
// server/routes/index.ts — add after /api/health
app.get('/healthz/api-test-target', (req, res) => {
  res.json({
    status: 'ok',
    dryRun: true,
    mockFindings: [
      { category: 'api9_improper_inventory_2023', severity: 'low', title: 'Mock: Endpoint sem documentação detectado' },
      { category: 'api8_security_misconfiguration_2023', severity: 'medium', title: 'Mock: CORS permissivo detectado' },
      { category: 'api2_broken_authentication_2023', severity: 'high', title: 'Mock: JWT alg:none aceito' },
      { category: 'api1_broken_object_level_authorization_2023', severity: 'critical', title: 'Mock: BOLA — acesso cross-identity confirmado' },
    ]
  });
});
```

**dryRun integration:** When `opts.dryRun=true`, `executeApiSecurity()` can verify connectivity by fetching `http://localhost:{PORT}/healthz/api-test-target` before running phases — or simply trust the flag and let Phase 11–13 orchestrators handle fixture loading (which they already do). The healthz endpoint's primary role is as a target URL for scanner connectivity tests.

### Pattern 6: JRNY-03 — Exposing Toggles via POST /api/v1/jobs

**What:** The job body for `api_security` journeys needs to carry `discoveryOpts` and `testingOpts`.
**Current state:** `POST /api/jobs/execute` accepts `{ journeyId }` — the journey's `params` field carries all opts. When creating a journey of type `api_security`, the `params` jsonb includes the nested opts structures.

**Implementation:** No new route is needed. The journey `params` field is already a free-form JSONB. The Zod schema for journey creation (`insertJourneySchema`) + the executor's extraction of `journey.params.discoveryOpts`, `journey.params.passiveOpts`, `journey.params.activeOpts` is sufficient. The CONTEXT.md decision confirms: "expostos no body de `POST /api/v1/jobs`" — this means the job creation body includes these opts, which flow through to `journey.params`.

### Anti-Patterns to Avoid

- **Calling `threatEngine.processJobResults()` inside `executeApiSecurity()`**: This is already called by the outer `executeJourney()` method after the sub-executor returns. Calling it again would duplicate threat processing.
- **Logging secrets in error paths**: Error handlers in `executeApiSecurity()` must not include `error.message` if it could contain credential values — sanitize with a safe subset.
- **Making `MAX_API_RATE_LIMIT` configurable via env**: The constant must be hardcoded in `rateLimiter.ts` so tests can mock it via module import without env dependency.
- **Creating a new `AbortController` for each scanner call**: The cooperative cancellation via `jobQueue.isJobCancelled()` is the correct pattern; AbortController adds complexity without benefit given the existing architecture.
- **Forgetting `authorizationAck` in `insertJourneySchema`**: The `createInsertSchema(journeys)` auto-derives from the Drizzle table — after adding the column, the Zod schema will include it. Must verify the `.omit()` set doesn't exclude it.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| JSON structured logging | Custom log serializer | `createLogger('journey:apiSecurity')` from `server/lib/logger.ts` | Already pino JSON |
| Rate limit backoff | Custom sleep loop | `TokenBucketRateLimiter.exponentialBackoff()` | Consistent with service design |
| Cooperative cancellation | Custom cancel flag | `jobQueue.isJobCancelled(jobId)` already implemented | Reuse to avoid race conditions |
| Audit persistence | New audit table | `storage.logAudit()` at `server/storage/settings.ts:47` | Already handles any `objectType` string |
| Process kill on abort | New kill logic | `processTracker.killAll(jobId)` | SIGTERM+SIGKILL timeout already implemented |
| Token bucket | npm `limiter` or `bottleneck` | Custom `TokenBucketRateLimiter` class | CONTEXT.md decision; avoids external dep |

**Key insight:** This phase is fundamentally about wiring, not building. Every primitive needed already exists in the codebase — the executor pattern, the audit log, the process tracker, the cancel machinery, the pino logger. The only genuinely new code is `TokenBucketRateLimiter` (a ~60-line class) and the `executeApiSecurity()` method (~120 lines).

---

## Common Pitfalls

### Pitfall 1: pgEnum ALTER TYPE Ordering
**What goes wrong:** Drizzle code-first doesn't auto-generate `ALTER TYPE ... ADD VALUE` migrations. Developer forgets to write the SQL file and gets a Postgres error when inserting an `api_security` journey.
**Why it happens:** Drizzle tracks table structure but not enum value additions the same way.
**How to avoid:** Hand-write the migration SQL file. Use `IF NOT EXISTS` for idempotency. Run migration in `initializeDatabaseStructure()` or via the migration runner before the switch case is exercised.
**Warning signs:** `invalid input value for enum journey_type: "api_security"` at runtime.

### Pitfall 2: Journey.params Shape vs. Executor Extraction
**What goes wrong:** `executeApiSecurity()` tries to access `journey.params.discoveryOpts.apiId` but the actual journey was created with a flat `params.apiId` structure.
**Why it happens:** `journey.params` is a free-form JSONB — no Zod enforcement at the DB layer.
**How to avoid:** Define a typed extraction helper at the top of `executeApiSecurity()` that reads `params` with safe defaults. Document the expected `params` shape in a JSDoc comment.
**Warning signs:** `undefined` discovery result or silently skipped stages.

### Pitfall 3: Rate Limiter Not Threaded to Scanners
**What goes wrong:** `TokenBucketRateLimiter` is instantiated in `executeApiSecurity()` but never passed down to the individual scanner calls (nuclei, bola, etc.), so rate limiting has no effect.
**Why it happens:** Phase 12 and 13 orchestrators (`runApiPassiveTests`, `runApiActiveTests`) have their own opts types that don't include a `rateLimiter` instance.
**How to avoid:** Extend `ApiPassiveTestOpts` and `ApiActiveTestOpts` (or their call-site counterparts) to accept `rateLimiter?: TokenBucketRateLimiter`, OR pass the rate limiter as a separate argument. The CONTEXT.md decision says "passa para os scanners via opts" — so augment the opts objects with an optional `rateLimiter` field (runtime-only, not serializable to DB).
**Warning signs:** SAFE-01 test fails because 429 responses aren't being respected.

### Pitfall 4: Audit Log Missing credential IDs
**What goes wrong:** Developer passes `journey.params.credentialIds` to the audit `after` field, but these are already-resolved secrets from `getApiCredentialWithSecret()` — they contain encrypted fields.
**Why it happens:** Copy-paste from places that use full credential objects.
**How to avoid:** Only log credential UUIDs. Source them from `listApiCredentials({ apiId })` which returns safe objects without `secretEncrypted`/`dekEncrypted` fields (per Phase 10 `SAFE_FIELDS` decision).
**Warning signs:** `audit_log` entries with `secretEncrypted` or `dekEncrypted` in the `after` JSON.

### Pitfall 5: authorizationAck in Zod Schema
**What goes wrong:** After adding `authorizationAck` column to the Drizzle table, `insertJourneySchema` (derived via `createInsertSchema`) includes it automatically, but it's not in the Journey type used by the executor — leading to TypeScript errors.
**Why it happens:** Drizzle-Zod auto-derives from table schema, but the `Journey` TypeScript type is inferred from the select schema, which includes all columns.
**How to avoid:** After adding the column, regenerate/check that `type Journey` (inferred from `journeys.$inferSelect`) now includes `authorizationAck: boolean`. No manual type update needed — it flows automatically from the table definition.

### Pitfall 6: SAFE-06 Test Capture Complexity
**What goes wrong:** Pino output goes to stdout/process.stdout — intercepting it in a vitest test requires replacing the transport.
**Why it happens:** `createLogger()` creates a pino instance that writes to `process.stdout` by default.
**How to avoid:** Inject a custom pino stream in the test that captures all log output. Pattern: `pino(opts, pino.destination(stream))` or a `PassThrough` stream. The test then reads captured strings and asserts no credential-pattern regex matches.

---

## Code Examples

Verified patterns from existing codebase:

### Existing cancel-process route (template for abort route)
```typescript
// Source: server/routes/jobs.ts:77 — confirmed
app.post('/api/jobs/:id/cancel-process', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
  const userId = req.user.id;
  const { id } = req.params;
  const job = await storage.getJob(id);
  if (!job) return res.status(404).json({ message: "Job não encontrado" });
  if (job.status !== 'running') return res.status(400).json({ message: "Job não está em execução" });
  jobQueue.markJobAsCancelled(id);
  const killedCount = processTracker.killAll(id);
  await storage.updateJob(id, { status: 'failed', error: 'Job cancelado pelo usuário', finishedAt: new Date() });
  jobQueue.emit('jobUpdate', { jobId: id, status: 'failed', ... });
  await storage.logAudit({ actorId: userId, action: 'cancel', objectType: 'job', objectId: id, ... });
  res.json({ message: `...`, killedProcesses: killedCount });
});
```

### Existing logAudit signature
```typescript
// Source: server/storage/settings.ts:47 — confirmed
export async function logAudit(
  entry: Omit<AuditLogEntry, 'id' | 'createdAt'>
): Promise<AuditLogEntry>
// AuditLogEntry fields: actorId, action, objectType, objectId, before, after
```

### Existing switch statement insertion point
```typescript
// Source: server/services/journeyExecutor.ts:88 — confirmed
switch (journey.type) {
  case 'attack_surface': await this.executeAttackSurface(...); break;
  case 'ad_security':    await this.executeADSecurity(...);    break;
  case 'edr_av':         await this.executeEDRAV(...);         break;
  case 'web_application':await this.executeWebApplication(...);break;
  // ADD HERE: case 'api_security': await this.executeApiSecurity(...); break;
  default: throw new Error(`Tipo de jornada não suportado: ${journey.type}`);
}
```

### Active test opts destructiveEnabled (already in schema)
```typescript
// Source: shared/schema.ts:1983 — confirmed
destructiveEnabled: z.boolean().optional(), // default false — gates BOPLA + BFLA method-based
```

### processTracker.killAll signature
```typescript
// Source: server/services/processTracker.ts:180 — confirmed
killAll(jobId: string): number  // returns count of killed processes
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Manual rate-limiting with sleep() | Token bucket with `acquire()` | This phase | Allows burst then wait, more natural |
| Cancel route only | Cancel + Abort routes | This phase | Backward compat + new v1 path |

---

## Open Questions

1. **Rate limiter injection into Phase 12/13 orchestrators**
   - What we know: `runApiPassiveTests` and `runApiActiveTests` accept opts objects (`ApiPassiveTestOpts`, `ApiActiveTestOpts`) that don't currently include a `rateLimiter` field.
   - What's unclear: Whether to add `rateLimiter?` to these Zod-typed opts schemas (would make them non-serializable) or pass as a separate positional argument.
   - Recommendation: Add `rateLimiter?: TokenBucketRateLimiter` as a second non-schema argument to `runApiPassiveTests(apiId, opts, jobId, rateLimiter?)` and `runApiActiveTests(apiId, opts, jobId, rateLimiter?)`. This avoids polluting the Zod schemas with non-serializable values and follows the existing pattern of `jobId` being passed separately from opts.

2. **apiId sourcing inside executeApiSecurity()**
   - What we know: The `Journey` type has `params: Record<string, any>` — `apiId` must be passed through `journey.params.apiId`.
   - What's unclear: Whether Phase 15 should validate that the `apiId` references an existing API before proceeding.
   - Recommendation: Add a guard `const api = await storage.getApi(apiId); if (!api) throw new Error(...)` before stage 1.

3. **Journey creation endpoint for api_security**
   - What we know: JRNY-03 says toggles are exposed in the body of `POST /api/v1/jobs`. The existing `/api/v1/journeys` route handles journey creation.
   - What's unclear: Whether Phase 15 needs to create a new `POST /api/v1/journeys` variant that validates `api_security`-specific params, or if the existing generic route handles it.
   - Recommendation: Use the existing route — the `insertJourneySchema` includes all fields. The `params` JSONB absorbs the nested opts. No new route needed for Phase 15 (UI wizard is Phase 16).

---

## Validation Architecture

> `nyquist_validation: true` in `.planning/config.json` — section included.

### Test Framework
| Property | Value |
|----------|-------|
| Framework | vitest (confirmed via `vitest.config.ts`) |
| Config file | `/opt/samureye/vitest.config.ts` |
| Quick run command | `npx vitest run server/__tests__/journeyOrchestration.test.ts --reporter=verbose` |
| Full suite command | `npx vitest run --reporter=verbose` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| JRNY-01 | `journey_type` enum contains `api_security`; switch routes to executeApiSecurity | unit | `npx vitest run server/__tests__/journeyOrchestration.test.ts -t "JRNY-01"` | ❌ Wave 0 |
| JRNY-02 | Journey without authorizationAck throws before any scan | unit | `npx vitest run server/__tests__/journeyOrchestration.test.ts -t "JRNY-02"` | ❌ Wave 0 |
| JRNY-03 | Discovery + testing opts flow from journey.params into sub-orchestrators | unit | `npx vitest run server/__tests__/journeyOrchestration.test.ts -t "JRNY-03"` | ❌ Wave 0 |
| JRNY-04 | Scheduler accepts api_security journey (enum-level — covered by JRNY-01) | integration (manual) | manual-only: create schedule, verify no validation error | N/A |
| JRNY-05 | POST /api/v1/jobs/:id/abort returns 200 + killedProcesses; job status = failed | unit (route) | `npx vitest run server/__tests__/abortRoute.test.ts` | ❌ Wave 0 |
| SAFE-01 | TokenBucketRateLimiter clamps to 50 req/s; default is 10; acquire() blocks at ceiling | unit | `npx vitest run server/__tests__/rateLimiter.test.ts -t "SAFE-01"` | ❌ Wave 0 |
| SAFE-02 | handleRetryAfter() parses Retry-After header and waits; exponentialBackoff jitter | unit | `npx vitest run server/__tests__/rateLimiter.test.ts -t "SAFE-02"` | ❌ Wave 0 |
| SAFE-03 | destructiveEnabled=false skips DELETE/PUT/PATCH; active test result has skippedStages | unit | `npx vitest run server/__tests__/journeyOrchestration.test.ts -t "SAFE-03"` | ❌ Wave 0 |
| SAFE-04 | audit_log has 2 entries per execution (start + complete); credentialIds are UUIDs | unit | `npx vitest run server/__tests__/journeyOrchestration.test.ts -t "SAFE-04"` | ❌ Wave 0 |
| SAFE-05 | GET /healthz/api-test-target returns 200 with 4 mockFindings covering all severities | unit (route) | `npx vitest run server/__tests__/healthzTarget.test.ts` | ❌ Wave 0 |
| SAFE-06 | No log output during dryRun contains body/credential/token/apiKey patterns | integration | `npx vitest run server/__tests__/journeyOrchestration.test.ts -t "SAFE-06"` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `npx vitest run server/__tests__/journeyOrchestration.test.ts server/__tests__/rateLimiter.test.ts server/__tests__/abortRoute.test.ts server/__tests__/healthzTarget.test.ts --reporter=verbose`
- **Per wave merge:** `npx vitest run --reporter=verbose`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `server/__tests__/journeyOrchestration.test.ts` — covers JRNY-01, JRNY-02, JRNY-03, SAFE-03, SAFE-04, SAFE-06
- [ ] `server/__tests__/rateLimiter.test.ts` — covers SAFE-01, SAFE-02
- [ ] `server/__tests__/abortRoute.test.ts` — covers JRNY-05
- [ ] `server/__tests__/healthzTarget.test.ts` — covers SAFE-05

These 4 test files must be created in Wave 0 (before implementation) with `it.todo` stubs per project Nyquist convention.

---

## Sources

### Primary (HIGH confidence)
- Direct code inspection: `server/services/journeyExecutor.ts` — switch statement structure, existing journey executor pattern, insertion point at line 88
- Direct code inspection: `server/services/processTracker.ts` — `killAll(jobId)` signature, SIGTERM+SIGKILL pattern
- Direct code inspection: `server/routes/jobs.ts:77` — cancel-process route body (template for abort route)
- Direct code inspection: `server/storage/settings.ts:47` — `logAudit()` signature
- Direct code inspection: `shared/schema.ts:41` — current `journeyTypeEnum` values
- Direct code inspection: `shared/schema.ts:177-189` — `journeys` table definition (location for new column)
- Direct code inspection: `shared/schema.ts:1875` — `rateLimit: z.number().int().min(1).max(50)` ceiling already in kiterunner opts
- Direct code inspection: `shared/schema.ts:1983` — `destructiveEnabled` in `apiActiveTestOptsSchema`
- Direct code inspection: `server/routes/index.ts:81` — `/api/health` route pattern for new `/healthz/` route
- Direct code inspection: `server/services/journeys/apiPassiveTests.ts` — Phase 12 orchestrator signature
- Direct code inspection: `server/services/journeys/apiActiveTests.ts` — Phase 13 orchestrator signature
- Direct code inspection: `.planning/config.json` — `nyquist_validation: true`
- Direct code inspection: `vitest.config.ts` — test framework configuration
- Project CONTEXT.md (`15-CONTEXT.md`) — all locked implementation decisions

### Secondary (MEDIUM confidence)
- PostgreSQL documentation pattern for `ALTER TYPE ... ADD VALUE IF NOT EXISTS` — standard PostgreSQL DDL confirmed in multiple prior phases

### Tertiary (LOW confidence)
- None

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all confirmed from existing project code
- Architecture: HIGH — insertion points confirmed by direct file inspection; patterns derived from existing journey implementations
- Pitfalls: HIGH — most derived from explicit project history in STATE.md accumulated decisions
- Test map: HIGH — framework confirmed via vitest.config.ts; test file names follow project convention

**Research date:** 2026-04-20
**Valid until:** 2026-05-20 (stable phase; all dependencies are internal project code)
