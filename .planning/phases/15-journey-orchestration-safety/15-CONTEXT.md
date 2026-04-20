# Phase 15: Journey Orchestration & Safety - Context

**Gathered:** 2026-04-20 (via `/gsd:discuss-phase 15 --auto`)
**Status:** Ready for planning

<domain>
## Phase Boundary

Conectar a jornada `api_security` ao executor, scheduler e maquinário de abort **já existentes** — acrescentando guardrails de segurança obrigatórios (authorization acknowledgment, rate caps, gating de métodos destrutivos, audit log estruturado, dry-run target) **na camada de orquestração**.

Escopo do Phase 15:
- **JRNY-01** — Estender o pgEnum `journey_type` com `api_security` (migration), adicionar `case 'api_security'` no `journeyExecutor.ts` chamando `executeApiSecurity()`.
- **JRNY-02** — Campo `authorizationAck: boolean` na tabela `journeys` (migration). Journey `api_security` não pode ser iniciada sem `authorizationAck=true`.
- **JRNY-03** — Toggles de discovery (spec-first, crawler, kiterunner) e testing (misconfigs, auth, BOLA, BFLA, BOPLA, rate-limit, SSRF) já modelados nas Phases 12/13 opts; Phase 15 os expõe no body de `POST /api/v1/jobs` para tipo `api_security`.
- **JRNY-04** — Scheduler existente aceita `api_security` automaticamente após enum ser extendido — nenhum código novo de scheduler necessário.
- **JRNY-05** — Nova rota `POST /api/v1/jobs/:id/abort` que encapsula lógica de cancel existente + sinaliza AbortController para child processes.
- **SAFE-01/02** — `TokenBucketRateLimiter` em `server/services/rateLimiter.ts`: default 10 req/s, ceiling absoluto 50 req/s (constante não configurável pelo usuário), respeita `Retry-After` + exponential backoff em 429/503.
- **SAFE-03** — Gate no orchestrator `executeApiSecurity()`: se `destructiveEnabled=false` (default), pula DELETE/PUT/PATCH contra schemas desconhecidos antes de invocar active tests (Phase 13).
- **SAFE-04** — `logAudit()` chamado no início de cada api_security journey execution com userId, targets, credentialIds (nunca secrets), timestamp, outcome inicial `'started'`; atualizado ao fim com `'completed'`/`'failed'`.
- **SAFE-05** — Novo endpoint `GET /healthz/api-test-target` (interno, sem autenticação session — só acesso local/infra) que retorna mock findings para dryRun consumir sem tocar targets reais.
- **SAFE-06** — Logs pino JSON já estruturados; constraintimplementado por convenção: nenhum log.info/warn/error em `executeApiSecurity()` ou scanners faz logging de request body, credenciais, ou tokens.

**Fora de escopo deste phase:**
- UI do wizard 4 passos (Alvos → Autenticação → Configuração → Confirmação) → Phase 16 (UI-05).
- Filtros UI `source=api_security`, curl reproduction, false-positive marking → Phase 16.
- Implementação dos scanners passivos/ativos → Phase 12/13 (já entregues).
- Sanitização de evidence → Phase 14 (já entregue).

</domain>

<decisions>
## Implementation Decisions

### Enum extension + executor wiring (JRNY-01)

- **pgEnum migration**: adicionar `'api_security'` ao array de valores do `journeyTypeEnum` em `shared/schema.ts` + arquivo de migration Drizzle correspondente.
- **Switch statement**: adicionar `case 'api_security': await this.executeApiSecurity(journey, jobId, onProgress); break;` no `journeyExecutor.ts` — antes do `default`.
- **`executeApiSecurity()`**: método privado no `JourneyExecutorService` que:
  1. Valida `authorizationAck` (JRNY-02) — lança `AuthorizationError` se false.
  2. Chama `runApiDiscovery()` (Phase 11) com opts de discovery vindos do job.
  3. Chama `runApiPassiveTests()` (Phase 12) com opts de testing.
  4. Chama `runApiActiveTests()` (Phase 13) com opts de testing + `destructiveEnabled` gate.
  5. Emite progresso via `onProgress` a cada stage.
  6. Chama `logAudit()` no início e no fim (SAFE-04).
- **Integração com processTracker existente**: `executeApiSecurity()` registra seus child processes no `processTracker` por jobId — o abort/cancel existente já mata tudo via `killAll(jobId)`.

### Authorization acknowledgment (JRNY-02)

- **Novo campo na tabela `journeys`**: `authorizationAck: boolean('authorization_ack').notNull().default(false)`.
- **Migration**: adicionar coluna com `DEFAULT false` (não quebra journeys existentes).
- **Validação no executor**: `executeApiSecurity()` verifica `journey.authorizationAck === true` antes de qualquer operação. Se false, lança erro claro: `'Jornada api_security requer acknowledgment de autorização de teste'`.
- **Persistência**: campo enviado no body de `POST /api/v1/journeys` (ou `POST /api/v1/jobs` para execução imediata) — schema Zod atualizado com `authorizationAck: z.boolean().optional().default(false)`.
- **Não é tabela separada**: segue padrão existente de campos no objeto journey — overhead desnecessário para uma flag booleana.

### Rate cap enforcement (SAFE-01/02)

- **`TokenBucketRateLimiter` em `server/services/rateLimiter.ts`**:
  ```ts
  class TokenBucketRateLimiter {
    private readonly ceiling = 50; // req/s absolute, não configurável pelo user
    constructor(private ratePerSecond: number = 10) {}
    async acquire(): Promise<void>; // bloqueia até token disponível
    private handleRetryAfter(headers: Headers): Promise<void>;
    private exponentialBackoff(attempt: number): Promise<void>;
  }
  ```
- **Ceiling de 50 req/s é constante de módulo** — se `opts.rateLimit > 50`, clampado para 50 sem erro (silente mas safe). Schema Zod já valida `max(50)`.
- **Injeção no orchestrator**: `executeApiSecurity()` instancia `new TokenBucketRateLimiter(opts.rateLimit ?? 10)` e passa para os scanners via opts. Scanners (nucleiApi, authFailure, bola, etc.) chamam `await rateLimiter.acquire()` antes de cada request HTTP.
- **Retry-After / 429/503**: se scanner recebe 429/503, chama `rateLimiter.handleRetryAfter(response.headers)`. Se sem `Retry-After` header: exponential backoff com jitter (base 1s, max 30s, 3 tentativas antes de falhar o endpoint).
- **Não aplica ao dryRun**: se `opts.dryRun=true`, rate limiter é no-op (mock responses são locais).

### Abort route (JRNY-05)

- **Nova rota `POST /api/v1/jobs/:id/abort`** (path conforme spec do REQUIREMENTS).
- **Implementação**: encapsula lógica existente de `POST /api/jobs/:id/cancel-process` + adiciona sinalização explícita de AbortController para child processes do `processTracker`.
- **Rota existente `/api/jobs/:id/cancel-process` mantida** para compatibilidade com frontend atual.
- **AbortController signal**: `processTracker` já tem `killAll(jobId)` com SIGTERM+SIGKILL timeout. Abort route chama a mesma sequência — sem novas abstrações.
- **Autenticação**: `isAuthenticatedWithPasswordCheck + requireOperator` (mesmo padrão da rota de cancel existente).
- **Resposta**: `{ message: 'Jornada abortada', killedProcesses: N }`.

### `/healthz/api-test-target` (SAFE-05)

- **Endpoint**: `GET /healthz/api-test-target` — registrado sem autenticação session (acesso local/infra/health-check).
- **Propósito dryRun**: quando `opts.dryRun=true`, `executeApiSecurity()` verifica conectividade com este endpoint no lugar de usar targets reais. O endpoint retorna mock findings pré-definidos que o orchestrator usa como resultado de teste.
- **Response**:
  ```json
  {
    "status": "ok",
    "dryRun": true,
    "mockFindings": [
      { "category": "api8_security_misconfiguration_2023", "severity": "medium", "title": "Mock: CORS permissivo detectado" },
      { "category": "api2_broken_authentication_2023", "severity": "high", "title": "Mock: JWT alg:none aceito" }
    ]
  }
  ```
- **Não expõe dados reais**: resposta é hardcoded no route handler — sem DB queries.
- **Path interno**: `/healthz/` (não `/api/`) para indicar que é endpoint de infra, não de aplicação.

### Destructive method gating (SAFE-03)

- **Gate no orchestrator antes de active tests**:
  ```ts
  if (!opts.destructiveEnabled) {
    // Filter active tests opts: remove DELETE/PUT/PATCH from unknown schemas
    activeOpts.stages.bola = activeOpts.stages.bola ?? false; // BOLA requer state mutation
    // Nuclei active com métodos destrutivos: skip
  }
  ```
- **`destructiveEnabled` default `false`** — usuário deve enviar `destructiveEnabled: true` no body + campo de double-confirmation (UI Phase 16 provê checkbox vermelho).
- **Phase 15 apenas enforça o gate no backend** — a UI de double-confirmation é Phase 16.
- **Qual fase de active tests é bloqueada**: os stages que requerem `DELETE/PUT/PATCH` contra schemas não presentes na spec descoberta. Stages `bola`, `bfla`, `bopla` podem fazer mutações; se `destructiveEnabled=false`, eles rodam em modo read-only (GET apenas).

### Audit log para api_security (SAFE-04)

- **`logAudit()` chamado 2 vezes por execução**:
  1. **Início**: `action: 'start'`, `objectType: 'api_security_journey'`, `objectId: jobId`, `after: { targets, credentialIds, authorizationAck: true, timestamp, stages, dryRun }`. `credentialIds` é array de UUIDs — nunca os secrets.
  2. **Fim (success/failure)**: `action: 'complete'` ou `action: 'failed'`, `after: { outcome, findingsCount, duration, errorMessage? }`.
- **`targets`**: array de strings (URLs/IPs) — não inclui request bodies ou payloads.
- **`credentialIds`**: array de `api_credentials.id` (UUIDs) — `getApiCredentialWithSecret()` nunca é chamado para o audit log.
- **Não requer nova tabela**: `audit_log` existente suporta qualquer `objectType` string — já funciona como log genérico.

### Logs estruturados (SAFE-06)

- **pino já é JSON**: todos os loggers usam `createLogger()` de `server/lib/logger.ts` que emite JSON estruturado.
- **Convenção enforçada por code review**: nenhum `log.info` em `executeApiSecurity()` ou nas funções de scanner pode incluir: request body, valor de credencial, tokens JWT/API key.
- **Campos permitidos em log**: jobId, apiId, endpointId, stage, duration, statusCode, findingId, severity, category.
- **Campos proibidos**: `body`, `credential`, `token`, `apiKey`, `password`, `authorization`, `headers.authorization`.
- **Nyquist test**: teste de integração verifica que nenhum log emitido durante dryRun contém strings sensíveis (regex de credential patterns contra captured pino output).

### Claude's Discretion

- Estrutura interna de `TokenBucketRateLimiter` (algoritmo exato — token bucket vs leaky bucket).
- Nomenclatura de campos de migration (desde que semântica seja clara).
- Ordem de chamar `logAudit` início vs outros guards no `executeApiSecurity()`.
- Como estruturar o pino test capture para o teste de SAFE-06.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requisitos da fase
- `.planning/REQUIREMENTS.md` §JRNY-01..05, SAFE-01..06 — definição normativa de cada requisito desta phase

### Executor e orchestração existentes
- `server/services/journeyExecutor.ts` — switch de journey types, padrão de execução, `isJobCancelled()`, `processTracker` integration
- `server/services/processTracker.ts` — `killAll(jobId)`, registro de child processes
- `server/services/jobQueue.ts` — `markJobAsCancelled()`, cancelamento cooperativo

### Schema e migration
- `shared/schema.ts:41` — `journeyTypeEnum` pgEnum atual (adicionar `api_security`)
- `shared/schema.ts:447` — tabela `audit_log` existente + campos
- `shared/schema.ts:180` — tabela `journeys` (adicionar `authorizationAck`)
- `shared/schema.ts:944` — `createScheduleSchema` (verifica se precisa de atualização após enum)

### Rotas existentes relevantes
- `server/routes/jobs.ts:77` — `POST /api/jobs/:id/cancel-process` (lógica a reutilizar em abort)
- `server/routes/index.ts:81` — `/api/health` existente (padrão para `/healthz/api-test-target`)
- `server/routes/apis.ts` — integração dryRun + `logAudit` já usados em Phase 12/13

### Storage
- `server/storage/settings.ts:47` — `logAudit()` — assinatura e implementação existente

### Fases upstream (outputs que Phase 15 orquestra)
- `server/services/journeys/apiDiscovery.ts` — `runApiDiscovery()` (Phase 11)
- `server/services/journeys/apiPassiveTests.ts` — `runApiPassiveTests()` (Phase 12)
- `server/services/journeys/apiActiveTests.ts` — `runApiActiveTests()` (Phase 13)

### Rate limiting e backoff
- `shared/schema.ts:1875` — `rateLimit: z.number().int().min(1).max(50)` — schema Zod já validando ceiling

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `processTracker.killAll(jobId)`: mata todos os child processes de um job — abort route pode chamar diretamente sem nova lógica de kill.
- `jobQueue.markJobAsCancelled(id)`: sinaliza cooperative cancellation — abort route deve chamar antes de `killAll`.
- `storage.logAudit()`: já implementado, aceita qualquer `objectType` string — Phase 15 só adiciona um novo pattern de chamada.
- `journeyTypeEnum`: pgEnum em `shared/schema.ts:41` — só adicionar `'api_security'` ao array + migration.
- `createScheduleSchema`: aceita qualquer journey via `journeyId` — sem mudança necessária (enum extension é suficiente para scheduler funcionar).

### Established Patterns
- **Journey executor pattern**: método privado `executeXxx(journey, jobId, onProgress)` → faz `onProgress({ status: 'running', ... })` nos checkpoints → lança erro se cancelado.
- **Audit log pattern**: `logAudit({ actorId, action, objectType, objectId, before, after })` chamado após operações significativas — Phase 15 adiciona `'start'` + `'complete'` para api_security journeys.
- **Cancel/abort pattern**: `markJobAsCancelled` + `killAll` + `updateJob(status: 'failed')` + WebSocket emit — rota abort reutiliza exatamente isso.
- **dryRun pattern**: `opts.dryRun=true` pula side effects reais — já usado em Phase 12/13 routes, Phase 15 estende para orchestrator.
- **Structured logging**: `createLogger('nome-do-módulo')` → pino JSON — todos os loggers seguem isso.

### Integration Points
- `server/services/journeyExecutor.ts:88` — switch statement: adicionar `case 'api_security'` aqui.
- `server/routes/jobs.ts` — adicionar `POST /api/v1/jobs/:id/abort` neste arquivo.
- `server/routes/index.ts` — registrar `/healthz/api-test-target` aqui (ou arquivo dedicado).
- `shared/schema.ts:41` — estender pgEnum; `shared/schema.ts:180` — adicionar `authorizationAck` na tabela.
- Migration: novo arquivo em `migrations/` com ALTER TABLE + enum extension.

</code_context>

<specifics>
## Specific Ideas

- A rota `/healthz/api-test-target` deve retornar mock findings que cubram pelo menos uma category de cada severity (low, medium, high, critical) para que dryRun possa ser testado com cenários variados.
- O `executeApiSecurity()` deve emitir progresso granular: `10% Preparando`, `20% Discovery`, `50% Passive Tests`, `75% Active Tests`, `90% Análise`, `100% Concluído` — seguindo padrão visual das outras journeys.
- O ceiling de 50 req/s deve ser constante nomeada `MAX_API_RATE_LIMIT = 50` em `rateLimiter.ts` (não hardcoded inline) para que testes possam mocká-la.

</specifics>

<deferred>
## Deferred Ideas

- UI do wizard de 4 passos para criação de journey api_security (Alvos → Autenticação → Configuração → Confirmação) com checkbox vermelho de double-confirmation para métodos destrutivos → Phase 16 (UI-05).
- Dashboard executivo mostrando métricas de api_security journeys (endpoints testados, findings por severity, trend) → Phase 16 ou backlog.
- Notificações por email/webhook ao fim de api_security journey → backlog pós-v2.0.

</deferred>

---

*Phase: 15-journey-orchestration-safety*
*Context gathered: 2026-04-20*
