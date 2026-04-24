# Phase 14: Findings Runtime & Threat Integration - Context

**Gathered:** 2026-04-20 (via `/gsd:discuss-phase 14 --auto`)
**Status:** Ready for planning

<domain>
## Phase Boundary

Endurecer o **caminho de escrita de findings** com sanitização de PII + headers, e **integrar findings críticos ao Threat Engine** existente para que apareçam no dashboard executivo — consumindo output do Phase 12 (passive) + Phase 13 (active), e catalisando WebSocket events em tempo real durante execução de journey.

Escopo do Phase 14:
- **FIND-02 (Sanitização)** — Redação de auth headers, truncagem de response body ≤8KB, mascaramento de PII (CPF/CNPJ/email/cartão de crédito) **antes de persistência**.
- **FIND-03 (Promoção)** — findings high/critical (`api_findings.severity in ['high', 'critical']`) auto-promovem para `threats` table (dedupe por endpoint+categoria; dedupe contra ameaças existentes; aparece dashboard + score recalc).
- **FIND-04 (WebSocket events)** — Durante execução de journey, emitir eventos de progresso (por-stage) + batch de novos findings descobertos (não per-request-found overflow) via WebSocket para UI em tempo real sem refresh.
- **Entrypoint** — Funções puras `sanitizeApiFinding(evidence)`, `promoteApiFindings(apiId, findings[])`, `emitFindingEvent(jobId, stage, newCount)` + integração no orquestrador Phase 15 `journeyExecutor.ts` + guard de boot na route Phase 12 `POST /test/passive` (e Phase 13 `POST /test/active`).

**Fora de escopo deste phase (em outras phases):**
- Enum `api_security` em `journey_type` + rota POST /jobs/{id}/abort → Phase 15 (JRNY-01, JRNY-05).
- Rate caps global (50 req/s absolute ceiling) + authorization ack + audit_log formal → Phase 15 (SAFE-01, JRNY-02, SAFE-04).
- UI filtering por `source=api_security` + curl reproduction + false-positive marking → Phase 16 (UI-03, UI-04, UI-05).

Phase 14 é **sanitização + promotion runtime** — refining findings post-scanner + surface on executive dashboard. Não wira journey orchestration full (Phase 15); não wira UI (Phase 16).

</domain>

<decisions>
## Implementation Decisions

### Sanitização (FIND-02) — Multi-layer protection

- **Timing: mask-at-source + storage guard + read-path redaction** (3 camadas):
  1. **Scanner (mask-at-source, já Phase 12/13)**: API keys/tokens em `evidence.extractedValues` são 3-char prefix + `***`. Phase 12 `authFailure.ts` + Phase 13 `bola/bfla/bopla/rateLimit/ssrf` aplicam padrão.
  2. **Storage guard (Phase 14 novo)**: função `sanitizeApiFinding(evidence: ApiFindingEvidence): ApiFindingEvidence` roda **antes de `upsertApiFindingByKey`** em ambas rotas Phase 12 + Phase 13. Garante que valores já mascarados não são re-expostos; **redação adicional** de auth headers completos em `evidence.request.headers` (remover `Authorization`, `X-API-Key`, `X-Auth-Token`, etc).
  3. **Read-path redaction**: GET `/api/v1/api-findings` filtra via Zod schema ou storage facade adicional para mascarar IDs harvestados que possam conter sensíveis (e.g., `evidence.extractedValues.objectId` se for email).
- **Body truncage**: `evidence.response.bodySnippet` (já campo em Phase 9) limitado a **8KB**. Se response body > 8KB, trunca + append `[... truncated ...]` marker.
- **PII masking — 4 padrões**:
  1. **CPF** (11 dígitos brasileiros): `###.###.###-##` via regex `/\d{3}\.\d{3}\.\d{3}-\d{2}/g` → `***.***.***-**`. Ou se sem pontuação `/\d{11}/g` → `***********`.
  2. **CNPJ** (14 dígitos): `##.###.###/####-##` → `**.***.***/**-**`.
  3. **Email**: `local@domain.com` → `***@domain.com` (preserve domain para context).
  4. **Credit Card (PAN)**: `4532-1234-5678-9090` → `****-****-****-9090` (last 4 dígitos preserved, padrão indústria).
- **Scope fields**: sanitização aplicada em:
  - `evidence.request.headers` (remover auth headers nominados + valores sensíveis).
  - `evidence.request.bodySnippet` (truncar + PII mask).
  - `evidence.response.bodySnippet` (truncar + PII mask).
  - `evidence.extractedValues.*` (redação de keys que contenham sensível, e.g., credit_card_number → `****`).
- **Função signature**:
  ```ts
  function sanitizeApiFinding(
    evidence: ApiFindingEvidence,
    options?: { piiMaskPatterns?: RegExp[] }
  ): ApiFindingEvidence {
    // Redact auth headers, truncate body, mask PII in-place
    // Return sanitized copy (não mutate input)
  }
  ```
  Exportada de `shared/sanitization.ts` (novo arquivo, ou inline em `shared/schema.ts` se modular).
- **PII patterns como regex const em `shared/sanitization.ts`**:
  ```ts
  const PII_PATTERNS = {
    cpf: /\d{3}\.\d{3}\.\d{3}-\d{2}|\d{11}/g,
    cnpj: /\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}/g,
    email: /(\w+)@(\w+\.\w+)/g,  // preserve domain
    creditCard: /\d{4}-\d{4}-\d{4}-\d{4}|\d{16}/g,
  };
  ```
- **Auth headers redaction list** (case-insensitive remove):
  ```ts
  const REDACT_HEADERS = [
    'authorization', 'x-api-key', 'x-auth-token',
    'api-key', 'apikey', 'x-access-token',
    'cookie', 'x-csrf-token', 'token',
  ];
  ```
- **Invocation**: Ambas rotas `POST /api/v1/apis/:id/test/passive` + `POST /api/v1/apis/:id/test/active` chamam `sanitizeApiFinding(finding.evidence)` **antes** de passar para `upsertApiFindingByKey`. Guard: se `sanitizeApiFinding` falha (erro no regex), loga warning + usa original (fail-open, não fail-closed que deixaria journey blocked).

### Promoção (FIND-03) — Findings → Threats table

- **Promotion trigger**: Após cada `upsertApiFindingByKey` completar (Phase 12/13 route handlers), invocar **async** `promoteHighCriticalFindings(apiId, newFindingIds): Promise<PromotionResult>`.
- **Criteria for promotion**:
  - `api_findings.severity in ['high', 'critical']` **AND**
  - `api_findings.status === 'open'` (não false_positive, não closed).
  - `api_findings.promotedThreatId IS NULL` (não já promovido — evita re-create).
- **Dedupe contra threats existentes — 2 estratégias** (primeiro match wins):
  1. **Exact dup check**: threat exists com `source='api_security'` AND `(assetId === apiId OR parentAssetId === apiId)` AND `threatTitle LIKE '%{oswapcategory}%{endpointPath}%'` (heurística — title contém categoria + path). Se existe, **link** via `promotedThreatId = threat.id` (não cria nova).
  2. **Temporal dup check** (fallback): threat com mesma `source` criado nos últimos 60 minutos. Se existir, link ao mais recente. Rationale: mesmo teste rodado 2ª vez em 1h encontra mesmos findings; link evita duplicação.
- **Promotion logic**:
  ```ts
  async function promoteHighCriticalFindings(
    apiId: string,
    newFindingIds: string[]
  ): Promise<{ promoted: number; linked: number; skipped: number }> {
    // Fetch new findings with high/critical severity
    // For each:
    //   1. Check dedupe against threats (exact + temporal)
    //   2. If new threat: db.transaction(() => {
    //        insert threat with apiId parentage + evidence FK
    //        update api_findings.promotedThreatId
    //      })
    //   3. If existing threat: update api_findings.promotedThreatId (link)
    // Return count summary
  }
  ```
- **Threat structure when promoted**:
  - `threats.id` — gerado (UUID).
  - `threats.assetId` — null (findings não têm asset direto).
  - `threats.parentAssetId` — **apiId** (reusa hierarchy: `apis` é `parentAssetId` de findings, e findings promovem como separate threat records com `parentAssetId = apis.id`).
  - `threats.threatTitle` — `{OWASP API category}: {pt-BR remediation title}` (e.g., `API1 Broken Object-Level Authorization: Acesso não autorizado a objeto via credencial secundária`).
  - `threats.threatSeverity` — copy from `api_findings.severity`.
  - `threats.source` — `'api_security'` (novo source, Phase 15 pode usar para filtering).
  - `threats.threatData` → JSONB `{ apiEndpointId: findings[0].apiEndpointId, owaspCategory, findingIds: [array of linkedFindingIds] }`.
  - `threats.resolvedCount` — 0 (opened fresh).
  - `threats.verifiedCount` — 0.
  - `threats.lastSeen` — now.
  - `threats.createdAt` — now.
  - **FK** `api_findings.promotedThreatId` → `threats.id` (soft link; não cascade delete).
- **Async safety**: Promotion roda **fire-and-forget** (não blocks route). Se promotion falha (DB error), loga warning + marking finding com `promotedThreatId = null` persists (findings still visible, just not on dashboard). Phase 15 can retry async.
- **Scorecard impact**: Quando threat promovido, executive dashboard `GET /api/v1/threats/summary` automaticamente reflete novo threat (contagem, score weighted by severity + source weighting futura). **Não recalcula score neste phase**; Phase 3+ (Remediation Engine) já define scoring rules.
- **Audit trail**: Promoção **não** gera `audit_log` entry direto (Phase 15 SAFE-04 propriedade). Phase 14 pode log via pino `logger.info({ apiEndpointId, promotedThreatId, reason }, 'Finding promoted to threat')`.

### WebSocket Events (FIND-04) — Real-time journey progress

- **Event types** (3 categorias):
  1. **Stage progress**: `{ type: 'stage_progress', stage: 'bola' | 'bfla' | ... | 'nuclei_passive', status: 'started' | 'completed' | 'failed', findingsDiscovered: N, durationMs, message: 'pt-BR msg' }`.
  2. **Batch findings**: `{ type: 'findings_batch', findings: [{ id, oswapcategory, severity, endpointPath, title }], batchNumber: 1, totalNewInBatch: 5 }`.
  3. **Journey complete**: `{ type: 'journey_complete', jobId, apiId, totalFindings, totalThreatsPromoted, durationMs, status: 'success' | 'cancelled' }`.
- **Granularidade**: **Per-stage** (não per-request/finding individual — evita WebSocket saturation). Cada stage emite 1 event "completed" com contagem acumulada de findings descobertos **naquele stage**. Batch de findings enviado a cada 10 novas findings descobertas (ou end-of-stage, o que vier primeiro).
- **Subscriber model** (reusa v1.0 WebSocket):
  - Client: `ws://localhost/api/v1/jobs/:jobId/ws` (já existe, Phase 11 subscribed; Phase 12/13 reusa).
  - Server route: `GET /api/v1/jobs/:jobId/ws` → WebSocket upgrade (RBAC check job ownership).
  - Broadcasting: service `JobEventBroadcaster` (ou melhoria de `jobQueue`) mantém subscribed clients; emite evento via `ws.send(JSON.stringify(event))`.
- **Integration point — 2 lugares**:
  1. **Route handlers** (Phase 12 `POST /test/passive` + Phase 13 `POST /test/active`): Após `upsertApiFindingByKey` retornar, chamar `jobEventBroadcaster.emit(jobId, { type: 'findings_batch', ... })`.
  2. **Orchestrator** (Phase 15 `journeyExecutor.ts`): Após cada stage completar, emitir `jobEventBroadcaster.emit(jobId, { type: 'stage_progress', stage, status: 'completed', findingsDiscovered, durationMs })`.
- **Event payload limits**:
  - `findings_batch` contains max **20 findings** (payload size ≤ 50KB typical; avoid massive JSON per-event).
  - If ≥ 20 findings to batch, send multiple batch events (batch 1, batch 2, etc).
  - Message field em stage_progress limitar a **200 chars** (pt-BR). Exemplos:
    - `"BOLA: 6 pares testados, 1 finding descoberto em 12s"`
    - `"Passive: 87 templates Nuclei testadas, 5 issues encontrados em 34s"`
- **Event schema (Zod)**:
  ```ts
  const jobEventSchema = z.discriminatedUnion('type', [
    z.object({
      type: z.literal('stage_progress'),
      stage: z.string(),
      status: z.enum(['started', 'completed', 'failed']),
      findingsDiscovered: z.number(),
      durationMs: z.number(),
      message: z.string().max(200),
    }),
    z.object({
      type: z.literal('findings_batch'),
      findings: z.array(z.object({
        id: z.string(),
        owaspCategory: z.string(),
        severity: z.string(),
        endpointPath: z.string(),
        title: z.string(),
      })),
      batchNumber: z.number(),
      totalNewInBatch: z.number(),
    }),
    z.object({
      type: z.literal('journey_complete'),
      jobId: z.string(),
      apiId: z.string(),
      totalFindings: z.number(),
      totalThreatsPromoted: z.number(),
      durationMs: z.number(),
      status: z.enum(['success', 'cancelled']),
    }),
  ]);
  ```
- **Resilience**: Se WebSocket send falha (client disconnect), loga + continua job (não blocks). Client não recebendo eventos continua via polling GET `/api/v1/jobs/:jobId` (status field) — fallback graceful.
- **Rate limiting WebSocket events**: Max **10 events/sec per jobId** (burst de stage_progress + findings_batch pode emit rápido). Implementar via event queue simples ou throttle via lodash `.throttle()`.

### Threat Engine Integration — Atomicity & Safety

- **Dedupe transaction**:
  ```ts
  await db.transaction(async (tx) => {
    // Check if threat with same (parentAssetId, source, title-pattern) exists
    const existing = await tx.select().from(threats)
      .where(and(
        eq(threats.parentAssetId, apiId),
        eq(threats.source, 'api_security'),
        like(threats.threatTitle, `%${owaspCategory}%`)
      ))
      .limit(1);
    
    if (existing.length > 0) {
      // Link finding to existing threat
      await tx.update(apiFindings)
        .set({ promotedThreatId: existing[0].id })
        .where(eq(apiFindings.id, findingId));
    } else {
      // Insert new threat + update finding
      const [threat] = await tx.insert(threats).values({...}).returning();
      await tx.update(apiFindings)
        .set({ promotedThreatId: threat.id })
        .where(eq(apiFindings.id, findingId));
    }
  });
  ```
- **Rollback behavior**: If tx fails (constraint violation, etc), finding remains in `api_findings` with `promotedThreatId = null`. Route logs error + returns 200 OK (findings persisted; promotion failed silently). Phase 15 async retry job can reattempt.
- **Constraint violation safety**: `threats.id` is PK (UUID); `apiFindings.promotedThreatId` is FK not-enforced (null-safe). If promotion inserts threat but update fails, finding unlinked. Idempotent: re-run promotion checks existing, links correctly.
- **Race condition mitigation**: If 2 parallel requests both promote high/critical findings for same API simultaneously:
  - Both check dedupe → both see no match → both try insert threat with similar title.
  - DB constraint (if added later): unique(parentAssetId, source, threatTitle) prevents duplicate insert.
  - Loser of race gets UNIQUE constraint error → rollback, updates finding with winner's threat ID (via fallback exact-match after insert fails).
  - For now (no unique constraint yet), both create similar threats → acceptable (duplication is harmless; dashboard shows 2 threats; Phase 15 can de-dup on read).

### Sanitization Invocation Timing

- **Route-level guards** (Phase 12 + Phase 13 POST handlers):
  ```ts
  app.post('/api/v1/apis/:id/test/passive', async (req, res) => {
    // ... run test, collect findings ...
    const sanitized = findings.map(f => ({
      ...f,
      evidence: sanitizeApiFinding(f.evidence),
    }));
    // upsert + promote
    for (const finding of sanitized) {
      await storage.upsertApiFindingByKey(finding);
    }
  });
  ```
- **Guard at boot** (Phase 14 novo): `initializeDatabaseStructure()` em `server/db.ts` adiciona **idempotent function handler**:
  ```ts
  async function ensureSanitizationGuard() {
    // Register before-insert trigger na tabela api_findings (se DB suporta)
    // OU decorator em storage facade (mais simples, TS-side)
    // OU middleware na rota (mais explícito)
    // Recomendação: decorator em route handlers (explícito, testável)
  }
  ```
  Invocação na rota explícita (não magic trigger) — mais claro para auditorias.

### Claude's Discretion

- Exato padrão regex para CPF/CNPJ/email/credit-card (pode ser mais ou menos restritivo).
- Estrutura interna de `sanitizeApiFinding` (pode ser função única vs helper per-type).
- Nome da função (`promoteHighCriticalFindings` vs `promoteFindingsToThreats` vs outro).
- Estrutura de `JobEventBroadcaster` (novo service vs extensão de existing `jobQueue`).
- Ordem dos campos em threat record criado (não-crítica; schema existente define).
- Mensagens pt-BR exatas em WebSocket events.
- Se `source='api_security'` enum entry novo em threats.source ou string-based para flexibilidade.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Milestone spec
- `.planning/ROADMAP.md` §"Phase 14: Findings Runtime & Threat Integration" — goal + 4 success criteria
- `.planning/REQUIREMENTS.md` §"Findings & Threat Integration (FIND)" — FIND-02, FIND-03, FIND-04
- `.planning/REQUIREMENTS.md` §"Safety & Guard-rails (SAFE)" — SAFE-06 (logs estruturados sem secrets)
- `.planning/PROJECT.md` §"Constraints" — "Schema changes must be additive", "Backward compatibility"

### Phase 9 CONTEXT carry-forward (schema + evidence)
- `.planning/phases/09-schema-asset-hierarchy/09-CONTEXT.md` — `api_findings` table, `ApiFindingEvidence` schema, `apiFindingEvidenceSchema` Zod com `bodySnippet` max 8KB
- `shared/schema.ts:1225-1317` — `api_findings` table, `ApiFinding`, `InsertApiFinding` types

### Phase 12 CONTEXT carry-forward (storage + dryRun + mask-at-source)
- `.planning/phases/12-security-testing-passive/12-CONTEXT.md` — `upsertApiFindingByKey` transactional dedupe, mask-at-source pattern (Phase 12 `authFailure.ts`), dryRun fixtures, PassiveTestResult shape
- `server/storage/apiFindings.ts` — `upsertApiFindingByKey(endpointId, category, title, data)` + `listApiFindings(filter)`
- Pattern: phase route calls storage facade; Phase 14 inserts sanitization before facade call

### Phase 13 CONTEXT carry-forward (scanners emit evidence, mask-at-source)
- `.planning/phases/13-security-testing-active/13-CONTEXT.md` — 5 scanners (bola/bfla/bopla/rateLimit/ssrf) emit findings com evidence; mask-at-source já implementado; `ActiveTestResult` shape
- Pattern: Phase 13 scanners populate evidence fields já; Phase 14 sanitization is post-scanner, pre-persistence

### v1.0 Threat Engine context (threats table + dashboard)
- `.planning/PROJECT.md` §"What v1.0 Delivered" — "Threat grouping engine with parent/child clusters", "Threat detail: problem/impact/fix hierarchy", "Executive dashboard with posture score"
- `.planning/PROJECT.md` §"Current State" — "298 tests across 17 files, zero failures, 25/25 threat rule snapshots"
- `shared/schema.ts` — `threats` table schema (id, assetId, parentAssetId, threatTitle, threatSeverity, source, threatData JSONB, resolvedCount, verifiedCount, lastSeen, createdAt, updatedAt)
- `server/services/scoringEngine.ts` — **contextual scoring with weighted formula**; Phase 14 threat promotion does NOT recalculate score (existing formula applies to new threat records)
- Dashboard route `GET /api/v1/threats/summary` — already reflects threats from all sources; Phase 14 new source `api_security` will appear

### WebSocket + Job Queue patterns (v1.0 + Phase 11)
- `.planning/PROJECT.md` §"What v1.0 Delivered" — "WebSocket-triggered dashboard refresh on job completion"
- `server/services/jobQueue.ts` — job scheduling, cancellation via `isJobCancelled(jobId)`
- `server/routes/jobs.ts` — `GET /api/v1/jobs/:jobId/ws` WebSocket upgrade (likely exists)
- Phase 11 orchestrator pattern: `DiscoveryResult` with `stagesRun`, `durationMs`, cancel hooks
- Phase 13 orchestrator pattern: similar with `ActiveTestResult`

### Sanitization + logging context
- `server/lib/logger.ts` — pino redaction paths already cover `secretEncrypted`, `dekEncrypted`, `authorization`. Phase 14 extends via `sanitizeApiFinding`.
- SAFE-06: "Logs are structured JSON and never include request bodies, credentials, or tokens" — Phase 14 enforces at storage layer (before insert)

### Zod + TypeScript patterns
- `.planning/codebase/CONVENTIONS.md` — naming, imports, pt-BR error messages
- `.planning/codebase/STACK.md` — Zod 3.24, TypeScript 5.6.3

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- **`threats` table + scoring engine** (`shared/schema.ts` + `server/services/scoringEngine.ts`) — promotion writes new threat records; existing weighting formula applies. Zero schema changes.
- **`upsertApiFindingByKey` + `listApiFindings`** (`server/storage/apiFindings.ts` Phase 12) — findings storage ready; Phase 14 wraps with sanitization before calling.
- **`api_findings` table + evidence schema** (`shared/schema.ts` Phase 9) — `ApiFindingEvidence` interface + Zod schema already defines `request`, `response`, `extractedValues` with `bodySnippet` field. Phase 14 populates via sanitized values.
- **WebSocket + job subscribers** (v1.0 + Phase 11) — `/api/v1/jobs/:jobId/ws` endpoint exists (or pattern established); Phase 14 extends with more event types.
- **pino logger + redaction** (`server/lib/logger.ts` v1.0) — `pino.redact` paths already protect secrets. Phase 14 adds sanitization function (logging not needed if pre-storage).
- **`jobQueue.isJobCancelled(jobId)`** — cancelation cooperatively checked in orchestrators; Phase 14 can check before promotion async.

### Established Patterns

- **Storage facade pattern** (Phase 9+) — Phase 14 calls `sanitizeApiFinding` **before** `upsertApiFindingByKey` in route handlers.
- **Async operations** (Phase 11+12) — fire-and-forget promotion via scheduled background service or Promise.then() without await in route.
- **Zod schema validation** (Phase 9+) — `jobEventSchema` for WebSocket payloads; `sanitizedEvidenceSchema` for output contract.
- **Transaction pattern** (Phase 12 dedupe) — `db.transaction()` for threat promotion atomicity (new pattern, mirrors existing dedupe logic).
- **pt-BR messages** (Phase 12+) — remediation templates in Portuguese; WebSocket events use pt-BR descriptions.

### Integration Points

- **`shared/sanitization.ts`** (novo arquivo Phase 14) — `sanitizeApiFinding(evidence)` função pública. Ou inline em `shared/schema.ts` se modular.
- **`server/storage/apiFindings.ts`** (estender Phase 12) — adicionar import `sanitizeApiFinding`, chamar na rota ANTES de `upsertApiFindingByKey` (route-level guard, não storage-internal).
- **`server/services/threatPromotion.ts`** (novo) — `promoteHighCriticalFindings(apiId, findingIds)` + `findDuplicateThreat(criteria)`. Exportado para route handlers.
- **`server/services/jobEventBroadcaster.ts`** (novo ou estender jobQueue) — `emit(jobId, event)` + subscribe/unsubscribe clients. Ou integrado em existing `jobQueue.ts` service.
- **`server/routes/apis.ts`** (estender Phase 12) — POST handlers `/test/passive` + `/test/active` chamam `sanitizeApiFinding` antes de `upsertApiFindingByKey`; chamar `promoteHighCriticalFindings` async após.
- **`server/routes/jobs.ts`** (estender v1.0) — GET `/jobs/:jobId/ws` upgrade ja existe (assumed); Phase 14 extends event types emitted.
- **`server/services/scoringEngine.ts`** — **Zero change** (threat promotion creates records; existing weighting applies).
- **`server/services/journeyExecutor.ts`** (Phase 15 owner, preview) — será chamar `jobEventBroadcaster.emit()` após cada stage; Phase 14 defines event types.
- **`shared/schema.ts`** — adicionar `jobEventSchema` Zod discriminated union.

### Constraints Aplicáveis

- PROJECT.md "Schema changes must be additive" — **satisfeito** (zero schema change; só popula existing fields).
- PROJECT.md "Backward compatibility" — **satisfeito** (zero breaking change; Phase 12/13 routes ainda funcionam, só com sanitization inserted).
- SAFE-06 "Logs structured JSON, no secrets" — **satisfeito** (sanitization at storage, logging via pino redaction).
- FIND-02/03/04 success criteria — Phase 14 implementa todos 3.

</code_context>

<specifics>
## Specific Ideas

- **Sanitization é "last line of defense"** — scanners (Phase 12/13) já fazem mask-at-source; Phase 14 re-sanitiza como precaução contra erro. Redundância proposital.
- **Promoção é "async advisory"** — findings persist com ou sem threat link. Se promotion fails, findings still queryable; dashboard show fewer threats. Eventually-consistent model.
- **WebSocket é "real-time signaling, não data tunnel"** — eventos são IDs + counts, não full finding payloads. Client polls `/api/v1/api-findings?jobId=...` para details se precisar.
- **Dedupe strategy é "temporal-aware"** — recente threat match preferido (60min window) porque testes rodados 2x em 1h é real; dedupe evita alarming duplicado.
- **Phase 15 será "orchestration enforcement"** — Phase 14 promotion é "optional advisory" (route can skip, findings persist). Phase 15 SAFE-* gates `opts.promoteToThreats=true` default, enforcement global.
- **Credit card masking preserva last-4** — indústria padrão (Stripe, Visa, etc). Full redaction seria muito severa.
- **Email masking preserva domain** — investigador sabe qual service a vulnerability afeta (e.g., `***@github.com` vs `***@internal.company.com`).
- **WebSocket batch size 20** — empirical: ~5-10KB per event, 10 events/sec = manageable 50-100KB/sec per client.

</specifics>

<deferred>
## Deferred Ideas

- **Automated threat de-duplication on read** — Phase 14 dedupe at write-time; Phase 15+ can merge similar threats on dashboard via `threatGroupingEngine` (já existe v1.0).
- **Custom sanitization rules per client** — e.g., "keep email domain hidden too" opt-in. Deferido; default rules são conservadores.
- **Sanitization audit trail** — log quais campos foram redated (utility para compliance). Deferido; current logs have threat record created event.
- **Real-time threat score recalc on promotion** — Phase 14 promotes; Phase 3 scoring applies. Per-threat incremental recalc futura. Score stable for now.
- **Feedback loop: client marks finding as false_positive → threat unlinks/closes** — Phase 16 has false_positive marking; Phase 15+ auto-closure on marking. Deferido.
- **Per-severity WebSocket event aggregation** — separate channels for critical vs high vs info. Deferido; single channel is simple.
- **Promotion webhook** — external SIEM/ticketing integration on threat creation. Deferido; v2.0 scope in-system only.
- **Sanitization performance optimization** — regex compilation at module init time. Low priority; regex overhead negligible for 8KB body.
- **PII locale customization** — CPF/CNPJ specific to Brazil. For global deployments, SSN/SIN/ABN patterns. Deferido; Brazil-specific for v2.0.
- **Threat timeline correlation** — when threat promoted, correlate with existing threats' timelines (when first seen, last seen). Timeline enrichment util. Deferido.

</deferred>

---

*Phase: 14-findings-runtime-threat-integration*
*Context gathered: 2026-04-20 via /gsd:discuss-phase 14 --auto*
