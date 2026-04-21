---
phase: 14-findings-runtime-threat-integration
plan: "02"
subsystem: threat-promotion
tags: [findings, threats, promotion, dedupe, FIND-03, atomicity, fail-open]
dependency_graph:
  requires:
    - "14-01 (sanitizeApiFinding foundation)"
    - "Phase 12 storage/apiFindings.ts (upsertApiFindingByKey)"
    - "Phase 9 shared/schema.ts (threats + apiFindings + promotedThreatId FK)"
    - "shared/owaspApiCategories.ts (OWASP_API_CATEGORY_LABELS pt-BR)"
  provides:
    - "server/services/threatPromotion.ts (promoteHighCriticalFindings + findDuplicateThreat + PromotionResult)"
    - "server/storage/apiFindings.ts (listFindingsForPromotion + updateFindingPromotedThreatId)"
  affects:
    - "Wave 3 (14-04): route handler POST /test/passive + /test/active invocam fire-and-forget"
    - "Executive dashboard GET /api/v1/threats/summary: novos threats com source=api_security aparecem"
tech_stack:
  added: []
  patterns:
    - "db.transaction() para atomicidade insert threats + update apiFindings.promotedThreatId"
    - "Fail-open: try/catch toda operação; error capturado em result.error, não lançado"
    - "Dedupe 2-strategy: exact (category+source+title LIKE) + temporal fallback (60min window)"
    - "Fire-and-forget invocation pattern: void promoteHighCriticalFindings(...).catch(console.warn)"
key_files:
  created:
    - server/services/threatPromotion.ts
    - server/__tests__/threatPromotion.test.ts
  modified:
    - server/storage/apiFindings.ts
    - server/storage/interface.ts
    - server/storage/index.ts
decisions:
  - "threats.category=apiId para agrupamento hierárquico (schema real não tem parentAssetId — plano referenciava versão hipotética)"
  - "correlationKey='api_security:{apiId}:{owaspCategory}:{endpointId}' para idempotência e dedup futuro"
  - "Tx type via Parameters<Parameters<typeof db.transaction>[0]>[0> — padrão estabelecido em actionPlanService.ts"
  - "OWASP title usa threats.category + owaspCategory (sem endpointPath — não existe em ApiFinding)"
  - "updateFindingPromotedThreatId aceita tx?: typeof db para compatibilidade de tipo entre db e Tx"
metrics:
  duration: "8m"
  completed_date: "2026-04-20"
  tasks_completed: 3
  files_created: 2
  files_modified: 3
---

# Phase 14 Plan 02: threatPromotion Service Summary

Wave 1 FIND-03 — promoção automática de findings high/critical para tabela `threats`, com dedupe dupla (exact + temporal 60min) e storage facade estendido.

## What Was Built

### PromotionResult Interface (final shape)

```typescript
export interface PromotionResult {
  promoted: number;   // new threats created
  linked: number;     // findings linked to existing threats (dedupe hit)
  skipped: number;    // findings did not qualify (severity/status/already promoted)
  error?: string;     // fail-open: set when DB error short-circuits the batch
}
```

### Function Signatures

```typescript
// server/services/threatPromotion.ts
export async function findDuplicateThreat(
  apiId: string,
  owaspCategory: string,
): Promise<ThreatRow | null>

export async function promoteHighCriticalFindings(
  apiId: string,
  newFindingIds: string[],
): Promise<PromotionResult>
```

```typescript
// server/storage/apiFindings.ts
export async function listFindingsForPromotion(findingIds: string[]): Promise<ApiFinding[]>
export async function updateFindingPromotedThreatId(
  findingId: string,
  threatId: string | null,
  tx?: typeof db,
): Promise<void>
```

### Dedupe Strategy (Queries Exatas)

```
Strategy 1 — Exact match (first wins):
  SELECT * FROM threats
  WHERE category = :apiId
    AND source = 'api_security'
    AND title LIKE '%{owaspCategory}%'
  ORDER BY created_at DESC LIMIT 1

Strategy 2 — Temporal fallback (if strategy 1 returns null):
  SELECT * FROM threats
  WHERE category = :apiId
    AND source = 'api_security'
    AND created_at >= now() - interval '60 minutes'
  ORDER BY created_at DESC LIMIT 1

→ Returns null if both strategies find nothing → create new threat path
```

### threatTitle Construction Pattern

```
threats.title = "{OWASP_API_CATEGORY_LABELS[owaspCategory].titulo}: {owaspCategory}"
Example: "Quebra de Autorização em Nível de Objeto: api1_bola_2023"

threats.category = apiId  (hierarchy grouping — schema has no parentAssetId)
threats.correlationKey = "api_security:{apiId}:{owaspCategory}:{apiEndpointId}"
threats.evidence = { apiEndpointId, owaspCategory, findingIds: [id] }
```

### Invocation Pattern for Wave 3 (14-04)

```typescript
// server/routes/apis.ts — POST /test/passive + /test/active
// Fire-and-forget: não bloqueia resposta da rota
// newFindingIds coletados durante o loop de upsertApiFindingByKey
void promoteHighCriticalFindings(apiId, newFindingIds).catch((err) => {
  console.warn('[route] promotion fire-and-forget error', { apiId, err });
});
```

## Schema Deviation: threats Table

The plan referenced a hypothetical threats schema (`parentAssetId`, `threatTitle`, `threatSeverity`, `threatData`, `resolvedCount`, `verifiedCount`, `lastSeen`). The **actual** schema has:

| Plan field | Actual schema field | Adaptation |
|------------|--------------------|-|
| `parentAssetId` | does not exist | Used `category = apiId` |
| `threatTitle` | `title` | Used `title` |
| `threatSeverity` | `severity` | Used `severity` |
| `threatData JSONB` | `evidence JSONB` | Used `evidence` |
| `resolvedCount` | does not exist | Omitted |
| `verifiedCount` | does not exist | Omitted |
| `lastSeen` | does not exist | Omitted |

All behaviors (promotion, dedupe, atomicity, fail-open) are preserved. Only field names adapted.

## Known Limitations

1. **Single finding per threat initially** — `evidence.findingIds` starts as `[finding.id]`. Subsequent dup-links update `promotedThreatId` on the finding but do NOT deep-merge `findingIds` array into the existing threat's `evidence`. Phase 15 can add merge logic.

2. **endpointPath not in ApiFinding** — The plan showed `endpointPath` as a field; the real schema does not have it. Title uses `owaspCategory` key instead. If human-readable endpoint path is needed, it must be resolved via `apiEndpoints` table join (deferred to Wave 3 or Phase 15).

3. **Race condition window** — Two parallel promotions for same `(apiId, owaspCategory, endpointId)` may both pass the dedupe check simultaneously and create 2 threats. The `correlationKey` unique constraint (`UQ_threats_correlation_key`) will cause one to fail — caught by fail-open. Dashboard shows deduplicated view eventually.

4. **tx type cast** — `updateFindingPromotedThreatId(..., tx as unknown as typeof db)` uses a type cast because drizzle's `Tx` type (transaction sub-type) is not assignable to `typeof db`. Behavior is correct; the cast is a TypeScript-level accommodation.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] threats table schema mismatch — plan described hypothetical fields**
- **Found during:** Task 3 (TypeScript compilation errors on `threats.parentAssetId`, `threats.threatTitle`, etc.)
- **Issue:** Plan's `<interfaces>` block showed a hypothetical threats schema different from `shared/schema.ts` actual definition.
- **Fix:** Adapted to real schema: `category=apiId`, `title` (not `threatTitle`), `severity` (not `threatSeverity`), `evidence` (not `threatData`), added `correlationKey` for idempotency.
- **Files modified:** `server/services/threatPromotion.ts`
- **Commit:** `32f1306`

**2. [Rule 1 - Bug] endpointPath field absent from ApiFinding**
- **Found during:** Task 3 TypeScript error `Property 'endpointPath' does not exist`
- **Issue:** Plan referenced `finding.endpointPath` but the actual `ApiFinding` type (from `shared/schema.ts`) does not include this column.
- **Fix:** Title uses `${label}: ${finding.owaspCategory}` instead of `${label}: ${endpointPath}`.
- **Files modified:** `server/services/threatPromotion.ts`
- **Commit:** `32f1306`

## Self-Check: PASSED
