---
phase: 15-journey-orchestration-safety
plan: "03"
subsystem: rate-limiter + healthz-route
tags:
  - rate-limiting
  - token-bucket
  - safe-01
  - safe-02
  - safe-05
  - infrastructure
dependency_graph:
  requires:
    - 15-01  # Nyquist stubs criados
  provides:
    - TokenBucketRateLimiter class (consumido por Plan 04 executeApiSecurity)
    - MAX_API_RATE_LIMIT constant (consumido por Plan 04)
    - GET /healthz/api-test-target (consumido por Plan 04 dryRun validation)
  affects: []
tech_stack:
  added: []
  patterns:
    - token-bucket rate limiter (puro Node.js built-ins, zero deps externas)
    - TDD RED/GREEN — testes promovidos de it.todo para it() reais antes da implementação
key_files:
  created:
    - server/services/rateLimiter.ts
  modified:
    - server/__tests__/rateLimiter.test.ts
    - server/__tests__/healthzTarget.test.ts
    - server/routes/index.ts
decisions:
  - MAX_API_RATE_LIMIT=50 exportado como constante nomeada — Plan 04 importa via named import sem hardcode
  - Silent clamp via Math.min(Math.max(1, ratePerSecond), MAX_API_RATE_LIMIT) — nenhum throw, user-facing Zod schemas já rejeitam >50
  - handleRetryAfter e exponentialBackoff usam apenas setTimeout (zero deps externas)
  - /healthz/api-test-target usa prefixo /healthz/ (não /api/) para escapar requireActiveSubscription linha 37
  - Route handler é hardcoded sem DB — resposta idêntica em chamadas consecutivas (verificado por teste)
metrics:
  duration: "~4 minutos"
  completed: "2026-04-20T19:04:05Z"
  tasks_completed: 2
  files_created: 1
  files_modified: 3
  tests_added: 19
---

# Phase 15 Plan 03: Rate Limiter + Healthz Route Summary

Token bucket rate limiter (SAFE-01/SAFE-02) + rota /healthz/api-test-target (SAFE-05) criados para consumo pelo orquestrador Plan 04.

## What Was Built

### Task 1 — server/services/rateLimiter.ts (SAFE-01, SAFE-02)

Classe TypeScript pura `TokenBucketRateLimiter` com:

- `MAX_API_RATE_LIMIT = 50` exportado como constante nomeada — ceiling absoluto per SAFE-01
- `DEFAULT_API_RATE_LIMIT = 10` — default quando constructor chamado sem args
- Constructor clampa silenciosamente via `Math.min(Math.max(1, ratePerSecond), MAX_API_RATE_LIMIT)` — nenhum throw
- `acquire(): Promise<void>` — token bucket com refill contínuo; setTimeout quando bucket vazio
- `handleRetryAfter(headers: Headers): Promise<void>` — parseia header Retry-After (segundos); fallback 1000ms
- `exponentialBackoff(attempt: number): Promise<void>` — `Math.min(1000 * 2^attempt, 30_000)` + jitter ±20%
- Zero dependências npm novas — apenas setTimeout de Node.js built-ins

**Confirmação:** handleRetryAfter e exponentialBackoff usam APENAS `setTimeout` — sem bibliotecas externas.

### Task 2 — GET /healthz/api-test-target em server/routes/index.ts (SAFE-05)

Rota hardcoded inserida imediatamente após `/api/health`:

- Path `/healthz/api-test-target` — prefixo `/healthz/` (não `/api/`) escapa o `app.use('/api', requireActiveSubscription)` da linha 37
- Resposta 200 JSON: `{ status: 'ok', dryRun: true, mockFindings: Array(4) }`
- 4 mockFindings cobrem exatamente uma entrada por severidade: low / medium / high / critical
- Categorias OWASP válidas: api9_inventory_2023, api8_misconfiguration_2023, api2_broken_auth_2023, api1_bola_2023
- Sem DB queries, sem middleware de autenticação (infra endpoint)

**Confirmação:** /healthz/api-test-target NÃO está sob /api — escapa requireActiveSubscription completamente.

## Test Results

```
Test Files: 2 passed
Tests:      19 passed (0 todo)

SAFE-01 — TokenBucketRateLimiter ceiling + default: 6/6
SAFE-02 — Retry-After + exponential backoff:       6/6
SAFE-05 — GET /healthz/api-test-target:            7/7
```

**Contagem final: 19 it() reais, 0 it.todo**

## Deviations from Plan

None — plano executado exatamente como escrito.

## Self-Check

- [x] server/services/rateLimiter.ts existe com 102 linhas (min 60)
- [x] MAX_API_RATE_LIMIT = 50 exportado (1 match)
- [x] TokenBucketRateLimiter class exportada (1 match)
- [x] acquire() async presente (1 match)
- [x] handleRetryAfter() async presente (1 match)
- [x] exponentialBackoff() async presente (1 match)
- [x] Clamp logic `Math.min(Math.max(1, ratePerSecond), MAX_API_RATE_LIMIT)` presente
- [x] `30_000` string presente (max backoff clamp)
- [x] 0 it.todo em rateLimiter.test.ts (apenas em comentário JSDoc, não em código)
- [x] 0 it.todo em healthzTarget.test.ts
- [x] /healthz/api-test-target aparece 2x em routes/index.ts (comentário + app.get)
- [x] app.get('/healthz/api-test-target' presente (1 match)
- [x] mockFindings presente em routes/index.ts (1 match)
- [x] 19 testes passando, 0 falhando
- [x] 0 erros TypeScript em arquivos do plano

## Self-Check: PASSED
