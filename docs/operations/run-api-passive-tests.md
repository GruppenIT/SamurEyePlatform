# Runbook — Testes Passivos de API (Phase 12)

**Versão:** 1.0
**Última atualização:** 2026-04-20
**Requisitos cobertos:** TEST-01 (Nuclei + API9 Inventory), TEST-02 (JWT/API key auth-failure)

Este runbook descreve como operar os testes passivos de API via CLI e via rota HTTP interna. Os testes são **stateless** (Nuclei templates oficiais misconfig/exposure/graphql/cors + checks DB-derived de inventário API9 + 4 vetores in-house de auth-failure: JWT alg:none, kid injection, token reuse, API key leakage).

---

## 1. Pré-requisitos

- Nuclei instalado em `/opt/samureye/bin/nuclei` ou no `PATH` (verificar com `which nuclei`).
- Templates Nuclei em `/tmp/nuclei/nuclei-templates` (gerenciados pelo `nucleiPreflight.ts` — são baixados automaticamente na primeira execução).
- Variáveis de ambiente em `.env`: `DATABASE_URL`, `ENCRYPTION_KEK`.
- API registrada via `POST /api/v1/apis` (Phase 9) e com endpoints descobertos via Phase 11 (`POST /api/v1/apis/:id/discover`).
- Para testes de auth-failure: credencial API cadastrada via `POST /api/v1/api-credentials` (Phase 10) dos tipos `bearer_jwt`, `api_key_header` ou `api_key_query`.

### Autorização

**Confirme que você tem permissão explícita para testar a API antes de executar contra qualquer alvo que não seja um ambiente de laboratório controlado.** A Phase 15 adicionará o checkbox formal de autorização; Phase 12 confia no operador.

---

## 2. Execução em `dryRun` (recomendado para primeira validação)

O modo `--dry-run` lê fixtures locais em `server/__tests__/fixtures/api-passive/`, não faz spawn de Nuclei nem requisições HTTP reais. Serve para validar o pipeline e o read path sem impacto no alvo.

```bash
npx tsx --env-file=.env server/scripts/runApiPassiveTests.ts \
  --api=<uuid-da-api> \
  --dry-run
```

Saída esperada (stdout — JSON de `PassiveTestResult`):

```json
{
  "apiId": "...",
  "stagesRun": ["api9_inventory", "nuclei_passive", "auth_failure"],
  "stagesSkipped": [],
  "findingsCreated": 5,
  "findingsUpdated": 0,
  "findingsByCategory": {
    "api8_misconfiguration_2023": 3,
    "api9_inventory_2023": 1,
    "api2_broken_auth_2023": 3
  },
  "findingsBySeverity": {
    "low": 2,
    "medium": 1,
    "high": 3,
    "critical": 1
  },
  "cancelled": false,
  "dryRun": true,
  "durationMs": 1234
}
```

**Findings geradas pelo dryRun têm o título prefixado com `[DRY-RUN] `** para facilitar filtragem posterior.

### Verificar findings via read path

```bash
curl -u <user>:<pwd> "http://localhost:3000/api/v1/api-findings?apiId=<uuid>&limit=100"
```

---

## 3. Execução real (contra alvo autorizado)

### 3.1 Usando CLI

```bash
npx tsx --env-file=.env server/scripts/runApiPassiveTests.ts \
  --api=<uuid-da-api>
```

Todas as 3 stages rodam por default (`api9_inventory`, `nuclei_passive`, `auth_failure`). Flags para desabilitar seletivamente:

| Flag | Efeito |
|------|--------|
| `--no-nuclei` | Skipa stage Nuclei (útil para depurar apenas auth-failure) |
| `--no-auth-failure` | Skipa stage auth-failure (útil quando não há credencial cadastrada) |
| `--no-api9` | Skipa stage API9 inventory (quando só interessa Nuclei) |
| `--credential=<uuid>` | Força uma credencial específica em vez de usar `resolveApiCredential()` |

### 3.2 Usando rota HTTP interna

```bash
curl -u <user>:<pwd> -X POST \
  -H "Content-Type: application/json" \
  -d '{"dryRun":false,"stages":{"nucleiPassive":true,"authFailure":true,"api9Inventory":true}}' \
  "http://localhost:3000/api/v1/apis/<uuid>/test/passive"
```

RBAC: exige role `operator` ou `global_administrator`.

Respostas:

- `201` + JSON `PassiveTestResult` em caso de sucesso.
- `400` quando o body não valida em `apiPassiveTestOptsSchema` (Zod `.strict()` rejeita campos desconhecidos).
- `404` quando o `apiId` não existe.
- `500` em falha interna (detalhes nos logs estruturados — sem secrets).

---

## 4. Interpretação de findings

Findings são persistidas em `api_findings` com categoria OWASP API Top 10 2023 + severidade:

### 4.1 Categorias geradas pelo Phase 12

- **`api2_broken_auth_2023`** — auth-failure in-house (severity `high` ou `critical`).
  - `critical` → "JWT com alg=none aceito pelo servidor" (bypass completo).
  - `high` → "kid injection", "JWT expirado aceito", "API key vazada em response body".
- **`api8_misconfiguration_2023`** — Nuclei com tags `misconfig`, `exposure`, `cors` (severity `low` a `high`, conforme template).
- **`api9_inventory_2023`** — 3 variantes DB-derived:
  - "Especificação de API exposta publicamente" (`medium`).
  - "GraphQL introspection habilitado em produção" (`medium`).
  - "Endpoint oculto descoberto por brute-force" (`low`).

### 4.2 Dedupe automático

Ao reexecutar contra a mesma API:

- Finding já aberta (`status != closed`) com mesma tripla `(endpointId, owaspCategory, title)` → **update** (refresh de evidence + jobId + updatedAt; status preservado).
- Finding fechada (`status = closed`) com match → **nova row** (issue reabriu).
- Sem match → insert normal.

Não há inflação desnecessária da tabela.

### 4.3 Mask-at-source em evidence

Phase 12 nunca escreve tokens/API keys completos em `evidence.extractedValues`. Para API key leakage, apenas o prefixo `<primeiros 3 chars>***` é armazenado. Phase 14 (FIND-02) formalizará sanitização global; Phase 12 é defensive-by-default.

---

## 5. Troubleshooting

### 5.1 Stage `nuclei_passive` em `stagesSkipped`

- Motivo mais comum: `nuclei` binário não está no PATH ou em `/opt/samureye/bin/`. Rode `which nuclei` para verificar.
- Verificar logs estruturados para a mensagem do `preflightNuclei` (templates dir, versão, etc).

### 5.2 Stage `auth_failure` em `stagesSkipped` com `reason: "no endpoints eligible"`

- Nenhum endpoint da API tem `requiresAuth=true` (rode Phase 11 httpx enrichment antes).
- Nenhuma credencial cadastrada é compatível com o `urlPattern` dos endpoints (`resolveApiCredential` retorna `null`).
- Credencial cadastrada é de auth-type fora de escopo Phase 12 (`basic`/`oauth2_client_credentials`/`hmac`/`mtls`) — apenas `bearer_jwt`, `api_key_header` e `api_key_query` são suportados nesta phase.

### 5.3 Stage `api9_inventory` reporta 0 hits

- API não tem `specUrl` populada (rode Phase 11 discovery contra alvo com OpenAPI/Swagger exposto).
- API não é `graphql` OU não tem endpoints descobertos via spec.
- Nenhum endpoint tem `discoverySources = ['kiterunner']` exclusivo (rode Phase 11 com `--kiterunner`).

### 5.4 Findings não aparecem no `GET /api/v1/api-findings`

- A query requer pelo menos um de `apiId`, `endpointId` ou `jobId`. Sem nenhum destes, retorna 400.
- Confirme o role — `readonly_analyst`, `operator` e `global_administrator` têm acesso.

### 5.5 Timeout do Nuclei

- Default total: 30 minutos por API. Se atingir, `log.warn` com mensagem `nuclei total timeout — SIGTERM`. Reduza o número de endpoints via `opts.endpointIds` ou aumente o `rateLimit` se o alvo aguentar (respeitando políticas de rate cap do ambiente de teste).

---

## 6. Observabilidade

- Logs estruturados via `pino` — todos os logs JSON, sem bodies nem secrets (pino redaction automática).
- Campos relevantes por log: `apiId`, `jobId`, `stage`, `findingsCreated`, `findingsUpdated`, `durationMs`, `cancelled`.
- Audit log escrito no start da execução via rota HTTP: `action: 'api_passive_test_started'` com `userId`, `apiId`, `jobId`, `dryRun`, `stages`.

---

## 7. Próximas phases

- **Phase 13** — BOLA/BFLA/BOPLA/rate-limit/SSRF (stateful).
- **Phase 14** — Sanitização formal de evidence (FIND-02), promoção para `threats` (FIND-03), WebSocket events (FIND-04).
- **Phase 15** — Wiring no `journeyExecutor`, abort via `/jobs/:id/abort`, authorization ack, rate ceiling 50 req/s, audit log formal.
- **Phase 16** — UI de findings filter por `source=api_security`, curl reproduction, false-positive marking.

---

**Paralelo ao Phase 11:** `docs/operations/run-api-discovery.md`.
