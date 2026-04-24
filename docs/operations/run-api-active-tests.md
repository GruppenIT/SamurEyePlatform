# Runbook — Testes de Segurança Ativos de API (Phase 13)

**Versão:** 1.0
**Última atualização:** 2026-04-20
**Requisitos cobertos:** TEST-03 (BOLA / API1), TEST-04 (BFLA / API5), TEST-05 (BOPLA / API3), TEST-06 (Rate-Limit / API4), TEST-07 (SSRF / API7)

> Guia operacional para execução dos 5 vetores OWASP API Top 10 (2023) stateful:
> BOLA (API1), BFLA (API5), BOPLA (API3), Rate-Limit absence (API4), SSRF (API7).

---

## 1. Pré-requisitos

- Node.js ≥ 20, `npx tsx` disponível (verificar com `npx tsx --version`).
- `.env` configurado com `DATABASE_URL` + `ENCRYPTION_KEK` (mesmas variáveis que Phase 11/12).
- `nuclei` instalado em `/opt/samureye/bin/nuclei` ou no `PATH` — necessário apenas para o stage SSRF:
  ```bash
  nuclei -update-templates
  ```
- Para SSRF com interactsh: variável `INTERACTSH_URL` opcional. Default: `oast.me` (servidor público ProjectDiscovery).
  Em ambientes air-gapped: configure `INTERACTSH_URL=https://oast.internal.exemplo.com`.
  Setup self-hosted: https://github.com/projectdiscovery/interactsh
- API alvo criada no sistema com ≥ 1 endpoint descoberto via Phase 11 (`POST /api/v1/apis/:id/discover`).
- ≥ 2 credenciais configuradas para BOLA/BFLA via Phase 10 (`POST /api/v1/api-credentials`):
  - BOLA requer ≥ 2 credenciais distintas com `urlPattern` compatível com a API.
  - BFLA requer ≥ 2 credenciais com diferentes níveis de privilégio (campo `priority` ou `description` contendo `readonly`/`viewer`).

### Autorização

**Confirme que você tem permissão explícita para testar a API antes de executar contra qualquer alvo que não seja um ambiente de laboratório controlado.** A Phase 15 adicionará o checkbox formal de autorização; Phase 13 confia no operador.

---

## 2. Segurança e Gates

**LEIA ANTES DE EXECUTAR:**

| Stage | Flag CLI | Gate | Impacto | Quando usar |
|-------|----------|------|---------|-------------|
| BOLA (API1) | habilitado por padrão | nenhum | GET cross-identity (read-only) | dev/staging/produção com autorização |
| BFLA (API5) | habilitado por padrão | nenhum para GET admin-path | GET em endpoints admin-path | dev/staging com autorização |
| BOPLA (API3) | desabilitado por padrão | `--destructive` obrigatório | PUT/PATCH reais no alvo | **dev/staging APENAS** com autorização explícita do proprietário |
| Rate-Limit (API4) | desabilitado por padrão | `--rate-limit` obrigatório | burst de 20 reqs paralelos | **dev/staging APENAS** — pode acionar WAF ou rate-limiting legítimo |
| SSRF (API7) | habilitado por padrão | nuclei preflight | injeta URL de callback OOB | dev/staging/produção com acesso de saída DNS/HTTP |

**BOPLA (`--destructive`):** Faz PUT/PATCH reais em endpoints do alvo. Pode alterar dados. Use apenas em ambientes de desenvolvimento/staging com autorização explícita do proprietário do sistema. **Nunca em produção sem autorização formal.**

**Rate-Limit (`--rate-limit`):** Envia burst de 20 requests em paralelo (padrão). Pode acionar alertas de WAF ou rate-limiting legítimo. Use apenas em endpoints de dev/staging.

**SSRF:** Requer acesso de saída de DNS/HTTP do appliance para `oast.me` (ou URL própria). Não expõe dados da aplicação — apenas injeta URL de callback. Seguro em produção com autorização.

**dryRun (padrão):** Seguro em qualquer ambiente — usa fixtures locais, sem requests reais. Findings prefixadas `[DRY-RUN]`.

---

## 3. Modo dryRun (recomendado para validar setup)

O modo `--dry-run` lê fixtures locais em `server/__tests__/fixtures/api-active/`, não faz requests HTTP reais nem spawn de Nuclei. Serve para validar o pipeline e o read path sem impacto no alvo.

```bash
# Executa todos os vetores configurados contra fixtures locais — sem requests reais
npx tsx --env-file=.env server/scripts/runApiActiveTests.ts \
  --api=<uuid-da-api> \
  --dry-run
```

Saída esperada (stdout — JSON de `ActiveTestResult`):

```json
{
  "apiId": "<uuid>",
  "stagesRun": ["bola", "bfla", "ssrf"],
  "stagesSkipped": [
    { "stage": "bopla", "reason": "destructive gate not enabled" },
    { "stage": "rate_limit", "reason": "rateLimit stage disabled (opt-in required)" }
  ],
  "findingsCreated": 5,
  "findingsUpdated": 0,
  "findingsByCategory": {
    "api1_bola_2023": 2,
    "api5_bfla_2023": 1,
    "api7_ssrf_2023": 2
  },
  "findingsBySeverity": { "high": 3, "medium": 0, "critical": 0, "low": 2 },
  "cancelled": false,
  "dryRun": true,
  "durationMs": 1234,
  "credentialsUsed": 2
}
```

**Findings geradas pelo dryRun têm o título prefixado com `[DRY-RUN]`** para facilitar filtragem posterior.

Confirmar findings via read path:

```bash
curl -u <user>:<pwd> \
  "http://localhost:3000/api/v1/api-findings?apiId=<uuid>&limit=100" | jq '[.[] | select(.title | startswith("[DRY-RUN]")) | .title]'
```

---

## 4. Execução Real

### 4.1 Via CLI (operador)

```bash
# Vetores padrão (BOLA + BFLA + SSRF — sem destrutivos)
npx tsx --env-file=.env server/scripts/runApiActiveTests.ts --api=<uuid>

# Com Rate-Limit opt-in (dev/staging apenas)
npx tsx --env-file=.env server/scripts/runApiActiveTests.ts \
  --api=<uuid> --rate-limit

# Com BOPLA destrutivo (requer autorização formal)
npx tsx --env-file=.env server/scripts/runApiActiveTests.ts \
  --api=<uuid> --destructive

# Todos os vetores (máximo impacto — dev/staging autorizado apenas)
npx tsx --env-file=.env server/scripts/runApiActiveTests.ts \
  --api=<uuid> --rate-limit --destructive

# Subset de vetores (apenas BOLA)
npx tsx --env-file=.env server/scripts/runApiActiveTests.ts \
  --api=<uuid> --no-bfla --no-bopla --no-ssrf

# Com credenciais específicas
npx tsx --env-file=.env server/scripts/runApiActiveTests.ts \
  --api=<uuid> --credential=<uuid-cred-a> --credential=<uuid-cred-b>

# Ver todas as opções
npx tsx --env-file=.env server/scripts/runApiActiveTests.ts --help
```

Flags disponíveis:

| Flag | Efeito |
|------|--------|
| `--dry-run` | Usa fixtures locais; sem requests reais |
| `--no-bola` | Desabilita stage BOLA (API1) |
| `--no-bfla` | Desabilita stage BFLA (API5) |
| `--no-bopla` | Desabilita stage BOPLA (API3) — já desabilitado sem `--destructive` |
| `--no-ssrf` | Desabilita stage SSRF (API7) |
| `--rate-limit` | Habilita stage Rate-Limit (API4) — opt-in |
| `--destructive` | Habilita BOPLA (gate de segurança) |
| `--credential=<uuid>` | Sobrescreve credenciais (pode repetir) |

Códigos de saída: `0` sucesso, `1` erro, `2` cancelado.

### 4.2 Via rota HTTP interna

```bash
# Vetores padrão (BOLA + BFLA + SSRF)
curl -u <user>:<pwd> -X POST \
  -H "Content-Type: application/json" \
  -d '{"dryRun":false}' \
  "http://localhost:3000/api/v1/apis/<uuid>/test/active"

# Com Rate-Limit opt-in
curl -u <user>:<pwd> -X POST \
  -H "Content-Type: application/json" \
  -d '{"stages":{"rateLimit":true},"dryRun":false}' \
  "http://localhost:3000/api/v1/apis/<uuid>/test/active"

# Com BOPLA destrutivo
curl -u <user>:<pwd> -X POST \
  -H "Content-Type: application/json" \
  -d '{"destructiveEnabled":true,"dryRun":false}' \
  "http://localhost:3000/api/v1/apis/<uuid>/test/active"

# dryRun via HTTP
curl -u <user>:<pwd> -X POST \
  -H "Content-Type: application/json" \
  -d '{"dryRun":true}' \
  "http://localhost:3000/api/v1/apis/<uuid>/test/active"
```

RBAC: exige role `operator` ou `global_administrator`. `readonly_analyst` recebe 403.

Respostas:

- `201` + JSON `ActiveTestResult` em caso de sucesso.
- `400` quando o body não valida em `apiActiveTestOptsSchema` (Zod `.strict()` rejeita campos desconhecidos).
- `404` quando o `apiId` não existe.
- `500` em falha interna (detalhes nos logs estruturados — sem secrets).

---

## 5. Interpretação de Findings

Findings são persistidas em `api_findings` com categoria OWASP API Top 10 2023 + severidade. Acessíveis via `GET /api/v1/api-findings?apiId=<uuid>`.

| OWASP | Severity | Título padrão | Ação recomendada |
|-------|----------|---------------|-----------------|
| API1 (BOLA) | `high` | "Acesso não autorizado a objeto via credencial secundária" | Implementar ACL por objeto — verificar que o principal autenticado tem permissão no objeto específico, não apenas no tipo |
| API3 (BOPLA) | `critical`/`high` | "Campo sensível aceito em PUT/PATCH sem validação (`<chave>`)" | Allow-list de campos em PUT/PATCH — ignorar silenciosamente propriedades sensíveis (`is_admin`, `role`, `permissions`) |
| API4 (Rate-Limit) | `medium` | "Ausência de rate-limiting em endpoint autenticado" | Implementar 429 + `Retry-After` + `X-RateLimit-*` headers com limites por tier de usuário |
| API5 (BFLA) | `high`/`medium` | "Privilégio administrativo acessível via credencial de baixo privilégio" | RBAC em todos endpoints admin — validar privilege no backend, nunca confiar no cliente |
| API7 (SSRF) | varia (Nuclei) | "SSRF confirmado via interação out-of-band em parâmetro `<param>`" | Allow-list de URLs destino — bloquear RFC 1918, localhost, cloud metadata (169.254.169.254) |

Notas sobre severidade:
- **BOPLA `critical`**: chaves `is_admin`, `role`, `superuser` com reflection confirmada.
- **BOPLA `high`**: outras chaves da lista curada (`permissions`, `owner`, `verified`, etc).
- **BFLA `high`**: RBAC contrastante confirmado (low-priv acessa, high-priv também mas com contraste).
- **BFLA `medium`**: RBAC ausente (todas as creds retornam mesmo status — ambíguo).

Findings com `[DRY-RUN]` no título são produzidas por `dryRun=true` — **não representam vulnerabilidades reais**.

### Dedupe automático

Ao reexecutar contra a mesma API, findings com mesma tripla `(endpointId, owaspCategory, title)` são atualizadas (não duplicadas). Segunda execução reporta `findingsCreated=0, findingsUpdated=N`.

---

## 6. Troubleshooting

**"BOLA requer ≥ 2 credenciais"**: Configure ≥ 2 credenciais distintas com `urlPattern` compatível para a API em Phase 10 (`POST /api/v1/api-credentials`).

**"nuclei preflight failed"**: Execute `nuclei -update-templates` e confirme que `nuclei` está no PATH ou em `/opt/samureye/bin/`. Rode `which nuclei` para verificar.

**"SSRF sem interações (0 findings)"**: Confirme acesso de saída DNS/HTTP para `oast.me` a partir do servidor onde o scanner roda. Em ambientes air-gapped, configure `INTERACTSH_URL` apontando para servidor interactsh self-hosted (ver https://github.com/projectdiscovery/interactsh).

**BOPLA não gera findings mesmo com `--destructive`**: Endpoints PUT/PATCH não encontrados, ou seed body GET falhou (401/404 no recurso). Confirme que endpoints têm `requiresAuth=true` e credencial tem acesso ao GET equivalente.

**Rate-Limit não gera finding**: Endpoint pode já ter rate-limiting implementado corretamente (429/`Retry-After`/`X-RateLimit-*`). Isso é o comportamento desejado; ausência de finding = proteção adequada.

**Stage em `stagesSkipped` com reason inesperado**: Verificar logs estruturados (`pino` JSON) no stderr para campo `stage` + `reason` + `apiId`. Campos nunca incluem secrets (pino redaction automática).

**BFLA não detecta distinção de privilégio**: Se todas as credenciais têm o mesmo `priority` e nenhuma tem `readonly`/`viewer` em `description`, BFLA não consegue identificar low-priv. Adicione ou ajuste campo `description` da credencial de baixo privilégio.

---

## 7. Verificações Manuais-Only

Os seguintes comportamentos requerem configuração específica do ambiente e não podem ser verificados automaticamente:

| Comportamento | Motivo | Instrução |
|---------------|--------|-----------|
| BOLA finding em alvo real | Requer 2 credenciais com namespace de objetos compartilhado e controle de acesso implementado no alvo | 1. Criar 2 creds com diferentes `priority`. 2. `--api=<id> --credential=<A> --credential=<B>`. 3. Verificar finding API1 com par de requests como evidence |
| SSRF callback interactsh | Requer saída de DNS/HTTP do servidor do scanner para `oast.me` ou self-hosted | 1. Confirmar saída de rede (`curl https://oast.me`). 2. Rodar sem `--dry-run`. 3. Aguardar até 30s poll. 4. Verificar finding API7 se param aceita URL |
| Rate-Limit em endpoint real | Requer endpoint que genuinamente não tem rate-limit (dev/staging sem WAF) | 1. Endpoint GET+200 em ambiente sem WAF. 2. `--rate-limit`. 3. Finding API4 apenas se TODOS os 3 sinais ausentes (sem 429, sem `Retry-After`, sem `X-RateLimit-*` headers) |
| BOPLA gate impede writes sem `--destructive` | Confirmar que BOPLA não roda sem flag | 1. Rodar sem `--destructive`. 2. Verificar `stagesSkipped` contém `{ stage: 'bopla', reason: 'destructive gate not enabled' }` |
| BFLA method-based (PUT/PATCH/DELETE) em admin-path | Requer `destructiveEnabled=true` (BFLA method-based desabilitado por padrão) | 1. Rodar com `--destructive`. 2. Confirmar que endpoints admin-path com método mutante são testados |

---

## 8. Observabilidade

- Logs estruturados via `pino` — todos os logs JSON, sem bodies nem secrets (pino redaction automática).
- Campos relevantes por log: `apiId`, `jobId`, `stage`, `findingsCreated`, `findingsUpdated`, `durationMs`, `cancelled`.
- Audit log escrito no start da execução via rota HTTP: `action: 'api_active_test_started'` com `actorId`, `objectType: 'api'`, `objectId: apiId`, `jobId`, `dryRun`, `destructiveEnabled`, `stages`.
- CLI: progress em stderr (machine-readable JSON no stdout).

---

**Paralelo ao Phase 12:** `docs/operations/run-api-passive-tests.md`.
**Próximas phases:** Phase 14 — sanitização formal de evidence; Phase 15 — wiring no journeyExecutor + authorization ack; Phase 16 — UI de findings.
