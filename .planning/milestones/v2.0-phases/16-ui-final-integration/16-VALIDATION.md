---
phase: 16
slug: ui-final-integration
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-20
---

# Phase 16 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | vitest (existing — `vitest.config.ts` present) |
| **Config file** | `vitest.config.ts` |
| **Quick run command** | `npx vitest run --reporter=verbose 2>&1 | tail -20` |
| **Full suite command** | `npx vitest run 2>&1 | tail -30` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `npx vitest run --reporter=verbose 2>&1 | tail -20`
- **After every plan wave:** Run `npx vitest run 2>&1 | tail -30`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 16-01-01 | 01 | 0 | UI-01 | unit | `npx vitest run tests/ui/api-discovery-page.test.tsx` | ❌ W0 | ⬜ pending |
| 16-01-02 | 01 | 0 | UI-02 | unit | `npx vitest run tests/ui/api-endpoint-drilldown.test.tsx` | ❌ W0 | ⬜ pending |
| 16-01-03 | 01 | 0 | UI-03 | unit | `npx vitest run tests/ui/findings-owasp-filter.test.tsx` | ❌ W0 | ⬜ pending |
| 16-01-04 | 01 | 0 | UI-04 | unit | `npx vitest run tests/ui/curl-reproduction.test.tsx` | ❌ W0 | ⬜ pending |
| 16-01-05 | 01 | 0 | UI-05 | unit | `npx vitest run tests/ui/false-positive-marking.test.tsx` | ❌ W0 | ⬜ pending |
| 16-01-06 | 01 | 0 | UI-06 | unit | `npx vitest run tests/ui/journey-wizard.test.tsx` | ❌ W0 | ⬜ pending |
| 16-02-01 | 02 | 1 | UI-01 | integration | `npx vitest run tests/routes/apis-list.test.ts` | ❌ W0 | ⬜ pending |
| 16-02-02 | 02 | 1 | UI-02 | integration | `npx vitest run tests/routes/apis-endpoints.test.ts` | ❌ W0 | ⬜ pending |
| 16-03-01 | 03 | 2 | UI-03 | integration | `npx vitest run tests/routes/threats-source-filter.test.ts` | ❌ W0 | ⬜ pending |
| 16-03-02 | 03 | 2 | UI-05 | integration | `npx vitest run tests/routes/api-findings-false-positive.test.ts` | ❌ W0 | ⬜ pending |
| 16-04-01 | 04 | 3 | UI-06 | integration | `npx vitest run tests/routes/jobs-api-security.test.ts` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/ui/api-discovery-page.test.tsx` — stubs for UI-01 (page renders list, shows baseUrl/type/endpointCount)
- [ ] `tests/ui/api-endpoint-drilldown.test.tsx` — stubs for UI-02 (Sheet opens with endpoints grouped by path, method badges visible)
- [ ] `tests/ui/findings-owasp-filter.test.tsx` — stubs for UI-03 (filter Select present, OWASP badge renders per finding)
- [ ] `tests/ui/curl-reproduction.test.tsx` — stubs for UI-04 (Dialog shows curl, no real secret rendered, placeholder present)
- [ ] `tests/ui/false-positive-marking.test.tsx` — stubs for UI-05 (AlertDialog appears, PATCH mutation called, toast shown)
- [ ] `tests/ui/journey-wizard.test.tsx` — stubs for UI-06 (4 steps render, authorizationAck required, estimated-requests preview changes)
- [ ] `tests/routes/apis-list.test.ts` — stubs for `GET /api/v1/apis` route (UI-01 backend)
- [ ] `tests/routes/apis-endpoints.test.ts` — stubs for `GET /api/v1/apis/:id/endpoints` route (UI-02 backend)
- [ ] `tests/routes/threats-source-filter.test.ts` — stubs for `source=api_security` filter on threats route (UI-03 backend)
- [ ] `tests/routes/api-findings-false-positive.test.ts` — stubs for `PATCH /api/v1/api-findings/:id` route (UI-05 backend)
- [ ] `tests/routes/jobs-api-security.test.ts` — stubs for `POST /api/v1/jobs` with api_security type + authorizationAck validation (UI-06 backend)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Drill-down Sheet abre ao clicar API na tabela | UI-01/02 | Requer interação de clique com dados reais da DB | 1. Seed API em DB. 2. Abrir `/journeys/api`. 3. Clicar na linha. 4. Verificar Sheet com endpoints agrupados por path |
| Curl gerado tem placeholder correto por auth type | UI-04 | Requer finding real com authType populado | 1. Seed api_finding com authType=bearer_jwt. 2. Clicar "Reproduzir". 3. Verificar que dialog mostra `$BEARER_TOKEN`, nunca valor real |
| Authorization acknowledgment bloqueia wizard | UI-06 | Requer interação multi-step | 1. Abrir wizard. 2. Tentar avançar sem marcar checkbox. 3. Verificar botão "Próximo" bloqueado |
| False-positive gravado em audit_log | UI-05 | Requer verificação em DB | 1. Marcar finding como false_positive via UI. 2. Confirmar row em audit_log com action='update' e objectType='api_finding' |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
