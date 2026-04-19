---
phase: 10
slug: api-credentials
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-19
---

# Phase 10 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | vitest (derivado do padrão atual do repo — planner deve confirmar) |
| **Config file** | `vitest.config.ts` (ou equivalente existente no projeto) |
| **Quick run command** | `npm run test -- server/__tests__/apiCredentials` |
| **Full suite command** | `npm run test` |
| **Estimated runtime** | ~30 segundos (quick) / ~2 minutos (full) |

---

## Sampling Rate

- **After every task commit:** Run `npm run test -- server/__tests__/apiCredentials`
- **After every plan wave:** Run `npm run test`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 segundos

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 10-01-01 | 01 | 0 | CRED-01..05 | stubs | `npm run test -- server/__tests__/apiCredentials` | ❌ W0 | ⬜ pending |

*Planner preencherá as linhas restantes durante o plan-phase; cada task do plan deve ter uma entrada aqui com comando automatizado ou dependência de Wave 0.*

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `server/__tests__/apiCredentials/schema.test.ts` — stub para schema + discriminated union (CRED-01)
- [ ] `server/__tests__/apiCredentials/storage.test.ts` — stub para facade + encryption round-trip (CRED-01, CRED-02)
- [ ] `server/__tests__/apiCredentials/route.test.ts` — stub para contrato dos 7 auth types (CRED-01, CRED-05)
- [ ] `server/__tests__/apiCredentials/urlPattern.test.ts` — stub para helper glob→regex (CRED-03)
- [ ] `server/__tests__/apiCredentials/resolveCredential.test.ts` — stub para resolução por prioridade (CRED-04)
- [ ] `server/__tests__/apiCredentials/guard.test.ts` — stub para `ensureApiCredentialTables()` idempotente
- [ ] `server/__tests__/helpers/apiCredentialFactory.ts` — factory + `URL_PATTERN_MATRIX` (compartilhado)

*Se framework vitest já estiver instalado: pular "framework install".*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Wizard inline-create flow | CRED-05 (UI) | UI do wizard só chega no Phase 16 | Deferido — validar SC5 apenas via rota POST + refetch backend no Phase 10 |

*No Phase 10, SC5 é validado apenas no backend: rota POST retorna credencial criada e GET lista incluindo ela (contrato que o wizard consumirá). UI é Phase 16.*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
