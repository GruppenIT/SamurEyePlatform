---
phase: 12
slug: security-testing-passive
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-20
---

# Phase 12 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution. Derived from `12-RESEARCH.md` §"Validation Architecture".

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Vitest 4.x (instalado; `vitest.config.ts` já inclui `shared/**/*.test.ts` + `server/**/*.test.ts`) |
| **Config file** | `vitest.config.ts` (raiz do projeto) |
| **Quick run command** | `npx vitest run server/__tests__/apiPassive` |
| **Full suite command** | `npx vitest run` |
| **Estimated runtime** | ~3-5s apiPassive unit · ~10s com orchestrator · ~30s full suite |

---

## Sampling Rate

- **After every task commit:** Run `npx vitest run server/__tests__/apiPassive --reporter=default`
- **After every plan wave:** Run `npx vitest run server/__tests__/apiPassive server/__tests__/apiDiscovery server/__tests__/apiCredentials` (Phase 9/10/11 regression)
- **Before `/gsd:verify-work`:** Full suite `npx vitest run` must be green
- **Max feedback latency:** ~10s para scope apiPassive

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 12-01-01 | 01 | 0 | TEST-01 | unit | `npx vitest run server/__tests__/apiPassive/nucleiArgs.test.ts` | ❌ W0 | ⬜ pending |
| 12-01-02 | 01 | 0 | TEST-01 | unit | `npx vitest run server/__tests__/apiPassive/jsonlMapper.test.ts` | ❌ W0 | ⬜ pending |
| 12-01-03 | 01 | 0 | TEST-01 | unit | `npx vitest run server/__tests__/apiPassive/api9Inventory.test.ts` | ❌ W0 | ⬜ pending |
| 12-01-04 | 01 | 0 | TEST-02 | unit | `npx vitest run server/__tests__/apiPassive/jwtAlgNone.test.ts` | ❌ W0 | ⬜ pending |
| 12-01-05 | 01 | 0 | TEST-02 | unit | `npx vitest run server/__tests__/apiPassive/kidInjection.test.ts` | ❌ W0 | ⬜ pending |
| 12-01-06 | 01 | 0 | TEST-02 | unit | `npx vitest run server/__tests__/apiPassive/tokenReuse.test.ts` | ❌ W0 | ⬜ pending |
| 12-01-07 | 01 | 0 | TEST-02 | unit | `npx vitest run server/__tests__/apiPassive/apiKeyLeakage.test.ts` | ❌ W0 | ⬜ pending |
| 12-01-08 | 01 | 0 | TEST-01+TEST-02 | unit+integration | `npx vitest run server/__tests__/apiPassive/dedupeUpsert.test.ts` | ❌ W0 | ⬜ pending |
| 12-01-09 | 01 | 0 | TEST-01+TEST-02 | integration | `npx vitest run server/__tests__/apiPassive/orchestrator.test.ts` | ❌ W0 | ⬜ pending |
| 12-01-10 | 01 | 0 | TEST-01+TEST-02 | integration | `npx vitest run server/__tests__/apiPassive/route.test.ts` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

### Test stubs (it.todo pattern)
- [ ] `server/__tests__/apiPassive/nucleiArgs.test.ts` — Nuclei CLI arg builder (TEST-01)
- [ ] `server/__tests__/apiPassive/jsonlMapper.test.ts` — JSONL → ApiFindingEvidence (kebab→camel + 8KB truncation) (TEST-01)
- [ ] `server/__tests__/apiPassive/api9Inventory.test.ts` — DB-derived API9 signal queries (TEST-01)
- [ ] `server/__tests__/apiPassive/jwtAlgNone.test.ts` — alg:none forge (TEST-02)
- [ ] `server/__tests__/apiPassive/kidInjection.test.ts` — 4 canonical kid payloads (TEST-02)
- [ ] `server/__tests__/apiPassive/tokenReuse.test.ts` — exp check + skip-opaque (TEST-02)
- [ ] `server/__tests__/apiPassive/apiKeyLeakage.test.ts` — substring + mask-at-source (TEST-02)
- [ ] `server/__tests__/apiPassive/dedupeUpsert.test.ts` — insert/update/reopen (TEST-01+TEST-02)
- [ ] `server/__tests__/apiPassive/orchestrator.test.ts` — stages + dryRun + cancel (TEST-01+TEST-02)
- [ ] `server/__tests__/apiPassive/route.test.ts` — POST /test/passive RBAC + Zod (TEST-01+TEST-02)

### Fixtures (determinístico dryRun)
- [ ] `server/__tests__/fixtures/api-passive/nuclei-passive-mock.jsonl` — 3-5 findings representativos (1 misconfig, 1 exposure, 1 graphql, 1 cors)
- [ ] `server/__tests__/fixtures/api-passive/jwt-alg-none-response.json` — response "aceito" com alg:none
- [ ] `server/__tests__/fixtures/api-passive/jwt-kid-injection-response.json` — response "aceito" com kid manipulado
- [ ] `server/__tests__/fixtures/api-passive/jwt-expired-response.json` — response "aceito" com token expirado
- [ ] `server/__tests__/fixtures/api-passive/api-key-leakage-body.json` — response body com API key vazando

### Framework install
Vitest 4.x + drizzle + zod já instalados. Zero nova dependência. Fixtures versionadas via git SHA (sem checksum explícito).

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Nuclei real execution against internal test target (Phase 15 owns `/healthz/api-test-target`) | TEST-01 #1 | Exige binário Nuclei + templates dir + rede — não reproducível em CI hermético | Executar `npx tsx --env-file=.env server/scripts/runApiPassiveTests.ts --api=<id> --dry-run` no runbook; validar findings geradas via `GET /api/v1/api-findings?apiId=<id>`. dryRun cobre reproducibilidade; non-dryRun run manual contra alvo OWASP juice-shop. |
| Real authenticated JWT manipulation against target com `bearer_jwt` cred | TEST-02 #2 | Requer API real com JWT auth + cred válida; non-hermético | Runbook operator: cadastrar API + cred bearer_jwt → `runApiPassiveTests --api=<id>` non-dryRun → validar findings API2 no read path |

---

## Validation Sign-Off

- [ ] Wave 0 stubs criados (10 arquivos de teste `it.todo`)
- [ ] Wave 0 fixtures criadas (5 arquivos JSON/JSONL)
- [ ] Todos Waves 1-3 têm `<automated>` command ou Wave 0 dependency declarado
- [ ] Sampling continuity: no 3 consecutive tasks sem automated verify
- [ ] Wave 0 cobre todas as MISSING references (TEST-01, TEST-02 ids)
- [ ] No watch-mode flags (`--watch` proibido em CI)
- [ ] Feedback latency < 10s para scope apiPassive
- [ ] `nyquist_compliant: true` no frontmatter após Wave 0 + Wave 1 verdes

**Approval:** pending
