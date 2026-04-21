# Project Retrospective

*A living document updated after each milestone. Lessons feed forward into future planning.*

## Milestone: v1.1 — Close Known Gaps

**Shipped:** 2026-03-23
**Phases:** 3 | **Plans:** 5

### What Was Built
- EDR per-host deployment/detection timestamps with queryable storage table
- Full-stack EDR deployment read path (API + Sheet UI)
- Scoring calibration regression tests and reusable CLI
- Zero-failure test baseline (298 tests, 25/25 snapshots)

### What Worked
- Gap-driven milestone scope kept work tightly focused — every phase traced to a specific audit finding
- Reuse of existing patterns (storage ops module, route registration, Sheet side-panel) made new features fast
- Calibration script as reusable CLI means future scoring changes can be re-validated quickly
- "Pre-resolved" findings (QUAL-01 already passing, PARS-11 snapshots already committed) saved execution time

### What Was Inefficient
- Nyquist validation was configured but never signed off for any phase — the workflow step exists but wasn't enforced
- STATE.md progress tracking fell out of sync during rapid execution — manual updates needed
- The original `getEdrDeploymentsByJourney` was created in Phase 5 but immediately superseded in Phase 7 — could have been designed once if phases were planned together

### Patterns Established
- Idempotent migration guard pattern (pg_tables check + CREATE TABLE IF NOT EXISTS) for additive schema changes
- Calibration regression tests as hierarchy invariants — express scoring rules as assertions, not documentation
- Sheet side-panel pattern for row-level detail views (journey → EDR deployment results)

### Key Lessons
1. Gap audits before milestone closure catch real issues — PARS-10 partial gap would have shipped incomplete without the audit
2. "Pre-resolved" status should be verified early — two of the Phase 6 items were already done, saving a full plan's worth of work
3. Fire-and-forget storage inserts (non-blocking try/catch) are the right pattern for metadata that doesn't block the primary flow

### Cost Observations
- Sessions: ~6 across 2 days (Mar 17, Mar 23)
- Notable: v1.1 was compact — 5 plans across 3 phases, 46 files changed, completed in 7 calendar days

---

## Milestone: v2.0 — API Discovery & Security Assessment

**Shipped:** 2026-04-21
**Phases:** 9 (8-16) | **Plans:** 43 | **Timeline:** 3 dias (2026-04-18 → 2026-04-20)

### What Was Built
- Offline-capable appliance update path — `install.sh` hard-reset + tarball (124MB) com SHA-256 para 4 binários
- API data model completo — `apis`, `api_endpoints`, `api_findings` + backfill automático de `web_application` existentes
- Credential store para 7 tipos de auth com KEK/DEK, URL patterns, e prioridade por credential
- Pipeline de discovery multi-método: OpenAPI 2/3/GraphQL + Katana + Kiterunner + httpx + Arjun
- OWASP API Top 10 (2023) completo: Nuclei passivo + TypeScript stateful (BOLA/BFLA/BOPLA/rate-limit/SSRF)
- Journey orchestration com safety guard-rails: authorizationAck, rate caps, gating destrutivo, audit log, abort
- UI completa: `/journeys/api`, drill-down, OWASP badges, wizard 4-steps, curl "Reproduzir", false-positive marking

### What Worked
- Waves estruturadas (0-stubs → 1-core → 2-orchestrator → 3-public surface) mantiveram cada fase focada e testável
- Reutilização de padrões existentes (KEK/DEK, parentAssetId, audit log, storage facade) acelerou fases 9-10 significativamente
- Nyquist test stubs no Wave 0 de cada fase garantiram cobertura sem retrabalho
- TypeScript stateful para BOLA/BFLA foi a decisão certa — Nuclei não conseguiria expressar esses vetores
- 3 dias para 9 fases de complexidade alta = milestone mais rápido até agora

### What Was Inefficient
- Plans 12/13/14 "phase details" em ROADMAP.md vieram copiados errados do Phase 9 (bug de template no gsd-tools) — não afetou execução mas poluiu o arquivo
- Fase 15 planos listados como 3/4 em ROADMAP.md progress table (erro de tracking)
- Accomplishments do `milestone complete` CLI vieram vazios — extração de one_liners falhou (campo não serializado no frontmatter YAML)

### Patterns Established
- Wave 0 = Nyquist test stubs para toda a fase — garante que nenhuma feature sai sem teste escrito antes
- `ensureXxxTables()` guard em cada nova entidade de schema — padrão de migração idempotente consolidado
- SAFE_FIELDS projection em todo storage de credenciais — nunca retornar segredos por descuido
- `__none__` sentinel para Radix Select sem empty-string — workaround validado para Radix UI

### Key Lessons
1. Fases com mais de 6 planos (Phase 11 com 7) podem ser divididas sem perder coesão — descoberta encadeada em sub-waves funciona bem
2. Release tarball bundled (app + binários + wordlists) é o único modelo viável para appliances air-gapped — o pattern `build-release.sh + --from-tarball` deve ser padrão em todos os projetos
3. authorizationAck persistido no banco (não apenas validado na UI) é o design correto — auditável e defensável

### Cost Observations
- Sessions: ~8-10 ao longo de 3 dias (Apr 18-20)
- Notable: Maior milestone até agora em volume (9 fases, 43 planos, 292 arquivos) concluído em menos tempo que v1.1

---

## Cross-Milestone Trends

### Process Evolution

| Milestone | Phases | Plans | Key Change |
|-----------|--------|-------|------------|
| v1.0 | 4 | 12 | Full product revision with GSD workflow |
| v1.1 | 3 | 5 | Gap-driven scope, audit-before-close pattern |
| v2.0 | 9 | 43 | Wave 0 Nyquist stubs enforced; offline tarball deploy model; OWASP security coverage |

### Cumulative Quality

| Milestone | Tests | Snapshots | Files Changed |
|-----------|-------|-----------|---------------|
| v1.0 | ~280 | 25 | 553 |
| v1.1 | 298 | 25 | 46 |
| v2.0 | 300+ | 25 | 292 |

### Top Lessons (Verified Across Milestones)

1. Additive schema changes prevent data loss and allow safe rollback — validated across all 3 milestones
2. Audit before closing milestones catches real gaps — v1.0 known gaps became v1.1 scope
3. Wave 0 test stubs are a forcing function for coverage — adopted in v2.0 and should be standard
4. Reutilização de padrões internos (KEK/DEK, audit log, parentAssetId) amortize complexity across milestones — design investment pays off
