# Milestones

## v2.0 API Discovery & Security Assessment (Shipped: 2026-04-21)

**Phases:** 8-16 | **Plans:** 43 | **Timeline:** 2026-04-18 → 2026-04-20 (3 dias)
**Files changed:** 292 | **Lines TypeScript:** 51.624

### Key Accomplishments

1. **Infraestrutura offline-first** — `install.sh` safe hard-reset updater + release tarball (124MB) com 4 binários pinados (Katana/Kiterunner/httpx/Arjun) verificados por SHA-256; 54 bats + 55 vitest passando
2. **Modelo de dados API completo** — tabelas `apis`, `api_endpoints`, `api_findings` com hierarquia `parentAssetId`; backfill automático de `web_application`; credential store KEK/DEK para 7 tipos de auth
3. **Pipeline de discovery end-to-end** — spec-first (OpenAPI 2/3/GraphQL) + Katana crawler + opt-in Kiterunner brute-force + httpx enrichment + Arjun parameter discovery
4. **OWASP API Top 10 completo** — Nuclei passivo (misconfigs/CORS/JWT) + testes ativos TypeScript stateful (BOLA/BFLA/BOPLA/rate-limit/SSRF) — cobrindo todos os 10 vetores
5. **Journey orchestration com guard-rails** — `authorizationAck` obrigatório, rate cap 10-50 req/s, gating de métodos destrutivos, audit log, abort via AbortController, dry-run target
6. **UI end-to-end** — página `/journeys/api` com drill-down, filtros OWASP, wizard 4-steps (Alvos→Autenticação→Configuração→Confirmação), botão "Reproduzir" com curl placeholders

### Tech Debt Carried Forward

- Business-flow abuse (API6) documentado como limitação manual na UI — automação requer modelagem por domínio (FLOW-01 deferred)
- Auto-update service (`update.sh` deprecated mas substituto completo fora de escopo — AUTOUP-01/02 deferred)
- Visualização Stoplight-style do mapa de APIs (VIZ-01 deferred)

**Archive:** `.planning/milestones/v2.0-ROADMAP.md`, `.planning/milestones/v2.0-REQUIREMENTS.md`

---

## v1.1 Close Known Gaps (Shipped: 2026-03-23)

**Phases:** 3 | **Plans:** 5
**Timeline:** 2026-03-17 to 2026-03-23 (7 days)
**Files changed:** 46 | **Lines:** +6,981

### Key Accomplishments

1. EDR timestamp extraction from timeline events — deploymentTimestamp/detectionTimestamp per host finding
2. Queryable edr_deployments table with idempotent migration guard and storage functions
3. Scoring calibration regression tests encoding THRT-06/08/09 hierarchy invariants
4. Reusable calibration CLI (scripts/calibrate.ts) for live DB validation of scoring constants
5. Full-stack EDR deployment read path: LEFT JOIN API endpoint + Sheet UI with per-host results
6. Zero-failure test baseline established: 298 tests across 17 files, 25/25 threat rule snapshots

### Tech Debt Carried Forward

- `getEdrDeploymentsByJourney` dormant (superseded by `getEdrDeploymentsByJourneyWithHost`)
- Direct import pattern in journeyExecutor bypasses storage facade (intentional)
- Nyquist validation incomplete for Phases 5-7
- THRT-06 live validation skipped (no critical threats in DB)
- PARS-09 missing from 05-01-SUMMARY.md frontmatter (metadata only)

**Archive:** `.planning/milestones/v1.1-ROADMAP.md`, `.planning/milestones/v1.1-REQUIREMENTS.md`

---

## v1.0 — SamurEye Product Revision

**Shipped:** 2026-03-17
**Phases:** 4 | **Plans:** 12
**Timeline:** 2026-03-16 to 2026-03-17
**Files changed:** 553 | **Lines:** ~110K

### Key Accomplishments

1. Rewrote nmap/nuclei parsers with XML output and Zod validation, capturing full OS detection, service versions, NSE scripts, and nuclei evidence
2. Built threat grouping engine consolidating related findings into parent/child clusters with journey-specific grouping keys
3. Implemented contextual scoring engine with weighted formula, score breakdown persistence, and projected posture delta per threat
4. Created 25 remediation templates generating host-specific fix instructions with effort tags and role requirements
5. Redesigned threats page with expandable parent/child grouping, structured detail dialog (Problema/Impacto/Correcao), and human-readable evidence
6. Built action plan page with prioritized remediation cards, filter by effort/role/journey, and score delta visualization
7. Rewrote postura dashboard with score hero + sparkline, journey coverage grid, top 3 actions, WebSocket auto-refresh, and journey comparison delta

### Known Gaps

- PARS-07/08/09: AD/EDR parser depth improvements deferred
- PARS-11: Snapshot test coverage partial
- THRT-06/08/09: Scoring weight calibration not finalized

### UAT Results

- 12 tests: 10 passed, 1 cosmetic issue (fixed), 1 skipped (WebSocket — no live job)

**Archive:** `.planning/milestones/v1.0-ROADMAP.md`, `.planning/milestones/v1.0-REQUIREMENTS.md`
