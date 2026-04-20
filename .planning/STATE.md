---
gsd_state_version: 1.0
milestone: v2.0
milestone_name: API Discovery & Security Assessment
status: completed
stopped_at: Completed 11-discovery-enrichment-02-PLAN.md
last_updated: "2026-04-20T00:48:48.737Z"
last_activity: 2026-04-19 — Plan 10-05 delivered server/routes/apiCredentials.ts (165 lines, registerApiCredentialsRoutes(app)) + barrel registration (+2 lines) + 30 route tests GREEN; 143 apiCredentials tests passing total; full suite 487 passed (+30 vs baseline)
progress:
  total_phases: 9
  completed_phases: 3
  total_plans: 22
  completed_plans: 17
  percent: 100
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-18)

**Core value:** After running a security journey, the user must walk away with a prioritized, contextualized action plan — not a wall of raw findings.
**Current focus:** v2.0 Phase 8 — Infrastructure & Install

## Current Position

Phase: 10 of 16 (API Credentials) — v2.0 Phase 10 COMPLETE
Plan: 01 + 02 + 03 + 04 + 05 of 05 completed — Phase 10 CLOSED; next: Phase 11 (runtime executor)
Status: Plan 10-05 complete (Wave 3 CRUD route — 5 endpoints on /api/v1/api-credentials; 30 new route tests GREEN; Phase 10 CRED-01..05 all satisfied)
Last activity: 2026-04-19 — Plan 10-05 delivered server/routes/apiCredentials.ts (165 lines, registerApiCredentialsRoutes(app)) + barrel registration (+2 lines) + 30 route tests GREEN; 143 apiCredentials tests passing total; full suite 487 passed (+30 vs baseline)

Progress: [██████████] 100%

## Performance Metrics

**Velocity:**
- v1.0 plans completed: 12
- v1.1 plans completed: 5
- Total plans completed: 17

**v1.1 By Phase:**

| Phase | Plans | Tasks | Files |
|-------|-------|-------|-------|
| Phase 05 P01 | 1 | 3 tasks | 11 files |
| Phase 06 P01 | 1 | 2 tasks | 1 file |
| Phase 06 P02 | 1 | 2 tasks | 2 files |
| Phase 07 P01 | 1 | 2 tasks | 5 files |
| Phase 07 P02 | 1 | 1 task | 1 file |
| Phase 08 P01 | 15m | 2 tasks | 7 files |
| Phase 08 P03 | 15 | 2 tasks | 5 files |
| Phase 08 P02 | 35 | 2 tasks | 8 files |
| Phase 08 P04 | 29 | 2 tasks | 4 files |
| Phase 08 P05 | 20 | 1 tasks | 5 files |
| Phase 08 P06 | 28 | 4 tasks | 7 files |
| Phase 09 P01 | 157 | 3 tasks | 8 files |
| Phase 09 P02 | 5 | 2 tasks | 3 files |
| Phase 09 P03 | 269 | 3 tasks | 6 files |
| Phase 09-schema-asset-hierarchy P04 | 3 | 2 tasks | 5 files |
| Phase 10-api-credentials P01 | 3m | 2 tasks | 7 files |
| Phase 10-api-credentials P03 | 6m | 2 tasks | 5 files |
| Phase 10-api-credentials P02 | 7m | 2 tasks | 2 files |
| Phase 10-api-credentials P04 | 28m | 3 tasks | 7 files |
| Phase 10-api-credentials P05 | 8m | 2 tasks | 3 files |
| Phase 11-discovery-enrichment P01 | 10m | 3 tasks | 23 files |
| Phase 11-discovery-enrichment P02 | 5 | 3 tasks | 10 files |

## Accumulated Context

### Decisions

Full decision log in PROJECT.md Key Decisions table. Recent decisions affecting v2.0:

- v2.0 reverses "no new journey types" — APIs justify first-class treatment
- `apis` as separate table (not `asset_type='api'`) — richer attributes
- BOLA/BFLA/BOPLA in-house TypeScript (Nuclei is stateless)
- Auxiliary binaries via release tarball; `update.sh` deprecated
- [Phase 08]: bats 1.10.0 already installed on system — source build of 1.11 skipped (>= 1.10 requirement met)
- [Phase 08]: arjun-extended-pt-en.txt SHA-256 computed locally: dc5ca8c739d2205d771a9409836107515291fc418495c9d9c54c1f1fdcbc47a9 (115 lines, exceeds 100-line minimum)
- [Phase 08]: safe_reset_gate snapshot excludes .git/ metadata — FETCH_HEAD is git plumbing, not working tree mutation
- [Phase 08]: safe_reset_gate uses return 1 (not exit 1) to preserve sourcing semantics in parent shell
- [Phase 08]: fetch_archive() handles file:// URLs natively for hermetic test isolation
- [Phase 08]: pip_source mktemp requires .tar.gz suffix — pip rejects extensionless paths
- [Phase 08]: Bats direct calls (not `run`) needed for tests accessing STAGING_DIR/MOVED_PATHS globals from preserve-paths.sh
- [Phase 08]: Restore failure test uses regular file at INSTALL_DIR path (not chmod 000) — chmod 000 ineffective under root
- [Phase 08]: rebuild_app() extracted from install_application() — shared by run_install and run_safe_update
- [Phase 08]: routes-large.kite vendored as 183MB plain git object — user confirms at checkpoint whether in-tree size acceptable or LFS preferred
- [Phase 08]: extracted_sha256 field added to wordlists.json for extracted-file verification independent of tarball SHA
- [Phase 08]: _WORDLIST_REPO_ROOT env override pattern enables hermetic bats test isolation for wordlist install tests
- [Phase 08]: Tarball wordlists copied directly in run_from_tarball (cp -a) not via install_wordlists — merged MANIFEST sets source=tarball which install-wordlists.sh does not handle
- [Phase 08]: setup_file/teardown_file (bats 1.10.0) used in test_tarball_build.bats — per-test teardown deleted tarball before tests 2-8 could use it
- [Phase 08]: update.sh wrapper: exec to install.sh --update preserves exit code and all env vars for systemUpdateService.ts chain (AUTO_CONFIRM, SKIP_BACKUP, GIT_TOKEN, BRANCH, INSTALL_DIR)
- [Phase 09]: DISCOVERY_SOURCES kept as TS const (not pgEnum) — adding new sources requires no migration
- [Phase 09]: [Phase 09-01]: 80 it.todo stubs created across 5 files for Nyquist sampling coverage of Plans 02-04
- [Phase 09]: threatSeverityEnum reused in apiFindings.severity — zero new severity enum
- [Phase 09]: vitest.config.ts extended to include shared/**/*.test.ts (Rule 3 — blocked shared test discovery)
- [Phase 09]: ApiFindingEvidence as TypeScript interface + Zod schema — interface for DB type inference, schema for runtime validation
- [Phase 09]: sql.raw() used for api_findings index loop — identifiers cannot be SQL parameters
- [Phase 09]: ensureApiTables() placed after edr_deployments block in initializeDatabaseStructure
- [Phase 09]: Error swallowed in ensureApiTables catch — matches existing pattern, keeps app booting
- [Phase 09]: POST /api/v1/apis uses /api/v1/ prefix (locked per CONTEXT.md HIER-03), not /api/ prefix used by existing routes
- [Phase 09]: backfillApiDiscovery uses direct db.insert (not storage facade) — mirrors backfillWebAppParent template, keeps CLI tsx-standalone-safe
- [Phase 09]: import.meta.url guard in backfillApiDiscovery enables named exports for unit tests without triggering main()
- [Phase 10-api-credentials]: [Phase 10-01]: 99 it.todo stubs em 6 arquivos + factory compartilhado apiCredentialFactory.ts cobrindo os 7 auth types e CRED-01..05
- [Phase 10-api-credentials]: [Phase 10-01]: External commit fd8bfc3 feat(10-03) antecipou matchUrlPattern + isValidUrlPattern ja no Plan 01; urlPattern.test.ts promovido de 14 it.todo para 27 it() reais. Plan 10-03 devera consolidar (no-op ou ajustes)
- [Phase 10-api-credentials]: [Phase 10-01]: stubs usam void statements para suprimir TS6133 em imports nao-utilizados enquanto it.todo nao tem assertions
- [Phase 10-api-credentials]: [Phase 10-03]: Pattern `*` isolado e caso especial (`.*` global) — sem guard, algoritmo uniforme `[^/]*` nunca casaria URLs com `/`, invalidando a semântica de wildcard global do CONTEXT.md
- [Phase 10-api-credentials]: [Phase 10-03]: 2 entries do URL_PATTERN_MATRIX ajustadas para consistência com algoritmo `* = [^/]*` (Rule 1 bug fix); comentário explicativo adicionado ao factory
- [Phase 10-api-credentials]: [Phase 10-03]: decodeJwtExp usa 4 guards explícitos (typeof string, split len, typeof number, Number.isFinite) + try/catch para silent-fail completo — cobre exp ausente, string, NaN, Infinity, base64 malformado, JWT opaco
- [Phase 10-api-credentials]: [Phase 10-02]: baseInsertApiCredential uses .strict() (não só .omit) — Armadilha 2 exige REJEITAR campos de outros auth types, não apenas não validá-los
- [Phase 10-api-credentials]: [Phase 10-02]: patchApiCredentialSchema como z.object flat (não discriminated union .partial) — Zod não suporta .partial() nativo em unions; authType imutável fica fora do patch
- [Phase 10-api-credentials]: [Phase 10-02]: apiCredentialsRelations usa relationName ('apiCredentialCreator'/'apiCredentialUpdater') para desambiguar 2 FKs da mesma tabela users — pattern novo no projeto
- [Phase 10-api-credentials]: [Phase 10-04]: Kept and adapted prior executor's in-memory db mock (502 lines) — matches project mock pattern (threatGrouping.test.ts); wrapped all mock state in vi.hoisted() to fix vitest TDZ bug (Rule 1)
- [Phase 10-api-credentials]: [Phase 10-04]: SAFE_FIELDS explicit projection in apiCredentials facade — list/get/resolve exclude secret*/dek*; getApiCredentialWithSecret is the ONLY path returning encrypted fields (Phase 11 executor only)
- [Phase 10-api-credentials]: [Phase 10-04]: resolveApiCredential specificity metric = literal count (pattern.replace(/\*/g,'').length) — simplest deterministic tie-break per CONTEXT.md §CRED-04; filter via matchUrlPattern in JS after drizzle fetches scoped candidates
- [Phase 10-api-credentials]: [Phase 10-04]: updateApiCredential fetches current row via getApiCredentialWithSecret to determine authType (patch payload lacks authType — immutable per Plan 10-02 decision); required for mTLS JSON composite vs plain-string encrypt path
- [Phase 10-api-credentials]: [Phase 10-05]: In-process HTTP route tests via express().listen(0) + native fetch — avoided supertest dependency
- [Phase 10-api-credentials]: [Phase 10-05]: Route test mocks require storage + localAuth + db + subscriptionService + logger (5 mocks) — unblocks any route module transitively importing middleware.ts
- [Phase 10-api-credentials]: [Phase 10-05]: Rule 3 fix — plan code example imported isAuthenticatedWithPasswordCheck from ./middleware, actual export is in ../localAuth (matches server/routes/apis.ts Phase 9 pattern)
- [Phase 11-discovery-enrichment]: 8 fixtures created (not 7): plan frontmatter explicitly listed 8 files; plan prose '7' was typo
- [Phase 11-discovery-enrichment]: discoverApiOptsSchema uses .strict() on both root and stages sub-object + superRefine cross-field validation with pt-BR error message for arjunEndpointIds
- [Phase 11-discovery-enrichment]: httpx_* columns added as additive nullable columns on apiEndpoints; ensureApiEndpointHttpxColumns() boot-time guard; no drizzle migration file
- [Phase 11-discovery-enrichment]: INSTALL_PATHS uses absolute /opt/samureye/bin/* first, falls back to PATH; kiterunner tries 'kr' before 'kiterunner'; arjun venv-only path
- [Phase 11-discovery-enrichment]: upsertApiEndpoints insert/update heuristic: createdAt === updatedAt means insert; appendQueryParams uses JS-side dedup; markEndpointsStale is logging-only

### Pending Todos

None.

### Blockers/Concerns

None.

## Session Continuity

Last session: 2026-04-20T00:48:48.731Z
Stopped at: Completed 11-discovery-enrichment-02-PLAN.md
Resume file: None
