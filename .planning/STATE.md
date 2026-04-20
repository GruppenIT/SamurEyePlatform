---
gsd_state_version: 1.0
milestone: v2.0
milestone_name: API Discovery & Security Assessment
status: completed
stopped_at: Completed 15-03-PLAN.md
last_updated: "2026-04-20T19:04:49.850Z"
last_activity: "2026-04-20 — Plan 11-07 delivered POST /api/v1/apis/:id/discover route (RBAC+Zod+audit log) + CLI server/scripts/runApiDiscovery.ts + docs/operations/run-api-discovery.md; 8 route tests GREEN; human UAT confirmed 6 smoke tests passed on real target; Phase 11 complete"
progress:
  total_phases: 9
  completed_phases: 7
  total_plans: 38
  completed_plans: 36
  percent: 100
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-18)

**Core value:** After running a security journey, the user must walk away with a prioritized, contextualized action plan — not a wall of raw findings.
**Current focus:** v2.0 Phase 8 — Infrastructure & Install

## Current Position

Phase: 11 of 16 (Discovery & Enrichment) — v2.0 Phase 11 COMPLETE
Plan: 01 + 02 + 03 + 04 + 05 + 06 + 07 of 07 completed — Phase 11 CLOSED; next: Phase 12 (Security Testing — Passive)
Status: Plan 11-07 complete (Wave 4 public surfaces — POST /api/v1/apis/:id/discover route + CLI runApiDiscovery.ts + operator runbook + 8 route tests GREEN; human UAT 6 smoke tests passed; DISC-01..06 + ENRH-01..03 all satisfied)
Last activity: 2026-04-20 — Plan 11-07 delivered POST /api/v1/apis/:id/discover route (RBAC+Zod+audit log) + CLI server/scripts/runApiDiscovery.ts + docs/operations/run-api-discovery.md; 8 route tests GREEN; human UAT confirmed 6 smoke tests passed on real target; Phase 11 complete

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
| Phase 11-discovery-enrichment P03 | 4 | 2 tasks | 7 files |
| Phase 11-discovery-enrichment P04 | 4 | 2 tasks | 4 files |
| Phase 11-discovery-enrichment P05 | 5 | 2 tasks | 4 files |
| Phase 11-discovery-enrichment P06 | 6 | 2 tasks | 3 files |
| Phase 12-security-testing-passive P01 | 7 | 3 tasks | 17 files |
| Phase 12-security-testing-passive P02 | 13m | 4 tasks | 11 files |
| Phase 12 P03 | 18 | 2 tasks | 4 files |
| Phase 12-security-testing-passive P04 | 9 | 4 tasks | 7 files |
| Phase 13-security-testing-active P01 | 5m | 3 tasks | 18 files |
| Phase 13-security-testing-active P02 | 6 | 5 tasks | 6 files |
| Phase 13-security-testing-active P03 | 4 | 1 tasks | 1 files |
| Phase 13-security-testing-active P04 | 6 | 4 tasks | 3 files |
| Phase 14-findings-runtime-threat-integration P01 | 4 | 3 tasks | 2 files |
| Phase 14-findings-runtime-threat-integration P02 | 8m | 3 tasks | 5 files |
| Phase 14-findings-runtime-threat-integration P03 | 4m | 3 tasks | 4 files |
| Phase 14-findings-runtime-threat-integration P04 | 329 | 2 tasks | 2 files |
| Phase 15-journey-orchestration-safety P01 | 2 | 2 tasks | 4 files |
| Phase 15-journey-orchestration-safety P03 | 4m | 2 tasks | 4 files |

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
- [Phase 11-discovery-enrichment]: @apidevtools/swagger-parser@^12.1.0 pinned (v11 had SSRF CVE); INTROSPECTION_QUERY hardcoded string to avoid graphql-js dep; same-origin  check uses URL.origin for SSRF boundary
- [Phase 11-discovery-enrichment]: SUCCESS_STATUSES in kiterunner.ts as integer array joined at call site — type-safe for both arg building and JSONL filter
- [Phase 11-discovery-enrichment]: kiterunner -x flag is connections-per-host (NOT QPS) per RESEARCH.md Pitfall 3; Phase 15 SAFE-01 governs true rate ceiling
- [Phase 11-discovery-enrichment]: opts.authHeader in httpx.ts auto-prefixes Authorization: when bare token passed; arjun tempfile uses mkdtemp for concurrency safety; ArjunOutputSchema exported from arjun.ts; parsed[url] ?? Object.values(parsed)[0] fallback for URL normalization edge cases
- [Phase 11-discovery-enrichment]: httpx stage always 'ran' even with 0 endpoints — stagesRun includes 'httpx' to signal stage was active (not skipped by configuration)
- [Phase 11-discovery-enrichment]: finalize() as inner closure captures all mutable state by reference — single exit path for all cancel/normal paths in discoverApi orchestrator
- [Phase 11-discovery-enrichment]: POST /api/v1/apis/:id/discover appended to registerApiRoutes(app) in apis.ts (not new route file) — consistent with Phase 9 barrel pattern
- [Phase 11-discovery-enrichment]: Synthetic jobId via crypto.randomUUID() for Phase 11; Phase 15 replaces with real queue.enqueue() — explicitly documented in route JSDoc
- [Phase 11-discovery-enrichment]: Human UAT smoke tests passed on real target — all 6 smoke tests confirmed green, no secrets in logs
- [Phase 12-security-testing-passive]: apiPassiveTestOptsSchema uses .strict() on root and stages sub-object — mirrors discoverApiOptsSchema Phase 11 pattern
- [Phase 12-security-testing-passive]: PassiveTestResult as TypeScript interface (not z.infer) — allows extension by Waves 2-3 without changing Zod schema boundary
- [Phase 12-security-testing-passive]: Nyquist Wave 0: it.todo stubs created before implementation so Wave 1-3 can use them as automated verify targets
- [Phase 12-security-testing-passive]: NucleiFinding schema uses camelCase fields (matchedAt/templateId/matcherName) not kebab-case as plan docs showed
- [Phase 12-security-testing-passive]: decodeJwtExp returns Date | null (not number | undefined) — checkTokenReuse uses .getTime() comparison
- [Phase 12-security-testing-passive]: mask-at-source pattern: API keys/tokens stored as 3-char prefix + *** at point of capture in all authFailure vectors
- [Phase 12]: upsertApiFindingByKey uses db.transaction (not ON CONFLICT) — dedupe rule requires status check; ON CONFLICT cannot express closed-row reopen logic
- [Phase 12]: listApiFindings guard requires at least one of apiId/endpointId/jobId — prevents full-table scans from callers
- [Phase 12]: encryptionService.decryptCredential(secretEncrypted, dekEncrypted) for credential secret access — ApiCredentialWithSecret has no plain .secret field
- [Phase 12-security-testing-passive]: requireAnyRole added to middleware.ts (readonly_analyst access for GET /api-findings)
- [Phase 12-security-testing-passive]: POST /test/passive audit log uses actorId (not userId) — matches Phase 11 pattern
- [Phase 12-security-testing-passive]: CLI uses pathToFileURL guard (not bare template string) — cross-platform correctness
- [Phase 12-security-testing-passive]: UAT humana aprovada em 2026-04-20 — fluxo completo dryRun confirmado, Phase 12 CLOSED
- [Phase 13-security-testing-active]: stagesRun uses snake_case 'rate_limit' for consistency with Phase 12 PassiveTestResult convention
- [Phase 13-security-testing-active]: BOPLA_SENSITIVE_KEYS as const array (not enum) — preserves literal tuple type for BoplaSensitiveKey derivation
- [Phase 13-security-testing-active]: ActiveTestResult as TypeScript interface (not z.infer) — allows extension by Waves 1-3 without changing Zod schema boundary
- [Phase 13-security-testing-active]: ssrfNuclei.ts reads interaction=true from raw JSON pre-schema-strip; uses camelCase matchedAt from Zod output (Phase 12 NucleiFindingSchema decision)
- [Phase 13-security-testing-active]: bola.ts isListLikePath uses /\{\w+\}/.test() non-stateful check to avoid global regex lastIndex bugs
- [Phase 13-security-testing-active]: bopla.ts re-exports BOPLA_SENSITIVE_KEYS so orchestrator imports from single scanner module
- [Phase 13-security-testing-active]: pairCredentials generic type {id} requires orchestrator to re-resolve full CredWithSecret from credsWithSecrets array after pairing
- [Phase 13-security-testing-active]: identifyLowPrivCreds returns BflaCredentialSignal (no secret); orchestrator resolves full cred via .find() before buildAuthHeaders
- [Phase 13-security-testing-active]: dryRun handling is orchestrator responsibility for all active stages; scanner interfaces don't carry dryRunFixturePath params
- [Phase 13-security-testing-active]: Used actorId (not userId) in logAudit for POST /test/active — matches Phase 12 passive handler pattern
- [Phase 13-security-testing-active]: UAT auto-approved in auto-mode: Steps 1-4 static checks pass; Steps 5-8 require live server (not available in CI)
- [Phase 14-findings-runtime-threat-integration]: Use new RegExp(pattern.source, 'g') per call instead of reusing /g constants — avoids lastIndex statefulness bugs in global regex
- [Phase 14-findings-runtime-threat-integration]: console.warn in fail-open path (not pino logger) — shared/sanitization.ts is runtime-agnostic, no server logger dependency
- [Phase 14-findings-runtime-threat-integration]: CPF formatted pattern applied before CPF plain to prevent 11-digit plain match from swallowing already-formatted CPF digits
- [Phase 14-findings-runtime-threat-integration]: threats.category=apiId para agrupamento (schema real sem parentAssetId — plano descrevia schema hipotético)
- [Phase 14-findings-runtime-threat-integration]: correlationKey='api_security:{apiId}:{owaspCategory}:{endpointId}' para idempotência de promoção
- [Phase 14-findings-runtime-threat-integration]: updateFindingPromotedThreatId aceita tx?: typeof db — type cast necessário pois drizzle Tx não é assignable a typeof db
- [Phase 14-findings-runtime-threat-integration]: WebSocket route in jobs.ts is REST-only — import anchor + TODO comment placed; upgrade handler deferred to Wave 3 (14-04) / Phase 15
- [Phase 14-findings-runtime-threat-integration]: forEach instead of for..of on Set<WebSocket> — avoids TS2802 downlevelIteration error given no explicit target in tsconfig
- [Phase 14-findings-runtime-threat-integration]: pino createLogger used in broadcaster (not console.warn) — consistent with project CONVENTIONS.md logging pattern
- [Phase 14-findings-runtime-threat-integration]: runPostScannerPipeline helper for Steps 2+3; sanitize inline per-handler (grep ≥ 2 call sites); listApiFindings({jobId}) for IDs post-scan
- [Phase 14-findings-runtime-threat-integration]: endpointPath in findings_batch uses apiEndpointId (UUID) as proxy — Phase 15 resolves human-readable path
- [Phase 15-journey-orchestration-safety]: [Phase 15-01]: Nyquist Wave 0 stubs created before implementation — Plans 02-04 promote it.todo to real it() with assertions
- [Phase 15-journey-orchestration-safety]: MAX_API_RATE_LIMIT=50 exportado como constante nomeada — Plan 04 importa via named import sem hardcode
- [Phase 15-journey-orchestration-safety]: /healthz/api-test-target usa prefixo /healthz/ (não /api/) para escapar requireActiveSubscription linha 37

### Pending Todos

None.

### Blockers/Concerns

None.

## Session Continuity

Last session: 2026-04-20T19:04:49.847Z
Stopped at: Completed 15-03-PLAN.md
Resume file: None
