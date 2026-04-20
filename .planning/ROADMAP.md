# Roadmap: SamurEye Platform

## Milestones

- **v1.0 Product Revision** — Phases 1-4 (shipped 2026-03-17)
- **v1.1 Close Known Gaps** — Phases 5-7 (shipped 2026-03-23)
- **v2.0 API Discovery & Security Assessment** — Phases 8-16 (planned, 2026-04-18)

## Phases

<details>
<summary>v1.0 Product Revision (Phases 1-4) — SHIPPED 2026-03-17</summary>

- [x] Phase 1: Parser Foundation (3/3 plans) — completed 2026-03-16
- [x] Phase 2: Threat Engine Intelligence (3/3 plans) — completed 2026-03-16
- [x] Phase 3: Remediation Engine (2/2 plans) — completed 2026-03-16
- [x] Phase 4: User-Facing Surfaces (4/4 plans) — completed 2026-03-16

See: `.planning/milestones/v1.0-ROADMAP.md` for full details.

</details>

<details>
<summary>v1.1 Close Known Gaps (Phases 5-7) — SHIPPED 2026-03-23</summary>

- [x] Phase 5: EDR Timestamps (1/1 plan) — completed 2026-03-17
- [x] Phase 6: Calibration and Quality (2/2 plans) — completed 2026-03-17
- [x] Phase 7: EDR Deployment Read Path (2/2 plans) — completed 2026-03-23

See: `.planning/milestones/v1.1-ROADMAP.md` for full details.

</details>

### v2.0 API Discovery & Security Assessment (Planned)

**Milestone Goal:** Deliver the 5th security journey — automated discovery of APIs (REST/GraphQL/SOAP) plus security testing aligned to OWASP API Security Top 10 (2023) — as a first-class capability integrated with the existing Attack Surface and Web Application journeys.

- [x] **Phase 8: Infrastructure & Install** — Safe hard-reset `install.sh`, pinned binaries, wordlists, tarball flow (completed 2026-04-18)
- [x] **Phase 9: Schema & Asset Hierarchy** — `apis`, `api_endpoints`, `api_findings` tables + backfill (completed 2026-04-19)
- [x] **Phase 10: API Credentials** — 7 auth-type credential store reusing KEK/DEK, URL patterns, priorities (completed 2026-04-19)
- [x] **Phase 11: Discovery & Enrichment** — Spec-first + crawler + brute-force + httpx + Arjun (completed 2026-04-20)
- [x] **Phase 12: Security Testing — Passive** — Nuclei misconfigs + stateless auth-failure tests (completed 2026-04-20)
- [x] **Phase 13: Security Testing — Active** — Stateful BOLA / BFLA / BOPLA / rate-limit / SSRF (completed 2026-04-20)
- [x] **Phase 14: Findings Runtime & Threat Integration** — Sanitization, promotion to threats, WebSocket events (completed 2026-04-20)
- [ ] **Phase 15: Journey Orchestration & Safety** — Enum, abort, wizard-backend, rate caps, audit, dry-run
- [ ] **Phase 16: UI & Final Integration** — API page, drill-down, findings filters, wizard, curl reproduction

## Phase Details

### Phase 8: Infrastructure & Install
**Goal**: Establish a reproducible appliance update path and pinned auxiliary binaries so every downstream phase can install, verify, and invoke Katana / Kiterunner / httpx / Arjun without runtime downloads.
**Depends on**: Phase 7 (v1.1 shipped baseline)
**Requirements**: INFRA-01, INFRA-02, INFRA-03, INFRA-04, INFRA-05
**Success Criteria** (what must be TRUE):
  1. Running `install.sh` on a clean checkout installs the appliance AND pinned versions of Katana, Kiterunner, httpx, and Arjun with verified SHA-256 checksums
  2. Running `install.sh` on a dirty checkout (unpushed commits ahead of origin) aborts cleanly without mutating the working tree
  3. After `install.sh` runs, `.planning/`, `docs/`, `backups/`, `uploads/`, `.env`, and cloud-synced skills directories are preserved unchanged
  4. `routes-large.kite` and `arjun-extended-pt-en.txt` are present on disk with verified checksums — no network fetch occurs at runtime
  5. A release tarball containing app + binaries + wordlists can be built and installed end-to-end; `update.sh` displays a deprecation notice
**Plans:** 6/6 plans complete
Plans:
- [ ] 08-01-PLAN.md — Wave 0: Pinned manifests (binaries.json + wordlists.json), bats-core harness, vendor staging, custom pt-BR Arjun wordlist seeded
- [ ] 08-02-PLAN.md — Wave 1: Binary fetch/verify module (install_binary + SHA-256 gate) with Arjun pip-source venv handling
- [ ] 08-03-PLAN.md — Wave 1: safe_reset_gate (ahead-of-origin + porcelain dirty-tree detection with exact recovery hints)
- [ ] 08-04-PLAN.md — Wave 2: install.sh flag dispatch + PRESERVE_PATHS expansion + run_safe_update flow
- [ ] 08-05-PLAN.md — Wave 2: Wordlist install + vendored routes-large.kite (in-tree, SHA-verified, CDN-resilient)
- [ ] 08-06-PLAN.md — Wave 3: build-release.sh tarball + install.sh --from-tarball + update.sh deprecation wrapper

### Phase 9: Schema & Asset Hierarchy
**Goal**: Persist the full API data model (apis, api_endpoints, api_findings) as additive migrations under the existing `parentAssetId` hierarchy, and backfill existing web_application assets so discovery has a home to write into.
**Depends on**: Phase 8
**Requirements**: HIER-01, HIER-02, HIER-03, HIER-04, FIND-01
**Success Criteria** (what must be TRUE):
  1. Running migrations creates `apis`, `api_endpoints`, and `api_findings` tables with the required columns, FKs, and indexes; re-running is idempotent
  2. User can manually register an API under an existing web_application asset (baseUrl, apiType, optional spec URL) via an internal endpoint and see it persisted
  3. Every `api_endpoints` row captures method, path, params (path/query/header), request/response schemas, `requiresAuth`, and discovery sources
  4. A backfill job probes existing web_application assets for API indicators (JSON content-type, `/api` paths, known spec paths) and auto-promotes detected ones into `apis` rows
  5. The `api_findings` table is queryable with OWASP API Top 10 2023 category, severity, evidence, remediation, and risk score columns in place
**Plans:** 4/4 plans complete
Plans:
- [ ] 09-01-PLAN.md — Wave 0: OWASP pt-BR labels constants + 7 Nyquist test stubs (evidence Zod, schema, guard, route, storage, backfill, owasp)
- [ ] 09-02-PLAN.md — Wave 1: shared/schema.ts additions (3 pgEnums, 3 tables, 3 insertSchemas, evidence Zod)
- [ ] 09-03-PLAN.md — Wave 2: storage facades (apis/apiEndpoints/apiFindings) + IStorage + DatabaseStorage + ensureApiTables guard
- [ ] 09-04-PLAN.md — Wave 3: POST /api/v1/apis route + backfillApiDiscovery CLI + operator docs

### Phase 10: API Credentials
**Goal**: Ship a credential store for the 7 supported API auth types that reuses the platform's existing KEK/DEK encryption, with URL-pattern mapping and priority resolution so the engine picks the right credential per endpoint.
**Depends on**: Phase 9
**Requirements**: CRED-01, CRED-02, CRED-03, CRED-04, CRED-05
**Success Criteria** (what must be TRUE):
  1. User can store a credential for each of the 7 auth types (api_key_header, api_key_query, bearer_jwt, basic, oauth2_client_credentials, hmac, mtls) and retrieve it decrypted only via the storage facade
  2. Credentials at rest are encrypted with the existing KEK/DEK flow — no new crypto primitives are introduced
  3. User can map a credential to a URL pattern (glob/prefix); the engine resolves and applies only matching credentials per endpoint
  4. When multiple credentials match the same URL, the user-assigned priority order determines selection
  5. During the journey wizard, user can create a credential inline without leaving the flow and the new credential is immediately available for selection
**Plans:** 5/5 plans complete
Plans:
- [x] 10-01-PLAN.md — Wave 0: Nyquist test stubs (6 files) + shared apiCredentialFactory helper (CRED-01..05)
- [x] 10-02-PLAN.md — Wave 1: shared/schema.ts additions — apiAuthTypeEnum + apiCredentials pgTable + relations + insertApiCredentialSchema discriminated union + tipos derivados (CRED-01, CRED-02)
- [x] 10-03-PLAN.md — Wave 1: helpers stateless — matchUrlPattern.ts (glob→regex + isValidUrlPattern) + decodeJwtExp.ts (CRED-03, CRED-04)
- [x] 10-04-PLAN.md — Wave 2: storage facade apiCredentials.ts (7 funções + SAFE_FIELDS) + ensureApiCredentialTables() guard + IStorage + DatabaseStorage wiring (CRED-01, CRED-02, CRED-03, CRED-04)
- [x] 10-05-PLAN.md — Wave 3: POST|GET|PATCH|DELETE /api/v1/api-credentials route + barrel registration (CRED-01, CRED-05)

### Phase 11: Discovery & Enrichment
**Goal**: Ship the full endpoint-discovery pipeline — spec-first probing, native OpenAPI/GraphQL parsing, Katana crawling, opt-in Kiterunner brute-force — plus httpx probing and optional Arjun parameter discovery that enriches every discovered endpoint.
**Depends on**: Phase 10 (credentials available for authenticated probing)
**Requirements**: DISC-01, DISC-02, DISC-03, DISC-04, DISC-05, DISC-06, ENRH-01, ENRH-02, ENRH-03
**Success Criteria** (what must be TRUE):
  1. Against a target exposing `/openapi.json`, `/swagger.json`, or `/v3/api-docs`, the discovery stage writes one `apis` row and N `api_endpoints` rows parsed natively from the spec (OpenAPI 2.0, 3.0, and 3.1 all supported)
  2. Against a target exposing a GraphQL introspection endpoint (`/graphql`, `/api/graphql`, `/query`), the discovery stage captures the schema when introspection is enabled
  3. Katana crawling of an SPA surfaces XHR/JS/form-derived endpoints and persists them with discovery source set; Kiterunner brute-force is strictly opt-in and uses `routes-large.kite`
  4. Every discovered endpoint has httpx enrichment (status, tech-detect, content-type, TLS) and `requiresAuth=true` when unauthenticated calls return 401/403
  5. Arjun parameter discovery runs only on user-selected GET endpoints and attaches discovered params to the endpoint record; `specHash` is computed and stored per spec fetch so drift is detectable across executions
**Plans:** 7/7 plans complete
Plans:
- [ ] 11-01-PLAN.md — Wave 0: 13 Nyquist test stubs + 7 fixtures + discoverApiOptsSchema + 5 httpx_* additive columns on api_endpoints + ensureApiEndpointHttpxColumns guard (DISC-01..06, ENRH-01..03)
- [ ] 11-02-PLAN.md — Wave 1: shared preflightApiBinary (4 binaries memoized) + canonical specHash helper + processTracker typing widened + 5 storage extensions (upsertApiEndpoints bulk, mergeHttpxEnrichment, appendQueryParams, markEndpointsStale, updateApiSpecMetadata) (DISC-06)
- [ ] 11-03-PLAN.md — Wave 2: scanners/api/openapi.ts (fetchAndParseSpec + specToEndpoints + same-origin $ref SSRF guard) + scanners/api/graphql.ts (probeGraphQL + schemaToEndpoints + INTROSPECTION_QUERY) + @apidevtools/swagger-parser@^12.1.0 (DISC-01, DISC-02, DISC-03)
- [ ] 11-04-PLAN.md — Wave 2: scanners/api/katana.ts (7-branch auth matrix + JSONL stream + AbortSignal) + scanners/api/kiterunner.ts (opt-in, -x 5 -j 100 defensive + explicit success/fail status codes) (DISC-04, DISC-05)
- [ ] 11-05-PLAN.md — Wave 2: scanners/api/httpx.ts (stdin batch + tri-valor mapRequiresAuth) + scanners/api/arjun.ts (Zod dict-keyed validation + tempfile try/finally) (ENRH-01, ENRH-02, ENRH-03)
- [ ] 11-06-PLAN.md — Wave 3: journeys/apiDiscovery.ts orchestrator (spec → crawler → kiterunner → httpx 2-pass → arjun) + DiscoveryResult contract + drift detection + stale endpoint logging + OAuth2 per-run cache (all DISC + ENRH)
- [ ] 11-07-PLAN.md — Wave 4: POST /api/v1/apis/:id/discover route (RBAC + Zod + audit log) + CLI server/scripts/runApiDiscovery.ts + docs/operations/run-api-discovery.md + human verification checkpoint against petstore3.swagger.io

### Phase 12: Security Testing — Passive
**Goal**: Run the stateless portion of the OWASP API Top 10 test matrix — Nuclei misconfiguration/exposure/GraphQL/CORS templates plus JWT/auth-failure tests — producing findings that flow into `api_findings`.
**Depends on**: Phase 11
**Requirements**: TEST-01, TEST-02
**Success Criteria** (what must be TRUE):
  1. User can run the `api_security` journey and observe Nuclei misconfiguration/exposure/graphql/cors templates executed against every discovered endpoint without credentials (API8 + API9 coverage)
  2. When credentials are supplied, the engine executes auth-failure tests — JWT `alg: none`, `kid` injection, token reuse, API key leakage in responses — and records any hits with OWASP category API2
  3. Findings from both test classes land in `api_findings` with severity, evidence, and remediation populated and are visible via an internal read path
  4. Passive-test output is reproducible via a `dryRun` against the internal test target with deterministic results
**Plans:** 4/4 plans complete
Plans:
- [ ] 09-01-PLAN.md — Wave 0: OWASP pt-BR labels constants + 7 Nyquist test stubs (evidence Zod, schema, guard, route, storage, backfill, owasp)
- [ ] 09-02-PLAN.md — Wave 1: shared/schema.ts additions (3 pgEnums, 3 tables, 3 insertSchemas, evidence Zod)
- [ ] 09-03-PLAN.md — Wave 2: storage facades (apis/apiEndpoints/apiFindings) + IStorage + DatabaseStorage + ensureApiTables guard
- [ ] 09-04-PLAN.md — Wave 3: POST /api/v1/apis route + backfillApiDiscovery CLI + operator docs

### Phase 13: Security Testing — Active
**Goal**: Implement the stateful OWASP API Top 10 vectors in-house (TypeScript) — BOLA, BFLA, BOPLA/Mass Assignment, rate-limit absence, SSRF — which require multi-identity enumeration and cross-request state that Nuclei cannot express.
**Depends on**: Phase 12
**Requirements**: TEST-03, TEST-04, TEST-05, TEST-06, TEST-07
**Success Criteria** (what must be TRUE):
  1. When two or more distinct credentials are supplied, the engine performs BOLA cross-identity object-access tests and records API1 findings with the evidencing pair of requests
  2. With a low-privilege credential, the engine attempts admin-level endpoint/method access and records API5 (BFLA) findings on success
  3. On PUT/PATCH endpoints with unknown schemas, the engine injects sensitive property names and inspects response reflection to record API3 (BOPLA/Mass Assignment) findings
  4. User can opt into rate-limit-absence testing; the engine bursts N requests and records API4 findings when neither 429 nor `Retry-After` is observed
  5. The engine runs Nuclei + interactsh SSRF tests only on params whose values accept URLs and records API7 findings when an out-of-band interaction fires
**Plans:** 4/4 plans complete
Plans:
- [ ] 13-01-PLAN.md — Wave 0: Nyquist stubs + fixtures api-active/ + apiActiveTestOptsSchema + ActiveTestResult
- [ ] 13-02-PLAN.md — Wave 1: 5 scanners (bola/bfla/bopla/rateLimit/ssrfNuclei) + remediation templates extension
- [ ] 13-03-PLAN.md — Wave 2: Orchestrator runApiActiveTests (5 stages + dryRun + cancel + BOPLA/rateLimit gates)
- [ ] 13-04-PLAN.md — Wave 3: POST /api/v1/apis/:id/test/active + CLI + runbook + UAT checkpoint

### Phase 14: Findings Runtime & Threat Integration
**Goal**: Harden the findings write path with sanitization, promote high/critical findings into the existing Threat Engine so they surface on the executive dashboard, and emit real-time progress events to the UI over WebSocket.
**Depends on**: Phase 13
**Requirements**: FIND-02, FIND-03, FIND-04
**Success Criteria** (what must be TRUE):
  1. Every `api_findings` row passes through sanitization — auth headers redacted, response body truncated to 8KB, PII masked (CPF / CNPJ / email / credit-card) — before persistence
  2. High and critical `api_findings` are automatically promoted into the existing `threats` table with dedupe against the same endpoint, and appear on the executive dashboard alongside findings from the other 4 journey types
  3. During journey execution, progress events and new findings are streamed over WebSocket and the UI reflects them without a refresh
  4. An end-to-end execution on the dry-run target produces sanitized findings, promoted threats, and WebSocket events observable from the browser dev console
**Plans:** 4/4 plans complete
Plans:
- [ ] 09-01-PLAN.md — Wave 0: OWASP pt-BR labels constants + 7 Nyquist test stubs (evidence Zod, schema, guard, route, storage, backfill, owasp)
- [ ] 09-02-PLAN.md — Wave 1: shared/schema.ts additions (3 pgEnums, 3 tables, 3 insertSchemas, evidence Zod)
- [ ] 09-03-PLAN.md — Wave 2: storage facades (apis/apiEndpoints/apiFindings) + IStorage + DatabaseStorage + ensureApiTables guard
- [ ] 09-04-PLAN.md — Wave 3: POST /api/v1/apis route + backfillApiDiscovery CLI + operator docs

### Phase 15: Journey Orchestration & Safety
**Goal**: Wire the `api_security` journey into the existing executor, scheduler, and abort machinery — with safety guard-rails (authorization acknowledgment, rate caps, destructive-method gating, structured logs, audit log, dry-run target) enforced at the orchestration layer.
**Depends on**: Phase 14
**Requirements**: JRNY-01, JRNY-02, JRNY-03, JRNY-04, JRNY-05, SAFE-01, SAFE-02, SAFE-03, SAFE-04, SAFE-05, SAFE-06
**Success Criteria** (what must be TRUE):
  1. The `journey_type` enum includes `api_security` and jobs of that type route to the API journey executor; user can schedule recurring `api_security` jobs through the existing scheduler with no new scheduler code
  2. User cannot start an `api_security` journey without acknowledging authorization to test; acknowledgment is persisted, and every execution creates an `audit_log` row with user, targets, credential IDs (never secrets), timestamp, and outcome
  3. The engine enforces a default 10 req/s per-endpoint cap, honors user overrides up to an absolute 50 req/s ceiling that cannot be bypassed, and respects `Retry-After` / exponential backoff on 429/503
  4. DELETE/PUT/PATCH against unknown schemas are disabled unless the user checks a red-warning box with double-confirmation; `POST /api/v1/jobs/{id}/abort` stops all child processes via AbortController
  5. The internal `/healthz/api-test-target` endpoint supports full `dryRun` executions without touching real targets; all logs are structured JSON and never include request bodies, credentials, or tokens
**Plans:** 4 plans
Plans:
- [ ] 15-01-PLAN.md — Wave 1: 4 Nyquist test stubs (journeyOrchestration + rateLimiter + abortRoute + healthzTarget) cobrindo JRNY-01..05 + SAFE-01..06
- [ ] 15-02-PLAN.md — Wave 2: shared/schema.ts journeyTypeEnum estendido (api_security) + journeys.authorizationAck column + ensureJourneyApiSecurityColumns guard
- [ ] 15-03-PLAN.md — Wave 2: server/services/rateLimiter.ts (TokenBucketRateLimiter + MAX_API_RATE_LIMIT=50 + backoff) + GET /healthz/api-test-target route
- [ ] 15-04-PLAN.md — Wave 3: executeApiSecurity() method in journeyExecutor.ts (JRNY-01..03, SAFE-03/04/06) + POST /api/v1/jobs/:id/abort route (JRNY-05)

### Phase 16: UI & Final Integration
**Goal**: Ship the end-user surface — API Discovery page, endpoint drill-down, findings filters with OWASP badges, false-positive marking, journey wizard (4 steps), and per-finding curl reproduction — delivering the "prioritized, contextualized action plan" promise for API findings.
**Depends on**: Phase 15
**Requirements**: UI-01, UI-02, UI-03, UI-04, UI-05, UI-06
**Success Criteria** (what must be TRUE):
  1. `/journeys/api` lists discovered APIs with baseUrl, type, discovery method, endpoint count, and last-execution metadata; clicking an API drills down into endpoints grouped by path with method badges, auth-required indicator, and known parameters
  2. The findings page accepts `source=api_security` as a filter and displays OWASP API Top 10 category badges on each finding
  3. Each finding has a "Reproduzir" action that produces a `curl` command with credential placeholders only — no real secret is ever rendered
  4. User can mark a finding as `false_positive`; the change is recorded in `audit_log`
  5. The 4-step journey creation wizard (Alvos → Autenticação → Configuração → Confirmação) exposes discovery toggles (spec-first, crawler, kiterunner), testing toggles (misconfigs, auth, BOLA, BFLA, BOPLA, rate-limit, SSRF), inline credential creation, an estimated-requests preview, and the mandatory authorization-acknowledgment checkbox
**Plans:** 4 plans
Plans:
- [ ] 09-01-PLAN.md — Wave 0: OWASP pt-BR labels constants + 7 Nyquist test stubs (evidence Zod, schema, guard, route, storage, backfill, owasp)
- [ ] 09-02-PLAN.md — Wave 1: shared/schema.ts additions (3 pgEnums, 3 tables, 3 insertSchemas, evidence Zod)
- [ ] 09-03-PLAN.md — Wave 2: storage facades (apis/apiEndpoints/apiFindings) + IStorage + DatabaseStorage + ensureApiTables guard
- [ ] 09-04-PLAN.md — Wave 3: POST /api/v1/apis route + backfillApiDiscovery CLI + operator docs

## Progress

**Execution Order:**
Phases execute in numeric order: 8 → 9 → 10 → 11 → 12 → 13 → 14 → 15 → 16

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Parser Foundation | v1.0 | 3/3 | Complete | 2026-03-16 |
| 2. Threat Engine Intelligence | v1.0 | 3/3 | Complete | 2026-03-16 |
| 3. Remediation Engine | v1.0 | 2/2 | Complete | 2026-03-16 |
| 4. User-Facing Surfaces | v1.0 | 4/4 | Complete | 2026-03-16 |
| 5. EDR Timestamps | v1.1 | 1/1 | Complete | 2026-03-17 |
| 6. Calibration and Quality | v1.1 | 2/2 | Complete | 2026-03-17 |
| 7. EDR Deployment Read Path | v1.1 | 2/2 | Complete | 2026-03-23 |
| 8. Infrastructure & Install | 6/6 | Complete   | 2026-04-18 | - |
| 9. Schema & Asset Hierarchy | 4/4 | Complete   | 2026-04-19 | - |
| 10. API Credentials | 5/5 | Complete    | 2026-04-19 | - |
| 11. Discovery & Enrichment | 7/7 | Complete    | 2026-04-20 | - |
| 12. Security Testing — Passive | 4/4 | Complete    | 2026-04-20 | - |
| 13. Security Testing — Active | 4/4 | Complete    | 2026-04-20 | - |
| 14. Findings Runtime & Threat Integration | 4/4 | Complete    | 2026-04-20 | - |
| 15. Journey Orchestration & Safety | v2.0 | 0/TBD | Not started | - |
| 16. UI & Final Integration | v2.0 | 0/TBD | Not started | - |
