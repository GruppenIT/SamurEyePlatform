# Requirements: API Discovery & Security Assessment (Milestone v2.0)

**Defined:** 2026-04-18
**Core Value:** After running a security journey, the user must walk away with a prioritized, contextualized action plan — not a wall of raw findings.

## v2.0 Requirements

Requirements for the API Discovery & Security Assessment milestone. Each maps to roadmap phases.

### Asset Hierarchy (HIER)

- [x] **HIER-01**: System persists `apis` as a first-class table with `parentAssetId → assets.id` under an existing `web_application` asset
- [x] **HIER-02**: System persists `api_endpoints` with `apiId → apis.id`, capturing method, path, params (path/query/header), request/response schemas, auth requirement, and discovery sources
- [x] **HIER-03**: User can manually register an API under an existing web_application asset (with baseUrl, apiType, and optional spec URL)
- [x] **HIER-04**: System backfills existing web_application assets by probing for API indicators (JSON content-type, /api paths, known spec paths) and auto-promoting when detected

### API Credentials (CRED)

- [x] **CRED-01**: User can store API credentials with auth types: api_key_header, api_key_query, bearer_jwt, basic, oauth2_client_credentials, hmac, mtls
- [x] **CRED-02**: System encrypts credentials reusing the existing KEK/DEK pattern (no new crypto logic)
- [x] **CRED-03**: User maps each credential to a URL pattern (glob/prefix) so the engine applies it only to matching endpoints
- [x] **CRED-04**: User can prioritize credentials when multiple match the same URL
- [x] **CRED-05**: User can create a credential inline during the journey wizard

### Discovery (DISC)

- [x] **DISC-01**: System probes spec-first paths (`/openapi.json`, `/swagger.json`, `/v2/api-docs`, `/v3/api-docs`, `/api-docs`, `/swagger-ui.html`, `/docs/openapi`) and parses the result
- [x] **DISC-02**: System parses OpenAPI 2.0 / 3.0 / 3.1 specs natively (via `@apidevtools/swagger-parser`), extracting every endpoint with full schema
- [x] **DISC-03**: System performs GraphQL introspection against common endpoints (`/graphql`, `/api/graphql`, `/query`) and captures schema when introspection is enabled
- [x] **DISC-04**: System crawls web applications via Katana with XHR/JS/form extraction to surface endpoints invoked by SPAs
- [x] **DISC-05**: System optionally brute-forces routes via Kiterunner (opt-in) using the `routes-large.kite` wordlist
- [x] **DISC-06**: System computes and stores a `specHash` to detect spec drift across executions

### Enrichment (ENRH)

- [x] **ENRH-01**: System probes every discovered endpoint via httpx to capture status, tech-detect, content-type, and TLS info
- [x] **ENRH-02**: System marks `requiresAuth=true` when an endpoint returns 401/403 without credentials
- [x] **ENRH-03**: System optionally discovers hidden parameters via Arjun on selected GET endpoints

### Security Testing (TEST)

- [x] **TEST-01**: System runs Nuclei misconfiguration/exposure/graphql/cors templates without credentials (API8 Misconfiguration + API9 Inventory coverage)
- [x] **TEST-02**: System executes auth-failure tests (JWT `alg: none`, `kid` injection, token reuse, API key leakage in responses) when credentials are provided (API2)
- [x] **TEST-03**: System performs BOLA tests (cross-identity object access) when two or more distinct credentials are supplied (API1)
- [x] **TEST-04**: System performs BFLA tests (admin-level endpoint/method access with a low-privilege credential) (API5)
- [x] **TEST-05**: System performs BOPLA / Mass Assignment tests (injects sensitive property names into PUT/PATCH bodies and inspects reflection) (API3)
- [x] **TEST-06**: System performs Rate-Limit-absence tests (burst N requests, checks 429 / Retry-After presence) — opt-in (API4)
- [x] **TEST-07**: System performs SSRF tests via Nuclei + interactsh on endpoints whose params accept URLs (API7)

### Findings & Threat Integration (FIND)

- [x] **FIND-01**: System persists findings in a dedicated `api_findings` table with OWASP API Top 10 2023 category, severity, evidence, remediation, and risk score
- [ ] **FIND-02**: System sanitizes evidence before persistence — auth headers redacted, response body truncated to 8KB, PII masked (CPF/CNPJ/email/credit-card)
- [ ] **FIND-03**: System promotes high/critical `api_findings` to the existing `threats` table (with dedupe against the same endpoint) so they appear in the executive dashboard
- [ ] **FIND-04**: System emits findings and progress events over WebSocket in real time during journey execution

### Journey Orchestration (JRNY)

- [ ] **JRNY-01**: `journey_type` enum gains `api_security` and jobs of that type route to the API journey executor
- [ ] **JRNY-02**: User must explicitly acknowledge authorization to test ("I have permission to test this API") before a journey starts; acknowledgment is persisted
- [ ] **JRNY-03**: User configures discovery toggles (spec-first, crawler, kiterunner) and testing toggles (misconfigs, auth, BOLA, BFLA, BOPLA, rate-limit, SSRF) via the wizard
- [ ] **JRNY-04**: User can schedule recurring `api_security` journeys via the existing scheduler (no new scheduler code)
- [ ] **JRNY-05**: `POST /api/v1/jobs/{id}/abort` stops all child processes for a running API journey via AbortController

### Safety & Guard-rails (SAFE)

- [ ] **SAFE-01**: Per-endpoint rate cap defaults to 10 req/s, is user-configurable up to an absolute ceiling of 50 req/s the user cannot override
- [ ] **SAFE-02**: Engine respects `Retry-After` headers and applies exponential backoff on 429/503
- [ ] **SAFE-03**: Destructive methods (DELETE / PUT / PATCH against unknown schemas) are disabled by default; enabling requires a checkbox with a red warning + double-confirmation
- [ ] **SAFE-04**: Each journey execution creates an entry in `audit_log` with user, targets, credential IDs (never secrets), timestamp, and outcome
- [ ] **SAFE-05**: Appliance exposes an internal `/healthz/api-test-target` endpoint used by `dryRun` runs to validate the engine without touching real targets
- [ ] **SAFE-06**: Logs are structured JSON and never include request bodies, credentials, or tokens

### UI (UI)

- [ ] **UI-01**: New page `/journeys/api` lists discovered APIs with baseUrl, type, discovery method, endpoint count, last-execution metadata
- [ ] **UI-02**: Drill-down view shows endpoints grouped by path with method badges, auth-required indicator, and known parameters
- [ ] **UI-03**: Findings page supports filtering by `source=api_security` and displays OWASP API Top 10 category badges
- [ ] **UI-04**: Each finding has a "Reproduzir" button that outputs a `curl` command with credential placeholders (never actual secret values)
- [ ] **UI-05**: User can mark a finding as `false_positive`, which is recorded in the audit log
- [ ] **UI-06**: Journey creation wizard (4 steps: Alvos → Autenticação → Configuração → Confirmação) includes the authorization acknowledgment checkbox and an estimated-requests preview

### Infrastructure (INFRA)

- [x] **INFRA-01**: `install.sh` is revised into a safe hard-reset updater — aborts cleanly if the local `main` branch has unpushed commits ahead of origin
- [x] **INFRA-02**: `install.sh` preserves user-owned artifacts between runs: `.planning/`, `docs/`, backups, uploads, `.env`, and any cloud-synced skills directories
- [x] **INFRA-03**: `install.sh` installs pinned versions of Katana, Kiterunner, httpx, and Arjun with SHA-256 verification
- [x] **INFRA-04**: `routes-large.kite` and custom Arjun wordlist (`arjun-extended-pt-en.txt`) are distributed with the release and verified by checksum (no runtime downloads)
- [x] **INFRA-05**: Release tarball flow is bootstrapped so future releases ship a single archive containing the app + binaries + wordlists; `update.sh` is marked legacy/deprecated pending a proper auto-update service (out of scope for v2.0)

## Future (post-v2.0)

Deferred to future release — tracked but not in current roadmap.

### Business Flow Testing (FLOW)

- **FLOW-01**: Automated detection of business-flow abuse (API6) — currently only documented as a manual-testing limitation in the UI

### Auto-Update Service (AUTOUP)

- **AUTOUP-01**: Replace `update.sh` with a proper service-based auto-updater for appliance + auxiliary binaries
- **AUTOUP-02**: Signed update manifests published by release pipeline

### Advanced Visualizations (VIZ)

- **VIZ-01**: Stoplight-style visual API map (resources as a tree colored by finding severity)

## Out of Scope

Explicitly excluded from v2.0. Documented to prevent scope creep.

| Feature | Reason |
|---------|--------|
| Business-flow abuse automation (API6) | Requires manual modeling of per-domain workflows; the platform will document the limitation in the UI rather than pretend to automate it |
| Destructive testing as default | Fail-safe posture — user must explicitly opt-in with double-confirmation |
| Custom auth flows beyond the 7 supported types | SAML, federation, biometric, etc. — out of scope; 7 types cover ≥95% of real-world APIs |
| ZAP / Burp integration | Adds JVM weight and overlaps Nuclei with no proportional gain |
| Commercial tools (Akto SaaS, Salt, StackHawk) | We are building a comparable capability, not integrating with competitors |
| Replacement of `update.sh` with auto-update service | Deferred to a dedicated future milestone (AUTOUP category) |
| `asset_type='api'` enum entry | `apis` uses its own table; no reason to inflate the generic `assets` enum |

## Traceability

Which phases cover which requirements. Populated during roadmap creation 2026-04-17.

| Requirement | Phase | Status |
|-------------|-------|--------|
| INFRA-01 | Phase 8: Infrastructure & Install | Complete |
| INFRA-02 | Phase 8: Infrastructure & Install | Complete |
| INFRA-03 | Phase 8: Infrastructure & Install | Complete |
| INFRA-04 | Phase 8: Infrastructure & Install | Complete |
| INFRA-05 | Phase 8: Infrastructure & Install | Complete |
| HIER-01 | Phase 9: Schema & Asset Hierarchy | Complete |
| HIER-02 | Phase 9: Schema & Asset Hierarchy | Complete |
| HIER-03 | Phase 9: Schema & Asset Hierarchy | Complete |
| HIER-04 | Phase 9: Schema & Asset Hierarchy | Complete |
| FIND-01 | Phase 9: Schema & Asset Hierarchy | Complete |
| CRED-01 | Phase 10: API Credentials | Complete |
| CRED-02 | Phase 10: API Credentials | Complete |
| CRED-03 | Phase 10: API Credentials | Complete |
| CRED-04 | Phase 10: API Credentials | Complete |
| CRED-05 | Phase 10: API Credentials | Complete |
| DISC-01 | Phase 11: Discovery & Enrichment | Complete |
| DISC-02 | Phase 11: Discovery & Enrichment | Complete |
| DISC-03 | Phase 11: Discovery & Enrichment | Complete |
| DISC-04 | Phase 11: Discovery & Enrichment | Complete |
| DISC-05 | Phase 11: Discovery & Enrichment | Complete |
| DISC-06 | Phase 11: Discovery & Enrichment | Complete |
| ENRH-01 | Phase 11: Discovery & Enrichment | Complete |
| ENRH-02 | Phase 11: Discovery & Enrichment | Complete |
| ENRH-03 | Phase 11: Discovery & Enrichment | Complete |
| TEST-01 | Phase 12: Security Testing — Passive | Complete |
| TEST-02 | Phase 12: Security Testing — Passive | Complete |
| TEST-03 | Phase 13: Security Testing — Active | Complete |
| TEST-04 | Phase 13: Security Testing — Active | Complete |
| TEST-05 | Phase 13: Security Testing — Active | Complete |
| TEST-06 | Phase 13: Security Testing — Active | Complete |
| TEST-07 | Phase 13: Security Testing — Active | Complete |
| FIND-02 | Phase 14: Findings Runtime & Threat Integration | Pending |
| FIND-03 | Phase 14: Findings Runtime & Threat Integration | Pending |
| FIND-04 | Phase 14: Findings Runtime & Threat Integration | Pending |
| JRNY-01 | Phase 15: Journey Orchestration & Safety | Pending |
| JRNY-02 | Phase 15: Journey Orchestration & Safety | Pending |
| JRNY-03 | Phase 15: Journey Orchestration & Safety | Pending |
| JRNY-04 | Phase 15: Journey Orchestration & Safety | Pending |
| JRNY-05 | Phase 15: Journey Orchestration & Safety | Pending |
| SAFE-01 | Phase 15: Journey Orchestration & Safety | Pending |
| SAFE-02 | Phase 15: Journey Orchestration & Safety | Pending |
| SAFE-03 | Phase 15: Journey Orchestration & Safety | Pending |
| SAFE-04 | Phase 15: Journey Orchestration & Safety | Pending |
| SAFE-05 | Phase 15: Journey Orchestration & Safety | Pending |
| SAFE-06 | Phase 15: Journey Orchestration & Safety | Pending |
| UI-01 | Phase 16: UI & Final Integration | Pending |
| UI-02 | Phase 16: UI & Final Integration | Pending |
| UI-03 | Phase 16: UI & Final Integration | Pending |
| UI-04 | Phase 16: UI & Final Integration | Pending |
| UI-05 | Phase 16: UI & Final Integration | Pending |
| UI-06 | Phase 16: UI & Final Integration | Pending |

**Coverage:**
- v2.0 requirements: 41 total
- Mapped to phases: 41
- Unmapped: 0

**Per-phase counts:**
- Phase 8 (Infrastructure & Install): 5 (INFRA-01..05)
- Phase 9 (Schema & Asset Hierarchy): 5 (HIER-01..04, FIND-01)
- Phase 10 (API Credentials): 5 (CRED-01..05)
- Phase 11 (Discovery & Enrichment): 9 (DISC-01..06, ENRH-01..03)
- Phase 12 (Security Testing — Passive): 2 (TEST-01, TEST-02)
- Phase 13 (Security Testing — Active): 5 (TEST-03..07)
- Phase 14 (Findings Runtime & Threat Integration): 3 (FIND-02, FIND-03, FIND-04)
- Phase 15 (Journey Orchestration & Safety): 11 (JRNY-01..05, SAFE-01..06)
- Phase 16 (UI & Final Integration): 6 (UI-01..06)

---
*Requirements defined: 2026-04-18*
*Last updated: 2026-04-17 after milestone v2.0 roadmap creation (9 phases, 41/41 mapped)*
