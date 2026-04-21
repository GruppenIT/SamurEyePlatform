# SamurEye Platform — Adversarial Exposure Validation

## What This Is

SamurEye is an Adversarial Exposure Validation platform for medium businesses. It runs automated security journeys (network scanning, AD security assessment, EDR/AV validation, web application testing, **API discovery & security assessment**) using industry tools (nmap, nuclei, PowerShell, smbclient, Katana, Kiterunner, httpx, Arjun) and translates findings into prioritized, actionable remediation plans with contextual scoring, threat grouping, and executive dashboards. API findings are categorized by OWASP API Top 10 (2023) and promoted into the executive dashboard alongside other journey types.

## Core Value

After running a security journey, the user must walk away with a prioritized, contextualized action plan — not a wall of raw findings.

## Current State

**Shipped:** v2.0 (2026-04-21)
**Stack:** TypeScript full-stack (React + Express + PostgreSQL), Drizzle ORM, Radix UI + Tailwind CSS
**Deployment:** Single-port appliance (Express serves API + Vite frontend); offline-capable with pinned binaries
**Test suite:** ~300+ tests; Nyquist test stubs across all phases

### What v2.0 Delivered

- Safe `install.sh` hard-reset updater + offline tarball (124MB, 4 verified binaries + wordlists)
- `apis`, `api_endpoints`, `api_findings` tables under existing `parentAssetId` hierarchy; backfill for existing web_application assets
- Encrypted credential store for 7 API auth types (KEK/DEK reuse), URL-pattern mapping, priority resolution
- Discovery pipeline: spec-first (OpenAPI 2/3/GraphQL introspection) + Katana crawler + opt-in Kiterunner brute-force + httpx enrichment + Arjun parameter discovery
- Full OWASP API Top 10 (2023): Nuclei passive (misconfigs/CORS/JWT) + stateful TypeScript active (BOLA/BFLA/BOPLA/rate-limit/SSRF)
- Sanitized evidence pipeline (PII masking, 8KB truncation, header redaction) + threat promotion to executive dashboard
- Journey orchestration with authorizationAck, rate caps (10–50 req/s), destructive-method gating, audit log, abort, dry-run
- UI: `/journeys/api` page, endpoint drill-down, OWASP badges, curl "Reproduzir", false-positive marking, 4-step wizard

## Requirements

### Validated

- Nmap XML parser with OS detection, service versions, NSE scripts, CVE refs — v1.0
- Nuclei JSONL parser with Zod validation, matcher-name, extracted-results — v1.0
- NormalizedFinding type system across all 4 parsers — v1.0
- Threat grouping with parent/child clusters and journey-specific keys — v1.0
- Contextual scoring with JSONB score breakdown persistence — v1.0
- Projected posture delta per threat — v1.0
- 25 remediation templates with host-specific data interpolation — v1.0
- Remediation lifecycle: mitigate, verify on re-scan, auto-close — v1.0
- Threat detail: problem/impact/fix hierarchy with human-readable evidence — v1.0
- Action plan: prioritized cards with effort/role filters — v1.0
- Executive dashboard: posture score, sparkline, coverage grid, top actions — v1.0
- WebSocket-triggered dashboard refresh on job completion — v1.0
- Journey comparison delta between snapshots — v1.0
- AD PowerShell -Depth 10 for full nested structures (36 ConvertTo-Json calls) — v1.0
- AD parser captures full group membership chains, GPO links, trust attributes — v1.0
- EDR per-host deploymentTimestamp and detectionTimestamp fields (PARS-09) — v1.1
- EDR per-host deployment metadata in queryable database table (PARS-10) — v1.1
- Snapshot files for all 25 threat rules (PARS-11) — v1.1
- Scoring weight distribution validated against real data (THRT-06) — v1.1
- Host criticality multipliers validated (THRT-08) — v1.1
- Exploitability multiplier validated (THRT-09) — v1.1
- edrAvScanner test failures resolved (QUAL-01) — v1.1
- Zero-failure test baseline (QUAL-02) — v1.1
- ✓ Safe `install.sh` hard-reset updater + offline tarball (INFRA-01..05) — v2.0
- ✓ `apis`, `api_endpoints`, `api_findings` schema + backfill (HIER-01..04, FIND-01) — v2.0
- ✓ 7-type API credential store with KEK/DEK + URL-pattern mapping (CRED-01..05) — v2.0
- ✓ Full discovery pipeline: OpenAPI/GraphQL/Katana/Kiterunner/httpx/Arjun (DISC-01..06, ENRH-01..03) — v2.0
- ✓ OWASP API Top 10 passive + active testing (TEST-01..07) — v2.0
- ✓ Sanitized findings + threat promotion + WebSocket events (FIND-02..04) — v2.0
- ✓ Journey orchestration with safety guard-rails + abort (JRNY-01..05, SAFE-01..06) — v2.0
- ✓ API Discovery UI + OWASP findings + wizard 4-steps + curl reproduction (UI-01..06) — v2.0

### Active

(None — next milestone to be defined via `/gsd:new-milestone`)

### Out of Scope

- AI/LLM-generated recommendations — complexity and cost; static contextual templates are sufficient
- Mobile app — web-first, responsive improvements only
- Multi-tenant architecture — single-tenant appliance model stays
- Agent-based scanning — agentless architecture stays
- Network topology graph visualization — high complexity, low actionable value
- Microservices / message queues — monolith is correct architecture
- Business-flow abuse automation (API6) — requires per-domain manual modeling; documented as limitation in UI
- ZAP / Burp integration — overlaps Nuclei with no proportional gain
- Auto-update service — `update.sh` deprecated; proper service deferred (AUTOUP-01/02)
- Stoplight-style API map visualization (VIZ-01) — deferred

## Constraints

- **Stack**: TypeScript full-stack (React/Express/PostgreSQL) — no framework migration
- **Binary tools**: nmap, nuclei, PowerShell, smbclient, Katana, Kiterunner, httpx, Arjun — no tool replacement
- **Deployment**: Single appliance, single port — no microservices
- **UI framework**: Radix UI + Tailwind CSS — no component library migration
- **Backward compatibility**: Existing journey definitions and credentials must continue working
- **Database**: Schema changes must be additive

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Contextual templates over AI/LLM | Cost, latency, reliability for offline appliance | ✓ Good — 25 templates cover all rules |
| Improve parsers, not rewrite | Preserve working functionality, reduce regression risk | ✓ Good — incremental improvement worked |
| Additive schema changes only | Protect existing data, allow rollback | ✓ Good — no data loss |
| Threat grouping at engine level | Single source of truth for count/severity | ✓ Good — consistent across all views |
| Self-referential parentThreatId with lambda | Drizzle circular init workaround | ✓ Good — clean FK relationship |
| Static TS templates over Handlebars | Type safety, compile-time validation | ✓ Good — easy to add new templates |
| Coverage endpoint: 2 queries per journey | Clarity over complex JOIN | ✓ Good — maintainable and fast |
| EDR timestamps via Array.find() on timeline events | Direct extraction, no extra API calls | ✓ Good — reliable for deploy_success/detected events |
| Non-blocking edr_deployments insert | Fire-and-forget after createJobResult | ✓ Good — scan flow never blocked by metadata storage |
| Idempotent migration guard (pg_tables check) | Safe for restarts, no down migration needed | ✓ Good — additive pattern maintained |
| Calibration regression tests in scoringEngine.test.ts | One file for all scoring tests, not fragmented | ✓ Good — hierarchy invariants enforced alongside unit tests |
| LEFT JOIN for EDR deployment read path | Enrich deployment rows with host metadata in one query | ✓ Good — single round-trip, clean separation |
| Inline return type in IStorage for circular import avoidance | Prevents edrDeployments.ts → interface.ts → edrDeployments.ts cycle | ✓ Good — pragmatic TypeScript workaround |
| v2.0 reverses "No new journey types" out-of-scope | APIs are dominant silent attack surface in modern stacks; separate Discovery/credential/test model justifies first-class treatment | ✓ Good — delivered full OWASP API Top 10 coverage |
| `apis` as separate table (not `asset_type='api'`) | Richer attributes don't fit generic `assets`; `parentAssetId` gives hierarchy | ✓ Good — clean model, no enum inflation |
| BOLA/BFLA/BOPLA implemented in-house (TypeScript) | Those vectors require cross-request state; Nuclei is stateless by design | ✓ Good — full stateful test coverage |
| Include auxiliary binaries via release tarball; deprecate `update.sh` | Reproducible deployment + SHA-256 pinning + no runtime downloads | ✓ Good — offline-capable appliance |

---
*Last updated: 2026-04-21 after v2.0 milestone — API Discovery & Security Assessment*
