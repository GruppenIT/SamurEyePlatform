# Phase 3: Remediation Engine - Context

**Gathered:** 2026-03-16
**Status:** Ready for planning

<domain>
## Phase Boundary

Every threat group has a specific, actionable remediation that references actual hosts, ports, and service versions found — and users can mark remediations as complete to close the loop. This phase builds the recommendation engine (template functions + persistence) and the lifecycle integration (mitigated → verified/failed). No UI changes — those are Phase 4.

</domain>

<decisions>
## Implementation Decisions

### Template content structure
- Exact commands: copy-paste ready shell/PowerShell commands with interpolated host IP, port, service version
- OS-aware branching: template checks hostFamily from host enrichment — Windows → PowerShell, Linux → bash, unknown → generic guidance
- 1:1 mapping: every threat rule ID gets its own template function (30+ templates in `server/services/remediation-templates/`)
- Each template exports a `generate()` function producing: whatIsWrong, businessImpact, fixSteps[], verificationStep, references[]
- CVE templates: NVD references + static fallback — link to vendor advisory URLs from cveService enrichment data, fix steps are static ("apply vendor patch, verify version")

### Effort & role tagging
- 4-tier effort: minutes, hours, days, weeks — hardcoded per template as constants
- Exposed-service effort varies by SERVICE_CATEGORIES category: admin=minutes, database=hours, sharing=minutes, web=minutes, email=hours, infrastructure=minutes, other=minutes
- 4 roles: sysadmin (infra changes, patching, AD config), developer (web vulns, app misconfig), security (policy, credentials, risk decisions), vendor (firmware, SaaS patches, license-gated)
- Effort and role hardcoded per template — not computed from evidence

### Remediation lifecycle flow
- Use existing 'mitigated' threat status for REMD-06 — no new status needed. Existing processReactivationLogic already handles auto-close (not found) and reactivation (found)
- Phase 3 adds "Mark as mitigated" action on recommendation, which sets threat status to 'mitigated' via existing PATCH /api/threats/:id/status
- Recommendations link to parent threats (one recommendation per group). Ungrouped/standalone threats also get their own recommendation — 100% coverage
- On reactivation: keep existing recommendation, mark status as 'failed' — user sees "fix attempted, threat persists"
- Recommendation status column added: pending → applied → verified | failed (→ reset to pending)

### Generation timing & triggers
- Generates in processJobResults pipeline: findings → threats → grouping → scoring → **recommendations** → posture snapshot
- Upsert on re-scan: update recommendation with fresh evidence if threat still open, keep as historical record if closed. Key: templateId + threatId
- Pipeline only + read API — no manual regeneration endpoint
- API surface: GET /api/threats/:id/recommendation, GET /api/recommendations (with effortTag, roleRequired, journeyType filters), existing PATCH /api/threats/:id/status for mitigation

### Claude's Discretion
- Template file organization and naming within `server/services/remediation-templates/`
- Exact interpolation mechanism for {{host}}, {{port}}, {{service}} variables
- How to aggregate child finding evidence into parent recommendation's hostSpecificData
- Recommendation status sync logic (how threat status changes propagate to recommendation status)
- Storage operations design for recommendations CRUD
- Test strategy for template output validation

</decisions>

<specifics>
## Specific Ideas

- AD scanner already has `recommendation` strings on some findings (e.g., "Stop-Service -Name Spooler -Force") — reuse these as input to AD remediation templates
- cveService already generates `remediation` text and fetches NVD references — feed into cve-detected template
- SERVICE_CATEGORIES map in threatEngine.ts can be reused to parameterize exposed-service templates per category
- Host enrichment provides hostType and hostFamily — no new data collection needed for OS-aware branching
- Recommendation status lifecycle mirrors threat status: when threat transitions, recommendation status should update in the same transaction

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `recommendations` table: already defined in shared/schema.ts (Phase 2) with all needed columns except `status`
- `threatEngine.processJobResults()`: pipeline entry point — add generateRecommendations() call after scoring
- `threatEngine.updateThreatStatus()`: existing status transition with history tracking — hook recommendation status sync here
- `cveService.generateRemediation()`: existing generic CVE remediation text generator — can be extended or replaced per-rule
- `adScanner` recommendation strings: existing per-finding fix guidance in Portuguese
- `SERVICE_CATEGORIES` map: port/service classification for exposed-service template parameterization
- `hostService` host enrichment: provides hostType, hostFamily for OS-aware template branching

### Established Patterns
- Class-based singleton services — recommendationEngine follows same pattern
- JSONB columns for flexible data (evidence, score_breakdown) — hostSpecificData follows same pattern
- Upsert via correlationKey — extend to templateId + threatId for recommendation upsert
- Portuguese error messages and UI text — remediation content in Portuguese

### Integration Points
- `processJobResults()` in threatEngine.ts: add generateRecommendations() after scoreThreats()
- `storage/threats.ts`: extend with recommendation CRUD operations (or new storage/recommendations.ts)
- `routes/threats.ts`: add GET endpoints for recommendations
- `updateThreatStatus()`: sync recommendation status when threat status changes
- WebSocket broadcast: existing job completion event — recommendations available for immediate UI consumption

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 03-remediation-engine*
*Context gathered: 2026-03-16*
