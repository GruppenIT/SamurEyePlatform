# Phase 2: Threat Engine Intelligence - Context

**Gathered:** 2026-03-16
**Status:** Ready for planning

<domain>
## Phase Boundary

Related findings are consolidated into grouped threat clusters with contextual severity scoring. After a scan, multiple related findings on the same host/CVE appear as one parent threat with child findings. Every threat carries a computed contextual score stored at persistence time, and each threat group shows a projected score delta for remediation prioritization. No UI changes, no remediation templates — those are Phase 3 and Phase 4.

</domain>

<decisions>
## Implementation Decisions

### Grouping model
- Parent-child hierarchy in the threats table — a new parent threat row is created, child threats link via `parentThreatId`
- Parent severity equals highest severity among children (THRT-03)
- Parent status auto-derived from children: open if any child is open, mitigated if all mitigated, closed if all closed (THRT-04)
- No manual status changes on parent threats — they reflect aggregate child state

### Grouping keys by journey type
- **Attack Surface**: one group per host + SERVICE_CATEGORIES category (admin, database, sharing, web, email, infrastructure). Example: all admin ports (SSH, RDP, VNC, WinRM) on 192.168.1.10 = one "Exposed Administration Services" parent
- **Attack Surface CVE**: one parent per CVE ID across all affected hosts. CVE-2024-1234 on 5 hosts = 1 parent with 5 children
- **AD Security**: group by adCheckCategory + domain (per roadmap THRT-02)
- **EDR/AV**: group by hostId (per roadmap THRT-02)

### Grouping timing
- Post-processing step: all findings processed first as flat child threats (preserving current analyzeWithLifecycle flow), then `groupFindings()` runs to create/update parent threats
- Grouping happens after all findings for a job are processed — enables cross-host CVE grouping since all hosts are known

### Scoring formula
- Contextual score = base severity (40%) × asset criticality (25%) × exposure context (20%) × compensating controls (15%)
- Score scale: 0-100 (100 = no threats, 0 = worst possible)
- **Asset criticality (3-tier mapping)**: Domain Controller = critical (1.5x), Server/Firewall/Router = high (1.2x), Desktop/Workstation = standard (1.0x). Uses existing hostType from host enrichment
- **Confirmed exploitability**: 1.3x multiplier when nmap vuln scripts or nuclei confirm exploitability (THRT-09)
- **Exposure context**: journey type as proxy — Attack Surface = external (1.3x), AD Security = internal (1.0x), EDR/AV = endpoint (0.9x)
- **Compensating controls (v1)**: EDR status as proxy — host passed EICAR test = 0.85x reduction, not tested or failed = 1.0x. V2 adds full network topology awareness (ASCR-01)

### Score persistence
- Score computed and stored at journey completion time (after grouping)
- `contextual_score` (numeric) and `score_breakdown` (JSONB with base, criticality, exposure, controls components) stored on each threat record
- `projected_score_after_fix` computed via subtract-and-recompute: posture_score_current - posture_score_if_this_threat_removed

### Posture snapshots
- One `posture_snapshots` row written per completed job with the overall posture score
- Dashboard reads posture_snapshots for trend sparkline
- Snapshot tied to specific job/journey for audit trail

### Simulate API
- `POST /api/posture/simulate` with body `{ threatIds: ['id1', 'id2'] }` returns projected score if all listed threats are fixed
- Supports multi-threat batch simulation for cumulative remediation impact on action plan

### Claude's Discretion
- Exact grouping key format strings (e.g., `grp:as:host:admin` vs `group:attack_surface:host:admin`)
- Score normalization algorithm (how raw weighted scores map to 0-100 scale)
- posture_snapshots table schema details (columns, indexes)
- Internal helper function decomposition within scoringEngine.ts and groupFindings()
- How to efficiently query EDR test results for compensating controls factor
- Order of operations within the post-processing step

</decisions>

<specifics>
## Specific Ideas

- SERVICE_CATEGORIES map already exists in threatEngine.ts — reuse directly for Attack Surface grouping keys
- Host enrichment already provides hostType and hostFamily — no new data collection needed for criticality scoring
- EDR/AV journey results already track per-host detection status — can be queried for compensating controls factor
- The `analyzeWithLifecycle()` method and upsert flow should remain unchanged — grouping is a separate post-processing layer on top

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `threatEngine.ts` SERVICE_CATEGORIES map: directly maps to grouping key categories for Attack Surface journey
- `threatEngine.ts` computeCorrelationKey(): existing per-journey-type key logic provides the pattern for grouping key computation
- `threatEngine.ts` analyzeWithLifecycle(): current upsert flow preserved as-is; groupFindings() added as post-processing step
- `hostService.ts` host enrichment: provides hostType for asset criticality tier mapping
- `shared/schema.ts` threats table: foundation for additive column migration

### Established Patterns
- Drizzle ORM migrations for schema changes — additive only (project constraint)
- JSONB columns for flexible structured data (evidence column pattern) — reuse for score_breakdown
- Class-based singleton services (ThreatEngineService) — scoringEngine follows same pattern
- Correlation key upsert pattern in storage/threats.ts — extend for grouping key upsert

### Integration Points
- `threatEngine.processJobResults()`: entry point — add groupFindings() and scoring calls after analyzeWithLifecycle()
- `storage/threats.ts`: add upsertParentThreat(), getChildThreats(), updateThreatScore() operations
- `shared/schema.ts`: add new columns to threats table, create posture_snapshots table, create recommendations table
- `server/routes/threats.ts`: extend threat queries to include parent-child relationships
- WebSocket broadcast on job completion: already exists — posture snapshot write hooks into same event

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 02-threat-engine-intelligence*
*Context gathered: 2026-03-16*
