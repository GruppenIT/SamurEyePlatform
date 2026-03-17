# Roadmap: SamurEye Platform Revision

## Overview

The revision deepens the existing scan pipeline in 4 coarse phases that follow a strict data dependency order. Parsers must be stable before the threat engine can group and score correctly. Scoring must be stable before remediation templates can interpolate real host data. Remediation records must exist before the UI can display actionable plans. Each phase completes a coherent capability layer and unblocks the next.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Parser Foundation** - Replace fragile parsers with typed, structured output validated by Zod schemas and protected by snapshot tests
- [x] **Phase 2: Threat Engine Intelligence** - Consolidate findings into grouped threat clusters with contextual severity scoring
- [x] **Phase 3: Remediation Engine** - Generate specific, host-referencing fix instructions and close the remediation lifecycle loop (completed 2026-03-16)
- [x] **Phase 4: User-Facing Surfaces** - Expose the new data model through redesigned findings view, action plan, and executive dashboard (completed 2026-03-16)

## Phase Details

### Phase 1: Parser Foundation
**Goal**: All 4 scanner parsers produce rich, typed, validated output that the threat engine can consume without data loss
**Depends on**: Nothing (first phase)
**Requirements**: PARS-01, PARS-02, PARS-03, PARS-04, PARS-05, PARS-06, PARS-07, PARS-08, PARS-09, PARS-10, PARS-11
**Success Criteria** (what must be TRUE):
  1. An nmap scan result includes OS detection data, full service version details, and complete NSE script output with CVE references — no data truncated
  2. A nuclei scan result preserves matcher name, extracted evidence, and curl command for every finding — not just the severity and template ID
  3. An AD scan result retains full group membership chains, GPO links, and trust attributes as nested structures — not flattened strings
  4. An EDR/AV scan result shows a per-host timeline with deployment timestamp, detection status, and diagnostic detail for each host
  5. All 30+ threat engine rules pass snapshot tests against known parser outputs, confirming the data contract is explicit and regression-safe
**Plans**: 3 plans

Plans:
- [ ] 01-01: nmap parser rewrite — switch invocation to `-oX -` XML output and parse with fast-xml-parser, capturing OS detection, service version details (PARS-01, PARS-03, PARS-04)
- [ ] 01-02: nmap NSE and nuclei parsers — capture full NSE script blocks with CVE refs; validate nuclei JSONL line-by-line with Zod, capturing matcher-name, extracted-results, curl-command (PARS-02, PARS-05, PARS-06)
- [ ] 01-03: AD and EDR parsers + typed interfaces — add `-Depth 10` to PowerShell scripts, capture full AD structures, produce per-host EDR timeline, define NormalizedFinding interfaces and Zod schemas for all 4 parsers, write snapshot tests (PARS-07, PARS-08, PARS-09, PARS-10, PARS-11)

### Phase 2: Threat Engine Intelligence
**Goal**: Related findings are consolidated into grouped threat clusters and every threat carries a contextual severity score stored at persistence time
**Depends on**: Phase 1
**Requirements**: THRT-01, THRT-02, THRT-03, THRT-04, THRT-05, THRT-06, THRT-07, THRT-08, THRT-09, THRT-10
**Success Criteria** (what must be TRUE):
  1. After an Attack Surface scan, multiple open admin ports on the same host appear as one "Exposed Administration Services" threat with child findings — not as separate line items
  2. A threat's severity score reflects whether the host is a domain controller, whether the vulnerability has confirmed exploitability, and the exposure category — not just raw CVSS
  3. The score breakdown (base severity weight, criticality multiplier, exposure factor) is readable on the threat record — not computed fresh on every page load
  4. Each threat carries a projected score delta showing how much the overall posture score improves if that threat is remediated
  5. Existing threat history and correlation keys remain intact after grouping is introduced — previously mitigated threats are not re-opened under new keys
**Plans**: 3 plans

Plans:
- [x] 02-01: Schema migrations — add `threats.contextual_score`, `threats.score_breakdown` (jsonb), `threats.projected_score_after_fix` columns; create `posture_snapshots` table; create `recommendations` table; add indexes (all additive)
- [x] 02-02: Threat grouping engine — extend `threatEngine.ts` with `groupFindings()` method using journey-specific grouping keys; preserve existing correlation key format and stored history (THRT-01, THRT-02, THRT-03, THRT-04, THRT-05)
- [x] 02-03: Contextual scoring engine — implement `scoringEngine.ts` with weighted formula (base 40%, criticality 25%, exposure 20%, controls 15%); persist score_breakdown as JSONB; write posture_snapshots on journey completion; add `/api/posture/simulate` endpoint (THRT-06, THRT-07, THRT-08, THRT-09, THRT-10)

### Phase 3: Remediation Engine
**Goal**: Every threat group has a specific, actionable remediation that references actual hosts, ports, and service versions found — and users can mark remediations as complete to close the loop
**Depends on**: Phase 2
**Requirements**: REMD-01, REMD-02, REMD-03, REMD-04, REMD-05, REMD-06, REMD-07
**Success Criteria** (what must be TRUE):
  1. A remediation for an exposed RDP finding names the actual host IP, port, and Windows version found — not a generic "disable RDP" instruction
  2. Every remediation shows what is wrong (one sentence), the business impact, step-by-step fix commands, a verification step, and an effort estimate with required role
  3. A user can mark a remediation as "mitigated — pending scan confirmation" and see that status reflected in the threat list
  4. After a re-scan where the finding is gone, the threat automatically transitions to "verified closed" — the user does not need to manually close it
**Plans**: 2 plans

Plans:
- [ ] 03-01-PLAN.md — Recommendation engine core: schema migration (status column + unique index), 25 template functions, recommendationEngine singleton, storage CRUD, pipeline integration after scoring (REMD-01, REMD-02, REMD-03, REMD-04, REMD-05)
- [ ] 03-02-PLAN.md — Remediation lifecycle: sync recommendation status on threat status changes (mitigated->applied, closed->verified, reactivated->failed), recommendation API endpoints (REMD-06, REMD-07)

### Phase 4: User-Facing Surfaces
**Goal**: Users can navigate from a dashboard showing their security posture to specific threats, see a clear problem/impact/fix hierarchy, follow a prioritized action plan, and track remediation progress — without encountering raw JSON or an undifferentiated wall of findings
**Depends on**: Phase 3
**Requirements**: UIFN-01, UIFN-02, UIFN-03, UIFN-04, UIAP-01, UIAP-02, UIAP-03, UIAP-04, UIDB-01, UIDB-02, UIDB-03, UIDB-04, UIDB-05, UIDB-06
**Success Criteria** (what must be TRUE):
  1. The threat detail view presents problem, impact, and fix as a clear hierarchy — the user never sees a raw JSON evidence blob or a stdout string
  2. The threat list shows parent threat groups with expandable child findings; each group shows its remediation preview and effort tag at a glance
  3. The post-journey action plan lists remediation actions in priority order with fix preview, effort tag, required role, and projected score delta — and the user can filter by effort or role
  4. The executive dashboard shows a posture score with trend sparkline, the top 3 prioritized actions, journey coverage for all 4 journey types, and a comparison of the current run against the previous run
  5. Dashboard data updates automatically when a journey completes — the user does not need to refresh the page to see new results
**Plans**: 4 plans

Plans:
- [x] 04-01-PLAN.md — Findings redesign: grouped threat list with expandable children, structured detail dialog (problem/impact/fix), human-readable evidence labels, remediation preview per group (UIFN-01, UIFN-02, UIFN-03, UIFN-04)
- [x] 04-02-PLAN.md — Action plan: GET /api/action-plan endpoint, new /action-plan page with prioritized cards, filter by effort/role/journey, sidebar link (UIAP-01, UIAP-02, UIAP-03, UIAP-04)
- [x] 04-03-PLAN.md — Dashboard core: GET /api/posture/coverage endpoint, posture hero with sparkline, journey coverage grid, top 3 actions (UIDB-01, UIDB-02, UIDB-03, UIDB-04)
- [x] 04-04-PLAN.md — Dashboard live updates: WebSocket-triggered cache invalidation, journey comparison delta view (UIDB-05, UIDB-06)

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Parser Foundation | 3/3 | Complete | 2026-03-16 |
| 2. Threat Engine Intelligence | 3/3 | Complete   | 2026-03-16 |
| 3. Remediation Engine | 2/2 | Complete   | 2026-03-16 |
| 4. User-Facing Surfaces | 4/4 | Complete | 2026-03-16 |
