# Requirements: SamurEye Product Revision

**Defined:** 2026-03-16
**Core Value:** After running a security journey, the user must walk away with a prioritized, contextualized action plan — not a wall of raw findings.

## v1 Requirements

Requirements for the product revision. Each maps to roadmap phases.

### Parsing

- [x] **PARS-01**: nmap parser uses XML output (`-oX -`) via fast-xml-parser instead of regex text parsing
- [x] **PARS-02**: nmap parser captures full NSE script output blocks with CVE references and vuln details
- [x] **PARS-03**: nmap parser captures OS detection data (name, accuracy, CPE strings)
- [x] **PARS-04**: nmap parser captures service version details (product, version, extrainfo, CPE)
- [x] **PARS-05**: nuclei parser validates each JSONL line against a Zod schema at parse boundary
- [x] **PARS-06**: nuclei parser captures matcher-name, extracted-results, curl-command, and template tags
- [ ] **PARS-07**: AD PowerShell scripts use ConvertTo-Json -Depth 10 to preserve nested structures
- [ ] **PARS-08**: AD parser captures full group membership chains, GPO links, and trust attributes
- [ ] **PARS-09**: EDR/AV parser produces per-host timeline with deployment timestamp, detection status, and diagnostic detail
- [x] **PARS-10**: All 4 parsers output typed `NormalizedFinding` interfaces validated by Zod schemas
- [ ] **PARS-11**: Snapshot tests exist for all 30+ threat engine rules against known parser outputs before any refactor

### Threat Engine

- [x] **THRT-01**: Related findings on the same host are consolidated into parent threat groups (e.g., 3 open admin ports = 1 "Exposed Administration Services" threat)
- [x] **THRT-02**: Grouping keys vary by journey type: host+serviceFamily (Attack Surface), cveId (multi-host CVE), adCheckCategory (AD), hostId (EDR)
- [x] **THRT-03**: Parent threat severity equals highest severity among child findings
- [x] **THRT-04**: Parent threat status is open if any child finding is open
- [x] **THRT-05**: Existing correlation key format and stored threat history are preserved (grouping does not break existing data)
- [ ] **THRT-06**: Contextual severity scoring weights base severity (40%), asset criticality (25%), exposure context (20%), compensating controls (15%)
- [x] **THRT-07**: Score breakdown is stored as JSONB at persistence time (not computed at display time)
- [ ] **THRT-08**: Host type (DC, server, workstation) factors into asset criticality multiplier
- [ ] **THRT-09**: Confirmed exploitability (nmap vuln script hit, nuclei match) increases score via multiplier
- [x] **THRT-10**: Each threat group has a projected score impact ("fixing this improves posture score by X")

### Remediation

- [x] **REMD-01**: Each of the 30+ threat rules has a static remediation template with host-specific commands/configs
- [x] **REMD-02**: Templates reference actual host, port, service, and version data from the finding evidence
- [x] **REMD-03**: Each remediation includes: what is wrong (1 sentence), business impact, fix steps, verification step, references
- [x] **REMD-04**: Each remediation has an effort tag (minutes, hours, days, weeks) and required role (sysadmin, developer, vendor, security)
- [x] **REMD-05**: Recommendations are persisted in a dedicated `recommendations` table linked to threats
- [x] **REMD-06**: User can mark a remediation as "mitigated — pending scan confirmation"
- [x] **REMD-07**: Re-scan automatically confirms closure when correlation key is absent in new results

### UI — Findings

- [ ] **UIFN-01**: Threat detail view shows problem → impact → fix hierarchy instead of raw JSON evidence
- [ ] **UIFN-02**: Evidence is human-readable: parsed data with labels, not stdout strings or JSON blobs
- [ ] **UIFN-03**: Threat list shows grouped parent threats with expandable child findings
- [ ] **UIFN-04**: Each threat group shows its remediation preview (first fix step + effort tag)

### UI — Action Plan

- [ ] **UIAP-01**: Post-journey view shows prioritized remediation actions ordered by contextual score
- [ ] **UIAP-02**: Each action shows: threat summary, fix preview, effort tag, required role, projected score delta
- [ ] **UIAP-03**: User can filter actions by effort level, role, or journey type
- [ ] **UIAP-04**: Action plan connects to threat detail for full remediation steps

### UI — Dashboard

- [x] **UIDB-01**: Posture hero shows score + delta arrow (vs last run) + date-labeled trend sparkline
- [x] **UIDB-02**: Posture score history is reliably populated on every journey completion via posture_snapshots table
- [x] **UIDB-03**: Dashboard shows top 3 prioritized remediation actions with fix preview and projected impact
- [x] **UIDB-04**: Journey coverage grid shows 4 journey types with last-run date and pass/fail indicator
- [ ] **UIDB-05**: Dashboard data refreshes via WebSocket-triggered React Query cache invalidation on job completion
- [ ] **UIDB-06**: Journey comparison view shows delta between current and previous run (new failures, resolved items)

## v2 Requirements

Deferred to future release. Tracked but not in current roadmap.

### Advanced Scoring

- **ASCR-01**: Compensating control detection (network topology awareness — VPN, firewall rule context)
- **ASCR-02**: Scoring multiplier calibration tool using real scan data distribution analysis

### Reporting

- **REPT-01**: PDF export of executive summary and action plan
- **REPT-02**: Compliance tags per threat (ISO 27001, PCI-DSS references as metadata)
- **REPT-03**: Compliance report builder with framework mapping

### Integration

- **INTG-01**: Ticket system integration (Jira, ServiceNow) for remediation handoff

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature | Reason |
|---------|--------|
| AI/LLM-generated remediation | Cost, latency, hallucination risk, offline appliance constraint; static templates sufficient |
| New journey types | Existing 4 need depth, not breadth |
| Mobile app | Web-first, responsive improvements only |
| Multi-tenant architecture | Single-tenant appliance model stays |
| Agent-based scanning | Agentless architecture stays (nmap, nuclei, WinRM, SMB) |
| Network topology graph visualization | High complexity, low actionable value for sysadmins |
| Real-time streaming scan output to UI | Current progress bar is sufficient; full output in job results |
| Microservices / message queues | Monolith is correct architecture for this product |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| PARS-01 | Phase 1 | Complete |
| PARS-02 | Phase 1 | Complete |
| PARS-03 | Phase 1 | Complete |
| PARS-04 | Phase 1 | Complete |
| PARS-05 | Phase 1 | Complete |
| PARS-06 | Phase 1 | Complete |
| PARS-07 | Phase 1 | Pending |
| PARS-08 | Phase 1 | Pending |
| PARS-09 | Phase 1 | Pending |
| PARS-10 | Phase 1 | Complete |
| PARS-11 | Phase 1 | Pending |
| THRT-01 | Phase 2 | Complete |
| THRT-02 | Phase 2 | Complete |
| THRT-03 | Phase 2 | Complete |
| THRT-04 | Phase 2 | Complete |
| THRT-05 | Phase 2 | Complete |
| THRT-06 | Phase 2 | Pending |
| THRT-07 | Phase 2 | Complete |
| THRT-08 | Phase 2 | Pending |
| THRT-09 | Phase 2 | Pending |
| THRT-10 | Phase 2 | Complete |
| REMD-01 | Phase 3 | Complete |
| REMD-02 | Phase 3 | Complete |
| REMD-03 | Phase 3 | Complete |
| REMD-04 | Phase 3 | Complete |
| REMD-05 | Phase 3 | Complete |
| REMD-06 | Phase 3 | Complete |
| REMD-07 | Phase 3 | Complete |
| UIFN-01 | Phase 4 | Pending |
| UIFN-02 | Phase 4 | Pending |
| UIFN-03 | Phase 4 | Pending |
| UIFN-04 | Phase 4 | Pending |
| UIAP-01 | Phase 4 | Pending |
| UIAP-02 | Phase 4 | Pending |
| UIAP-03 | Phase 4 | Pending |
| UIAP-04 | Phase 4 | Pending |
| UIDB-01 | Phase 4 | Complete |
| UIDB-02 | Phase 4 | Complete |
| UIDB-03 | Phase 4 | Complete |
| UIDB-04 | Phase 4 | Complete |
| UIDB-05 | Phase 4 | Pending |
| UIDB-06 | Phase 4 | Pending |

**Coverage:**
- v1 requirements: 42 total
- Mapped to phases: 42
- Unmapped: 0

---
*Requirements defined: 2026-03-16*
*Last updated: 2026-03-16 after roadmap creation*
