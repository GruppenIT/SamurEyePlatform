# Requirements: SamurEye v1.1

**Defined:** 2026-03-17
**Core Value:** After running a security journey, the user must walk away with a prioritized, contextualized action plan — not a wall of raw findings.

## v1.1 Requirements

Close known gaps from v1.0 — parser refinements, test coverage, scoring calibration.

### Parsers

- [x] **PARS-09**: EDR findings include explicit deploymentTimestamp and detectionTimestamp fields per host
- [x] **PARS-10**: EDR per-host deployment metadata stored in queryable database table (not buried in JSONB artifacts)
- [ ] **PARS-11**: Snapshot files generated and committed for all 25 threat rule tests

### Scoring

- [ ] **THRT-06**: Scoring component weight distribution (40/25/20/15) validated against real scan data and adjusted if inversions found
- [ ] **THRT-08**: Host type criticality multipliers (domain 1.5, server/firewall/router 1.2) validated against real scan data
- [ ] **THRT-09**: Exploitability multiplier (1.3x for confirmed) validated against real scan data

### Quality

- [ ] **QUAL-01**: edrAvScanner.test.ts 7 pre-existing failures resolved (missing C:\tmp\ directory dependency)
- [ ] **QUAL-02**: All existing test suites pass with zero failures before milestone close

## Validated (from v1.0)

- PARS-07: AD PowerShell scripts use ConvertTo-Json -Depth 10 (verified: 36 occurrences)
- PARS-08: AD parser captures full group membership chains, GPO links, and trust attributes with -Depth 10

## Out of Scope

| Feature | Reason |
|---------|--------|
| New threat rules beyond existing 25 | Focus on coverage and quality of existing rules |
| EDR WMI deployment method | SMB-only is sufficient; WMI adds complexity |
| Real-time scoring recalculation | Batch scoring on scan completion is sufficient |
| ML-based weight optimization | Manual calibration against expert consensus is appropriate for v1.1 |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| PARS-09 | Phase 5 | Complete |
| PARS-10 | Phase 5 | Complete |
| PARS-11 | Phase 6 | Pending |
| THRT-06 | Phase 6 | Pending |
| THRT-08 | Phase 6 | Pending |
| THRT-09 | Phase 6 | Pending |
| QUAL-01 | Phase 6 | Pending |
| QUAL-02 | Phase 6 | Pending |

**Coverage:**
- v1.1 requirements: 8 total
- Mapped to phases: 8
- Unmapped: 0

---
*Requirements defined: 2026-03-17*
*Last updated: 2026-03-17 after roadmap creation*
