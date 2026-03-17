# Milestones

## v1.0 — SamurEye Product Revision

**Shipped:** 2026-03-17
**Phases:** 4 | **Plans:** 12
**Timeline:** 2026-03-16 to 2026-03-17
**Files changed:** 553 | **Lines:** ~110K

### Key Accomplishments

1. Rewrote nmap/nuclei parsers with XML output and Zod validation, capturing full OS detection, service versions, NSE scripts, and nuclei evidence
2. Built threat grouping engine consolidating related findings into parent/child clusters with journey-specific grouping keys
3. Implemented contextual scoring engine with weighted formula, score breakdown persistence, and projected posture delta per threat
4. Created 25 remediation templates generating host-specific fix instructions with effort tags and role requirements
5. Redesigned threats page with expandable parent/child grouping, structured detail dialog (Problema/Impacto/Correcao), and human-readable evidence
6. Built action plan page with prioritized remediation cards, filter by effort/role/journey, and score delta visualization
7. Rewrote postura dashboard with score hero + sparkline, journey coverage grid, top 3 actions, WebSocket auto-refresh, and journey comparison delta

### Known Gaps

- PARS-07/08/09: AD/EDR parser depth improvements deferred
- PARS-11: Snapshot test coverage partial
- THRT-06/08/09: Scoring weight calibration not finalized

### UAT Results

- 12 tests: 10 passed, 1 cosmetic issue (fixed), 1 skipped (WebSocket — no live job)

**Archive:** `.planning/milestones/v1.0-ROADMAP.md`, `.planning/milestones/v1.0-REQUIREMENTS.md`
