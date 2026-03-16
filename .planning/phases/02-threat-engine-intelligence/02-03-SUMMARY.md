---
phase: 02-threat-engine-intelligence
plan: "03"
subsystem: scoring-engine
tags: [scoring, posture, simulation, risk, contextual-score]
dependency_graph:
  requires: [02-01, 02-02]
  provides: [contextual-scoring, posture-snapshots, simulate-api]
  affects: [server/services/threatEngine.ts, server/routes/dashboard.ts]
tech_stack:
  added: []
  patterns: [weighted-scoring-formula, singleton-service, tdd]
key_files:
  created:
    - server/services/scoringEngine.ts
    - server/storage/posture.ts
    - server/__tests__/scoringEngine.test.ts
  modified:
    - server/services/threatEngine.ts
    - server/routes/dashboard.ts
    - server/storage/threats.ts
decisions:
  - "rawScore used for criticality comparison in tests (not normalizedScore) — both clamped to 100 for critical+attack_surface threats"
  - "getThreats() extended with jobId+category filters to support scoring engine scoping"
  - "edrAvScanner.test.ts failures confirmed pre-existing (C:/tmp missing on host) — out of scope"
metrics:
  duration_seconds: 11977
  completed_date: "2026-03-16"
  tasks_completed: 2
  files_changed: 6
---

# Phase 2 Plan 3: Contextual Scoring Engine Summary

Implements weighted contextual scoring that transforms raw severity into a risk-adjusted score reflecting asset criticality, exposure context, and compensating controls — enabling prioritization by actual impact rather than raw CVSS.

## What Was Built

**ScoringEngineService** (`server/services/scoringEngine.ts`) — singleton with five methods:

- `computeContextualScore(threat, host, journeyType, edrStatus)` — pure function returning `ScoreBreakdownRecord` with all 7 fields. Formula: `(base*0.40 + base*criticality*0.25 + base*exposure*0.20 + base*controls*0.15) * exploitability`, clamped 0–100.
- `scoreAllThreatsForJob(jobId)` — queries job threats, resolves host + EDR status, persists `contextualScore` and `scoreBreakdown` via `updateThreat()`.
- `computeProjectedScores(jobId)` — for each parent threat: computes `projectedScoreAfterFix` = posture delta when removing parent+children.
- `computePostureFromThreats(threats)` — overall posture from open threats; returns 100 when none.
- `writePostureSnapshot(jobId, journeyId)` — counts severity distribution, writes to `posture_snapshots` table.

**Posture storage** (`server/storage/posture.ts`): `writePostureSnapshot`, `getPostureHistory`, `getLatestPostureSnapshot`.

**Pipeline integration** (`server/services/threatEngine.ts`): scoring pipeline wired after `groupFindings` in `processJobResults`. Full order: `analyzeWithLifecycle → runJourneyPostProcessing → groupFindings → scoreAllThreatsForJob → computeProjectedScores → writePostureSnapshot`.

**API endpoints** (`server/routes/dashboard.ts`):
- `POST /api/posture/simulate` — accepts `threatIds[]`, returns `{currentScore, projectedScore, delta, threatsRemoved}`.
- `GET /api/posture/history` — returns posture snapshot time series, optional `journeyId` + `limit` query params.

**Filter extension** (`server/storage/threats.ts`): added `jobId` and `category` filters to `getThreats()` — required for job-scoped scoring and EDR status resolution.

## Multiplier Table

| Factor | Values |
|--------|--------|
| Severity base | critical=100, high=75, medium=50, low=25 |
| Host criticality | domain=1.5x, server/firewall/router=1.2x, desktop/switch/other=1.0x |
| Journey exposure | attack_surface=1.3, web_application=1.2, ad_security=1.0, edr_av=0.9 |
| EDR controls | passed=0.85, unknown=1.0 |
| Exploitability | nmap_vuln source or nuclei confirmation=1.3x, else=1.0x |

## Tests

24 tests in `server/__tests__/scoringEngine.test.ts` covering THRT-06 through THRT-10:
- All 4 severity base weights
- All host criticality multipliers (domain/server/firewall/router/desktop/switch/other + no-host)
- All 4 journey exposure factors
- EDR controls reduction (passed vs unknown)
- Exploitability multiplier (nmap_vuln, nuclei evidence, standard)
- All 7 scoreBreakdown fields present
- normalizedScore clamped 0–100
- computePostureFromThreats: empty=100, open-only, closed-ignored, clamp, projected improvement
- Singleton export
- scoreAllThreatsForJob with mocked DB

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Test assertion used normalizedScore for DC vs desktop comparison**
- **Found during:** Task 1, GREEN phase
- **Issue:** Critical+attack_surface threats on both DC and desktop produce rawScore > 100, both clamp to normalizedScore=100. The test `expect(dcNormalized).toBeGreaterThan(desktopNormalized)` always fails.
- **Fix:** Changed assertion to compare `rawScore` (pre-clamp) which correctly reflects the 1.5x vs 1.0x criticalityMultiplier difference.
- **Files modified:** server/__tests__/scoringEngine.test.ts
- **Commit:** 47c2093

**2. [Rule 2 - Missing functionality] getThreats() lacked jobId and category filters**
- **Found during:** Task 2 implementation
- **Issue:** scoringEngine calls `getThreats({ jobId })` to scope threats to a job, and `getThreats({ category: 'edr_av' })` for EDR status lookup. Neither filter existed.
- **Fix:** Extended getThreats() signature and Drizzle query conditions to support both filters.
- **Files modified:** server/storage/threats.ts
- **Commit:** 74e8b4c

## Self-Check: PASSED
