---
phase: 03-remediation-engine
plan: "01"
subsystem: recommendations
tags: [typescript, drizzle-orm, postgres, vitest, recommendations, templates]

# Dependency graph
requires:
  - phase: 02-threat-engine-intelligence
    provides: threats table with groupingKey/parentThreatId, scoring pipeline in processJobResults, recommendations table schema (no status col)

provides:
  - 25 remediation template functions covering all threat rule IDs
  - templateMap dispatch index (ruleId -> TemplateGenerator)
  - RecommendationEngine singleton with generateForJob() and syncRecommendationStatus()
  - storage/recommendations.ts CRUD (upsertRecommendation, getRecommendationByThreatId, getRecommendations)
  - Pipeline integration: generateForJob called after computeProjectedScores in processJobResults
  - status column on recommendations table + UQ_recommendations_threat_id unique index

affects:
  - 04-ui (recommendation display, mitigation actions, effort/role filters)
  - future threat routes (GET /api/threats/:id/recommendation)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Static TypeScript template functions per rule ID (not Handlebars — type safety)
    - Class-based singleton RecommendationEngine (matches scoringEngine pattern)
    - Drizzle onConflictDoUpdate on threat_id unique index for upsert
    - Evidence fallback chain: parent evidence merged with first child evidence for parent threats

key-files:
  created:
    - server/services/remediation-templates/types.ts
    - server/services/remediation-templates/index.ts
    - server/services/remediation-templates/exposed-service.ts
    - server/services/remediation-templates/cve-detected.ts
    - server/services/remediation-templates/nuclei-vulnerability.ts
    - server/services/remediation-templates/web-vulnerability.ts
    - server/services/remediation-templates/edr-av-failure.ts
    - server/services/remediation-templates/ad-security-generic.ts
    - server/services/remediation-templates/ad-users-password-never-expires.ts
    - server/services/remediation-templates/ad-domain-controller-not-found.ts
    - server/services/remediation-templates/ad-inactive-users.ts
    - server/services/remediation-templates/ad-users-old-passwords.ts
    - server/services/remediation-templates/ad-privileged-group-members.ts
    - server/services/remediation-templates/ad-obsolete-os.ts
    - server/services/remediation-templates/ad-inactive-computers.ts
    - server/services/remediation-templates/ad-weak-password-policy.ts
    - server/services/remediation-templates/domain-admin-critical-password-expired.ts
    - server/services/remediation-templates/specific-inactive-user.ts
    - server/services/remediation-templates/privileged-group-too-many-members.ts
    - server/services/remediation-templates/password-complexity-disabled.ts
    - server/services/remediation-templates/password-history-insufficient.ts
    - server/services/remediation-templates/passwords-never-expire.ts
    - server/services/remediation-templates/inactive-computer-detected.ts
    - server/services/remediation-templates/obsolete-operating-system.ts
    - server/services/remediation-templates/bidirectional-trust-detected.ts
    - server/services/remediation-templates/domain-admin-old-password.ts
    - server/services/remediation-templates/password-never-expires.ts
    - server/services/recommendationEngine.ts
    - server/storage/recommendations.ts
    - server/__tests__/recommendationEngine.test.ts
  modified:
    - shared/schema.ts
    - server/storage/database-init.ts
    - server/services/threatEngine.ts

key-decisions:
  - "Static TypeScript template functions per rule ID chosen over Handlebars for type safety and compile-time validation"
  - "Upsert keyed on threatId (unique) — templateId stored as audit trail, not uniqueness key"
  - "Parent-only generation: filter parentThreatId IS NULL to avoid one-recommendation-per-child explosion"
  - "Evidence fallback: merge first child evidence into parent evidence when parent evidence lacks host/port"
  - "ruleId column added additively to threats table — nullable, bootstrapped in database-init.ts"
  - "Status sync: mitigated->applied, closed->verified, open->failed; other statuses are no-ops"

patterns-established:
  - "Template shape: every template file exports generate(ctx: RecommendationContext): GeneratedRecommendation"
  - "OS-aware branching inside templates via ctx.hostFamily (linux/windows_server/windows_desktop)"
  - "Evidence fallback: parent threat merges first child evidence when evidence.host is missing"
  - "RecommendationEngine follows class-based singleton pattern (same as scoringEngine)"

requirements-completed: [REMD-01, REMD-02, REMD-03, REMD-04, REMD-05]

# Metrics
duration: 9min
completed: 2026-03-16
---

# Phase 3 Plan 01: Recommendation Engine Core Summary

**25 static remediation templates with host interpolation, RecommendationEngine singleton with pipeline integration, and recommendation persistence via upsert-keyed-on-threatId**

## Performance

- **Duration:** ~9 min
- **Started:** 2026-03-16T22:28:36Z
- **Completed:** 2026-03-16T22:37:44Z
- **Tasks:** 2
- **Files modified:** 32

## Accomplishments

- Built 25 remediation template functions covering every threat rule ID — each produces whatIsWrong, businessImpact, fixSteps[], verificationStep, references[], effortTag, roleRequired, hostSpecificData in Portuguese
- Created RecommendationEngine singleton that dispatches to templates, upserts recommendations per parent/standalone threat, and syncs recommendation status with threat lifecycle transitions
- Wired generateForJob() into processJobResults pipeline after computeProjectedScores, before writePostureSnapshot
- All 21 unit tests pass

## Task Commits

1. **Task 1: Schema migration, types, storage, and template scaffold** - `c1aee90` (feat)
2. **Task 2: RecommendationEngine service and pipeline integration** - `6000d76` (feat)

## Files Created/Modified

- `shared/schema.ts` - Added status column and UQ_recommendations_threat_id unique index; added ruleId column to threats
- `server/storage/database-init.ts` - Bootstrap migrations for recommendations unique index, status column, threats.rule_id
- `server/services/remediation-templates/types.ts` - Shared types: RecommendationContext, GeneratedRecommendation, EffortTag, RoleRequired, TemplateGenerator
- `server/services/remediation-templates/index.ts` - templateMap dispatch (25 entries) and getTemplate()
- `server/services/remediation-templates/*.ts` - 25 template files
- `server/services/recommendationEngine.ts` - RecommendationEngine class singleton
- `server/storage/recommendations.ts` - upsertRecommendation, getRecommendationByThreatId, getRecommendations
- `server/services/threatEngine.ts` - Pipeline integration (import + generateForJob call)
- `server/__tests__/recommendationEngine.test.ts` - 21 unit tests

## Decisions Made

- Static TypeScript template functions chosen over Handlebars/Mustache: type safety prevents missing interpolation slots at compile time
- Upsert keyed on threatId (not templateId+threatId): one recommendation per threat; templateId is audit metadata
- Parent-only generation: filter `parentThreatId IS NULL` to avoid one-recommendation-per-child explosion (per research pitfall #2)
- ruleId column added additively to threats — enables cleaner template dispatch vs. relying solely on category
- Evidence fallback: parent threat merges first child's evidence when parent evidence lacks host/port (per research pitfall #3)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed edr-av-failure.ts array push/filter chaining error**
- **Found during:** Task 1 test run
- **Issue:** `fixSteps.push(...).filter(Boolean)` — Array.push() returns a number, not the array; `.filter()` call throws TypeError
- **Fix:** Extracted items into `additionalSteps` array with `.filter(Boolean)`, then pushed into `fixSteps`
- **Files modified:** server/services/remediation-templates/edr-av-failure.ts
- **Verification:** All 21 tests pass after fix
- **Committed in:** c1aee90 (Task 1 commit)

**2. [Rule 2 - Auto-fix] Added ruleId column to threats table (linter pre-created)**
- **Found during:** Task 2 implementation
- **Issue:** recommendationEngine uses `threat.ruleId` for template dispatch, but threats table had no ruleId column
- **Fix:** Linter added ruleId text column to schema.ts and database-init.ts bootstrap; column is nullable/additive
- **Files modified:** shared/schema.ts, server/storage/database-init.ts
- **Verification:** TypeScript compiles cleanly for recommendation-related files
- **Committed in:** 6000d76 (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (1 bug, 1 missing critical column)
**Impact on plan:** Both auto-fixes necessary for correctness. No scope creep.

## Issues Encountered

None — plan executed smoothly. Pre-existing TypeScript errors in client/ and threatEngine.ts (logger overloads) are unrelated to this plan's scope.

## Next Phase Readiness

- All 25 templates operational with pipeline integration
- Recommendations will be generated automatically on next job execution
- Phase 4 UI can query recommendations via storage/recommendations.ts operations
- GET /api/threats/:id/recommendation and GET /api/recommendations endpoints still needed (Phase 4 scope)
- syncRecommendationStatus should be called from threat status route handler for full lifecycle sync (Phase 4 scope)

---
*Phase: 03-remediation-engine*
*Completed: 2026-03-16*
