---
phase: 13-security-testing-active
plan: 02
subsystem: testing
tags: [owasp, bola, bfla, bopla, rate-limit, ssrf, nuclei, interactsh, security-scanners]

# Dependency graph
requires:
  - phase: 13-security-testing-active/13-01
    provides: BOPLA_SENSITIVE_KEYS + apiActiveTestOptsSchema + ActiveTestResult in shared/schema.ts
  - phase: 12-security-testing-passive
    provides: API_REMEDIATION_TEMPLATES base (api2/api8/api9) + NucleiFindingSchema camelCase + nucleiApi.ts pattern
  - phase: 10-api-credentials
    provides: ApiCredentialSafe + getApiCredentialWithSecret + listApiCredentials

provides:
  - 5 new entries in API_REMEDIATION_TEMPLATES (api1/api3/api4/api5/api7) pt-BR
  - bola.ts: pairCredentials + harvestObjectIds + testCrossAccess + buildAccessUrl (BOLA / TEST-03 / API1)
  - bfla.ts: identifyLowPrivCreds + matchAdminEndpoint + testPrivEscalation + isUniversalCred (BFLA / TEST-04 / API5)
  - bopla.ts: fetchSeedBody + injectSensitiveKey + verifyReflection + re-exports BOPLA_SENSITIVE_KEYS (BOPLA / TEST-05 / API3)
  - rateLimit.ts: buildBurst + detectThrottling (Rate-Limit / TEST-06 / API4)
  - ssrfNuclei.ts: identifyUrlParams + buildSsrfNucleiArgs + runSsrfNuclei (SSRF / TEST-07 / API7)

affects:
  - 13-security-testing-active/13-03 (orchestrator apiActiveTests.ts imports all 5 scanners)
  - 13-security-testing-active/13-04 (route + CLI + fixtures consume scanner outputs)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - In-house TypeScript scanners using native fetch (no external deps) — BOLA/BFLA/BOPLA/RateLimit
    - Nuclei wrapper adapted for interactsh-enabled SSRF (no -ni flag, +interactions-* flags)
    - C(n,2) pair generation without mirroring for BOLA credential pairs
    - Key-path deep compare (not regex) for BOPLA reflection detection
    - ALL-3-signals detection for rate-limit absence (429 + Retry-After + X-RateLimit-*)
    - 3-heuristic OR identification for URL-like params (name regex + type/format + example URL parse)
    - mask-at-source for IDs and URLs (prefix-3 + ***)

key-files:
  created:
    - server/services/scanners/api/bola.ts
    - server/services/scanners/api/bfla.ts
    - server/services/scanners/api/bopla.ts
    - server/services/scanners/api/rateLimit.ts
    - server/services/scanners/api/ssrfNuclei.ts
  modified:
    - shared/apiRemediationTemplates.ts

key-decisions:
  - "bola.ts: pairCredentials uses slice+nested loop for C(n,2) without mirroring; /^(id|uuid|pk)$/i regex for ID harvest; isListLikePath uses regex test (no stateful lastIndex) via !/\\{\\w+\\}/.test()"
  - "bfla.ts: testPrivEscalation treats 3xx as rejected (redirect-to-login); allCredResults optional for severity contrast"
  - "bopla.ts: resolveInjectedValue infers type from seed body (boolean→true, string→admin, array→['admin']); verifyReflection uses key-path exact compare not regex"
  - "rateLimit.ts: detectThrottling breaks early on 429 detection (optimization); successRate < 0.9 → no finding (endpoint unhealthy)"
  - "ssrfNuclei.ts: interaction=true and interactsh-interaction-type read from raw parsed JSON before NucleiFindingSchema.strip() — schema strips unknown fields; finding criterion includes extracted-results interactsh URL check"
  - "ssrfNuclei.ts: NO '-ni' flag anywhere in args — interactsh MUST be active for SSRF OOB detection; all 3 occurrences of '-ni' string are in comments only"
  - "API_REMEDIATION_TEMPLATES: 5 new entries added inline in existing object — no new file, no type change (typeof inference auto-extends)"

patterns-established:
  - "Pattern 1: Scanner returns typed Hit interface (BolaHit/BflaHit/BoplaHit/RateLimitHit/SsrfHit) — null when no finding. Orchestrator (Wave 2) calls scanner and persists via upsertApiFindingByKey."
  - "Pattern 2: SAFE-06 mask-at-source applied in all scanners: object IDs in BOLA, auth patterns in BFLA/BOPLA, interactsh URLs in SSRF."
  - "Pattern 3: Each scanner self-contained with createLogger + direct imports from @shared. No circular deps."

requirements-completed:
  - TEST-03
  - TEST-04
  - TEST-05
  - TEST-06
  - TEST-07

# Metrics
duration: 6min
completed: 2026-04-20
---

# Phase 13 Plan 02: Security Testing Active — Scanners

**5 OWASP API Top 10 scanner functions (BOLA/BFLA/BOPLA/RateLimit/SSRF) + 5 pt-BR remediation templates; Wave 1 implementation ready for Wave 2 orchestrator composition**

## Performance

- **Duration:** 6 min
- **Started:** 2026-04-20T16:52:26Z
- **Completed:** 2026-04-20T16:58:36Z
- **Tasks:** 5
- **Files modified:** 6

## Accomplishments

- Extended `API_REMEDIATION_TEMPLATES` with 5 Phase 13 entries (api1/api3/api4/api5/api7) preserving all Phase 12 entries
- Implemented 4 in-house TypeScript scanners using native fetch: BOLA (pairCredentials+harvestObjectIds+testCrossAccess), BFLA (identifyLowPrivCreds+matchAdminEndpoint+testPrivEscalation), BOPLA (fetchSeedBody+injectSensitiveKey+verifyReflection), RateLimit (buildBurst+detectThrottling)
- Implemented SSRF Nuclei wrapper (ssrfNuclei.ts) with interactsh enabled (no -ni), 3 OOB polling flags, 3-heuristic URL-like param detection
- Zero new npm dependencies — native fetch + child_process + existing Nuclei binary

## Task Commits

1. **Task 1: API_REMEDIATION_TEMPLATES extension** - `1916f67` (feat)
2. **Task 2: bola.ts BOLA scanner** - `e076072` (feat)
3. **Task 3: bfla.ts BFLA scanner** - `fa79370` (feat)
4. **Task 4: bopla.ts + rateLimit.ts** - `a2e0adc` (feat)
5. **Task 5: ssrfNuclei.ts SSRF scanner** - `0e98384` (feat)

## Files Created/Modified

- `shared/apiRemediationTemplates.ts` — Extended with api1/api3/api4/api5/api7 pt-BR remediation strings
- `server/services/scanners/api/bola.ts` — C(n,2) cred pairing, JSON ID harvest, cross-access GET test (TEST-03)
- `server/services/scanners/api/bfla.ts` — 3-signal low-priv identification, admin path regex, privilege escalation test (TEST-04)
- `server/services/scanners/api/bopla.ts` — Seed GET, key injection, reflection deep-compare (TEST-05)
- `server/services/scanners/api/rateLimit.ts` — Promise.all burst, ALL-3-signals throttling detection (TEST-06)
- `server/services/scanners/api/ssrfNuclei.ts` — URL-like param filter, Nuclei SSRF with interactsh OOB (TEST-07)

## Decisions Made

- bola.ts uses `/\{\w+\}/.test()` (non-stateful) instead of `/\{(\w+)\}/g` with lastIndex — avoids stateful global regex bugs in `isListLikePath`
- ssrfNuclei.ts reads `interaction=true` and `interactsh-interaction-type` from raw JSON (before NucleiFindingSchema.strip()); uses camelCase `matchedAt` from Zod-parsed output
- bopla.ts re-exports `BOPLA_SENSITIVE_KEYS` so orchestrator can import from one place
- bfla.ts treats HTTP 3xx as rejected (not just `Location: /login` check) — simpler and conservative
- rateLimit.ts `detectThrottling` breaks loop early on 429 detection for efficiency

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] ssrfNuclei.ts: plan code used kebab-case field access on Zod-parsed output**
- **Found during:** Task 5 (ssrfNuclei.ts implementation)
- **Issue:** Plan's `mapSsrfFinding` example used `finding['matched-at']` and `finding['template-id']` — but `NucleiFindingSchema` uses `.strip()` which removes unknown fields, and defines camelCase `matchedAt`/`templateId` (Phase 12 STATE.md decision explicitly states this)
- **Fix:** Used `safe.data.matchedAt` for camelCase fields, accessed `rawParsed['interactsh-interaction-type']` from pre-schema raw JSON object for fields stripped by schema
- **Files modified:** server/services/scanners/api/ssrfNuclei.ts
- **Verification:** `npx tsc --noEmit` passes clean
- **Committed in:** `0e98384` (Task 5 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 — bug in plan's example code)
**Impact on plan:** Required correction for TypeScript type safety. No scope creep.

## Issues Encountered

None beyond the camelCase fix above.

## Next Phase Readiness

- All 5 scanners ready for Wave 2 orchestrator (13-03) to compose into `runApiActiveTests()`
- Wave 0 test stubs (139 `it.todo`) in `server/__tests__/apiActive/` are the verification targets for Waves 1-3
- ssrfNuclei.ts requires `preflightNuclei()` to pass before spawn — same as Phase 12 nucleiApi.ts pattern

---
*Phase: 13-security-testing-active*
*Completed: 2026-04-20*
