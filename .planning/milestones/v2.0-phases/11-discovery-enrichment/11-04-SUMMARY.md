---
phase: 11-discovery-enrichment
plan: 04
subsystem: api-discovery
tags: [vitest, katana, kiterunner, child_process, spawn, processTracker, jsonl, auth-matrix, mtls, oauth2, tdd]

# Dependency graph
requires:
  - phase: 11-02
    provides: preflightApiBinary('katana'|'kiterunner'), processTracker widened for new binary names
  - phase: 11-01
    provides: katana.test.ts + kiterunner.test.ts Nyquist stubs, fixtures/katana-jsonl.txt + kiterunner-json.txt

provides:
  - "runKatana(target, opts, ctx): Promise<KatanaResult> — spawn-based SPA crawler with 7-branch auth matrix"
  - "runKiterunner(target, opts, ctx): Promise<KiterunnerResult> — spawn-based brute-force scanner with status filtering"
  - "9 real katana tests GREEN (preflight failure, base args, JSONL parse, 7 auth types, abort signal)"
  - "8 real kiterunner tests GREEN (preflight failure, base args, status codes, filtering, rateLimit, abort)"

affects: [11-06-PLAN]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "TDD RED→GREEN: test file written first (module not found = RED), implementation written to pass (GREEN)"
    - "spawn pattern: stdio pipe + processTracker.register + AbortSignal.addEventListener('abort') + SIGTERM/SIGKILL fallback"
    - "JSONL streaming: stdout split by newline, JSON.parse per line, swallow parse errors (partial EOF lines)"
    - "Auth matrix switch: 7 cases including OAuth2 pre-mint via fetch and mTLS tempfile with try/finally cleanup"
    - "SUCCESS_STATUSES as array constant — join(',') at call site produces correct --success-status-codes string"

key-files:
  created:
    - server/services/scanners/api/katana.ts
    - server/services/scanners/api/kiterunner.ts
  modified:
    - server/__tests__/apiDiscovery/katana.test.ts
    - server/__tests__/apiDiscovery/kiterunner.test.ts

key-decisions:
  - "SUCCESS_STATUSES in kiterunner.ts defined as integer array + joined at call site (not hardcoded string literal) — type-safe and used both for arg building and JSONL filter"
  - "katana.ts preflight reason message prefixed with 'katana binary not available:' to match acceptance criteria substring check"
  - "kiterunner.ts -x flag uses opts.rateLimit ?? 5 (not a dedicated QPS concept) — CONTEXT.md clarifies SAFE-01 Phase 15 governs true QPS ceiling"
  - "spawnSync mock in katana tests uses vi.hoisted() alongside spawn mock — required because katana.ts uses both spawn and spawnSync for chromium-browser check"

patterns-established:
  - "Phase 11 scanner pattern: preflightApiBinary check → args build → processTracker.register → AbortSignal listener → close handler resolves Promise"
  - "Test mock pattern: vi.hoisted() for spawn + preflight + processTracker; EventEmitter fake child with setImmediate(close) for sync test flow"

requirements-completed: [DISC-04, DISC-05]

# Metrics
duration: 4min
completed: 2026-04-20
---

# Phase 11 Plan 04: Katana + Kiterunner Scanners Summary

**Katana SPA crawler with 7-branch auth matrix (bearer/basic/api_key_header/oauth2/mtls/api_key_query/hmac) + Kiterunner brute-force with 401/403 as success hits and per-host connection defaults, 17 tests GREEN**

## Performance

- **Duration:** ~4 min
- **Started:** 2026-04-20T00:55:58Z
- **Completed:** 2026-04-20T00:59:48Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- `server/services/scanners/api/katana.ts` (~220 lines) — runKatana with full auth matrix, JSONL streaming, AbortSignal, mTLS tempfile cleanup in try/finally, OAuth2 pre-mint via global fetch
- `server/services/scanners/api/kiterunner.ts` (~155 lines) — runKiterunner with spawn + status filtering + processTracker + AbortSignal
- katana.test.ts converted from 8 it.todo stubs to 9 real assertions (100% behavior coverage)
- kiterunner.test.ts converted from 6 it.todo stubs to 8 real assertions (coverage + extras for rateLimit + status filtering)
- Full suite: 548 tests passing (17 new from this plan), pre-existing actionPlanService DATABASE_URL failure unchanged

## Task Commits

Each task was committed atomically:

1. **Task 1: Create katana.ts with full auth matrix + 9 tests GREEN** - `d71a930` (feat)
2. **Task 2: Create kiterunner.ts + 8 tests GREEN** - `325666c` (feat)

## Files Created/Modified

- `server/services/scanners/api/katana.ts` — runKatana with 7-branch auth matrix, JSONL parse, AbortSignal, processTracker, mTLS tempfile
- `server/services/scanners/api/kiterunner.ts` — runKiterunner with status filtering (SUCCESS_STATUSES), -x/-j defaults, AbortSignal, processTracker
- `server/__tests__/apiDiscovery/katana.test.ts` — 9 real tests replacing 8 it.todo stubs
- `server/__tests__/apiDiscovery/kiterunner.test.ts` — 8 real tests replacing 6 it.todo stubs

## Decisions Made

- `SUCCESS_STATUSES` array constant in kiterunner.ts used both for `--success-status-codes` arg building (`join(',')`) and JSONL post-filter (`Array.includes()`), eliminating duplication
- `katana.ts` uses both `spawn` (katana binary) and `spawnSync` (chromium-browser check) — test mock requires `vi.hoisted()` for both
- kiterunner `-x` semantics preserved as per RESEARCH.md Pitfall 3: connections-per-host, not QPS; Phase 15 SAFE-01 governs true rate ceiling

## Deviations from Plan

None — plan executed exactly as written. The plan specified 14+ tests total; delivered 17 (9 katana + 8 kiterunner). The extra tests cover rateLimit override and status-code filtering explicitly, improving behavior coverage beyond the minimum.

## Issues Encountered

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- Plan 11-06 orchestrator can `import { runKatana } from './scanners/api/katana'` and `import { runKiterunner } from './scanners/api/kiterunner'`
- Both scanners return `{ endpoints: InsertApiEndpoint[]; skipped?: { reason } }` — orchestrator checks skipped for stage-skip logging
- DISC-04 and DISC-05 satisfied at scanner level; orchestrator wiring in Plan 11-06

---
*Phase: 11-discovery-enrichment*
*Completed: 2026-04-20*
