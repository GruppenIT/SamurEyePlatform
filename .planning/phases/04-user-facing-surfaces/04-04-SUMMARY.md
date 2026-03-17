---
phase: 04-user-facing-surfaces
plan: "04"
subsystem: ui
tags: [react, websocket, tanstack-query, lucide-react, date-fns]

# Dependency graph
requires:
  - phase: 04-03
    provides: JourneyCoverage component, postura page foundation with PostureHero/TopActions
  - phase: 02-threat-engine-intelligence
    provides: postureSnapshots table with score/openThreatCount/criticalCount/highCount/scoredAt
provides:
  - WebSocket-triggered React Query cache invalidation on terminal job statuses in postura.tsx
  - JourneyComparison component showing aggregate score and threat count delta between two most recent runs
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "WebSocket lastMessage effect pattern: useEffect on lastMessage, filter by type+status, invalidateQueries"
    - "Terminal-only invalidation: completed/failed/timeout — not running/pending"
    - "Snapshot delta component: useQuery limit=2, compute deltas, color-coded with ArrowUpRight/ArrowDownRight/Minus"

key-files:
  created:
    - client/src/components/dashboard/journey-comparison.tsx
  modified:
    - client/src/pages/postura.tsx

key-decisions:
  - "WebSocket invalidation only on terminal job statuses (completed, failed, timeout) — prevents excessive refetches on running/pending"
  - "JourneyComparison limited to aggregate delta (score + count diff) — per-threat delta deferred as it requires new server query"

patterns-established:
  - "lastMessage effect pattern: check lastMessage?.type + lastMessage.data?.status before bulk invalidateQueries"
  - "Snapshot comparison: snapshots[0] = current, snapshots[1] = previous; guard on length < 2"

requirements-completed: [UIDB-05, UIDB-06]

# Metrics
duration: 13min
completed: 2026-03-16
---

# Phase 4 Plan 04: WebSocket Invalidation and Journey Comparison Summary

**WebSocket-triggered React Query cache invalidation on terminal job statuses + JourneyComparison delta component showing score and threat count changes between the two most recent posture snapshots**

## Performance

- **Duration:** 13 min
- **Started:** 2026-03-16T23:30:23Z
- **Completed:** 2026-03-16T23:43:00Z
- **Tasks:** 2
- **Files modified:** 2 (1 created, 1 modified)

## Accomplishments
- postura.tsx now auto-refreshes all dashboard queries when any job completes, fails, or times out via WebSocket event
- JourneyComparison component computes and displays score delta, open threat count delta, critical and high count deltas between the two most recent posture snapshots
- Graceful fallback when fewer than 2 snapshots exist ("execute pelo menos duas jornadas")
- Summary sentence adapts: melhorou / piorou / estavel based on score delta direction

## Task Commits

Each task was committed atomically:

1. **Task 1: Wire WebSocket cache invalidation in postura page** - `e47fc05` (feat)
2. **Task 2: Build journey comparison delta component** - `522925f` (feat)

**Plan metadata:** (docs commit follows)

## Files Created/Modified
- `client/src/pages/postura.tsx` - Added useEffect watching lastMessage to invalidate 4 query keys on terminal job statuses; imported JourneyComparison and rendered it in a Card below JourneyCoverage
- `client/src/components/dashboard/journey-comparison.tsx` - New component: fetches /api/posture/history?limit=2, computes deltas, displays score row + 3-column threat grid + summary sentence with color-coded ArrowUpRight/ArrowDownRight/Minus icons

## Decisions Made
- WebSocket invalidation only on terminal job statuses (completed, failed, timeout) — prevents excessive refetches on running/pending events (research Pitfall 3)
- JourneyComparison limited to aggregate delta (score + count diff) — per-threat delta (which specific threats appeared/disappeared) deferred as it requires a new server-side diff query

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
- Node.js not in bash PATH on this Windows host; worked around by invoking TypeScript compiler via `cmd /c node_modules\.bin\tsc` — no functional impact

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Phase 4 complete: all 4 plans executed (postura page, action plan, remediation wiring, WebSocket invalidation + journey comparison)
- Dashboard refreshes automatically on job completion
- Journey comparison visible to users after at least 2 journeys run
- No blockers for v1.0 milestone

---
*Phase: 04-user-facing-surfaces*
*Completed: 2026-03-16*
