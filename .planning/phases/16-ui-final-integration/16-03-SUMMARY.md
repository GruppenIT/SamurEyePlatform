---
phase: 16-ui-final-integration
plan: "03"
subsystem: ui
tags: [react, tanstack-query, radix-ui, wouter, tailwind, collapsible, sheet, vitest, testing-library]

requires:
  - phase: 16-ui-final-integration/16-01
    provides: shared methodColors + test infrastructure (vitest + jsdom + @testing-library/react setup)
  - phase: 16-ui-final-integration/16-02
    provides: GET /api/v1/apis + GET /api/v1/apis/:id/endpoints backend routes

provides:
  - client/src/pages/api-discovery.tsx — full page with Table of APIs + Sheet drill-down with Collapsible path groups
  - /journeys/api route registered in App.tsx
  - Sidebar "API Discovery" entry with Globe icon in Operações group
  - tests/ui/helpers.tsx — renderWithProviders wrapper (QueryClientProvider + wouter/memory-location)
  - tests/ui/api-discovery-page.test.tsx — 7 passing assertions for UI-01
  - tests/ui/api-endpoint-drilldown.test.tsx — 8 passing assertions for UI-02

affects:
  - 16-04 (future plans can rely on /journeys/api page being accessible)
  - Tests that use skeleton.tsx (React import fix applied)

tech-stack:
  added: []
  patterns:
    - "ApiDiscovery uses ApiWithCount = Api & { endpointCount, discoveryMethod?, lastExecutionAt? } — optional fields because server returns only endpointCount from listApisWithEndpointCount"
    - "EndpointGroup component uses local useState(false) for Collapsible open state — each path group independent"
    - "renderWithProviders helper uses wouter/memory-location for URL routing in jsdom tests"
    - "fireEvent.click(groupRoot.querySelector('button')) pattern for Radix CollapsibleTrigger in jsdom (avoids pointer-events:none blocking)"
    - "Method badge data-testid = method-badge-{METHOD} for stable test assertions"
    - "Collapsible root gets data-testid group-{path} while button inside is the actual trigger"

key-files:
  created:
    - client/src/pages/api-discovery.tsx
    - tests/ui/helpers.tsx
  modified:
    - client/src/App.tsx
    - client/src/components/layout/sidebar.tsx
    - tests/ui/api-discovery-page.test.tsx
    - tests/ui/api-endpoint-drilldown.test.tsx
    - client/src/components/ui/skeleton.tsx

key-decisions:
  - "ApiWithCount extends Api with optional discoveryMethod? and lastExecutionAt? — real server type (ApiWithEndpointCount) only has endpointCount; optional fields avoid TS errors while supporting future extension"
  - "TopBar receives title+subtitle props directly — no zero-argument variant exists"
  - "React explicit import in api-discovery.tsx for jsdom (tests run before bundler transform)"
  - "fireEvent.click on button inside CollapsibleTrigger asChild — userEvent blocked by Radix pointer-events:none overlay on Sheet open"
  - "Rule 1 fix: skeleton.tsx missing React import caused ReferenceError in jsdom — added import React"

requirements-completed: [UI-01, UI-02]

duration: 9min
completed: "2026-04-20"
---

# Phase 16 Plan 03: API Discovery UI Summary

**ApiDiscovery page (/journeys/api) with Table + Sheet drill-down + Collapsible endpoint groups using METHOD_COLORS/PARAM_COLORS, wired into App.tsx route and sidebar Operações group; 15 promoted test assertions passing**

## Performance

- **Duration:** ~9 min
- **Started:** 2026-04-20T21:38:01Z
- **Completed:** 2026-04-20T21:47:00Z
- **Tasks:** 2
- **Files modified:** 7

## Accomplishments

- Created `client/src/pages/api-discovery.tsx` (320 lines): Table listing APIs with baseUrl/Tipo/Descoberto por/Endpoints/Última execução columns, empty-state with Globe icon, Skeleton loading, Sheet drill-down with Collapsible path groups, MethodBadge + ParamChip helpers using `@shared/ui/methodColors`
- Registered `/journeys/api` route in App.tsx + added "API Discovery" with Globe icon to sidebar Operações group (after Jornadas, before Agendamentos)
- Created `tests/ui/helpers.tsx` with `renderWithProviders` (QueryClientProvider + wouter/memory-location Router), promoted 7 UI-01 it.todo → passing it() and 8 UI-02 it.todo → passing it() (15 total)

## Task Commits

1. **Task 1: Create ApiDiscovery page + wire route + sidebar entry** - `32cded7` (feat)
2. **Task 2: Promote UI-01 + UI-02 test stubs to real assertions** - `25b0da3` (feat)

## Files Created/Modified

- `client/src/pages/api-discovery.tsx` (created, 320 lines) — Full ApiDiscovery page component
- `client/src/App.tsx` — Added ApiDiscovery import + Route path="/journeys/api"
- `client/src/components/layout/sidebar.tsx` — Added Globe import + API Discovery navGroup entry
- `tests/ui/helpers.tsx` (created) — renderWithProviders test utility
- `tests/ui/api-discovery-page.test.tsx` — 7 it.todo promoted to passing it()
- `tests/ui/api-endpoint-drilldown.test.tsx` — 8 it.todo promoted to passing it()
- `client/src/components/ui/skeleton.tsx` — Added missing React import (Rule 1 fix)

## Decisions Made

- `ApiWithCount` type extends `Api` with optional `discoveryMethod?` and `lastExecutionAt?` — the real `ApiWithEndpointCount` type from `server/storage/apis.ts` only carries `endpointCount`; optional fields prevent TypeScript errors while leaving room for future API enrichment
- `TopBar` receives explicit `title` and `subtitle` props — no parameterless variant exists in the project
- `React` is explicitly imported in `api-discovery.tsx` for jsdom compatibility (Vite's JSX transform doesn't apply in test environment without the import)
- Tests use `fireEvent.click(groupRoot.querySelector('button'))` to expand Collapsible groups — `userEvent.click` is blocked by Radix's `pointer-events: none` overlay on the Sheet's body lock

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Missing React import in skeleton.tsx caused ReferenceError in jsdom**
- **Found during:** Task 2 (running UI-01 tests)
- **Issue:** `client/src/components/ui/skeleton.tsx` uses `React.HTMLAttributes` without importing React; works in browser via Vite JSX transform but crashes in jsdom
- **Fix:** Added `import React from "react"` to skeleton.tsx
- **Files modified:** client/src/components/ui/skeleton.tsx
- **Verification:** UI-01 skeleton loading test passes
- **Committed in:** 25b0da3 (Task 2 commit)

**2. [Rule 1 - Bug] ApiWithCount type mismatch — server type lacks discoveryMethod/lastExecutionAt**
- **Found during:** Task 1 (tsc check)
- **Issue:** Plan's context interfaces included `discoveryMethod` and `lastExecutionAt` but the real `ApiWithEndpointCount` type from storage only has `endpointCount`; caused TS error TS2339
- **Fix:** Declared `ApiWithCount = Api & { endpointCount: number; discoveryMethod?: string|null; lastExecutionAt?: ... }` with optional fields
- **Files modified:** client/src/pages/api-discovery.tsx
- **Verification:** tsc reports 0 new errors for our files
- **Committed in:** 32cded7 (Task 1 commit)

**3. [Rule 1 - Bug] TopBar props mismatch — title/subtitle required**
- **Found during:** Task 1 (tsc check)
- **Issue:** `<TopBar />` without props causes TS2739; component requires `title` and `subtitle` string props
- **Fix:** Added `title="API Discovery" subtitle="APIs descobertas nas jornadas api_security"` to TopBar usage
- **Files modified:** client/src/pages/api-discovery.tsx
- **Verification:** tsc reports 0 new errors for our files
- **Committed in:** 32cded7 (Task 1 commit)

---

**Total deviations:** 3 auto-fixed (3x Rule 1 — bug/type mismatch)
**Impact on plan:** All fixes necessary for correctness. No scope creep. Sidebar error (pre-existing TS2339 on user.role) unchanged at 89 total pre-existing TS errors.

## Issues Encountered

- Radix Collapsible in jsdom: `userEvent.click` on CollapsibleTrigger blocked by Radix's pointer-events overlay when Sheet is open. Fixed by using `fireEvent.click(groupRoot.querySelector('button'))` — fires synthetic DOM event directly, bypassing CSS pointer-events restriction.
- Pre-existing TS errors (89 errors) in `server/services/threatEngine.ts` and `server/storage/threats.ts` — not caused by Plan 03 changes, unchanged count verified by git stash comparison.

## Next Phase Readiness

- `/journeys/api` page is fully accessible, authenticated, with Table + Sheet drill-down
- UI-01 (7 tests) and UI-02 (8 tests) assertions all passing
- Phase 16 Plans 04+ can build on this page (e.g. findings overlay, action buttons)
- No blockers

---
*Phase: 16-ui-final-integration*
*Completed: 2026-04-20*
