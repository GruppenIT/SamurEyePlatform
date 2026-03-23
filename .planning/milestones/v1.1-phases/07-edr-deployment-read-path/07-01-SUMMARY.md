---
phase: 07-edr-deployment-read-path
plan: "01"
subsystem: api
tags: [drizzle, postgresql, express, typescript, left-join]

# Dependency graph
requires:
  - phase: 05-edr-timestamps
    provides: edr_deployments table and insertEdrDeployment/getEdrDeploymentsByJourney storage functions
provides:
  - GET /api/edr-deployments?journeyId=X endpoint returning EdrDeploymentWithHost[]
  - getEdrDeploymentsByJourneyWithHost storage function with LEFT JOIN on hosts table
  - EdrDeploymentWithHost type (EdrDeployment + hostName, hostIps, hostOperatingSystem)
affects: [07-02-frontend-edr-deployments, future EDR reporting features]

# Tech tracking
tech-stack:
  added: []
  patterns: [storage-ops module pattern (edrDeploymentOps.*), route file with registerXxxRoutes export, inline return type in IStorage to avoid circular imports]

key-files:
  created:
    - server/routes/edrDeployments.ts
  modified:
    - server/storage/edrDeployments.ts
    - server/storage/interface.ts
    - server/storage/index.ts
    - server/routes/index.ts

key-decisions:
  - "IStorage declaration uses inline return type (EdrDeployment & { hostName, hostIps, hostOperatingSystem }) rather than importing EdrDeploymentWithHost to avoid circular import risk"
  - "Route returns 400 with Portuguese error message 'journeyId é obrigatório' when journeyId query param missing or non-string"

patterns-established:
  - "Left JOIN pattern: db.select({...explicit columns}).from(table).leftJoin(other, eq(fk, pk)) as EdrDeploymentWithHost[]"

requirements-completed: [PARS-10]

# Metrics
duration: 7min
completed: 2026-03-17
---

# Phase 7 Plan 01: EDR Deployment Read Path Summary

**Drizzle LEFT JOIN query on hosts table wired through IStorage/DatabaseStorage to a new authenticated GET /api/edr-deployments?journeyId=X Express route**

## Performance

- **Duration:** 7 min
- **Started:** 2026-03-17T22:40:00Z
- **Completed:** 2026-03-17T22:47:46Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments
- Added `EdrDeploymentWithHost` type and `getEdrDeploymentsByJourneyWithHost` LEFT JOIN query to server/storage/edrDeployments.ts
- Declared new storage function in IStorage interface and wired it in DatabaseStorage
- Created GET /api/edr-deployments route with journeyId validation, auth middleware, and error handling

## Task Commits

Each task was committed atomically:

1. **Task 1: Add getEdrDeploymentsByJourneyWithHost join query and wire through IStorage/DatabaseStorage** - `56f4106` (feat)
2. **Task 2: Create GET /api/edr-deployments route and register it** - `426835d` (feat)

## Files Created/Modified
- `server/storage/edrDeployments.ts` - Added EdrDeploymentWithHost type and getEdrDeploymentsByJourneyWithHost function with LEFT JOIN
- `server/storage/interface.ts` - Added getEdrDeploymentsByJourneyWithHost declaration to IStorage
- `server/storage/index.ts` - Wired getEdrDeploymentsByJourneyWithHost in DatabaseStorage
- `server/routes/edrDeployments.ts` - New route file with registerEdrDeploymentRoutes (GET /api/edr-deployments)
- `server/routes/index.ts` - Registered registerEdrDeploymentRoutes

## Decisions Made
- Used inline return type in IStorage interface (`Array<EdrDeployment & { hostName: string | null; hostIps: string[]; hostOperatingSystem: string | null }>`) rather than importing `EdrDeploymentWithHost` from the implementation file to avoid potential circular import issues.
- Portuguese error message "journeyId é obrigatório" for 400 response, consistent with existing route error messages in the codebase.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

Pre-existing TypeScript errors exist in unrelated client-side files (sidebar.tsx, useAuth.ts) and server files (replitAuth.ts, cveService.ts, jobQueue.ts). None are in the files modified by this plan. These errors predated this work and are out of scope.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Storage-to-API chain is complete: `edrDeployments.ts` -> `interface.ts` -> `index.ts` -> `routes/edrDeployments.ts` -> `routes/index.ts`
- Plan 02 (frontend) can now call GET /api/edr-deployments?journeyId=X to fetch deployment records with host details

---
*Phase: 07-edr-deployment-read-path*
*Completed: 2026-03-17*
