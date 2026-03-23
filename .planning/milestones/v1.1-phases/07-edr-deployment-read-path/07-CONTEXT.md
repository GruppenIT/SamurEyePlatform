# Phase 7: EDR Deployment Read Path - Context

**Gathered:** 2026-03-17
**Status:** Ready for planning

<domain>
## Phase Boundary

Wire the existing dormant `getEdrDeploymentsByJourney` storage function to an API endpoint and surface EDR test results (EICAR deployment metadata) in the journey detail UI. No new scanner capabilities, no EDR installation features — read-only consumption of data already written by Phase 5.

**Clarification:** "EDR Deployment" refers to the deployment of EICAR test files during EDR/AV validation journeys, NOT deployment/installation of EDR software. SamurEye remains EDR-agnostic.

</domain>

<decisions>
## Implementation Decisions

### API endpoint design
- Standalone route: `GET /api/edr-deployments?journeyId=X` — independent resource, not nested under journeys
- Response includes joined host details (hostname, IP, OS) alongside deployment data — frontend doesn't need a second call
- Authentication: `isAuthenticatedWithPasswordCheck` — same pattern as all existing routes
- Filter/sort: Claude's discretion on whether to add hostId filter in addition to journeyId

### UI placement and layout
- Side sheet (right panel) that slides in from the right when user clicks a "View Results" button on a journey row
- Button visible on all journey types, not just edr_av — hide if no edr_deployments data exists (show appropriate empty state)
- Uses shadcn Sheet component for the overlay

### Data presentation
- Summary stats banner at top of side sheet: total hosts tested, detection rate, average duration
- Detail table below summary with per-host results
- Detection status shown as color-coded Badge: green "Detected" / red "Not Detected" / gray "N/A"
- Column selection: Claude's discretion — pick a sensible default from available schema fields (hostname, detected, timestamps, duration, deployment method)

### Claude's Discretion
- Exact column set for the results table (essential vs full details)
- Whether to add hostId filter to the API
- Summary stats calculations (which metrics, how to display)
- Empty state design when no EDR deployments exist for a journey
- Loading state while fetching deployment data
- Timestamp formatting (relative vs absolute)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Storage layer (Phase 5 output)
- `server/storage/edrDeployments.ts` — `insertEdrDeployment` and `getEdrDeploymentsByJourney` functions (read path is the dormant function to wire)
- `server/storage/interface.ts` line 253 — `IStorage` interface declaring `getEdrDeploymentsByJourney`
- `server/storage/index.ts` line 184 — `DatabaseStorage` wiring of `getEdrDeploymentsByJourney`

### Schema and types
- `shared/schema.ts` lines 224-241 — `edrDeployments` table definition, `EdrDeployment` and `InsertEdrDeployment` types
- `shared/schema.ts` lines 202-210 — `hosts` table (join target for host details)

### Existing route patterns
- `server/routes/journeys.ts` — current journey CRUD routes, auth middleware patterns
- `server/routes/journeys.ts` lines 154-163 — `/api/journeys/:id/credentials` as example of journey-scoped data endpoint

### Frontend patterns
- `client/src/pages/journeys.tsx` — current journeys page (table + create/edit dialogs) where the "View Results" button will be added
- `client/src/components/ui/` — shadcn components including Sheet, Badge, Table, Card

### Requirements
- `.planning/REQUIREMENTS.md` — PARS-10 definition (queryable database table for EDR deployment metadata)

### Audit findings
- `.planning/v1.1-MILESTONE-AUDIT.md` — documents the dormant read path gap this phase closes

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `getEdrDeploymentsByJourney` (server/storage/edrDeployments.ts): Already implemented, registered in IStorage and DatabaseStorage — just needs a caller
- `Badge` component: Used throughout the app for status display — reuse for detection status
- `Sheet` component (shadcn): Available in ui/ components for side panel overlay
- `Table/TableHeader/TableBody/TableRow/TableCell`: Used in journeys.tsx — same pattern for results table
- `useQuery` from @tanstack/react-query: Standard data fetching pattern used everywhere in the app

### Established Patterns
- Route registration: `registerXxxRoutes(app)` pattern in server/routes/
- Auth middleware: `isAuthenticatedWithPasswordCheck` on all data routes
- Error handling: try/catch with Portuguese error messages and `createLogger` for server logging
- Frontend queries: `useQuery` with queryKey matching the API path
- Badge styling: `bg-{color}/20 text-{color}` pattern for colored badges

### Integration Points
- `server/routes/journeys.ts` — register new route in same file or create new `edrDeployments.ts` route file
- `client/src/pages/journeys.tsx` — add "View Results" button to table rows and Sheet component
- `server/storage/edrDeployments.ts` — may need a new function for joined query (current one returns raw rows without host details)

</code_context>

<specifics>
## Specific Ideas

No specific requirements — open to standard approaches

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 07-edr-deployment-read-path*
*Context gathered: 2026-03-17*
