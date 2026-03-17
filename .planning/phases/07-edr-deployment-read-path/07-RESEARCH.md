# Phase 7: EDR Deployment Read Path - Research

**Researched:** 2026-03-17
**Domain:** Express API route registration, Drizzle ORM join queries, React/TanStack Query data fetching, shadcn Sheet component
**Confidence:** HIGH — all findings verified directly against existing codebase source code

## Summary

Phase 7 is a pure wiring task: connect the already-implemented `getEdrDeploymentsByJourney` storage function to an API route, then surface the data in the journeys page via a side sheet. The storage layer (table, types, write path, read function, IStorage interface, DatabaseStorage registration) is 100% complete. The API and UI layers are 0% implemented.

The critical design choice is that the existing `getEdrDeploymentsByJourney` returns raw `EdrDeployment[]` rows without host details. The API must return host details (hostname, IP, OS) alongside deployment data per the locked decisions. This requires a new storage function that joins `edr_deployments` with `hosts`. Drizzle 0.39.3 supports join queries via `.leftJoin()` on `db.select()` — this is the correct approach rather than N+1 host lookups.

The UI integration is additive: add a "View Results" button to each journey table row, manage a `selectedJourneyId` state, conditionally fetch deployment data with `useQuery` (enabled only when a journey is selected), and render results inside a shadcn `Sheet` component that already exists in `client/src/components/ui/sheet.tsx`.

**Primary recommendation:** Create one new route file `server/routes/edrDeployments.ts`, one new storage function `getEdrDeploymentsByJourneyWithHost` in `server/storage/edrDeployments.ts`, register the route in `server/routes/index.ts`, then extend `client/src/pages/journeys.tsx` with the Sheet + View Results button.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- **API endpoint:** Standalone route `GET /api/edr-deployments?journeyId=X` — independent resource, not nested under journeys
- **Response shape:** Includes joined host details (hostname, IP, OS) alongside deployment data — frontend does not need a second call
- **Authentication:** `isAuthenticatedWithPasswordCheck` — same pattern as all existing routes
- **UI placement:** Side sheet (right panel) that slides in from the right when user clicks "View Results" button on a journey row
- **Button visibility:** Visible on all journey types, not just edr_av — hide content (not button) if no edr_deployments data exists; show appropriate empty state
- **Sheet component:** Uses shadcn `Sheet` component for the overlay
- **Summary banner:** Stats at top of side sheet: total hosts tested, detection rate, average duration
- **Detail table:** Per-host results below the summary banner
- **Detection status badges:** Color-coded Badge — green "Detected" / red "Not Detected" / gray "N/A"

### Claude's Discretion
- Exact column set for the results table (essential vs full details)
- Whether to add hostId filter to the API
- Summary stats calculations (which metrics, how to display)
- Empty state design when no EDR deployments exist for a journey
- Loading state while fetching deployment data
- Timestamp formatting (relative vs absolute)
- Filter/sort: hostId filter in addition to journeyId

### Deferred Ideas (OUT OF SCOPE)
None — discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| PARS-10 | EDR per-host deployment metadata stored in queryable database table (not buried in JSONB artifacts) | Table exists, write path is complete, read path needs a caller. This phase creates that caller: an API route that queries `edr_deployments` and returns data to the frontend. "Queryable" is satisfied when `getEdrDeploymentsByJourney` has a consumer that actually queries it via the storage facade. |
</phase_requirements>

## Standard Stack

### Core (all already in project)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| drizzle-orm | 0.39.3 | Database join query for edr_deployments + hosts | Already the project ORM; join support verified in `pg-core/query-builders/select.js` |
| @tanstack/react-query | ^5.60.5 | Data fetching on frontend with `useQuery` | Already the project's standard data-fetching library |
| @radix-ui/react-dialog (via shadcn Sheet) | installed | Side panel overlay | shadcn Sheet wraps Radix Dialog; `sheet.tsx` already exists in `client/src/components/ui/` |
| express | ^4.21.2 | Route registration | Already the project's server framework |

### Supporting (already installed)
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| date-fns | ^3.6.0 | Timestamp formatting | Use `format` from date-fns for absolute timestamps in the table — consistent with rest of app |
| lucide-react | installed | Icon for "View Results" button | `Eye` or `BarChart2` icon — consistent with other action icons in journeys.tsx |
| class-variance-authority | installed | Badge color variants | Used by shadcn Badge — detection status coloring |

### No New Installations Required
All libraries are already installed. No `npm install` step needed.

## Architecture Patterns

### Recommended File Structure Changes
```
server/
├── routes/
│   ├── edrDeployments.ts      # NEW: GET /api/edr-deployments?journeyId=X
│   └── index.ts               # MODIFY: add registerEdrDeploymentRoutes(app)
├── storage/
│   └── edrDeployments.ts      # MODIFY: add getEdrDeploymentsByJourneyWithHost
│   └── interface.ts           # MODIFY: add getEdrDeploymentsByJourneyWithHost to IStorage
│   └── index.ts               # MODIFY: wire new function in DatabaseStorage

client/src/
└── pages/
    └── journeys.tsx           # MODIFY: add Sheet, View Results button, useQuery
```

### Pattern 1: Route Registration
**What:** Each domain has its own route file with a `registerXxxRoutes(app: Express)` export, imported and called in `server/routes/index.ts`.
**When to use:** For all new API endpoints.
**Example (from `server/routes/hosts.ts`):**
```typescript
// server/routes/edrDeployments.ts
import type { Express } from "express";
import { storage } from "../storage";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { createLogger } from '../lib/logger';

const log = createLogger('routes:edrDeployments');

export function registerEdrDeploymentRoutes(app: Express) {
  app.get('/api/edr-deployments', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { journeyId } = req.query;
      if (!journeyId || typeof journeyId !== 'string') {
        return res.status(400).json({ message: "journeyId é obrigatório" });
      }
      const deployments = await storage.getEdrDeploymentsByJourneyWithHost(journeyId);
      res.json(deployments);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch edr deployments');
      res.status(500).json({ message: "Falha ao buscar implantações EDR" });
    }
  });
}
```

**Registration in `server/routes/index.ts` — add after existing imports:**
```typescript
import { registerEdrDeploymentRoutes } from "./edrDeployments";
// ... in registerRoutes():
registerEdrDeploymentRoutes(app);
```

### Pattern 2: Drizzle Join Query
**What:** Drizzle 0.39.3 supports `.leftJoin()` chained on `db.select()`. The project has no existing join examples but the capability is verified present.
**When to use:** When you need columns from two tables in a single DB round-trip.
**Example (new function in `server/storage/edrDeployments.ts`):**
```typescript
import { db } from "../db";
import { edrDeployments, hosts, type EdrDeployment } from "@shared/schema";
import { eq, desc } from "drizzle-orm";

export type EdrDeploymentWithHost = EdrDeployment & {
  hostName: string | null;
  hostIps: string[];
  hostOperatingSystem: string | null;
};

export async function getEdrDeploymentsByJourneyWithHost(
  journeyId: string
): Promise<EdrDeploymentWithHost[]> {
  const rows = await db
    .select({
      // All edrDeployments columns
      id: edrDeployments.id,
      hostId: edrDeployments.hostId,
      journeyId: edrDeployments.journeyId,
      jobId: edrDeployments.jobId,
      deploymentTimestamp: edrDeployments.deploymentTimestamp,
      detectionTimestamp: edrDeployments.detectionTimestamp,
      deploymentMethod: edrDeployments.deploymentMethod,
      detected: edrDeployments.detected,
      testDuration: edrDeployments.testDuration,
      createdAt: edrDeployments.createdAt,
      // Joined host columns
      hostName: hosts.name,
      hostIps: hosts.ips,
      hostOperatingSystem: hosts.operatingSystem,
    })
    .from(edrDeployments)
    .leftJoin(hosts, eq(edrDeployments.hostId, hosts.id))
    .where(eq(edrDeployments.journeyId, journeyId))
    .orderBy(desc(edrDeployments.createdAt));

  return rows as EdrDeploymentWithHost[];
}
```

### Pattern 3: Frontend Conditional useQuery
**What:** `useQuery` with `enabled: !!selectedJourneyId` fetches only when a journey is selected. The `queryKey` includes the journey ID so each journey gets its own cache entry.
**When to use:** For on-demand data that loads when the user takes an action.
**Example (in `client/src/pages/journeys.tsx`):**
```typescript
const [selectedJourneyId, setSelectedJourneyId] = useState<string | null>(null);

const { data: edrDeployments = [], isLoading: isLoadingEdr } = useQuery<EdrDeploymentWithHost[]>({
  queryKey: ["/api/edr-deployments", { journeyId: selectedJourneyId }],
  enabled: !!selectedJourneyId,
});
```
The `queryClient` already supports object params in `queryKey[1]` — see `client/src/lib/queryClient.ts` lines 36-50, which builds query strings from the second queryKey element automatically.

### Pattern 4: shadcn Sheet Usage
**What:** `Sheet` wraps `SheetContent`, `SheetHeader`, `SheetTitle`, `SheetDescription`. Default `side="right"` for right panel. Control open state with a boolean derived from `selectedJourneyId !== null`.
**Example:**
```typescript
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";

<Sheet open={!!selectedJourneyId} onOpenChange={(open) => !open && setSelectedJourneyId(null)}>
  <SheetContent side="right" className="w-[600px] sm:max-w-[600px] overflow-y-auto">
    <SheetHeader>
      <SheetTitle>Resultados EDR</SheetTitle>
      <SheetDescription>Resultados de validação EDR/AV por host</SheetDescription>
    </SheetHeader>
    {/* summary stats + detail table */}
  </SheetContent>
</Sheet>
```
Note: The default `sm:max-w-sm` in `sheet.tsx` line 43 constrains width. Override with `className` on `SheetContent` for wider panel to fit the table.

### Pattern 5: Badge Detection Status
**What:** Project uses `bg-{color}/20 text-{color}` pattern on Badge. Import Badge from `@/components/ui/badge`.
**Example:**
```typescript
function DetectionBadge({ detected }: { detected: boolean | null }) {
  if (detected === true)  return <Badge className="bg-green-500/20 text-green-500">Detectado</Badge>;
  if (detected === false) return <Badge className="bg-red-500/20 text-red-500">Não Detectado</Badge>;
  return <Badge className="bg-muted text-muted-foreground">N/A</Badge>;
}
```

### Anti-Patterns to Avoid
- **N+1 host lookups:** Do not call `getEdrDeploymentsByJourney` then loop to call `getHost()` for each row. Use a single join query instead.
- **Nesting under `/api/journeys/:id/edr-deployments`:** Locked decision is standalone route `GET /api/edr-deployments?journeyId=X`.
- **Sheet trigger as SheetTrigger component:** Use external state (`selectedJourneyId`) to control Sheet open/close rather than Radix's built-in trigger — journeys page uses external state for all dialogs (see `editingJourney` and `showCreateDialog` patterns).
- **Adding requireOperator middleware:** Read-only data endpoints in the project do not require operator role — only write operations use `requireOperator`. Match the pattern of `/api/journeys` (GET) and `/api/journeys/:id/credentials`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Sheet overlay/backdrop | Custom modal CSS | shadcn `Sheet` | Focus trap, a11y, animation, keyboard dismiss all handled |
| Query string parsing (journeyId param) | Manual `req.url` parsing | Express `req.query.journeyId` | Express parses query strings automatically |
| Frontend cache per journey | Manual state cache | TanStack Query `queryKey: [path, { journeyId }]` | Each unique journeyId gets its own cache entry automatically |
| Duration formatting | Custom time math | `testDuration` field (already integer seconds) | The field is already computed and stored; display directly |

**Key insight:** Almost every concern in this phase is already solved by existing infrastructure. The work is wiring, not building.

## Common Pitfalls

### Pitfall 1: IStorage and DatabaseStorage Must Be Updated
**What goes wrong:** Adding `getEdrDeploymentsByJourneyWithHost` to `edrDeployments.ts` but forgetting to declare it in `server/storage/interface.ts` and assign it in `server/storage/index.ts` → TypeScript error when route calls `storage.getEdrDeploymentsByJourneyWithHost`.
**Why it happens:** The project's storage pattern requires 3 files to be updated in sync: the implementation file, the interface, and the class wiring.
**How to avoid:** After writing the new function, immediately update IStorage declaration and DatabaseStorage assignment — follow the same 3-file pattern as `insertEdrDeployment` / `getEdrDeploymentsByJourney`.
**Warning signs:** TypeScript error "Property does not exist on type IStorage".

### Pitfall 2: Sheet Width Too Narrow for Table
**What goes wrong:** Default `sm:max-w-sm` (384px) in shadcn's `sheetVariants` is too narrow for a multi-column results table.
**Why it happens:** Default Sheet size is designed for simple panels, not data tables.
**How to avoid:** Override `className` on `SheetContent` — e.g. `className="w-[700px] sm:max-w-[700px] overflow-y-auto"`. The Sheet component fully supports className overrides via `cn()`.

### Pitfall 3: Query Fires Before Journey Is Selected
**What goes wrong:** `useQuery` fires immediately on page load with `journeyId: null`, sending `GET /api/edr-deployments?journeyId=null` to the server.
**Why it happens:** Forgetting `enabled: !!selectedJourneyId` in useQuery options.
**How to avoid:** Always include `enabled: !!selectedJourneyId`. Also handle the 400 response in the server if journeyId is absent/invalid.

### Pitfall 4: queryKey Object Param — Existing queryClient Handles This
**What might seem like a pitfall:** How do you pass `journeyId` as a query param via useQuery's queryKey?
**Actually fine:** `client/src/lib/queryClient.ts` lines 36-50 already handle `queryKey[1]` as an object and convert it to a query string. Use `queryKey: ["/api/edr-deployments", { journeyId: selectedJourneyId }]` — it works automatically.

### Pitfall 5: Drizzle leftJoin Result Type
**What goes wrong:** Drizzle's `.leftJoin()` makes joined columns nullable (host could theoretically not exist). TypeScript will type `hostName` as `string | null`.
**Why it happens:** LEFT JOIN semantics — `hosts` row could be missing if `host_id` FK is stale.
**How to avoid:** Accept `string | null` in the response type and handle gracefully in the UI (show "—" or the raw `hostId` if `hostName` is null). In practice this should never happen since `hostId` is a NOT NULL FK, but the type is correct.

## Code Examples

Verified patterns from existing source:

### Existing Storage Pattern (for reference, verified from `server/storage/edrDeployments.ts`)
```typescript
// Current getEdrDeploymentsByJourney — returns raw rows, no host join
export async function getEdrDeploymentsByJourney(
  journeyId: string
): Promise<EdrDeployment[]> {
  return await db
    .select()
    .from(edrDeployments)
    .where(eq(edrDeployments.journeyId, journeyId))
    .orderBy(desc(edrDeployments.createdAt));
}
```

### Summary Stats Calculation Pattern
```typescript
// Compute in route handler or in the component — either is fine
const totalHosts = edrDeployments.length;
const detected = edrDeployments.filter(d => d.detected === true).length;
const detectionRate = totalHosts > 0 ? Math.round((detected / totalHosts) * 100) : 0;
const avgDuration = totalHosts > 0
  ? Math.round(edrDeployments.reduce((sum, d) => sum + d.testDuration, 0) / totalHosts)
  : 0;
```

### Error Message Pattern (Portuguese, verified from routes)
```typescript
res.status(400).json({ message: "journeyId é obrigatório" });
res.status(500).json({ message: "Falha ao buscar implantações EDR" });
```

### Existing useQuery Pattern with Enabled Guard (verified from journeys.tsx lines 45-48)
```typescript
const { data: journeyCredentials = [], isLoading: isLoadingCredentials } = useQuery<...>({
  queryKey: [`/api/journeys/${editingJourney?.id}/credentials`],
  enabled: !!editingJourney,  // <-- the pattern to replicate
});
```

### edrDeployments Schema Fields (verified from `shared/schema.ts` lines 224-238)
```
id                    varchar PK
hostId                varchar FK -> hosts.id (NOT NULL)
journeyId             varchar FK -> journeys.id (NOT NULL)
jobId                 varchar FK -> jobs.id (NOT NULL)
deploymentTimestamp   timestamp (nullable)
detectionTimestamp    timestamp (nullable)
deploymentMethod      text (NOT NULL)
detected              boolean (nullable)
testDuration          integer (NOT NULL) — seconds
createdAt             timestamp defaultNow
```

### Host Schema Fields Available for Join (verified from `shared/schema.ts` lines 203-210)
```
id                  varchar PK
name                text (hostname, always lowercase)
operatingSystem     text (nullable)
ips                 jsonb string[] (nullable-ish, defaults [])
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| N/A — no read path existed | New: join query + API route + Sheet UI | Phase 7 (now) | PARS-10 fully satisfied |
| getEdrDeploymentsByJourney (dormant) | getEdrDeploymentsByJourneyWithHost (active caller) | Phase 7 | Read path no longer dormant |

**Deprecated/outdated:**
- `getEdrDeploymentsByJourney` (no-join version): Keep it registered in IStorage/DatabaseStorage for API symmetry, but the new withHost variant is what the route will call. Alternatively, replace the IStorage declaration — planner's call. Either way, the route calls the joined version.

## Open Questions

1. **Replace or augment `getEdrDeploymentsByJourney` in IStorage?**
   - What we know: The current function returns raw rows without host details. The new route needs host details.
   - What's unclear: Should we replace the IStorage declaration with the WithHost version, or add a second function? The existing function has no callers in app code (only the dormant registration), so replacement is clean.
   - Recommendation: Add `getEdrDeploymentsByJourneyWithHost` as a second IStorage method. Keep the original to avoid any future breakage. This is the lowest-risk path.

2. **Add hostId filter to API?**
   - What we know: Locked decisions leave this to Claude's discretion.
   - Recommendation: Skip for now. The use case is per-journey results display, not per-host filtering. Adding it adds complexity for no current UI benefit.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Vitest (vitest run) |
| Config file | vitest.config.ts (inferred from project; test files in `server/__tests__/`) |
| Quick run command | `npm run test -- --reporter=verbose 2>&1 \| tail -20` |
| Full suite command | `npm run test` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| PARS-10 | `getEdrDeploymentsByJourneyWithHost` returns rows with host details | unit | `npm run test -- server/__tests__/edrDeployments.test.ts` | ❌ Wave 0 |
| PARS-10 | API route `GET /api/edr-deployments?journeyId=X` returns 200 with data | integration/manual | Manual test with curl or browser after server starts | N/A |
| PARS-10 | API route returns 400 when journeyId missing | unit | Same test file | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `npm run test -- server/__tests__/edrDeployments.test.ts` (if created)
- **Per wave merge:** `npm run test` (full suite — must stay 298+ passing)
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `server/__tests__/edrDeployments.test.ts` — unit tests for `getEdrDeploymentsByJourneyWithHost` and route validation; covers PARS-10

*(Existing test infrastructure covers all other phase concerns — only the new function/route needs a new test file)*

## Sources

### Primary (HIGH confidence)
- `server/storage/edrDeployments.ts` — current function signatures, verified directly
- `server/storage/interface.ts` line 253 — IStorage declarations, verified directly
- `server/storage/index.ts` line 184 — DatabaseStorage wiring, verified directly
- `shared/schema.ts` lines 202-241 — edrDeployments and hosts table definitions, verified directly
- `server/routes/journeys.ts` — auth middleware pattern, route registration pattern, verified directly
- `server/routes/index.ts` — `registerXxxRoutes` pattern, verified directly
- `client/src/pages/journeys.tsx` — useQuery pattern, Dialog state management, Badge styling, verified directly
- `client/src/components/ui/sheet.tsx` — Sheet component API and default variants, verified directly
- `client/src/lib/queryClient.ts` lines 36-50 — queryKey object param handling, verified directly
- `node_modules/drizzle-orm` version 0.39.3 — join support verified in `pg-core/query-builders/select.js`

### Secondary (MEDIUM confidence)
- Drizzle ORM 0.39.3 join syntax (`.leftJoin()`) — verified file exists in node_modules; exact API inferred from Drizzle docs patterns common to this version

### Tertiary (LOW confidence)
- None

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all libraries already installed and in use
- Architecture: HIGH — all patterns directly verified from existing source files
- Pitfalls: HIGH — derived from direct code inspection of the existing codebase
- Join query syntax: MEDIUM — file presence verified, exact API inferred from known Drizzle 0.39.x patterns

**Research date:** 2026-03-17
**Valid until:** 2026-06-17 (stable project stack, no fast-moving dependencies)
