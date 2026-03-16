# Phase 4: User-Facing Surfaces - Research

**Researched:** 2026-03-16
**Domain:** React UI — threat detail restructure, action plan view, executive dashboard with recharts sparklines and WebSocket-triggered cache invalidation
**Confidence:** HIGH

## Summary

Phase 4 replaces the existing raw-data UI surfaces with a structured problem/impact/fix hierarchy. Three plans cover: (1) redesigning the threats page to group parent threats with expandable children and structured evidence display, (2) building a post-journey action plan view backed by the existing `/api/recommendations` endpoint, and (3) upgrading the posture/dashboard page with a score hero, recharts AreaChart sparkline, journey coverage grid, and WebSocket-triggered React Query invalidation.

All required APIs already exist from Phase 3: `GET /api/recommendations` (filterable), `GET /api/threats/:id/recommendation`, `GET /api/posture/history`, and the `jobUpdate` WebSocket event. No new backend work is needed for Phase 4 — this is a pure client-side build against already-available data.

The project is a React 18 / Vite 6 SPA using TanStack Query v5, Wouter v3, Radix UI (shadcn/ui), Tailwind CSS 3, recharts 2.15, and the native browser WebSocket API via a project-built `useWebSocket()` hook. All these are already installed and in active use. Recharts AreaChart is already demonstrated in `client/src/pages/hosts.tsx`.

**Primary recommendation:** Build all three plans as in-place rewrites of existing pages/components — no new routing needed, no new libraries needed, no backend changes needed.

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| UIFN-01 | Threat detail view shows problem → impact → fix hierarchy instead of raw JSON evidence | `recommendations` table has `whatIsWrong`, `businessImpact`, `fixSteps[]`; `GET /api/threats/:id/recommendation` already exists |
| UIFN-02 | Evidence is human-readable: parsed data with labels, not stdout strings or JSON blobs | `evidence` JSONB on threats has structured fields; display logic must map keys to labels rather than raw JSON.stringify |
| UIFN-03 | Threat list shows grouped parent threats with expandable child findings | `threats` table has `parentThreatId` + `groupingKey`; existing `/api/threats` returns all; client groups by parentThreatId |
| UIFN-04 | Each threat group shows its remediation preview (first fix step + effort tag) | `GET /api/threats/:id/recommendation` returns `fixSteps[0]` + `effortTag`; batch approach: fetch recommendations for visible parents |
| UIAP-01 | Post-journey view shows prioritized remediation actions ordered by contextual score | `GET /api/recommendations` exists; join with threat `contextualScore` for ordering |
| UIAP-02 | Each action shows: threat summary, fix preview, effort tag, required role, projected score delta | All fields present: `recommendations.effortTag`, `roleRequired`, `fixSteps[0]`; `threats.projectedScoreAfterFix` |
| UIAP-03 | User can filter actions by effort level, role, or journey type | `GET /api/recommendations?effortTag=&roleRequired=` already supported; journey type filter needs threat join |
| UIAP-04 | Action plan connects to threat detail for full remediation steps | Wouter `<Link to="/threats">` with threat ID or query param to open detail dialog |
| UIDB-01 | Posture hero shows score + delta arrow (vs last run) + date-labeled trend sparkline | `GET /api/posture/history` returns `PostureSnapshot[]` with `score` + `scoredAt`; recharts AreaChart already used in project |
| UIDB-02 | Posture score history is reliably populated on every journey completion | `postureSnapshots` table written by `scoringEngine.runScoringPipeline()` in Phase 2; already in production |
| UIDB-03 | Dashboard shows top 3 prioritized remediation actions with fix preview and projected impact | `GET /api/recommendations` ordered by threat `contextualScore` DESC, limit 3 |
| UIDB-04 | Journey coverage grid shows 4 journey types with last-run date and pass/fail indicator | `GET /api/jobs` or new `GET /api/posture/coverage` endpoint; group by journeyType, last completed job |
| UIDB-05 | Dashboard data refreshes via WebSocket-triggered React Query cache invalidation on job completion | `jobUpdate` event with `status: 'completed'` → `queryClient.invalidateQueries()` — pattern already established in `active-jobs.tsx` |
| UIDB-06 | Journey comparison view shows delta between current and previous run (new failures, resolved items) | `GET /api/posture/history` + per-journey threat diff; or new server endpoint comparing two job snapshots |
</phase_requirements>

## Standard Stack

### Core (already installed — no new installs needed)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| React | 18.3.1 | Component rendering | Project baseline |
| @tanstack/react-query | 5.60.5 | Server state, cache invalidation | Already used everywhere |
| recharts | 2.15.2 | AreaChart sparkline | Already used in hosts.tsx |
| wouter | 3.3.5 | Client-side routing, links | Project router |
| @radix-ui/* | various | Accordion, Collapsible, Dialog, Select, Badge, Tabs | shadcn/ui — all already installed |
| lucide-react | 0.453.0 | Icons (ArrowUp, ArrowDown, Clock, Shield, etc.) | Already used throughout |
| tailwindcss | 3.4.17 | Styling | Project CSS framework |
| date-fns | 3.6.0 | Date formatting for sparkline labels | Already installed |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| framer-motion | 11.13.1 | Expand/collapse animations | Already installed; use for accordion expand if desired — optional |

**Installation:** None needed. All dependencies are already present.

## Architecture Patterns

### Recommended Project Structure (additions only)
```
client/src/
├── pages/
│   ├── threats.tsx          # Rewrite: grouped threats + detail dialog (UIFN-01..04)
│   ├── postura.tsx          # Rewrite: posture hero + sparkline + coverage + comparison (UIDB-01..06)
│   └── action-plan.tsx      # New page: post-journey action list (UIAP-01..04)
├── components/
│   └── dashboard/
│       ├── posture-hero.tsx     # Score + delta arrow + sparkline
│       ├── journey-coverage.tsx # 4-grid journey status
│       └── top-actions.tsx      # Top 3 action cards
```

### Pattern 1: Parent/Child Threat Grouping on Client
**What:** Fetch all threats from `/api/threats`, group by `parentThreatId` on the client. Parent threats (`parentThreatId === null` and `groupingKey !== null`) render as collapsible group rows; child threats render inside accordion body.
**When to use:** UIFN-03, UIFN-04
**Example:**
```typescript
// Group flat threat list into tree
const groupedThreats = useMemo(() => {
  const parents = threats.filter(t => t.groupingKey !== null && t.parentThreatId === null);
  const childMap: Record<string, Threat[]> = {};
  threats.filter(t => t.parentThreatId !== null).forEach(t => {
    if (!childMap[t.parentThreatId!]) childMap[t.parentThreatId!] = [];
    childMap[t.parentThreatId!].push(t);
  });
  const standalone = threats.filter(t => t.groupingKey === null && t.parentThreatId === null);
  return { parents, childMap, standalone };
}, [threats]);
```
Use `@radix-ui/react-collapsible` (already installed as `Collapsible` in shadcn/ui) for expand/collapse.

### Pattern 2: Recommendation Fetch per Threat Detail
**What:** Lazy-fetch recommendation when user opens a threat detail dialog. Use `useQuery` with `enabled: !!selectedThreatId`.
**When to use:** UIFN-01, UIFN-02, UIAP-04
**Example:**
```typescript
const { data: recommendation } = useQuery({
  queryKey: ['/api/threats', selectedThreatId, 'recommendation'],
  queryFn: () => fetch(`/api/threats/${selectedThreatId}/recommendation`).then(r => r.json()),
  enabled: !!selectedThreatId,
  staleTime: 60_000,
});
```

### Pattern 3: WebSocket-Triggered Cache Invalidation
**What:** In the dashboard/postura page, listen to `lastMessage` from `useWebSocket()`. When `lastMessage.type === 'jobUpdate'` and `lastMessage.data.status === 'completed'`, call `queryClient.invalidateQueries()` for all posture/recommendation/coverage query keys.
**When to use:** UIDB-05
**Example:**
```typescript
// Source: established pattern from active-jobs.tsx
const { lastMessage } = useWebSocket();
useEffect(() => {
  if (lastMessage?.type === 'jobUpdate' && lastMessage.data?.status === 'completed') {
    queryClient.invalidateQueries({ queryKey: ['/api/posture/history'] });
    queryClient.invalidateQueries({ queryKey: ['/api/recommendations'] });
    queryClient.invalidateQueries({ queryKey: ['/api/posture/coverage'] });
  }
}, [lastMessage]);
```

### Pattern 4: Recharts AreaChart Sparkline
**What:** Minimal AreaChart with `height={80}`, no axes (hide with `hide` prop), gradient fill. Use `PostureSnapshot[]` from `/api/posture/history`, map to `{ date: format(scoredAt, 'dd/MM'), score }`.
**When to use:** UIDB-01
**Example:**
```typescript
// Source: established pattern from hosts.tsx lines 189-229
import { AreaChart, Area, ResponsiveContainer, Tooltip } from 'recharts';
<ResponsiveContainer width="100%" height={80}>
  <AreaChart data={sparkData}>
    <defs>
      <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="5%" stopColor="hsl(var(--primary))" stopOpacity={0.3} />
        <stop offset="95%" stopColor="hsl(var(--primary))" stopOpacity={0} />
      </linearGradient>
    </defs>
    <Tooltip formatter={(v: number) => [`${v}`, 'Score']} />
    <Area type="monotone" dataKey="score" stroke="hsl(var(--primary))" fill="url(#scoreGrad)" strokeWidth={2} dot={false} />
  </AreaChart>
</ResponsiveContainer>
```

### Pattern 5: Score Delta Arrow
**What:** Compare latest two posture snapshots. If history has < 2 entries, show no delta. Positive delta: green ArrowUpRight. Negative: red ArrowDownRight. Zero: Minus icon.
**When to use:** UIDB-01
**Example:**
```typescript
import { ArrowUpRight, ArrowDownRight, Minus } from 'lucide-react';
const delta = snapshots.length >= 2 ? snapshots[0].score - snapshots[1].score : 0;
const DeltaIcon = delta > 0 ? ArrowUpRight : delta < 0 ? ArrowDownRight : Minus;
const deltaColor = delta > 0 ? 'text-green-400' : delta < 0 ? 'text-red-400' : 'text-muted-foreground';
// Render: <DeltaIcon className={`h-5 w-5 ${deltaColor}`} /> {Math.abs(delta).toFixed(1)}
```

### Pattern 6: Human-Readable Evidence Display
**What:** Map `threat.evidence` JSONB keys to Portuguese labels. Never use `JSON.stringify()`. Render as `<dl>` with `<dt>` label and `<dd>` value pairs, or use a `<Table>`. Skip null/undefined values.
**When to use:** UIFN-02
**Example:**
```typescript
const EVIDENCE_LABELS: Record<string, string> = {
  port: 'Porta',
  protocol: 'Protocolo',
  service: 'Servico',
  version: 'Versao',
  cveId: 'CVE',
  severity: 'Severidade',
  matcherName: 'Correspondencia',
  extractedResults: 'Resultados',
  // ... extend per finding type
};

function EvidenceTable({ evidence }: { evidence: Record<string, any> }) {
  const entries = Object.entries(evidence).filter(([, v]) => v !== null && v !== undefined && v !== '');
  return (
    <dl className="grid grid-cols-2 gap-2 text-sm">
      {entries.map(([k, v]) => (
        <>
          <dt key={`${k}-label`} className="text-muted-foreground">{EVIDENCE_LABELS[k] ?? k}</dt>
          <dd key={`${k}-value`} className="font-mono">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</dd>
        </>
      ))}
    </dl>
  );
}
```

### Pattern 7: Action Plan Page
**What:** New route `/action-plan`. Fetch `GET /api/recommendations` with filter params (effortTag, roleRequired). Sort by associated threat's `contextualScore` DESC. Each card shows: threat title, `whatIsWrong`, `fixSteps[0]`, effortTag badge, roleRequired badge, projected score delta from `threat.projectedScoreAfterFix`.
**When to use:** UIAP-01..04

The recommendations endpoint currently returns `Recommendation[]` without the threat's `contextualScore`. Two approaches:
1. Client-side join: fetch `/api/recommendations` + `/api/threats` then join on `threatId` — simple, workable for moderate data volumes.
2. New server endpoint: `GET /api/action-plan` that joins recommendations + threats ordered by `contextualScore DESC`. Cleaner, avoids over-fetching.

**Recommendation:** New `GET /api/action-plan` endpoint in `server/routes/dashboard.ts` — returns pre-joined, pre-sorted result. Less client code, better for pagination later.

### Pattern 8: Journey Coverage Grid
**What:** Four cards (attack_surface, ad_security, edr_av, web_application). Each shows: last job `finishedAt`, job `status` (pass = completed, fail = failed/timeout), and count of open threats in that category.
**When to use:** UIDB-04

Requires new `GET /api/posture/coverage` endpoint: query last job per journey type + open threat count per category. Register in `dashboard.ts`.

### Anti-Patterns to Avoid
- **JSON.stringify in UI:** Never render raw evidence as a JSON blob string. Use labeled key-value display.
- **Polling instead of WS invalidation:** Don't set `refetchInterval` on posture queries — use `queryClient.invalidateQueries` from WebSocket message instead.
- **Fetching recommendations for all threats on mount:** Only fetch recommendation when user opens a threat detail (lazy, with `enabled: !!selectedThreatId`).
- **New routing library:** Wouter is established — use `<Link>` and `useLocation` from wouter, not a different router.
- **CSS-in-JS animations:** Use Tailwind classes (`transition-all`, `duration-200`) or Radix Collapsible built-in animations — not framer-motion (unnecessary complexity).
- **Non-nullable parentThreatId assumption:** Standalone threats (no grouping) have both `parentThreatId === null` AND `groupingKey === null`. Parent threats have `groupingKey !== null` AND `parentThreatId === null`. Handle both cases.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Collapsible threat groups | Custom show/hide state per row | `@radix-ui/react-collapsible` (already installed, exported as `Collapsible` in shadcn/ui) | Accessible keyboard nav, animation, WAI-ARIA |
| Score sparkline | SVG path builder | `recharts` AreaChart + ResponsiveContainer | Already used in hosts.tsx, responsive, tooltips |
| Filter dropdowns | Custom select with useState | `@radix-ui/react-select` (already installed as `Select`) | Accessible, keyboard, portal rendering |
| Dialog / drawer for threat detail | Custom modal with z-index | `@radix-ui/react-dialog` (already installed as `Dialog`) | Currently used in threats.tsx |
| Date formatting in sparkline labels | Manual date math | `date-fns` `format()` (already installed) | Locale-aware, handles edge cases |

**Key insight:** Every UI primitive needed for Phase 4 is already installed. The work is composition, not library selection.

## Common Pitfalls

### Pitfall 1: Recommendations API Returns Without Threat Score
**What goes wrong:** `GET /api/recommendations` returns `Recommendation[]` — it does NOT include `contextualScore` or `projectedScoreAfterFix` from the threats table. Sorting by score requires a join that doesn't exist client-side without fetching threats separately.
**Why it happens:** Recommendations storage was designed for Phase 3 read-by-threat-id; cross-entity sorting wasn't a requirement then.
**How to avoid:** Add `GET /api/action-plan` server endpoint that JOINs recommendations + threats, orders by `contextualScore DESC`, returns combined shape. Planner should include this as a task in plan 04-02.
**Warning signs:** If you sort recommendations client-side, `contextualScore` will be undefined for every item.

### Pitfall 2: Journey Coverage Has No Dedicated Endpoint
**What goes wrong:** No existing API returns "last job per journey type + pass/fail + open threat count per category." Using existing endpoints requires multiple fetches and complex client-side aggregation.
**Why it happens:** Dashboard endpoints were built for the old metric system (host risk scores), not for journey coverage semantics.
**How to avoid:** Add `GET /api/posture/coverage` in `server/routes/dashboard.ts`. Returns `{ journeyType, lastRunAt, status, openThreatCount }[]` for all 4 journey types (including null/never-run entries).
**Warning signs:** If plan 04-03 doesn't include a server task for coverage, the dashboard grid will need 3+ client fetches.

### Pitfall 3: WebSocket `jobUpdate` Does Not Always Carry `status: 'completed'`
**What goes wrong:** `jobQueue.ts` emits `jobUpdate` events for progress updates too (status = 'running'), not just completion. Invalidating on every `jobUpdate` causes excessive refetches.
**Why it happens:** The `jobUpdate` event type covers the full lifecycle — pending, running, completed, failed, timeout.
**How to avoid:** Filter in the `useEffect`: `if (lastMessage?.type === 'jobUpdate' && ['completed', 'failed', 'timeout'].includes(lastMessage.data?.status))`.

### Pitfall 4: Collapsible Threat Group Count Is Misleading Without Parent/Child Distinction
**What goes wrong:** If you render all threats (parent + child) in the same flat list with filtering, severity badges and counts will double-count: the parent inherits the highest child severity, and children also appear individually.
**Why it happens:** `/api/threats` returns the complete flat list including both parent and child threats.
**How to avoid:** Always filter out child threats (those with `parentThreatId !== null`) from the top-level list. Only render children inside their parent's Collapsible body. Apply filters (severity, status) to parents only, OR to both and propagate: if any child matches filter, show the parent.

### Pitfall 5: `postura.tsx` Uses Old Posture Score Endpoint
**What goes wrong:** The existing postura page fetches from `GET /api/posture/score` which computes score from host `riskScore` averages (host_risk_history table), NOT from the `posture_snapshots` table written by the scoring engine.
**Why it happens:** `/api/posture/score` was the pre-Phase-2 implementation. The `postureSnapshots` table was added in Phase 2 with `GET /api/posture/history` as its reader.
**How to avoid:** UIDB-01 sparkline and score MUST use `GET /api/posture/history` (from `postureSnapshots`). Planner should update the postura hero to call `/api/posture/history` and display `snapshots[0].score` as the current score.

### Pitfall 6: No Route for Action Plan Page
**What goes wrong:** `App.tsx` doesn't have a `/action-plan` route. If plan 04-02 creates the page file but not the route, the page is unreachable.
**Why it happens:** New pages need both a file and a `<Route>` in `App.tsx`.
**How to avoid:** Plan 04-02 must include: create `client/src/pages/action-plan.tsx` AND add `<Route path="/action-plan" component={ActionPlan} />` in `App.tsx`, AND add a sidebar link in `client/src/components/layout/sidebar.tsx`.

## Code Examples

### Existing recharts AreaChart Pattern (from hosts.tsx)
```typescript
// Source: client/src/pages/hosts.tsx lines 188-229
import { AreaChart, Area, ResponsiveContainer, CartesianGrid, XAxis, YAxis, Tooltip } from 'recharts';

<ResponsiveContainer width="100%" height={200}>
  <AreaChart data={chartData}>
    <defs>
      <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
        <stop offset="5%" stopColor={color} stopOpacity={0.3}/>
        <stop offset="95%" stopColor={color} stopOpacity={0}/>
      </linearGradient>
    </defs>
    <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
    <XAxis dataKey="date" tick={{ fontSize: 10 }} />
    <YAxis domain={[0, 100]} tick={{ fontSize: 10 }} />
    <Tooltip contentStyle={{ backgroundColor: 'hsl(var(--background))', border: '1px solid hsl(var(--border))' }} />
    <Area type="monotone" dataKey="riskScore" stroke={color} fill="url(#colorRisk)" strokeWidth={2} />
  </AreaChart>
</ResponsiveContainer>
```

### Existing queryClient.invalidateQueries Pattern (from active-jobs.tsx)
```typescript
// Source: client/src/components/dashboard/active-jobs.tsx lines 41-42
import { queryClient } from "@/lib/queryClient";
queryClient.invalidateQueries({ queryKey: ["/api/dashboard/running-jobs"] });
queryClient.invalidateQueries({ queryKey: ["/api/jobs"] });
```

### Existing Collapsible (Radix) Available
```typescript
// From @radix-ui/react-collapsible — already in package.json
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
// shadcn/ui wraps this — check if collapsible.tsx exists under components/ui/
// If not, it follows the same shadcn pattern as accordion.tsx
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Polling `/api/posture/score` every 60s | WS-triggered invalidation of `/api/posture/history` | Phase 4 | Instant refresh on job completion, no stale 60s window |
| Flat threat list (all items equal) | Parent groups + expandable children | Phase 4 | Reduces cognitive load; 30+ findings collapse to ~5-8 groups |
| Raw JSON evidence in dialog | Labeled key-value evidence table | Phase 4 | Eliminates stdout strings and JSON blobs |
| No action plan surface | Dedicated /action-plan page ordered by contextualScore | Phase 4 | First time user has a prioritized work queue |
| Legacy `/api/posture/score` (host risk avg) | `postureSnapshots` table via `/api/posture/history` | Phase 2 complete | Score now reflects threat engine scoring, not raw host risk |

**Deprecated/outdated:**
- `GET /api/posture/score`: Do not use for UIDB-01. It reads from `host_risk_history` via raw SQL, not from `postureSnapshots`. Use `/api/posture/history` instead.
- Polling refetchInterval on posture queries: Replace with WebSocket-triggered invalidation for UIDB-05.

## Open Questions

1. **journeyType filter on recommendations (UIAP-03)**
   - What we know: `GET /api/recommendations` supports `effortTag` and `roleRequired` filters. The `journeyType` filter is mentioned in the route file but the storage layer ignores it (see `recommendationFiltersSchema` has `journeyType` but `getRecommendations()` doesn't use it).
   - What's unclear: Whether journeyType needs to be stored on recommendations or derived from the threat's category.
   - Recommendation: Plan 04-02 should filter by joining through threat `category` field (attack_surface, ad_security, edr_av maps 1:1 to journey types). Either extend `getRecommendations()` to join threats on category, or do it in the new `/api/action-plan` endpoint.

2. **Journey comparison delta (UIDB-06)**
   - What we know: `posture_snapshots` has one row per job with score + counts. Comparing two snapshots gives score delta and count deltas.
   - What's unclear: "New failures, resolved items" requires knowing which specific threats appeared/disappeared between two jobs — snapshot table only has aggregate counts, not per-threat delta.
   - Recommendation: For Phase 4, limit UIDB-06 to aggregate delta (score diff + count diff between current and previous snapshot per journey). Per-threat delta would require a new server query comparing threat correlation keys across two jobIds — defer full diff to a separate task if time permits.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Vitest 4.0.18 |
| Config file | `/vitest.config.ts` |
| Quick run command | `npx vitest run server/__tests__/` |
| Full suite command | `npx vitest run` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| UIFN-01 | Threat detail shows problem/impact/fix — no raw JSON blobs rendered | manual | visual inspection | N/A |
| UIFN-02 | Evidence rendered with labels, not JSON.stringify | manual | visual inspection | N/A |
| UIFN-03 | Parent/child grouping logic in client | unit | `npx vitest run server/__tests__/threatGrouping.test.ts` | ✅ (server-side grouping tested; client grouping logic is pure JS, unit test optional) |
| UIFN-04 | Remediation preview on each threat group | manual | visual inspection | N/A |
| UIAP-01 | Action plan ordered by contextualScore | unit | `npx vitest run server/__tests__/` (new endpoint test) | ❌ Wave 0 |
| UIAP-02 | Action card fields present | manual | visual inspection | N/A |
| UIAP-03 | Filter by effort/role/journeyType works | unit | `npx vitest run server/__tests__/` (new endpoint test) | ❌ Wave 0 |
| UIAP-04 | Deep link to threat detail | manual | navigation test | N/A |
| UIDB-01 | Sparkline renders with date-labeled history | manual | visual inspection | N/A |
| UIDB-02 | postureSnapshots populated on job completion | unit | `npx vitest run server/__tests__/scoringEngine.test.ts` | ✅ |
| UIDB-03 | Top 3 actions shown | manual | visual inspection | N/A |
| UIDB-04 | Coverage grid endpoint returns correct shape | unit | `npx vitest run server/__tests__/` (new endpoint test) | ❌ Wave 0 |
| UIDB-05 | WS message triggers cache invalidation | manual | WS event simulation | N/A |
| UIDB-06 | Delta between runs shows correct diff | unit | `npx vitest run server/__tests__/` (new endpoint test) | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `npx vitest run server/__tests__/scoringEngine.test.ts server/__tests__/recommendationEngine.test.ts`
- **Per wave merge:** `npx vitest run`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `server/__tests__/actionPlan.test.ts` — covers UIAP-01, UIAP-03 (GET /api/action-plan endpoint tests)
- [ ] `server/__tests__/postureCoverage.test.ts` — covers UIDB-04 (GET /api/posture/coverage endpoint tests)

## Sources

### Primary (HIGH confidence)
- Direct codebase inspection — `client/src/pages/hosts.tsx` (recharts AreaChart pattern)
- Direct codebase inspection — `client/src/components/dashboard/active-jobs.tsx` (queryClient.invalidateQueries pattern)
- Direct codebase inspection — `client/src/lib/websocket.ts` (useWebSocket hook, lastMessage pattern)
- Direct codebase inspection — `server/routes/recommendations.ts` (existing filter API surface)
- Direct codebase inspection — `server/routes/dashboard.ts` (posture history endpoint)
- Direct codebase inspection — `shared/schema.ts` (threats, recommendations, postureSnapshots tables)
- Direct codebase inspection — `package.json` (all dependency versions confirmed)

### Secondary (MEDIUM confidence)
- recharts 2.15 AreaChart API — consistent with code already working in production in hosts.tsx
- TanStack Query v5 `invalidateQueries` API — consistent with code already working in active-jobs.tsx

### Tertiary (LOW confidence)
- None

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all packages confirmed in package.json, patterns confirmed in production code
- Architecture: HIGH — all API endpoints confirmed in server routes, all data shapes confirmed in schema
- Pitfalls: HIGH — identified from direct source inspection of existing code gaps (score endpoint mismatch, missing route, WS filter, journeyType filter gap)

**Research date:** 2026-03-16
**Valid until:** 2026-04-16 (stable stack, no external API dependencies)
