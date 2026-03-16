---
phase: 04-user-facing-surfaces
plan: "03"
subsystem: dashboard-postura
tags: [dashboard, posture, recharts, coverage, action-plan]
dependency_graph:
  requires:
    - 02-03-PLAN (postureSnapshots table + getPostureHistory storage)
    - 03-02-PLAN (recommendations table + action-plan endpoint from 04-02)
  provides:
    - GET /api/posture/coverage (4 journey types with last run + status + open threats)
    - PostureHero component (score + delta + sparkline)
    - JourneyCoverage component (4-card grid)
    - TopActions component (top 3 prioritized actions)
    - Rewritten postura.tsx composing all 3 components
  affects:
    - client/src/pages/postura.tsx (rewritten)
    - server/routes/dashboard.ts (new endpoint added)
tech_stack:
  added: []
  patterns:
    - recharts AreaChart with linearGradient for sparkline
    - date-fns format() for date display in Portuguese locale
    - useQuery with staleTime for all data fetching
    - Promise.all for parallel DB queries in coverage endpoint
key_files:
  created:
    - client/src/components/dashboard/posture-hero.tsx
    - client/src/components/dashboard/journey-coverage.tsx
    - client/src/components/dashboard/top-actions.tsx
  modified:
    - server/routes/dashboard.ts
    - client/src/pages/postura.tsx
decisions:
  - "Coverage endpoint uses 2 queries per journey type (last job + open threat count) instead of complex JOIN for clarity and maintainability"
  - "PostureHero reverses snapshot array for chronological sparkline (API returns newest-first)"
  - "TopActions gracefully handles empty /api/action-plan response — shows 'Nenhuma acao prioritaria' when 0 items"
  - "postura.tsx completely rewritten — removed all legacy /api/posture/score references"
metrics:
  duration: ~15min
  completed_date: "2026-03-16"
  tasks_completed: 2
  files_created: 3
  files_modified: 2
---

# Phase 04 Plan 03: Postura Dashboard Rewrite Summary

**One-liner:** Rewrote postura page composing PostureHero (score/delta/sparkline from postureSnapshots), JourneyCoverage (4-type grid), and TopActions (top 3 actions), backed by new GET /api/posture/coverage endpoint.

## Tasks Completed

| Task | Description | Commit |
|------|-------------|--------|
| 1 | Create coverage endpoint + 3 dashboard sub-components | d59bf7b |
| 2 | Rewrite postura.tsx composing all 3 components | 79d994b |

## What Was Built

### Server: GET /api/posture/coverage
Added to `server/routes/dashboard.ts`. For each of the 4 journey types (`attack_surface`, `ad_security`, `edr_av`, `web_application`), runs 2 queries in parallel:
1. Most recent completed/failed/timeout job with its `finished_at` timestamp
2. Count of open, root-level (non-grouped) threats in that category

Returns array: `[{ journeyType, lastRunAt, lastStatus, openThreatCount }]`

### PostureHero (`client/src/components/dashboard/posture-hero.tsx`)
- Fetches `GET /api/posture/history?limit=30` via useQuery
- Displays latest score (text-5xl font-bold) with color coding by score range
- Delta arrow: green ArrowUpRight / red ArrowDownRight / gray Minus vs previous snapshot
- Recharts AreaChart sparkline (height=80) with linearGradient using `hsl(var(--primary))`
- Threat counts row: total open, critical (red), high (orange)

### JourneyCoverage (`client/src/components/dashboard/journey-coverage.tsx`)
- Fetches `GET /api/posture/coverage` via useQuery
- 2-column grid of 4 cards — one per journey type
- Each card: Portuguese label, journey icon (Globe/Shield/ShieldCheck/Code), last run date formatted `dd/MM/yyyy HH:mm` or "Nunca executada", status icon (CheckCircle green / XCircle red / Circle gray), open threat Badge

### TopActions (`client/src/components/dashboard/top-actions.tsx`)
- Fetches `GET /api/action-plan` via useQuery, slices to first 3 items
- Compact numbered cards with: title (60 char), whatIsWrong (100 char), fix preview (80 char), effort/role Badges, projected score delta in green

### postura.tsx (rewritten)
- Composed from PostureHero, TopActions, JourneyCoverage
- Each section in Card with CardHeader (Portuguese title + description)
- Removed all references to legacy `/api/posture/score` endpoint
- Removed old dashboard components (DeltaCard, category distribution, activity feed, top hosts)

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check

Checking created files exist:
- `client/src/components/dashboard/posture-hero.tsx`: created
- `client/src/components/dashboard/journey-coverage.tsx`: created
- `client/src/components/dashboard/top-actions.tsx`: created

Checking commits:
- d59bf7b: feat(04-03): add coverage endpoint and posture dashboard sub-components
- 79d994b: feat(04-03): rewrite postura.tsx composing PostureHero, TopActions, JourneyCoverage

TypeScript: no errors in plan files (pre-existing errors in sidebar.tsx, replitAuth.ts, etc. are out of scope)

## Self-Check: PASSED
