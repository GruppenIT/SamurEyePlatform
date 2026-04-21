---
phase: 14-findings-runtime-threat-integration
plan: "03"
subsystem: websocket-event-infrastructure
tags: [websocket, realtime, find-04, broadcaster, zod, rate-limit]
dependency_graph:
  requires: ["14-01", "14-02"]
  provides: ["jobEventSchema", "jobEventBroadcaster", "test-scaffold-find-04"]
  affects: ["server/routes/jobs.ts", "shared/schema.ts"]
tech_stack:
  added: []
  patterns: ["discriminated-union-zod", "singleton-service", "fail-open-ws-emit", "rate-limit-sliding-window"]
key_files:
  created:
    - server/services/jobEventBroadcaster.ts
    - server/__tests__/jobEventBroadcaster.test.ts
  modified:
    - shared/schema.ts
    - server/routes/jobs.ts
decisions:
  - "WebSocket route in jobs.ts is REST-only — added import anchor + TODO comment; upgrade handler deferred to Wave 3 (14-04) / Phase 15"
  - "forEach instead of for..of on Set<WebSocket> — avoids TS2802 downlevelIteration error given no explicit target in tsconfig"
  - "Logging via pino createLogger (not console.warn) — consistent with project CONVENTIONS.md logging pattern"
metrics:
  duration: "~4 minutes"
  completed: "2026-04-20"
  tasks_completed: 3
  files_created: 2
  files_modified: 2
---

# Phase 14 Plan 03: jobEventBroadcaster + jobEventSchema Summary

Wave 2 FIND-04 real-time event infrastructure — Zod discriminated union contract, singleton broadcaster service with rate limiting and resilient send, and 6 it.todo test stubs wired.

## What Was Built

### 1. jobEventSchema Zod Discriminated Union (`shared/schema.ts`)

3-variant discriminated union on `type` field:

```typescript
export const jobEventSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('stage_progress'),
    stage: z.string(),
    status: z.enum(['started', 'completed', 'failed']),
    findingsDiscovered: z.number().int().min(0),
    durationMs: z.number().int().min(0),
    message: z.string().max(200),          // pt-BR human-readable, max 200 chars
  }),
  z.object({
    type: z.literal('findings_batch'),
    findings: z.array(z.object({
      id: z.string(),
      owaspCategory: z.string(),
      severity: z.string(),
      endpointPath: z.string(),
      title: z.string(),
    })).max(20),                           // avoids massive JSON per event
    batchNumber: z.number().int().min(1),
    totalNewInBatch: z.number().int().min(0),
  }),
  z.object({
    type: z.literal('journey_complete'),
    jobId: z.string(),
    apiId: z.string(),
    totalFindings: z.number().int().min(0),
    totalThreatsPromoted: z.number().int().min(0),
    durationMs: z.number().int().min(0),
    status: z.enum(['success', 'cancelled']),
  }),
]);

export type JobEvent = z.infer<typeof jobEventSchema>;
```

### 2. JobEventBroadcaster Class API (`server/services/jobEventBroadcaster.ts`)

| Method | Signature | Description |
|--------|-----------|-------------|
| `subscribe` | `(jobId: string, ws: WebSocket): void` | Add ws to jobId subscriber set; idempotent |
| `unsubscribe` | `(jobId: string, ws: WebSocket): void` | Remove ws; cleans up empty sets + rate tracker |
| `emit` | `(jobId: string, event: JobEvent): void` | Validated + rate-limited broadcast |
| `subscriberCount` | `(jobId: string): number` | Current subscriber count (for tests/telemetry) |

### 3. Rate Limit Configuration

```typescript
const RATE_LIMIT_EVENTS_PER_SEC = 10;   // events allowed per window
const RATE_LIMIT_WINDOW_MS = 1000;      // sliding window duration
```

Sliding window: per-jobId tracker `{ count, windowStart }`. Window resets when `now - windowStart >= 1000ms`. Events exceeding 10/sec are dropped with `log.warn`.

### 4. WebSocket Route Status

**Status: B — import-only anchor placed** (not fully wired).

`server/routes/jobs.ts` is REST-only (no WebSocket upgrade handler existed). Added:
- `import { jobEventBroadcaster } from '../services/jobEventBroadcaster'`
- TODO comment with upgrade handler pattern for Wave 3 / Phase 15

```typescript
// TODO(14-04/Phase-15): Wire upgrade handler GET /api/v1/jobs/:jobId/ws
//   wss.on('connection', (ws, req) => {
//     const match = req.url?.match(/\/api\/v1\/jobs\/([^/]+)\/ws$/);
//     if (!match) { ws.close(); return; }
//     const jobId = match[1];
//     jobEventBroadcaster.subscribe(jobId, ws);
//     ws.on('close', () => jobEventBroadcaster.unsubscribe(jobId, ws));
//     ws.on('error', () => jobEventBroadcaster.unsubscribe(jobId, ws));
//   });
```

### 5. Wave 3 (14-04) Invocation Pattern

```typescript
import { jobEventBroadcaster } from '../services/jobEventBroadcaster';

// After upsertApiFindingByKey in route handler:
jobEventBroadcaster.emit(jobId, {
  type: 'findings_batch',
  findings: batchItems.map(f => ({
    id: f.id,
    owaspCategory: f.owaspCategory,
    severity: f.severity,
    endpointPath: f.endpointPath,
    title: f.title,
  })),
  batchNumber: currentBatch,
  totalNewInBatch: batchItems.length,
});

// Phase 15 journeyExecutor after each stage:
jobEventBroadcaster.emit(jobId, {
  type: 'stage_progress',
  stage: 'bola',
  status: 'completed',
  findingsDiscovered: stageResult.findingsCreated,
  durationMs: elapsed,
  message: 'BOLA: 6 pares testados, 2 vulnerabilidades encontradas',
});

// Phase 15 journeyExecutor after full journey:
jobEventBroadcaster.emit(jobId, {
  type: 'journey_complete',
  jobId,
  apiId,
  totalFindings: totalCount,
  totalThreatsPromoted: promotedCount,
  durationMs: totalElapsed,
  status: cancelled ? 'cancelled' : 'success',
});
```

### 6. Test Scaffold (`server/__tests__/jobEventBroadcaster.test.ts`)

6 `it.todo` stubs:
1. Schema validation — all 3 variants via safeParse
2. Subscribe/unsubscribe lifecycle — count assertions
3. Broadcast — correct jobId only
4. Rate limit — 11th event dropped + warning
5. ws.send failure — auto-unsubscribe, others continue
6. Invalid payload — Zod fail, ws.send not called

## Known Limitations

- **No retry/replay**: Events are fire-and-forget. Client must poll `GET /api/v1/jobs/:jobId` to reconcile state if WS connection drops mid-journey.
- **No persistence**: Events are never stored in DB. Real-time signaling only, not a data tunnel.
- **No auth on WS upgrade** (yet): RBAC check deferred to Phase 15 SAFE-04 — middleware will verify job ownership before `subscribe()`.
- **Rate limit is per-broadcaster-instance**: In multi-process deployments, each process has independent rate tracking. Phase 15 can upgrade to Redis-backed counter if needed.
- **WebSocket upgrade handler not yet wired**: Requires `wss` (WebSocket.Server) to be available in server setup — that wiring is Phase 15's responsibility alongside other WS infrastructure.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Changed `for...of` on Set to `.forEach()` to fix TS2802**
- **Found during:** Task 3 TypeScript compilation check
- **Issue:** `for (const ws of subscribers)` on `Set<WebSocket>` triggered TS2802 "can only be iterated through when using --downlevelIteration flag or with --target of es2015 or higher" — tsconfig.json has no explicit `target`, only `lib: ["esnext", ...]`
- **Fix:** Replaced both `for...of` loops (broadcast loop + dead socket cleanup) with `.forEach()` calls which have no downlevel iteration requirement
- **Files modified:** `server/services/jobEventBroadcaster.ts`
- **Commit:** b943484

**2. [Rule 2 - Convention] Used pino logger instead of console.warn**
- **Found during:** Task 3 implementation
- **Context:** Plan code template used `console.warn`. CONVENTIONS.md mandates pino `createLogger` for all server services.
- **Fix:** Used `createLogger('jobEventBroadcaster')` + `log.warn(...)` throughout broadcaster
- **Files modified:** `server/services/jobEventBroadcaster.ts`

## Self-Check: PASSED

- `server/services/jobEventBroadcaster.ts` — FOUND
- `server/__tests__/jobEventBroadcaster.test.ts` — FOUND
- `shared/schema.ts` exports jobEventSchema — FOUND
- `server/routes/jobs.ts` imports jobEventBroadcaster — FOUND
- Commit 2482b68 (schema) — FOUND
- Commit b29f738 (test stubs) — FOUND
- Commit b943484 (broadcaster + wiring) — FOUND
- vitest: 6 todo stubs confirmed (vitest run output showed `6 todo`)
- TypeScript: no errors in new files
