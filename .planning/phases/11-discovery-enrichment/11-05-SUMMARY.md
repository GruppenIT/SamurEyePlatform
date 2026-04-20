---
phase: 11-discovery-enrichment
plan: 05
subsystem: api-discovery
tags: [vitest, zod, httpx, arjun, spawn, tdd, processTracker, tempfile, tri-valor]

# Dependency graph
requires:
  - phase: 11-01
    provides: Nyquist stubs (httpx.test.ts + arjun.test.ts), httpx_* columns on apiEndpoints, fixtures
  - phase: 11-02
    provides: preflightApiBinary(), processTracker widening (httpx/arjun), mergeHttpxEnrichment(), appendQueryParams()

provides:
  - "runHttpx(urls, opts, ctx): Promise<HttpxResult> — batches URLs via stdin, parses JSONL, returns HttpxEnrichment[]"
  - "mapRequiresAuth(status): boolean|null — explicit tri-valor: 401/403→true, 2xx/3xx→false, else→null (ENRH-02)"
  - "runArjun(url, opts, ctx): Promise<ArjunResult> — spawns venv arjun, parses dict-keyed JSON via Zod, cleans tempdir in try/finally (ENRH-03)"
  - "ArjunOutputSchema (Zod z.record) exported for test reuse and orchestrator validation"
  - "16 real tests GREEN: 9 httpx + 7 arjun"

affects: [11-06-PLAN]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "stdin URL batching: child.stdin.write(urls.join('\\n') + '\\n') + child.stdin.end() — avoids per-URL spawn overhead"
    - "Tri-valor mapRequiresAuth explicit switch: 401/403→true, 2xx (200/201/204)/3xx→false, all else (null/undefined/5xx/4xx)→null"
    - "Zod z.record(z.string(), z.object({...})) for dict-keyed JSON validation — rejects array input (Pitfall 4)"
    - "mkdtemp + try/finally rm(dir, {recursive:true,force:true}) — tempdir cleanup survives SIGKILL path (Pitfall 9)"
    - "TDD RED-GREEN: tests written first (import fails → RED), implementation added (all GREEN)"

key-files:
  created:
    - server/services/scanners/api/httpx.ts
    - server/services/scanners/api/arjun.ts
  modified:
    - server/__tests__/apiDiscovery/httpx.test.ts
    - server/__tests__/apiDiscovery/arjun.test.ts

key-decisions:
  - "opts.authHeader is auto-prefixed with 'Authorization: ' if not already starting with 'Authorization:' — handles bare token vs full header value"
  - "ArjunOutputSchema exported from arjun.ts (not separate file) — allows test files and orchestrator to import schema for re-validation"
  - "arjun tempfile path: mkdtemp('/tmp/api-discovery-<jobId>-<rand>/') + join(dir, 'arjun.json') — cleanup removes both dir and file atomically via rm(dir, {recursive:true})"
  - "Fallback in arjun.ts: parsed[url] ?? Object.values(parsed)[0] — handles Arjun sometimes keying by resolved URL instead of input URL"
  - "httpx.ts uses stdio: ['pipe','pipe','pipe'] (not ['ignore',...]) — stdin must be writable for URL feeding"
  - "arjun.ts uses stdio: ['ignore','pipe','pipe'] — arjun reads args/file paths from CLI, not stdin"

# Metrics
duration: 5min
completed: 2026-04-20
---

# Phase 11 Plan 05: httpx Enrichment Scanner + Arjun Parameter Discovery Summary

**runHttpx with tri-valor mapRequiresAuth (ENRH-01/02) + runArjun with Zod dict-keyed validation and try/finally tempdir cleanup (ENRH-03); 16 tests GREEN across httpx.test.ts (9) + arjun.test.ts (7)**

## Performance

- **Duration:** ~5 min
- **Started:** 2026-04-20T01:01:43Z
- **Completed:** 2026-04-20T01:06:47Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- `server/services/scanners/api/httpx.ts` (~145 lines) — `runHttpx(urls, opts, ctx)` batches all URLs to stdin via single spawn; spawns httpx with `-json -silent -sc -ct -td -tls-grab -timeout 10 -rl 50`; parses JSONL stdout; `mapRequiresAuth` explicit tri-valor per Pitfall 8; AbortSignal + processTracker integration; `opts.authHeader` injects Authorization for 2nd-pass auth probe
- `server/services/scanners/api/arjun.ts` (~145 lines) — `runArjun(url, opts, ctx)` spawns `/opt/samureye/venv-security/bin/arjun` with default wordlist `arjun-extended-pt-en.txt`; Zod `ArjunOutputSchema = z.record(z.string(), ...)` validates dict-keyed output (Pitfall 4); mkdtemp + try/finally cleanup even on abort/SIGKILL (Pitfall 9); fallback URL key lookup
- httpx.test.ts: 9 real assertions (spawns correct args, feeds stdin, parses JSONL fixture, mapRequiresAuth tri-valor, preflight skip, authHeader injection, AbortSignal+kill)
- arjun.test.ts: 7 real assertions (spawns correct args, dict-keyed parse, multi-URL fixture, preflight skip without tempfile, SIGKILL cleanup via finally, AbortSignal+kill+cleanup, Zod schema rejects array input)
- Full suite: 564 tests passing (16 new from this plan); pre-existing actionPlanService.test.ts failure (DATABASE_URL) unchanged

## Task Commits

1. **Task 1: runHttpx + mapRequiresAuth** — `4c08e95` (feat)
2. **Task 2: runArjun + ArjunOutputSchema + tempfile cleanup** — `cc0b1c9` (feat)

## Decisions Made

- `opts.authHeader` auto-prefixes `Authorization:` when bare token provided — caller can pass either `"Bearer jwt"` or `"Authorization: Bearer jwt"`
- `ArjunOutputSchema` exported from `arjun.ts` (not a shared types file) — tight coupling appropriate for scanner-specific validation
- `arjun.ts` tempfile dir uses `mkdtemp` (not a fixed path) — prevents path collisions for concurrent Arjun runs
- `parsed[url] ?? Object.values(parsed)[0]` fallback handles Arjun URL normalization edge cases
- httpx stdin uses `['pipe','pipe','pipe']` (not `['ignore',...]`) to allow `child.stdin.write()`

## Deviations from Plan

None — plan executed exactly as written. Implementation matches the code template in the plan's `<action>` blocks verbatim (with minor tuning for test harness compatibility).

## Issues Encountered

None.

## User Setup Required

None.

## Next Phase Readiness

- Plan 11-06 (orchestrator) can call `runHttpx(urls, {}, ctx)` then `storage.mergeHttpxEnrichment(endpointId, data)` per result
- Plan 11-06 can call `runArjun(url, { wordlistPath }, ctx)` then `storage.appendQueryParams(endpointId, params)`
- `mapRequiresAuth` exported for direct use in orchestrator's 2nd-pass auth probe decision logic
- `ArjunOutputSchema` exported if orchestrator needs to re-validate raw tempfile content

## Self-Check: PASSED

- server/services/scanners/api/httpx.ts — FOUND
- server/services/scanners/api/arjun.ts — FOUND
- server/__tests__/apiDiscovery/httpx.test.ts — FOUND
- server/__tests__/apiDiscovery/arjun.test.ts — FOUND
- Commit 4c08e95 (Task 1) — FOUND
- Commit cc0b1c9 (Task 2) — FOUND

---
*Phase: 11-discovery-enrichment*
*Completed: 2026-04-20*
