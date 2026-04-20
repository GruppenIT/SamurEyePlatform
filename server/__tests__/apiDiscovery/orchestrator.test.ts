/**
 * Phase 11 — Nyquist stubs for apiDiscovery orchestrator (cross-cutting).
 * Task 11-07-T1 (apiDiscovery.ts) replaces it.todo with real assertions.
 */
import { describe, it } from 'vitest';
// import placeholder — real imports added when stubs become real tests:
// import { discoverApi } from '../../services/journeys/apiDiscovery';
void 0;

describe('apiDiscovery orchestrator', () => {
  it.todo('runs stages in canonical order spec → crawler → kiterunner → httpx → arjun');
  it.todo('skips stage + logs error + continues pipeline when preflightApiBinary returns ok=false');
  it.todo('stages.crawler=true and stages.spec=true both run regardless of spec success');
  it.todo('cancellation via AbortController persists already-written endpoints');
  it.todo('returns DiscoveryResult with stagesRun, stagesSkipped[{stage,reason}], endpointsDiscovered, endpointsUpdated, endpointsStale, specFetched?, cancelled, durationMs');
  it.todo('dryRun=true skips crawler/kiterunner/arjun (runs only spec + httpx)');
  it.todo('endpointsStale contains IDs of endpoints in DB but not re-seen this run');
});
