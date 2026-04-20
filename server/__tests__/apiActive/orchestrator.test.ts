/**
 * Phase 13 Wave 0 — Nyquist stub for orchestrator.
 * Implementation comes in Wave 2 (13-03-PLAN — journeys/apiActiveTests.ts).
 * Requirements: TEST-03, TEST-04, TEST-05, TEST-06, TEST-07
 */
import { describe, it } from 'vitest';

describe('journeys/apiActiveTests: runApiActiveTests', () => {
  it.todo('runs 5 stages in order: bola → bfla → bopla → rate_limit → ssrf');
  it.todo('honors opts.stages.X=false to skip stage (stagesSkipped populated with reason)');
  it.todo('dryRun=true: reads fixtures from server/__tests__/fixtures/api-active/, no spawn/fetch, findings prefixed [DRY-RUN]');
  it.todo('cancellation via jobQueue.isJobCancelled between stages sets cancelled=true');
  it.todo('cancellation also checked between endpoints within long-running BOLA loop');
  it.todo('preserves partial findings on cancel (no rollback)');
  it.todo('preflightNuclei called ONLY before ssrf stage (not before bola/bfla/bopla/rateLimit)');
  it.todo('preflightNuclei failure: skip ssrf stage only, continue others');
  it.todo('durationMs populated; findingsByCategory/findingsBySeverity counts match persistHit actions');
  it.todo('credentialsUsed reports how many unique creds participated across stages');
  it.todo('BOPLA stage auto-skips when opts.destructiveEnabled !== true (gate enforced at orchestrator, stage function, or both)');
  it.todo('rateLimit stage auto-skips when opts.stages.rateLimit !== true (default false)');
  it.todo('each stage failure logs + push to stagesSkipped; pipeline continues without abort');
  it.todo('uses storage.upsertApiFindingByKey(endpointId, owaspCategory, title, data) for every hit (dedupe)');
  it.todo('resolves creds via listApiCredentials({apiId}) for BOLA cred pairing');
});
