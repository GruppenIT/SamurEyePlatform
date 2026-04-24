/**
 * Phase 12 Wave 0 — Nyquist stub for orchestrator.
 * Implementation comes in Wave 2 (12-03-PLAN — journeys/apiPassiveTests.ts).
 * Requirements: TEST-01, TEST-02
 */
import { describe, it } from 'vitest';

describe('journeys/apiPassiveTests: runApiPassiveTests', () => {
  it.todo('runs 3 stages in order: api9Inventory → nucleiPassive → authFailure');
  it.todo('honors opts.stages.X=false to skip stage (stagesSkipped populated)');
  it.todo('dryRun=true: reads fixtures, no spawn/fetch, findings prefixed [DRY-RUN]');
  it.todo('cancellation via jobQueue.isJobCancelled between stages sets cancelled=true');
  it.todo('preserves partial findings on cancel (no rollback)');
  it.todo('preflightNuclei failure: skip nucleiPassive, continue authFailure + api9Inventory');
  it.todo('durationMs populated, findingsByCategory counts match upsert actions');
  it.todo('authFailure stage skips endpoints where requiresAuth != true');
  it.todo('authFailure stage skips endpoints without compatible resolveApiCredential match');
});
