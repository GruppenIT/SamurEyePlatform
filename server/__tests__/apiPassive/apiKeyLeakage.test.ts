/**
 * Phase 12 Wave 0 — Nyquist stub for API key leakage heuristic.
 * Implementation comes in Wave 1 (12-02-PLAN — scanners/api/authFailure.ts).
 * Requirement: TEST-02
 */
import { describe, it } from 'vitest';

describe('authFailure: detectApiKeyLeakage', () => {
  it.todo('probes up to 5 GET endpoints per API');
  it.todo('returns match when API key substring appears in any response body');
  it.todo('mask-at-source: leakedKeyPrefix = first 3 chars + "***" (never full key)');
  it.todo('emits severity=high finding with leakedInEndpointId UUID');
  it.todo('returns no match when key does not appear in any probed body');
  it.todo('respects 1s delay between requests (rate cap)');
});
