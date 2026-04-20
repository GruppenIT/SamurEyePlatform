/**
 * Phase 11 — Nyquist stubs for discoverApiOptsSchema Zod schema coverage.
 * Task 11-01-T2 replaces it.todo with real assertions.
 */
import { describe, it } from 'vitest';
// import placeholder — real imports added when stubs become real tests:
// import { discoverApiOptsSchema } from '../schema';
void 0;

describe('discoverApiOptsSchema (Zod)', () => {
  it.todo('parses empty object {} using all defaults (spec=true, crawler=true, httpx=true, kiterunner=false, arjun=false, dryRun=false)');
  it.todo('requires arjunEndpointIds (min 1 UUID) when stages.arjun=true');
  it.todo('allows arjunEndpointIds=undefined when stages.arjun=false');
  it.todo('validates credentialIdOverride is UUID when present');
  it.todo('validates katana.depth is int >= 1 <= 10 when present');
  it.todo('validates kiterunner.rateLimit is int >= 1 <= 50 when present');
  it.todo('rejects extra top-level fields via .strict()');
});
