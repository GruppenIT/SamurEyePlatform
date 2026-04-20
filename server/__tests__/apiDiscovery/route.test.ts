/**
 * Phase 11 — Nyquist stubs for POST /api/v1/apis/:id/discover route.
 * Task 11-07-T3 (apiDiscovery route) replaces it.todo with real assertions.
 */
import { describe, it } from 'vitest';
// import placeholder — real imports added when stubs become real tests:
// import { registerApiDiscoveryRoutes } from '../../routes/apiDiscovery';
void 0;

describe('POST /api/v1/apis/:id/discover', () => {
  it.todo('401 when unauthenticated');
  it.todo('403 when user role is read_only');
  it.todo('accepts roles global_administrator and operator');
  it.todo('400 when body fails discoverApiOptsSchema Zod parse');
  it.todo('404 when apiId does not exist');
  it.todo('202 accepted + returns jobId when discoverApi starts successfully');
  it.todo('500 with pt-BR message on internal failure');
  it.todo('log.info uses apiId, userId, opts.stages — never secrets');
});
