/**
 * Phase 11 — Nyquist stubs for upsertApiEndpoints dedupe storage (DISC-04 dedupe).
 * Task 11-07-T2 (apiEndpoints storage) replaces it.todo with real assertions.
 */
import { describe, it } from 'vitest';
// import placeholder — real imports added when stubs become real tests:
// import { upsertApiEndpoints, mergeHttpxEnrichment, appendQueryParams } from '../../storage/apiEndpoints';
void 0;

describe('upsertApiEndpoints storage (DISC-04 dedupe)', () => {
  it.todo('appends discoverySources via ARRAY DISTINCT unnest when row exists');
  it.todo('preserves requestSchema via COALESCE when crawler row lacks schema');
  it.todo('preserves responseSchema via COALESCE');
  it.todo('preserves requiresAuth via COALESCE (does not overwrite true with null)');
  it.todo('updates httpxStatus/httpxContentType/httpxTech/httpxTls/httpxLastProbedAt on mergeHttpxEnrichment');
  it.todo('appendQueryParams merges new params into queryParams JSONB, dedupe by name');
});
