/**
 * Phase 16 — UI-02 Backend — GET /api/v1/apis/:id/endpoints
 *
 * Wave 0 Nyquist stubs. Promoted to real it() by Plan 02 during Wave 1.
 * Per 16-VALIDATION.md task map.
 *
 * Requirement: Return ApiEndpoint rows for a given apiId.
 * Auth required. 404 for unknown apiId. Ordered by path ASC, method ASC.
 */
import { describe, it } from 'vitest';

describe('GET /api/v1/apis/:id/endpoints', () => {
  it.todo('returns 401 when request has no authentication');
  it.todo('returns 404 when apiId does not exist in DB');
  it.todo('returns 200 with array of ApiEndpoint rows filtered by apiId');
  it.todo('response rows include fields: method, path, pathParams, queryParams, headerParams, requiresAuth, discoverySources');
  it.todo('rows are ordered by path ASC then method ASC (deterministic for UI path-grouping)');
  it.todo('returns empty array [] when API exists but has no endpoints');
});
