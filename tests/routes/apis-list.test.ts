/**
 * Phase 16 — UI-01 Backend — GET /api/v1/apis
 *
 * Wave 0 Nyquist stubs. Promoted to real it() by Plan 02 during Wave 1.
 * Per 16-VALIDATION.md task map.
 *
 * Requirement: List all discovered APIs with computed endpointCount.
 * Auth required (operator role). Returns paginated or full array.
 */
import { describe, it } from 'vitest';

describe('GET /api/v1/apis', () => {
  it.todo('returns 401 when request has no authentication');
  it.todo('returns 200 with array of APIs when authenticated as operator role');
  it.todo('response rows include fields: baseUrl, apiType, discoveryMethod, endpointCount, lastExecutionAt');
  it.todo('endpointCount is computed as COUNT(api_endpoints.apiId) — returns 3 for API seeded with 3 endpoints');
  it.todo('returns empty array [] when no APIs exist in DB');
  it.todo('Zod rejects unknown query params (strict filter shape — no extra fields allowed)');
  it.todo('readonly_analyst role can also access the endpoint (GET is read-only)');
});
