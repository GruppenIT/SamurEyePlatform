/**
 * Phase 12 Wave 0 — Nyquist stub for route handlers.
 * Implementation comes in Wave 3 (12-04-PLAN — routes/apis.ts + routes/apiFindings.ts).
 * Requirements: TEST-01, TEST-02
 */
import { describe, it } from 'vitest';

describe('POST /api/v1/apis/:id/test/passive', () => {
  it.todo('requires authentication (401 if not logged)');
  it.todo('requires operator or global_administrator role (403 if readonly)');
  it.todo('rejects body with unknown field (.strict() Zod)');
  it.todo('returns 404 when apiId does not exist');
  it.todo('calls runApiPassiveTests with parsed opts + jobId');
  it.todo('returns 201 with PassiveTestResult shape');
});

describe('GET /api/v1/api-findings', () => {
  it.todo('requires at least one of apiId/endpointId/jobId (400 otherwise)');
  it.todo('allows readonly_analyst role (RBAC expanded)');
  it.todo('filters by owaspCategory/severity/status/jobId');
  it.todo('applies limit (default 50) + offset pagination');
  it.todo('returns ApiFinding[] sanitized (no secret fields — api_findings has none natively)');
});
