/**
 * Phase 16 — UI-06 Backend — POST /api/v1/jobs (api_security type)
 *
 * Wave 0 Nyquist stubs. Promoted to real it() by Plan 04 during Wave 3.
 * Per 16-VALIDATION.md task map.
 *
 * Requirement: POST /api/v1/jobs with type=api_security.
 * authorizationAck=false returns 400 with pt-BR message.
 * Full config payload (stage toggles, rateLimit, dryRun) persisted to journey.params.
 * Audit log written. dryRun=true skips actual scanners.
 */
import { describe, it } from 'vitest';

describe('POST /api/v1/jobs — api_security type', () => {
  it.todo('POST with type="api_security" and authorizationAck=false returns 400 with pt-BR error message');
  it.todo('POST with type="api_security" and authorizationAck=true creates job and returns 201');
  it.todo('POST with destructiveEnabled=true AND rateLimit > 50 returns 400 (SAFE-01 ceiling enforcement)');
  it.todo('POST persists full apiSecurityConfig in journey.params (specFirst, crawler, kiterunner, misconfigs, auth, bola, bfla, bopla, rateLimitTest, ssrf toggles)');
  it.todo('POST writes audit_log row with action="create", objectType="job", actorId from authenticated user');
  it.todo('POST with dryRun=true skips actual scanners and returns 201 success quickly (no scanner execution)');
  it.todo('POST returns 401 when request has no authentication');
});
