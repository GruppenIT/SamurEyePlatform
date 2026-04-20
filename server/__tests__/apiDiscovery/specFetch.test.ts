/**
 * Phase 11 — Nyquist stubs for DISC-01 spec-path probing + auth retry.
 * Task 11-03-T1 (openapi.ts) replaces it.todo with real assertions.
 */
import { describe, it } from 'vitest';
// import placeholder — real imports added when stubs become real tests:
// import { fetchAndParseSpec, KNOWN_SPEC_PATHS } from '../../services/scanners/api/openapi';
void 0;

describe('spec-first probing (DISC-01)', () => {
  it.todo('iterates KNOWN_SPEC_PATHS in canonical order openapi.json → swagger.json → v3 → v2 → api-docs → swagger-ui.html → docs/openapi');
  it.todo('short-circuits on first response with status 200 and JSON content-type');
  it.todo('skips non-JSON responses (except swagger-ui.html path)');
  it.todo('returns null when no path yields a valid spec');
  it.todo('retries with Authorization header on 401/403 when cred is api_key_header/bearer_jwt/basic/oauth2');
  it.todo('skips retry when cred type is hmac/mtls/api_key_query and logs warn');
  it.todo('logs specPubliclyExposed=true when unauth fetch succeeds');
});
