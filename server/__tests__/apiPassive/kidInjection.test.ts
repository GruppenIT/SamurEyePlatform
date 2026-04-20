/**
 * Phase 12 Wave 0 — Nyquist stub for kid injection.
 * Implementation comes in Wave 1 (12-02-PLAN — scanners/api/authFailure.ts).
 * Requirement: TEST-02
 */
import { describe, it } from 'vitest';

describe('authFailure: injectKid + KID_INJECTION_PAYLOADS', () => {
  it.todo('exports exactly 4 canonical payloads: path-traversal-dev-null, path-traversal-etc-passwd, sql-injection-tautology, url-injection-external-jwks');
  it.todo('injectKid replaces header.kid with payload value, preserves payload + signature');
  it.todo('injectKid emits three-segment token (header.payload.signature)');
  it.todo('injectKid with empty original signature yields trailing dot (header.payload.)');
});
