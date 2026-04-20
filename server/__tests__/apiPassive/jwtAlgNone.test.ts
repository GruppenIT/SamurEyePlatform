/**
 * Phase 12 Wave 0 — Nyquist stub for JWT alg:none forge.
 * Implementation comes in Wave 1 (12-02-PLAN — scanners/api/authFailure.ts).
 * Requirement: TEST-02
 */
import { describe, it } from 'vitest';

describe('authFailure: forgeJwtAlgNone', () => {
  it.todo('replaces header.alg with "none", preserves payload verbatim');
  it.todo('emits three-segment token (header.payload. — signature empty string)');
  it.todo('returns originalAlg from decoded original header (e.g., RS256)');
  it.todo('throws "JWT opaco" on tokens with < 2 segments');
  it.todo('returns originalAlg=null when header.alg is not a string');
  it.todo('round-trips standard JWT claims (iss/sub/exp) in payload unchanged');
});
