/**
 * Phase 12 Wave 0 — Nyquist stub for token reuse detection.
 * Implementation comes in Wave 1 (12-02-PLAN — scanners/api/authFailure.ts).
 * Requirement: TEST-02
 */
import { describe, it } from 'vitest';

describe('authFailure: checkTokenReuse', () => {
  it.todo('returns skip={reason:"opaque_token"} when decodeJwtExp returns undefined');
  it.todo('returns skip={reason:"not_expired"} when exp > now()');
  it.todo('proceeds with probe when exp < now()');
  it.todo('emits severity=high finding when probe status < 400');
  it.todo('extractedValues includes tokenExpiredAt (ISO) and acceptedAt (ISO)');
});
