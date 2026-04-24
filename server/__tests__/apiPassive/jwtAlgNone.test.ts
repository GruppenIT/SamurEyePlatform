/**
 * Phase 12-02 — authFailure: forgeJwtAlgNone tests
 * TDD GREEN: implementation in server/services/scanners/api/authFailure.ts
 */
import { describe, it, expect } from 'vitest';
import { forgeJwtAlgNone } from '../../services/scanners/api/authFailure';

// Build a real-ish JWT for testing
function makeJwt(header: Record<string, unknown>, payload: Record<string, unknown>): string {
  const h = Buffer.from(JSON.stringify(header)).toString('base64url');
  const p = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${h}.${p}.signature`;
}

describe('authFailure: forgeJwtAlgNone', () => {
  it('Test 1: replaces header.alg with none, preserves payload verbatim', () => {
    const payload = { sub: '123', exp: 9999999999, iss: 'test' };
    const jwt = makeJwt({ alg: 'RS256', typ: 'JWT' }, payload);
    const { forged } = forgeJwtAlgNone(jwt);
    const parts = forged.split('.');
    const forgedHeader = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const forgedPayload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    expect(forgedHeader.alg).toBe('none');
    expect(forgedPayload).toEqual(payload);
  });

  it('Test 2: emits three-segment token with empty signature (trailing dot)', () => {
    const jwt = makeJwt({ alg: 'HS256', typ: 'JWT' }, { sub: 'user' });
    const { forged } = forgeJwtAlgNone(jwt);
    const parts = forged.split('.');
    expect(parts).toHaveLength(3);
    expect(parts[2]).toBe('');
  });

  it('Test 3: returns originalAlg from decoded original header', () => {
    const jwt = makeJwt({ alg: 'RS256', typ: 'JWT' }, { sub: 'user' });
    const { originalAlg } = forgeJwtAlgNone(jwt);
    expect(originalAlg).toBe('RS256');
  });

  it('Test 4 (behavior Test 2): throws "JWT opaco" on token with < 2 segments', () => {
    expect(() => forgeJwtAlgNone('opaque-token-no-dots')).toThrow('JWT opaco');
  });

  it('Test 5: preserves parts[1] (payload) verbatim', () => {
    const jwt = makeJwt({ alg: 'ES256', typ: 'JWT' }, { sub: '456', exp: 1234567890 });
    const originalParts = jwt.split('.');
    const { forged } = forgeJwtAlgNone(jwt);
    const forgedParts = forged.split('.');
    expect(forgedParts[1]).toBe(originalParts[1]);
  });
});
