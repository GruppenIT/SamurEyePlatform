/**
 * Phase 12-02 — authFailure: injectKid + KID_INJECTION_PAYLOADS tests
 * TDD GREEN: implementation in server/services/scanners/api/authFailure.ts
 */
import { describe, it, expect } from 'vitest';
import { injectKid, KID_INJECTION_PAYLOADS } from '../../services/scanners/api/authFailure';

function makeJwt(header: Record<string, unknown>, payload: Record<string, unknown>, sig = 'sig'): string {
  const h = Buffer.from(JSON.stringify(header)).toString('base64url');
  const p = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${h}.${p}.${sig}`;
}

describe('authFailure: KID_INJECTION_PAYLOADS', () => {
  it('Test 4: exports exactly 4 canonical payloads', () => {
    expect(KID_INJECTION_PAYLOADS.length).toBe(4);
  });

  it('Test 4b: has label path-traversal-dev-null', () => {
    expect(KID_INJECTION_PAYLOADS.some((p) => p.label === 'path-traversal-dev-null')).toBe(true);
  });

  it('Test 4c: has label path-traversal-etc-passwd', () => {
    expect(KID_INJECTION_PAYLOADS.some((p) => p.label === 'path-traversal-etc-passwd')).toBe(true);
  });

  it('Test 4d: has label sql-injection-tautology', () => {
    expect(KID_INJECTION_PAYLOADS.some((p) => p.label === 'sql-injection-tautology')).toBe(true);
  });

  it('Test 4e: has label url-injection-external-jwks', () => {
    expect(KID_INJECTION_PAYLOADS.some((p) => p.label === 'url-injection-external-jwks')).toBe(true);
  });
});

describe('authFailure: injectKid', () => {
  it('Test 5: injectKid replaces header.kid with payload value', () => {
    const jwt = makeJwt({ alg: 'RS256', kid: 'original-key-id' }, { sub: 'user' });
    const injected = injectKid(jwt, 'injected-value');
    const parts = injected.split('.');
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    expect(header.kid).toBe('injected-value');
  });

  it('Test 5b: injectKid preserves payload verbatim', () => {
    const jwt = makeJwt({ alg: 'RS256' }, { sub: 'user', exp: 9999 });
    const originalParts = jwt.split('.');
    const injected = injectKid(jwt, 'some-kid');
    const injectedParts = injected.split('.');
    expect(injectedParts[1]).toBe(originalParts[1]);
  });

  it('Test 5c: injectKid preserves original signature', () => {
    const jwt = makeJwt({ alg: 'RS256' }, { sub: 'user' }, 'original-sig');
    const injected = injectKid(jwt, 'some-kid');
    const parts = injected.split('.');
    expect(parts[2]).toBe('original-sig');
  });
});
