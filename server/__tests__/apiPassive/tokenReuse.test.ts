/**
 * Phase 12-02 — authFailure: checkTokenReuse tests
 * TDD GREEN: implementation in server/services/scanners/api/authFailure.ts
 */
import { describe, it, expect, vi } from 'vitest';
import { checkTokenReuse } from '../../services/scanners/api/authFailure';

function makeJwt(payload: Record<string, unknown>): string {
  const h = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const p = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${h}.${p}.signature`;
}

describe('authFailure: checkTokenReuse', () => {
  it('Test 6: returns skip={reason:opaque_token} for token without exp', async () => {
    const opaqueJwt = makeJwt({ sub: 'user' }); // no exp claim
    const probeFn = vi.fn();
    const result = await checkTokenReuse({
      endpointId: 'ep-001',
      endpointUrl: 'https://example.com/api/data',
      expiredJwt: opaqueJwt,
      probeFn,
    });
    expect(result.skip?.reason).toBe('opaque_token');
    expect(probeFn).not.toHaveBeenCalled();
  });

  it('Test 6b: returns skip={reason:opaque_token} for non-JWT token', async () => {
    const opaqueToken = 'not-a-jwt-token';
    const probeFn = vi.fn();
    const result = await checkTokenReuse({
      endpointId: 'ep-001',
      endpointUrl: 'https://example.com/api/data',
      expiredJwt: opaqueToken,
      probeFn,
    });
    expect(result.skip?.reason).toBe('opaque_token');
    expect(probeFn).not.toHaveBeenCalled();
  });

  it('Test 7: returns skip={reason:not_expired} for token with exp in the future', async () => {
    const futureExp = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
    const futureJwt = makeJwt({ sub: 'user', exp: futureExp });
    const probeFn = vi.fn();
    const result = await checkTokenReuse({
      endpointId: 'ep-001',
      endpointUrl: 'https://example.com/api/data',
      expiredJwt: futureJwt,
      probeFn,
    });
    expect(result.skip?.reason).toBe('not_expired');
    expect(probeFn).not.toHaveBeenCalled();
  });

  it('Test 8: returns hit severity=high when probe accepts expired token', async () => {
    const pastExp = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
    const expiredJwt = makeJwt({ sub: 'user', exp: pastExp });
    const probeFn = vi.fn().mockResolvedValue({ status: 200, bodySnippet: '{"data":"ok"}' });
    const result = await checkTokenReuse({
      endpointId: 'ep-002',
      endpointUrl: 'https://example.com/api/protected',
      expiredJwt: expiredJwt,
      probeFn,
    });
    expect(result.hit).toBeDefined();
    expect(result.hit?.severity).toBe('high');
    expect(result.hit?.owaspCategory).toBe('api2_broken_auth_2023');
    expect(result.hit?.evidence.extractedValues?.tokenExpiredAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('Test 8b: no finding when probe returns status >= 400', async () => {
    const pastExp = Math.floor(Date.now() / 1000) - 3600;
    const expiredJwt = makeJwt({ sub: 'user', exp: pastExp });
    const probeFn = vi.fn().mockResolvedValue({ status: 401 });
    const result = await checkTokenReuse({
      endpointId: 'ep-003',
      endpointUrl: 'https://example.com/api/protected',
      expiredJwt: expiredJwt,
      probeFn,
    });
    expect(result.hit).toBeUndefined();
    expect(result.skip).toBeUndefined();
  });
});
