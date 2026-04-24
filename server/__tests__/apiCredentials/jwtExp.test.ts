import { describe, it, expect } from 'vitest';
import { decodeJwtExp } from '../../services/credentials/decodeJwtExp';

function makeJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(
    JSON.stringify({ alg: 'HS256', typ: 'JWT' }),
  ).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${header}.${body}.signature`;
}

describe('decodeJwtExp (Phase 10 — CRED-01)', () => {
  it('JWT com exp numerico retorna Date correto (exp * 1000)', () => {
    const epochSeconds = 9999999999;
    const jwt = makeJwt({ sub: 'user', exp: epochSeconds });
    const result = decodeJwtExp(jwt);
    expect(result).toBeInstanceOf(Date);
    expect(result?.getTime()).toBe(epochSeconds * 1000);
  });

  it('JWT sem claim exp retorna null', () => {
    const jwt = makeJwt({ sub: 'user' });
    expect(decodeJwtExp(jwt)).toBeNull();
  });

  it('JWT com exp string nao-numerico retorna null', () => {
    const jwt = makeJwt({ sub: 'user', exp: 'tomorrow' });
    expect(decodeJwtExp(jwt)).toBeNull();
  });

  it('JWT opaco (1 segmento) retorna null sem lancar', () => {
    expect(() => decodeJwtExp('opaco-sem-pontos')).not.toThrow();
    expect(decodeJwtExp('opaco-sem-pontos')).toBeNull();
  });

  it('JWT com payload nao-base64url retorna null sem lancar', () => {
    expect(() => decodeJwtExp('h.notValidBase64URL!!!.s')).not.toThrow();
    expect(decodeJwtExp('h.notValidBase64URL!!!.s')).toBeNull();
  });

  it('string vazia retorna null', () => {
    expect(decodeJwtExp('')).toBeNull();
  });

  it('exp = NaN retorna null', () => {
    const jwtNaN = makeJwt({ exp: NaN });
    expect(decodeJwtExp(jwtNaN)).toBeNull();
  });
});
