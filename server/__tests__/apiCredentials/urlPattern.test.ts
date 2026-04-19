import { describe, it, expect } from 'vitest';
import {
  matchUrlPattern,
  isValidUrlPattern,
} from '../../services/credentials/matchUrlPattern';
import {
  URL_PATTERN_MATRIX,
  VALID_PATTERN_CASES,
} from '../helpers/apiCredentialFactory';

describe('matchUrlPattern (Phase 10 — CRED-03)', () => {
  it.each(URL_PATTERN_MATRIX)(
    '%s vs %s → %s (%s)',
    (pattern, url, expected, _description) => {
      expect(matchUrlPattern(pattern, url)).toBe(expected);
    },
  );

  describe('casos individuais explicitos da matriz', () => {
    it('* casa qualquer URL (wildcard global caso especial)', () => {
      expect(matchUrlPattern('*', 'https://any.url/path')).toBe(true);
      expect(matchUrlPattern('*', 'https://api.corp.com/v2/users/123')).toBe(
        true,
      );
    });
    it('https://api.corp.com/* casa /users mas nao /v2/users (* nao cruza /)', () => {
      expect(
        matchUrlPattern(
          'https://api.corp.com/*',
          'https://api.corp.com/users',
        ),
      ).toBe(true);
      expect(
        matchUrlPattern(
          'https://api.corp.com/*',
          'https://api.corp.com/v2/users',
        ),
      ).toBe(false);
    });
    it('https://*.prod.example.com/* casa api.prod.example.com mas nao api.staging.example.com', () => {
      expect(
        matchUrlPattern(
          'https://*.prod.example.com/*',
          'https://api.prod.example.com/v1',
        ),
      ).toBe(true);
      expect(
        matchUrlPattern(
          'https://*.prod.example.com/*',
          'https://api.staging.example.com/v1',
        ),
      ).toBe(false);
    });
    it('match exato sem glob: trailing slash NAO casa', () => {
      expect(
        matchUrlPattern(
          'https://api.corp.com/v2/users',
          'https://api.corp.com/v2/users',
        ),
      ).toBe(true);
      expect(
        matchUrlPattern(
          'https://api.corp.com/v2/users',
          'https://api.corp.com/v2/users/',
        ),
      ).toBe(false);
    });
    it('path params {id} sao tratados como caracteres literais', () => {
      expect(
        matchUrlPattern(
          'https://api.corp.com/v2/users/{id}',
          'https://api.corp.com/v2/users/{id}',
        ),
      ).toBe(true);
      expect(
        matchUrlPattern(
          'https://api.corp.com/v2/users/{id}',
          'https://api.corp.com/v2/users/123',
        ),
      ).toBe(false);
    });
  });

  describe('escape de caracteres regex', () => {
    it('ponto em pattern e escapado (literal . no regex resultante)', () => {
      expect(matchUrlPattern('a.b', 'aXb')).toBe(false);
      expect(matchUrlPattern('a.b', 'a.b')).toBe(true);
    });
    it('parenteses, colchetes, chaves regex sao escapados', () => {
      expect(matchUrlPattern('foo(bar)', 'foo(bar)')).toBe(true);
      expect(matchUrlPattern('foo[bar]', 'foo[bar]')).toBe(true);
      expect(matchUrlPattern('foo{bar}', 'foo{bar}')).toBe(true);
    });
  });

  describe('guards de input vazio', () => {
    it('pattern vazio retorna false', () => {
      expect(matchUrlPattern('', 'https://api.corp.com')).toBe(false);
    });
    it('url vazia retorna false', () => {
      expect(matchUrlPattern('*', '')).toBe(false);
    });
  });
});

describe('isValidUrlPattern (Phase 10 — CRED-03)', () => {
  it.each(VALID_PATTERN_CASES)(
    'isValidUrlPattern(%s) → %s (%s)',
    (pattern, expected, _description) => {
      expect(isValidUrlPattern(pattern)).toBe(expected);
    },
  );
  it('** retorna false (ambiguo)', () => {
    expect(isValidUrlPattern('**')).toBe(false);
  });
  it('string vazia retorna false', () => {
    expect(isValidUrlPattern('')).toBe(false);
  });
  it('* retorna true', () => {
    expect(isValidUrlPattern('*')).toBe(true);
  });
  it('padrao com wildcard retorna true', () => {
    expect(isValidUrlPattern('https://api.corp.com/*')).toBe(true);
  });
  it('rejeita pattern com caractere fora da whitelist', () => {
    expect(isValidUrlPattern('https://api.corp.com/<script>')).toBe(false);
  });
});
