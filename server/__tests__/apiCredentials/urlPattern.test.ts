import { describe, it, expect } from 'vitest';
import {
  URL_PATTERN_MATRIX,
  VALID_PATTERN_CASES,
} from '../helpers/apiCredentialFactory';

// Referenced exports keep TS happy even while stubs are it.todo.
void URL_PATTERN_MATRIX;
void VALID_PATTERN_CASES;
void expect;

describe('matchUrlPattern (Phase 10 — CRED-03)', () => {
  it.todo('cobre todos os casos da URL_PATTERN_MATRIX [pattern,url,expected]');

  describe('casos individuais explicitos da matriz', () => {
    it.todo('* casa qualquer URL (wildcard global)');
    it.todo('https://api.corp.com/* casa /v2/users mas nao /v2/users/123 (* nao cruza /)');
    it.todo('*.prod.example.com/* casa api.prod.example.com mas nao api.staging.example.com');
    it.todo('match exato sem glob: trailing slash NAO casa');
    it.todo('path params {id} sao tratados como caracteres literais');
  });

  describe('escape de caracteres regex', () => {
    it.todo('ponto em pattern e escapado (literal . no regex resultante)');
    it.todo('parenteses, colchetes, chaves regex sao escapados');
  });
});

describe('isValidUrlPattern (Phase 10 — CRED-03)', () => {
  it.todo('cobre todos os casos da VALID_PATTERN_CASES [pattern,expected]');
  it.todo('** retorna false (ambiguo)');
  it.todo('string vazia retorna false');
  it.todo('* retorna true');
  it.todo('https://api.corp.com/* retorna true');
});
