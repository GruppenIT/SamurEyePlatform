/**
 * Phase 15 — SAFE-05 Nyquist stubs.
 * Implementação chega no Plano 15-03.
 */
import { describe, it } from 'vitest';

describe('SAFE-05 — GET /healthz/api-test-target', () => {
  it.todo('rota registrada em server/routes/index.ts NÃO exige autenticação session');
  it.todo('GET /healthz/api-test-target retorna 200 com Content-Type application/json');
  it.todo('response body tem { status: "ok", dryRun: true, mockFindings: [...] }');
  it.todo('mockFindings contém exatamente 4 itens cobrindo severidades low/medium/high/critical');
  it.todo('mockFindings[*].category são valores válidos do owaspApiCategoryEnum');
  it.todo('mockFindings[*].title começa com prefixo "Mock: " (indica dados fictícios)');
  it.todo('rota NÃO faz nenhuma query ao DB (response é hardcoded)');
});
