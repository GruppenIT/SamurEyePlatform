import { describe, it, expect } from 'vitest';

void expect;

describe('resolveApiCredential (Phase 10 — CRED-04)', () => {
  describe('priority como tie-break primario', () => {
    it.todo('multiplas credenciais casam → retorna a com menor priority');
    it.todo('priority 50 vence priority 100 quando ambas casam o mesmo URL');
  });

  describe('specificity como tie-break secundario (mais literais ganha)', () => {
    it.todo('mesma priority — pattern mais especifico (mais literais) ganha');
    it.todo('https://api.corp.com/v2/users vence https://api.corp.com/* quando ambos casam');
  });

  describe('createdAt como tie-break terciario', () => {
    it.todo('mesma priority + mesma specificity → mais antiga ganha (createdAt ASC)');
  });

  describe('escopo apiId vs global', () => {
    it.todo('credencial com apiId=X candidata para query apiId=X');
    it.todo('credencial global (apiId IS NULL) candidata para qualquer apiId');
    it.todo('credencial com apiId=Y NAO candidata para query apiId=X');
  });

  describe('caso negativo', () => {
    it.todo('nenhuma credencial casa o URL → retorna null (nao lanca erro)');
  });

  describe('shape de retorno', () => {
    it.todo('resolveApiCredential retorna ApiCredentialSafe (sem secret*/dek*)');
  });
});
