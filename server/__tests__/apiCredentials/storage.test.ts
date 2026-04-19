import { describe, it, expect } from 'vitest';
import {
  createTestApiCredential,
  TEST_PEM_CERT,
  TEST_PEM_KEY,
} from '../helpers/apiCredentialFactory';

// Referenced exports keep TS happy even while stubs are it.todo.
void createTestApiCredential;
void TEST_PEM_CERT;
void TEST_PEM_KEY;
void expect;

describe('apiCredentials storage facade (Phase 10 — CRED-01, CRED-02)', () => {
  describe('createApiCredential — encryption round-trip por auth type', () => {
    it.todo('api_key_header: persiste secret cifrado via encryptionService.encryptCredential');
    it.todo('api_key_query: persiste secret cifrado');
    it.todo('bearer_jwt: persiste JWT inteiro como secret cifrado');
    it.todo('basic: persiste senha cifrada (basicUsername em coluna plain)');
    it.todo('oauth2_client_credentials: persiste client_secret cifrado (clientId em coluna plain)');
    it.todo('hmac: persiste hmacSecretKey cifrada (hmacKeyId em coluna plain)');
    it.todo('mtls: persiste JSON.stringify({cert,key,ca}) cifrado (multi-part composite)');
  });

  describe('decryptCredential round-trip', () => {
    it.todo('api_key_header: decryptCredential retorna o API key original');
    it.todo('mtls: decrypt + JSON.parse retorna { cert, key, ca } com 3 PEMs originais');
    it.todo('mtls sem ca: decrypt + JSON.parse retorna objeto sem chave ca definida');
  });

  describe('sanitizacao de secrets na resposta', () => {
    it.todo('listApiCredentials() nunca retorna secretEncrypted nem dekEncrypted');
    it.todo('getApiCredential(id) nunca retorna secretEncrypted nem dekEncrypted');
    it.todo('getApiCredentialWithSecret(id) RETORNA secretEncrypted e dekEncrypted (uso interno do executor)');
  });

  describe('bearerExpiresAt derivado do JWT', () => {
    it.todo('bearer_jwt com exp valido popula bearerExpiresAt no insert');
    it.todo('bearer_jwt opaco (sem exp ou nao-decodavel) aceita sem erro com bearerExpiresAt null');
  });

  describe('UNIQUE constraint', () => {
    it.todo('createApiCredential com (name, createdBy) duplicado lanca erro 23505');
    it.todo('createApiCredential com mesmo name por usuarios diferentes nao conflita');
  });

  describe('FK ON DELETE SET NULL', () => {
    it.todo('deletar API referenciada nao deleta a credencial — apiId vira NULL');
  });
});
