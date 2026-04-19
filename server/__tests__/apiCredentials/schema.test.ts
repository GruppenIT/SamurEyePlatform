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

describe('insertApiCredentialSchema (Phase 10 — CRED-01)', () => {
  describe('aceita os 7 auth types com payload valido', () => {
    it.todo('aceita api_key_header com apiKeyHeaderName + secret');
    it.todo('aceita api_key_query com apiKeyQueryParam + secret');
    it.todo('aceita bearer_jwt com secret (JWT string)');
    it.todo('aceita basic com basicUsername + secret');
    it.todo('aceita oauth2_client_credentials com oauth2ClientId + oauth2TokenUrl + secret');
    it.todo('aceita hmac com hmacKeyId + hmacAlgorithm HMAC-SHA256 + secret');
    it.todo('aceita mtls com mtlsCert + mtlsKey PEM (sem mtlsCa)');
    it.todo('aceita mtls com mtlsCert + mtlsKey + mtlsCa todos PEM');
  });

  describe('rejeita payload invalido', () => {
    it.todo('rejeita authType desconhecido (ex: saml)');
    it.todo('rejeita api_key_header sem apiKeyHeaderName');
    it.todo('rejeita api_key_header com secret string vazia');
    it.todo('rejeita api_key_query sem apiKeyQueryParam');
    it.todo('rejeita bearer_jwt sem secret');
    it.todo('rejeita basic sem basicUsername');
    it.todo('rejeita basic sem secret');
    it.todo('rejeita oauth2_client_credentials sem oauth2ClientId');
    it.todo('rejeita oauth2_client_credentials com oauth2TokenUrl nao-URL');
    it.todo('rejeita hmac sem hmacKeyId');
    it.todo('rejeita hmac com hmacAlgorithm nao suportado (ex: HMAC-MD5)');
    it.todo('rejeita mtls sem mtlsCert');
    it.todo('rejeita mtls com mtlsCert string nao-PEM');
    it.todo('rejeita cross-type: bearer_jwt + apiKeyHeaderName presente');
  });
});
