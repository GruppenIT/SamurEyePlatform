import { describe, it, expect } from 'vitest';
import { getTableColumns } from 'drizzle-orm';
import { getTableConfig } from 'drizzle-orm/pg-core';
import {
  createTestApiCredential,
  TEST_PEM_CERT,
  TEST_PEM_KEY,
} from '../helpers/apiCredentialFactory';
import {
  apiAuthTypeEnum,
  apiCredentials,
  insertApiCredentialSchema,
  patchApiCredentialSchema,
  type ApiCredential,
  type ApiCredentialSafe,
  type ApiCredentialWithSecret,
  type InsertApiCredential,
} from '../../../shared/schema';

// Referenced exports keep TS happy even while stubs are it.todo.
void createTestApiCredential;
void TEST_PEM_CERT;
void TEST_PEM_KEY;
void expect;

describe('apiAuthTypeEnum (Phase 10 — CRED-01)', () => {
  it('declara exatamente os 7 valores na ordem fixa', () => {
    expect(apiAuthTypeEnum.enumValues).toEqual([
      'api_key_header',
      'api_key_query',
      'bearer_jwt',
      'basic',
      'oauth2_client_credentials',
      'hmac',
      'mtls',
    ]);
  });

  it('usa nome de enum api_auth_type', () => {
    expect(apiAuthTypeEnum.enumName).toBe('api_auth_type');
  });
});

describe('apiCredentials pgTable (Phase 10 — CRED-01, CRED-02)', () => {
  const columns = getTableColumns(apiCredentials);
  const config = getTableConfig(apiCredentials);

  it('tem colunas comuns (id, name, description, authType, urlPattern, priority, apiId)', () => {
    expect(columns.id).toBeDefined();
    expect(columns.name).toBeDefined();
    expect(columns.name.notNull).toBe(true);
    expect(columns.description).toBeDefined();
    expect(columns.description.notNull).toBe(false);
    expect(columns.authType).toBeDefined();
    expect(columns.authType.notNull).toBe(true);
    expect(columns.urlPattern).toBeDefined();
    expect(columns.urlPattern.notNull).toBe(true);
    expect(columns.priority).toBeDefined();
    expect(columns.priority.notNull).toBe(true);
    expect(columns.apiId).toBeDefined();
    expect(columns.apiId.notNull).toBe(false);
  });

  it('tem crypto columns secretEncrypted + dekEncrypted notNull (CRED-02)', () => {
    expect(columns.secretEncrypted).toBeDefined();
    expect(columns.secretEncrypted.notNull).toBe(true);
    expect(columns.dekEncrypted).toBeDefined();
    expect(columns.dekEncrypted.notNull).toBe(true);
  });

  it('tem colunas por-tipo (nullable) para todos 7 auth types', () => {
    const perTypeCols = [
      'apiKeyHeaderName',
      'apiKeyQueryParam',
      'basicUsername',
      'bearerExpiresAt',
      'oauth2ClientId',
      'oauth2TokenUrl',
      'oauth2Scope',
      'oauth2Audience',
      'hmacKeyId',
      'hmacAlgorithm',
      'hmacSignatureHeader',
      'hmacSignedHeaders',
      'hmacCanonicalTemplate',
    ];
    for (const col of perTypeCols) {
      expect(columns[col as keyof typeof columns]).toBeDefined();
      expect(columns[col as keyof typeof columns].notNull).toBe(false);
    }
  });

  it('tem auditoria (createdAt, updatedAt, createdBy, updatedBy)', () => {
    expect(columns.createdAt.notNull).toBe(true);
    expect(columns.updatedAt.notNull).toBe(true);
    expect(columns.createdBy.notNull).toBe(true);
    expect(columns.updatedBy.notNull).toBe(false);
  });

  it('expõe os 3 indexes esperados', () => {
    const names = [...config.indexes.map((i) => i.config.name)];
    expect(names).toContain('IDX_api_credentials_api_id');
    expect(names).toContain('IDX_api_credentials_priority');
    expect(names).toContain('UQ_api_credentials_name_created_by');
  });

  it('usa tabela com nome api_credentials', () => {
    expect(config.name).toBe('api_credentials');
  });
});

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
