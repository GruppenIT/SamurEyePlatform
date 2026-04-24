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
    it('aceita api_key_header com apiKeyHeaderName + secret', () => {
      const payload = createTestApiCredential('api_key_header');
      expect(insertApiCredentialSchema.safeParse(payload).success).toBe(true);
    });
    it('aceita api_key_query com apiKeyQueryParam + secret', () => {
      const payload = createTestApiCredential('api_key_query');
      expect(insertApiCredentialSchema.safeParse(payload).success).toBe(true);
    });
    it('aceita bearer_jwt com secret (JWT string)', () => {
      const payload = createTestApiCredential('bearer_jwt');
      expect(insertApiCredentialSchema.safeParse(payload).success).toBe(true);
    });
    it('aceita basic com basicUsername + secret', () => {
      const payload = createTestApiCredential('basic');
      expect(insertApiCredentialSchema.safeParse(payload).success).toBe(true);
    });
    it('aceita oauth2_client_credentials com oauth2ClientId + oauth2TokenUrl + secret', () => {
      const payload = createTestApiCredential('oauth2_client_credentials');
      expect(insertApiCredentialSchema.safeParse(payload).success).toBe(true);
    });
    it('aceita hmac com hmacKeyId + hmacAlgorithm HMAC-SHA256 + secret', () => {
      const payload = createTestApiCredential('hmac');
      expect(insertApiCredentialSchema.safeParse(payload).success).toBe(true);
    });
    it('aceita mtls com mtlsCert + mtlsKey PEM (sem mtlsCa)', () => {
      const payload = createTestApiCredential('mtls');
      expect(insertApiCredentialSchema.safeParse(payload).success).toBe(true);
    });
    it('aceita mtls com mtlsCert + mtlsKey + mtlsCa todos PEM', () => {
      const payload = createTestApiCredential('mtls', {
        mtlsCa: TEST_PEM_CERT,
      });
      expect(insertApiCredentialSchema.safeParse(payload).success).toBe(true);
    });
  });

  describe('rejeita payload invalido', () => {
    it('rejeita authType desconhecido (ex: saml)', () => {
      const payload = { ...createTestApiCredential('basic'), authType: 'saml' };
      expect(insertApiCredentialSchema.safeParse(payload).success).toBe(false);
    });
    it('rejeita api_key_header sem apiKeyHeaderName', () => {
      const payload = createTestApiCredential('api_key_header', {
        apiKeyHeaderName: undefined,
      });
      expect(insertApiCredentialSchema.safeParse(payload).success).toBe(false);
    });
    it('rejeita api_key_header com secret string vazia', () => {
      const payload = createTestApiCredential('api_key_header', { secret: '' });
      expect(insertApiCredentialSchema.safeParse(payload).success).toBe(false);
    });
    it('rejeita api_key_query sem apiKeyQueryParam', () => {
      const payload = createTestApiCredential('api_key_query', {
        apiKeyQueryParam: undefined,
      });
      expect(insertApiCredentialSchema.safeParse(payload).success).toBe(false);
    });
    it('rejeita bearer_jwt sem secret', () => {
      const payload = createTestApiCredential('bearer_jwt', { secret: undefined });
      expect(insertApiCredentialSchema.safeParse(payload).success).toBe(false);
    });
    it('rejeita basic sem basicUsername', () => {
      const payload = createTestApiCredential('basic', { basicUsername: undefined });
      expect(insertApiCredentialSchema.safeParse(payload).success).toBe(false);
    });
    it('rejeita basic sem secret', () => {
      const payload = createTestApiCredential('basic', { secret: undefined });
      expect(insertApiCredentialSchema.safeParse(payload).success).toBe(false);
    });
    it('rejeita oauth2_client_credentials sem oauth2ClientId', () => {
      const payload = createTestApiCredential('oauth2_client_credentials', {
        oauth2ClientId: undefined,
      });
      expect(insertApiCredentialSchema.safeParse(payload).success).toBe(false);
    });
    it('rejeita oauth2_client_credentials com oauth2TokenUrl nao-URL', () => {
      const payload = createTestApiCredential('oauth2_client_credentials', {
        oauth2TokenUrl: 'not-a-url',
      });
      expect(insertApiCredentialSchema.safeParse(payload).success).toBe(false);
    });
    it('rejeita hmac sem hmacKeyId', () => {
      const payload = createTestApiCredential('hmac', { hmacKeyId: undefined });
      expect(insertApiCredentialSchema.safeParse(payload).success).toBe(false);
    });
    it('rejeita hmac com hmacAlgorithm nao suportado (ex: HMAC-MD5)', () => {
      const payload = createTestApiCredential('hmac', {
        hmacAlgorithm: 'HMAC-MD5',
      });
      expect(insertApiCredentialSchema.safeParse(payload).success).toBe(false);
    });
    it('rejeita mtls sem mtlsCert', () => {
      const payload = createTestApiCredential('mtls', { mtlsCert: undefined });
      expect(insertApiCredentialSchema.safeParse(payload).success).toBe(false);
    });
    it('rejeita mtls com mtlsCert string nao-PEM', () => {
      const payload = createTestApiCredential('mtls', {
        mtlsCert: 'not a PEM cert',
      });
      expect(insertApiCredentialSchema.safeParse(payload).success).toBe(false);
    });
    it('rejeita cross-type: bearer_jwt + apiKeyHeaderName presente (Armadilha 2)', () => {
      const payload = {
        ...createTestApiCredential('bearer_jwt'),
        apiKeyHeaderName: 'X-API-Key',
      };
      expect(insertApiCredentialSchema.safeParse(payload).success).toBe(false);
    });
  });
});

describe('patchApiCredentialSchema (Phase 10 — CRED-01)', () => {
  it('aceita patch vazio (todos campos opcionais)', () => {
    expect(patchApiCredentialSchema.safeParse({}).success).toBe(true);
  });
  it('aceita patch com name e priority', () => {
    expect(
      patchApiCredentialSchema.safeParse({ name: 'renamed', priority: 50 }).success,
    ).toBe(true);
  });
  it('rejeita oauth2TokenUrl invalida em patch', () => {
    expect(
      patchApiCredentialSchema.safeParse({ oauth2TokenUrl: 'not-a-url' }).success,
    ).toBe(false);
  });
  it('rejeita hmacAlgorithm invalido em patch', () => {
    expect(
      patchApiCredentialSchema.safeParse({ hmacAlgorithm: 'HMAC-MD5' }).success,
    ).toBe(false);
  });
});

describe('Tipos derivados (Phase 10)', () => {
  it('ApiCredential tem shape inferrido da tabela', () => {
    // Verificação estrutural: compile-time type check via asserção runtime
    const sample: ApiCredential = {
      id: 'uuid',
      name: 'sample',
      description: null,
      authType: 'basic',
      urlPattern: '*',
      priority: 100,
      apiId: null,
      secretEncrypted: 'enc',
      dekEncrypted: 'dek',
      apiKeyHeaderName: null,
      apiKeyQueryParam: null,
      basicUsername: 'u',
      bearerExpiresAt: null,
      oauth2ClientId: null,
      oauth2TokenUrl: null,
      oauth2Scope: null,
      oauth2Audience: null,
      hmacKeyId: null,
      hmacAlgorithm: null,
      hmacSignatureHeader: null,
      hmacSignedHeaders: null,
      hmacCanonicalTemplate: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: 'user-id',
      updatedBy: null,
    };
    expect(sample.authType).toBe('basic');
  });

  it('ApiCredentialSafe omite secretEncrypted e dekEncrypted', () => {
    // Compile-time: o tipo não permite esses campos; runtime só confirma uso
    const safe: ApiCredentialSafe = {
      id: 'uuid',
      name: 'sample',
      description: null,
      authType: 'basic',
      urlPattern: '*',
      priority: 100,
      apiId: null,
      apiKeyHeaderName: null,
      apiKeyQueryParam: null,
      basicUsername: 'u',
      bearerExpiresAt: null,
      oauth2ClientId: null,
      oauth2TokenUrl: null,
      oauth2Scope: null,
      oauth2Audience: null,
      hmacKeyId: null,
      hmacAlgorithm: null,
      hmacSignatureHeader: null,
      hmacSignedHeaders: null,
      hmacCanonicalTemplate: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: 'user-id',
      updatedBy: null,
    };
    expect('secretEncrypted' in safe).toBe(false);
  });

  it('ApiCredentialWithSecret == ApiCredential (interno, para executor)', () => {
    const withSecret: ApiCredentialWithSecret = {
      id: 'uuid',
      name: 'sample',
      description: null,
      authType: 'basic',
      urlPattern: '*',
      priority: 100,
      apiId: null,
      secretEncrypted: 'enc',
      dekEncrypted: 'dek',
      apiKeyHeaderName: null,
      apiKeyQueryParam: null,
      basicUsername: 'u',
      bearerExpiresAt: null,
      oauth2ClientId: null,
      oauth2TokenUrl: null,
      oauth2Scope: null,
      oauth2Audience: null,
      hmacKeyId: null,
      hmacAlgorithm: null,
      hmacSignatureHeader: null,
      hmacSignedHeaders: null,
      hmacCanonicalTemplate: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: 'user-id',
      updatedBy: null,
    };
    expect(withSecret.secretEncrypted).toBe('enc');
  });

  it('InsertApiCredential é inferrido de insertApiCredentialSchema', () => {
    const insertSample: InsertApiCredential = {
      name: 'sample',
      description: null,
      urlPattern: '*',
      priority: 100,
      apiId: null,
      authType: 'basic',
      basicUsername: 'user',
      secret: 'pass',
    };
    expect(insertSample.authType).toBe('basic');
  });
});
