// Phase 10 Wave 0 — fixtures compartilhadas para testes de api_credentials.
// Não importa código de produção; serve como fonte única de verdade para payloads de teste.

export type ApiAuthType =
  | 'api_key_header'
  | 'api_key_query'
  | 'bearer_jwt'
  | 'basic'
  | 'oauth2_client_credentials'
  | 'hmac'
  | 'mtls';

export const TEST_PEM_CERT =
  '-----BEGIN CERTIFICATE-----\nMIIBpTCCAQ+gAwIBAgIUtest\n-----END CERTIFICATE-----';

export const TEST_PEM_KEY =
  '-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBgkqtest\n-----END PRIVATE KEY-----';

export function createTestApiCredential(
  authType: ApiAuthType,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const base = {
    name: `test-${authType}-cred`,
    description: null,
    urlPattern: '*',
    priority: 100,
    apiId: null,
  };

  const typeFields: Record<ApiAuthType, Record<string, unknown>> = {
    api_key_header: {
      authType,
      apiKeyHeaderName: 'X-API-Key',
      secret: 'test-api-key-value',
    },
    api_key_query: {
      authType,
      apiKeyQueryParam: 'api_key',
      secret: 'test-api-key-value',
    },
    bearer_jwt: {
      authType,
      secret:
        'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiZXhwIjo5OTk5OTk5OTk5fQ.sig',
    },
    basic: {
      authType,
      basicUsername: 'testuser',
      secret: 'testpassword',
    },
    oauth2_client_credentials: {
      authType,
      oauth2ClientId: 'test-client-id',
      oauth2TokenUrl: 'https://auth.example.com/oauth/token',
      oauth2Scope: 'read:api',
      oauth2Audience: 'https://api.example.com',
      secret: 'test-client-secret',
    },
    hmac: {
      authType,
      hmacKeyId: 'key-2024-01',
      hmacAlgorithm: 'HMAC-SHA256',
      hmacSignatureHeader: 'Authorization',
      hmacSignedHeaders: ['host', 'x-date'],
      hmacCanonicalTemplate: null,
      secret: 'test-hmac-secret-key',
    },
    mtls: {
      authType,
      mtlsCert: TEST_PEM_CERT,
      mtlsKey: TEST_PEM_KEY,
      mtlsCa: null,
    },
  };

  return { ...base, ...typeFields[authType], ...overrides };
}

// Matriz de URL patterns para testes de matchUrlPattern
// [pattern, url, expected, description]
//
// Algoritmo autoritativo (CONTEXT.md linhas 90-93 e RESEARCH.md Padrão 5):
//   `*` em pattern = `[^/]*` → NÃO cruza `/`. Uniforme para host e path.
//   Pattern `*` sozinho também é `[^/]*` (e portanto não casa URLs com `/`).
//
// Nota (Phase 10 Plan 03): entries originais do factory continham URLs que
// exigiriam `*` cruzar `/` (e.g. `/v2/users` com pattern `.../com/*`),
// o que contradiz a regra do algoritmo. Ajuste aplicado aqui alinha a
// matriz com o algoritmo canônico, preservando a intenção dos rationales.
export const URL_PATTERN_MATRIX: Array<[string, string, boolean, string]> = [
  [
    '*',
    'https://any.url/path',
    true,
    'wildcard global casa qualquer URL (caso especial)',
  ],
  [
    'https://api.corp.com/*',
    'https://api.corp.com/users',
    true,
    'glob path de um segmento casa',
  ],
  [
    'https://api.corp.com/*',
    'https://api.corp.com/v2/users',
    false,
    'glob nao cruza barra (2 segmentos)',
  ],
  [
    'https://api.corp.com/v2/*',
    'https://api.corp.com/v2/users/123',
    false,
    'glob nao cruza barra (deep, 2 segmentos extras)',
  ],
  [
    'https://*.prod.example.com/*',
    'https://api.prod.example.com/v1',
    true,
    'glob no host casa',
  ],
  [
    'https://*.prod.example.com/*',
    'https://api.staging.example.com/v1',
    false,
    'host diferente nao casa',
  ],
  [
    'https://api.corp.com/v2/users',
    'https://api.corp.com/v2/users',
    true,
    'match exato casa',
  ],
  [
    'https://api.corp.com/v2/users',
    'https://api.corp.com/v2/users/',
    false,
    'trailing slash nao casa',
  ],
  [
    'https://api.corp.com/v2/users/{id}',
    'https://api.corp.com/v2/users/{id}',
    true,
    'path params literais casam literalmente',
  ],
];

// Casos para isValidUrlPattern — [pattern, expected, description]
export const VALID_PATTERN_CASES: Array<[string, boolean, string]> = [
  ['**', false, 'duplo asterisco rejeitado por ambiguidade'],
  ['', false, 'string vazia rejeitada'],
  ['https://api.corp.com/*', true, 'pattern com wildcard valido'],
  ['*', true, 'wildcard global valido'],
];
