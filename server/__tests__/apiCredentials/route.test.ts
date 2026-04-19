/**
 * Phase 10 — CRED-01, CRED-05: tests for POST|GET|PATCH|DELETE /api/v1/api-credentials.
 *
 * Strategy:
 *   - Mock `../../storage` to intercept facade calls with spyable fn implementations.
 *   - Mock `../../localAuth` so isAuthenticatedWithPasswordCheck is a trivial middleware
 *     that honors a header-injected user (used by each test via `runReq` helper).
 *   - Mount registerApiCredentialsRoutes on a plain express() app and exercise
 *     via an in-process HTTP server + native fetch (Node 20+).
 *   - Capture log output for the "logging seguro" assertion.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import type { Server } from 'http';
import express from 'express';
import { createTestApiCredential } from '../helpers/apiCredentialFactory';

// --- Storage mock ------------------------------------------------------------
// All 5 storage methods the route consumes are vi.fn() so each test can
// configure mockResolvedValue / mockRejectedValue / mockImplementation.

const storageMock = vi.hoisted(() => ({
  createApiCredential: vi.fn(),
  listApiCredentials: vi.fn(),
  getApiCredential: vi.fn(),
  updateApiCredential: vi.fn(),
  deleteApiCredential: vi.fn(),
}));

vi.mock('../../storage', () => ({
  storage: storageMock,
}));

// --- Auth middleware mock ----------------------------------------------------
// isAuthenticatedWithPasswordCheck pulls a user off the request when the
// test has injected one via `__testUser` (set by a prior middleware below).
// Otherwise it returns 401.

vi.mock('../../localAuth', () => ({
  isAuthenticatedWithPasswordCheck: (req: any, res: any, next: any) => {
    if (!req.user) {
      return res.status(401).json({ message: 'Não autenticado' });
    }
    next();
  },
}));

// --- Capture logger output ---------------------------------------------------
// Spy on console-style destinations by hooking createLogger? Simpler: replace
// the logger with a spyable one.

const logCapture = vi.hoisted(() => {
  const events: Array<{ level: string; obj: any; msg?: string }> = [];
  const logger = {
    info: (obj: any, msg?: string) => events.push({ level: 'info', obj, msg }),
    warn: (obj: any, msg?: string) => events.push({ level: 'warn', obj, msg }),
    error: (obj: any, msg?: string) => events.push({ level: 'error', obj, msg }),
    debug: (obj: any, msg?: string) => events.push({ level: 'debug', obj, msg }),
  };
  return { events, logger };
});

vi.mock('../../lib/logger', () => ({
  createLogger: () => logCapture.logger,
}));

// --- Now import the route under test ----------------------------------------
// Defer import until after mocks are in place (vi.mock is hoisted, but clearer).
import { registerApiCredentialsRoutes } from '../../routes/apiCredentials';

// --- In-process HTTP server + fetch helper ----------------------------------

let server: Server;
let baseUrl: string;

/**
 * Each request can supply a synthetic user. The injector middleware sets
 * req.user when the X-Test-Role header is present.
 */
function userInjector(req: any, _res: any, next: any) {
  const role = req.headers['x-test-role'];
  const id = req.headers['x-test-user-id'] ?? 'user-tester';
  if (typeof role === 'string' && role.length > 0) {
    req.user = { id, role };
  }
  next();
}

beforeAll(async () => {
  const app = express();
  app.use(express.json());
  app.use(userInjector);
  registerApiCredentialsRoutes(app);
  await new Promise<void>((resolve) => {
    server = app.listen(0, () => resolve());
  });
  const addr = server.address();
  if (!addr || typeof addr === 'string') throw new Error('no address');
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
});

beforeEach(() => {
  storageMock.createApiCredential.mockReset();
  storageMock.listApiCredentials.mockReset();
  storageMock.getApiCredential.mockReset();
  storageMock.updateApiCredential.mockReset();
  storageMock.deleteApiCredential.mockReset();
  logCapture.events.length = 0;
});

// Helper: build a sanitized ApiCredentialSafe row from a payload
function safeRowFor(payload: any, overrides: Record<string, unknown> = {}) {
  // Intentionally mirror SAFE_FIELDS columns (no secretEncrypted, no dekEncrypted, no secret/mtls*)
  const base: Record<string, unknown> = {
    id: 'cred-fixed-uuid',
    name: payload.name,
    description: payload.description ?? null,
    authType: payload.authType,
    urlPattern: payload.urlPattern ?? '*',
    priority: payload.priority ?? 100,
    apiId: payload.apiId ?? null,
    apiKeyHeaderName: payload.apiKeyHeaderName ?? null,
    apiKeyQueryParam: payload.apiKeyQueryParam ?? null,
    basicUsername: payload.basicUsername ?? null,
    bearerExpiresAt: null,
    oauth2ClientId: payload.oauth2ClientId ?? null,
    oauth2TokenUrl: payload.oauth2TokenUrl ?? null,
    oauth2Scope: payload.oauth2Scope ?? null,
    oauth2Audience: payload.oauth2Audience ?? null,
    hmacKeyId: payload.hmacKeyId ?? null,
    hmacAlgorithm: payload.hmacAlgorithm ?? null,
    hmacSignatureHeader: payload.hmacSignatureHeader ?? null,
    hmacSignedHeaders: payload.hmacSignedHeaders ?? null,
    hmacCanonicalTemplate: payload.hmacCanonicalTemplate ?? null,
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
    createdBy: 'user-tester',
    updatedBy: null,
  };
  return { ...base, ...overrides };
}

async function post(path: string, body: any, headers: Record<string, string> = {}) {
  return fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}
async function get(path: string, headers: Record<string, string> = {}) {
  return fetch(`${baseUrl}${path}`, { headers });
}
async function patch(path: string, body: any, headers: Record<string, string> = {}) {
  return fetch(`${baseUrl}${path}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}
async function del(path: string, headers: Record<string, string> = {}) {
  return fetch(`${baseUrl}${path}`, { method: 'DELETE', headers });
}

const OPERATOR_HEADERS = { 'X-Test-Role': 'operator' };
const ADMIN_HEADERS = { 'X-Test-Role': 'global_administrator' };
const READONLY_HEADERS = { 'X-Test-Role': 'read_only' };

// ----------------------------------------------------------------------------
// POST /api/v1/api-credentials — 7 auth types happy path
// ----------------------------------------------------------------------------
describe('POST /api/v1/api-credentials — contrato dos 7 auth types', () => {
  const TYPES = [
    'api_key_header',
    'api_key_query',
    'bearer_jwt',
    'basic',
    'oauth2_client_credentials',
    'hmac',
    'mtls',
  ] as const;

  for (const authType of TYPES) {
    it(`POST ${authType} retorna 201 com id, name, authType, urlPattern, priority, createdAt`, async () => {
      const payload = createTestApiCredential(authType) as any;
      const safe = safeRowFor(payload);
      storageMock.createApiCredential.mockResolvedValue(safe);

      const res = await post('/api/v1/api-credentials', payload, OPERATOR_HEADERS);
      expect(res.status).toBe(201);
      const body = await res.json();
      expect(body.id).toBeDefined();
      expect(body.name).toBe(payload.name);
      expect(body.authType).toBe(authType);
      expect(body.urlPattern).toBeDefined();
      expect(body.priority).toBeDefined();
      expect(body.createdAt).toBeDefined();
    });
  }
});

// ----------------------------------------------------------------------------
// Sanitization
// ----------------------------------------------------------------------------
describe('POST /api/v1/api-credentials — sanitizacao', () => {
  it('response 201 NUNCA contem secretEncrypted nem dekEncrypted', async () => {
    const payload = createTestApiCredential('api_key_header') as any;
    storageMock.createApiCredential.mockResolvedValue(safeRowFor(payload));
    const res = await post('/api/v1/api-credentials', payload, OPERATOR_HEADERS);
    expect(res.status).toBe(201);
    const body = await res.json();
    const keys = Object.keys(body);
    expect(keys).not.toContain('secretEncrypted');
    expect(keys).not.toContain('dekEncrypted');
  });

  it('response 201 NUNCA contem secret, mtlsCert, mtlsKey, mtlsCa em texto puro', async () => {
    const payload = createTestApiCredential('mtls') as any;
    storageMock.createApiCredential.mockResolvedValue(safeRowFor(payload));
    const res = await post('/api/v1/api-credentials', payload, OPERATOR_HEADERS);
    expect(res.status).toBe(201);
    const body = await res.json();
    const keys = Object.keys(body);
    expect(keys).not.toContain('secret');
    expect(keys).not.toContain('mtlsCert');
    expect(keys).not.toContain('mtlsKey');
    expect(keys).not.toContain('mtlsCa');
  });
});

// ----------------------------------------------------------------------------
// Error codes
// ----------------------------------------------------------------------------
describe('POST /api/v1/api-credentials — codigos de erro', () => {
  it('POST com payload invalido (Zod fail) retorna 400 com "Dados de credencial invalidos"', async () => {
    const res = await post('/api/v1/api-credentials', { name: 'no-auth-type' }, OPERATOR_HEADERS);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.message).toBe('Dados de credencial inválidos');
    expect(storageMock.createApiCredential).not.toHaveBeenCalled();
  });

  it('POST com urlPattern invalido (**) retorna 400 com "URL pattern invalido"', async () => {
    const payload = createTestApiCredential('api_key_header', { urlPattern: '**' }) as any;
    const res = await post('/api/v1/api-credentials', payload, OPERATOR_HEADERS);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.message).toBe('URL pattern inválido');
    expect(storageMock.createApiCredential).not.toHaveBeenCalled();
  });

  it('POST duplicado retorna 409 com "Credencial ja cadastrada com esse nome"', async () => {
    const payload = createTestApiCredential('api_key_header') as any;
    const err: any = new Error('duplicate');
    err.code = '23505';
    storageMock.createApiCredential.mockRejectedValue(err);
    const res = await post('/api/v1/api-credentials', payload, OPERATOR_HEADERS);
    expect(res.status).toBe(409);
    const body = await res.json();
    expect(body.message).toBe('Credencial já cadastrada com esse nome');
  });

  it('POST sem autenticacao retorna 401', async () => {
    const payload = createTestApiCredential('api_key_header') as any;
    const res = await post('/api/v1/api-credentials', payload); // no role header → no user
    expect(res.status).toBe(401);
    expect(storageMock.createApiCredential).not.toHaveBeenCalled();
  });

  it('POST com role read_only retorna 403', async () => {
    const payload = createTestApiCredential('api_key_header') as any;
    const res = await post('/api/v1/api-credentials', payload, READONLY_HEADERS);
    expect(res.status).toBe(403);
    expect(storageMock.createApiCredential).not.toHaveBeenCalled();
  });

  it('POST com role operator retorna 201', async () => {
    const payload = createTestApiCredential('api_key_header') as any;
    storageMock.createApiCredential.mockResolvedValue(safeRowFor(payload));
    const res = await post('/api/v1/api-credentials', payload, OPERATOR_HEADERS);
    expect(res.status).toBe(201);
  });

  it('POST com role global_administrator retorna 201', async () => {
    const payload = createTestApiCredential('api_key_header') as any;
    storageMock.createApiCredential.mockResolvedValue(safeRowFor(payload));
    const res = await post('/api/v1/api-credentials', payload, ADMIN_HEADERS);
    expect(res.status).toBe(201);
  });
});

// ----------------------------------------------------------------------------
// bearer_jwt exp
// ----------------------------------------------------------------------------
describe('POST /api/v1/api-credentials — bearer_jwt exp passthrough', () => {
  it('bearer_jwt com exp valido: response reflete bearerExpiresAt ISO string quando facade popula', async () => {
    const payload = createTestApiCredential('bearer_jwt') as any;
    const bearerExpiresAt = new Date(9999999999 * 1000);
    storageMock.createApiCredential.mockResolvedValue(
      safeRowFor(payload, { bearerExpiresAt }),
    );
    const res = await post('/api/v1/api-credentials', payload, OPERATOR_HEADERS);
    expect(res.status).toBe(201);
    const body = await res.json();
    // Express JSON serializes Date → ISO string; reconstruct as Date.
    expect(body.bearerExpiresAt).toBeDefined();
    expect(new Date(body.bearerExpiresAt).getTime()).toBe(9999999999 * 1000);
  });

  it('bearer_jwt opaco: 201 com bearerExpiresAt null', async () => {
    const payload = createTestApiCredential('bearer_jwt', { secret: 'opaque-token-no-dots' }) as any;
    storageMock.createApiCredential.mockResolvedValue(
      safeRowFor(payload, { bearerExpiresAt: null }),
    );
    const res = await post('/api/v1/api-credentials', payload, OPERATOR_HEADERS);
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.bearerExpiresAt).toBeNull();
  });
});

// ----------------------------------------------------------------------------
// GET /api/v1/api-credentials (list)
// ----------------------------------------------------------------------------
describe('GET /api/v1/api-credentials (list)', () => {
  it('GET sem filter retorna 200 com lista sanitizada', async () => {
    const rows = [
      safeRowFor(createTestApiCredential('api_key_header')),
      safeRowFor(createTestApiCredential('basic')),
    ];
    storageMock.listApiCredentials.mockResolvedValue(rows);
    const res = await get('/api/v1/api-credentials', OPERATOR_HEADERS);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body)).toBe(true);
    expect(body.length).toBe(2);
    for (const r of body) {
      expect(Object.keys(r)).not.toContain('secretEncrypted');
      expect(Object.keys(r)).not.toContain('dekEncrypted');
    }
    expect(storageMock.listApiCredentials).toHaveBeenCalledWith({});
  });

  it('GET com filter ?apiId=X chama storage com apiId', async () => {
    storageMock.listApiCredentials.mockResolvedValue([]);
    const res = await get('/api/v1/api-credentials?apiId=api-42', OPERATOR_HEADERS);
    expect(res.status).toBe(200);
    expect(storageMock.listApiCredentials).toHaveBeenCalledWith({ apiId: 'api-42' });
  });

  it('GET com filter ?authType=basic chama storage com authType=basic', async () => {
    storageMock.listApiCredentials.mockResolvedValue([]);
    const res = await get('/api/v1/api-credentials?authType=basic', OPERATOR_HEADERS);
    expect(res.status).toBe(200);
    expect(storageMock.listApiCredentials).toHaveBeenCalledWith({ authType: 'basic' });
  });
});

// ----------------------------------------------------------------------------
// GET /api/v1/api-credentials/:id
// ----------------------------------------------------------------------------
describe('GET /api/v1/api-credentials/:id', () => {
  it('GET por id retorna 200 com row sanitizado', async () => {
    const row = safeRowFor(createTestApiCredential('api_key_header'), { id: 'cred-id-1' });
    storageMock.getApiCredential.mockResolvedValue(row);
    const res = await get('/api/v1/api-credentials/cred-id-1', OPERATOR_HEADERS);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.id).toBe('cred-id-1');
    expect(Object.keys(body)).not.toContain('secretEncrypted');
  });

  it('GET por id inexistente retorna 404 com "Credencial nao encontrada"', async () => {
    storageMock.getApiCredential.mockResolvedValue(undefined);
    const res = await get('/api/v1/api-credentials/nonexistent', OPERATOR_HEADERS);
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.message).toBe('Credencial não encontrada');
  });
});

// ----------------------------------------------------------------------------
// PATCH /api/v1/api-credentials/:id
// ----------------------------------------------------------------------------
describe('PATCH /api/v1/api-credentials/:id', () => {
  it('PATCH atualiza name + description sem tocar secret', async () => {
    const existing = safeRowFor(createTestApiCredential('api_key_header'), { id: 'c1' });
    storageMock.getApiCredential.mockResolvedValue(existing);
    storageMock.updateApiCredential.mockResolvedValue({ ...existing, name: 'novo-nome', description: 'desc atualizado' });
    const res = await patch('/api/v1/api-credentials/c1', { name: 'novo-nome', description: 'desc atualizado' }, OPERATOR_HEADERS);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.name).toBe('novo-nome');
    expect(body.description).toBe('desc atualizado');
    // Ensure storage not called with secret in payload
    expect(storageMock.updateApiCredential).toHaveBeenCalledWith('c1', { name: 'novo-nome', description: 'desc atualizado' }, 'user-tester');
  });

  it('PATCH com secret novo: storage recebe secret e facade re-encripta (contrato respeitado)', async () => {
    const existing = safeRowFor(createTestApiCredential('api_key_header'), { id: 'c2' });
    storageMock.getApiCredential.mockResolvedValue(existing);
    storageMock.updateApiCredential.mockResolvedValue(existing);
    const res = await patch('/api/v1/api-credentials/c2', { secret: 'rotated-secret-value' }, OPERATOR_HEADERS);
    expect(res.status).toBe(200);
    expect(storageMock.updateApiCredential).toHaveBeenCalledWith('c2', { secret: 'rotated-secret-value' }, 'user-tester');
  });

  it('PATCH com urlPattern invalido retorna 400', async () => {
    const res = await patch('/api/v1/api-credentials/c3', { urlPattern: '**' }, OPERATOR_HEADERS);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.message).toBe('URL pattern inválido');
    expect(storageMock.updateApiCredential).not.toHaveBeenCalled();
  });

  it('PATCH em id inexistente retorna 404', async () => {
    storageMock.getApiCredential.mockResolvedValue(undefined);
    const res = await patch('/api/v1/api-credentials/missing', { name: 'x' }, OPERATOR_HEADERS);
    expect(res.status).toBe(404);
    expect(storageMock.updateApiCredential).not.toHaveBeenCalled();
  });
});

// ----------------------------------------------------------------------------
// DELETE /api/v1/api-credentials/:id
// ----------------------------------------------------------------------------
describe('DELETE /api/v1/api-credentials/:id', () => {
  it('DELETE retorna 204', async () => {
    const existing = safeRowFor(createTestApiCredential('api_key_header'), { id: 'd1' });
    storageMock.getApiCredential.mockResolvedValue(existing);
    storageMock.deleteApiCredential.mockResolvedValue(undefined);
    const res = await del('/api/v1/api-credentials/d1', OPERATOR_HEADERS);
    expect(res.status).toBe(204);
    expect(storageMock.deleteApiCredential).toHaveBeenCalledWith('d1');
  });

  it('DELETE em id inexistente retorna 404', async () => {
    storageMock.getApiCredential.mockResolvedValue(undefined);
    const res = await del('/api/v1/api-credentials/nonexistent', OPERATOR_HEADERS);
    expect(res.status).toBe(404);
    expect(storageMock.deleteApiCredential).not.toHaveBeenCalled();
  });
});

// ----------------------------------------------------------------------------
// Logging seguro (Armadilha 3)
// ----------------------------------------------------------------------------
describe('logging seguro (Armadilha 3)', () => {
  it('log.info de criacao inclui apiCredentialId + authType + apiId e NAO inclui secret/mtls*/req.body', async () => {
    const payload = createTestApiCredential('mtls', { apiId: 'api-abc' }) as any;
    storageMock.createApiCredential.mockResolvedValue(safeRowFor(payload, { id: 'cred-mtls-1', apiId: 'api-abc' }));
    const res = await post('/api/v1/api-credentials', payload, OPERATOR_HEADERS);
    expect(res.status).toBe(201);

    // Assert a creation log line exists with the safe shape.
    const creations = logCapture.events.filter(
      (e) => e.level === 'info' && typeof e.msg === 'string' && e.msg.includes('api credential created'),
    );
    expect(creations.length).toBeGreaterThan(0);
    const creation = creations[0];
    expect(creation.obj.apiCredentialId).toBe('cred-mtls-1');
    expect(creation.obj.authType).toBe('mtls');
    expect(creation.obj.apiId).toBe('api-abc');

    // Assert NO log event contains sensitive fields from the request body.
    for (const event of logCapture.events) {
      const serialized = JSON.stringify(event);
      expect(serialized).not.toContain(payload.mtlsCert);
      expect(serialized).not.toContain(payload.mtlsKey);
      // No event should embed the full body as `body` or include all keys.
      expect(event.obj?.body).toBeUndefined();
    }
  });
});
