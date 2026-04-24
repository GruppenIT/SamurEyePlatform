/**
 * Phase 16 — UI-02 Backend — GET /api/v1/apis/:id/endpoints
 *
 * Promoted from it.todo stubs by Plan 02.
 * Per 16-VALIDATION.md task map.
 *
 * Requirement: Return ApiEndpoint rows for a given apiId.
 * Auth required. 404 for unknown apiId. Ordered by path ASC, method ASC.
 */
import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import express, { type Express } from 'express';
import type { Server } from 'http';

const mocks = vi.hoisted(() => ({
  listApisWithEndpointCount: vi.fn(),
  getApi: vi.fn(),
  listEndpointsByApi: vi.fn(),
  logAudit: vi.fn(async () => ({ id: 'audit-1' })),
  createApi: vi.fn(),
}));

vi.mock('../../server/storage', () => ({
  storage: {
    listApisWithEndpointCount: mocks.listApisWithEndpointCount,
    getApi: mocks.getApi,
    listEndpointsByApi: mocks.listEndpointsByApi,
    logAudit: mocks.logAudit,
    createApi: mocks.createApi,
  },
}));

vi.mock('../../server/localAuth', () => ({
  isAuthenticatedWithPasswordCheck: (req: any, _res: any, next: any) => {
    req.user = { id: 'user-1', role: 'operator' };
    next();
  },
}));

vi.mock('../../server/routes/middleware', () => ({
  requireOperator: (_req: any, _res: any, next: any) => next(),
  requireAnyRole: (_req: any, _res: any, next: any) => next(),
}));

vi.mock('../../server/db', () => ({ db: {} }));

vi.mock('../../server/lib/logger', () => ({
  createLogger: () => ({
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
  }),
}));

vi.mock('../../server/services/journeys/apiDiscovery', () => ({ discoverApi: vi.fn() }));
vi.mock('../../server/services/journeys/apiPassiveTests', () => ({ runApiPassiveTests: vi.fn() }));
vi.mock('../../server/services/journeys/apiActiveTests', () => ({ runApiActiveTests: vi.fn() }));
vi.mock('../../server/services/threatPromotion', () => ({ promoteHighCriticalFindings: vi.fn() }));
vi.mock('../../server/services/jobEventBroadcaster', () => ({
  jobEventBroadcaster: { subscribe: vi.fn(), unsubscribe: vi.fn(), emit: vi.fn() },
}));
vi.mock('../../server/services/journeys/urls', () => ({ normalizeTarget: vi.fn((u: string) => u) }));
vi.mock('../../shared/sanitization', () => ({ sanitizeApiFinding: vi.fn((f: any) => f) }));

async function buildApp(): Promise<Express> {
  const app = express();
  app.use(express.json());
  const { registerApiRoutes } = await import('../../server/routes/apis');
  registerApiRoutes(app);
  return app;
}

describe('GET /api/v1/apis/:id/endpoints', () => {
  let server: Server;
  let baseUrl: string;

  beforeAll(async () => {
    const app = await buildApp();
    server = app.listen(0);
    const addr = server.address();
    const port = typeof addr === 'object' && addr ? addr.port : 0;
    baseUrl = `http://localhost:${port}`;
  });

  afterAll(() => {
    server?.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns 404 when apiId does not exist in DB', async () => {
    mocks.getApi.mockResolvedValue(undefined);

    const res = await fetch(`${baseUrl}/api/v1/apis/non-existent-id/endpoints`);
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.message).toBe('API não encontrada');
  });

  it('returns 200 with array of ApiEndpoint rows filtered by apiId', async () => {
    mocks.getApi.mockResolvedValue({ id: 'api-1', baseUrl: 'https://api.example.com' });
    mocks.listEndpointsByApi.mockResolvedValue([
      { id: 'ep-1', apiId: 'api-1', method: 'GET', path: '/users', pathParams: [], queryParams: [], headerParams: [], requiresAuth: false, discoverySources: ['spec'] },
      { id: 'ep-2', apiId: 'api-1', method: 'POST', path: '/users', pathParams: [], queryParams: [], headerParams: [], requiresAuth: true, discoverySources: ['crawler'] },
    ]);

    const res = await fetch(`${baseUrl}/api/v1/apis/api-1/endpoints`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body)).toBe(true);
    expect(body).toHaveLength(2);
    expect(body[0].path).toBe('/users');
  });

  it('returns empty array [] when API exists but has no endpoints', async () => {
    mocks.getApi.mockResolvedValue({ id: 'api-1', baseUrl: 'https://api.example.com' });
    mocks.listEndpointsByApi.mockResolvedValue([]);

    const res = await fetch(`${baseUrl}/api/v1/apis/api-1/endpoints`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body)).toBe(true);
    expect(body).toHaveLength(0);
  });

  it('returns 500 when listEndpointsByApi throws', async () => {
    mocks.getApi.mockResolvedValue({ id: 'api-1', baseUrl: 'https://api.example.com' });
    mocks.listEndpointsByApi.mockRejectedValue(new Error('DB error'));

    const res = await fetch(`${baseUrl}/api/v1/apis/api-1/endpoints`);
    expect(res.status).toBe(500);
  });

  it.todo('returns 401 when request has no authentication');
  it.todo('rows are ordered by path ASC then method ASC (deterministic for UI path-grouping)');
});
