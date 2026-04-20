/**
 * Phase 16 — UI-01 Backend — GET /api/v1/apis
 *
 * Promoted from it.todo stubs by Plan 02.
 * Per 16-VALIDATION.md task map.
 *
 * Requirement: List all discovered APIs with computed endpointCount.
 * Auth required (any role). Returns array.
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

describe('GET /api/v1/apis', () => {
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

  it('returns 200 with array of APIs when authenticated as operator role', async () => {
    mocks.listApisWithEndpointCount.mockResolvedValue([
      {
        id: 'a1',
        baseUrl: 'https://api.example.com',
        apiType: 'rest',
        discoveryMethod: 'manual',
        endpointCount: 3,
        lastExecutionAt: null,
        createdAt: new Date('2026-01-01').toISOString(),
        updatedAt: new Date('2026-01-01').toISOString(),
      },
    ]);

    const res = await fetch(`${baseUrl}/api/v1/apis`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body)).toBe(true);
    expect(body).toHaveLength(1);
    expect(body[0].id).toBe('a1');
  });

  it('response rows include endpointCount field as numeric', async () => {
    mocks.listApisWithEndpointCount.mockResolvedValue([
      {
        id: 'a1',
        baseUrl: 'https://api.example.com',
        apiType: 'rest',
        discoveryMethod: 'manual',
        endpointCount: 3,
        lastExecutionAt: null,
        createdAt: new Date('2026-01-01').toISOString(),
        updatedAt: new Date('2026-01-01').toISOString(),
      },
    ]);

    const res = await fetch(`${baseUrl}/api/v1/apis`);
    const body = await res.json();
    expect(typeof body[0].endpointCount).toBe('number');
    expect(body[0].endpointCount).toBe(3);
  });

  it('returns empty array [] when no APIs exist in DB', async () => {
    mocks.listApisWithEndpointCount.mockResolvedValue([]);

    const res = await fetch(`${baseUrl}/api/v1/apis`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body)).toBe(true);
    expect(body).toHaveLength(0);
  });

  it('returns 500 when storage throws', async () => {
    mocks.listApisWithEndpointCount.mockRejectedValue(new Error('DB connection error'));

    const res = await fetch(`${baseUrl}/api/v1/apis`);
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.message).toBeDefined();
  });

  it.todo('returns 401 when request has no authentication');
  it.todo('readonly_analyst role can also access the endpoint (GET is read-only)');
  it.todo('Zod rejects unknown query params (strict filter shape — no extra fields allowed)');
});
