/**
 * Phase 12 Wave 3 — Route handler tests for:
 *   POST /api/v1/apis/:id/test/passive  (server/routes/apis.ts)
 *   GET  /api/v1/api-findings            (server/routes/apiFindings.ts)
 * Requirements: TEST-01, TEST-02
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import express from 'express';
import { createServer } from 'http';

// ── Mocks ────────────────────────────────────────────────────────────────────

const mockStorage = vi.hoisted(() => ({
  getApi: vi.fn(),
  logAudit: vi.fn().mockResolvedValue({}),
  listApiFindings: vi.fn().mockResolvedValue([]),
}));

vi.mock('../../storage', () => ({ storage: mockStorage }));

const mockRunApiPassiveTests = vi.hoisted(() =>
  vi.fn().mockResolvedValue({
    apiId: 'api-001',
    stagesRun: ['api9_inventory', 'nuclei_passive', 'auth_failure'],
    stagesSkipped: [],
    findingsCreated: 3,
    findingsUpdated: 0,
    findingsByCategory: {},
    findingsBySeverity: {},
    cancelled: false,
    dryRun: true,
    durationMs: 100,
  }),
);

vi.mock('../../services/journeys/apiPassiveTests', () => ({
  runApiPassiveTests: mockRunApiPassiveTests,
}));

// isAuthenticatedWithPasswordCheck — middleware mock
vi.mock('../../localAuth', () => ({
  isAuthenticatedWithPasswordCheck: (req: any, _res: any, next: any) => {
    if (req.headers['x-test-user']) {
      req.user = JSON.parse(req.headers['x-test-user']);
      return next();
    }
    return _res.status(401).json({ message: 'Não autenticado' });
  },
}));

// db + logger
vi.mock('../../db', () => ({ db: {} }));
vi.mock('../../lib/logger', () => ({
  createLogger: () => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }),
}));

// ── Test helpers ─────────────────────────────────────────────────────────────

function operatorUser() {
  return JSON.stringify({ id: 'user-op', role: 'operator' });
}

function readonlyUser() {
  return JSON.stringify({ id: 'user-ro', role: 'readonly_analyst' });
}

function adminUser() {
  return JSON.stringify({ id: 'user-adm', role: 'global_administrator' });
}

async function buildApp() {
  const { registerApiRoutes } = await import('../../routes/apis');
  const { registerApiFindingsRoutes } = await import('../../routes/apiFindings');
  const app = express();
  app.use(express.json());
  registerApiRoutes(app);
  registerApiFindingsRoutes(app);
  return app;
}

async function makeRequest(
  app: express.Application,
  method: string,
  path: string,
  opts: { user?: string; body?: unknown } = {},
) {
  const server = createServer(app);
  await new Promise<void>((r) => server.listen(0, r));
  const port = (server.address() as any).port;

  const init: RequestInit = { method };
  if (opts.user) (init as any).headers = { 'x-test-user': opts.user };
  if (opts.body) {
    (init as any).headers = { ...(init as any).headers, 'content-type': 'application/json' };
    init.body = JSON.stringify(opts.body);
  }

  const res = await fetch(`http://localhost:${port}${path}`, init);
  const body = await res.json().catch(() => null);
  server.close();
  return { status: res.status, body };
}

// ── Tests: POST /api/v1/apis/:id/test/passive ─────────────────────────────

describe('POST /api/v1/apis/:id/test/passive', () => {
  let app: express.Application;

  beforeEach(async () => {
    vi.clearAllMocks();
    app = await buildApp();
  });

  it('requires authentication (401 if not logged)', async () => {
    const { status } = await makeRequest(app, 'POST', '/api/v1/apis/api-001/test/passive');
    expect(status).toBe(401);
  });

  it('requires operator or global_administrator role (403 if readonly)', async () => {
    mockStorage.getApi.mockResolvedValue({ id: 'api-001' });
    const { status } = await makeRequest(app, 'POST', '/api/v1/apis/api-001/test/passive', {
      user: readonlyUser(),
      body: {},
    });
    expect(status).toBe(403);
  });

  it('rejects body with unknown field (.strict() Zod)', async () => {
    mockStorage.getApi.mockResolvedValue({ id: 'api-001' });
    const { status, body } = await makeRequest(app, 'POST', '/api/v1/apis/api-001/test/passive', {
      user: operatorUser(),
      body: { foo: 'bar' },
    });
    expect(status).toBe(400);
    expect(body.message).toContain('inválidas');
  });

  it('returns 404 when apiId does not exist', async () => {
    mockStorage.getApi.mockResolvedValue(null);
    const { status, body } = await makeRequest(app, 'POST', '/api/v1/apis/nonexistent/test/passive', {
      user: operatorUser(),
      body: {},
    });
    expect(status).toBe(404);
    expect(body.message).toBe('API não encontrada');
  });

  it('calls runApiPassiveTests with parsed opts + jobId', async () => {
    mockStorage.getApi.mockResolvedValue({ id: 'api-001' });
    await makeRequest(app, 'POST', '/api/v1/apis/api-001/test/passive', {
      user: operatorUser(),
      body: { dryRun: true },
    });
    expect(mockRunApiPassiveTests).toHaveBeenCalledOnce();
    const [calledApiId, calledOpts, calledJobId] = mockRunApiPassiveTests.mock.calls[0];
    expect(calledApiId).toBe('api-001');
    expect(calledOpts.dryRun).toBe(true);
    expect(typeof calledJobId).toBe('string');
    expect(calledJobId.length).toBeGreaterThan(10);
  });

  it('returns 201 with PassiveTestResult shape', async () => {
    mockStorage.getApi.mockResolvedValue({ id: 'api-001' });
    const { status, body } = await makeRequest(app, 'POST', '/api/v1/apis/api-001/test/passive', {
      user: operatorUser(),
      body: { dryRun: true },
    });
    expect(status).toBe(201);
    expect(body).toMatchObject({
      apiId: 'api-001',
      stagesRun: expect.any(Array),
      findingsCreated: expect.any(Number),
      findingsUpdated: expect.any(Number),
      cancelled: expect.any(Boolean),
      dryRun: expect.any(Boolean),
    });
  });
});

// ── Tests: GET /api/v1/api-findings ─────────────────────────────────────────

describe('GET /api/v1/api-findings', () => {
  let app: express.Application;

  beforeEach(async () => {
    vi.clearAllMocks();
    app = await buildApp();
  });

  it('requires at least one of apiId/endpointId/jobId (400 otherwise)', async () => {
    const { status, body } = await makeRequest(app, 'GET', '/api/v1/api-findings', {
      user: operatorUser(),
    });
    expect(status).toBe(400);
    expect(body.message).toContain('Forneça ao menos um filtro');
  });

  it('allows readonly_analyst role (RBAC expanded)', async () => {
    mockStorage.listApiFindings.mockResolvedValue([]);
    const { status } = await makeRequest(app, 'GET', '/api/v1/api-findings?apiId=7be49f9d-e4c3-4c08-9aab-000000000001', {
      user: readonlyUser(),
    });
    expect(status).toBe(200);
  });

  it('filters by owaspCategory/severity/status/jobId', async () => {
    const mockFinding = { id: 'f-1', owaspCategory: 'api2_broken_auth_2023', severity: 'high' };
    mockStorage.listApiFindings.mockResolvedValue([mockFinding]);
    const { status, body } = await makeRequest(
      app,
      'GET',
      '/api/v1/api-findings?apiId=7be49f9d-e4c3-4c08-9aab-000000000001&severity=high&status=open',
      { user: operatorUser() },
    );
    expect(status).toBe(200);
    expect(mockStorage.listApiFindings).toHaveBeenCalledWith(
      expect.objectContaining({ severity: 'high', status: 'open' }),
    );
    expect(body).toEqual([mockFinding]);
  });

  it('applies limit (default 50) + offset pagination', async () => {
    mockStorage.listApiFindings.mockResolvedValue([]);
    await makeRequest(
      app,
      'GET',
      '/api/v1/api-findings?apiId=7be49f9d-e4c3-4c08-9aab-000000000001&limit=10&offset=20',
      { user: operatorUser() },
    );
    expect(mockStorage.listApiFindings).toHaveBeenCalledWith(
      expect.objectContaining({ limit: 10, offset: 20 }),
    );
  });

  it('returns ApiFinding[] sanitized (no secret fields — api_findings has none natively)', async () => {
    const mockFindings = [
      { id: 'f-1', title: '[DRY-RUN] Test finding', owaspCategory: 'api9_inventory_2023', severity: 'low' },
    ];
    mockStorage.listApiFindings.mockResolvedValue(mockFindings);
    const { status, body } = await makeRequest(
      app,
      'GET',
      '/api/v1/api-findings?apiId=7be49f9d-e4c3-4c08-9aab-000000000001',
      { user: adminUser() },
    );
    expect(status).toBe(200);
    expect(body).toEqual(mockFindings);
  });
});
