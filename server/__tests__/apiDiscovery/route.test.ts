/**
 * Phase 11-07 — 8 tests for POST /api/v1/apis/:id/discover route.
 *
 * Strategy:
 *   - Mock `../../storage` (getApi + logAudit).
 *   - Mock `../../services/journeys/apiDiscovery` (discoverApi).
 *   - Mock `../../localAuth` so isAuthenticatedWithPasswordCheck is a trivial middleware.
 *   - Mount registerApiRoutes on a plain express() app and exercise
 *     via an in-process HTTP server + native fetch (Node 20+).
 *   - Capture log output for the "logging sem secrets" assertion.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import type { Server } from 'http';
import express from 'express';

// --- Storage mock ------------------------------------------------------------
const storageMock = vi.hoisted(() => ({
  getApi: vi.fn(),
  logAudit: vi.fn().mockResolvedValue(undefined),
  // Stub additional methods that might be pulled in transitively
  createApi: vi.fn(),
  getAsset: vi.fn(),
}));

vi.mock('../../storage', () => ({
  storage: storageMock,
}));

// --- discoverApi mock --------------------------------------------------------
const discoverApiMock = vi.hoisted(() => vi.fn());

vi.mock('../../services/journeys/apiDiscovery', () => ({
  discoverApi: discoverApiMock,
}));

// Transitive imports through middleware.ts / subscriptionService require DATABASE_URL.
vi.mock('../../db', () => ({ db: {}, pool: {} }));
vi.mock('../../services/subscriptionService', () => ({
  subscriptionService: { isReadOnly: () => false },
}));

// --- Auth middleware mock ----------------------------------------------------
vi.mock('../../localAuth', () => ({
  isAuthenticatedWithPasswordCheck: (req: any, res: any, next: any) => {
    if (!req.user) {
      return res.status(401).json({ message: 'Não autenticado' });
    }
    next();
  },
}));

// --- Capture logger output ---------------------------------------------------
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

// Mock urls service (used in existing POST /api/v1/apis handler)
vi.mock('../../services/journeys/urls', () => ({
  normalizeTarget: (url: string) => url,
}));

// Phase 14 additions — prevent heavy transitive chains from loading esbuild in vm context
vi.mock('../../services/journeys/apiPassiveTests', () => ({
  runApiPassiveTests: vi.fn().mockResolvedValue({}),
}));

vi.mock('../../services/journeys/apiActiveTests', () => ({
  runApiActiveTests: vi.fn().mockResolvedValue({}),
}));

vi.mock('../../services/threatPromotion', () => ({
  promoteHighCriticalFindings: vi.fn().mockResolvedValue({ promoted: 0, linked: 0, skipped: 0 }),
}));

vi.mock('../../services/jobEventBroadcaster', () => ({
  jobEventBroadcaster: { emit: vi.fn(), subscribe: vi.fn(), unsubscribe: vi.fn() },
}));

// --- Now import the route under test ----------------------------------------
import { registerApiRoutes } from '../../routes/apis';

// --- In-process HTTP server + fetch helper -----------------------------------
let server: Server;
let baseUrl: string;

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
  registerApiRoutes(app);
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
  storageMock.getApi.mockReset();
  storageMock.logAudit.mockReset().mockResolvedValue(undefined);
  discoverApiMock.mockReset();
  logCapture.events.length = 0;
});

// Helper
async function post(path: string, body: any, headers: Record<string, string> = {}) {
  return fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}

const OPERATOR_HEADERS = { 'X-Test-Role': 'operator' };
const ADMIN_HEADERS = { 'X-Test-Role': 'global_administrator' };
const READONLY_HEADERS = { 'X-Test-Role': 'read_only' };

const API_ID = 'api-uuid-test-1234';
const DISCOVER_PATH = `/api/v1/apis/${API_ID}/discover`;

const MOCK_DISCOVERY_RESULT = {
  apiId: API_ID,
  stagesRun: ['spec', 'httpx'] as const,
  stagesSkipped: [],
  endpointsDiscovered: 5,
  endpointsUpdated: 0,
  endpointsStale: [],
  specFetched: {
    url: 'https://example.com/openapi.json',
    version: '3.0.0',
    hash: 'abc123',
    driftDetected: false,
  },
  cancelled: false,
  durationMs: 420,
};

// ---------------------------------------------------------------------------
// Test 1: 401 when unauthenticated
// ---------------------------------------------------------------------------
describe('POST /api/v1/apis/:id/discover', () => {
  it('401 when unauthenticated', async () => {
    const res = await post(DISCOVER_PATH, {});
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.message).toBe('Não autenticado');
    expect(storageMock.getApi).not.toHaveBeenCalled();
    expect(discoverApiMock).not.toHaveBeenCalled();
  });

  // Test 2: 403 when user role is read_only
  it('403 when user role is read_only', async () => {
    const res = await post(DISCOVER_PATH, {}, READONLY_HEADERS);
    expect(res.status).toBe(403);
    expect(discoverApiMock).not.toHaveBeenCalled();
  });

  // Test 3: accepts roles global_administrator and operator
  it('accepts roles global_administrator and operator', async () => {
    storageMock.getApi.mockResolvedValue({ id: API_ID, baseUrl: 'https://example.com' });
    discoverApiMock.mockResolvedValue(MOCK_DISCOVERY_RESULT);

    const resOp = await post(DISCOVER_PATH, {}, OPERATOR_HEADERS);
    expect(resOp.status).toBe(202);

    discoverApiMock.mockReset();
    storageMock.getApi.mockResolvedValue({ id: API_ID, baseUrl: 'https://example.com' });
    discoverApiMock.mockResolvedValue(MOCK_DISCOVERY_RESULT);

    const resAdmin = await post(DISCOVER_PATH, {}, ADMIN_HEADERS);
    expect(resAdmin.status).toBe(202);
  });

  // Test 4: 400 when body fails discoverApiOptsSchema Zod parse
  it('400 when body fails discoverApiOptsSchema Zod parse', async () => {
    // arjun=true without arjunEndpointIds triggers superRefine cross-field error
    const res = await post(
      DISCOVER_PATH,
      { stages: { arjun: true } },
      OPERATOR_HEADERS,
    );
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.message).toBe('Dados inválidos para discovery');
    expect(body.details).toBeDefined();
    expect(discoverApiMock).not.toHaveBeenCalled();
  });

  // Test 5: 404 when apiId does not exist
  it('404 when apiId does not exist', async () => {
    storageMock.getApi.mockResolvedValue(undefined);
    const res = await post(DISCOVER_PATH, {}, OPERATOR_HEADERS);
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.message).toBe('API não encontrada');
    expect(discoverApiMock).not.toHaveBeenCalled();
  });

  // Test 6: 202 accepted + returns jobId when discoverApi starts successfully
  it('202 accepted + returns jobId and result when discoverApi succeeds', async () => {
    storageMock.getApi.mockResolvedValue({ id: API_ID, baseUrl: 'https://example.com' });
    discoverApiMock.mockResolvedValue(MOCK_DISCOVERY_RESULT);

    const res = await post(DISCOVER_PATH, { dryRun: true }, OPERATOR_HEADERS);
    expect(res.status).toBe(202);
    const body = await res.json();
    expect(body.jobId).toBeDefined();
    expect(typeof body.jobId).toBe('string');
    // UUID format
    expect(body.jobId).toMatch(/^[0-9a-f-]{36}$/i);
    expect(body.result).toBeDefined();
    expect(body.result.apiId).toBe(API_ID);
    expect(body.result.endpointsDiscovered).toBe(5);

    // discoverApi was called with the correct apiId and a valid jobId
    expect(discoverApiMock).toHaveBeenCalledOnce();
    const [calledApiId, calledOpts, calledJobId] = discoverApiMock.mock.calls[0];
    expect(calledApiId).toBe(API_ID);
    expect(calledOpts.dryRun).toBe(true);
    expect(calledJobId).toBe(body.jobId);

    // Audit log was called
    expect(storageMock.logAudit).toHaveBeenCalledOnce();
    const auditCall = storageMock.logAudit.mock.calls[0][0];
    expect(auditCall.action).toBe('discover');
    expect(auditCall.objectType).toBe('api');
    expect(auditCall.objectId).toBe(API_ID);
  });

  // Test 7: 500 with pt-BR message on internal failure
  it('500 with pt-BR message on internal failure', async () => {
    storageMock.getApi.mockResolvedValue({ id: API_ID, baseUrl: 'https://example.com' });
    discoverApiMock.mockRejectedValue(new Error('scanner crashed'));

    const res = await post(DISCOVER_PATH, {}, OPERATOR_HEADERS);
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.message).toBe('Falha ao executar discovery');
  });

  // Test 8: log.info uses apiId, userId, opts.stages — never secrets
  it('log.info uses apiId, userId, jobId, stages — never secret values', async () => {
    storageMock.getApi.mockResolvedValue({ id: API_ID, baseUrl: 'https://example.com' });
    discoverApiMock.mockResolvedValue(MOCK_DISCOVERY_RESULT);

    await post(
      DISCOVER_PATH,
      { stages: { spec: true, crawler: false, kiterunner: false, httpx: true, arjun: false } },
      { ...OPERATOR_HEADERS, 'X-Test-User-Id': 'user-op-42' },
    );

    // Find the "discovery requested" log event
    const infoEvents = logCapture.events.filter(
      (e) => e.level === 'info' && e.msg === 'discovery requested',
    );
    expect(infoEvents.length).toBeGreaterThan(0);
    const logEvent = infoEvents[0];

    // Must include safe fields
    expect(logEvent.obj.apiId).toBe(API_ID);
    expect(logEvent.obj.userId).toBe('user-op-42');
    expect(logEvent.obj.jobId).toBeDefined();
    expect(logEvent.obj.stages).toBeDefined();

    // Must NOT include credential values or authorization headers
    const serialized = JSON.stringify(logCapture.events);
    expect(serialized).not.toContain('secretEncrypted');
    expect(serialized).not.toContain('dekEncrypted');
    expect(serialized).not.toContain('authorization');
    // req.body must not be logged wholesale
    for (const e of logCapture.events) {
      expect(e.obj?.body).toBeUndefined();
    }
  });
});
