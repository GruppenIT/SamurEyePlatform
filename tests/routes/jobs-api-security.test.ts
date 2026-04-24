/**
 * Phase 16 — UI-06 Backend — POST /api/v1/jobs (api_security type)
 *
 * Promoted from it.todo stubs — Plan 05.
 * Per 16-VALIDATION.md task map.
 *
 * Requirement: POST /api/v1/jobs with type=api_security.
 * authorizationAck=false returns 400 with pt-BR message.
 * Full config payload (stage toggles, rateLimit, dryRun) persisted to journey.params.
 * Audit log written. dryRun=true skips actual scanners.
 */
import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import express, { type Express } from 'express';
import type { Server } from 'http';

const mocks = vi.hoisted(() => ({
  createJourney: vi.fn(),
  executeJobNow: vi.fn(),
  logAudit: vi.fn(async () => ({ id: 'audit-1' })),
  getJob: vi.fn(),
  getJobs: vi.fn(async () => []),
  getJobResult: vi.fn(),
  updateJob: vi.fn(),
  listApisWithEndpointCount: vi.fn(async () => []),
  getApi: vi.fn(),
  listEndpointsByApi: vi.fn(async () => []),
  createApi: vi.fn(),
  listApisByParent: vi.fn(),
}));

vi.mock('../../server/storage', () => ({
  storage: {
    createJourney: mocks.createJourney,
    logAudit: mocks.logAudit,
    getJob: mocks.getJob,
    getJobs: mocks.getJobs,
    getJobResult: mocks.getJobResult,
    updateJob: mocks.updateJob,
    listApisWithEndpointCount: mocks.listApisWithEndpointCount,
    getApi: mocks.getApi,
    listEndpointsByApi: mocks.listEndpointsByApi,
    createApi: mocks.createApi,
    listApisByParent: mocks.listApisByParent,
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

vi.mock('../../server/services/jobQueue', () => ({
  jobQueue: {
    executeJobNow: mocks.executeJobNow,
    markJobAsCancelled: vi.fn(),
    emit: vi.fn(),
  },
}));

vi.mock('../../server/services/processTracker', () => ({
  processTracker: { killAll: vi.fn(() => 0) },
}));

vi.mock('../../server/services/jobEventBroadcaster', () => ({
  jobEventBroadcaster: { subscribe: vi.fn(), unsubscribe: vi.fn(), emit: vi.fn() },
}));

vi.mock('../../server/services/journeys/apiDiscovery', () => ({ discoverApi: vi.fn() }));
vi.mock('../../server/services/journeys/apiPassiveTests', () => ({ runApiPassiveTests: vi.fn() }));
vi.mock('../../server/services/journeys/apiActiveTests', () => ({ runApiActiveTests: vi.fn() }));
vi.mock('../../server/services/threatPromotion', () => ({ promoteHighCriticalFindings: vi.fn() }));
vi.mock('../../server/services/journeys/urls', () => ({ normalizeTarget: vi.fn((u: string) => u) }));
vi.mock('../../shared/sanitization', () => ({ sanitizeApiFinding: vi.fn((f: any) => f) }));

const VALID_BODY = {
  type: 'api_security',
  name: 'Test Journey',
  params: {
    assetIds: ['asset-1'],
    authorizationAck: true,
    apiSecurityConfig: {
      discovery: { specFirst: true, crawler: true, kiterunner: false },
      testing: { misconfigs: true, auth: true, bola: false, bfla: false, bopla: false, rateLimit: true, ssrf: false },
      rateLimit: 10,
      destructiveEnabled: false,
      dryRun: false,
    },
  },
};

async function buildApp(): Promise<Express> {
  const app = express();
  app.use(express.json());
  const { registerJobRoutes } = await import('../../server/routes/jobs');
  registerJobRoutes(app);
  return app;
}

describe('POST /api/v1/jobs — api_security type', () => {
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
    // Default happy-path mocks
    mocks.createJourney.mockResolvedValue({ id: 'jrny-1', name: 'Test Journey', type: 'api_security' });
    mocks.executeJobNow.mockResolvedValue({ id: 'job-1', status: 'queued' });
    // Return existing api so apiId resolution doesn't need to create one
    mocks.listApisByParent.mockResolvedValue([{ id: 'api-1', baseUrl: 'http://test.com', apiType: 'rest' }]);
  });

  it('POST with type="api_security" and authorizationAck=true creates job and returns 201', async () => {
    const res = await fetch(`${baseUrl}/api/v1/jobs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(VALID_BODY),
    });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body).toHaveProperty('id');
    expect(body).toHaveProperty('journeyId');
    expect(mocks.createJourney).toHaveBeenCalledOnce();
    expect(mocks.executeJobNow).toHaveBeenCalledWith('jrny-1');
  });

  it('POST with type="api_security" and authorizationAck=false returns 400 with pt-BR error message', async () => {
    const res = await fetch(`${baseUrl}/api/v1/jobs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...VALID_BODY,
        params: { ...VALID_BODY.params, authorizationAck: false },
      }),
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.message).toMatch(/autoriza/i);
    expect(mocks.createJourney).not.toHaveBeenCalled();
  });

  it('POST with rateLimit > 50 (SAFE-01 ceiling) returns 400', async () => {
    const res = await fetch(`${baseUrl}/api/v1/jobs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...VALID_BODY,
        params: {
          ...VALID_BODY.params,
          apiSecurityConfig: {
            ...VALID_BODY.params.apiSecurityConfig,
            rateLimit: 51,
          },
        },
      }),
    });
    expect(res.status).toBe(400);
    expect(mocks.createJourney).not.toHaveBeenCalled();
  });

  it('POST writes audit_log with action="create" and objectType="job"', async () => {
    await fetch(`${baseUrl}/api/v1/jobs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(VALID_BODY),
    });
    expect(mocks.logAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'create',
        objectType: 'job',
        actorId: 'user-1',
      }),
    );
  });

  it('POST with missing name returns 400', async () => {
    const { name: _omit, ...noName } = VALID_BODY;
    const res = await fetch(`${baseUrl}/api/v1/jobs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(noName),
    });
    expect(res.status).toBe(400);
    expect(mocks.createJourney).not.toHaveBeenCalled();
  });

  it('POST with empty assetIds returns 400', async () => {
    const res = await fetch(`${baseUrl}/api/v1/jobs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...VALID_BODY,
        params: { ...VALID_BODY.params, assetIds: [] },
      }),
    });
    expect(res.status).toBe(400);
    expect(mocks.createJourney).not.toHaveBeenCalled();
  });

  it('POST with dryRun=true passes dryRun in apiSecurityConfig and returns 201', async () => {
    const res = await fetch(`${baseUrl}/api/v1/jobs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...VALID_BODY,
        params: {
          ...VALID_BODY.params,
          apiSecurityConfig: {
            ...VALID_BODY.params.apiSecurityConfig,
            dryRun: true,
          },
        },
      }),
    });
    expect(res.status).toBe(201);
    // Verify createJourney was called with dryRun propagated to all opts
    const callArgs = mocks.createJourney.mock.calls[0][0];
    expect(callArgs.params.discoveryOpts.dryRun).toBe(true);
    expect(callArgs.params.passiveOpts.dryRun).toBe(true);
    expect(callArgs.params.activeOpts.dryRun).toBe(true);
  });
});
