/**
 * Phase 16 — UI-05 Backend — PATCH /api/v1/api-findings/:id
 *
 * Promoted from it.todo stubs by Plan 02.
 * Per 16-VALIDATION.md task map.
 *
 * Requirement: PATCH endpoint to mark an api_finding as false_positive.
 * Sets status='false_positive' or reverts to 'open' with {falsePositive: false}.
 * Writes audit_log row for compliance trail.
 * Auth required (operator role). 404 for unknown id. Zod rejects unknown fields.
 */
import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import express, { type Express } from 'express';
import type { Server } from 'http';

const mocks = vi.hoisted(() => ({
  patchApiFinding: vi.fn(),
  logAudit: vi.fn(async () => ({ id: 'audit-1' })),
  listApiFindings: vi.fn(),
}));

vi.mock('../../server/storage', () => ({
  storage: {
    patchApiFinding: mocks.patchApiFinding,
    logAudit: mocks.logAudit,
    listApiFindings: mocks.listApiFindings,
  },
}));

vi.mock('../../server/localAuth', () => ({
  isAuthenticatedWithPasswordCheck: (req: any, _res: any, next: any) => {
    req.user = { id: 'user-operator', role: 'operator' };
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

async function buildApp(): Promise<Express> {
  const app = express();
  app.use(express.json());
  const { registerApiFindingsRoutes } = await import('../../server/routes/apiFindings');
  registerApiFindingsRoutes(app);
  return app;
}

describe('PATCH /api/v1/api-findings/:id', () => {
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

  it('PATCH with {falsePositive: true} sets finding status to "false_positive"', async () => {
    const previousFinding = { id: 'f-1', status: 'open', apiEndpointId: 'ep-1', owaspCategory: 'api1_bola_2023' };
    const currentFinding = { id: 'f-1', status: 'false_positive', apiEndpointId: 'ep-1', owaspCategory: 'api1_bola_2023' };
    mocks.patchApiFinding.mockResolvedValue({ previous: previousFinding, current: currentFinding });

    const res = await fetch(`${baseUrl}/api/v1/api-findings/f-1`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ falsePositive: true }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe('false_positive');
  });

  it('creates audit_log row with action="update", objectType="api_finding"', async () => {
    const previousFinding = { id: 'f-1', status: 'open', apiEndpointId: 'ep-1', owaspCategory: 'api1_bola_2023' };
    const currentFinding = { id: 'f-1', status: 'false_positive', apiEndpointId: 'ep-1', owaspCategory: 'api1_bola_2023' };
    mocks.patchApiFinding.mockResolvedValue({ previous: previousFinding, current: currentFinding });

    await fetch(`${baseUrl}/api/v1/api-findings/f-1`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ falsePositive: true }),
    });

    expect(mocks.logAudit).toHaveBeenCalledOnce();
    const logAuditCall = mocks.logAudit.mock.calls[0][0];
    expect(logAuditCall.action).toBe('update');
    expect(logAuditCall.objectType).toBe('api_finding');
    expect(logAuditCall.objectId).toBe('f-1');
    expect(logAuditCall.actorId).toBe('user-operator');
  });

  it('returns 404 when finding id does not exist in DB', async () => {
    mocks.patchApiFinding.mockRejectedValue(new Error('api_finding non-existent-id not found'));

    const res = await fetch(`${baseUrl}/api/v1/api-findings/non-existent-id`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ falsePositive: true }),
    });

    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.message).toBe('Finding não encontrado');
  });

  it('Zod rejects unknown body fields — strict schema enforced', async () => {
    const res = await fetch(`${baseUrl}/api/v1/api-findings/f-1`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ falsePositive: true, unknownField: 'bad' }),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.message).toBeDefined();
  });

  it('Zod rejects non-boolean falsePositive value', async () => {
    const res = await fetch(`${baseUrl}/api/v1/api-findings/f-1`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ falsePositive: 'yes' }),
    });

    expect(res.status).toBe(400);
  });

  it('PATCH with {falsePositive: false} reverts finding status to "open"', async () => {
    const previousFinding = { id: 'f-1', status: 'false_positive', apiEndpointId: 'ep-1' };
    const currentFinding = { id: 'f-1', status: 'open', apiEndpointId: 'ep-1' };
    mocks.patchApiFinding.mockResolvedValue({ previous: previousFinding, current: currentFinding });

    const res = await fetch(`${baseUrl}/api/v1/api-findings/f-1`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ falsePositive: false }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe('open');
  });

  it.todo('returns 401 when request has no authentication');
  it.todo('returns 403 when authenticated user has readonly_analyst role (write operation)');
});
