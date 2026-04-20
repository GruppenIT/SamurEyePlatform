/**
 * Phase 15 — JRNY-05 integration tests for POST /api/v1/jobs/:id/abort
 */
import { describe, it, expect, vi, beforeEach, afterAll, beforeAll } from 'vitest';
import express, { type Express } from 'express';
import type { Server } from 'http';

const mocks = vi.hoisted(() => ({
  getJob: vi.fn(),
  updateJob: vi.fn(),
  logAudit: vi.fn(async () => ({ id: 'audit-1' })),
  markJobAsCancelled: vi.fn(),
  isJobCancelled: vi.fn(),
  emit: vi.fn(),
  on: vi.fn(),
  killAll: vi.fn().mockReturnValue(2),
}));

vi.mock('../storage', () => ({
  storage: {
    getJob: mocks.getJob,
    getJobs: vi.fn(),
    getJobResult: vi.fn(),
    updateJob: mocks.updateJob,
    logAudit: mocks.logAudit,
  },
}));

vi.mock('../localAuth', () => ({
  isAuthenticatedWithPasswordCheck: (req: any, _res: any, next: any) => {
    req.user = { id: 'user-1' };
    next();
  },
}));

vi.mock('../services/jobQueue', () => ({
  jobQueue: {
    markJobAsCancelled: mocks.markJobAsCancelled,
    isJobCancelled: mocks.isJobCancelled,
    emit: mocks.emit,
    on: mocks.on,
    executeJobNow: vi.fn(),
  },
}));

vi.mock('../services/processTracker', () => ({
  processTracker: { killAll: mocks.killAll },
}));

vi.mock('../services/jobEventBroadcaster', () => ({
  jobEventBroadcaster: { subscribe: vi.fn(), unsubscribe: vi.fn() },
}));

vi.mock('../routes/middleware', () => ({
  requireOperator: (_req: any, _res: any, next: any) => next(),
}));

vi.mock('../db', () => ({ db: {} }));

async function buildApp(): Promise<Express> {
  const app = express();
  app.use(express.json());
  const { registerJobRoutes } = await import('../routes/jobs');
  registerJobRoutes(app);
  return app;
}

describe('JRNY-05 — POST /api/v1/jobs/:id/abort', () => {
  let server: Server;
  let baseUrl: string;

  beforeAll(async () => {
    const app = await buildApp();
    server = app.listen(0);
    const addr = server.address();
    const port = typeof addr === 'object' && addr ? addr.port : 0;
    baseUrl = `http://localhost:${port}`;
  });

  afterAll(async () => {
    server?.close();
  });

  beforeEach(() => {
    mocks.getJob.mockReset();
    mocks.updateJob.mockReset();
    mocks.logAudit.mockReset();
    mocks.markJobAsCancelled.mockReset();
    mocks.emit.mockReset();
    mocks.killAll.mockReset();
    mocks.killAll.mockReturnValue(2);
    mocks.logAudit.mockResolvedValue({ id: 'audit-1' });
  });

  it('rota registrada em server/routes/jobs.ts responde 404 para jobId inexistente', async () => {
    mocks.getJob.mockResolvedValue(undefined);
    const res = await fetch(`${baseUrl}/api/v1/jobs/missing-id/abort`, { method: 'POST' });
    expect(res.status).toBe(404);
  });

  it('rota responde 400 quando job.status !== "running"', async () => {
    mocks.getJob.mockResolvedValue({ id: 'j1', status: 'completed', progress: 100 });
    const res = await fetch(`${baseUrl}/api/v1/jobs/j1/abort`, { method: 'POST' });
    expect(res.status).toBe(400);
  });

  it('rota chama jobQueue.markJobAsCancelled(id) antes de killAll', async () => {
    mocks.getJob.mockResolvedValue({ id: 'j1', status: 'running', progress: 50 });
    await fetch(`${baseUrl}/api/v1/jobs/j1/abort`, { method: 'POST' });
    expect(mocks.markJobAsCancelled).toHaveBeenCalledWith('j1');
    expect(mocks.markJobAsCancelled.mock.invocationCallOrder[0])
      .toBeLessThan(mocks.killAll.mock.invocationCallOrder[0]);
  });

  it('rota chama processTracker.killAll(id) e retorna killedProcesses count', async () => {
    mocks.getJob.mockResolvedValue({ id: 'j1', status: 'running', progress: 50 });
    mocks.killAll.mockReturnValue(3);
    const res = await fetch(`${baseUrl}/api/v1/jobs/j1/abort`, { method: 'POST' });
    const body = await res.json();
    expect(mocks.killAll).toHaveBeenCalledWith('j1');
    expect(body.killedProcesses).toBe(3);
  });

  it('rota atualiza storage.updateJob(id, { status: "failed", error, finishedAt })', async () => {
    mocks.getJob.mockResolvedValue({ id: 'j1', status: 'running', progress: 50 });
    await fetch(`${baseUrl}/api/v1/jobs/j1/abort`, { method: 'POST' });
    expect(mocks.updateJob).toHaveBeenCalledWith('j1', expect.objectContaining({
      status: 'failed',
      error: expect.any(String),
      finishedAt: expect.any(Date),
    }));
  });

  it('rota emite jobQueue.emit("jobUpdate", ...) com status "failed"', async () => {
    mocks.getJob.mockResolvedValue({ id: 'j1', status: 'running', progress: 50 });
    await fetch(`${baseUrl}/api/v1/jobs/j1/abort`, { method: 'POST' });
    expect(mocks.emit).toHaveBeenCalledWith('jobUpdate', expect.objectContaining({
      jobId: 'j1',
      status: 'failed',
    }));
  });

  it('rota chama storage.logAudit com action="abort", objectType="job"', async () => {
    mocks.getJob.mockResolvedValue({ id: 'j1', status: 'running', progress: 50 });
    await fetch(`${baseUrl}/api/v1/jobs/j1/abort`, { method: 'POST' });
    expect(mocks.logAudit).toHaveBeenCalledWith(expect.objectContaining({
      action: 'abort',
      objectType: 'job',
      objectId: 'j1',
    }));
  });

  it('rota retorna JSON { message: "Jornada abortada", killedProcesses: N }', async () => {
    mocks.getJob.mockResolvedValue({ id: 'j1', status: 'running', progress: 50 });
    const res = await fetch(`${baseUrl}/api/v1/jobs/j1/abort`, { method: 'POST' });
    const body = await res.json();
    expect(body.message).toBe('Jornada abortada');
    expect(typeof body.killedProcesses).toBe('number');
  });

  it('rota original POST /api/jobs/:id/cancel-process permanece funcional (backward compat)', async () => {
    mocks.getJob.mockResolvedValue({ id: 'j1', status: 'running', progress: 50 });
    const res = await fetch(`${baseUrl}/api/jobs/j1/cancel-process`, { method: 'POST' });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.killedProcesses).toBeDefined();
  });
});
