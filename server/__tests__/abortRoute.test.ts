/**
 * Phase 15 — JRNY-05 Nyquist stubs.
 * Implementação chega no Plano 15-04.
 */
import { describe, it } from 'vitest';

describe('JRNY-05 — POST /api/v1/jobs/:id/abort', () => {
  it.todo('rota registrada em server/routes/jobs.ts responde 404 para jobId inexistente');
  it.todo('rota responde 400 quando job.status !== "running"');
  it.todo('rota chama jobQueue.markJobAsCancelled(id) antes de killAll');
  it.todo('rota chama processTracker.killAll(id) e retorna killedProcesses count');
  it.todo('rota atualiza storage.updateJob(id, { status: "failed", error, finishedAt })');
  it.todo('rota emite jobQueue.emit("jobUpdate", ...) com status "failed"');
  it.todo('rota chama storage.logAudit com action="abort", objectType="job"');
  it.todo('rota retorna JSON { message: "Jornada abortada", killedProcesses: N }');
  it.todo('rota original POST /api/jobs/:id/cancel-process permanece funcional (backward compat)');
});
