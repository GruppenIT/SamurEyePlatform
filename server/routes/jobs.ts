import type { Express } from "express";
import { z } from "zod";
import { storage } from "../storage";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { requireOperator } from "./middleware";
import { jobQueue } from "../services/jobQueue";
import { processTracker } from "../services/processTracker";
import { createLogger } from '../lib/logger';
import { MAX_API_RATE_LIMIT } from '../services/rateLimiter';
// Phase 14 FIND-04: WebSocket event broadcaster anchor.
// TODO(14-04/Phase-15): Wire upgrade handler GET /api/v1/jobs/:jobId/ws
//   wss.on('connection', (ws, req) => {
//     const match = req.url?.match(/\/api\/v1\/jobs\/([^/]+)\/ws$/);
//     if (!match) { ws.close(); return; }
//     const jobId = match[1];
//     jobEventBroadcaster.subscribe(jobId, ws);
//     ws.on('close', () => jobEventBroadcaster.unsubscribe(jobId, ws));
//     ws.on('error', () => jobEventBroadcaster.unsubscribe(jobId, ws));
//   });
import { jobEventBroadcaster } from '../services/jobEventBroadcaster';

const log = createLogger('routes:jobs');

export function registerJobRoutes(app: Express) {
  app.get('/api/jobs', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const limit = req.query.limit ? parseInt(req.query.limit as string) : undefined;
      const jobs = await storage.getJobs(limit);
      res.json(jobs);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch jobs');
      res.status(500).json({ message: "Falha ao buscar jobs" });
    }
  });

  app.post('/api/jobs/execute', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { journeyId } = req.body;

      if (!journeyId) {
        return res.status(400).json({ message: "ID da jornada é obrigatório" });
      }

      const job = await jobQueue.executeJobNow(journeyId);

      await storage.logAudit({
        actorId: userId,
        action: 'execute',
        objectType: 'job',
        objectId: job.id,
        before: null,
        after: job,
      });

      res.status(201).json(job);
    } catch (error) {
      log.error({ err: error }, 'failed to execute job');
      res.status(400).json({ message: "Falha ao executar job" });
    }
  });

  app.get('/api/jobs/:id/result', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { id } = req.params;
      const result = await storage.getJobResult(id);

      if (!result) {
        return res.status(404).json({ message: "Resultado não encontrado" });
      }

      res.json(result);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch job result');
      res.status(500).json({ message: "Falha ao buscar resultado" });
    }
  });

  app.post('/api/jobs/:id/cancel-process', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;

      // Verificar se o job existe
      const job = await storage.getJob(id);
      if (!job) {
        return res.status(404).json({ message: "Job não encontrado" });
      }

      // Verificar se o job está em execução
      if (job.status !== 'running') {
        return res.status(400).json({ message: "Job não está em execução" });
      }

      // Marcar job como cancelado para cooperative cancellation
      jobQueue.markJobAsCancelled(id);

      // Matar todos os processos do job (pode ser 0 entre fases)
      const killedCount = processTracker.killAll(id);

      // Marcar job como cancelado no DB
      await storage.updateJob(id, {
        status: 'failed',
        error: 'Job cancelado pelo usuário',
        finishedAt: new Date()
      });

      // Emitir update WebSocket para atualizar UI imediatamente
      jobQueue.emit('jobUpdate', {
        jobId: id,
        status: 'failed',
        progress: job.progress,
        currentTask: 'Job cancelado pelo usuário',
        error: 'Job cancelado pelo usuário',
      });

      // Log de auditoria
      await storage.logAudit({
        actorId: userId,
        action: 'cancel',
        objectType: 'job',
        objectId: id,
        before: null,
        after: { status: 'failed', error: 'Job cancelado pelo usuário' },
      });

      log.info({ jobId: id, userId, killedCount }, 'job cancelled by user');

      res.json({
        message: `Job cancelado com sucesso.${killedCount > 0 ? ` ${killedCount} processo(s) terminado(s).` : ' Cancelamento cooperativo ativado.'}`,
        killedProcesses: killedCount
      });

    } catch (error) {
      log.error({ err: error }, 'failed to cancel job');
      res.status(500).json({ message: "Falha ao cancelar job" });
    }
  });

  /**
   * Phase 16 UI-06 — POST /api/v1/jobs
   *
   * Creates an api_security journey + queues for execution.
   * Validates authorizationAck=true (SAFE-04) and rateLimit ≤ MAX_API_RATE_LIMIT (SAFE-01).
   *
   * Body shape (type=api_security):
   *   { type, name, description?, params: { assetIds, targetBaseUrl?, credentialId?,
   *     authorizationAck, apiSecurityConfig: { discovery, testing, rateLimit, destructiveEnabled, dryRun } } }
   *
   * Response: 201 { id: string, journeyId: string }
   */
  const createApiSecurityJobSchema = z.object({
    type: z.literal("api_security"),
    name: z.string().min(1, "Nome é obrigatório"),
    description: z.string().optional(),
    params: z.object({
      assetIds: z.array(z.string()).min(1, "Selecione ao menos um alvo"),
      targetBaseUrl: z.string().optional(),
      credentialId: z.string().optional(),
      authorizationAck: z.boolean(),
      apiSecurityConfig: z.object({
        discovery: z.object({
          specFirst: z.boolean(),
          crawler: z.boolean(),
          kiterunner: z.boolean(),
        }),
        testing: z.object({
          misconfigs: z.boolean(),
          auth: z.boolean(),
          bola: z.boolean(),
          bfla: z.boolean(),
          bopla: z.boolean(),
          rateLimit: z.boolean(),
          ssrf: z.boolean(),
        }),
        rateLimit: z.number().int().min(1).max(MAX_API_RATE_LIMIT),
        destructiveEnabled: z.boolean(),
        dryRun: z.boolean(),
      }),
    }),
  });

  app.post('/api/v1/jobs', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;

      const parsed = createApiSecurityJobSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({
          message: "Dados inválidos",
          errors: parsed.error.flatten().fieldErrors,
        });
      }

      const { name, description, params } = parsed.data;

      // SAFE-04: authorizationAck must be true
      if (params.authorizationAck !== true) {
        return res.status(400).json({
          message: "Autorização de teste é obrigatória (authorizationAck deve ser true)",
        });
      }

      // SAFE-01: rateLimit ceiling
      if (params.apiSecurityConfig.rateLimit > MAX_API_RATE_LIMIT) {
        return res.status(400).json({
          message: `Rate limit não pode exceder ${MAX_API_RATE_LIMIT} req/s`,
        });
      }

      // Create journey record
      const journey = await storage.createJourney(
        {
          name,
          description: description || null,
          type: "api_security",
          authorizationAck: true,
          params: {
            assetIds: params.assetIds,
            targetBaseUrl: params.targetBaseUrl,
            credentialId: params.credentialId,
            apiSecurityConfig: params.apiSecurityConfig,
          },
        } as any,
        userId,
      );

      // Enqueue job
      const job = await jobQueue.executeJobNow(journey.id);

      await storage.logAudit({
        actorId: userId,
        action: 'create',
        objectType: 'job',
        objectId: job.id,
        before: null,
        after: { journeyId: journey.id, type: 'api_security', dryRun: params.apiSecurityConfig.dryRun },
      });

      log.info({ jobId: job.id, journeyId: journey.id, userId }, 'api_security job created');

      return res.status(201).json({ id: job.id, journeyId: journey.id });
    } catch (error) {
      log.error({ err: error }, 'failed to create api_security job');
      return res.status(500).json({ message: 'Falha ao criar jornada' });
    }
  });

  /**
   * Phase 15 JRNY-05 — POST /api/v1/jobs/:id/abort
   *
   * Aborta uma jornada em execução. Encapsula a mesma lógica de
   * POST /api/jobs/:id/cancel-process (mantida para backward compat) mas
   * com path canônico /api/v1/ e semântica de "abort" no audit log.
   *
   * Fluxo:
   *   1. Valida existência do job (404 se não existir)
   *   2. Valida status='running' (400 caso contrário)
   *   3. jobQueue.markJobAsCancelled(id) — cooperative cancellation flag
   *   4. processTracker.killAll(id) — SIGTERM+SIGKILL em todos os child processes
   *   5. storage.updateJob(id, { status: 'failed', error, finishedAt })
   *   6. jobQueue.emit('jobUpdate', ...) — WebSocket para UI
   *   7. storage.logAudit(action='abort', objectType='job')
   *
   * Response: 200 { message: 'Jornada abortada', killedProcesses: N }
   */
  app.post('/api/v1/jobs/:id/abort', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;

      const job = await storage.getJob(id);
      if (!job) {
        return res.status(404).json({ message: "Job não encontrado" });
      }

      if (job.status !== 'running') {
        return res.status(400).json({ message: "Job não está em execução" });
      }

      // Phase 15 JRNY-05 — cooperative cancel + hard kill sequence
      jobQueue.markJobAsCancelled(id);
      const killedCount = processTracker.killAll(id);

      await storage.updateJob(id, {
        status: 'failed',
        error: 'Jornada abortada pelo usuário',
        finishedAt: new Date(),
      });

      jobQueue.emit('jobUpdate', {
        jobId: id,
        status: 'failed',
        progress: job.progress,
        currentTask: 'Jornada abortada pelo usuário',
        error: 'Jornada abortada pelo usuário',
      });

      await storage.logAudit({
        actorId: userId,
        action: 'abort',
        objectType: 'job',
        objectId: id,
        before: null,
        after: { status: 'failed', error: 'Jornada abortada pelo usuário', killedProcesses: killedCount },
      });

      log.info({ jobId: id, userId, killedCount }, 'job aborted by user');

      return res.json({
        message: 'Jornada abortada',
        killedProcesses: killedCount,
      });
    } catch (error) {
      log.error({ err: error }, 'failed to abort job');
      return res.status(500).json({ message: 'Falha ao abortar jornada' });
    }
  });
}
