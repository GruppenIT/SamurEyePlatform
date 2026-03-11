import type { Express } from "express";
import { storage } from "../storage";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { requireOperator } from "./middleware";
import { jobQueue } from "../services/jobQueue";
import { processTracker } from "../services/processTracker";
import { createLogger } from '../lib/logger';

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
}
