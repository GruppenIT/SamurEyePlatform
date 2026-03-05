// REDIGIDO PARA DEPOSITO INPI (sem segredos)
// Fila de Jobs - gerencia execucao concorrente de jornadas
// Trecho representativo (server/services/jobQueue.ts)

import { EventEmitter } from 'events';
import { storage } from '../storage';
import { journeyExecutor } from './journeyExecutor';
import { type Job, type InsertJob } from '@shared/schema';
import { processTracker, type ProcessUpdate } from './processTracker';

export interface JobUpdate {
  jobId: string;
  status: Job['status'];
  progress?: number;
  currentTask?: string;
  error?: string;
  pid?: number;
  processName?: 'nmap' | 'nuclei';
  stage?: string;
  isAlive?: boolean;
}

class JobQueueService extends EventEmitter {
  private runningJobs = new Map<string, Job>();
  private jobTimeouts = new Map<string, number>();
  private maxConcurrentJobs = 3;
  private cancelledJobs = new Set<string>();

  /** Timeout padrao: 30 min. Timeout dinamico calculado por jornada. */
  private static DEFAULT_TIMEOUT_MS = 30 * 60 * 1000;

  constructor() {
    super();
    this.startQueueProcessor();
    this.setupProcessTrackerListener();
  }

  // Configura listener para atualizacoes do ProcessTracker
  private setupProcessTrackerListener(): void {
    processTracker.on('processUpdate', (update: ProcessUpdate) => {
      this.handleProcessUpdate(update);
    });
  }

  // Manipula atualizacoes de processos (nmap, nuclei)
  private async handleProcessUpdate(update: ProcessUpdate): Promise<void> {
    const job = await storage.getJob(update.jobId);
    if (!job) return;
    if (job.status === 'completed' || job.status === 'failed' || job.status === 'timeout') return;

    let currentTask = update.stage;
    if (update.pid && update.processName) {
      currentTask = `${update.stage} (${update.processName} pid ${update.pid})`;
    }

    const jobUpdate: JobUpdate = {
      jobId: update.jobId,
      status: job.status,
      progress: job.progress ?? undefined,
      currentTask,
      pid: update.pid,
      processName: update.processName,
      stage: update.stage,
      isAlive: update.isAlive,
    };

    this.emit('jobUpdate', jobUpdate);
  }

  // Processa fila de jobs pendentes
  // Gerencia concorrencia, timeouts dinamicos e cancelamento
  // Emite eventos via WebSocket para atualizacao em tempo real na UI
  // [implementacao completa omitida - ver codigo-fonte]
}
