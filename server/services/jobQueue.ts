import { EventEmitter } from 'events';
import { storage } from '../storage';
import { journeyExecutor } from './journeyExecutor';
import { type Job, type InsertJob } from '@shared/schema';
import { processTracker, type ProcessUpdate } from './processTracker';
import { createLogger } from '../lib/logger';

const log = createLogger('jobQueue');

export interface JobUpdate {
  jobId: string;
  status: Job['status'];
  progress?: number;
  currentTask?: string;
  error?: string;
  // Campos para monitoramento de processos
  pid?: number;
  processName?: 'nmap' | 'nuclei';
  stage?: string;
  isAlive?: boolean;
}

class JobQueueService extends EventEmitter {
  private runningJobs = new Map<string, Job>();
  private jobTimeouts = new Map<string, number>(); // jobId -> timeout in ms
  private maxConcurrentJobs = 3;
  private cancelledJobs = new Set<string>(); // Track cancelled jobs

  /** Default timeout: 30 min. Dynamic timeout computed per-journey. */
  private static DEFAULT_TIMEOUT_MS = 30 * 60 * 1000;

  constructor() {
    super();
    this.startQueueProcessor();
    this.setupProcessTrackerListener();
  }

  /**
   * Configura listener para atualizações do ProcessTracker
   */
  private setupProcessTrackerListener(): void {
    processTracker.on('processUpdate', (update: ProcessUpdate) => {
      this.handleProcessUpdate(update);
    });
  }

  /**
   * Manipula atualizações de processos
   */
  private async handleProcessUpdate(update: ProcessUpdate): Promise<void> {
    try {
      // Verificar se job ainda está ativo antes de atualizar
      const job = await storage.getJob(update.jobId);
      if (!job) {
        log.info(`🚫 Job ${update.jobId} não encontrado, ignorando update de processo`);
        return;
      }

      // Não atualizar se job já está em estado terminal
      if (job.status === 'completed' || job.status === 'failed' || job.status === 'timeout') {
        log.info(`🚫 Job ${update.jobId} em estado terminal (${job.status}), ignorando update de processo`);
        return;
      }

      // Construir mensagem de currentTask com PID
      let currentTask = update.stage;
      if (update.pid && update.processName) {
        currentTask = `${update.stage} (${update.processName} pid ${update.pid})`;
      }

      // Emitir JobUpdate com informações de processo (sem forçar status)
      const jobUpdate: JobUpdate = {
        jobId: update.jobId,
        status: job.status, // Preservar status atual do job
        progress: job.progress ?? undefined, // Incluir progresso atual do DB
        currentTask,
        pid: update.pid,
        processName: update.processName,
        stage: update.stage,
        isAlive: update.isAlive,
      };

      // Atualizar apenas currentTask no database (não status)
      await storage.updateJob(update.jobId, { currentTask });

      // Emitir para WebSocket
      this.emit('jobUpdate', jobUpdate);

      log.info(`📡 JobUpdate emitido para ${update.jobId}: ${currentTask} (alive: ${update.isAlive}, status: ${job.status})`);
    } catch (error) {
      log.error(`❌ Erro ao processar update de processo:`, error);
    }
  }

  /**
   * Adds a job to the queue
   */
  async enqueueJob(jobData: InsertJob): Promise<Job> {
    const job = await storage.createJob(jobData);
    
    // If we have capacity, start the job immediately
    if (this.runningJobs.size < this.maxConcurrentJobs) {
      this.processJob(job);
    }
    
    return job;
  }

  /**
   * Executes a job on demand
   */
  async executeJobNow(journeyId: string): Promise<Job> {
    const journey = await storage.getJourney(journeyId);
    if (!journey) {
      throw new Error('Jornada não encontrada');
    }

    const jobData: InsertJob = {
      journeyId,
      status: 'pending',
      progress: 0,
    };

    return this.enqueueJob(jobData);
  }

  /**
   * Processes a single job
   */
  private async processJob(job: Job): Promise<void> {
    try {
      // Verify job exists in database before processing
      const existingJob = await storage.getJob(job.id);
      if (!existingJob) {
        log.error(`Cannot process non-existent job: ${job.id}`);
        return;
      }

      this.runningJobs.set(job.id, job);

      // Update job status to running
      await this.updateJobStatus(job.id, 'running', 0, 'Iniciando execução');

      // Get journey details
      const journey = await storage.getJourney(job.journeyId);
      if (!journey) {
        throw new Error('Jornada não encontrada');
      }

      // Compute dynamic timeout based on journey scope
      const timeoutMs = await this.computeJobTimeout(journey);
      this.jobTimeouts.set(job.id, timeoutMs);
      log.info(`⏱️  Job ${job.id} timeout: ${Math.round(timeoutMs / 60000)} minutos (journey: ${journey.type})`);

      // Execute the journey
      await journeyExecutor.executeJourney(journey, job.id, (update) => {
        // Handle updateJobStatus asynchronously to avoid unhandled promise rejections
        this.updateJobStatus(job.id, update.status, update.progress, update.currentTask).catch((error) => {
          if (error.message?.includes('not found')) {
            log.info(`Job ${job.id} no longer exists, ignoring progress update`);
          } else {
            log.error(`Failed to update job status for ${job.id}:`, error);
          }
        });
      });

      // Check if job was cancelled before marking as completed
      if (this.isJobCancelled(job.id)) {
        log.info(`🚫 Job ${job.id} foi cancelado, não marcando como completed`);
        await this.updateJobStatus(job.id, 'failed', undefined, 'Job cancelado pelo usuário');
        return;
      }

      // Mark as completed
      await this.updateJobStatus(job.id, 'completed', 100, 'Execução finalizada');
      
    } catch (error) {
      log.error(`Erro na execução do job ${job.id}:`, error);
      try {
        await this.updateJobStatus(job.id, 'failed', undefined, error instanceof Error ? error.message : 'Erro desconhecido');
      } catch (updateError) {
        // Ignore "not found" errors when marking as failed - job may have been deleted
        if (!(updateError instanceof Error) || !updateError.message?.includes('not found')) {
          log.error(`Failed to mark job ${job.id} as failed:`, updateError);
        }
      }
    } finally {
      this.removeJobFromRunning(job.id); // Use helper to cleanup both runningJobs and cancelledJobs
      // Process next job in queue if any
      this.processNextJob();
    }
  }

  /**
   * Updates job status and emits update event
   */
  private async updateJobStatus(
    jobId: string, 
    status: Job['status'], 
    progress?: number, 
    currentTask?: string,
    error?: string
  ): Promise<void> {
    const updates: Partial<Job> = { status };
    
    if (progress !== undefined) updates.progress = progress;
    if (currentTask) updates.currentTask = currentTask;
    if (error) updates.error = error;
    
    if (status === 'running' && !updates.startedAt) {
      updates.startedAt = new Date();
    }
    
    if (['completed', 'failed', 'timeout'].includes(status)) {
      updates.finishedAt = new Date();
    }

    try {
      await storage.updateJob(jobId, updates);
      
      // Emit update ONLY after successful DB update
      const update: JobUpdate = {
        jobId,
        status,
        progress,
        currentTask,
        error,
      };
      
      this.emit('jobUpdate', update);
    } catch (dbError) {
      log.error(`Failed to update job ${jobId}: ${dbError}`);
      // Don't emit update for non-existent jobs to prevent ghost jobs in UI
      if (dbError instanceof Error && dbError.message.includes('not found')) {
        log.error(`Ghost job detected: ${jobId} - removing from running jobs`);
        this.runningJobs.delete(jobId);
      }
      throw dbError;
    }
  }

  /**
   * Process next job in queue
   */
  private async processNextJob(): Promise<void> {
    if (this.runningJobs.size >= this.maxConcurrentJobs) {
      return;
    }

    // Get next pending job
    const jobs = await storage.getJobs(1);
    const pendingJob = jobs.find(job => job.status === 'pending');
    
    if (pendingJob) {
      this.processJob(pendingJob);
    }
  }

  /**
   * Starts the queue processor
   */
  private startQueueProcessor(): void {
    // Check for pending jobs every 30 seconds
    setInterval(async () => {
      this.processNextJob();
    }, 30000);

    // Timeout long-running jobs (per-job dynamic timeout)
    setInterval(async () => {
      const runningJobs = await storage.getRunningJobs();
      const now = new Date();

      for (const job of runningJobs) {
        if (job.startedAt) {
          const runtime = now.getTime() - job.startedAt.getTime();
          const jobTimeout = this.jobTimeouts.get(job.id) ?? JobQueueService.DEFAULT_TIMEOUT_MS;

          if (runtime > jobTimeout) {
            const timeoutMin = Math.round(jobTimeout / 60000);
            // Kill all child processes associated with this job
            const killedCount = processTracker.killAll(job.id);
            if (killedCount > 0) {
              log.info(`🔪 Timeout: ${killedCount} processos terminados para job ${job.id}`);
            }

            await this.updateJobStatus(job.id, 'timeout', undefined, `Job ultrapassou tempo limite de ${timeoutMin} minutos`);
            // Release concurrency slot
            this.removeJobFromRunning(job.id);
          }
        }
      }
    }, 60000); // Check every minute
  }

  /**
   * Compute a dynamic timeout based on the journey's type and scope.
   *
   * Heuristic:
   *   - Base: 15 min (overhead: startup, DB, threat analysis)
   *   - Per single host:  +3 min
   *   - Per CIDR /24:    +40 min  (254 hosts × discovery + port scan + vuln)
   *   - Per CIDR /16:    clamps to 4 hours max
   *   - vulnScriptTimeout param is added on top (default 60 min)
   *   - webScanEnabled adds +20 min per asset
   *   - AD Security / EDR: fixed 45 min
   *   - Absolute cap: 4 hours
   */
  private async computeJobTimeout(journey: any): Promise<number> {
    const MINUTE = 60_000;

    if (journey.type !== 'attack_surface') {
      // AD Security / EDR / Web App: fixed 45 min is plenty
      return 45 * MINUTE;
    }

    const params = journey.params || {};
    const vulnTimeout = (params.vulnScriptTimeout || 60) * MINUTE;
    const webExtra = params.webScanEnabled ? 20 * MINUTE : 0;

    let baseMins = 15; // startup + DB + threat analysis overhead

    // Resolve assets to estimate scope
    const assetIds = params.assetIds || [];
    let targetCount = 0;

    for (const assetId of assetIds) {
      try {
        const asset = await storage.getAsset(assetId);
        if (!asset) continue;

        if (asset.type === 'range') {
          const cidrMatch = asset.value.match(/\/(\d+)$/);
          const prefix = cidrMatch ? parseInt(cidrMatch[1], 10) : 32;
          const hosts = Math.min(2 ** (32 - prefix) - 2, 65534);
          // /24 = 254 hosts → ~40 min,  /22 = 1022 hosts → ~80 min
          baseMins += Math.ceil(hosts * 0.16);
          targetCount += hosts;
        } else {
          baseMins += 3; // single host
          targetCount += 1;
        }
      } catch { /* skip unresolvable assets */ }
    }

    // Also resolve tag-based targets
    if (journey.targetSelectionMode === 'by_tag' && journey.selectedTags?.length > 0) {
      try {
        const tagAssets = await storage.getAssetsByTags(journey.selectedTags);
        for (const asset of tagAssets) {
          if (asset.type === 'range') {
            const cidrMatch = asset.value.match(/\/(\d+)$/);
            const prefix = cidrMatch ? parseInt(cidrMatch[1], 10) : 32;
            const hosts = Math.min(2 ** (32 - prefix) - 2, 65534);
            baseMins += Math.ceil(hosts * 0.16);
            targetCount += hosts;
          } else {
            baseMins += 3;
            targetCount += 1;
          }
        }
      } catch { /* ignore */ }
    }

    // Total = base + vuln script timeout + web scan extra
    const totalMs = baseMins * MINUTE + vulnTimeout + webExtra;
    const MAX_TIMEOUT = 4 * 60 * MINUTE; // 4 hour absolute cap
    const computed = Math.min(totalMs, MAX_TIMEOUT);

    log.info(`📐 Timeout calculado: ~${targetCount} hosts → base ${baseMins}min + vuln ${Math.round(vulnTimeout/MINUTE)}min + web ${Math.round(webExtra/MINUTE)}min = ${Math.round(computed/MINUTE)}min`);

    return computed;
  }

  /**
   * Gets current running jobs
   */
  getRunningJobs(): Job[] {
    return Array.from(this.runningJobs.values());
  }

  /**
   * Mark job as cancelled for cooperative cancellation
   */
  markJobAsCancelled(jobId: string): void {
    this.cancelledJobs.add(jobId);
    log.info(`🚫 Job ${jobId} marcado como cancelado`);
  }

  /**
   * Check if job was cancelled
   */
  isJobCancelled(jobId: string): boolean {
    return this.cancelledJobs.has(jobId);
  }

  /**
   * Remove job completed from running jobs map
   */
  private removeJobFromRunning(jobId: string): void {
    this.runningJobs.delete(jobId);
    this.jobTimeouts.delete(jobId);
    this.cancelledJobs.delete(jobId); // Cleanup cancelled flag
    log.info(`🗑️  Job ${jobId} removido dos jobs em execução`);
  }

  /**
   * Cancels a running job
   */
  async cancelJob(jobId: string): Promise<void> {
    const job = this.runningJobs.get(jobId);
    if (job) {
      // Mark as cancelled first for cooperative cancellation
      this.markJobAsCancelled(jobId);
      
      await this.updateJobStatus(jobId, 'failed', undefined, 'Job cancelado pelo usuário');
      this.removeJobFromRunning(jobId);
    }
  }
}

export const jobQueue = new JobQueueService();
