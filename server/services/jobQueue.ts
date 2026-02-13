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
  // Campos para monitoramento de processos
  pid?: number;
  processName?: 'nmap' | 'nuclei';
  stage?: string;
  isAlive?: boolean;
}

class JobQueueService extends EventEmitter {
  private runningJobs = new Map<string, Job>();
  private maxConcurrentJobs = 3;
  private cancelledJobs = new Set<string>(); // Track cancelled jobs

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
        console.log(`🚫 Job ${update.jobId} não encontrado, ignorando update de processo`);
        return;
      }

      // Não atualizar se job já está em estado terminal
      if (job.status === 'completed' || job.status === 'failed' || job.status === 'timeout') {
        console.log(`🚫 Job ${update.jobId} em estado terminal (${job.status}), ignorando update de processo`);
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

      console.log(`📡 JobUpdate emitido para ${update.jobId}: ${currentTask} (alive: ${update.isAlive}, status: ${job.status})`);
    } catch (error) {
      console.error(`❌ Erro ao processar update de processo:`, error);
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
        console.error(`Cannot process non-existent job: ${job.id}`);
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

      // Execute the journey
      await journeyExecutor.executeJourney(journey, job.id, (update) => {
        // Handle updateJobStatus asynchronously to avoid unhandled promise rejections
        this.updateJobStatus(job.id, update.status, update.progress, update.currentTask).catch((error) => {
          if (error.message?.includes('not found')) {
            console.log(`Job ${job.id} no longer exists, ignoring progress update`);
          } else {
            console.error(`Failed to update job status for ${job.id}:`, error);
          }
        });
      });

      // Check if job was cancelled before marking as completed
      if (this.isJobCancelled(job.id)) {
        console.log(`🚫 Job ${job.id} foi cancelado, não marcando como completed`);
        await this.updateJobStatus(job.id, 'failed', undefined, 'Job cancelado pelo usuário');
        return;
      }

      // Mark as completed
      await this.updateJobStatus(job.id, 'completed', 100, 'Execução finalizada');
      
    } catch (error) {
      console.error(`Erro na execução do job ${job.id}:`, error);
      try {
        await this.updateJobStatus(job.id, 'failed', undefined, error instanceof Error ? error.message : 'Erro desconhecido');
      } catch (updateError) {
        // Ignore "not found" errors when marking as failed - job may have been deleted
        if (!(updateError instanceof Error) || !updateError.message?.includes('not found')) {
          console.error(`Failed to mark job ${job.id} as failed:`, updateError);
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
      console.error(`Failed to update job ${jobId}: ${dbError}`);
      // Don't emit update for non-existent jobs to prevent ghost jobs in UI
      if (dbError instanceof Error && dbError.message.includes('not found')) {
        console.error(`Ghost job detected: ${jobId} - removing from running jobs`);
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

    // Timeout long-running jobs (30 minutes)
    setInterval(async () => {
      const runningJobs = await storage.getRunningJobs();
      const now = new Date();

      for (const job of runningJobs) {
        if (job.startedAt) {
          const runtime = now.getTime() - job.startedAt.getTime();
          if (runtime > 30 * 60 * 1000) { // 30 minutes
            // Kill all child processes associated with this job
            const killedCount = processTracker.killAll(job.id);
            if (killedCount > 0) {
              console.log(`🔪 Timeout: ${killedCount} processos terminados para job ${job.id}`);
            }

            await this.updateJobStatus(job.id, 'timeout', undefined, 'Job ultrapassou tempo limite de 30 minutos');
            // Release concurrency slot
            this.removeJobFromRunning(job.id);
          }
        }
      }
    }, 60000); // Check every minute
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
    console.log(`🚫 Job ${jobId} marcado como cancelado`);
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
    this.cancelledJobs.delete(jobId); // Cleanup cancelled flag
    console.log(`🗑️  Job ${jobId} removido dos jobs em execução`);
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
