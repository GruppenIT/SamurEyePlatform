import { EventEmitter } from 'events';
import { storage } from '../storage';
import { journeyExecutor } from './journeyExecutor';
import { type Job, type InsertJob } from '@shared/schema';

export interface JobUpdate {
  jobId: string;
  status: Job['status'];
  progress?: number;
  currentTask?: string;
  error?: string;
}

class JobQueueService extends EventEmitter {
  private runningJobs = new Map<string, Job>();
  private maxConcurrentJobs = 3;

  constructor() {
    super();
    this.startQueueProcessor();
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

      // Mark as completed
      await this.updateJobStatus(job.id, 'completed', 100, 'Execução finalizada');
      
    } catch (error) {
      console.error(`Erro na execução do job ${job.id}:`, error);
      try {
        await this.updateJobStatus(job.id, 'failed', undefined, error instanceof Error ? error.message : 'Erro desconhecido');
      } catch (updateError) {
        // Ignore "not found" errors when marking as failed - job may have been deleted
        if (!updateError.message?.includes('not found')) {
          console.error(`Failed to mark job ${job.id} as failed:`, updateError);
        }
      }
    } finally {
      this.runningJobs.delete(job.id);
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
            await this.updateJobStatus(job.id, 'timeout', undefined, 'Job ultrapassou tempo limite');
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
   * Cancels a running job
   */
  async cancelJob(jobId: string): Promise<void> {
    const job = this.runningJobs.get(jobId);
    if (job) {
      await this.updateJobStatus(jobId, 'failed', undefined, 'Job cancelado pelo usuário');
      this.runningJobs.delete(jobId);
    }
  }
}

export const jobQueue = new JobQueueService();
