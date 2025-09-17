import { EventEmitter } from 'events';
import { ChildProcess } from 'child_process';

export interface ProcessInfo {
  pid: number;
  name: 'nmap' | 'nuclei';
  startedAt: Date;
  lastHeartbeat: Date;
  stage: string;
  process: ChildProcess;
}

export interface ProcessUpdate {
  jobId: string;
  pid: number;
  processName: 'nmap' | 'nuclei';
  stage: string;
  isAlive: boolean;
}

class ProcessTrackerService extends EventEmitter {
  private processes = new Map<string, ProcessInfo[]>(); // jobId -> ProcessInfo[]
  private heartbeatIntervals = new Map<string, NodeJS.Timeout>(); // pid -> interval

  /**
   * Registra um novo processo para monitoramento
   */
  register(jobId: string, name: 'nmap' | 'nuclei', child: ChildProcess, stage: string): void {
    if (!child.pid) {
      throw new Error('Process PID not available');
    }

    const processInfo: ProcessInfo = {
      pid: child.pid,
      name,
      startedAt: new Date(),
      lastHeartbeat: new Date(),
      stage,
      process: child,
    };

    // Adicionar à lista de processos do job
    if (!this.processes.has(jobId)) {
      this.processes.set(jobId, []);
    }
    this.processes.get(jobId)!.push(processInfo);

    console.log(`📍 Processo registrado: ${name} pid ${child.pid} para job ${jobId} - ${stage}`);

    // Emitir evento inicial
    this.emit('processUpdate', {
      jobId,
      pid: child.pid,
      processName: name,
      stage,
      isAlive: true,
    } as ProcessUpdate);

    // Iniciar heartbeat monitoring
    this.startHeartbeat(jobId, child.pid);

    // Cleanup automático quando processo termina
    child.on('close', () => {
      this.unregister(jobId, child.pid!);
    });
  }

  /**
   * Atualiza o stage de um processo
   */
  updateStage(jobId: string, pid: number, stage: string): void {
    const jobProcesses = this.processes.get(jobId);
    if (!jobProcesses) return;

    const processInfo = jobProcesses.find(p => p.pid === pid);
    if (!processInfo) return;

    processInfo.stage = stage;
    processInfo.lastHeartbeat = new Date();

    console.log(`🔄 Atualizando stage: ${processInfo.name} pid ${pid} - ${stage}`);

    // Emitir update
    this.emit('processUpdate', {
      jobId,
      pid,
      processName: processInfo.name,
      stage,
      isAlive: true,
    } as ProcessUpdate);
  }

  /**
   * Verifica se um PID ainda está ativo
   */
  isAlive(pid: number): boolean {
    try {
      // process.kill(pid, 0) não mata o processo, apenas verifica se existe
      process.kill(pid, 0);
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Remove processo do tracking
   */
  unregister(jobId: string, pid: number): void {
    const jobProcesses = this.processes.get(jobId);
    if (!jobProcesses) return;

    const index = jobProcesses.findIndex(p => p.pid === pid);
    if (index === -1) return;

    const processInfo = jobProcesses[index];
    jobProcesses.splice(index, 1);

    // Limpar interval
    const intervalId = this.heartbeatIntervals.get(pid.toString());
    if (intervalId) {
      clearInterval(intervalId);
      this.heartbeatIntervals.delete(pid.toString());
    }

    console.log(`🗑️ Processo removido: ${processInfo.name} pid ${pid} para job ${jobId}`);

    // Emitir final update
    this.emit('processUpdate', {
      jobId,
      pid,
      processName: processInfo.name,
      stage: processInfo.stage,
      isAlive: false,
    } as ProcessUpdate);

    // Remover job se não há mais processos
    if (jobProcesses.length === 0) {
      this.processes.delete(jobId);
    }
  }

  /**
   * Mata um processo específico
   */
  kill(jobId: string, pid: number): boolean {
    const jobProcesses = this.processes.get(jobId);
    if (!jobProcesses) return false;

    const processInfo = jobProcesses.find(p => p.pid === pid);
    if (!processInfo) return false;

    console.log(`🔪 Matando processo: ${processInfo.name} pid ${pid}`);

    try {
      // Tentar SIGTERM primeiro
      processInfo.process.kill('SIGTERM');
      
      // Force kill após 5s se não responder
      setTimeout(() => {
        if (this.isAlive(pid)) {
          console.log(`🔪 Force kill: ${processInfo.name} pid ${pid}`);
          processInfo.process.kill('SIGKILL');
        }
      }, 5000);

      return true;
    } catch (error) {
      console.error(`❌ Erro ao matar processo ${pid}:`, error);
      return false;
    }
  }

  /**
   * Mata todos os processos de um job
   */
  killAll(jobId: string): number {
    const jobProcesses = this.processes.get(jobId);
    if (!jobProcesses) return 0;

    console.log(`🔪 Matando todos os processos do job ${jobId} (${jobProcesses.length} processos)`);

    let killed = 0;
    for (const processInfo of [...jobProcesses]) {
      if (this.kill(jobId, processInfo.pid)) {
        killed++;
      }
    }

    return killed;
  }

  /**
   * Lista todos os processos de um job
   */
  list(jobId: string): ProcessInfo[] {
    return this.processes.get(jobId) || [];
  }

  /**
   * Lista todos os jobs com processos ativos
   */
  listAllJobs(): string[] {
    return Array.from(this.processes.keys());
  }

  /**
   * Obtém estatísticas do tracker
   */
  getStats(): { totalJobs: number; totalProcesses: number; activeProcesses: number } {
    const totalJobs = this.processes.size;
    let totalProcesses = 0;
    let activeProcesses = 0;

    this.processes.forEach((jobProcesses) => {
      totalProcesses += jobProcesses.length;
      for (const processInfo of jobProcesses) {
        if (this.isAlive(processInfo.pid)) {
          activeProcesses++;
        }
      }
    });

    return { totalJobs, totalProcesses, activeProcesses };
  }

  /**
   * Inicia monitoramento heartbeat para um PID
   */
  private startHeartbeat(jobId: string, pid: number): void {
    const intervalId = setInterval(() => {
      if (!this.isAlive(pid)) {
        console.log(`💔 Processo morreu: pid ${pid} no job ${jobId}`);
        this.unregister(jobId, pid);
        return;
      }

      // Atualizar heartbeat
      const jobProcesses = this.processes.get(jobId);
      if (jobProcesses) {
        const processInfo = jobProcesses.find(p => p.pid === pid);
        if (processInfo) {
          processInfo.lastHeartbeat = new Date();
          
          // Emitir heartbeat update a cada 5s apenas para mostrar que está vivo
          this.emit('processUpdate', {
            jobId,
            pid,
            processName: processInfo.name,
            stage: processInfo.stage,
            isAlive: true,
          } as ProcessUpdate);
        }
      }
    }, 2000); // Check every 2 seconds

    this.heartbeatIntervals.set(pid.toString(), intervalId);
  }

  /**
   * Cleanup todos os processos ao desligar
   */
  shutdown(): void {
    console.log('🔄 Encerrando ProcessTracker...');
    
    for (const jobId of this.listAllJobs()) {
      this.killAll(jobId);
    }

    // Limpar todos os intervals
    this.heartbeatIntervals.forEach((interval) => {
      clearInterval(interval);
    });
    
    this.heartbeatIntervals.clear();
    this.processes.clear();
  }
}

// Singleton instance
export const processTracker = new ProcessTrackerService();

// Cleanup graceful no shutdown
process.on('SIGINT', () => {
  processTracker.shutdown();
  process.exit(0);
});

process.on('SIGTERM', () => {
  processTracker.shutdown();
  process.exit(0);
});