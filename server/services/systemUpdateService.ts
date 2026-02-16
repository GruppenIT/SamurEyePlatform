import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { storage } from '../storage';
import { APP_VERSION } from '../version';

const INSTALL_DIR = process.env.INSTALL_DIR || '/opt/samureye';
const UPDATE_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes max

interface UpdateResult {
  success: boolean;
  previousVersion: string;
  newVersion: string;
  phase: string;
  log: string;
  error?: string;
}

/**
 * SystemUpdateService
 *
 * Executes a local platform update triggered by a console command.
 * Runs the existing update.sh script with AUTO_CONFIRM=true and
 * captures output for reporting back to the console.
 *
 * Only one update can run at a time.
 */
class SystemUpdateService {
  private running = false;

  isRunning(): boolean {
    return this.running;
  }

  /**
   * Execute system update for a given command ID.
   * Runs asynchronously — caller should not await unless they want to block.
   */
  async execute(commandId: string, params: Record<string, any> = {}): Promise<UpdateResult> {
    if (this.running) {
      return {
        success: false,
        previousVersion: this.getCurrentVersion(),
        newVersion: this.getCurrentVersion(),
        phase: 'pre-check',
        log: '',
        error: 'Update já em execução. Aguarde a conclusão do update atual.',
      };
    }

    this.running = true;
    await storage.updateCommandStatus(commandId, 'running');

    const previousVersion = this.getCurrentVersion();

    try {
      const result = await this.runUpdate(params);

      const newVersion = this.getCurrentVersion();
      const updateResult: UpdateResult = {
        success: result.exitCode === 0,
        previousVersion,
        newVersion,
        phase: result.exitCode === 0 ? 'completed' : result.lastPhase,
        log: result.output.slice(-5000), // Last 5KB of output
        ...(result.exitCode !== 0 ? { error: `Update falhou na fase "${result.lastPhase}" (exit code ${result.exitCode})` } : {}),
      };

      await storage.updateCommandStatus(commandId, updateResult.success ? 'completed' : 'failed', {
        result: {
          previousVersion: updateResult.previousVersion,
          newVersion: updateResult.newVersion,
          phase: updateResult.phase,
        },
        error: updateResult.error,
      });

      return updateResult;
    } catch (err: any) {
      const errorResult: UpdateResult = {
        success: false,
        previousVersion,
        newVersion: previousVersion,
        phase: 'exception',
        log: '',
        error: err.message,
      };

      await storage.updateCommandStatus(commandId, 'failed', {
        error: err.message,
      });

      return errorResult;
    } finally {
      this.running = false;
    }
  }

  private getCurrentVersion(): string {
    // After an update, .version is regenerated — read fresh from disk
    try {
      const versionFile = path.join(INSTALL_DIR, '.version');
      if (fs.existsSync(versionFile)) {
        return fs.readFileSync(versionFile, 'utf-8').trim();
      }
    } catch { /* fallback below */ }

    return APP_VERSION;
  }

  private runUpdate(params: Record<string, any>): Promise<{
    exitCode: number;
    output: string;
    lastPhase: string;
  }> {
    return new Promise((resolve, reject) => {
      const scriptPath = path.join(INSTALL_DIR, 'update.sh');

      // Determine how to run the update
      let command: string;
      let args: string[];

      if (fs.existsSync(scriptPath)) {
        // Local script available
        command = '/bin/bash';
        args = [scriptPath];
      } else {
        // Fallback: download and run from GitHub
        command = '/bin/bash';
        args = ['-c', 'curl -fsSL https://raw.githubusercontent.com/GruppenIT/SamurEyePlatform/refs/heads/main/update.sh | bash'];
      }

      const env: Record<string, string> = {
        ...process.env as Record<string, string>,
        AUTO_CONFIRM: 'true',
        INSTALL_DIR,
      };

      // Allow branch override from console params
      if (params.branch) {
        env.BRANCH = params.branch;
      }

      // Allow skipping backup from console params
      if (params.skipBackup) {
        env.SKIP_BACKUP = 'true';
      }

      // Pass GitHub PAT for private repo access (token is NOT persisted to disk)
      if (params.token) {
        env.GIT_TOKEN = params.token;
      }

      let output = '';
      let lastPhase = 'starting';

      const child = spawn(command, args, {
        env,
        cwd: INSTALL_DIR,
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      const timeout = setTimeout(() => {
        child.kill('SIGTERM');
        setTimeout(() => child.kill('SIGKILL'), 5000);
      }, UPDATE_TIMEOUT_MS);

      const processLine = (line: string) => {
        output += line + '\n';

        // Track phases from update.sh output
        if (line.includes('Verificando instalação')) lastPhase = 'checking';
        else if (line.includes('Criando backup')) lastPhase = 'backup';
        else if (line.includes('Parando serviço')) lastPhase = 'stopping';
        else if (line.includes('Atualizando código')) lastPhase = 'pulling';
        else if (line.includes('Atualizando dependências') || line.includes('Instalando dependências')) lastPhase = 'dependencies';
        else if (line.includes('Compilando aplicação')) lastPhase = 'building';
        else if (line.includes('migrações')) lastPhase = 'migrating';
        else if (line.includes('Iniciando serviço')) lastPhase = 'restarting';
        else if (line.includes('Verificando integridade')) lastPhase = 'verifying';
        else if (line.includes('Atualização concluída')) lastPhase = 'completed';
        else if (line.includes('ROLLBACK')) lastPhase = 'rollback';
      };

      child.stdout.on('data', (data: Buffer) => {
        const lines = data.toString().split('\n');
        lines.forEach(processLine);
      });

      child.stderr.on('data', (data: Buffer) => {
        const lines = data.toString().split('\n');
        lines.forEach(processLine);
      });

      child.on('error', (err) => {
        clearTimeout(timeout);
        reject(err);
      });

      child.on('close', (exitCode) => {
        clearTimeout(timeout);
        resolve({
          exitCode: exitCode ?? 1,
          output,
          lastPhase,
        });
      });
    });
  }
}

export const systemUpdateService = new SystemUpdateService();
