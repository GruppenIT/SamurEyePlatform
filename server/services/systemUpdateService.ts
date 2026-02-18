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

      // update.sh requires root (check_root). The service runs as samureye,
      // so we must use sudo. The install.sh/update.sh provisions a sudoers
      // rule: samureye ALL=(root) NOPASSWD: <INSTALL_DIR>/update.sh
      //
      // sudo resets environment by default, so we pass env vars explicitly
      // as VAR=value arguments before the command.
      const envVars: Record<string, string> = {
        AUTO_CONFIRM: 'true',
        INSTALL_DIR,
        PATH: process.env.PATH || '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        HOME: '/root',
      };

      if (params.branch) envVars.BRANCH = params.branch;
      if (params.skipBackup) envVars.SKIP_BACKUP = 'true';
      if (params.token) envVars.GIT_TOKEN = params.token;

      // Load .env vars for database access (needed by backup and migrations)
      const dotenvPath = path.join(INSTALL_DIR, '.env');
      if (fs.existsSync(dotenvPath)) {
        try {
          const lines = fs.readFileSync(dotenvPath, 'utf-8').split('\n');
          for (const line of lines) {
            const match = line.match(/^([A-Z_][A-Z0-9_]*)=(.*)$/);
            if (match) {
              envVars[match[1]] = match[2].replace(/^["']|["']$/g, '');
            }
          }
        } catch { /* ignore */ }
      }

      // Build: sudo VAR1=val1 VAR2=val2 /bin/bash <script>
      const sudoEnvArgs = Object.entries(envVars).map(([k, v]) => `${k}=${v}`);

      let command: string;
      let args: string[];

      if (fs.existsSync(scriptPath)) {
        command = '/usr/bin/sudo';
        args = [...sudoEnvArgs, '/bin/bash', scriptPath];
      } else {
        command = '/usr/bin/sudo';
        args = [...sudoEnvArgs, '/bin/bash', '-c', 'curl -fsSL https://raw.githubusercontent.com/GruppenIT/SamurEyePlatform/refs/heads/main/update.sh | bash'];
      }

      console.log(`🔧 Executando update: sudo ${sudoEnvArgs.filter(a => !a.startsWith('GIT_TOKEN') && !a.startsWith('PG')).join(' ')} /bin/bash update.sh`);

      let output = '';
      let lastPhase = 'starting';

      const child = spawn(command, args, {
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

        // Log summary for debugging remote update failures
        if (exitCode !== 0) {
          console.error(`❌ update.sh saiu com código ${exitCode} na fase "${lastPhase}"`);
          // Show last 20 lines of output for context
          const tail = output.split('\n').filter(Boolean).slice(-20).join('\n');
          console.error(`📋 Últimas linhas do output:\n${tail}`);
        }

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
