import { execSync } from 'child_process';
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
 *
 * The samureye-api systemd unit runs with NoNewPrivileges=yes +
 * ProtectSystem=strict, which blocks both sudo and systemctl start.
 * To run update.sh as root we use a pair of pre-installed companion
 * systemd units (samureye-update.path + samureye-update.service)
 * that the install.sh and update.sh provision at setup time.
 *
 * Flow:
 *  1. Service writes env file + wrapper script to INSTALL_DIR/temp/ (writable)
 *  2. Service writes a trigger file that samureye-update.path watches (inotify)
 *  3. systemd detects the trigger and starts samureye-update.service
 *  4. The companion service runs the wrapper as root (no NoNewPrivileges)
 *  5. Service polls the unit status and reads the log file
 *
 * Only one update can run at a time.
 */
class SystemUpdateService {
  private running = false;

  isRunning(): boolean {
    return this.running;
  }

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
        log: result.output.slice(-5000),
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
      try {
        const scriptPath = path.join(INSTALL_DIR, 'update.sh');
        const tempDir = path.join(INSTALL_DIR, 'temp');
        const logFile = path.join(tempDir, 'update-output.log');
        const envFile = path.join(tempDir, 'update-env.sh');
        const wrapperPath = path.join(tempDir, 'run-update.sh');

        // Ensure temp dir exists
        if (!fs.existsSync(tempDir)) {
          fs.mkdirSync(tempDir, { recursive: true });
        }

        // Verify the companion path unit is enabled (installed by update.sh / install.sh)
        const pathUnitEnabled = (() => {
          try {
            const state = execSync(
              'systemctl is-enabled samureye-update.path 2>/dev/null || true',
              { timeout: 5_000 }
            ).toString().trim();
            return state === 'enabled';
          } catch { return false; }
        })();
        if (!pathUnitEnabled) {
          throw new Error(
            'samureye-update.path não está habilitado. Execute um update manual primeiro: ' +
            'sudo curl -fsSL https://raw.githubusercontent.com/GruppenIT/SamurEyePlatform/main/update.sh | sudo AUTO_CONFIRM=true bash'
          );
        }

        // Clean previous files
        try { fs.unlinkSync(logFile); } catch { /* ok */ }
        try { fs.unlinkSync(path.join(tempDir, 'update-exit-code')); } catch { /* ok */ }
        try { fs.unlinkSync(path.join(tempDir, '.update-trigger')); } catch { /* ok */ }

        // Build env vars
        const envVars: Record<string, string> = {
          AUTO_CONFIRM: 'true',
          INSTALL_DIR,
          PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
          HOME: '/root',
        };

        if (params.branch) envVars.BRANCH = params.branch;
        if (params.skipBackup) envVars.SKIP_BACKUP = 'true';
        if (params.token) envVars.GIT_TOKEN = params.token;

        // Load .env vars for database access (backup and migrations need them)
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

        // Write env file (mode 600 — read only by root after unit starts)
        const envContent = Object.entries(envVars)
          .map(([k, v]) => `export ${k}=${JSON.stringify(v)}`)
          .join('\n');
        fs.writeFileSync(envFile, envContent, { mode: 0o600 });

        // Determine the actual update command
        let updateCmd: string;
        if (fs.existsSync(scriptPath)) {
          updateCmd = `/bin/bash ${scriptPath}`;
        } else {
          updateCmd = `curl -fsSL https://raw.githubusercontent.com/GruppenIT/SamurEyePlatform/refs/heads/main/update.sh | /bin/bash`;
        }

        // Write wrapper script (runs as root via the companion unit)
        const triggerFile = path.join(tempDir, '.update-trigger');
        const resultFile = path.join(tempDir, 'update-exit-code');
        const wrapperContent = [
          '#!/bin/bash',
          'set -uo pipefail',
          `rm -f ${triggerFile}`,
          `source ${envFile}`,
          `${updateCmd} 2>&1 | tee ${logFile}; EXIT_CODE=\${PIPESTATUS[0]}`,
          `rm -f ${envFile}`,
          `echo \$EXIT_CODE > ${resultFile}`,
          'exit $EXIT_CODE',
          '',
        ].join('\n');
        fs.writeFileSync(wrapperPath, wrapperContent, { mode: 0o755 });

        console.log(`🔧 Escrevendo trigger de update para systemd path unit...`);
        console.log(`📋 Log file: ${logFile}`);

        // Write trigger file — the samureye-update.path unit watches for this
        // and automatically starts samureye-update.service when it appears.
        // This avoids the need for systemctl start (blocked by NoNewPrivileges).
        fs.writeFileSync(triggerFile, JSON.stringify({ ts: Date.now() }), { mode: 0o644 });

        // Poll for completion (path unit detects trigger via inotify ~instantly)
        this.pollUpdateCompletion(logFile, wrapperPath).then(resolve).catch(reject);

      } catch (err) {
        reject(err);
      }
    });
  }

  /**
   * Poll the samureye-update.service unit until it finishes,
   * then read the output log and determine exit code.
   */
  private pollUpdateCompletion(logFile: string, wrapperPath: string): Promise<{
    exitCode: number;
    output: string;
    lastPhase: string;
  }> {
    return new Promise((resolve) => {
      const startTime = Date.now();
      let lastPhase = 'starting';

      const poll = setInterval(() => {
        try {
          // Check if the unit is still active
          const status = execSync(
            'systemctl is-active samureye-update.service 2>/dev/null || true',
            { timeout: 5_000 }
          ).toString().trim();

          // Read current log output for phase tracking
          let output = '';
          try {
            output = fs.readFileSync(logFile, 'utf-8');
          } catch { /* file may not exist yet */ }

          // Track phases (use if, not else-if — phases progress forward)
          if (output.includes('Verificando instalação')) lastPhase = 'checking';
          if (output.includes('Criando backup')) lastPhase = 'backup';
          if (output.includes('Parando serviço')) lastPhase = 'stopping';
          if (output.includes('Atualizando código')) lastPhase = 'pulling';
          if (output.includes('Atualizando dependências') || output.includes('Instalando dependências')) lastPhase = 'dependencies';
          if (output.includes('Compilando aplicação')) lastPhase = 'building';
          if (output.includes('migrações')) lastPhase = 'migrating';
          if (output.includes('Iniciando serviço')) lastPhase = 'restarting';
          if (output.includes('Verificando integridade')) lastPhase = 'verifying';
          if (output.includes('Atualização concluída')) lastPhase = 'completed';
          if (output.includes('ROLLBACK')) lastPhase = 'rollback';

          // Timeout check
          if (Date.now() - startTime > UPDATE_TIMEOUT_MS) {
            clearInterval(poll);
            try { execSync('systemctl stop samureye-update.service', { timeout: 10_000 }); } catch { /* ok */ }
            console.error(`❌ Update timeout após ${UPDATE_TIMEOUT_MS / 60000} minutos`);
            resolve({ exitCode: 124, output, lastPhase });
            return;
          }

          // Check if finished (inactive = completed successfully, failed = error)
          if (status === 'inactive' || status === 'failed') {
            clearInterval(poll);

            // Get exit code from systemd
            let exitCode = 0;
            try {
              const exitStr = execSync(
                'systemctl show -p ExecMainStatus --value samureye-update.service 2>/dev/null || echo 1',
                { timeout: 5_000 }
              ).toString().trim();
              exitCode = parseInt(exitStr, 10) || 0;
            } catch {
              exitCode = status === 'failed' ? 1 : 0;
            }

            // Read final output
            try {
              output = fs.readFileSync(logFile, 'utf-8');
            } catch { /* use what we had */ }

            // Log on failure
            if (exitCode !== 0) {
              console.error(`❌ update.sh saiu com código ${exitCode} na fase "${lastPhase}"`);
              const tail = output.split('\n').filter(Boolean).slice(-20).join('\n');
              console.error(`📋 Últimas linhas do output:\n${tail}`);
            } else {
              console.log(`✅ Update concluído com sucesso na fase "${lastPhase}"`);
            }

            // Cleanup temp files
            try { fs.unlinkSync(wrapperPath); } catch { /* ok */ }
            try { fs.unlinkSync(logFile); } catch { /* ok */ }

            resolve({ exitCode, output, lastPhase });
          }

        } catch (err) {
          console.warn(`⚠️  Erro ao verificar status do update: ${err}`);
        }
      }, 3_000); // Poll every 3 seconds
    });
  }
}

export const systemUpdateService = new SystemUpdateService();
