import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { storage } from '../storage';
import { APP_VERSION } from '../version';
import { createLogger } from '../lib/logger';

const log = createLogger('systemUpdate');

const INSTALL_DIR = process.env.INSTALL_DIR || '/opt/samureye';
const UPDATE_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes max

/**
 * Strict validation patterns for update parameters (FND-001 mitigation).
 *
 * These prevent command injection via MITM-controlled heartbeat responses.
 * Values are written to a shell env file that gets `source`d as root,
 * so we must ensure no shell metacharacters can slip through.
 */
const PARAM_VALIDATORS: Record<string, RegExp> = {
  // Git branch names: alphanumeric, hyphens, underscores, dots, forward slashes
  branch:     /^[a-zA-Z0-9][a-zA-Z0-9._\-\/]{0,253}[a-zA-Z0-9]$/,
  // Git tokens: alphanumeric + common token chars (GitHub PAT, etc.)
  token:      /^[a-zA-Z0-9_\-\.]{1,512}$/,
  // Boolean-like
  skipBackup: /^(true|false|1|0)$/i,
};

/** Characters that must NEVER appear in any parameter value (shell metacharacters) */
const SHELL_DANGEROUS = /[`$(){}|;&<>!\\'"#\n\r\x00]/;

/**
 * Validate and sanitize a single update parameter.
 * Returns the sanitized value or null if the parameter is rejected.
 */
export function validateUpdateParam(key: string, value: unknown): string | null {
  if (value === undefined || value === null) return null;

  const strValue = String(value);

  // Block any shell-dangerous characters regardless of the specific validator
  if (SHELL_DANGEROUS.test(strValue)) {
    log.error({ param: key }, 'update param rejected: contains dangerous shell characters (FND-001)');
    return null;
  }

  // Apply specific format validation if known parameter
  const validator = PARAM_VALIDATORS[key];
  if (validator) {
    if (!validator.test(strValue)) {
      log.error({ param: key, value: strValue.slice(0, 50) }, 'update param rejected: invalid format (FND-001)');
      return null;
    }
  } else {
    // Unknown parameter — reject (whitelist approach)
    log.warn({ param: key }, 'unknown update param ignored — not in whitelist (FND-001)');
    return null;
  }

  return strValue;
}

/**
 * Escape a value for safe inclusion inside single-quoted shell strings.
 * Single quotes cannot contain single quotes, so we use the '\'' idiom:
 * close the single-quote, add an escaped single-quote, re-open single-quote.
 */
export function shellSingleQuoteEscape(value: string): string {
  return value.replace(/'/g, "'\\''");
}

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

        // Build env vars — only trusted, internally-set values
        const envVars: Record<string, string> = {
          AUTO_CONFIRM: 'true',
          INSTALL_DIR,
          PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
          HOME: '/root',
        };

        // Validate and sanitize all params from the console (FND-001 mitigation).
        // These values arrive via heartbeat response and could be MITM-controlled.
        const validatedBranch = validateUpdateParam('branch', params.branch);
        if (validatedBranch) envVars.BRANCH = validatedBranch;

        const validatedSkipBackup = validateUpdateParam('skipBackup', params.skipBackup);
        if (validatedSkipBackup) envVars.SKIP_BACKUP = validatedSkipBackup === 'true' || validatedSkipBackup === '1' ? 'true' : 'false';

        const validatedToken = validateUpdateParam('token', params.token);
        if (validatedToken) envVars.GIT_TOKEN = validatedToken;

        // Log any unknown params that were silently dropped
        const knownParams = new Set(['branch', 'skipBackup', 'token']);
        for (const key of Object.keys(params)) {
          if (!knownParams.has(key)) {
            log.warn({ param: key }, 'unknown update param from console ignored');
          }
        }

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

        // Write env file (mode 600 — read only by root after unit starts).
        // SECURITY (FND-001): Use single quotes to prevent command substitution.
        // With double quotes, bash interprets $() and `` as command substitution
        // when the file is `source`d — an MITM attacker could exploit this.
        // Single quotes prevent ALL shell interpretation of the value.
        const envContent = Object.entries(envVars)
          .map(([k, v]) => `export ${k}='${shellSingleQuoteEscape(v)}'`)
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

        log.info({ logFile }, 'writing update trigger for systemd path unit');

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
            log.error({ timeoutMin: UPDATE_TIMEOUT_MS / 60000 }, 'update timed out');
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
              const tail = output.split('\n').filter(Boolean).slice(-20).join('\n');
              log.error({ exitCode, lastPhase, tail }, 'update.sh failed');
            } else {
              log.info({ lastPhase }, 'update completed successfully');
            }

            // Cleanup temp files
            try { fs.unlinkSync(wrapperPath); } catch { /* ok */ }
            try { fs.unlinkSync(logFile); } catch { /* ok */ }

            resolve({ exitCode, output, lastPhase });
          }

        } catch (err) {
          log.warn({ err }, 'error checking update status');
        }
      }, 3_000); // Poll every 3 seconds
    });
  }
}

export const systemUpdateService = new SystemUpdateService();
