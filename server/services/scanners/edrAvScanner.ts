import { spawn, execSync } from 'child_process';
import * as crypto from 'crypto';
import * as path from 'path';
import * as fs from 'fs/promises';
import { storage } from '../../storage';
import { createLogger } from '../../lib/logger';

const log = createLogger('edrScanner');

/**
 * Preferred directory for temporary auth files (FND-004 mitigation).
 * /dev/shm is a tmpfs (RAM-backed) — files never touch disk, preventing
 * credential recovery from disk forensics. Falls back to /tmp if unavailable.
 */
const SECURE_TEMP_DIR = (() => {
  try {
    const stats = require('fs').statSync('/dev/shm');
    if (stats.isDirectory()) return '/dev/shm';
  } catch { /* fallback */ }
  return '/tmp';
})();

/**
 * Create a temporary auth file with secure properties (FND-004 mitigation):
 * - Stored in /dev/shm (tmpfs, RAM-only) when available
 * - Unpredictable filename using crypto.randomBytes
 * - Mode 0o600 (owner-read-only)
 * Returns the file path. Caller MUST call secureCleanup() when done.
 */
async function createSecureAuthFile(
  credential: { username: string; password: string; domain?: string }
): Promise<string> {
  const randomName = `smbauth_${crypto.randomBytes(16).toString('hex')}`;
  const authFile = path.join(SECURE_TEMP_DIR, randomName);

  const authContent = [
    `username=${credential.username}`,
    `password=${credential.password}`,
    credential.domain ? `domain=${credential.domain}` : '',
    credential.domain ? `workgroup=${credential.domain}` : '',
  ].filter(Boolean).join('\n');

  await fs.writeFile(authFile, authContent, { mode: 0o600 });
  return authFile;
}

/**
 * Securely delete a file by overwriting its contents before unlinking (FND-004).
 * This prevents credential recovery from disk (defense in depth even on tmpfs).
 */
async function secureCleanup(filePath: string | null): Promise<void> {
  if (!filePath) return;
  try {
    // Overwrite with zeros before deletion
    const stat = await fs.stat(filePath);
    await fs.writeFile(filePath, Buffer.alloc(stat.size, 0), { flag: 'r+' });
    await fs.unlink(filePath);
  } catch {
    // Best-effort: try plain unlink as fallback
    try { await fs.unlink(filePath); } catch { /* already gone */ }
  }
}

/**
 * Scanner para testes EDR/AV reais
 * Implementa deployment de arquivo EICAR via SMB e WMI
 */
export class EDRAVScanner {
  private readonly eicarContent = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

  /**
   * Executa teste EDR/AV com credenciais e sistema de retry para garantir amostragem
   */
  async runEDRAVTest(
    credential: { username: string; password: string; domain?: string },
    targets: string[],
    sampleRate: number = 15,
    timeout: number = 30
  ): Promise<{
    findings: any[];
    statistics: {
      totalDiscovered: number;
      requestedSampleRate: number;
      requestedSampleSize: number;
      successfulDeployments: number;
      failedDeployments: number;
      attemptsExhausted: boolean;
      eicarRemovedCount: number;
      eicarPersistedCount: number;
    };
  }> {
    const totalDiscovered = targets.length;
    const requestedSampleSize = Math.max(1, Math.floor(totalDiscovered * sampleRate / 100));
    
    log.info({ totalDiscovered, sampleRate, requestedSampleSize }, 'starting EDR/AV test');
    
    const findings: any[] = [];
    const usedTargets = new Set<string>();
    const availableTargets = [...targets]; // Cópia para manipular
    let successfulDeployments = 0;
    let failedDeployments = 0;
    
    // Shuffle initial targets para randomização
    this.shuffleArray(availableTargets);
    
    while (successfulDeployments < requestedSampleSize && availableTargets.length > 0) {
      // Selecionar próximo target disponível
      const currentTarget = availableTargets.shift()!;
      usedTargets.add(currentTarget);
      
      log.info({ host: currentTarget, attempt: successfulDeployments + failedDeployments + 1 }, 'testing host');
      
      try {
        const finding = await this.testSingleHost(currentTarget, credential, timeout);
        
        // Verificar se conseguiu fazer deploy do EICAR (sucesso na cópia)
        if (finding.error) {
          failedDeployments++;
          log.warn({ host: currentTarget, err: finding.error }, 'EICAR deploy failed');
          findings.push(finding);
        } else {
          successfulDeployments++;
          findings.push(finding);
          log.info({ host: currentTarget, eicarRemoved: finding.eicarRemoved }, `EICAR deployed — ${finding.eicarRemoved ? 'removed by EDR/AV' : 'PERSISTED — EDR/AV failure'}`);
        }
        
      } catch (error) {
        failedDeployments++;
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error({ host: currentTarget, err: errorMessage }, 'critical error testing host');
        
        findings.push({
          type: 'edr_test',
          hostname: currentTarget,
          error: errorMessage,
          eicarRemoved: null,
          testDuration: 0,
          timestamp: new Date().toISOString(),
        });
      }
    }
    
    const attemptsExhausted = successfulDeployments < requestedSampleSize;
    const eicarRemovedCount = findings.filter(f => f.eicarRemoved === true).length;
    const eicarPersistedCount = findings.filter(f => f.eicarRemoved === false).length;
    
    // Analisar tipos de falhas para diagnóstico mais preciso
    const authFailures = findings.filter(f => f.error && f.error.includes('NT_STATUS_LOGON_FAILURE')).length;
    const accessDenied = findings.filter(f => f.error && f.error.includes('NT_STATUS_ACCESS_DENIED')).length;
    const networkErrors = findings.filter(f => f.error && f.error.includes('NT_STATUS_BAD_NETWORK_NAME')).length;
    const otherErrors = failedDeployments - authFailures - accessDenied - networkErrors;

    const stats = {
      totalDiscovered,
      sampleRate,
      requestedSampleSize,
      successfulDeployments,
      failedDeployments,
      attemptsExhausted,
      eicarRemovedCount,
      eicarPersistedCount,
      failureBreakdown: { authFailures, accessDenied, networkErrors, otherErrors },
    };

    if (attemptsExhausted) {
      log.warn(stats, 'EDR/AV test finished — sample target NOT reached');
    } else {
      log.info(stats, 'EDR/AV test finished — sample target reached');
    }
    
    return {
      findings,
      statistics: {
        totalDiscovered,
        requestedSampleRate: sampleRate,
        requestedSampleSize,
        successfulDeployments,
        failedDeployments,
        attemptsExhausted,
        eicarRemovedCount,
        eicarPersistedCount,
      }
    };
  }

  /**
   * Testa um único host com deployment EICAR
   */
  private async testSingleHost(
    hostname: string,
    credential: { username: string; password: string; domain?: string },
    timeout: number = 30
  ): Promise<any> {
    const startTime = Date.now();
    log.debug({ host: hostname }, 'testing EDR/AV');

    // Usar timeout da jornada (parâmetro recebido)
    const timeoutMs = Math.max(5, Math.min(3600, timeout)) * 1000; // Limitar entre 5s e 1h
    log.debug({ timeoutSec: Math.floor(timeoutMs / 1000) }, 'EICAR test timeout configured');

    try {
      // 1. Primeiro, tentar deployment via SMB
      const smbResult = await this.deployEicarViaSMB(hostname, credential);
      
      if (smbResult.success) {
        // 2. Aguardar tempo configurado para o EDR/AV agir
        log.debug({ host: hostname, waitSec: Math.floor(timeoutMs / 1000) }, 'waiting for EDR/AV to process EICAR');
        await this.delay(timeoutMs);
        
        // 3. Verificar se o arquivo ainda existe
        const fileExists = await this.checkEicarFileExists(hostname, credential, smbResult.filePath!);
        
        // 4. Tentar limpar o arquivo (se ainda existir)
        if (fileExists) {
          await this.cleanupEicarFile(hostname, credential, smbResult.filePath!);
        }

        const testDuration = Math.floor((Date.now() - startTime) / 1000);

        return {
          type: 'edr_test',
          hostname,
          filePath: smbResult.filePath!,
          eicarRemoved: !fileExists,
          deploymentMethod: 'smb',
          testDuration,
          timestamp: new Date().toISOString(),
        };
      } else {
        // Fallback para WMI se SMB falhar
        const wmiResult = await this.deployEicarViaWMI(hostname, credential);
        
        if (wmiResult.success) {
          // Aguardar mesmo tempo configurado para WMI
          log.debug({ host: hostname, waitSec: Math.floor(timeoutMs / 1000) }, 'waiting after WMI deploy');
          await this.delay(timeoutMs);
          const fileExists = await this.checkEicarFileExists(hostname, credential, wmiResult.filePath!);
          
          if (fileExists) {
            await this.cleanupEicarFile(hostname, credential, wmiResult.filePath!);
          }

          const testDuration = Math.floor((Date.now() - startTime) / 1000);

          return {
            type: 'edr_test',
            hostname,
            filePath: wmiResult.filePath!,
            eicarRemoved: !fileExists,
            deploymentMethod: 'wmi',
            testDuration,
            timestamp: new Date().toISOString(),
          };
        } else {
          throw new Error(`Falha em todos os métodos de deployment: SMB (${smbResult.error}), WMI (${wmiResult.error})`);
        }
      }
    } catch (error) {
      const testDuration = Math.floor((Date.now() - startTime) / 1000);
      const errorMessage = error instanceof Error ? error.message : String(error);
      
      return {
        type: 'edr_test',
        hostname,
        error: errorMessage,
        eicarRemoved: null,
        testDuration,
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Deploy EICAR via SMB usando smbclient com arquivo de autenticação seguro
   */
  private async deployEicarViaSMB(
    hostname: string,
    credential: { username: string; password: string; domain?: string }
  ): Promise<{ success: boolean; filePath?: string; error?: string }> {
    let tempFile: string | null = null;
    let authFile: string | null = null;

    try {
      // Verificar se smbclient está disponível
      const smbclientAvailable = await this.checkBinaryExists('smbclient');
      if (!smbclientAvailable) {
        return {
          success: false,
          error: 'smbclient não está instalado ou não está no PATH',
        };
      }

      // Criar arquivo EICAR temporário
      tempFile = path.join(SECURE_TEMP_DIR, `eicar_${crypto.randomBytes(8).toString('hex')}.txt`);
      const targetPath = 'C$\\Windows\\Temp\\samureye_eicar.txt';

      await fs.writeFile(tempFile, this.eicarContent);

      // FND-004: Auth file em tmpfs com nome imprevisível e modo 0o600
      authFile = await createSecureAuthFile(credential);

      log.debug({ storage: SECURE_TEMP_DIR === '/dev/shm' ? 'tmpfs' : '/tmp' }, 'auth file created');

      const targetSmbPath = 'Windows\\Temp\\samureye_eicar.txt';

      const args = [
        `//${hostname}/C$`,
        '-A', authFile,
        '-c', `put "${tempFile}" "${targetSmbPath}"`
      ];

      log.info({ host: hostname }, 'executing SMB deploy');

      // Testar conectividade básica antes de tentar copiar
      const testArgs = [
        `//${hostname}/C$`,
        '-A', authFile,
        '-c', 'ls'
      ];

      const testResult = await this.executeCommand('smbclient', testArgs, 15000);

      if (testResult.exitCode !== 0) {
        log.debug({ host: hostname, exitCode: testResult.exitCode }, 'SMB connectivity test failed');
      } else {
        log.debug({ host: hostname }, 'SMB connectivity OK');
      }

      const result = await this.executeCommand('smbclient', args, 30000);

      log.debug({ host: hostname, exitCode: result.exitCode }, 'SMB deploy result');

      if (result.exitCode === 0) {
        log.info({ host: hostname }, 'SMB deploy successful');
        return {
          success: true,
          filePath: `\\\\${hostname}\\${targetPath}`,
        };
      } else {
        // Diagnóstico detalhado baseado no tipo de erro
        let diagnosticMessage = result.stderr || result.stdout || 'Erro desconhecido no smbclient';

        // FND-004: Removido fallback com credenciais na linha de comando.
        // Credenciais em argv são visíveis em /proc/<pid>/cmdline por qualquer
        // usuário do sistema. Se o auth file falhar, reportar o erro.
        if (result.stderr?.includes('Unable to open credentials file') || result.stderr?.includes('Error reading credentials')) {
          log.error({ host: hostname, tempDir: SECURE_TEMP_DIR }, 'failed to read auth file — check permissions');
          diagnosticMessage = `Falha ao ler arquivo de autenticação. Verifique permissões em ${SECURE_TEMP_DIR}.`;
        }

        if (result.stdout?.includes('NT_STATUS_LOGON_FAILURE') || diagnosticMessage.includes('NT_STATUS_LOGON_FAILURE')) {
          log.warn({ host: hostname }, 'NT_STATUS_LOGON_FAILURE — account may need local admin privileges on target');

          diagnosticMessage = `FALHA DE AUTENTICAÇÃO SMB: ${hostname} negou acesso à conta '${credential.username}'. Servidores membros requerem privilégios administrativos locais específicos.`;

        } else if (result.stdout?.includes('NT_STATUS_ACCESS_DENIED') || result.stderr.includes('NT_STATUS_ACCESS_DENIED')) {
          diagnosticMessage = `ACESSO NEGADO: Conta autenticada mas sem privilégios para acessar C$ em ${hostname}`;

        } else if (result.stdout?.includes('NT_STATUS_BAD_NETWORK_NAME')) {
          diagnosticMessage = `SERVIDOR INACESSÍVEL: ${hostname} não responde ou share C$ indisponível`;

        } else if (result.stderr?.includes('gencache_init')) {
          // Warnings de gencache não impedem funcionamento
        }

        return {
          success: false,
          error: diagnosticMessage,
        };
      }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error),
      };
    } finally {
      // FND-004: Secure cleanup — overwrite before delete
      await secureCleanup(tempFile);
      await secureCleanup(authFile);
    }
  }

  /**
   * Deploy EICAR via WMI - DESABILITADO POR QUESTÕES DE SEGURANÇA
   * WMI expõe credenciais em argumentos de processo, não recomendado para produção
   */
  private async deployEicarViaWMI(
    hostname: string,
    credential: { username: string; password: string; domain?: string }
  ): Promise<{ success: boolean; filePath?: string; error?: string }> {
    // Método WMI desabilitado por questões de segurança
    // Credenciais seriam expostas em argumentos de processo
    log.warn('WMI deploy disabled for security — use SMB only');
    
    return {
      success: false,
      error: 'WMI deployment desabilitado por questões de segurança. Use SMB.',
    };
  }

  /**
   * Verifica se o arquivo EICAR ainda existe usando autenticação segura
   */
  private async checkEicarFileExists(
    hostname: string,
    credential: { username: string; password: string; domain?: string },
    filePath: string
  ): Promise<boolean> {
    let authFile: string | null = null;

    try {
      authFile = await createSecureAuthFile(credential);

      const args = [
        `//${hostname}/C$`,
        '-A', authFile,
        '-c', 'ls "Windows\\Temp\\samureye_eicar.txt"'
      ];

      const result = await this.executeCommand('smbclient', args, 10000);

      const fileExists = result.exitCode === 0 && !result.stderr.includes('NT_STATUS_OBJECT_NAME_NOT_FOUND');
      log.info({ host: hostname, fileExists }, `EICAR file ${fileExists ? 'present' : 'removed by EDR/AV'}`);

      return fileExists;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      log.error({ host: hostname, err: errorMessage }, 'error checking EICAR file');
      return false;
    } finally {
      await secureCleanup(authFile);
    }
  }

  /**
   * Remove o arquivo EICAR (cleanup) usando autenticação segura
   */
  private async cleanupEicarFile(
    hostname: string,
    credential: { username: string; password: string; domain?: string },
    filePath: string
  ): Promise<void> {
    let authFile: string | null = null;

    try {
      authFile = await createSecureAuthFile(credential);

      const args = [
        `//${hostname}/C$`,
        '-A', authFile,
        '-c', 'del "Windows\\Temp\\samureye_eicar.txt"'
      ];

      await this.executeCommand('smbclient', args, 10000);

      log.info({ host: hostname }, 'EICAR file cleaned up');
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      log.error({ host: hostname, err: errorMessage }, 'error removing EICAR file');
    } finally {
      await secureCleanup(authFile);
    }
  }

  /**
   * Verifica se um binário existe no sistema
   */
  private async checkBinaryExists(binaryName: string): Promise<boolean> {
    try {
      const result = await this.executeCommand('which', [binaryName], 5000);
      return result.exitCode === 0;
    } catch (error) {
      log.error({ binary: binaryName, err: error }, 'error checking binary availability');
      return false;
    }
  }

  /**
   * Executa comando com timeout
   */
  private executeCommand(command: string, args: string[], timeout: number = 30000): Promise<{
    stdout: string;
    stderr: string;
    exitCode: number;
  }> {
    return new Promise(async (resolve, reject) => {
      // Criar diretório para cache do Samba se não existir
      try {
        await fs.mkdir('/tmp/samba', { recursive: true });
      } catch {
        // Ignorar se já existe
      }
      
      // FND-004: Sanitize log — redact auth file paths and any credential-like args
      const safeArgs = args.map(a => a.startsWith(SECURE_TEMP_DIR) ? '[AUTH_FILE]' : a);
      log.debug({ command, args: safeArgs }, 'executing command');
      
      const child = spawn(command, args, {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { 
          ...process.env,
          // Configurar diretórios temporários para Samba evitar erro read-only
          HOME: '/tmp',
          TMPDIR: '/tmp',
          TMP: '/tmp',
          TEMP: '/tmp',
          // Configurações específicas do Samba para evitar erros de gencache
          SAMBA_CACHEDIR: '/tmp/samba',
          GENCACHE_PATH: '/tmp/samba/gencache.tdb'
        },
      });

      let stdout = '';
      let stderr = '';

      child.stdout?.on('data', (data) => {
        stdout += data.toString();
      });

      child.stderr?.on('data', (data) => {
        stderr += data.toString();
      });

      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        reject(new Error(`Comando ${command} excedeu timeout de ${timeout}ms`));
      }, timeout);

      child.on('close', (code) => {
        clearTimeout(timer);
        resolve({
          stdout: stdout.trim(),
          stderr: stderr.trim(),
          exitCode: code || 0,
        });
      });

      child.on('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
    });
  }

  /**
   * Seleciona amostra de hosts para teste
   */
  private sampleHosts(hosts: string[], sampleSize: number): string[] {
    if (hosts.length <= sampleSize) {
      return [...hosts];
    }

    const shuffled = [...hosts];
    this.shuffleArray(shuffled);
    return shuffled.slice(0, sampleSize);
  }

  /**
   * Embaralha array in-place usando algoritmo Fisher-Yates
   */
  private shuffleArray<T>(array: T[]): void {
    for (let i = array.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [array[i], array[j]] = [array[j], array[i]];
    }
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}