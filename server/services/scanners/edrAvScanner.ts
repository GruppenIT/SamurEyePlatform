import { spawn } from 'child_process';
import * as path from 'path';
import * as fs from 'fs/promises';

/**
 * Scanner para testes EDR/AV reais
 * Implementa deployment de arquivo EICAR via SMB e WMI
 */
export class EDRAVScanner {
  private readonly eicarContent = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

  /**
   * Executa teste EDR/AV com credenciais
   */
  async runEDRAVTest(
    credential: { username: string; password: string; domain?: string },
    targets: string[],
    sampleRate: number = 15
  ): Promise<any[]> {
    console.log(`Iniciando teste EDR/AV em ${targets.length} hosts (amostra: ${sampleRate}%)`);
    
    const findings: any[] = [];
    const sampleSize = Math.max(1, Math.floor(targets.length * sampleRate / 100));
    const sampledTargets = this.sampleHosts(targets, sampleSize);

    for (const target of sampledTargets) {
      try {
        const finding = await this.testSingleHost(target, credential);
        findings.push(finding);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        console.error(`Erro testando ${target}:`, errorMessage);
        findings.push({
          type: 'edr_test',
          hostname: target,
          error: errorMessage,
          eicarRemoved: null,
          testDuration: 0,
          timestamp: new Date().toISOString(),
        });
      }
    }

    return findings;
  }

  /**
   * Testa um único host com deployment EICAR
   */
  private async testSingleHost(
    hostname: string,
    credential: { username: string; password: string; domain?: string }
  ): Promise<any> {
    const startTime = Date.now();
    console.log(`Testando EDR/AV em ${hostname}`);

    try {
      // 1. Primeiro, tentar deployment via SMB
      const smbResult = await this.deployEicarViaSMB(hostname, credential);
      
      if (smbResult.success) {
        // 2. Aguardar um tempo para o EDR/AV agir
        await this.delay(30000); // 30 segundos
        
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
          await this.delay(30000);
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
      const tempDir = '/tmp';
      tempFile = path.join(tempDir, `eicar_${Date.now()}.txt`);
      authFile = path.join(tempDir, `smbauth_${Date.now()}`);
      const targetPath = 'C$\\Windows\\Temp\\samureye_eicar.txt';
      
      await fs.writeFile(tempFile, this.eicarContent);

      // Criar arquivo de autenticação seguro para evitar exposição de credenciais
      const authContent = [
        `username=${credential.username}`,
        `password=${credential.password}`,
        credential.domain ? `domain=${credential.domain}` : '',
      ].filter(Boolean).join('\n');
      
      await fs.writeFile(authFile, authContent, { mode: 0o600 }); // Apenas proprietário pode ler

      const args = [
        `//${hostname}/C$`,
        '-A', authFile, // Usar arquivo de autenticação em vez de linha de comando
        '-c', `put "${tempFile}" "Windows\\Temp\\samureye_eicar.txt"`
      ];

      console.log(`Executando: smbclient //${hostname}/C$ -A [AUTH_FILE] -c [PUT_COMMAND]`);
      console.log(`[DEBUG] Comando completo: smbclient ${args.join(' ')}`);
      console.log(`[DEBUG] Target path: ${targetPath}`);
      console.log(`[DEBUG] User: ${credential.domain ? `${credential.domain}\\${credential.username}` : credential.username}`);

      const result = await this.executeCommand('smbclient', args, 30000);

      console.log(`[DEBUG] SMB Result - Exit Code: ${result.exitCode}`);
      console.log(`[DEBUG] SMB Result - STDOUT:`, result.stdout);
      console.log(`[DEBUG] SMB Result - STDERR:`, result.stderr);

      if (result.exitCode === 0) {
        console.log(`✅ SMB Deploy bem-sucedido para ${hostname}`);
        return {
          success: true,
          filePath: `\\\\${hostname}\\${targetPath}`,
        };
      } else {
        console.log(`❌ SMB Deploy falhou para ${hostname}:`);
        console.log(`   Error Code: ${result.exitCode}`);
        console.log(`   STDERR: ${result.stderr}`);
        console.log(`   STDOUT: ${result.stdout}`);
        
        // Análise específica de erros comuns
        if (result.stderr.includes('NT_STATUS_ACCESS_DENIED')) {
          console.log(`🔍 DIAGNÓSTICO NT_STATUS_ACCESS_DENIED para ${hostname}:`);
          console.log('   - Verificar se usuário tem permissões administrativas');
          console.log('   - Verificar se share C$ está habilitado');
          console.log('   - Verificar políticas de UAC/segurança');
          console.log('   - Verificar firewall local');
        }
        
        return {
          success: false,
          error: result.stderr || result.stdout || 'Erro desconhecido no smbclient',
        };
      }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error),
      };
    } finally {
      // Garantir limpeza de arquivos sensíveis mesmo em caso de erro
      if (tempFile) {
        await fs.unlink(tempFile).catch(() => {});
      }
      if (authFile) {
        await fs.unlink(authFile).catch(() => {});
      }
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
    console.warn('Deploy via WMI desabilitado por questões de segurança - usando apenas SMB');
    
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
      // Criar arquivo de autenticação temporário
      const tempDir = '/tmp';
      authFile = path.join(tempDir, `smbauth_check_${Date.now()}`);
      
      const authContent = [
        `username=${credential.username}`,
        `password=${credential.password}`,
        credential.domain ? `domain=${credential.domain}` : '',
      ].filter(Boolean).join('\n');
      
      await fs.writeFile(authFile, authContent, { mode: 0o600 });

      const args = [
        `//${hostname}/C$`,
        '-A', authFile,
        '-c', 'ls "Windows\\Temp\\samureye_eicar.txt"'
      ];

      console.log(`[DEBUG] Verificando existência do arquivo: ${filePath}`);
      console.log(`[DEBUG] Comando verificação: smbclient ${args.join(' ')}`);
      
      const result = await this.executeCommand('smbclient', args, 10000);
      
      console.log(`[DEBUG] Verificação - Exit Code: ${result.exitCode}`);
      console.log(`[DEBUG] Verificação - STDOUT: ${result.stdout}`);
      console.log(`[DEBUG] Verificação - STDERR: ${result.stderr}`);
      
      // Se o arquivo existir, smbclient retornará informações sobre ele
      const fileExists = result.exitCode === 0 && !result.stderr.includes('NT_STATUS_OBJECT_NAME_NOT_FOUND');
      console.log(`[DEBUG] Arquivo ${filePath.split('\\').pop()} existe: ${fileExists ? '✅ SIM' : '❌ NÃO'}`);
      
      return fileExists;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      console.log(`Erro verificando arquivo em ${hostname}:`, errorMessage);
      return false;
    } finally {
      // Garantir limpeza do arquivo de autenticação
      if (authFile) {
        await fs.unlink(authFile).catch(() => {});
      }
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
      // Criar arquivo de autenticação temporário
      const tempDir = '/tmp';
      authFile = path.join(tempDir, `smbauth_cleanup_${Date.now()}`);
      
      const authContent = [
        `username=${credential.username}`,
        `password=${credential.password}`,
        credential.domain ? `domain=${credential.domain}` : '',
      ].filter(Boolean).join('\n');
      
      await fs.writeFile(authFile, authContent, { mode: 0o600 });

      const args = [
        `//${hostname}/C$`,
        '-A', authFile,
        '-c', 'rm "Windows\\Temp\\samureye_eicar.txt"'
      ];

      await this.executeCommand('smbclient', args, 10000);
      
      console.log(`Arquivo EICAR removido de ${hostname}`);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      console.log(`Erro removendo arquivo EICAR de ${hostname}:`, errorMessage);
    } finally {
      // Garantir limpeza do arquivo de autenticação
      if (authFile) {
        await fs.unlink(authFile).catch(() => {});
      }
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
      console.log(`Erro verificando existência de ${binaryName}:`, error);
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
    return new Promise((resolve, reject) => {
      console.log(`Executando: ${command} ${args.join(' ')}`);
      
      const child = spawn(command, args, {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { ...process.env },
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
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }

    return shuffled.slice(0, sampleSize);
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}