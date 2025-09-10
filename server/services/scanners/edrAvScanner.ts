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
   * Deploy EICAR via SMB usando smbclient
   */
  private async deployEicarViaSMB(
    hostname: string,
    credential: { username: string; password: string; domain?: string }
  ): Promise<{ success: boolean; filePath?: string; error?: string }> {
    try {
      // Criar arquivo EICAR temporário
      const tempDir = '/tmp';
      const tempFile = path.join(tempDir, `eicar_${Date.now()}.txt`);
      const targetPath = 'C$\\Windows\\Temp\\samureye_eicar.txt';
      
      await fs.writeFile(tempFile, this.eicarContent);

      const args = [
        `//${hostname}/C$`,
        '-U', this.formatCredentials(credential),
        '-c', `put "${tempFile}" "Windows\\Temp\\samureye_eicar.txt"`
      ];

      console.log(`Executando: smbclient ${args.join(' ').replace(/-U.*?-c/, '-U [HIDDEN] -c')}`);

      const result = await this.executeCommand('smbclient', args, 30000);

      // Limpar arquivo temporário
      await fs.unlink(tempFile).catch(() => {});

      if (result.exitCode === 0) {
        return {
          success: true,
          filePath: `\\\\${hostname}\\${targetPath}`,
        };
      } else {
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
    }
  }

  /**
   * Deploy EICAR via WMI usando wmic (se disponível)
   */
  private async deployEicarViaWMI(
    hostname: string,
    credential: { username: string; password: string; domain?: string }
  ): Promise<{ success: boolean; filePath?: string; error?: string }> {
    try {
      const targetPath = `C:\\Windows\\Temp\\samureye_eicar.txt`;
      const encodedEicar = Buffer.from(this.eicarContent).toString('base64');

      // Usar PowerShell remoto via SSH (se disponível) ou fall back para wmic
      const psCommand = `
        $bytes = [System.Convert]::FromBase64String('${encodedEicar}');
        [System.IO.File]::WriteAllBytes('${targetPath}', $bytes);
        Write-Host 'EICAR deployed successfully'
      `;

      const args = [
        '/node:' + hostname,
        '/user:' + this.formatCredentials(credential),
        'process', 'call', 'create',
        `cmd.exe /c "powershell.exe -Command \\"${psCommand.replace(/"/g, '\\"')}\\""`,
      ];

      console.log(`Executando: wmic ${args.join(' ').replace(/\/user:.*?process/, '/user:[HIDDEN] process')}`);

      const result = await this.executeCommand('wmic', args, 30000);

      if (result.exitCode === 0 && result.stdout.includes('ReturnValue = 0')) {
        return {
          success: true,
          filePath: `\\\\${hostname}\\C$\\Windows\\Temp\\samureye_eicar.txt`,
        };
      } else {
        return {
          success: false,
          error: result.stderr || result.stdout || 'Erro desconhecido no wmic',
        };
      }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Verifica se o arquivo EICAR ainda existe
   */
  private async checkEicarFileExists(
    hostname: string,
    credential: { username: string; password: string; domain?: string },
    filePath: string
  ): Promise<boolean> {
    try {
      const args = [
        `//${hostname}/C$`,
        '-U', this.formatCredentials(credential),
        '-c', 'ls "Windows\\Temp\\samureye_eicar.txt"'
      ];

      const result = await this.executeCommand('smbclient', args, 10000);
      
      // Se o arquivo existir, smbclient retornará informações sobre ele
      return result.exitCode === 0 && !result.stderr.includes('NT_STATUS_OBJECT_NAME_NOT_FOUND');
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      console.log(`Erro verificando arquivo em ${hostname}:`, errorMessage);
      return false;
    }
  }

  /**
   * Remove o arquivo EICAR (cleanup)
   */
  private async cleanupEicarFile(
    hostname: string,
    credential: { username: string; password: string; domain?: string },
    filePath: string
  ): Promise<void> {
    try {
      const args = [
        `//${hostname}/C$`,
        '-U', this.formatCredentials(credential),
        '-c', 'rm "Windows\\Temp\\samureye_eicar.txt"'
      ];

      await this.executeCommand('smbclient', args, 10000);
      console.log(`Arquivo EICAR removido de ${hostname}`);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      console.log(`Erro removendo arquivo EICAR de ${hostname}:`, errorMessage);
    }
  }

  /**
   * Formata credenciais para ferramentas
   */
  private formatCredentials(credential: { username: string; password: string; domain?: string }): string {
    if (credential.domain) {
      return `${credential.domain}\\${credential.username}%${credential.password}`;
    }
    return `${credential.username}%${credential.password}`;
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