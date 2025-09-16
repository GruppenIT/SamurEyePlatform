import { spawn } from 'child_process';
import * as path from 'path';
import * as fs from 'fs/promises';
import { storage } from '../../storage';

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
    
    console.log(`🎯 Iniciando teste EDR/AV: ${totalDiscovered} computadores descobertos`);
    console.log(`📊 Amostragem solicitada: ${sampleRate}%/${requestedSampleSize} computadores`);
    
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
      
      console.log(`🔍 Testando ${currentTarget} (tentativa ${successfulDeployments + failedDeployments + 1})`);
      
      try {
        const finding = await this.testSingleHost(currentTarget, credential, timeout);
        
        // Verificar se conseguiu fazer deploy do EICAR (sucesso na cópia)
        if (finding.error) {
          failedDeployments++;
          console.log(`❌ Falha no deploy EICAR em ${currentTarget}: ${finding.error}`);
          findings.push(finding);
        } else {
          successfulDeployments++;
          findings.push(finding);
          console.log(`✅ EICAR copiado com sucesso em ${currentTarget} (${finding.eicarRemoved ? 'REMOVIDO pelo EDR/AV' : 'PERSISTIU - FALHA NO EDR/AV'})`);
        }
        
      } catch (error) {
        failedDeployments++;
        const errorMessage = error instanceof Error ? error.message : String(error);
        console.error(`❌ Erro crítico testando ${currentTarget}:`, errorMessage);
        
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
    
    // Log de resultados finais
    console.log(`📈 ESTATÍSTICAS FINAIS:`);
    console.log(`   • ${totalDiscovered} computadores descobertos`);
    console.log(`   • Amostragem solicitada: ${sampleRate}%/${requestedSampleSize} computadores`);
    console.log(`   • EICAR copiado para ${successfulDeployments} computadores após tentativas`);
    console.log(`   • Falhas no deployment: ${failedDeployments}`);
    
    // Analisar tipos de falhas para diagnóstico mais preciso
    const authFailures = findings.filter(f => f.error && f.error.includes('NT_STATUS_LOGON_FAILURE')).length;
    const accessDenied = findings.filter(f => f.error && f.error.includes('NT_STATUS_ACCESS_DENIED')).length;
    const networkErrors = findings.filter(f => f.error && f.error.includes('NT_STATUS_BAD_NETWORK_NAME')).length;
    const otherErrors = failedDeployments - authFailures - accessDenied - networkErrors;

    if (attemptsExhausted) {
      console.log(`⚠️ NÃO FOI POSSÍVEL ALCANÇAR A AMOSTRAGEM SOLICITADA`);
      console.log(`   📊 ANÁLISE DAS FALHAS (${failedDeployments} total):`);
      if (authFailures > 0) {
        console.log(`   🔑 ${authFailures} falhas de autenticação (NT_STATUS_LOGON_FAILURE)`);
        console.log(`      → SOLUÇÃO: Adicionar conta aos administradores locais dos servidores membros`);
      }
      if (accessDenied > 0) {
        console.log(`   🚫 ${accessDenied} acessos negados (NT_STATUS_ACCESS_DENIED)`);
        console.log(`      → SOLUÇÃO: Verificar privilégios e compartilhamento C$`);
      }
      if (networkErrors > 0) {
        console.log(`   🌐 ${networkErrors} erros de rede/conectividade`);
        console.log(`      → SOLUÇÃO: Verificar se servidores estão online`);
      }
      if (otherErrors > 0) {
        console.log(`   ❓ ${otherErrors} outros erros diversos`);
      }
      console.log(`   💡 DICA: Domain Controllers geralmente funcionam, servidores membros precisam configuração adicional`);
    } else {
      console.log(`✅ Amostragem alcançada com sucesso`);
    }
    
    console.log(`   • EDR/AV funcionando: ${eicarRemovedCount} computadores`);
    console.log(`   • EDR/AV com falhas: ${eicarPersistedCount} computadores`);
    
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
    console.log(`Testando EDR/AV em ${hostname}`);

    // Usar timeout da jornada (parâmetro recebido)
    const timeoutMs = Math.max(5, Math.min(3600, timeout)) * 1000; // Limitar entre 5s e 1h
    console.log(`⏱️ Timeout da jornada: ${Math.floor(timeoutMs / 1000)}s para teste EICAR`);

    try {
      // 1. Primeiro, tentar deployment via SMB
      const smbResult = await this.deployEicarViaSMB(hostname, credential);
      
      if (smbResult.success) {
        // 2. Aguardar tempo configurado para o EDR/AV agir
        console.log(`⏱️ Aguardando ${Math.floor(timeoutMs / 1000)}s para EDR/AV processar o arquivo EICAR...`);
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
          console.log(`⏱️ Aguardando ${Math.floor(timeoutMs / 1000)}s após deploy via WMI...`);
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
        credential.domain ? `workgroup=${credential.domain}` : '', // Compatibilidade adicional
      ].filter(Boolean).join('\n');
      
      await fs.writeFile(authFile, authContent, { mode: 0o600 }); // Apenas proprietário pode ler

      // Debug: Verificar conteúdo do arquivo de auth (sem mostrar password)
      console.log(`🔑 Arquivo de autenticação criado:`);
      console.log(`   Tamanho: ${authContent.length} bytes`);
      console.log(`   Username: ${credential.username}`);
      console.log(`   Domain: ${credential.domain || 'N/A'}`);
      console.log(`   Password: [${credential.password.length} caracteres]`);

      // SMB client espera barras normais, não backslashes para caminhos internos
      const targetSmbPath = 'Windows/Temp/samureye_eicar.txt';
      
      const args = [
        `//${hostname}/C$`,
        '-A', authFile, // Usar arquivo de autenticação em vez de linha de comando
        '-c', `put "${tempFile}" "${targetSmbPath}"`
      ];

      console.log(`📋 Executando SMB Deploy para ${hostname}:`);
      console.log(`   Comando: smbclient //${hostname}/C$ -A [AUTH_FILE] -c [PUT_COMMAND]`);
      console.log(`   Arquivo local: ${tempFile}`);
      console.log(`   Destino remoto: ${targetSmbPath}`);
      console.log(`   Usuário: ${credential.domain ? `${credential.domain}\\${credential.username}` : credential.username}`);
      console.log(`   Arquivo de auth: ${authFile}`);

      // Primeiro, testar conectividade básica antes de tentar copiar
      console.log(`🔍 Testando conectividade SMB para ${hostname}...`);
      const testArgs = [
        `//${hostname}/C$`,
        '-A', authFile,
        '-c', 'ls'
      ];
      
      const testResult = await this.executeCommand('smbclient', testArgs, 15000);
      console.log(`   Teste de conectividade - Exit Code: ${testResult.exitCode}`);
      
      if (testResult.exitCode !== 0) {
        console.log(`❌ Falha no teste de conectividade:`);
        console.log(`   STDOUT: ${testResult.stdout}`);
        console.log(`   STDERR: ${testResult.stderr}`);
      } else {
        console.log(`✅ Conectividade SMB funcionando, prosseguindo com cópia...`);
      }

      const result = await this.executeCommand('smbclient', args, 30000);

      console.log(`📊 Resultado SMB Deploy - Exit Code: ${result.exitCode}`);
      console.log(`📊 STDOUT:`, result.stdout);
      console.log(`📊 STDERR:`, result.stderr);

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
        
        // Diagnóstico detalhado baseado no tipo de erro
        let diagnosticMessage = result.stderr || result.stdout || 'Erro desconhecido no smbclient';
        
        // Verificar se o problema pode ser com o arquivo de autenticação
        if (result.stderr?.includes('Unable to open credentials file') || result.stderr?.includes('Error reading credentials')) {
          console.log(`🔧 PROBLEMA COM ARQUIVO DE AUTENTICAÇÃO - tentando método alternativo...`);
          
          // Tentar comando direto (menos seguro, mas pode funcionar)
          const directArgs = [
            `//${hostname}/C$`,
            '-U', `${credential.domain ? credential.domain + '\\' : ''}${credential.username}%${credential.password}`,
            '-c', `put "${tempFile}" "${targetSmbPath}"`
          ];
          
          console.log(`🔄 Tentativa com autenticação direta na linha de comando...`);
          const directResult = await this.executeCommand('smbclient', directArgs, 30000);
          
          if (directResult.exitCode === 0) {
            console.log(`✅ SMB Deploy bem-sucedido com método direto para ${hostname}`);
            return {
              success: true,
              filePath: `\\\\${hostname}\\C$\\Windows\\Temp\\samureye_eicar.txt`,
            };
          } else {
            diagnosticMessage = `Falha com ambos os métodos de autenticação. Último erro: ${directResult.stderr || directResult.stdout}`;
          }
        }
        
        if (result.stdout?.includes('NT_STATUS_LOGON_FAILURE') || diagnosticMessage.includes('NT_STATUS_LOGON_FAILURE')) {
          console.log(`🔍 DIAGNÓSTICO NT_STATUS_LOGON_FAILURE para ${hostname}:`);
          console.log('   ⚠️  PROBLEMA COMUM EM SERVIDORES MEMBROS - Domain Controllers funcionam, mas servidores membros falham');
          console.log('   🔧 SOLUÇÕES RECOMENDADAS:');
          console.log('   1. Verificar se conta tem privilégios administrativos LOCAIS no servidor de destino');
          console.log('   2. Adicionar conta ao grupo "Administradores" local do servidor');
          console.log('   3. Habilitar LocalAccountTokenFilterPolicy para contas de domínio:');
          console.log('      reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1');
          console.log('   4. Verificar se UAC não está bloqueando acesso remoto');
          console.log('   5. Confirmar que não há GPO bloqueando acesso SMB administrativo');
          
          diagnosticMessage = `FALHA DE AUTENTICAÇÃO SMB: ${hostname} negou acesso à conta '${credential.username}'. Servidores membros requerem privilégios administrativos locais específicos.`;
          
        } else if (result.stdout?.includes('NT_STATUS_ACCESS_DENIED') || result.stderr.includes('NT_STATUS_ACCESS_DENIED')) {
          console.log(`🔍 DIAGNÓSTICO NT_STATUS_ACCESS_DENIED para ${hostname}:`);
          console.log('   - Conta autenticada, mas sem privilégios suficientes');
          console.log('   - Verificar se share C$ está habilitado');
          console.log('   - Verificar políticas de UAC/segurança');
          console.log('   - Verificar firewall local');
          
          diagnosticMessage = `ACESSO NEGADO: Conta autenticada mas sem privilégios para acessar C$ em ${hostname}`;
          
        } else if (result.stdout?.includes('NT_STATUS_BAD_NETWORK_NAME')) {
          console.log(`🔍 DIAGNÓSTICO NT_STATUS_BAD_NETWORK_NAME para ${hostname}:`);
          console.log('   - Servidor pode estar offline ou inacessível');
          console.log('   - Compartilhamento C$ pode estar desabilitado');
          console.log('   - Verificar conectividade de rede');
          
          diagnosticMessage = `SERVIDOR INACESSÍVEL: ${hostname} não responde ou share C$ indisponível`;
          
        } else if (result.stderr?.includes('gencache_init')) {
          console.log(`ℹ️  Warnings de gencache ignorados (não impedem funcionamento)`);
          // Não alterar diagnosticMessage se só tem warning de gencache
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
        credential.domain ? `workgroup=${credential.domain}` : '', // Compatibilidade adicional
      ].filter(Boolean).join('\n');
      
      await fs.writeFile(authFile, authContent, { mode: 0o600 });

      const args = [
        `//${hostname}/C$`,
        '-A', authFile,
        '-c', 'ls "Windows/Temp/samureye_eicar.txt"'
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
        credential.domain ? `workgroup=${credential.domain}` : '', // Compatibilidade adicional
      ].filter(Boolean).join('\n');
      
      await fs.writeFile(authFile, authContent, { mode: 0o600 });

      const args = [
        `//${hostname}/C$`,
        '-A', authFile,
        '-c', 'del "Windows/Temp/samureye_eicar.txt"'
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
        env: { 
          ...process.env,
          // Configurar diretórios temporários para Samba evitar erro read-only
          HOME: '/tmp',
          TMPDIR: '/tmp',
          TMP: '/tmp',
          TEMP: '/tmp'
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