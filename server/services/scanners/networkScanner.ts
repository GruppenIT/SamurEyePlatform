import { spawn } from 'child_process';
import dns from 'dns';
import net from 'net';
import { promisify } from 'util';
import { XMLParser } from 'fast-xml-parser';
import { processTracker } from '../processTracker';
import { createLogger } from '../../lib/logger';
import { NmapFindingSchema, NmapVulnFindingSchema, type NmapFinding, type NmapVulnFinding, type NseScript } from '../../../shared/schema';

const log = createLogger('networkScanner');

const dnsLookup = promisify(dns.lookup);

export interface PortScanResult {
  type: 'port';
  target: string;
  ip?: string;
  port: string;
  state: 'open' | 'closed' | 'filtered';
  service: string;
  version?: string;
  banner?: string;
  osInfo?: string;
  hostInfo?: string;
  versionAccuracy?: 'high' | 'medium' | 'low'; // Indica precisão da detecção
}

/**
 * Result from host discovery (ping sweep)
 */
export interface AliveHostResult {
  ip: string;
  hostname?: string;
  latency?: string;
}

export interface ServiceInfo {
  name: string;
  version?: string;
  banner?: string;
}

/**
 * Context for process tracking
 */
interface ProcessContext {
  jobId?: string;
  processName?: 'nmap' | 'nuclei';
  stage?: string;
  maxWaitTime?: number; // Maximum time to wait (fallback protection)
}

export class NetworkScanner {
  private readonly commonPorts = [
    { port: 21, service: 'ftp' },
    { port: 22, service: 'ssh' },
    { port: 23, service: 'telnet' },
    { port: 25, service: 'smtp' },
    { port: 53, service: 'dns' },
    { port: 80, service: 'http' },
    { port: 110, service: 'pop3' },
    { port: 135, service: 'msrpc' },
    { port: 139, service: 'netbios-ssn' },
    { port: 143, service: 'imap' },
    { port: 443, service: 'https' },
    { port: 445, service: 'microsoft-ds' },
    { port: 993, service: 'imaps' },
    { port: 995, service: 'pop3s' },
    { port: 1433, service: 'mssql' },
    { port: 3306, service: 'mysql' },
    { port: 3389, service: 'rdp' },
    { port: 5432, service: 'postgresql' },
    { port: 5985, service: 'winrm' },
    { port: 5986, service: 'winrm-https' },
    { port: 8080, service: 'http-alt' },
    { port: 8443, service: 'https-alt' },
  ];

  /**
   * Realiza scan de portas em um host
   */
  async scanPorts(target: string, ports?: number[], nmapProfile?: string, jobId?: string): Promise<PortScanResult[]> {
    log.info(`Iniciando scan de portas para ${target}`);
    
    // Verificar se é um IP válido ou hostname
    const resolvedTarget = await this.resolveTarget(target);
    if (!resolvedTarget) {
      throw new Error(`❌ Erro de DNS: Não foi possível resolver o hostname '${target}'. Verifique se o domínio existe e é acessível.`);
    }

    log.info(`✅ DNS resolvido: ${target} → ${resolvedTarget}`);

    // Determinar portas baseado no perfil nmap
    const portsToScan = this.getPortsForProfile(nmapProfile, ports);
    const results: PortScanResult[] = [];

    // Tentar usar nmap se disponível, senão usar scan TCP nativo
    try {
      const nmapResults = await this.nmapScan(target, resolvedTarget, portsToScan, nmapProfile, jobId);
      return nmapResults;
    } catch (error) {
      log.info(`⚠️ nmap falhou, usando scan TCP nativo:`, error);
      
      // Se foi erro de DNS no nmap, não tentar TCP scan
      if (error instanceof Error && error.message.includes('Failed to resolve')) {
        throw new Error(`❌ Erro de DNS: O hostname '${target}' não pode ser resolvido. Verifique a conectividade de rede.`);
      }
      
      // Para TCP fallback, usar portas comuns se array vazio (profiles fast/comprehensive)
      const fallbackPorts = portsToScan.length > 0 ? portsToScan : this.commonPorts.map(p => p.port);
      log.info(`🔄 TCP fallback usará ${fallbackPorts.length} portas comuns`);
      
      return this.tcpPortScan(resolvedTarget, fallbackPorts);
    }
  }

  /**
   * Resolve hostname para IP
   */
  private async resolveTarget(target: string): Promise<string | null> {
    try {
      // Se já é um IP, retorna direto
      if (/^\d+\.\d+\.\d+\.\d+$/.test(target)) {
        log.info(`📍 Target ${target} já é um IP válido`);
        return target;
      }

      log.info(`🔍 Resolvendo DNS para ${target}...`);
      
      // Resolve hostname com timeout reduzido
      const result = await Promise.race([
        dnsLookup(target),
        new Promise<never>((_, reject) => 
          setTimeout(() => reject(new Error('DNS lookup timeout after 10s')), 10000)
        )
      ]);
      
      log.info(`✅ ${target} resolvido para ${result.address}`);
      return result.address;
    } catch (error) {
      log.error(`❌ Erro ao resolver DNS para ${target}:`, error);
      
      if (error instanceof Error && error.message.includes('timeout')) {
        log.error(`⏱️ Timeout de DNS - possível problema de conectividade`);
      } else if (error instanceof Error && (error.message.includes('ENOTFOUND') || error.message.includes('ENOENT'))) {
        log.error(`🚫 Hostname não encontrado - domínio pode não existir`);
      }
      
      return null;
    }
  }

  /**
   * Scan usando nmap (quando disponível)
   */
  private async nmapScan(originalTarget: string, resolvedTarget: string, ports: number[], nmapProfile?: string, jobId?: string): Promise<PortScanResult[]> {
    // Validar e sanitizar target para prevenir injeção de comando
    if (!this.isValidTarget(resolvedTarget)) {
      throw new Error(`Target inválido: ${resolvedTarget}`);
    }
    
    let args = this.buildNmapArgs(resolvedTarget, ports, nmapProfile);
    
    // Timeout diferenciado por perfil - ajustado para evitar timeouts prematuros
    let maxWaitTime = 120000; // 2 minutos padrão
    switch (nmapProfile) {
      case 'fast':
        maxWaitTime = 600000; // 10 minutos - mesmo fast pode ser lento em hosts com firewall
        break;
      case 'comprehensive':
        maxWaitTime = 1800000; // 30 minutos - scan completo precisa muito mais tempo
        break;
      case 'stealth':
        maxWaitTime = 1200000; // 20 minutos - scan discreto pode ser muito mais lento
        break;
    }
    
    const stage = `Escaneando portas de ${originalTarget}... nmap`;
    log.info(`🎯 ${stage} (perfil: ${nmapProfile || 'default'})`);
    
    const context: ProcessContext = {
      jobId,
      processName: 'nmap',
      stage,
      maxWaitTime
    };
    
    try {
      const stdout = await this.spawnCommand('nmap', args, context);
      const results = this.parseNmapXml(stdout, originalTarget);

      // Log verbose port findings
      log.info(`📊 Nmap concluído para ${originalTarget} - ${results.length} portas processadas:`);
      for (const result of results) {
        log.info(`  🔍 Porta ${result.port}: ${result.state} | Serviço: ${result.service || 'desconhecido'} | Versão: ${result.version || 'N/A'}`);
        if (result.ip && result.ip !== originalTarget) {
          log.info(`    🔗 IP resolvido: ${result.ip}`);
        }
        if (result.osInfo) {
          log.info(`    💻 OS detectado: ${result.osInfo}`);
        }
      }

      return results;
    } catch (error) {
      // Verificar se é erro de privilégios e fazer fallback para TCP scan
      if (error instanceof Error && (
        error.message.includes('requires root privileges') ||
        error.message.includes('You requested a scan type which requires root')
      )) {
        log.info(`⚠️ nmap requer privilégios de root para perfil ${nmapProfile}, fazendo fallback para TCP scan`);

        // Reconstruir args com TCP scan
        args = this.buildNmapArgs(resolvedTarget, ports, 'tcp-fallback');

        try {
          const stdout = await this.spawnCommand('nmap', args, context);
          const results = this.parseNmapXml(stdout, originalTarget);

          log.info(`📊 Nmap TCP fallback concluído para ${originalTarget} - ${results.length} portas processadas`);
          return results;
        } catch (fallbackError) {
          log.error(`❌ Fallback TCP também falhou: ${fallbackError}`);
          throw fallbackError;
        }
      }

      // Re-throw outros erros
      throw error;
    }
  }

  /**
   * Valida se o target é um IP ou hostname válido
   */
  private isValidTarget(target: string): boolean {
    // Validar IP
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipRegex.test(target)) {
      return true;
    }
    
    // Validar hostname (permitir apenas letras, números, pontos e hífens)
    const hostnameRegex = /^[a-zA-Z0-9.-]+$/;
    if (hostnameRegex.test(target) && target.length <= 255) {
      return true;
    }
    
    return false;
  }

  /**
   * Executa comando usando spawn com monitoramento de PID
   */
  private async spawnCommand(command: string, args: string[], context: ProcessContext = {}): Promise<string> {
    return new Promise((resolve, reject) => {
      const { jobId, processName, stage, maxWaitTime = 600000 } = context; // 10min default fallback
      
      log.info(`🔧 Executando: ${command} ${args.join(' ')}`);
      if (jobId && processName && stage) {
        log.info(`📍 Job: ${jobId} | Processo: ${processName} | Stage: ${stage}`);
      }
      
      const child = spawn(command, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      
      if (!child.pid) {
        reject(new Error('Failed to get process PID'));
        return;
      }

      let stdout = '';
      let stderr = '';
      
      // Registrar no ProcessTracker se contexto foi fornecido
      if (jobId && processName && stage) {
        try {
          processTracker.register(jobId, processName, child, stage);
        } catch (error) {
          log.warn(`⚠️ Falha ao registrar processo no tracker: ${error}`);
        }
      }
      
      child.stdout?.on('data', (data) => {
        stdout += data.toString();
      });
      
      child.stderr?.on('data', (data) => {
        stderr += data.toString();
      });
      
      // Fallback protection - kill if exceeds maximum wait time
      const fallbackTimer = setTimeout(() => {
        log.info(`⏱️ Fallback timeout após ${maxWaitTime/1000}s - matando processo ${child.pid}`);
        
        if (jobId && child.pid) {
          processTracker.kill(jobId, child.pid);
        } else {
          child.kill('SIGTERM');
          setTimeout(() => child.kill('SIGKILL'), 5000);
        }
        
        reject(new Error(`Process exceeded maximum wait time of ${maxWaitTime/1000}s`));
      }, maxWaitTime);
      
      child.on('close', (code) => {
        clearTimeout(fallbackTimer);
        log.info(`📋 Comando concluído com código ${code}`);
        
        if (code === 0) {
          resolve(stdout);
        } else {
          const errorMsg = `Command failed with code ${code}: ${stderr}`;
          log.error(`❌ ${errorMsg}`);
          reject(new Error(errorMsg));
        }
      });
      
      child.on('error', (error) => {
        clearTimeout(fallbackTimer);
        log.error(`💥 Erro no comando:`, error);
        reject(error);
      });
    });
  }

  /**
   * Normaliza e melhora detecção de versão com base em padrões conhecidos
   */
  private normalizeServiceVersion(service: string, version: string | undefined, osInfo: string): { 
    version: string | undefined, 
    accuracy: 'high' | 'medium' | 'low' 
  } {
    if (!version) {
      return { version, accuracy: 'low' };
    }

    let normalizedVersion = version;
    let accuracy: 'high' | 'medium' | 'low' = 'medium';

    // Microsoft-DS: Tentar melhorar precisão com base no OS detectado
    if (service === 'microsoft-ds' || service === 'netbios-ssn') {
      // Se temos OS info mais preciso, usar ele
      if (osInfo && osInfo.includes('Windows')) {
        // Extrair versão do Windows do OS info
        const windowsVersionMatch = osInfo.match(/Windows\s+(Server\s+)?(\d{4}|[^,\s]+)/i);
        if (windowsVersionMatch) {
          const osVersion = windowsVersionMatch[0];
          normalizedVersion = osVersion + ' ' + service;
          accuracy = 'high';
          log.info(`📝 Versão normalizada de '${version}' para '${normalizedVersion}' baseado em OS detection`);
        }
      }
      
      // Avisar sobre ranges de versão (indicam baixa precisão)
      if (version.includes(' - ') || version.includes('|')) {
        accuracy = 'low';
        log.info(`⚠️ Versão detectada como range: ${version} - precisão baixa`);
      }
    }

    return { version: normalizedVersion, accuracy };
  }

  /**
   * Parse da saída do nmap (formato texto/regex)
   * @deprecated Use parseNmapXml(stdout, target) instead — requires '-oX -' flag.
   *             This method is kept for reference only and will be removed in plan 01-02.
   */
  private parseNmapOutput(output: string, originalTarget: string, resolvedTarget: string): PortScanResult[] {
    const results: PortScanResult[] = [];
    const lines = output.split('\n');
    let vulnerabilityBuffer = '';
    let currentPort = '';
    let osInfo = '';
    let hostInfo = '';
    
    // Contexto do host para informações globais
    const hostContext = {
      host: originalTarget,
      ip: resolvedTarget,
      osInfo: '',
    };
    
    // Parse de informações globais do host
    for (const line of lines) {
      const trimmed = line.trim();
      
      // Extrair informações do host do cabeçalho
      const hostMatch = trimmed.match(/^Nmap scan report for (.+?)(?: \((\d{1,3}(?:\.\d{1,3}){3})\))?$/);
      if (hostMatch) {
        const [, hostPart, ipPart] = hostMatch;
        if (ipPart) {
          // Formato: "hostname (IP)"
          hostContext.host = hostPart;
          hostContext.ip = ipPart;
        } else if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostPart)) {
          // Formato: "IP"
          hostContext.ip = hostPart;
          hostContext.host = originalTarget;
        } else {
          // Formato: "hostname"
          hostContext.host = hostPart;
        }
      }
      
      // Extrair informações do SO (priorizar OS details como mais preciso)
      if (trimmed.startsWith('OS details:')) {
        const osDetails = trimmed.replace('OS details:', '').trim();
        hostContext.osInfo = osDetails;
        log.info(`🖥️ OS detectado via 'OS details': ${osDetails}`);
      } else if (trimmed.startsWith('Running:')) {
        // Usar Running apenas se não temos OS details
        if (!hostContext.osInfo) {
          hostContext.osInfo = trimmed.replace('Running:', '').trim();
          log.info(`🖥️ OS detectado via 'Running': ${hostContext.osInfo}`);
        }
      } else if (trimmed.startsWith('Service Info:')) {
        // Service Info é menos preciso, usar apenas como fallback
        if (!hostContext.osInfo) {
          const osMatch = trimmed.match(/OS:\s*([^;,]+)/i);
          if (osMatch) {
            hostContext.osInfo = osMatch[1].trim();
            log.info(`🖥️ OS detectado via 'Service Info': ${hostContext.osInfo}`);
          }
        }
      }
      
      // Tentar extrair OS CPE (Common Platform Enumeration) para mais precisão
      const cpeMatch = trimmed.match(/OS CPE:\s*cpe:\/o:([^:]+):([^:]+):([^:\s]+)/);
      if (cpeMatch) {
        const [, vendor, product, version] = cpeMatch;
        const cpeOs = `${vendor} ${product} ${version}`;
        if (!hostContext.osInfo || hostContext.osInfo.length < cpeOs.length) {
          hostContext.osInfo = cpeOs;
          log.info(`🖥️ OS detectado via CPE: ${cpeOs}`);
        }
      }
    }
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      // Update host context when encountering a new host section (critical for CIDR range scans)
      const hostMatchInner = trimmed.match(/^Nmap scan report for (.+?)(?: \((\d{1,3}(?:\.\d{1,3}){3})\))?$/);
      if (hostMatchInner) {
        const [, hostPart, ipPart] = hostMatchInner;
        if (ipPart) {
          hostContext.host = hostPart;
          hostContext.ip = ipPart;
        } else if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostPart)) {
          hostContext.ip = hostPart;
          hostContext.host = hostPart;
        } else {
          hostContext.host = hostPart;
        }
        // Reset OS info for new host (each host may have different OS)
        hostContext.osInfo = '';
        continue;
      }

      // Update OS info within the port parsing loop (for multi-host output)
      if (trimmed.startsWith('OS details:')) {
        hostContext.osInfo = trimmed.replace('OS details:', '').trim();
      } else if (trimmed.startsWith('Running:') && !hostContext.osInfo) {
        hostContext.osInfo = trimmed.replace('Running:', '').trim();
      } else if (trimmed.startsWith('Service Info:') && !hostContext.osInfo) {
        const osMatch2 = trimmed.match(/OS:\s*([^;,]+)/i);
        if (osMatch2) {
          hostContext.osInfo = osMatch2[1].trim();
        }
      }

      // Procurar por linhas de porta: "22/tcp open ssh OpenSSH 8.2" ou "3389/tcp open|filtered ms-wbt-server"
      const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+(open|closed|filtered|open\|filtered|closed\|filtered)\s+(\S+)(?:\s+(.+))?/);
      if (portMatch) {
        const [, port, protocol, state, service, version] = portMatch;
        currentPort = port;
        
        // Normalizar estados compostos (open|filtered -> filtered, etc.)
        const normalizedState = this.normalizePortState(state);
        
        // Coletar vulnerabilidades encontradas após a linha da porta
        vulnerabilityBuffer = '';
        for (let j = i + 1; j < lines.length && j < i + 20; j++) {
          const nextLine = lines[j];
          
          // Parar se encontrar outra porta ou seção
          if (nextLine.match(/^\d+\/(tcp|udp)/) || nextLine.startsWith('Nmap scan report')) {
            break;
          }
          
          // Coletar informações de vulnerabilidades dos scripts
          if (nextLine.includes('CVE-') || 
              nextLine.includes('VULNERABLE:') ||
              nextLine.includes('POTENTIALLY VULNERABLE:') ||
              nextLine.includes('| ') && nextLine.trim().length > 0) {
            vulnerabilityBuffer += nextLine.trim() + ' ';
          }
        }
        
        // Normalizar versão com base em OS info
        const { version: normalizedVersion, accuracy } = this.normalizeServiceVersion(
          service, 
          version?.trim(), 
          hostContext.osInfo || ''
        );
        
        results.push({
          type: 'port',
          target: hostContext.host,
          ip: hostContext.ip,
          port,
          state: normalizedState,
          service,
          version: normalizedVersion,
          versionAccuracy: accuracy,
          banner: vulnerabilityBuffer.trim() || undefined,
          osInfo: hostContext.osInfo || undefined,
        });
      }
    }
    
    log.info(`Parse nmap encontrou ${results.length} portas para ${originalTarget}`);
    if (results.length > 0) {
      log.info('Primeiras portas encontradas:', results.slice(0, 3).map(r => `${r.port}/${r.state}`));
      if (hostContext.ip && hostContext.ip !== originalTarget) {
        log.info(`🔗 Host ${originalTarget} resolvido para IP: ${hostContext.ip}`);
      }
      if (hostContext.osInfo) {
        log.info(`💻 Sistema operacional detectado: ${hostContext.osInfo}`);
      }
    }
    
    return results;
  }

  /**
   * Normaliza estados compostos do nmap para tipos válidos
   */
  private normalizePortState(state: string): 'open' | 'closed' | 'filtered' {
    switch (state) {
      case 'open':
        return 'open';
      case 'closed':
        return 'closed';
      case 'filtered':
        return 'filtered';
      case 'open|filtered':
        // Estado incerto - tratar como filtered para segurança
        return 'filtered';
      case 'closed|filtered':
        // Estado incerto - tratar como filtered para segurança
        return 'filtered';
      default:
        log.warn(`Estado de porta desconhecido: ${state}, assumindo 'filtered'`);
        return 'filtered';
    }
  }

  /**
   * Scan TCP nativo (fallback quando nmap não está disponível)
   */
  private async tcpPortScan(target: string, ports: number[]): Promise<PortScanResult[]> {
    log.info(`🔄 Iniciando TCP scan nativo para ${target} em ${ports.length} portas`);
    const results: PortScanResult[] = [];
    const timeout = 3000; // Aumenta timeout para 3 segundos por porta
    const maxConcurrent = 10; // Reduz concorrência para ser mais estável

    // Processa portas em lotes para melhor performance
    for (let i = 0; i < ports.length; i += maxConcurrent) {
      const batch = ports.slice(i, i + maxConcurrent);
      log.info(`📦 Processando lote ${Math.floor(i/maxConcurrent) + 1}: portas ${batch.join(', ')}`);
      
      const promises = batch.map(async (port) => {
        try {
          const isOpen = await this.checkTcpPort(target, port, timeout);
          const serviceInfo = this.getServiceInfo(port);
          
          if (isOpen) {
            log.info(`✅ Porta ${port} aberta em ${target}`);
            // Tentar obter banner se a porta estiver aberta
            const banner = await this.getBanner(target, port);
            
            return {
              type: 'port' as const,
              target,
              port: port.toString(),
              state: 'open' as const,
              service: serviceInfo.name,
              version: serviceInfo.version,
              banner,
            };
          } else {
            log.info(`❌ Porta ${port} fechada/filtrada em ${target}`);
          }
          return null;
        } catch (error) {
          log.info(`⚠️ Erro na porta ${port}: ${error}`);
          return null;
        }
      });

      const batchResults = await Promise.all(promises);
      const openPorts = batchResults.filter(result => result !== null);
      results.push(...openPorts);
      
      log.info(`📊 Lote concluído: ${openPorts.length}/${batch.length} portas abertas`);
    }

    log.info(`🎯 TCP scan concluído: ${results.length} portas abertas encontradas de ${ports.length} testadas`);
    return results;
  }

  /**
   * Verifica se uma porta TCP está aberta
   */
  private async checkTcpPort(host: string, port: number, timeout: number): Promise<boolean> {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      
      const timer = setTimeout(() => {
        socket.destroy();
        resolve(false);
      }, timeout);

      socket.on('connect', () => {
        clearTimeout(timer);
        socket.destroy();
        resolve(true);
      });

      socket.on('error', () => {
        clearTimeout(timer);
        resolve(false);
      });

      socket.connect(port, host);
    });
  }

  /**
   * Obtém informações do serviço baseado na porta
   */
  private getServiceInfo(port: number): ServiceInfo {
    const serviceMap = this.commonPorts.find(p => p.port === port);
    return {
      name: serviceMap?.service || 'unknown',
    };
  }

  /**
   * Tenta obter banner do serviço
   */
  private async getBanner(host: string, port: number): Promise<string | undefined> {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let banner = '';
      
      const timer = setTimeout(() => {
        socket.destroy();
        resolve(undefined);
      }, 5000);

      socket.on('connect', () => {
        // Enviar requisição básica dependendo do serviço
        if (port === 80) {
          socket.write('HEAD / HTTP/1.0\r\n\r\n');
        } else if (port === 21) {
          // FTP responde automaticamente
        } else if (port === 22) {
          // SSH responde automaticamente
        }
      });

      socket.on('data', (data) => {
        banner += data.toString();
        if (banner.length > 1024) { // Limitar tamanho do banner
          clearTimeout(timer);
          socket.destroy();
          resolve(banner.substring(0, 1024));
        }
      });

      socket.on('error', () => {
        clearTimeout(timer);
        resolve(undefined);
      });

      socket.on('close', () => {
        clearTimeout(timer);
        resolve(banner || undefined);
      });

      socket.connect(port, host);
    });
  }

  /**
   * Discovers alive hosts in a CIDR range using nmap ping sweep (-sn).
   * This is a fast preliminary scan that only finds which hosts are up,
   * without port scanning. Returns a list of alive IPs/hostnames.
   */
  async discoverAliveHosts(target: string, jobId?: string): Promise<AliveHostResult[]> {
    log.info(`🔍 Descoberta de hosts ativos em ${target} (ping sweep)`);

    const args = [
      '-sn',       // Ping sweep only - no port scan
      '-T4',       // Aggressive timing for speed
      '--max-rtt-timeout', '2s',
      '--initial-rtt-timeout', '500ms',
      target
    ];

    const context: ProcessContext = {
      jobId,
      processName: 'nmap',
      stage: `Descobrindo hosts ativos em ${target}... nmap -sn`,
      maxWaitTime: 300000 // 5 min max for discovery
    };

    try {
      const stdout = await this.spawnCommand('nmap', args, context);
      const aliveHosts = this.parseNmapDiscoveryOutput(stdout);
      log.info(`✅ Descoberta concluída: ${aliveHosts.length} hosts ativos em ${target}`);
      return aliveHosts;
    } catch (error) {
      log.error(`❌ Erro na descoberta de hosts: ${error}`);
      // Fallback: if target is a single IP/hostname, return it as-is
      if (!target.includes('/')) {
        return [{ ip: target }];
      }
      return [];
    }
  }

  /**
   * Parses nmap -sn output to extract alive hosts.
   * Output format:
   *   Nmap scan report for hostname (IP)
   *   Host is up (0.0015s latency).
   *   -or-
   *   Nmap scan report for IP
   *   Host is up (0.0015s latency).
   */
  private parseNmapDiscoveryOutput(output: string): AliveHostResult[] {
    const hosts: AliveHostResult[] = [];
    const lines = output.split('\n');

    let currentHost: Partial<AliveHostResult> | null = null;

    for (const line of lines) {
      const trimmed = line.trim();

      // Match: "Nmap scan report for hostname (IP)" or "Nmap scan report for IP"
      const reportMatch = trimmed.match(/^Nmap scan report for (.+?)(?: \((\d{1,3}(?:\.\d{1,3}){3})\))?$/);
      if (reportMatch) {
        const [, hostPart, ipPart] = reportMatch;
        if (ipPart) {
          currentHost = { ip: ipPart, hostname: hostPart };
        } else if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostPart)) {
          currentHost = { ip: hostPart };
        } else {
          currentHost = { ip: hostPart, hostname: hostPart };
        }
        continue;
      }

      // Match: "Host is up (0.0015s latency)."
      const upMatch = trimmed.match(/^Host is up(?: \((.+?) latency\))?/);
      if (upMatch && currentHost && currentHost.ip) {
        currentHost.latency = upMatch[1];
        hosts.push(currentHost as AliveHostResult);
        currentHost = null;
      }
    }

    return hosts;
  }

  /**
   * Scan de range CIDR - usa nmap diretamente com suporte nativo a CIDR
   * para descoberta paralela de hosts e scan de portas
   */
  async scanCidrRange(cidr: string, nmapProfile?: string, jobId?: string): Promise<PortScanResult[]> {
    // Validate CIDR format
    const cidrMatch = cidr.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
    if (!cidrMatch) {
      throw new Error(`Range CIDR inválido: ${cidr}`);
    }

    const prefix = parseInt(cidrMatch[2], 10);
    if (prefix < 16) {
      throw new Error('Range CIDR muito grande. Use /16 ou maior.');
    }

    const totalHosts = 2 ** (32 - prefix) - 2; // Exclude network and broadcast
    log.info(`📡 Escaneando range CIDR ${cidr} (${totalHosts} hosts possíveis) diretamente via nmap`);

    // Use nmap directly with the CIDR range - nmap natively handles
    // parallel host discovery and only port-scans alive hosts
    const args = this.buildNmapArgs(cidr, [], nmapProfile, true);

    // Longer timeout for range scans - scale with number of hosts
    const baseTimeoutMs = 600000; // 10 min base
    const maxWaitTime = Math.min(baseTimeoutMs + totalHosts * 5000, 3600000); // Up to 1 hour

    const context: ProcessContext = {
      jobId,
      processName: 'nmap',
      stage: `Escaneando range ${cidr}... nmap`,
      maxWaitTime
    };

    try {
      const stdout = await this.spawnCommand('nmap', args, context);
      const results = this.parseNmapXml(stdout, cidr);

      // Count unique hosts discovered
      const uniqueHosts = new Set(results.filter(r => r.state === 'open').map(r => r.ip || r.target));
      log.info(`✅ Scan CIDR concluído: ${results.length} portas encontradas em ${uniqueHosts.size} hosts ativos de ${cidr}`);
      return results;
    } catch (error) {
      log.error(`❌ Erro no scan CIDR via nmap: ${error}`);
      log.info(`🔄 Tentando fallback: expandindo range manualmente`);
      return this.scanCidrFallback(cidr, nmapProfile, jobId);
    }
  }

  /**
   * Fallback para scan CIDR quando nmap não suporta range diretamente
   * Expande o CIDR e escaneia todos os hosts individualmente
   */
  private async scanCidrFallback(cidr: string, nmapProfile?: string, jobId?: string): Promise<PortScanResult[]> {
    const hosts = this.expandCidrRange(cidr);
    const results: PortScanResult[] = [];

    log.info(`🔄 Fallback CIDR: escaneando ${hosts.length} hosts individualmente`);

    for (const host of hosts) {
      try {
        const hostResults = await this.scanPorts(host, undefined, nmapProfile, jobId);
        results.push(...hostResults);
      } catch (error) {
        log.error(`Erro ao escanear ${host}:`, error);
      }
    }

    return results;
  }

  /**
   * Expande range CIDR em lista de IPs (todos os hosts utilizáveis)
   */
  private expandCidrRange(cidr: string): string[] {
    const [network, prefixLength] = cidr.split('/');
    const prefix = parseInt(prefixLength, 10);

    if (prefix < 16) {
      throw new Error('Range CIDR muito grande. Use /16 ou maior.');
    }

    const networkParts = network.split('.').map(Number);
    const hosts: string[] = [];

    // Calculate total usable hosts (exclude network and broadcast addresses)
    const totalAddresses = 2 ** (32 - prefix);
    const maxHost = totalAddresses - 1; // Exclude broadcast

    for (let i = 1; i < maxHost; i++) {
      const offset = networkParts[3] + i;
      const thirdOctet = networkParts[2] + Math.floor(offset / 256);
      const lastOctet = offset % 256;
      const host = `${networkParts[0]}.${networkParts[1]}.${thirdOctet}.${lastOctet}`;
      hosts.push(host);
    }

    return hosts;
  }

  /**
   * Determina quais portas escanear baseado no perfil nmap
   */
  private getPortsForProfile(nmapProfile?: string, customPorts?: number[]): number[] {
    // Se portas customizadas foram especificadas, usar elas
    if (customPorts && customPorts.length > 0) {
      return customPorts;
    }

    // Normalizar perfis legados para novos nomes
    const profile = this.normalizeProfile(nmapProfile);

    // Aplicar perfil de escaneamento
    switch (profile) {
      case 'leve':
        // Top 1000 portas (usar --top-ports 1000 do nmap)
        log.info('🚀 Perfil Leve selecionado: escaneando top 1000 portas');
        return [];

      case 'profundo':
        // Todas as portas (1-65535)
        log.info('⚠️  Perfil Profundo selecionado: escaneando TODAS as portas (1-65535)');
        return [];

      default:
        // Padrão: top 1000 portas (leve)
        log.info('🚀 Perfil padrão: escaneando top 1000 portas');
        return [];
    }
  }

  /**
   * Normaliza nomes de perfis legados para os novos nomes
   */
  private normalizeProfile(nmapProfile?: string): string {
    switch (nmapProfile) {
      case 'fast': return 'leve';
      case 'comprehensive': return 'profundo';
      case 'stealth': return 'leve'; // stealth depreciado, usa leve
      case 'leve': return 'leve';
      case 'profundo': return 'profundo';
      default: return 'leve';
    }
  }

  /**
   * Parses nmap XML output (produced with -oX -) and returns NmapFinding[].
   * Captures NSE script blocks including CVE references into nseScripts array (PARS-02).
   * Uses fast-xml-parser for robust XML handling.
   */
  public parseNmapXml(xml: string, target: string): NmapFinding[] {
    if (!xml || xml.trim().length === 0) return [];

    const parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
      parseAttributeValue: true,
      allowBooleanAttributes: true,
      isArray: (name: string) =>
        ['host', 'port', 'script', 'elem', 'table', 'osmatch', 'osclass', 'cpe', 'hostname', 'address'].includes(name),
    });

    let doc: any;
    try {
      doc = parser.parse(xml);
    } catch (err) {
      log.warn({ err }, '[parseNmapXml] Failed to parse XML — returning empty array');
      return [];
    }

    const nmaprun = doc?.nmaprun;
    if (!nmaprun) return [];

    const hosts: any[] = nmaprun.host ?? [];
    const findings: NmapFinding[] = [];

    for (const host of hosts) {
      // Resolve IP from address array (ipv4 type)
      const addresses: any[] = host.address ?? [];
      const ipAddr = addresses.find((a: any) => a['@_addrtype'] === 'ipv4')?.['@_addr'] ?? target;

      // Resolve best hostname: prefer PTR hostname, fall back to target
      const hostnames: any[] = host.hostnames?.hostname ?? [];
      const hostname = hostnames[0]?.['@_name'] ?? target;

      // OS info — use best osmatch (first = highest accuracy)
      let osName: string | undefined;
      let osAccuracy: number | undefined;
      let osCpe: string[] | undefined;
      const osmatches: any[] = host.os?.osmatch ?? [];
      if (osmatches.length > 0) {
        const bestOs = osmatches[0];
        osName = bestOs['@_name'] as string | undefined;
        const rawAccuracy = bestOs['@_accuracy'];
        osAccuracy = rawAccuracy !== undefined ? Number(rawAccuracy) : undefined;
        const osclasses: any[] = bestOs.osclass ?? [];
        const cpes = osclasses.flatMap((c: any) => {
          const cpelist: any[] = c.cpe ?? [];
          return cpelist.map((cpeEntry: any) =>
            typeof cpeEntry === 'string' ? cpeEntry : (cpeEntry['#text'] ?? String(cpeEntry))
          );
        }).filter(Boolean);
        if (cpes.length > 0) osCpe = cpes;
      }

      const ports: any[] = host.ports?.port ?? [];
      for (const port of ports) {
        const portId = String(port['@_portid'] ?? '');
        const rawState = port.state?.['@_state'];

        // Only emit findings for open ports (per PARS-01 spec — skips filtered/closed)
        if (rawState !== 'open') continue;

        const svc = port.service ?? {};
        const service = (svc['@_name'] != null ? String(svc['@_name']) : undefined) ?? 'unknown';
        const product = svc['@_product'] != null ? String(svc['@_product']) : undefined;
        // Coerce to string: parseAttributeValue may parse numeric-looking versions as numbers
        const version = svc['@_version'] != null ? String(svc['@_version']) : undefined;
        const extrainfo = svc['@_extrainfo'] != null ? String(svc['@_extrainfo']) : undefined;

        // serviceCpe: nmap emits <cpe> as child element of <service>, not as attribute
        const svcCpeList: any[] = svc.cpe ?? [];
        const serviceCpe: string | undefined = svcCpeList.length > 0
          ? (typeof svcCpeList[0] === 'string' ? svcCpeList[0] : (svcCpeList[0]['#text'] ?? undefined))
          : undefined;

        // Parse NSE scripts — extract CVE IDs from output text
        const scripts: any[] = port.script ?? [];
        const nseScripts: NseScript[] = scripts.map((script: any) => {
          const scriptId = (script['@_id'] ?? '') as string;
          const output = (script['@_output'] ?? '') as string;

          // Extract CVE references from output attribute text
          const cvePattern = /CVE-\d{4}-\d{4,7}/g;
          const cveMatches = output.match(cvePattern);
          const cves = cveMatches ? Array.from(new Set<string>(cveMatches)) : undefined;

          // Extract exploit state from output
          let exploitState: string | undefined;
          const stateMatch = output.match(/State:\s*(\S+)/);
          if (stateMatch) exploitState = stateMatch[1];

          return { id: scriptId, output, cves, exploitState } satisfies NseScript;
        });

        const mapped: Record<string, unknown> = {
          type: 'port',
          target: hostname,
          severity: 'medium',
          ip: ipAddr,
          port: portId,
          state: 'open',
          service,
          product,
          version,
          extrainfo,
          serviceCpe,
          osName,
          osAccuracy,
          osCpe,
          nseScripts: nseScripts.length > 0 ? nseScripts : undefined,
          osInfo: osName,
        };

        const result = NmapFindingSchema.safeParse(mapped);
        if (result.success) {
          findings.push(result.data);
        } else {
          log.warn(
            { raw: mapped, err: result.error.flatten() },
            `[parseNmapXml] nmap finding validation failed for port ${portId} — skipping`,
          );
        }
      }
    }

    log.info(`[parseNmapXml] Parsed ${findings.length} open port findings from XML for ${target}`);
    return findings;
  }

  /**
   * Runs nmap with --script=vuln against target and returns NmapVulnFinding[].
   * Delegates XML parsing to parseNmapXml, then re-validates as NmapVulnFinding (type: 'nmap_vuln').
   * Used by journeyExecutor to replace its private runNmapVulnScripts/parseNmapVulnOutput pattern.
   */
  public async scanVulns(target: string, ports?: string[], jobId?: string): Promise<NmapVulnFinding[]> {
    const portList = ports && ports.length > 0 ? ports.join(',') : '1-65535';
    const args = [
      '-Pn',
      '-sT',
      '-p', portList,
      '--script', 'vuln',
      '--script-args', 'vulns.showall',
      '-oX', '-',  // Output XML to stdout
      target,
    ];

    const stage = `Validando CVEs em ${target}... nmap --script=vuln`;
    log.info(`[scanVulns] ${stage}`);

    const context: ProcessContext = {
      jobId,
      processName: 'nmap',
      stage,
      maxWaitTime: 3600000, // 60 min max for vuln scan
    };

    let stdout: string;
    try {
      stdout = await this.spawnCommand('nmap', args, context);
    } catch (error) {
      log.error(`[scanVulns] nmap vuln scan failed: ${error}`);
      return [];
    }

    // Parse XML, then re-cast to NmapVulnFinding (type 'nmap_vuln')
    const portFindings = this.parseNmapXml(stdout, target);
    const vulnFindings: NmapVulnFinding[] = [];

    for (const pf of portFindings) {
      const vulnMapped = { ...pf, type: 'nmap_vuln' as const };
      const result = NmapVulnFindingSchema.safeParse(vulnMapped);
      if (result.success) {
        vulnFindings.push(result.data);
      }
    }

    log.info(`[scanVulns] Found ${vulnFindings.length} vuln findings for ${target}`);
    return vulnFindings;
  }

  /**
   * Constrói argumentos do nmap baseado no perfil
   */
  private buildNmapArgs(target: string, ports: number[], nmapProfile?: string, skipOsDetection: boolean = false): string[] {
    const args = [];
    const profile = this.normalizeProfile(nmapProfile);

    // Sempre adicionar flag para pular ping discovery
    args.push('-Pn'); // Muitos hosts bloqueiam ping mas têm portas abertas

    // Determinar tipo de scan baseado no perfil
    if (nmapProfile === 'tcp-fallback') {
      args.push('-sT'); // TCP connect scan forçado (fallback de privilégios)
      log.info('🔄 Usando TCP connect scan como fallback por falta de privilégios root');
    } else {
      args.push('-sT'); // TCP connect scan (não requer root)
    }

    // Configurar agressividade baseada no perfil
    if (profile === 'leve') {
      // Perfil Leve: detecção rápida de serviços, sem scripts pesados
      args.push(
        '-sV', // Version detection básica
        '--max-hostgroup', '1',
        '--max-parallelism', '10', // Mais paralelo para velocidade
        '--min-rate', '100',        // Rate mais alto
        '--max-rate', '1000',       // Rate máximo maior
        '--max-rtt-timeout', '3s',  // Timeout reduzido
        '--initial-rtt-timeout', '500ms',
        '--version-intensity', '5'  // Intensidade reduzida
      );

      if (!skipOsDetection) {
        args.push('-O', '--osscan-guess');
      }
    } else if (nmapProfile === 'tcp-fallback') {
      // Fallback sem privilégios: apenas scan TCP básico, sem OS detection
      args.push(
        '-sV',
        '--max-hostgroup', '1',
        '--max-parallelism', '5',
        '--min-rate', '50',
        '--max-rate', '500',
        '--max-rtt-timeout', '5s',
        '--initial-rtt-timeout', '1s',
        '--version-intensity', '5'
      );
    } else {
      // Perfil Profundo: scan completo com scripts de vulnerabilidade
      args.push(
        '-sV', // Version detection
        '--script=vuln', // Scripts de vulnerabilidade
        '--script-args', 'vulns.showall',
        '--max-hostgroup', '1',
        '--max-parallelism', '5',
        '--min-rate', '50',
        '--max-rate', '500',
        '--max-rtt-timeout', '5s',
        '--initial-rtt-timeout', '1s',
        '--version-intensity', '7'
      );

      if (!skipOsDetection) {
        args.push('-O', '--osscan-guess');
      }
    }

    // Timing template baseado no perfil
    if (profile === 'leve') {
      args.push('-T4'); // Timing agressivo
    } else {
      args.push('-T3'); // Timing normal
    }

    // Configurar portas
    if (profile === 'profundo') {
      // Scan profundo: todas as portas
      args.push('-p', '1-65535');
      log.info('🔍 Executando nmap profundo: portas 1-65535');
    } else if (ports.length > 0) {
      // Portas específicas
      const portList = ports.join(',');
      args.push('-p', portList);
      log.info(`🔍 Executando nmap com portas: ${portList}`);
    } else {
      // Top 1000 portas (padrão do nmap)
      args.push('--top-ports', '1000');
      log.info('🔍 Executando nmap leve: top 1000 portas');
    }

    // Output XML to stdout — required for parseNmapXml (PARS-01)
    // Must come BEFORE target and NOT be combined with -oN/-oG flags
    args.push('-oX', '-');

    args.push(target);
    return args;
  }
}

export const networkScanner = new NetworkScanner();