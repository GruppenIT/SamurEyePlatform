import { spawn } from 'child_process';
import dns from 'dns';
import net from 'net';
import { promisify } from 'util';

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
}

export interface ServiceInfo {
  name: string;
  version?: string;
  banner?: string;
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
  async scanPorts(target: string, ports?: number[], nmapProfile?: string): Promise<PortScanResult[]> {
    console.log(`Iniciando scan de portas para ${target}`);
    
    // Verificar se é um IP válido ou hostname
    const resolvedTarget = await this.resolveTarget(target);
    if (!resolvedTarget) {
      throw new Error(`❌ Erro de DNS: Não foi possível resolver o hostname '${target}'. Verifique se o domínio existe e é acessível.`);
    }

    console.log(`✅ DNS resolvido: ${target} → ${resolvedTarget}`);

    // Determinar portas baseado no perfil nmap
    const portsToScan = this.getPortsForProfile(nmapProfile, ports);
    const results: PortScanResult[] = [];

    // Tentar usar nmap se disponível, senão usar scan TCP nativo
    try {
      const nmapResults = await this.nmapScan(target, resolvedTarget, portsToScan, nmapProfile);
      return nmapResults;
    } catch (error) {
      console.log(`⚠️ nmap falhou, usando scan TCP nativo:`, error);
      
      // Se foi erro de DNS no nmap, não tentar TCP scan
      if (error instanceof Error && error.message.includes('Failed to resolve')) {
        throw new Error(`❌ Erro de DNS: O hostname '${target}' não pode ser resolvido. Verifique a conectividade de rede.`);
      }
      
      return this.tcpPortScan(resolvedTarget, portsToScan);
    }
  }

  /**
   * Resolve hostname para IP
   */
  private async resolveTarget(target: string): Promise<string | null> {
    try {
      // Se já é um IP, retorna direto
      if (/^\d+\.\d+\.\d+\.\d+$/.test(target)) {
        console.log(`📍 Target ${target} já é um IP válido`);
        return target;
      }

      console.log(`🔍 Resolvendo DNS para ${target}...`);
      
      // Resolve hostname com timeout reduzido
      const result = await Promise.race([
        dnsLookup(target),
        new Promise<never>((_, reject) => 
          setTimeout(() => reject(new Error('DNS lookup timeout after 10s')), 10000)
        )
      ]);
      
      console.log(`✅ ${target} resolvido para ${result.address}`);
      return result.address;
    } catch (error) {
      console.error(`❌ Erro ao resolver DNS para ${target}:`, error);
      
      if (error instanceof Error && error.message.includes('timeout')) {
        console.error(`⏱️ Timeout de DNS - possível problema de conectividade`);
      } else if (error instanceof Error && (error.message.includes('ENOTFOUND') || error.message.includes('ENOENT'))) {
        console.error(`🚫 Hostname não encontrado - domínio pode não existir`);
      }
      
      return null;
    }
  }

  /**
   * Scan usando nmap (quando disponível)
   */
  private async nmapScan(originalTarget: string, resolvedTarget: string, ports: number[], nmapProfile?: string): Promise<PortScanResult[]> {
    // Validar e sanitizar target para prevenir injeção de comando
    if (!this.isValidTarget(resolvedTarget)) {
      throw new Error(`Target inválido: ${resolvedTarget}`);
    }
    
    const args = this.buildNmapArgs(resolvedTarget, ports, nmapProfile);
    
    const stdout = await this.spawnCommand('nmap', args, 120000); // Reduz timeout para 2 minutos
    const results = this.parseNmapOutput(stdout, originalTarget, resolvedTarget);
    
    // Log verboso das portas detectadas
    console.log(`📊 Nmap concluído para ${originalTarget} - ${results.length} portas processadas:`);
    for (const result of results) {
      console.log(`  🔍 Porta ${result.port}: ${result.state} | Serviço: ${result.service || 'desconhecido'} | Versão: ${result.version || 'N/A'}`);
      if (result.ip && result.ip !== originalTarget) {
        console.log(`    🔗 IP resolvido: ${result.ip}`);
      }
      if (result.osInfo) {
        console.log(`    💻 OS detectado: ${result.osInfo}`);
      }
    }
    
    return results;
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
   * Executa comando usando spawn para segurança
   */
  private async spawnCommand(command: string, args: string[], timeout: number): Promise<string> {
    return new Promise((resolve, reject) => {
      console.log(`🔧 Executando: ${command} ${args.join(' ')}`);
      
      const child = spawn(command, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
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
        console.log(`⏱️ Timeout após ${timeout/1000}s - matando processo`);
        child.kill('SIGTERM');
        
        // Force kill após 5s se não responder
        setTimeout(() => {
          child.kill('SIGKILL');
        }, 5000);
        
        reject(new Error(`Command timeout after ${timeout/1000}s`));
      }, timeout);
      
      child.on('close', (code) => {
        clearTimeout(timer);
        console.log(`📋 Comando concluído com código ${code}`);
        
        if (code === 0) {
          resolve(stdout);
        } else {
          const errorMsg = `Command failed with code ${code}: ${stderr}`;
          console.error(`❌ ${errorMsg}`);
          reject(new Error(errorMsg));
        }
      });
      
      child.on('error', (error) => {
        clearTimeout(timer);
        console.error(`💥 Erro no comando:`, error);
        reject(error);
      });
    });
  }

  /**
   * Parse da saída do nmap
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
      
      // Extrair informações do SO
      if (trimmed.startsWith('OS details:')) {
        hostContext.osInfo = trimmed.replace('OS details:', '').trim();
      } else if (trimmed.startsWith('Running:')) {
        hostContext.osInfo = trimmed.replace('Running:', '').trim();
      } else if (trimmed.startsWith('Service Info:')) {
        const osMatch = trimmed.match(/OS:\s*([^;,]+)/i);
        if (osMatch) {
          hostContext.osInfo = osMatch[1].trim();
        }
      }
    }
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
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
        
        results.push({
          type: 'port',
          target: hostContext.host,
          ip: hostContext.ip,
          port,
          state: normalizedState,
          service,
          version: version?.trim(),
          banner: vulnerabilityBuffer.trim() || undefined,
          osInfo: hostContext.osInfo || undefined,
        });
      }
    }
    
    console.log(`Parse nmap encontrou ${results.length} portas para ${originalTarget}`);
    if (results.length > 0) {
      console.log('Primeiras portas encontradas:', results.slice(0, 3).map(r => `${r.port}/${r.state}`));
      if (hostContext.ip && hostContext.ip !== originalTarget) {
        console.log(`🔗 Host ${originalTarget} resolvido para IP: ${hostContext.ip}`);
      }
      if (hostContext.osInfo) {
        console.log(`💻 Sistema operacional detectado: ${hostContext.osInfo}`);
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
        console.warn(`Estado de porta desconhecido: ${state}, assumindo 'filtered'`);
        return 'filtered';
    }
  }

  /**
   * Scan TCP nativo (fallback quando nmap não está disponível)
   */
  private async tcpPortScan(target: string, ports: number[]): Promise<PortScanResult[]> {
    console.log(`🔄 Iniciando TCP scan nativo para ${target} em ${ports.length} portas`);
    const results: PortScanResult[] = [];
    const timeout = 3000; // Aumenta timeout para 3 segundos por porta
    const maxConcurrent = 10; // Reduz concorrência para ser mais estável

    // Processa portas em lotes para melhor performance
    for (let i = 0; i < ports.length; i += maxConcurrent) {
      const batch = ports.slice(i, i + maxConcurrent);
      console.log(`📦 Processando lote ${Math.floor(i/maxConcurrent) + 1}: portas ${batch.join(', ')}`);
      
      const promises = batch.map(async (port) => {
        try {
          const isOpen = await this.checkTcpPort(target, port, timeout);
          const serviceInfo = this.getServiceInfo(port);
          
          if (isOpen) {
            console.log(`✅ Porta ${port} aberta em ${target}`);
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
            console.log(`❌ Porta ${port} fechada/filtrada em ${target}`);
          }
          return null;
        } catch (error) {
          console.log(`⚠️ Erro na porta ${port}: ${error}`);
          return null;
        }
      });

      const batchResults = await Promise.all(promises);
      const openPorts = batchResults.filter(result => result !== null);
      results.push(...openPorts);
      
      console.log(`📊 Lote concluído: ${openPorts.length}/${batch.length} portas abertas`);
    }

    console.log(`🎯 TCP scan concluído: ${results.length} portas abertas encontradas de ${ports.length} testadas`);
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
   * Scan de range CIDR
   */
  async scanCidrRange(cidr: string, nmapProfile?: string): Promise<PortScanResult[]> {
    const hosts = this.expandCidrRange(cidr);
    const results: PortScanResult[] = [];

    // Limitar para primeiros 10 hosts para evitar sobrecarga
    const hostsToScan = hosts.slice(0, 10);
    
    for (const host of hostsToScan) {
      try {
        const hostResults = await this.scanPorts(host, undefined, nmapProfile);
        results.push(...hostResults);
      } catch (error) {
        console.error(`Erro ao escanear ${host}:`, error);
      }
    }

    return results;
  }

  /**
   * Expande range CIDR em lista de IPs
   */
  private expandCidrRange(cidr: string): string[] {
    const [network, prefixLength] = cidr.split('/');
    const prefix = parseInt(prefixLength, 10);
    
    if (prefix < 24) {
      throw new Error('Range CIDR muito grande. Use /24 ou maior.');
    }

    const networkParts = network.split('.').map(Number);
    const hosts: string[] = [];
    
    // Para /24, escanear apenas primeiros 10 hosts
    const maxHosts = Math.min(2 ** (32 - prefix), 10);
    
    for (let i = 1; i < maxHosts; i++) {
      const lastOctet = (networkParts[3] + i) % 256;
      const host = `${networkParts[0]}.${networkParts[1]}.${networkParts[2]}.${lastOctet}`;
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

    // Aplicar perfil de escaneamento
    switch (nmapProfile) {
      case 'fast':
        // Top 1000 portas (usar --top-ports 1000 do nmap)
        console.log('🚀 Perfil rápido selecionado: escaneando top 1000 portas');
        return [];
      
      case 'comprehensive':
        // Todas as portas (1-65535) - pode ser muito lento
        console.log('⚠️  Perfil completo selecionado: escaneando TODAS as portas (1-65535)');
        return [];
      
      case 'stealth':
        // Portas comuns com varredura SYN stealth
        console.log('🥷 Perfil stealth selecionado: escaneando portas comuns discretamente');
        return this.commonPorts.map(p => p.port);
      
      default:
        // Padrão: portas comuns
        return this.commonPorts.map(p => p.port);
    }
  }

  /**
   * Constrói argumentos do nmap baseado no perfil
   */
  private buildNmapArgs(target: string, ports: number[], nmapProfile?: string): string[] {
    const args = [];

    // Determinar tipo de scan baseado no perfil
    switch (nmapProfile) {
      case 'stealth':
        args.push('-sS'); // SYN stealth scan
        break;
      default:
        args.push('-sT'); // TCP connect scan (não requer root)
        break;
    }

    // Argumentos comuns
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

    // Timing template baseado no perfil
    switch (nmapProfile) {
      case 'fast':
        args.push('-T4'); // Timing agressivo
        break;
      case 'stealth':
        args.push('-T2'); // Timing mais lento e discreto
        break;
      default:
        args.push('-T3'); // Timing normal
        break;
    }

    // Configurar portas
    if (nmapProfile === 'comprehensive') {
      // Scan completo: todas as portas
      args.push('-p', '1-65535');
      console.log('🔍 Executando nmap com scan completo: portas 1-65535');
    } else if (ports.length > 0) {
      // Portas específicas
      const portList = ports.join(',');
      args.push('-p', portList);
      console.log(`🔍 Executando nmap com portas: ${portList}`);
    } else {
      // Top 1000 portas (padrão do nmap)
      args.push('--top-ports', '1000');
      console.log('🔍 Executando nmap com top 1000 portas');
    }

    args.push(target);
    return args;
  }
}

export const networkScanner = new NetworkScanner();