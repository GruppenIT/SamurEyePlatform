import { spawn } from 'child_process';
import dns from 'dns';
import net from 'net';
import { promisify } from 'util';

const dnsLookup = promisify(dns.lookup);

export interface PortScanResult {
  type: 'port';
  target: string;
  port: string;
  state: 'open' | 'closed' | 'filtered';
  service: string;
  version?: string;
  banner?: string;
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
  async scanPorts(target: string, ports?: number[]): Promise<PortScanResult[]> {
    console.log(`Iniciando scan de portas para ${target}`);
    
    // Verificar se é um IP válido ou hostname
    const resolvedTarget = await this.resolveTarget(target);
    if (!resolvedTarget) {
      throw new Error(`Não foi possível resolver o target: ${target}`);
    }

    const portsToScan = ports || this.commonPorts.map(p => p.port);
    const results: PortScanResult[] = [];

    // Tentar usar nmap se disponível, senão usar scan TCP nativo
    try {
      const nmapResults = await this.nmapScan(resolvedTarget, portsToScan);
      return nmapResults;
    } catch (error) {
      console.log('nmap não disponível, usando scan TCP nativo:', error);
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
        return target;
      }

      // Resolve hostname
      const result = await dnsLookup(target);
      return result.address;
    } catch (error) {
      console.error(`Erro ao resolver ${target}:`, error);
      return null;
    }
  }

  /**
   * Scan usando nmap (quando disponível)
   */
  private async nmapScan(target: string, ports: number[]): Promise<PortScanResult[]> {
    // Validar e sanitizar target para prevenir injeção de comando
    if (!this.isValidTarget(target)) {
      throw new Error(`Target inválido: ${target}`);
    }
    
    const portList = ports.join(',');
    const args = [
      '-sT', // TCP connect scan (não requer root)
      '-sV', // Version detection
      '--script=vuln', // Scripts de vulnerabilidade para detecção real
      '--script-args', 'vulns.showall', // Mostrar todas as vulnerabilidades encontradas
      '--max-hostgroup', '1', // Limita número de hosts simultâneos
      '--max-parallelism', '5', // Reduz paralelismo para scripts vuln
      '--min-rate', '50', // Taxa mínima reduzida para scripts
      '--max-rate', '500', // Taxa máxima reduzida para estabilidade
      '--max-rtt-timeout', '5s', // Timeout RTT maior para scripts vuln
      '--initial-rtt-timeout', '1s', // Timeout RTT inicial maior
      '-T3', // Timing template normal (mais seguro para scripts vuln)
      '--version-intensity', '7', // Intensidade de detecção de versão
      '-p', portList,
      target
    ];
    
    const stdout = await this.spawnCommand('nmap', args, 300000); // Aumenta timeout para 5 minutos
    return this.parseNmapOutput(stdout, target);
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
        child.kill();
        reject(new Error('Command timeout'));
      }, timeout);
      
      child.on('close', (code) => {
        clearTimeout(timer);
        if (code === 0) {
          resolve(stdout);
        } else {
          reject(new Error(`Command failed with code ${code}: ${stderr}`));
        }
      });
      
      child.on('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
    });
  }

  /**
   * Parse da saída do nmap
   */
  private parseNmapOutput(output: string, target: string): PortScanResult[] {
    const results: PortScanResult[] = [];
    const lines = output.split('\n');
    let vulnerabilityBuffer = '';
    let currentPort = '';
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Procurar por linhas de porta: "22/tcp open ssh OpenSSH 8.2" ou "3389/tcp open|filtered ms-wbt-server"
      const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+(open|closed|filtered|open\|filtered|closed\|filtered)\s+(\S+)(?:\s+(.+))?/);
      if (portMatch) {
        const [, port, protocol, state, service, version] = portMatch;
        currentPort = port;
        
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
          target,
          port,
          state: state as 'open' | 'closed' | 'filtered',
          service,
          version: version?.trim(),
          banner: vulnerabilityBuffer.trim() || undefined
        });
      }
    }
    
    console.log(`Parse nmap encontrou ${results.length} portas para ${target}`);
    if (results.length > 0) {
      console.log('Primeiras portas encontradas:', results.slice(0, 3).map(r => `${r.port}/${r.state}`));
    }
    
    return results;
  }

  /**
   * Scan TCP nativo (fallback quando nmap não está disponível)
   */
  private async tcpPortScan(target: string, ports: number[]): Promise<PortScanResult[]> {
    const results: PortScanResult[] = [];
    const timeout = 2000; // Reduz timeout para 2 segundos por porta
    const maxConcurrent = 20; // Máximo de 20 conexões simultâneas

    // Processa portas em lotes para melhor performance
    for (let i = 0; i < ports.length; i += maxConcurrent) {
      const batch = ports.slice(i, i + maxConcurrent);
      const promises = batch.map(async (port) => {
        try {
          const isOpen = await this.checkTcpPort(target, port, timeout);
          const serviceInfo = this.getServiceInfo(port);
          
          if (isOpen) {
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
          }
          return null;
        } catch (error) {
          // Porta fechada ou filtrada - não incluir no resultado
          return null;
        }
      });

      const batchResults = await Promise.all(promises);
      results.push(...batchResults.filter(result => result !== null));
    }

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
  async scanCidrRange(cidr: string): Promise<PortScanResult[]> {
    const hosts = this.expandCidrRange(cidr);
    const results: PortScanResult[] = [];

    // Limitar para primeiros 10 hosts para evitar sobrecarga
    const hostsToScan = hosts.slice(0, 10);
    
    for (const host of hostsToScan) {
      try {
        const hostResults = await this.scanPorts(host);
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
}

export const networkScanner = new NetworkScanner();