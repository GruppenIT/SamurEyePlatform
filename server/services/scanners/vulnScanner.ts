import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import https from 'https';
import http from 'http';
import { URL } from 'url';

export interface VulnerabilityFinding {
  type: 'vulnerability' | 'web_vulnerability';
  target: string;
  name: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  cve?: string;
  cvss?: number;
  description: string;
  template?: string;
  service?: string;
  port?: string;
  details?: string;
  evidence?: any;
}

export class VulnerabilityScanner {
  private readonly webVulnChecks = [
    {
      name: 'Server Information Disclosure',
      severity: 'low' as const,
      check: this.checkServerHeaders.bind(this),
    },
    {
      name: 'Directory Listing',
      severity: 'medium' as const,
      check: this.checkDirectoryListing.bind(this),
    },
    {
      name: 'SSL/TLS Configuration',
      severity: 'medium' as const,
      check: this.checkSSLConfig.bind(this),
    },
    {
      name: 'HTTP Security Headers',
      severity: 'medium' as const,
      check: this.checkSecurityHeaders.bind(this),
    },
    {
      name: 'Default Credentials',
      severity: 'high' as const,
      check: this.checkDefaultCredentials.bind(this),
    },
  ];

  /**
   * Executa scan de vulnerabilidades em um target
   */
  async scanVulnerabilities(target: string, ports: string[], portResults?: import('./networkScanner').PortScanResult[]): Promise<VulnerabilityFinding[]> {
    console.log(`Iniciando scan de vulnerabilidades para ${target}`);
    
    const results: VulnerabilityFinding[] = [];

    // Filtrar dinamicamente por serviços HTTP/HTTPS detectados pelo nmap
    const webServices = this.identifyWebServices(ports, portResults);
    console.log(`Encontrados ${webServices.length} serviços web para escanear:`, webServices.map(w => `${w.port}/${w.service}`));
    
    for (const webService of webServices) {
      try {
        const protocol = this.getProtocolForService(webService.service);
        
        // Executar verificações básicas de web com protocolo correto
        const webResults = await this.scanWebVulnerabilities(target, webService.port, protocol);
        results.push(...webResults);
        
        // Executar nuclei com URL construída adequadamente
        const targetUrl = `${protocol}://${target}:${webService.port}`;
        
        console.log(`Executando nuclei para URL construída: ${targetUrl} (service: ${webService.service})`);
        const nucleiResults = await this.nucleiScanUrl(targetUrl);
        
        // Log verboso dos resultados do nuclei
        if (nucleiResults.length > 0) {
          console.log(`🎯 Nuclei encontrou ${nucleiResults.length} vulnerabilidades em ${targetUrl}:`);
          for (const vuln of nucleiResults) {
            console.log(`  ⚠️  ${vuln.title || vuln.templateId} | Severidade: ${vuln.severity || 'medium'} | URL: ${vuln.url}`);
          }
        } else {
          console.log(`✅ Nuclei não encontrou vulnerabilidades em ${targetUrl}`);
        }
        
        results.push(...nucleiResults);
      } catch (error) {
        console.log(`Scan falhou para ${target}:${webService.port} (${webService.service}) - ${error}`);
      }
    }

    return results;
  }

  /**
   * Scan usando nuclei com URL construída adequadamente
   */
  private async nucleiScanUrl(targetUrl: string): Promise<VulnerabilityFinding[]> {
    // Validar URL para prevenir injeção de comando
    if (!this.isValidUrl(targetUrl)) {
      console.warn(`URL inválida para nuclei: ${targetUrl}`);
      return [];
    }
    
    try {
      // Bootstrap templates do nuclei se necessário
      await this.ensureNucleiTemplates();
      
      const args = [
        '-u', targetUrl, // Flag correta para URL única
        '-jsonl', // Usar formato JSONL correto
        '-silent',
        '-duc', // Desabilitar verificação de atualizações
        '-ni', // Desabilitar interactsh
        '-nc', // Desabilitar cores no output
        '-nm', // Não mostrar metadata
        '-s', 'medium,high,critical', // Apenas vulnerabilidades relevantes
        '-timeout', '10', // Timeout de 10 segundos por request
        '-retries', '1', // Apenas 1 retry por falha
        '-c', '5', // Limitar concorrência
        '-t', '/tmp/nuclei/nuclei-templates', // Caminho dos templates
      ];
      
      console.log(`Executando nuclei para ${targetUrl} com templates em /tmp/nuclei/nuclei-templates`);
      const stdout = await this.spawnCommand('nuclei', args, 300000);
      console.log(`Nuclei completado para ${targetUrl}, processando resultados...`);
      
      return this.parseNucleiOutput(stdout, targetUrl);
    } catch (error) {
      console.log(`Nuclei não disponível ou falhou: ${error}`);
      return [];
    }
  }

  /**
   * Garante que os templates do nuclei estão disponíveis
   */
  private async ensureNucleiTemplates(): Promise<void> {
    const templatesDir = '/tmp/nuclei/nuclei-templates';
    const configDir = '/tmp/nuclei/.config';
    
    try {
      // Criar diretórios necessários
      await this.ensureDirectoryExists('/tmp/nuclei');
      await this.ensureDirectoryExists(configDir);
      await this.ensureDirectoryExists('/tmp/nuclei/.cache');
      
      // Verificar se templates existem
      try {
        const stats = await fs.stat(templatesDir);
        if (stats.isDirectory()) {
          // Verificar se tem conteúdo
          const files = await fs.readdir(templatesDir);
          if (files.length > 0) {
            console.log(`Templates nuclei encontrados: ${files.length} arquivos/pastas`);
            return; // Templates já existem
          }
        }
      } catch {
        // Diretório não existe, precisa baixar templates
      }
      
      console.log('Baixando templates nuclei...');
      
      // Tentar baixar templates
      const updateArgs = ['-update-templates', '-ud', templatesDir];
      
      try {
        await this.spawnCommand('nuclei', updateArgs, 120000); // 2 minutos para download
        console.log('Templates nuclei baixados com sucesso');
      } catch (error) {
        console.warn(`Falha ao baixar templates nuclei: ${error}`);
        
        // Fallback: tentar com flag alternativa
        try {
          const altArgs = ['-ut', '-ud', templatesDir];
          await this.spawnCommand('nuclei', altArgs, 120000);
          console.log('Templates nuclei baixados com sucesso (fallback)');
        } catch (altError) {
          console.warn(`Falha no fallback de templates: ${altError}`);
          throw new Error('Não foi possível baixar templates do nuclei');
        }
      }
      
    } catch (error) {
      console.error(`Erro ao configurar templates nuclei: ${error}`);
      throw error;
    }
  }

  /**
   * Cria diretório se não existir (para nuclei config)
   */
  private async ensureDirectoryExists(dirPath: string): Promise<void> {
    try {
      await fs.mkdir(dirPath, { recursive: true });
    } catch (error: unknown) {
      // Ignorar se já existir ou não conseguir criar
      console.log(`Aviso: Não foi possível criar diretório ${dirPath}: ${error}`);
    }
  }

  /**
   * Identifica serviços web dinamicamente a partir dos resultados do nmap
   */
  private identifyWebServices(ports: string[], portResults?: import('./networkScanner').PortScanResult[]): Array<{port: string, service: string}> {
    const webServices: Array<{port: string, service: string}> = [];
    const seenPorts = new Set<string>(); // Deduplicação por porta
    
    if (portResults && portResults.length > 0) {
      // Usar resultados reais do nmap quando disponíveis
      for (const result of portResults) {
        // Verificar se porta já foi processada e se service não é nulo
        if (result.state === 'open' && 
            result.service && 
            !seenPorts.has(result.port) && 
            this.isWebService(result.service)) {
          
          webServices.push({ port: result.port, service: result.service });
          seenPorts.add(result.port);
        }
      }
    }
    
    // Fallback para portas comuns se não houver resultados web válidos
    if (webServices.length === 0) {
      const commonWebPorts = ports.filter(port => ['80', '443', '8080', '8443'].includes(port));
      for (const port of commonWebPorts) {
        if (!seenPorts.has(port)) {
          const service = ['443', '8443'].includes(port) ? 'https' : 'http';
          webServices.push({ port, service });
          seenPorts.add(port);
        }
      }
    }
    
    return webServices;
  }

  /**
   * Verifica se um serviço é relacionado a HTTP/HTTPS
   */
  private isWebService(service: string): boolean {
    if (!service || typeof service !== 'string') {
      return false;
    }
    
    const webServices = [
      'http', 'https', 'http-alt', 'https-alt',
      'http-proxy', 'ssl/http', 'ssl/https',
      // Removido 'tcpwrapped' pois pode ser qualquer serviço mascarado
      'nginx', 'apache', 'lighttpd', 'httpd',
      'tomcat', 'jetty', 'websphere',
      'iis', 'nodejs', 'express'
    ];
    
    const serviceLower = service.toLowerCase();
    return webServices.some(webSvc => serviceLower.includes(webSvc));
  }

  /**
   * Determina o protocolo (http/https) baseado no serviço
   */
  private getProtocolForService(service: string): string {
    const httpsServices = ['https', 'ssl', 'https-alt'];
    return httpsServices.some(s => service.toLowerCase().includes(s)) ? 'https' : 'http';
  }

  /**
   * Valida se a URL é válida e segura
   */
  private isValidUrl(url: string): boolean {
    try {
      const parsed = new URL(url);
      // Permitir apenas HTTP/HTTPS
      return ['http:', 'https:'].includes(parsed.protocol);
    } catch {
      return false;
    }
  }

  /**
   * Valida se o target é um IP ou hostname válido
   */
  private isValidTarget(target: string): boolean {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipRegex.test(target)) {
      return true;
    }
    
    const hostnameRegex = /^[a-zA-Z0-9.-]+$/;
    return hostnameRegex.test(target) && target.length <= 255;
  }

  /**
   * Executa comando usando spawn para segurança
   */
  private async spawnCommand(command: string, args: string[], timeout: number): Promise<string> {
    return new Promise((resolve, reject) => {
      const child = spawn(command, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        env: {
          ...process.env,
          HOME: '/tmp/nuclei', // Forçar nuclei a usar diretório temporário como HOME
          NUCLEI_CONFIG_DIR: '/tmp/nuclei/.config', // Diretório de configuração do nuclei
          XDG_CONFIG_HOME: '/tmp/nuclei/.config', // Padrão XDG para configuração
          XDG_CACHE_HOME: '/tmp/nuclei/.cache', // Cache
          NUCLEI_TEMPLATES_DIR: '/tmp/nuclei/nuclei-templates', // Diretório específico dos templates
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
      
      child.on('error', (error: Error) => {
        clearTimeout(timer);
        reject(error);
      });
    });
  }

  /**
   * Parse da saída do nuclei
   */
  private parseNucleiOutput(output: string, target: string): VulnerabilityFinding[] {
    const results: VulnerabilityFinding[] = [];
    const lines = output.split('\n').filter(line => line.trim());
    
    console.log(`🔍 Parseando ${lines.length} linhas de saída do nuclei para ${target}...`);
    
    for (const line of lines) {
      try {
        const finding = JSON.parse(line);
        
        // Log detalhado do achado parseado - mostra linha raw para debug
        console.log(`📝 Nuclei linha raw: ${line.substring(0, 200)}...`);
        console.log(`📝 Nuclei achado parseado: template=${finding.templateID || finding.template}, severity=${finding.info?.severity}, matched=${finding['matched-at'] || finding.matched_at}`);
        
        const vulnerability = {
          type: 'vulnerability',  // Tipo para corresponder ao matcher do threatEngine
          target,
          name: finding.info?.name || finding.templateID || finding.template,
          severity: this.mapNucleiSeverity(finding.info?.severity),
          template: finding.templateID || finding.template,
          description: finding.info?.description || '',
          evidence: {
            source: 'nuclei',     // Identifica origem dentro do evidence
            templateId: finding.templateID || finding.template,
            url: finding['matched-at'] || finding.matched_at,
            matcher: finding['matcher-name'] || finding.matcher_name,
            extractedResults: finding['extracted-results'] || finding.extracted_results,
            curl: finding['curl-command'] || finding.curl_command,
            info: finding.info,
            host: finding.host,
            port: finding.port,
          },
        };
        
        results.push(vulnerability);
        console.log(`✅ Vulnerabilidade adicionada: ${vulnerability.name} (${vulnerability.severity})`);
        
      } catch (error) {
        console.warn('❌ Erro ao parsear linha do nuclei:', line, 'Erro:', error);
      }
    }
    
    console.log(`📊 Nuclei parsing concluído: ${results.length} vulnerabilidades extraídas de ${lines.length} linhas`);
    return results;
  }

  /**
   * Mapeia severidade do nuclei para nosso formato
   */
  private mapNucleiSeverity(severity: string): 'low' | 'medium' | 'high' | 'critical' {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'critical';
      case 'high': return 'high';
      case 'medium': return 'medium';
      case 'low':
      case 'info':
      default: return 'low';
    }
  }

  /**
   * Scan de vulnerabilidades web usando verificações básicas
   */
  private async scanWebVulnerabilities(target: string, port: string, protocol: string = 'http'): Promise<VulnerabilityFinding[]> {
    const results: VulnerabilityFinding[] = [];
    const baseUrl = `${protocol}://${target}:${port}`;

    for (const vulnCheck of this.webVulnChecks) {
      try {
        const finding = await vulnCheck.check(baseUrl, target, port);
        if (finding) {
          results.push({
            type: 'web_vulnerability',
            target,
            name: vulnCheck.name,
            severity: vulnCheck.severity,
            description: finding.description,
            service: 'http',
            port,
            evidence: finding.evidence,
          });
        }
      } catch (error) {
        console.warn(`Erro na verificação ${vulnCheck.name} para ${baseUrl}:`, error);
      }
    }

    return results;
  }

  /**
   * Verifica headers do servidor para vazamento de informações
   */
  private async checkServerHeaders(baseUrl: string, target: string, port: string): Promise<any> {
    const response = await this.httpRequest(baseUrl);
    const serverHeader = response.headers.server;
    const xPoweredBy = response.headers['x-powered-by'];
    
    if (serverHeader || xPoweredBy) {
      return {
        description: 'Servidor está expondo informações de versão nos headers HTTP',
        evidence: {
          server: serverHeader,
          'x-powered-by': xPoweredBy,
          headers: response.headers,
        },
      };
    }
    
    return null;
  }

  /**
   * Verifica directory listing
   */
  private async checkDirectoryListing(baseUrl: string): Promise<any> {
    const testPaths = ['/admin/', '/backup/', '/config/', '/logs/', '/uploads/'];
    
    for (const path of testPaths) {
      try {
        const response = await this.httpRequest(baseUrl + path);
        if (response.body.includes('Index of') || response.body.includes('Directory listing')) {
          return {
            description: `Directory listing habilitado em ${path}`,
            evidence: {
              path,
              status: response.statusCode,
              body_sample: response.body.substring(0, 500),
            },
          };
        }
      } catch (error) {
        // Path não existe ou erro de acesso
      }
    }
    
    return null;
  }

  /**
   * Verifica configuração SSL/TLS
   */
  private async checkSSLConfig(baseUrl: string): Promise<any> {
    if (!baseUrl.startsWith('https://')) {
      return null;
    }

    try {
      const url = new URL(baseUrl);
      const response = await this.httpRequest(baseUrl);
      
      // Verificar se aceita HTTP também
      const httpUrl = baseUrl.replace('https://', 'http://');
      try {
        await this.httpRequest(httpUrl);
        return {
          description: 'Servidor aceita conexões HTTP e HTTPS simultaneamente',
          evidence: {
            https_available: true,
            http_available: true,
            mixed_content_risk: true,
          },
        };
      } catch (error: unknown) {
        // HTTP não disponível, o que é bom
      }
      
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      if (errorMessage.includes('certificate') || errorMessage.includes('SSL')) {
        return {
          description: 'Problemas na configuração SSL/TLS detectados',
          evidence: {
            ssl_error: errorMessage,
          },
        };
      }
    }
    
    return null;
  }

  /**
   * Verifica headers de segurança
   */
  private async checkSecurityHeaders(baseUrl: string): Promise<any> {
    const response = await this.httpRequest(baseUrl);
    const missingHeaders = [];
    
    const securityHeaders = [
      'x-frame-options',
      'x-content-type-options',
      'x-xss-protection',
      'strict-transport-security',
      'content-security-policy',
    ];
    
    for (const header of securityHeaders) {
      if (!response.headers[header]) {
        missingHeaders.push(header);
      }
    }
    
    if (missingHeaders.length > 0) {
      return {
        description: `Headers de segurança não configurados: ${missingHeaders.join(', ')}`,
        evidence: {
          missing_headers: missingHeaders,
          current_headers: response.headers,
        },
      };
    }
    
    return null;
  }

  /**
   * Verifica credenciais padrão
   */
  private async checkDefaultCredentials(baseUrl: string): Promise<any> {
    const commonPaths = ['/admin', '/login', '/wp-admin', '/administrator'];
    const defaultCreds = [
      { user: 'admin', pass: 'admin' },
      { user: 'admin', pass: 'password' },
      { user: 'root', pass: 'root' },
      { user: 'administrator', pass: 'administrator' },
    ];
    
    for (const path of commonPaths) {
      try {
        const loginUrl = baseUrl + path;
        const response = await this.httpRequest(loginUrl);
        
        if (response.body.includes('login') || response.body.includes('password')) {
          // Página de login encontrada - não testar credenciais automaticamente por segurança
          return {
            description: `Página de login encontrada em ${path} - verificar credenciais padrão manualmente`,
            evidence: {
              login_page: path,
              status: response.statusCode,
            },
          };
        }
      } catch (error) {
        // Path não existe
      }
    }
    
    return null;
  }

  /**
   * Utilitário para fazer requisições HTTP
   */
  private async httpRequest(url: string): Promise<{ statusCode: number; headers: any; body: string }> {
    return new Promise((resolve, reject) => {
      const urlObj = new URL(url);
      const client = urlObj.protocol === 'https:' ? https : http;
      
      const options = {
        hostname: urlObj.hostname,
        port: urlObj.port,
        path: urlObj.pathname + urlObj.search,
        method: 'GET',
        timeout: 10000,
        headers: {
          'User-Agent': 'SamurEye-Scanner/1.0',
        },
        // Para HTTPS, aceitar certificados auto-assinados em ambiente de teste
        rejectUnauthorized: false,
      };

      const req = client.request(options, (res) => {
        let body = '';
        
        res.on('data', (chunk) => {
          body += chunk;
          // Limitar tamanho do body para evitar memory overflow
          if (body.length > 50000) {
            req.destroy();
            resolve({
              statusCode: res.statusCode || 0,
              headers: res.headers,
              body: body.substring(0, 50000),
            });
          }
        });
        
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode || 0,
            headers: res.headers,
            body,
          });
        });
      });

      req.on('error', (error) => {
        reject(error);
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });

      req.end();
    });
  }
}

export const vulnScanner = new VulnerabilityScanner();