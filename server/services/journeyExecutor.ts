import { storage } from '../storage';
import { threatEngine } from './threatEngine';
import { encryptionService } from './encryption';
import { networkScanner } from './scanners/networkScanner';
import { vulnScanner } from './scanners/vulnScanner';
import { ADScanner } from './scanners/adScanner';
import { EDRAVScanner } from './scanners/edrAvScanner';
import { jobQueue } from './jobQueue';
import { hostService } from './hostService';
import { type Journey, type Job } from '@shared/schema';

const adScanner = new ADScanner();

export interface JourneyProgress {
  status: Job['status'];
  progress: number;
  currentTask: string;
}

type ProgressCallback = (progress: JourneyProgress) => void;

class JourneyExecutorService {
  /**
   * Resolve asset IDs based on target selection mode
   * If targetSelectionMode is 'by_tag', expands selectedTags into assetIds
   * If targetSelectionMode is 'individual', uses assetIds from params directly
   */
  private async resolveAssetIds(journey: Journey): Promise<string[]> {
    // Modo 1: Seleção por TAG
    if (journey.targetSelectionMode === 'by_tag' && journey.selectedTags && journey.selectedTags.length > 0) {
      console.log(`🏷️  Expandindo TAGs selecionadas: ${journey.selectedTags.join(', ')}`);
      const assets = await storage.getAssetsByTags(journey.selectedTags);
      const assetIds = assets.map(a => a.id);
      console.log(`✅ ${assetIds.length} alvos encontrados com as TAGs selecionadas`);
      return assetIds;
    }
    
    // Modo 2: Seleção Individual (padrão ou explícito)
    const assetIds = journey.params.assetIds || [];
    return assetIds;
  }

  /**
   * Executes a journey based on its type
   */
  async executeJourney(
    journey: Journey, 
    jobId: string, 
    onProgress: ProgressCallback
  ): Promise<void> {
    onProgress({ status: 'running', progress: 10, currentTask: 'Preparando execução' });

    switch (journey.type) {
      case 'attack_surface':
        await this.executeAttackSurface(journey, jobId, onProgress);
        break;
      case 'ad_security':
        await this.executeADSecurity(journey, jobId, onProgress);
        break;
      case 'edr_av':
        await this.executeEDRAV(journey, jobId, onProgress);
        break;
      default:
        throw new Error(`Tipo de jornada não suportado: ${journey.type}`);
    }

    // Check if job was cancelled before threat analysis
    if (this.isJobCancelled(jobId)) {
      console.log(`🚫 Job ${jobId} cancelado, parando antes de análise de ameaças`);
      throw new Error('Job cancelado pelo usuário');
    }

    onProgress({ status: 'running', progress: 90, currentTask: 'Analisando resultados' });
    
    // Process results and generate threats
    await threatEngine.processJobResults(jobId);
    
    // Process journey completion for threat lifecycle management
    await threatEngine.processJourneyCompletion(jobId);
    
    onProgress({ status: 'completed', progress: 100, currentTask: 'Execução finalizada' });
  }

  /**
   * Check if job was cancelled for cooperative cancellation
   */
  private isJobCancelled(jobId: string): boolean {
    return jobQueue.isJobCancelled(jobId);
  }

  /**
   * Executes Attack Surface journey - New architecture with active CVE validation
   * 
   * Phase 1: Discovery (port scanning with nmap)
   * Phase 2: Active Vulnerability Validation
   *   - Nmap vuln scripts for network services
   *   - Nuclei for web applications (if webScanEnabled)
   * Phase 3: Host discovery and result storage
   */
  private async executeAttackSurface(
    journey: Journey, 
    jobId: string, 
    onProgress: ProgressCallback
  ): Promise<void> {
    const params = journey.params;
    const assetIds = await this.resolveAssetIds(journey);
    const webScanEnabled = params.webScanEnabled === true;
    const processTimeoutMinutes = params.processTimeout || 60; // Default 60 minutos
    const processTimeoutMs = processTimeoutMinutes * 60 * 1000; // Converter para ms
    
    if (assetIds.length === 0) {
      throw new Error('Nenhum ativo selecionado para varredura');
    }

    console.log(`🚀 Iniciando Attack Surface Journey com varredura web: ${webScanEnabled ? 'ATIVADA' : 'DESATIVADA'}`);
    console.log(`⏱️  Timeout por processo: ${processTimeoutMinutes} minutos`);

    onProgress({ status: 'running', progress: 20, currentTask: 'Carregando ativos' });

    // Get assets
    const assets = [];
    for (const assetId of assetIds) {
      const asset = await storage.getAsset(assetId);
      if (asset) assets.push(asset);
    }

    const findings = [];
    let currentAsset = 0;

    for (const asset of assets) {
      // Check if job was cancelled
      if (this.isJobCancelled(jobId)) {
        console.log(`🚫 Job ${jobId} cancelado, parando execução no asset ${asset.value}`);
        throw new Error('Job cancelado pelo usuário');
      }

      currentAsset++;
      const baseProgress = 20 + (currentAsset / assets.length) * 60;
      
      onProgress({ 
        status: 'running', 
        progress: baseProgress, 
        currentTask: `Fase 1: Descobrindo serviços em ${asset.value} (${currentAsset}/${assets.length})` 
      });

      try {
        // ==================== PHASE 1: DISCOVERY ====================
        console.log(`📡 FASE 1: Descoberta de serviços em ${asset.value}`);
        
        let portResults;
        if (asset.type === 'range') {
          portResults = await networkScanner.scanCidrRange(asset.value, params.nmapProfile, jobId);
        } else {
          portResults = await networkScanner.scanPorts(asset.value, undefined, params.nmapProfile, jobId);
        }
        
        findings.push(...portResults);
        console.log(`✅ FASE 1: ${portResults.length} portas descobertas`);

        // ==================== PHASE 2: ACTIVE VALIDATION ====================
        // Group by host for vulnerability scanning
        const hostPortMap = new Map<string, { ports: string[], portResults: any[] }>();
        
        for (const result of portResults) {
          if (result.state === 'open') {
            const target = result.target || asset.value;
            const existing = hostPortMap.get(target) || { ports: [], portResults: [] };
            
            // Sanitize port: remove /tcp or /udp suffix
            // result.port can be "443" or "443/tcp", nmap needs just "443"
            const cleanPort = result.port.toString().replace(/\/(tcp|udp)$/i, '');
            existing.ports.push(cleanPort);
            existing.portResults.push(result);
            hostPortMap.set(target, existing);
          }
        }
        
        // Validate vulnerabilities for each discovered host
        for (const [host, data] of Array.from(hostPortMap.entries())) {
          if (this.isJobCancelled(jobId)) {
            throw new Error('Job cancelado pelo usuário');
          }

          if (data.ports.length === 0) continue;

          onProgress({ 
            status: 'running', 
            progress: baseProgress + 5, 
            currentTask: `Fase 2: Validando vulnerabilidades em ${host}` 
          });

          console.log(`🔍 FASE 2: Validação ativa de vulnerabilidades em ${host}`);
          
          // Phase 2A: Nmap vuln scripts for active CVE detection
          console.log(`🎯 FASE 2A: Executando nmap vuln scripts em ${host}`);
          const nmapVulnResults = await this.runNmapVulnScripts(host, data.ports, jobId, processTimeoutMs);
          findings.push(...nmapVulnResults);
          console.log(`✅ FASE 2A: ${nmapVulnResults.length} CVEs validados ativamente via nmap`);

          // Phase 2B: Nuclei for web applications (conditional)
          if (webScanEnabled) {
            console.log(`🌐 FASE 2B: Identificando aplicações web em ${host}`);
            const webUrls = this.identifyWebServices(host, data.portResults);
            
            if (webUrls.length > 0) {
              console.log(`🔍 FASE 2B: ${webUrls.length} aplicações web encontradas, executando Nuclei`);
              
              onProgress({ 
                status: 'running', 
                progress: baseProgress + 10, 
                currentTask: `Fase 2: Varredura web em ${host} (${webUrls.length} URLs)` 
              });

              const nucleiResults = await this.runNucleiWebScan(webUrls, jobId, processTimeoutMs);
              findings.push(...nucleiResults);
              console.log(`✅ FASE 2B: ${nucleiResults.length} vulnerabilidades web encontradas via Nuclei`);
            } else {
              console.log(`ℹ️  FASE 2B: Nenhuma aplicação web detectada em ${host}`);
            }
          } else {
            console.log(`⏭️  FASE 2B: Varredura web DESATIVADA (webScanEnabled=false)`);
          }
        }
        
      } catch (error) {
        console.error(`❌ Erro ao escanear ${asset.value}:`, error);
        
        const errorMessage = error instanceof Error ? error.message : String(error);
        findings.push({
          type: 'error',
          target: asset.value,
          message: `Erro durante escaneamento: ${errorMessage}`,
          timestamp: new Date().toISOString(),
        });
      }
    }

    // ==================== PHASE 3: HOST DISCOVERY & STORAGE ====================
    onProgress({ status: 'running', progress: 85, currentTask: 'Fase 3: Descobrindo hosts' });
    
    try {
      const discoveredHosts = await hostService.discoverHostsFromFindings(findings, jobId);
      console.log(`🏠 FASE 3: ${discoveredHosts.length} hosts descobertos/atualizados`);
    } catch (error) {
      console.error('❌ Erro ao descobrir hosts:', error);
    }

    // Store results
    await storage.createJobResult({
      jobId,
      stdout: `Varredura ativa concluída. ${findings.length} achados encontrados.`,
      stderr: '',
      artifacts: {
        findings,
        summary: {
          totalAssets: assets.length,
          totalFindings: findings.length,
          webScanEnabled,
        },
      },
    });
    
    console.log(`✅ Attack Surface concluído: ${findings.length} findings total`);
  }

  /**
   * Executes AD Security journey
   */
  private async executeADSecurity(
    journey: Journey, 
    jobId: string, 
    onProgress: ProgressCallback
  ): Promise<void> {
    const params = journey.params;
    const domain = params.domain || 'corp.local';
    const credentialId = params.credentialId;

    if (!credentialId) {
      throw new Error('Credencial não especificada para análise AD');
    }

    onProgress({ status: 'running', progress: 20, currentTask: 'Obtendo credenciais' });

    // Get and decrypt credential
    const credential = await storage.getCredential(credentialId);
    if (!credential) {
      throw new Error('Credencial não encontrada');
    }

    // Decrypt credential for actual AD connection
    const decryptedPassword = encryptionService.decryptCredential(
      credential.secretEncrypted, 
      credential.dekEncrypted
    );

    onProgress({ status: 'running', progress: 30, currentTask: 'Conectando ao Active Directory' });

    try {
      onProgress({ status: 'running', progress: 40, currentTask: 'Criando host de domínio' });

      // CREATE DOMAIN HOST FIRST - this ensures the host exists before threat analysis
      let domainHost;
      try {
        domainHost = await hostService.createDomainHost(domain, jobId);
        console.log(`🏠 AD Hygiene: Host de domínio criado: ${domainHost.name}`);
      } catch (error) {
        console.error('❌ Erro ao criar host de domínio:', error);
        // Continue execution even if domain host creation fails
      }

      onProgress({ status: 'running', progress: 50, currentTask: 'Executando testes de segurança AD' });

      // Extract enabled categories from journey params (default all enabled)
      const enabledCategories = params.enabledCategories || {
        configuracoes_criticas: true,
        gerenciamento_contas: true,
        kerberos_delegacao: true,
        compartilhamentos_gpos: true,
        politicas_configuracao: true,
        contas_inativas: true,
      };

      // Get DC host - prefer primary, fallback to secondary if provided
      // Note: Scanner will handle fallback internally if connection fails
      const dcHost = params.primaryDC || params.secondaryDC || undefined;

      // Execute AD Security scan using PowerShell via WinRM
      const scanResult = await adScanner.scanADSecurity(
        domain,
        credential.username,
        decryptedPassword,
        dcHost,
        enabledCategories
      );

      const { findings, testResults } = scanResult;

      onProgress({ status: 'running', progress: 70, currentTask: 'Salvando resultados dos testes' });

      // Save test results to database (linked to domain host)
      if (testResults.length > 0 && domainHost) {
        try {
          const testResultsToInsert = testResults.map(result => ({
            jobId,
            hostId: domainHost.id,
            testId: result.testId,
            testName: result.testName,
            category: result.category,
            severityHint: result.severityHint,
            status: result.status,
            evidence: result.evidence,
          }));
          
          await storage.createAdSecurityTestResults(testResultsToInsert);
          console.log(`✅ Salvos ${testResults.length} resultados de testes AD Security`);
        } catch (error) {
          console.error('❌ Erro ao salvar resultados dos testes:', error);
        }
      }

      onProgress({ status: 'running', progress: 80, currentTask: 'Processando resultados' });

      // Store results
      await storage.createJobResult({
        jobId,
        stdout: `Análise AD concluída para domínio ${domain}. ${findings.length} achados identificados, ${testResults.length} testes executados.`,
        stderr: '',
        artifacts: {
          findings,
          testResults,
          summary: {
            domain,
            totalFindings: findings.length,
            totalTests: testResults.length,
            findingsByCategory: this.groupFindingsByCategory(findings),
            findingsBySeverity: this.groupFindingsBySeverity(findings),
            scanDuration: new Date().toISOString(),
          },
        },
      });

    } catch (error) {
      console.error('Erro durante análise AD:', error);
      
      const errorMessage = error instanceof Error ? error.message : String(error);
      
      // Store error result
      await storage.createJobResult({
        jobId,
        stdout: '',
        stderr: `Erro durante análise AD: ${errorMessage}`,
        artifacts: {
          findings: [],
          summary: {
            domain,
            error: errorMessage,
            scanDuration: new Date().toISOString(),
          },
        },
      });
      
      throw error;
    }
  }

  /**
   * Executes EDR/AV Testing journey
   */
  private async executeEDRAV(
    journey: Journey, 
    jobId: string, 
    onProgress: ProgressCallback
  ): Promise<void> {
    const params = journey.params;
    const sampleRate = params.sampleRate || 15; // percentage
    const timeout = params.timeout || 30; // timeout EICAR em segundos
    const credentialId = params.credentialId;

    if (!credentialId) {
      throw new Error('Credencial não especificada para teste EDR/AV');
    }

    try {
      onProgress({ status: 'running', progress: 20, currentTask: 'Obtendo credencial' });

      // Buscar e descriptografar credencial
      const credential = await storage.getCredential(credentialId);
      if (!credential) {
        throw new Error('Credencial não encontrada');
      }

      const decryptedPassword = encryptionService.decryptCredential(credential.secretEncrypted, credential.dekEncrypted);

      onProgress({ status: 'running', progress: 30, currentTask: 'Descobrindo workstations do domínio' });

      // Para teste EDR/AV, descobrir workstations baseado no tipo configurado
      let workstationTargets: string[] = [];
      const edrAvType = params.edrAvType || 'network_based'; // Default para compatibilidade
      
      if (edrAvType === 'ad_based') {
        // Modo AD Based: Descobrir workstations via PowerShell/WinRM
        console.log('🔍 Modo AD Based: Descobrindo workstations via PowerShell/WinRM...');
        
        if (credential.type !== 'ad') {
          throw new Error('Para jornada AD Based é necessário usar credencial do tipo AD/LDAP');
        }

        const domainName = params.domainName || credential.domain;
        if (!domainName) {
          throw new Error('Nome do domínio não especificado para jornada AD Based');
        }

        const adScanner = new ADScanner();
        const dcHost = params.primaryDC || params.secondaryDC || undefined;
        
        workstationTargets = await adScanner.discoverWorkstations(
          domainName,
          credential.username,
          decryptedPassword,
          dcHost
        );

        console.log(`✅ Descobertas ${workstationTargets.length} workstations via AD`);

      } else if (edrAvType === 'network_based') {
        // Modo Network Based: Usar ativos específicos
        console.log('🎯 Modo Network Based: Usando ativos específicos...');
        
        // Resolver assetIds baseado em targetSelectionMode (individual ou by_tag)
        const resolvedAssetIds = await this.resolveAssetIds(journey);
        
        if (resolvedAssetIds && resolvedAssetIds.length > 0) {
          // Buscar ativos pelos IDs fornecidos/resolvidos
          const selectedAssets = await Promise.all(
            resolvedAssetIds.map(async (assetId: string) => {
              const asset = await storage.getAsset(assetId);
              return asset;
            })
          );

          // Extrair valores dos ativos (IPs, ranges, etc)
          for (const asset of selectedAssets) {
            if (asset) {
              if (asset.type === 'host') {
                workstationTargets.push(asset.value);
              } else if (asset.type === 'range') {
                // Expandir range CIDR em IPs individuais
                console.log(`🌐 Expandindo range CIDR: ${asset.value}`);
                const expandedIPs = this.expandCIDR(asset.value);
                console.log(`📊 Range expandido para ${expandedIPs.length} IPs`);
                workstationTargets.push(...expandedIPs);
              }
            }
          }
        } else if (params.targets && params.targets.length > 0) {
          // Fallback para compatibilidade com jornadas antigas
          workstationTargets = params.targets;
        } else {
          throw new Error('Nenhum ativo selecionado para jornada Network Based');
        }

        console.log(`Usando ${workstationTargets.length} targets específicos`);
      }

      if (workstationTargets.length === 0) {
        throw new Error(`Nenhuma workstation encontrada para teste (modo: ${edrAvType})`);
      }

      onProgress({ 
        status: 'running', 
        progress: 50, 
        currentTask: `Executando teste EICAR em ${workstationTargets.length} workstations (amostra: ${sampleRate}%)` 
      });

      // Executar teste EDR/AV real
      const edrScanner = new EDRAVScanner();
      
      // Usar domínio da credencial, ou da jornada, ou deduzir do FQDN das workstations
      let effectiveDomain = credential.domain;
      if (!effectiveDomain && params.domainName) {
        effectiveDomain = params.domainName;
      }
      // Se ainda não tiver domínio, tentar deduzir o NetBIOS domain do primeiro workstation FQDN
      if (!effectiveDomain && workstationTargets.length > 0) {
        const firstTarget = workstationTargets[0];
        if (firstTarget.includes('.')) {
          const parts = firstTarget.split('.');
          if (parts.length >= 3) {
            // Para smbclient, usar o segundo nível como NetBIOS domain (GRUPPEN não gruppen.com.br)
            effectiveDomain = parts[1].toUpperCase(); // Exemplo: server.gruppen.com.br -> GRUPPEN
          }
        }
      }
      
      console.log(`🔑 Usando credenciais: ${credential.username}@${effectiveDomain || 'LOCAL'}`);
      
      const result = await edrScanner.runEDRAVTest(
        {
          username: credential.username,
          password: decryptedPassword,
          domain: effectiveDomain || undefined,
        },
        workstationTargets,
        sampleRate,
        timeout
      );

      const { findings, statistics } = result;

      onProgress({ status: 'running', progress: 90, currentTask: 'Processando resultados' });

      const eicarRemoved = statistics.eicarRemovedCount;
      const eicarPersisted = statistics.eicarPersistedCount;
      const errors = findings.filter(f => f.error).length;

      // Criar log detalhado para exibição
      const detailedLog = [
        `📈 ESTATÍSTICAS DO TESTE EDR/AV:`,
        `• ${statistics.totalDiscovered} computadores descobertos`,
        `• Amostragem solicitada: ${statistics.requestedSampleRate}%/${statistics.requestedSampleSize} computadores`,
        `• EICAR copiado para ${statistics.successfulDeployments} computadores após tentativas`,
        `• Falhas no deployment: ${statistics.failedDeployments}`,
        statistics.attemptsExhausted 
          ? `⚠️ NÃO FOI POSSÍVEL ALCANÇAR A AMOSTRAGEM SOLICITADA. Isso pode ser causado por contas inativas no AD ou computadores desligados no horário de execução.`
          : `✅ Amostragem alcançada com sucesso`,
        `• EDR/AV funcionando: ${eicarRemoved} computadores`,
        `• EDR/AV com falhas: ${eicarPersisted} computadores`,
      ].join('\n');

      await storage.createJobResult({
        jobId,
        stdout: detailedLog,
        stderr: errors > 0 ? `${errors} hosts com erros durante o teste` : '',
        artifacts: {
          findings,
          statistics,
          summary: {
            ...statistics,
            domain: credential.domain,
            testDuration: new Date().toISOString(),
          },
        },
      });

    } catch (error) {
      console.error('Erro durante teste EDR/AV:', error);
      
      const errorMessage = error instanceof Error ? error.message : String(error);
      
      // Store error result
      await storage.createJobResult({
        jobId,
        stdout: '',
        stderr: `Erro durante teste EDR/AV: ${errorMessage}`,
        artifacts: {
          findings: [],
          summary: {
            error: errorMessage,
            testDuration: new Date().toISOString(),
          },
        },
      });
      
      throw error;
    }
  }

  /**
   * Generate realistic attack surface findings
   */
  private generateAttackSurfaceFindings(target: string): any[] {
    const findings = [];
    
    // Port scan findings
    const commonPorts = [22, 80, 443, 3389, 5985];
    for (const port of commonPorts) {
      if (Math.random() > 0.3) { // 70% chance port is open
        findings.push({
          type: 'port',
          target,
          port: port.toString(),
          state: 'open',
          service: this.getServiceForPort(port),
          version: this.getRandomVersion(port),
        });
      }
    }

    // Add some vulnerabilities
    if (Math.random() > 0.7) { // 30% chance of critical vulnerability
      findings.push({
        type: 'vulnerability',
        target,
        cve: 'CVE-2024-1234',
        severity: 'critical',
        cvss: 9.8,
        description: 'Vulnerabilidade crítica em Apache HTTP Server permite execução remota de código',
        service: 'http',
        port: '80',
        details: 'Buffer overflow in HTTP request parsing',
      });
    }

    return findings;
  }

  /**
   * Generate nuclei findings
   */
  private generateNucleiFindings(): any[] {
    const findings = [];
    
    // Some common web vulnerabilities
    const vulns = [
      { name: 'Apache Server Status', severity: 'low' },
      { name: 'Directory Listing', severity: 'medium' },
      { name: 'Weak SSL/TLS Configuration', severity: 'medium' },
    ];

    for (const vuln of vulns) {
      if (Math.random() > 0.5) {
        findings.push({
          type: 'web_vulnerability',
          name: vuln.name,
          severity: vuln.severity,
          template: vuln.name.toLowerCase().replace(/\s+/g, '-'),
        });
      }
    }

    return findings;
  }

  /**
   * Generate AD hygiene findings
   */
  private generateADHygieneFindings(domain: string): any[] {
    const findings = [];

    // Users with old passwords
    const problematicUsers = [
      'administrador.silva',
      'backup.service',
      'sql.admin',
    ];

    for (const username of problematicUsers) {
      if (Math.random() > 0.4) {
        findings.push({
          type: 'ad_user',
          username,
          domain,
          passwordAge: Math.floor(Math.random() * 200) + 90, // 90-290 days
          groups: username.includes('admin') ? ['Domain Admins'] : ['Domain Users'],
          lastLogon: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString(),
          enabled: true,
        });
      }
    }

    // Password never expires accounts
    const serviceAccounts = ['svc_backup', 'svc_sql', 'svc_web'];
    for (const account of serviceAccounts) {
      if (Math.random() > 0.6) {
        findings.push({
          type: 'ad_user',
          username: account,
          domain,
          passwordNeverExpires: true,
          enabled: true,
          lastLogon: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000).toISOString(),
        });
      }
    }

    return findings;
  }

  /**
   * Generate EDR/AV test findings
   */
  private generateEDRAVFindings(sampleSize: number): any[] {
    const findings = [];

    for (let i = 0; i < sampleSize; i++) {
      const hostname = `ws-${String(i + 1).padStart(3, '0')}.corp.local`;
      const eicarRemoved = Math.random() > 0.1; // 90% success rate
      
      findings.push({
        type: 'edr_test',
        hostname,
        filePath: `\\\\${hostname}\\C$\\Windows\\Temp\\samureye_eicar.txt`,
        eicarRemoved,
        testDuration: Math.floor(Math.random() * 300) + 30, // 30-330 seconds
        timestamp: new Date().toISOString(),
      });
    }

    return findings;
  }

  /**
   * Helper methods
   */
  private getServiceForPort(port: number): string {
    const services: Record<number, string> = {
      22: 'ssh',
      80: 'http',
      443: 'https',
      3389: 'rdp',
      5985: 'winrm',
    };
    return services[port] || 'unknown';
  }

  private getRandomVersion(port: number): string {
    const versions: Record<number, string[]> = {
      22: ['OpenSSH 8.9', 'OpenSSH 8.2', 'OpenSSH 7.4'],
      80: ['Apache 2.4.52', 'nginx 1.18.0', 'IIS 10.0'],
      443: ['Apache 2.4.52', 'nginx 1.18.0', 'IIS 10.0'],
      3389: ['Microsoft Terminal Services'],
      5985: ['Microsoft WinRM 2.0'],
    };
    const options = versions[port] || ['unknown'];
    return options[Math.floor(Math.random() * options.length)];
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Gera lista de workstations para um domínio
   * Em implementação real, consultaria AD para obter lista real
   */
  private generateWorkstationList(domain: string): string[] {
    const workstations: string[] = [];
    const baseName = domain.split('.')[0]; // primeiro parte do domínio
    
    // Gerar workstations simuladas
    for (let i = 1; i <= 50; i++) {
      workstations.push(`ws-${String(i).padStart(3, '0')}.${domain}`);
    }
    
    // Adicionar algumas workstations com nomes mais realistas
    const commonNames = ['admin', 'dev', 'hr', 'finance', 'it', 'sales'];
    for (const name of commonNames) {
      workstations.push(`${name}-${Math.floor(Math.random() * 10) + 1}.${domain}`);
    }
    
    return workstations;
  }

  /**
   * Agrupa achados por categoria
   */
  private groupFindingsByCategory(findings: any[]): Record<string, number> {
    const categoryCount: Record<string, number> = {};
    
    for (const finding of findings) {
      const category = finding.category || 'other';
      categoryCount[category] = (categoryCount[category] || 0) + 1;
    }
    
    return categoryCount;
  }

  /**
   * Agrupa achados por severidade
   */
  private groupFindingsBySeverity(findings: any[]): Record<string, number> {
    const severityCount: Record<string, number> = {};
    
    for (const finding of findings) {
      const severity = finding.severity || 'unknown';
      severityCount[severity] = (severityCount[severity] || 0) + 1;
    }
    
    return severityCount;
  }

  /**
   * Executa nmap vuln scripts para validação ativa de CVEs
   * Phase 2A: Active CVE detection using nmap --script=vuln
   */
  private async runNmapVulnScripts(host: string, ports: string[], jobId?: string, timeoutMs: number = 3600000): Promise<any[]> {
    try {
      const { spawn } = await import('child_process');
      
      // Construir argumentos do nmap para validação de vulnerabilidades
      const portList = ports.join(',');
      const args = [
        '-Pn',  // Skip ping
        '-sT',  // TCP connect scan (não requer root)
        '-p', portList,  // Portas específicas
        '--script', 'vuln',  // Scripts de vulnerabilidade
        '--script-args', 'vulns.showall',  // Mostrar todos os CVEs
        host
      ];
      
      console.log(`🎯 Executando nmap vuln scripts: nmap ${args.join(' ')}`);
      
      return new Promise((resolve, reject) => {
        const child = spawn('nmap', args);
        
        let stdout = '';
        let stderr = '';
        
        const timeout = setTimeout(() => {
          child.kill('SIGTERM');
          console.log(`⏱️ Nmap vuln scripts timeout após ${timeoutMs/60000}min para ${host}`);
          resolve([]); // Retorna vazio em caso de timeout
        }, timeoutMs);
        
        child.stdout?.on('data', (data) => {
          stdout += data.toString();
        });
        
        child.stderr?.on('data', (data) => {
          stderr += data.toString();
        });
        
        child.on('close', (code) => {
          clearTimeout(timeout);
          
          if (code === 0 || stdout.length > 0) {
            // Parse do output para extrair vulnerabilidades detectadas
            const vulnFindings = this.parseNmapVulnOutput(stdout, host);
            console.log(`✅ Nmap vuln scripts concluído: ${vulnFindings.length} vulnerabilidades encontradas`);
            resolve(vulnFindings);
          } else {
            console.error(`❌ Nmap vuln scripts falhou (code ${code}): ${stderr}`);
            resolve([]); // Retorna vazio em caso de erro
          }
        });
        
        child.on('error', (error) => {
          clearTimeout(timeout);
          console.error(`❌ Erro ao executar nmap vuln scripts:`, error);
          resolve([]); // Retorna vazio em caso de erro
        });
      });
    } catch (error) {
      console.error(`❌ Erro fatal ao executar nmap vuln scripts:`, error);
      return [];
    }
  }

  /**
   * Parse do output do nmap --script=vuln para extrair vulnerabilidades
   */
  private parseNmapVulnOutput(output: string, host: string): any[] {
    const findings: any[] = [];
    const lines = output.split('\n');
    
    let currentPort = '';
    let currentService = '';
    let vulnerabilityBuffer = '';
    let isInVulnBlock = false;
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Detectar linha de porta: "445/tcp open  microsoft-ds"
      const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+(open|filtered)\s+(.+)/);
      if (portMatch) {
        // Processar vulnerabilidade anterior se existir
        if (vulnerabilityBuffer && currentPort) {
          const vuln = this.extractVulnerabilityFromBuffer(vulnerabilityBuffer, host, currentPort, currentService);
          if (vuln) findings.push(vuln);
        }
        
        currentPort = portMatch[1];
        currentService = portMatch[4].trim();
        vulnerabilityBuffer = '';
        isInVulnBlock = false;
        continue;
      }
      
      // Detectar início de bloco de vulnerabilidade
      if (line.includes('|') && (line.includes('CVE-') || line.includes('VULNERABLE') || line.includes('State: VULNERABLE'))) {
        isInVulnBlock = true;
      }
      
      // Acumular linhas do bloco de vulnerabilidade
      if (isInVulnBlock && line.includes('|')) {
        vulnerabilityBuffer += line + '\n';
      }
      
      // Detectar fim do bloco de vulnerabilidade (linha vazia após '|_')
      if (isInVulnBlock && line.match(/^\|_/)) {
        vulnerabilityBuffer += line + '\n';
        
        // Processar vulnerabilidade acumulada
        if (currentPort) {
          const vuln = this.extractVulnerabilityFromBuffer(vulnerabilityBuffer, host, currentPort, currentService);
          if (vuln) findings.push(vuln);
        }
        
        vulnerabilityBuffer = '';
        isInVulnBlock = false;
      }
    }
    
    // Processar última vulnerabilidade se existir
    if (vulnerabilityBuffer && currentPort) {
      const vuln = this.extractVulnerabilityFromBuffer(vulnerabilityBuffer, host, currentPort, currentService);
      if (vuln) findings.push(vuln);
    }
    
    return findings;
  }

  /**
   * Extrai informações de vulnerabilidade de um bloco de output do nmap
   */
  private extractVulnerabilityFromBuffer(buffer: string, host: string, port: string, service: string): any | null {
    // Extrair CVE IDs
    const cveMatches = buffer.match(/CVE-\d{4}-\d{4,7}/g);
    if (!cveMatches || cveMatches.length === 0) {
      return null; // Sem CVE, ignorar
    }
    
    const cveId = cveMatches[0]; // Usar primeiro CVE encontrado
    
    // Extrair título/nome da vulnerabilidade
    let title = '';
    const titleMatch = buffer.match(/\|\s+(.+?):/);
    if (titleMatch) {
      title = titleMatch[1].trim();
    }
    
    // Determinar severidade (padrão: high para CVEs confirmados)
    let severity: 'low' | 'medium' | 'high' | 'critical' = 'high';
    if (buffer.toLowerCase().includes('critical')) {
      severity = 'critical';
    } else if (buffer.toLowerCase().includes('high')) {
      severity = 'high';
    } else if (buffer.toLowerCase().includes('medium')) {
      severity = 'medium';
    } else if (buffer.toLowerCase().includes('low')) {
      severity = 'low';
    }
    
    // Extrair descrição
    const description = buffer
      .replace(/\|/g, '')
      .replace(/\s+/g, ' ')
      .trim()
      .substring(0, 500); // Limitar tamanho
    
    return {
      type: 'nmap_vuln',
      target: host,
      port,
      service,
      cve: cveId,
      name: title || `Vulnerabilidade ${cveId}`,
      severity,
      description: description || `CVE ${cveId} detectado ativamente via nmap vuln scripts`,
      details: buffer.trim(),
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Identifica serviços web (HTTP/HTTPS) dos port results
   * Retorna array de URLs para varredura com Nuclei
   */
  private identifyWebServices(host: string, portResults: any[]): string[] {
    const webUrls: string[] = [];
    const webPorts = new Set(['80', '443', '8080', '8443', '3000', '5000', '8000', '8888']);
    const webServiceNames = ['http', 'https', 'http-alt', 'https-alt', 'http-proxy', 'ssl/http'];
    
    for (const result of portResults) {
      if (result.state !== 'open') continue;
      
      const port = result.port;
      const service = result.service?.toLowerCase() || '';
      
      // Determinar protocolo baseado em porta e service
      let protocol = 'http';
      
      // Verificar por HTTPS
      if (port === '443' || port === '8443' || 
          service.includes('https') || service.includes('ssl')) {
        protocol = 'https';
      }
      
      // Verificar se é serviço web conhecido
      if (webPorts.has(port) || webServiceNames.some(name => service.includes(name))) {
        const url = `${protocol}://${host}:${port}`;
        webUrls.push(url);
        console.log(`🌐 Aplicação web detectada: ${url} (service: ${service || 'unknown'})`);
      }
    }
    
    return webUrls;
  }

  /**
   * Executa varredura Nuclei em URLs web com timeout configurável
   * Phase 2B: Web vulnerability scanning
   */
  private async runNucleiWebScan(urls: string[], jobId?: string, timeoutMs: number = 3600000): Promise<any[]> {
    const findings: any[] = [];
    const { spawn } = await import('child_process');
    
    // Garantir que templates Nuclei estão instalados
    await this.ensureNucleiTemplates();
    
    for (const url of urls) {
      try {
        console.log(`🔍 Executando Nuclei em ${url} (timeout: ${timeoutMs/60000}min)`);
        
        const args = [
          '-u', url,
          '-jsonl',
          '-silent',
          '-duc',
          '-ni',
          '-nc',
          '-nm',
          '-s', 'medium,high,critical',
          '-timeout', '10',
          '-retries', '1',
          '-c', '5',
          '-t', '/tmp/nuclei/nuclei-templates',
        ];
        
        const result = await new Promise<string>((resolve, reject) => {
          const child = spawn('nuclei', args, {
            stdio: ['ignore', 'pipe', 'pipe'],
            env: {
              ...process.env,
              HOME: '/tmp/nuclei',
              NUCLEI_CONFIG_DIR: '/tmp/nuclei/.config',
              XDG_CONFIG_HOME: '/tmp/nuclei/.config',
              XDG_CACHE_HOME: '/tmp/nuclei/.cache',
              NUCLEI_TEMPLATES_DIR: '/tmp/nuclei/nuclei-templates',
            },
          });
          
          let stdout = '';
          let stderr = '';
          
          const timeout = setTimeout(() => {
            child.kill('SIGTERM');
            console.log(`⏱️ Nuclei timeout após ${timeoutMs/60000}min para ${url}`);
            resolve(''); // Retorna vazio em caso de timeout
          }, timeoutMs);
          
          child.stdout?.on('data', (data) => {
            stdout += data.toString();
          });
          
          child.stderr?.on('data', (data) => {
            stderr += data.toString();
          });
          
          child.on('close', (code) => {
            clearTimeout(timeout);
            resolve(stdout);
          });
          
          child.on('error', (error) => {
            clearTimeout(timeout);
            console.error(`❌ Erro ao executar Nuclei:`, error);
            resolve('');
          });
        });
        
        // Parse do output JSON lines
        const urlFindings = this.parseNucleiOutput(result, url);
        findings.push(...urlFindings);
        console.log(`✅ Nuclei concluído para ${url}: ${urlFindings.length} vulnerabilidades`);
        
      } catch (error) {
        console.error(`❌ Erro ao escanear ${url} com Nuclei:`, error);
      }
    }
    
    return findings;
  }
  
  /**
   * Parse do output do Nuclei JSONL
   */
  private parseNucleiOutput(output: string, target: string): any[] {
    const findings: any[] = [];
    
    if (!output || output.trim().length === 0) {
      return findings;
    }
    
    const lines = output.split('\n').filter(line => line.trim());
    
    for (const line of lines) {
      try {
        const finding = JSON.parse(line);
        
        findings.push({
          type: 'vulnerability',
          target,
          name: finding.info?.name || finding.templateID || finding.template,
          severity: this.mapNucleiSeverity(finding.info?.severity),
          template: finding.templateID || finding.template,
          description: finding.info?.description || '',
          evidence: {
            source: 'nuclei',
            templateId: finding.templateID || finding.template,
            url: finding['matched-at'] || finding.matched_at,
            matcher: finding['matcher-name'] || finding.matcher_name,
            info: finding.info,
          },
        });
      } catch (error) {
        // Ignorar linhas que não são JSON válido
      }
    }
    
    return findings;
  }
  
  /**
   * Mapeia severidade do Nuclei para padrão do sistema
   */
  private mapNucleiSeverity(severity?: string): 'low' | 'medium' | 'high' | 'critical' {
    const sev = (severity || 'medium').toLowerCase();
    if (['critical', 'high', 'medium', 'low'].includes(sev)) {
      return sev as 'low' | 'medium' | 'high' | 'critical';
    }
    return 'medium';
  }
  
  /**
   * Garante que templates do Nuclei estão instalados
   */
  private async ensureNucleiTemplates(): Promise<void> {
    const { spawn } = await import('child_process');
    const { promises: fs } = await import('fs');
    
    const templatesDir = '/tmp/nuclei/nuclei-templates';
    
    try {
      const stats = await fs.stat(templatesDir);
      if (stats.isDirectory()) {
        const files = await fs.readdir(templatesDir);
        if (files.length > 0) {
          return; // Templates já existem
        }
      }
    } catch {
      // Diretório não existe
    }
    
    console.log('📥 Baixando templates Nuclei...');
    
    return new Promise((resolve, reject) => {
      const child = spawn('nuclei', ['-update-templates', '-ud', templatesDir], {
        stdio: ['ignore', 'pipe', 'pipe'],
        env: {
          ...process.env,
          HOME: '/tmp/nuclei',
          NUCLEI_CONFIG_DIR: '/tmp/nuclei/.config',
        },
      });
      
      const timeout = setTimeout(() => {
        child.kill('SIGTERM');
        reject(new Error('Template download timeout'));
      }, 120000);
      
      child.on('close', (code) => {
        clearTimeout(timeout);
        if (code === 0 || code === null) {
          console.log('✅ Templates Nuclei baixados');
          resolve();
        } else {
          reject(new Error(`Failed to download templates: code ${code}`));
        }
      });
      
      child.on('error', (error) => {
        clearTimeout(timeout);
        reject(error);
      });
    });
  }

  /**
   * Expande um range CIDR em IPs individuais
   * Ex: 192.168.100.0/24 -> [192.168.100.1, 192.168.100.2, ...]
   */
  private expandCIDR(cidr: string): string[] {
    const ips: string[] = [];
    
    try {
      // Separar IP base e máscara
      const [baseIP, mask] = cidr.split('/');
      const maskBits = parseInt(mask);
      
      if (!baseIP || isNaN(maskBits) || maskBits < 0 || maskBits > 32) {
        console.warn(`CIDR inválido: ${cidr}, usando como IP único`);
        return [cidr];
      }
      
      // Converter IP para número
      const ipParts = baseIP.split('.').map(Number);
      if (ipParts.length !== 4 || ipParts.some(p => isNaN(p) || p < 0 || p > 255)) {
        console.warn(`IP base inválido: ${baseIP}, usando como IP único`);
        return [cidr];
      }
      
      const baseIPNum = (ipParts[0] << 24) + (ipParts[1] << 16) + (ipParts[2] << 8) + ipParts[3];
      
      // Calcular quantidade de IPs no range
      const hostBits = 32 - maskBits;
      const totalHosts = Math.pow(2, hostBits);
      
      // Para /32, retornar apenas o IP
      if (maskBits === 32) {
        return [baseIP];
      }
      
      // Para redes grandes, limitar para evitar consumo excessivo de memória
      const maxIPs = 10000; // Limite máximo de IPs por range
      const actualHosts = Math.min(totalHosts - 2, maxIPs); // -2 para excluir network e broadcast
      
      if (totalHosts > maxIPs + 2) {
        console.warn(`Range ${cidr} muito grande (${totalHosts - 2} IPs), limitando para ${maxIPs} IPs`);
      }
      
      // Gerar IPs (excluindo network address e broadcast address)
      const networkAddress = baseIPNum & ((0xFFFFFFFF << hostBits) >>> 0);
      
      for (let i = 1; i <= actualHosts; i++) {
        const ip = networkAddress + i;
        const a = (ip >>> 24) & 0xFF;
        const b = (ip >>> 16) & 0xFF;
        const c = (ip >>> 8) & 0xFF;
        const d = ip & 0xFF;
        ips.push(`${a}.${b}.${c}.${d}`);
      }
      
    } catch (error) {
      console.error(`Erro ao expandir CIDR ${cidr}:`, error);
      return [cidr]; // Usar como IP único em caso de erro
    }
    
    return ips;
  }
}

export const journeyExecutor = new JourneyExecutorService();
