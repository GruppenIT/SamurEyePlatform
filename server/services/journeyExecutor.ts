import { storage } from '../storage';
import { insertEdrDeployment } from '../storage/edrDeployments';
import { threatEngine } from './threatEngine';
import { encryptionService } from './encryption';
import { networkScanner } from './scanners/networkScanner';
import { vulnScanner } from './scanners/vulnScanner';
import { ADScanner } from './scanners/adScanner';
import { EDRAVScanner } from './scanners/edrAvScanner';
import { jobQueue } from './jobQueue';
import { hostService } from './hostService';
import { processTracker } from './processTracker';
import { cveService } from './cveService';
import { hostEnricher } from './hostEnricher';
import { WMICollector } from './collectors/wmiCollector';
import { SSHCollector } from './collectors/sshCollector';
import { type Journey, type Job, assets as assetsTable } from '@shared/schema';
import { createLogger } from '../lib/logger';
import { buildWebAppUrl, detectWebScheme, normalizeTarget } from './journeys/urls';
import { preflightNuclei } from './journeys/nucleiPreflight';
import { and, eq } from 'drizzle-orm';
import { db } from '../db';

const log = createLogger('journey');
const adScanner = new ADScanner();

// Max size for stdout/stderr stored in job_results artifacts
const MAX_ARTIFACT_STDOUT = 2_000;

/** Strip verbose fields from findings before storing in artifacts to prevent DB bloat */
function sanitizeFindingsForArtifacts(findings: any[]): any[] {
  return findings.map(f => ({
    ...f,
    evidence: f.evidence ? {
      ...f.evidence,
      stdout: f.evidence.stdout ? f.evidence.stdout.substring(0, MAX_ARTIFACT_STDOUT) : undefined,
      stderr: f.evidence.stderr ? f.evidence.stderr.substring(0, 500) : undefined,
      command: undefined,  // Commands already stored in ad_security_test_results
      objectData: f.evidence.objectData
        ? { _summary: `${Object.keys(f.evidence.objectData).length} fields` }
        : undefined,
    } : undefined,
  }));
}

// Register host enrichment collectors
hostEnricher.registerCollector(new WMICollector());
hostEnricher.registerCollector(new SSHCollector());

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
      log.info(`🏷️  Expandindo TAGs selecionadas: ${journey.selectedTags.join(', ')}`);
      const assets = await storage.getAssetsByTags(journey.selectedTags);
      const assetIds = assets.map(a => a.id);
      log.info(`✅ ${assetIds.length} alvos encontrados com as TAGs selecionadas`);
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
      case 'web_application':
        await this.executeWebApplication(journey, jobId, onProgress);
        break;
      default:
        throw new Error(`Tipo de jornada não suportado: ${journey.type}`);
    }

    // Check if job was cancelled before threat analysis
    if (this.isJobCancelled(jobId)) {
      log.info(`🚫 Job ${jobId} cancelado, parando antes de análise de ameaças`);
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
   * Executes Attack Surface journey - Infrastructure discovery
   * 
   * Phase 1: Discovery (port scanning with nmap)
   * Phase 2: Active Vulnerability Validation (nmap vuln scripts)
   * Phase 3: Host discovery and web application asset creation
   */
  private async executeAttackSurface(
    journey: Journey,
    jobId: string,
    onProgress: ProgressCallback
  ): Promise<void> {
    const params = journey.params;
    const assetIds = await this.resolveAssetIds(journey);
    const vulnScriptTimeoutMinutes = params.vulnScriptTimeout || 60;
    const vulnScriptTimeoutMs = vulnScriptTimeoutMinutes * 60 * 1000;

    if (assetIds.length === 0) {
      throw new Error('Nenhum ativo selecionado para varredura');
    }

    log.info(`🚀 Iniciando Attack Surface Journey - Descoberta de Infraestrutura`);
    log.info(`⏱️  Timeout Fase 3 (nmap vuln): ${vulnScriptTimeoutMinutes} minutos`);

    onProgress({ status: 'running', progress: 5, currentTask: 'Carregando ativos' });

    // Get assets
    const assets = [];
    for (const assetId of assetIds) {
      const asset = await storage.getAsset(assetId);
      if (asset) assets.push(asset);
    }

    const findings: any[] = [];
    let currentAsset = 0;

    // Progress distribution: 5-90% split evenly across assets
    // Within each asset slice:
    //   Phase 1A (Host Discovery): 0-10%
    //   Phase 1B (Port Scan):     10-35%
    //   Phase 2 (Enrichment):     35-45%
    //   Phase 3A (CVE Lookup):    45-55%
    //   Phase 3B (Nmap Vuln):     55-75%
    //   Phase 3C (Nuclei Web):    75-100%
    const SCAN_START = 5;
    const SCAN_END = 90;
    const assetSlice = (SCAN_END - SCAN_START) / assets.length;

    for (const asset of assets) {
      // Check if job was cancelled
      if (this.isJobCancelled(jobId)) {
        log.info(`🚫 Job ${jobId} cancelado, parando execução no asset ${asset.value}`);
        throw new Error('Job cancelado pelo usuário');
      }

      const assetBase = SCAN_START + currentAsset * assetSlice;
      currentAsset++;

      try {
        // ==================== PHASE 1A: HOST DISCOVERY ====================
        // Discover alive hosts first and register them immediately in the database.
        // This ensures hosts exist before any port scanning or vulnerability analysis.
        onProgress({
          status: 'running',
          progress: Math.round(assetBase),
          currentTask: `Fase 1A: Descobrindo hosts ativos em ${asset.value} (${currentAsset}/${assets.length})`
        });

        log.info(`📡 FASE 1A: Descoberta de hosts ativos em ${asset.value}`);

        // Determine target IPs for this asset
        let aliveHosts: { ip: string; hostname?: string }[];

        if (asset.type === 'range') {
          // CIDR range: use nmap ping sweep to discover alive hosts
          aliveHosts = await networkScanner.discoverAliveHosts(asset.value, jobId);
        } else {
          // Single host: treat as alive directly
          aliveHosts = [{ ip: asset.value }];
        }

        log.info(`✅ FASE 1A: ${aliveHosts.length} hosts ativos descobertos em ${asset.value}`);

        // Register discovered hosts immediately in the database
        // This creates hosts early so they can be linked to threats later
        const registeredHostMap = new Map<string, string>(); // ip -> hostId
        for (const aliveHost of aliveHosts) {
          if (this.isJobCancelled(jobId)) {
            throw new Error('Job cancelado pelo usuário');
          }

          try {
            const hostData: any = {
              name: aliveHost.hostname || `host-${aliveHost.ip.replace(/\./g, '-')}`,
              description: `Host descoberto via ping sweep (Job ID: ${jobId?.substring(0, 8) || 'unknown'})`,
              type: 'other',
              family: 'other',
              ips: [aliveHost.ip],
              aliases: aliveHost.hostname ? [aliveHost.hostname.toLowerCase()] : [],
            };
            const host = await storage.upsertHost(hostData);
            registeredHostMap.set(aliveHost.ip, host.id);
            log.info(`🏠 FASE 1A: Host registrado: ${host.name} (${aliveHost.ip}) - ID: ${host.id}`);
          } catch (error) {
            log.error(`❌ FASE 1A: Erro ao registrar host ${aliveHost.ip}:`, error);
          }
        }

        log.info(`🏠 FASE 1A: ${registeredHostMap.size} hosts cadastrados no inventário`);

        // ==================== PHASE 1B: PORT/SERVICE SCAN ====================
        // Scan ports and services on each discovered host, then update host info
        onProgress({
          status: 'running',
          progress: Math.round(assetBase + assetSlice * 0.10),
          currentTask: `Fase 1B: Escaneando serviços em ${aliveHosts.length} hosts de ${asset.value}`
        });

        log.info(`🔍 FASE 1B: Escaneando serviços em ${aliveHosts.length} hosts`);

        let portResults: any[];
        if (asset.type === 'range') {
          // For ranges, scan the full CIDR via nmap (nmap handles alive hosts internally)
          portResults = await networkScanner.scanCidrRange(asset.value, params.nmapProfile, jobId);
        } else {
          portResults = await networkScanner.scanPorts(asset.value, undefined, params.nmapProfile, jobId);
        }

        findings.push(...portResults);
        log.info(`✅ FASE 1B: ${portResults.length} portas descobertas`);

        // Update hosts with service/OS information from port scan results
        // Group port results by IP to update each host
        const hostPortGroups = new Map<string, any[]>();
        for (const result of portResults) {
          const hostIp = result.ip || result.target || asset.value;
          if (!hostPortGroups.has(hostIp)) {
            hostPortGroups.set(hostIp, []);
          }
          hostPortGroups.get(hostIp)!.push(result);
        }

        // Update each host with discovered services and OS info
        for (const [hostIp, hostFindings] of Array.from(hostPortGroups.entries())) {
          try {
            const updatedHosts = await hostService.discoverHostsFromFindings(hostFindings, jobId);
            if (updatedHosts.length > 0) {
              // Update our map with the (potentially new/merged) host ID
              registeredHostMap.set(hostIp, updatedHosts[0].id);
              log.info(`🔄 FASE 1B: Host ${hostIp} atualizado: ${updatedHosts[0].name} (type: ${updatedHosts[0].type}, family: ${updatedHosts[0].family})`);
            }
          } catch (error) {
            log.error(`❌ FASE 1B: Erro ao atualizar host ${hostIp}:`, error);
          }
        }

        // ==================== PHASE 2: HOST ENRICHMENT (OPTIONAL) ====================
        // Try to enrich discovered hosts using credentials (WMI/SSH/SNMP)
        const journeyCredentials = await storage.getJourneyCredentials(journey.id);

        if (journeyCredentials.length > 0) {
          onProgress({
            status: 'running',
            progress: Math.round(assetBase + assetSlice * 0.35),
            currentTask: `Fase 2: Enriquecendo ${registeredHostMap.size} hosts com credenciais`
          });

          log.info(`🔑 FASE 2: Enriquecimento de ${registeredHostMap.size} hosts com ${journeyCredentials.length} credenciais`);

          for (const [hostIp, hostId] of Array.from(registeredHostMap.entries())) {
            if (this.isJobCancelled(jobId)) {
              throw new Error('Job cancelado pelo usuário');
            }

            try {
              log.info(`🔍 FASE 2: Tentando enriquecer host ${hostIp} (ID: ${hostId})`);

              const enrichmentResult = await hostEnricher.enrichHost(
                hostId,
                hostIp,
                jobId,
                journeyCredentials
              );

              // Persist enrichments to database
              for (const enrichment of enrichmentResult.enrichments) {
                await storage.createHostEnrichment(enrichment);
              }

              log.info(`✅ FASE 2: Host ${hostIp} enriquecido - ${enrichmentResult.successCount} sucessos, ${enrichmentResult.failureCount} falhas`);

              if (enrichmentResult.successCount > 0) {
                for (const e of enrichmentResult.enrichments) {
                  if (e.success) {
                    log.info(`   ✓ ${e.protocol}: OS=${e.osVersion || 'N/A'}, Apps=${e.installedApps?.length || 0}, Patches=${e.patches?.length || 0}`);
                  }
                }
              }
            } catch (error) {
              log.error(`❌ FASE 2: Erro ao enriquecer host ${hostIp}:`, error);
            }
          }

          log.info(`✅ FASE 2: Enriquecimento concluído para ${registeredHostMap.size} hosts`);
        } else {
          log.info(`⏭️  FASE 2: Nenhuma credencial vinculada - pulando enriquecimento`);
        }

        // ==================== PHASE 3: VULNERABILITY DETECTION (OPTIONAL) ====================
        const enableCveDetection = journey.enableCveDetection !== false;

        if (enableCveDetection) {
          // ==================== PHASE 3A: CVE LOOKUP FROM NVD ====================
          onProgress({
            status: 'running',
            progress: Math.round(assetBase + assetSlice * 0.45),
            currentTask: `Fase 3A: Buscando CVEs conhecidos para ${asset.value}`
          });

          log.info(`🔍 FASE 3A: Buscando CVEs conhecidos na base NVD`);
          const cveFindings = await this.searchKnownCVEs(portResults, jobId);
          findings.push(...cveFindings);
          log.info(`✅ FASE 3A: ${cveFindings.length} CVEs encontrados na base NVD`);

          // ==================== PHASE 3B: ACTIVE VALIDATION ====================
          const hostPortMap = new Map<string, { ports: string[], portResults: any[] }>();

          for (const result of portResults) {
            if (result.state === 'open') {
              const target = result.target || asset.value;
              const existing = hostPortMap.get(target) || { ports: [], portResults: [] };
              const cleanPort = result.port.toString().replace(/\/(tcp|udp)$/i, '');
              existing.ports.push(cleanPort);
              existing.portResults.push(result);
              hostPortMap.set(target, existing);
            }
          }

          for (const [host, data] of Array.from(hostPortMap.entries())) {
            if (this.isJobCancelled(jobId)) {
              throw new Error('Job cancelado pelo usuário');
            }

            if (data.ports.length === 0) continue;

            onProgress({
              status: 'running',
              progress: Math.round(assetBase + assetSlice * 0.55),
              currentTask: `Fase 3B: Validando vulnerabilidades ativamente em ${host}`
            });

            log.info(`🎯 FASE 3B: Executando nmap vuln scripts em ${host}`);
            const nmapVulnResults = await this.runNmapVulnScripts(host, data.ports, jobId, vulnScriptTimeoutMs);
            findings.push(...nmapVulnResults);
            log.info(`✅ FASE 3B: ${nmapVulnResults.length} CVEs validados ativamente via nmap`);
          }
        } else {
          log.info(`⏭️  FASE 3: Detecção de CVEs desabilitada - pulando Fases 3A e 3B`);
        }

        // Phase 3C (Nuclei web scan) was removed — attack_surface is now discovery-only.
        // Web application assets are auto-created in Phase 4 and must be scanned via a
        // dedicated web_application journey. `params.webScanEnabled` from legacy journeys
        // is silently ignored.
        if (params.webScanEnabled === true) {
          log.info(`ℹ️  webScanEnabled ignorado: use jornada web_application para avaliar os web apps descobertos`);
        }

      } catch (error) {
        log.error(`❌ Erro ao escanear ${asset.value}:`, error);

        const errorMessage = error instanceof Error ? error.message : String(error);
        findings.push({
          type: 'error',
          target: asset.value,
          message: `Erro durante escaneamento: ${errorMessage}`,
          timestamp: new Date().toISOString(),
        });
      }
    }

    // ==================== PHASE 4: FINALIZE & WEB APP ASSET CREATION ====================
    onProgress({ status: 'running', progress: 90, currentTask: 'Fase 4: Finalizando e criando ativos web' });

    // Final pass: ensure all hosts from findings are registered (catches any missed during scan)
    try {
      const finalHosts = await hostService.discoverHostsFromFindings(findings, jobId);
      log.info(`🏠 FASE 4: ${finalHosts.length} hosts verificados/atualizados no inventário`);
    } catch (error) {
      log.error('❌ Erro ao verificar hosts:', error);
    }

    // Auto-discover and create web application assets from HTTP/HTTPS services
    const createdWebApps = await this.createWebApplicationAssets(findings, journey.createdBy, jobId);
    log.info(`🌐 FASE 4: ${createdWebApps.length} aplicações web criadas como ativos`);

    // Store results
    onProgress({ status: 'running', progress: 95, currentTask: 'Salvando resultados' });
    const webScanWasEnabled = params.webScanEnabled === true;
    await storage.createJobResult({
      jobId,
      stdout: `Varredura concluída. ${findings.length} achados encontrados. ${createdWebApps.length} aplicações web descobertas.${webScanWasEnabled ? ' Nuclei habilitado.' : ''}`,
      stderr: '',
      artifacts: {
        findings,
        summary: {
          totalAssets: assets.length,
          totalFindings: findings.length,
          webApplicationsDiscovered: createdWebApps.length,
          webScanEnabled: webScanWasEnabled,
        },
      },
    });

    log.info(`✅ Attack Surface concluído: ${findings.length} findings, ${createdWebApps.length} web apps criadas`);
  }

  /**
   * Executes Web Application journey - OWASP Top 10 vulnerability scanning
   * 
   * Uses Nuclei to scan previously discovered web applications
   */
  private async executeWebApplication(
    journey: Journey, 
    jobId: string, 
    onProgress: ProgressCallback
  ): Promise<void> {
    const params = journey.params;
    const assetIds = params.assetIds || [];
    const processTimeoutMinutes = params.processTimeout || 60; // Default 60 minutos
    const processTimeoutMs = processTimeoutMinutes * 60 * 1000;
    
    if (assetIds.length === 0) {
      throw new Error('Nenhuma aplicação web selecionada para varredura');
    }

    log.info(`🌐 Iniciando Web Application Journey - Análise OWASP Top 10`);
    log.info(`⏱️  Timeout por processo: ${processTimeoutMinutes} minutos`);

    onProgress({ status: 'running', progress: 5, currentTask: 'Carregando aplicações web' });

    // Get web application assets
    const webApps = [];
    for (const assetId of assetIds) {
      const asset = await storage.getAsset(assetId);
      if (asset) {
        // Validate asset type
        if (asset.type !== 'web_application') {
          log.warn(`⚠️  Asset ${asset.value} não é do tipo web_application, ignorando`);
          continue;
        }
        webApps.push(asset);
      }
    }

    if (webApps.length === 0) {
      throw new Error('Nenhuma aplicação web válida encontrada para varredura');
    }

    log.info(`🎯 ${webApps.length} aplicações web serão analisadas`);

    const findings = [];
    let currentApp = 0;

    for (const app of webApps) {
      // Check if job was cancelled
      if (this.isJobCancelled(jobId)) {
        log.info(`🚫 Job ${jobId} cancelado, parando execução em ${app.value}`);
        throw new Error('Job cancelado pelo usuário');
      }

      // Distribute 5-90% evenly across web apps
      const appProgress = Math.round(5 + (currentApp / webApps.length) * 85);
      currentApp++;

      onProgress({
        status: 'running',
        progress: appProgress,
        currentTask: `Analisando ${app.value} (${currentApp}/${webApps.length})`
      });

      try {
        log.info(`🔍 Executando Nuclei em ${app.value}`);
        
        const appFindings = await this.runNucleiWebScan([app.value], jobId, processTimeoutMs);
        findings.push(...appFindings);
        
        log.info(`✅ ${appFindings.length} vulnerabilidades encontradas em ${app.value}`);
      } catch (error) {
        log.error(`❌ Erro ao analisar ${app.value}:`, error);
        
        const errorMessage = error instanceof Error ? error.message : String(error);
        findings.push({
          type: 'error',
          target: app.value,
          message: `Erro durante análise: ${errorMessage}`,
          timestamp: new Date().toISOString(),
        });
      }
    }

    // Store results
    await storage.createJobResult({
      jobId,
      stdout: `Análise web concluída. ${findings.length} vulnerabilidades encontradas.`,
      stderr: '',
      artifacts: {
        findings,
        summary: {
          totalWebApps: webApps.length,
          totalVulnerabilities: findings.length,
        },
      },
    });
    
    log.info(`✅ Web Application Journey concluída: ${findings.length} vulnerabilidades total`);
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
        log.info(`🏠 AD Hygiene: Host de domínio criado: ${domainHost.name}`);
      } catch (error) {
        log.error('❌ Erro ao criar host de domínio:', error);
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
          log.info(`✅ Salvos ${testResults.length} resultados de testes AD Security`);
        } catch (error) {
          log.error('❌ Erro ao salvar resultados dos testes:', error);
        }
      }

      onProgress({ status: 'running', progress: 80, currentTask: 'Processando resultados' });

      // Store results (sanitize findings to avoid duplicating large evidence data)
      await storage.createJobResult({
        jobId,
        stdout: `Análise AD concluída para domínio ${domain}. ${findings.length} achados identificados, ${testResults.length} testes executados.`,
        stderr: '',
        artifacts: {
          findings: sanitizeFindingsForArtifacts(findings),
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
      log.error('Erro durante análise AD:', error);
      
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
        log.info('🔍 Modo AD Based: Descobrindo workstations via PowerShell/WinRM...');
        
        if (credential.type !== 'ad' && credential.type !== 'wmi' && credential.type !== 'omi') {
          throw new Error('Para jornada AD Based é necessário usar credencial do tipo WMI (Windows)');
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

        log.info(`✅ Descobertas ${workstationTargets.length} workstations via AD`);

      } else if (edrAvType === 'network_based') {
        // Modo Network Based: Usar ativos específicos
        log.info('🎯 Modo Network Based: Usando ativos específicos...');
        
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
                log.info(`🌐 Expandindo range CIDR: ${asset.value}`);
                const expandedIPs = this.expandCIDR(asset.value);
                log.info(`📊 Range expandido para ${expandedIPs.length} IPs`);
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

        log.info(`Usando ${workstationTargets.length} targets específicos`);
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
      
      log.info({ domain: effectiveDomain || 'LOCAL' }, 'using credentials for EDR/AV test');
      
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

      // Phase 5 (PARS-10): Insert per-host EDR deployment metadata into edr_deployments table
      // This runs AFTER createJobResult so scan results are persisted regardless of insert outcome.
      // Host resolution uses hostService.findHostsByTarget() which searches hosts table by name/IP.
      // Hosts for EDR targets are registered by the threat engine during threat processing.
      for (const finding of findings) {
        try {
          const hostname = finding.hostname || finding.target;
          if (!hostname) continue;

          // Resolve hostId — host may or may not exist yet depending on threat engine timing
          const hosts = await hostService.findHostsByTarget(hostname);
          if (hosts.length === 0) {
            log.debug({ host: hostname }, 'edr_deployments: host not yet registered, skipping insert');
            continue;
          }

          await insertEdrDeployment({
            hostId: hosts[0].id,
            journeyId: journey.id,
            jobId,
            deploymentTimestamp: finding.deploymentTimestamp ? new Date(finding.deploymentTimestamp) : null,
            detectionTimestamp: finding.detectionTimestamp ? new Date(finding.detectionTimestamp) : null,
            deploymentMethod: finding.deploymentMethod || 'smb',
            detected: finding.detected ?? null,
            testDuration: finding.testDuration || 0,
          });
        } catch (insertErr) {
          log.warn({ host: finding.hostname, err: insertErr }, 'edr_deployments insert failed — scan result unaffected');
        }
      }

    } catch (error) {
      log.error('Erro durante teste EDR/AV:', error);
      
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
   * Busca CVEs conhecidos na base NVD para serviços detectados
   * Phase 2A: CVE lookup from NIST NVD database
   */
  private async searchKnownCVEs(portResults: any[], jobId?: string): Promise<any[]> {
    const cveFindings: any[] = [];
    
    // Extrair OS info do primeiro resultado (todos os portResults do mesmo host têm o mesmo OS)
    const osInfo = portResults.length > 0 ? portResults[0].osInfo : undefined;
    if (osInfo) {
      log.info(`💻 OS detectado para filtragem de CVEs: ${osInfo}`);
    }
    
    // Agrupar por serviço único para evitar buscas duplicadas
    const uniqueServices = new Map<string, any>();
    
    for (const result of portResults) {
      if (result.state !== 'open' || !result.service) continue;
      
      const service = result.service.toLowerCase();
      const version = result.version || '';
      const key = `${service}:${version}`;
      
      if (!uniqueServices.has(key)) {
        uniqueServices.set(key, {
          service,
          version,
          osInfo: result.osInfo, // Incluir osInfo específico do resultado
          versionAccuracy: result.versionAccuracy || 'low',
          targets: [result.target || result.ip],
          ports: [result.port],
        });
      } else {
        const existing = uniqueServices.get(key)!;
        existing.targets.push(result.target || result.ip);
        existing.ports.push(result.port);
      }
    }
    
    log.info(`🔍 Buscando CVEs para ${uniqueServices.size} serviços únicos...`);
    
    // Buscar CVEs para cada serviço único
    const serviceEntries = Array.from(uniqueServices.entries());
    for (const [key, data] of serviceEntries) {
      // Verificar se job foi cancelado
      if (jobId && this.isJobCancelled(jobId)) {
        log.info(`🚫 Job ${jobId} cancelado durante busca de CVEs`);
        break;
      }
      
      try {
        log.info(`🔎 Buscando CVEs para: ${data.service} ${data.version || '(sem versão)'} (OS: ${data.osInfo || 'N/A'}, precisão: ${data.versionAccuracy})`);
        
        // Para cada target, buscar CVEs considerando dados enriquecidos
        const targetCVEs = new Map<string, any[]>();
        
        for (const target of data.targets) {
          // Try to get hostId for this target/IP
          let hostId: string | undefined;
          try {
            const { hostService } = require('./hostService');
            const hosts = await hostService.findHostsByTarget(target);
            if (hosts && hosts.length > 0) {
              hostId = hosts[0].id;
              log.info(`🔐 Host encontrado para ${target}: ${hostId} - enriquecimento disponível`);
            }
          } catch (error) {
            log.warn(`⚠️ Erro ao buscar host para ${target}:`, error);
          }
          
          // Buscar CVEs (com enrichment se hostId disponível)
          const cves = await cveService.searchCVEs(data.service, data.version, data.osInfo, hostId);
          targetCVEs.set(target, cves);
        }
        
        // Aggregate total unique CVEs found
        const allCVEs = new Set<string>();
        const targetCVEValues = Array.from(targetCVEs.values());
        for (const cves of targetCVEValues) {
          for (const cve of cves) {
            allCVEs.add(cve.cveId);
          }
        }
        
        if (allCVEs.size > 0) {
          log.info(`✅ Encontrados ${allCVEs.size} CVEs únicos aplicáveis para ${data.service} (filtrados por versão/OS/enrichment)`);
          
          // Criar findings para cada CVE encontrado por target
          for (const target of data.targets) {
            const cves = targetCVEs.get(target) || [];
            for (const cve of cves) {
              cveFindings.push({
                type: 'nvd_cve',
                target,
                port: data.ports[data.targets.indexOf(target)],
                service: data.service,
                version: data.version || 'unknown',
                osInfo: data.osInfo,
                cve: cve.cveId,
                name: `${cve.cveId} - ${data.service}`,
                severity: cve.severity,
                cvssScore: cve.cvssScore,
                description: cve.description,
                remediation: cve.remediation,
                publishedDate: cve.publishedDate,
                confidence: cve.confidence || 'medium', // Incluir nível de confiança
                timestamp: new Date().toISOString(),
              });
            }
          }
        } else {
          log.info(`ℹ️  Nenhum CVE aplicável encontrado para ${data.service} ${data.version || ''} (filtrados por versão/OS/enrichment)`);
        }
      } catch (error) {
        log.error(`❌ Erro ao buscar CVEs para ${data.service}:`, error);
      }
    }
    
    return cveFindings;
  }

  /**
   * Executa nmap vuln scripts para validação ativa de CVEs
   * Phase 2B: Active CVE detection using nmap --script=vuln
   * Delegates to networkScanner.scanVulns() — no longer spawns nmap directly.
   */
  private async runNmapVulnScripts(host: string, ports: string[], jobId?: string, timeoutMs: number = 3600000): Promise<any[]> {
    try {
      log.info(`🎯 Delegando nmap vuln scan para networkScanner.scanVulns(${host})`);
      return await networkScanner.scanVulns(host, ports, jobId);
    } catch (error) {
      log.error(`❌ Erro ao executar nmap vuln scripts via networkScanner:`, error);
      return [];
    }
  }

  /**
   * Creates web_application assets from discovered HTTP/HTTPS services
   * Returns array of created assets
   */
  private async createWebApplicationAssets(findings: any[], createdBy: string, jobId: string): Promise<any[]> {
    const webApps: any[] = [];
    const createdUrls = new Set<string>(); // Within-job dedup short-circuit

    // Load host assets once to resolve parent links efficiently
    const allAssets = await storage.getAssets();
    const hostAssets = allAssets.filter((a: any) => a.type === 'host');
    const hostByValue = new Map<string, any>();
    for (const h of hostAssets) {
      hostByValue.set(h.value, h);
    }

    for (const finding of findings) {
      if (finding.type !== 'port' || finding.state !== 'open') continue;

      const host = finding.target || finding.ip;
      if (!host) continue;

      const port = finding.port?.toString().replace(/\/(tcp|udp)$/i, '') ?? '';
      const service = finding.service?.toLowerCase() ?? '';

      const scheme = detectWebScheme(port, service);
      if (!scheme) continue;

      const url = buildWebAppUrl(host, port, scheme);

      if (createdUrls.has(url)) continue;
      createdUrls.add(url);

      // Resolve parent host asset (by exact value match on IP or hostname)
      const parentHost = hostByValue.get(host) ?? hostByValue.get(finding.ip) ?? null;
      const parentAssetId = parentHost?.id ?? null;

      const signals = {
        source: 'attack_surface_job',
        jobId,
        port,
        service,
        detectionSignals: ['nmap_port_service'],
      };

      try {
        // Cross-job idempotency: does a web_application with this value + parent already exist?
        const whereClause = parentAssetId
          ? and(
              eq(assetsTable.type, 'web_application' as any),
              eq(assetsTable.value, url),
              eq(assetsTable.parentAssetId, parentAssetId),
            )
          : and(
              eq(assetsTable.type, 'web_application' as any),
              eq(assetsTable.value, url),
            );

        const [existing] = await db.select().from(assetsTable).where(whereClause).limit(1);

        if (existing) {
          webApps.push(existing);
          log.info(`🌐 Aplicação web já catalogada: ${url} (parent=${parentHost?.value ?? 'none'})`);
          continue;
        }

        const asset = await storage.createAsset(
          {
            type: 'web_application',
            value: url,
            tags: ['auto-discovered', `job:${jobId.substring(0, 8)}`],
            parentAssetId,
          } as any,
          createdBy,
        );
        webApps.push(asset);
        log.info(`🌐 Aplicação web criada como ativo: ${url} (parent=${parentHost?.value ?? 'none'}, service=${service || 'unknown'})`);
      } catch (error) {
        log.error(`❌ Erro ao criar/linkar ativo web_application para ${url}:`, error);
      }

      // Note: promotionMetadata will be wired in a later task when that column is added
      // (Problem 3 plan noted it as optional — omitting here to keep the change minimal).
      void signals;
    }

    return webApps;
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
        log.info(`🌐 Aplicação web detectada: ${url} (service: ${service || 'unknown'})`);
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

    // Pre-flight: verify nuclei binary and templates are available
    const preflight = await preflightNuclei(log);
    if (!preflight.ok) {
      log.warn(`⚠️ Nuclei preflight failed (${preflight.reason}) — skipping scan of ${urls.length} URLs, returning 0 findings`);
      return [];
    }

    for (const url of urls) {
      try {
        // Normalize and validate URL before spawning
        const normalized = normalizeTarget(url);
        if (!normalized) {
          log.warn(`⚠️ URL inválida para Nuclei: ${JSON.stringify(url)} — pulando`);
          continue;
        }

        const startedAt = Date.now();
        log.info(`🔍 Executando Nuclei em ${normalized} (timeout: ${timeoutMs/60000}min)`);

        const args = [
          '-u', normalized,
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

        const result = await new Promise<{ stdout: string; stderr: string; exitCode: number | null }>((resolve) => {
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
            // Force kill after 5s if SIGTERM doesn't work
            setTimeout(() => {
              if (!child.killed) {
                child.kill('SIGKILL');
              }
            }, 5000);
            log.info(`⏱️ Nuclei timeout após ${timeoutMs/60000}min para ${normalized}`);
            resolve({ stdout: '', stderr: '<timeout>', exitCode: null });
          }, timeoutMs);

          child.stdout?.on('data', (data) => {
            stdout += data.toString();
          });

          child.stderr?.on('data', (data) => {
            stderr += data.toString();
          });

          child.on('close', (code) => {
            clearTimeout(timeout);
            resolve({ stdout, stderr, exitCode: code });
          });

          child.on('error', (error) => {
            clearTimeout(timeout);
            log.error(`❌ Erro ao executar Nuclei:`, error);
            resolve({ stdout: '', stderr: String(error), exitCode: null });
          });
        });

        // Parse do output JSON lines — delegate to vulnScanner.parseNuclei (PARS-05, PARS-06)
        const urlFindings = vulnScanner.parseNuclei(result.stdout);
        findings.push(...urlFindings);

        log.info({
          jobId,
          tool: 'nuclei',
          target: normalized,
          exitCode: result.exitCode,
          durationMs: Date.now() - startedAt,
          stdoutBytes: result.stdout.length,
          stderrTail: result.stderr.slice(-500),
          findingsCount: urlFindings.length,
        }, `nuclei scan complete`);

      } catch (error) {
        log.error(`❌ Erro ao escanear ${url} com Nuclei:`, error);
      }
    }

    return findings;
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
        log.warn(`CIDR inválido: ${cidr}, usando como IP único`);
        return [cidr];
      }
      
      // Converter IP para número
      const ipParts = baseIP.split('.').map(Number);
      if (ipParts.length !== 4 || ipParts.some(p => isNaN(p) || p < 0 || p > 255)) {
        log.warn(`IP base inválido: ${baseIP}, usando como IP único`);
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
        log.warn(`Range ${cidr} muito grande (${totalHosts - 2} IPs), limitando para ${maxIPs} IPs`);
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
      log.error(`Erro ao expandir CIDR ${cidr}:`, error);
      return [cidr]; // Usar como IP único em caso de erro
    }
    
    return ips;
  }
}

export const journeyExecutor = new JourneyExecutorService();
