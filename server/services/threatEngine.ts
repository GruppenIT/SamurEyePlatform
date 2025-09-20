import { storage } from '../storage';
import { hostService } from './hostService';
import { type InsertThreat, type Threat } from '@shared/schema';

export interface ThreatRule {
  id: string;
  name: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  matcher: (finding: any) => boolean;
  createThreat: (finding: any, assetId?: string, jobId?: string) => InsertThreat;
}

class ThreatEngineService {
  private rules: ThreatRule[] = [];

  constructor() {
    this.initializeRules();
  }

  /**
   * Initialize threat detection rules
   */
  private initializeRules(): void {
    this.rules = [
      // Attack Surface Rules
      {
        id: 'critical-cve',
        name: 'CVE Crítico Detectado',
        description: 'Vulnerabilidade crítica identificada por nuclei',
        severity: 'critical',
        matcher: (finding) => finding.severity === 'critical' && finding.cve,
        createThreat: (finding, assetId, jobId) => ({
          title: `${finding.cve} detectado em servidor`,
          description: `Vulnerabilidade crítica: ${finding.description}`,
          severity: 'critical',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            cve: finding.cve,
            cvss: finding.cvss,
            service: finding.service,
            port: finding.port,
            details: finding.details,
          },
        }),
      },
      {
        id: 'open-admin-ports',
        name: 'Portas Administrativas Expostas',
        description: 'Portas de administração abertas na internet',
        severity: 'high',
        matcher: (finding) => 
          finding.type === 'port' && 
          ['22', '3389', '5985', '5986'].includes(finding.port) &&
          finding.state === 'open',
        createThreat: (finding, assetId, jobId) => ({
          title: `Porta administrativa ${finding.port} exposta`,
          description: `Porta ${finding.port} (${finding.service}) está aberta e acessível no host ${finding.target}`,
          severity: 'high',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            host: finding.target,
            ip: finding.ip,
            port: finding.port,
            service: finding.service,
            state: finding.state,
            version: finding.version,
            banner: finding.banner,
            osInfo: finding.osInfo,
          },
        }),
      },
      {
        id: 'web-ports-exposed',
        name: 'Portas Web Expostas',
        description: 'Portas de serviços web abertas na internet',
        severity: 'medium',
        matcher: (finding) => 
          finding.type === 'port' && 
          ['80', '443', '8080', '8443'].includes(finding.port) &&
          finding.state === 'open',
        createThreat: (finding, assetId, jobId) => ({
          title: `Porta web ${finding.port} exposta`,
          description: `Serviço web na porta ${finding.port} (${finding.service}) está acessível no host ${finding.target}`,
          severity: 'medium',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            host: finding.target,
            ip: finding.ip,
            port: finding.port,
            service: finding.service,
            state: finding.state,
            version: finding.version,
            banner: finding.banner,
            osInfo: finding.osInfo,
          },
        }),
      },
      {
        id: 'smb-ports-exposed',
        name: 'Portas SMB/NetBIOS Expostas',
        description: 'Portas de compartilhamento SMB abertas na internet',
        severity: 'high',
        matcher: (finding) => 
          finding.type === 'port' && 
          ['139', '445'].includes(finding.port) &&
          finding.state === 'open',
        createThreat: (finding, assetId, jobId) => ({
          title: `Porta SMB ${finding.port} exposta`,
          description: `Serviço de compartilhamento na porta ${finding.port} (${finding.service}) está acessível no host ${finding.target}`,
          severity: 'high',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            host: finding.target,
            ip: finding.ip,
            port: finding.port,
            service: finding.service,
            state: finding.state,
            version: finding.version,
            banner: finding.banner,
            osInfo: finding.osInfo,
          },
        }),
      },
      {
        id: 'database-ports-exposed',
        name: 'Portas de Banco de Dados Expostas',
        description: 'Portas de bancos de dados abertas na internet',
        severity: 'high',
        matcher: (finding) => 
          finding.type === 'port' && 
          ['1433', '3306', '5432', '1521', '27017'].includes(finding.port) &&
          finding.state === 'open',
        createThreat: (finding, assetId, jobId) => ({
          title: `Porta de banco ${finding.port} exposta`,
          description: `Banco de dados na porta ${finding.port} (${finding.service}) está acessível no host ${finding.target}`,
          severity: 'high',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            host: finding.target,
            ip: finding.ip,
            port: finding.port,
            service: finding.service,
            state: finding.state,
            version: finding.version,
            banner: finding.banner,
            osInfo: finding.osInfo,
          },
        }),
      },
      {
        id: 'nuclei-vulnerability',
        name: 'Vulnerabilidade Detectada pelo Nuclei',
        description: 'Vulnerabilidade identificada por nuclei',
        severity: 'high',
        matcher: (finding) => 
          finding.type === 'vulnerability' && 
          finding.evidence?.source === 'nuclei',
        createThreat: (finding, assetId, jobId) => ({
          title: `${finding.name || finding.template} detectado`,
          description: `Vulnerabilidade: ${finding.description || finding.name}`,
          severity: finding.severity || 'medium',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            templateId: finding.template,
            url: finding.evidence?.url,
            matcher: finding.evidence?.matcher,
            extractedResults: finding.evidence?.extractedResults,
            curl: finding.evidence?.curl,
            nucleiInfo: finding.evidence?.info,
          },
        }),
      },
      {
        id: 'web-vulnerability',
        name: 'Vulnerabilidade Web Detectada',
        description: 'Vulnerabilidade identificada em serviço web',
        severity: 'medium',
        matcher: (finding) => 
          finding.type === 'web_vulnerability',
        createThreat: (finding, assetId, jobId) => ({
          title: `${finding.name} detectado`,
          description: `Vulnerabilidade web: ${finding.description || finding.name}`,
          severity: finding.severity || 'medium',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            host: finding.target,
            port: finding.port,
            service: finding.service,
            vulnerabilityType: finding.name,
            description: finding.description,
            template: finding.template,
            details: finding.evidence,
          },
        }),
      },

      // EDR/AV Testing Rules - Regras para testes de EDR/AV
      {
        id: 'edr-av-failure',
        name: 'Falha no EDR/AV Detectada',
        description: 'Sistema EDR/AV falhou em detectar/remover arquivo EICAR malicioso',
        severity: 'critical',
        matcher: (finding) => 
          finding.type === 'edr_test' && 
          finding.eicarRemoved === false &&
          !finding.error, // Só criar ameaça se a cópia foi bem-sucedida mas não foi removida
        createThreat: (finding, assetId, jobId) => ({
          title: `EDR/AV Falhou - ${finding.hostname}`,
          description: `Sistema de proteção EDR/AV no computador ${finding.hostname} falhou em detectar e remover arquivo EICAR malicioso. Isso indica uma falha crítica na proteção de endpoint.`,
          severity: 'critical',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            hostname: finding.hostname,
            filePath: finding.filePath,
            deploymentMethod: finding.deploymentMethod,
            testDuration: finding.testDuration,
            timestamp: finding.timestamp,
            eicarPersisted: true,
            recommendation: 'Verificar configuração e funcionamento do EDR/AV no endpoint. Considerar atualização de assinaturas e revisão de políticas de segurança.',
          } as Record<string, any>,
        }),
      },

      // AD Hygiene Rules - Regras para achados específicos do AD
      {
        id: 'ad-users-password-never-expires',
        name: 'Usuários com Senhas que Nunca Expiram',
        description: 'Usuários configurados com senhas que nunca expiram',
        severity: 'medium',
        matcher: (finding) => 
          finding.type === 'ad_misconfiguration' &&
          finding.name === 'Usuários com Senhas que Nunca Expiram',
        createThreat: (finding, assetId, jobId) => ({
          title: finding.name,
          description: finding.description,
          severity: finding.severity,
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            target: finding.target,
            category: finding.category,
            count: finding.evidence?.count,
            recommendation: finding.recommendation,
          },
        }),
      },
      {
        id: 'ad-inactive-users',
        name: 'Usuários Inativos Identificados',
        description: 'Usuários sem login há mais de 6 meses',
        severity: 'low',
        matcher: (finding) => 
          finding.type === 'ad_hygiene' &&
          finding.name === 'Usuários Inativos Identificados',
        createThreat: (finding, assetId, jobId) => ({
          title: finding.name,
          description: finding.description,
          severity: finding.severity,
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            target: finding.target,
            category: finding.category,
            count: finding.evidence?.count,
            recommendation: finding.recommendation,
          },
        }),
      },
      {
        id: 'ad-users-old-passwords',
        name: 'Usuários com Senhas Antigas',
        description: 'Usuários com senhas não alteradas há mais de 90 dias',
        severity: 'medium',
        matcher: (finding) => 
          finding.type === 'ad_vulnerability' &&
          finding.name === 'Usuários com Senhas Antigas',
        createThreat: (finding, assetId, jobId) => ({
          title: finding.name,
          description: finding.description,
          severity: finding.severity,
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            target: finding.target,
            category: finding.category,
            count: finding.evidence?.count,
            recommendation: finding.recommendation,
          },
        }),
      },
      {
        id: 'ad-privileged-group-members',
        name: 'Grupo Privilegiado com Muitos Membros',
        description: 'Grupo administrativo com membros em excesso',
        severity: 'high',
        matcher: (finding) => 
          finding.type === 'ad_misconfiguration' &&
          finding.name === 'Grupo Privilegiado com Muitos Membros',
        createThreat: (finding, assetId, jobId) => ({
          title: `${finding.name}: ${finding.target}`,
          description: finding.description,
          severity: finding.severity,
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            target: finding.target,
            category: finding.category,
            count: finding.evidence?.count,
            memberCount: finding.evidence?.memberCount,
            recommendation: finding.recommendation,
          },
        }),
      },
      {
        id: 'ad-obsolete-os',
        name: 'Sistemas Operacionais Obsoletos',
        description: 'Computadores com sistemas operacionais desatualizados',
        severity: 'high',
        matcher: (finding) => 
          finding.type === 'ad_vulnerability' &&
          finding.name === 'Sistemas Operacionais Obsoletos',
        createThreat: (finding, assetId, jobId) => ({
          title: finding.name,
          description: finding.description,
          severity: finding.severity,
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            target: finding.target,
            category: finding.category,
            count: finding.evidence?.count,
            recommendation: finding.recommendation,
          },
        }),
      },
      {
        id: 'ad-inactive-computers',
        name: 'Computadores Inativos',
        description: 'Computadores sem comunicação com o domínio há muito tempo',
        severity: 'low',
        matcher: (finding) => 
          finding.type === 'ad_hygiene' &&
          finding.name === 'Computadores Inativos',
        createThreat: (finding, assetId, jobId) => ({
          title: finding.name,
          description: finding.description,
          severity: finding.severity,
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            target: finding.target,
            category: finding.category,
            count: finding.evidence?.count,
            recommendation: finding.recommendation,
          },
        }),
      },
      {
        id: 'ad-weak-password-policy',
        name: 'Política de Senha Fraca',
        description: 'Política de senhas do domínio não atende padrões de segurança',
        severity: 'medium',
        matcher: (finding) => 
          finding.type === 'ad_vulnerability' &&
          finding.name === 'Política de Senha Fraca',
        createThreat: (finding, assetId, jobId) => ({
          title: finding.name,
          description: finding.description,
          severity: finding.severity,
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            target: finding.target,
            category: finding.category,
            recommendation: finding.recommendation,
          },
        }),
      },
      // Regras específicas para ameaças individuais
      {
        id: 'domain-admin-critical-password-expired',
        name: 'Domain Admin com Senha Crítica Expirada',
        description: 'Conta Domain Admin com senha expirada há muito tempo',
        severity: 'critical',
        matcher: (finding) => 
          finding.type === 'ad_vulnerability' &&
          finding.name === 'Domain Admin com Senha Crítica Expirada',
        createThreat: (finding, assetId, jobId) => ({
          title: finding.name,
          description: finding.description,
          severity: 'critical',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            username: finding.evidence?.username,
            target: finding.target,
            daysSincePasswordChange: finding.evidence?.daysSincePasswordChange,
            lastPasswordSet: finding.evidence?.lastPasswordSet,
            lastLogon: finding.evidence?.lastLogon,
            passwordAgeLimit: finding.evidence?.passwordAgeLimit,
            groupMembership: finding.evidence?.groupMembership,
            recommendation: finding.recommendation,
          },
        }),
      },
      {
        id: 'specific-inactive-user',
        name: 'Usuário Inativo Detectado',
        description: 'Usuário específico inativo há muito tempo',
        severity: 'low',
        matcher: (finding) => 
          finding.type === 'ad_hygiene' &&
          finding.name === 'Usuário Inativo Detectado',
        createThreat: (finding, assetId, jobId) => ({
          title: `Usuário inativo: ${finding.target}`,
          description: finding.description,
          severity: 'low',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            username: finding.evidence?.username,
            target: finding.target,
            daysSinceLastLogon: finding.evidence?.daysSinceLastLogon,
            lastLogon: finding.evidence?.lastLogon,
            inactiveUserLimit: finding.evidence?.inactiveUserLimit,
            recommendation: finding.recommendation,
          },
        }),
      },
      // Novas regras para configuração de domínio
      {
        id: 'privileged-group-too-many-members',
        name: 'Grupo Privilegiado com Muitos Membros',
        description: 'Grupo administrativo com número excessivo de membros',
        severity: 'medium',
        matcher: (finding) => 
          finding.type === 'ad_vulnerability' &&
          finding.name === 'Grupo Privilegiado com Muitos Membros',
        createThreat: (finding, assetId, jobId) => ({
          title: `Grupo privilegiado: ${finding.target}`,
          description: finding.description,
          severity: 'medium',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            groupName: finding.evidence?.groupName,
            memberCount: finding.evidence?.memberCount,
            maxRecommendedMembers: finding.evidence?.maxRecommendedMembers,
            members: finding.evidence?.members,
            recommendation: finding.recommendation,
          },
        }),
      },
      {
        id: 'password-complexity-disabled',
        name: 'Complexidade de Senha Desabilitada',
        description: 'Política de complexidade de senhas não habilitada',
        severity: 'high',
        matcher: (finding) => 
          finding.type === 'ad_vulnerability' &&
          finding.name === 'Complexidade de Senha Desabilitada',
        createThreat: (finding, assetId, jobId) => ({
          title: finding.name,
          description: finding.description,
          severity: 'high',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            pwdProperties: finding.evidence?.pwdProperties,
            complexityEnabled: finding.evidence?.complexityEnabled,
            recommendation: finding.recommendation,
          },
        }),
      },
      {
        id: 'password-history-insufficient',
        name: 'Histórico de Senhas Insuficiente',
        description: 'Histórico de senhas configurado inadequadamente',
        severity: 'low',
        matcher: (finding) => 
          finding.type === 'ad_vulnerability' &&
          finding.name === 'Histórico de Senhas Insuficiente',
        createThreat: (finding, assetId, jobId) => ({
          title: finding.name,
          description: finding.description,
          severity: 'low',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            currentHistoryLength: finding.evidence?.currentHistoryLength,
            recommendation: finding.recommendation,
          },
        }),
      },
      {
        id: 'passwords-never-expire',
        name: 'Senhas Sem Expiração',
        description: 'Senhas configuradas para nunca expirar',
        severity: 'medium',
        matcher: (finding) => 
          finding.type === 'ad_vulnerability' &&
          finding.name === 'Senhas Sem Expiração',
        createThreat: (finding, assetId, jobId) => ({
          title: finding.name,
          description: finding.description,
          severity: 'medium',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            maxPwdAge: finding.evidence?.maxPwdAge,
            recommendation: finding.recommendation,
          },
        }),
      },
      {
        id: 'inactive-computer-detected',
        name: 'Computador Inativo no Domínio',
        description: 'Computador específico inativo há muito tempo',
        severity: 'low',
        matcher: (finding) => 
          finding.type === 'ad_hygiene' &&
          finding.name === 'Computador Inativo no Domínio',
        createThreat: (finding, assetId, jobId) => ({
          title: `Computador inativo: ${finding.target}`,
          description: finding.description,
          severity: 'low',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            computerName: finding.evidence?.computerName,
            daysSinceLastLogon: finding.evidence?.daysSinceLastLogon,
            lastLogon: finding.evidence?.lastLogon,
            inactiveComputerLimit: finding.evidence?.inactiveComputerLimit,
            recommendation: finding.recommendation,
          },
        }),
      },
      {
        id: 'obsolete-operating-system',
        name: 'Sistema Operacional Obsoleto',
        description: 'Sistema operacional não suportado detectado',
        severity: 'medium',
        matcher: (finding) => 
          finding.type === 'ad_vulnerability' &&
          finding.name === 'Sistema Operacional Obsoleto',
        createThreat: (finding, assetId, jobId) => ({
          title: `SO obsoleto: ${finding.target}`,
          description: finding.description,
          severity: 'medium',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            computerName: finding.evidence?.computerName,
            operatingSystem: finding.evidence?.operatingSystem,
            osVersion: finding.evidence?.osVersion,
            recommendation: finding.recommendation,
          },
        }),
      },
      {
        id: 'bidirectional-trust-detected',
        name: 'Trust Bidirecional Detectado',
        description: 'Trust de domínio bidirecional configurado',
        severity: 'low',
        matcher: (finding) => 
          finding.type === 'ad_hygiene' &&
          finding.name === 'Trust Bidirecional Detectado',
        createThreat: (finding, assetId, jobId) => ({
          title: `Trust bidirecional: ${finding.target}`,
          description: finding.description,
          severity: 'low',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            trustName: finding.evidence?.trustName,
            trustDirection: finding.evidence?.trustDirection,
            trustType: finding.evidence?.trustType,
            trustAttributes: finding.evidence?.trustAttributes,
            recommendation: finding.recommendation,
          },
        }),
      },
      {
        id: 'domain-admin-old-password',
        name: 'Domain Admin com Senha Antiga',
        description: 'Conta Domain Admin com senha não alterada há muito tempo',
        severity: 'high',
        matcher: (finding) => 
          finding.type === 'ad_user' &&
          finding.groups?.includes('Domain Admins') &&
          finding.passwordAge > 90,
        createThreat: (finding, assetId, jobId) => ({
          title: `Domain Admin com senha expirada há ${finding.passwordAge} dias`,
          description: `Conta privilegiada ${finding.username} sem rotação de senha`,
          severity: 'high',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            username: finding.username,
            domain: finding.domain,
            passwordAge: finding.passwordAge,
            lastLogon: finding.lastLogon,
            groups: finding.groups,
          },
        }),
      },
      {
        id: 'password-never-expires',
        name: 'Conta com PasswordNeverExpires',
        description: 'Conta configurada para senha nunca expirar',
        severity: 'medium',
        matcher: (finding) => 
          finding.type === 'ad_user' && finding.passwordNeverExpires === true,
        createThreat: (finding, assetId, jobId) => ({
          title: `Conta ${finding.username} com PasswordNeverExpires`,
          description: 'Conta configurada para senha nunca expirar',
          severity: 'medium',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            username: finding.username,
            domain: finding.domain,
            enabled: finding.enabled,
            lastLogon: finding.lastLogon,
          },
        }),
      },

    ];
  }

  /**
   * Analyzes findings and creates threats
   */
  async analyzeFindings(findings: any[], assetId?: string, jobId?: string): Promise<Threat[]> {
    const threats: Threat[] = [];

    console.log(`🔍 ThreatEngine analisando ${findings.length} achados para criação de ameaças...`);
    
    for (const finding of findings) {
      console.log(`📋 Analisando achado: tipo=${finding.type}, porta=${finding.port}, severidade=${finding.severity}`);
      
      let matchedRules = 0;
      for (const rule of this.rules) {
        if (rule.matcher(finding)) {
          matchedRules++;
          try {
            const threatData = rule.createThreat(finding, assetId, jobId);
            const threat = await storage.createThreat(threatData);
            threats.push(threat);
            
            console.log(`✅ Ameaça criada pela regra '${rule.id}': ${threat.title} (${threat.severity})`);
          } catch (error) {
            console.error(`❌ Erro ao criar ameaça para regra ${rule.id}:`, error);
          }
        }
      }
      
      if (matchedRules === 0) {
        console.log(`⚪ Nenhuma regra correspondeu ao achado: ${JSON.stringify(finding).substring(0, 100)}...`);
      }
    }

    console.log(`🎯 ThreatEngine criou ${threats.length} ameaças de ${findings.length} achados analisados`);
    return threats;
  }

  /**
   * Processes job results and generates threats using lifecycle management
   */
  async processJobResults(jobId: string): Promise<Threat[]> {
    const jobResult = await storage.getJobResult(jobId);
    if (!jobResult || !jobResult.artifacts) {
      return [];
    }

    const findings = jobResult.artifacts.findings || [];
    const job = await storage.getJob(jobId);
    if (!job) {
      return [];
    }

    const journey = await storage.getJourney(job.journeyId);
    if (!journey) {
      return [];
    }

    // Use new lifecycle-aware analysis
    const threats = await this.analyzeWithLifecycle(findings, journey.type, job.journeyId, jobId);
    
    // Run post-processing for journey-specific auto-closure logic
    await this.runJourneyPostProcessing(journey.type, job.journeyId, jobId, findings);
    
    return threats;
  }

  /**
   * Computes a unique correlation key for a finding based on journey type
   */
  private computeCorrelationKey(finding: any, journeyType: string): string {
    const normalizeHost = (host: string): string => {
      return host?.toLowerCase().trim() || '';
    };

    switch (journeyType) {
      case 'attack_surface':
        if (finding.type === 'port') {
          return `as:port:${normalizeHost(finding.target)}:${finding.port}`;
        }
        if (finding.type === 'vulnerability' || finding.type === 'web_vulnerability') {
          const templateId = finding.template || finding.cve || finding.name;
          let path = '';
          try {
            if (finding.evidence?.url) {
              path = new URL(finding.evidence.url).pathname;
            }
          } catch {
            // If URL is invalid, use empty path
            path = '';
          }
          return `as:vuln:${normalizeHost(finding.target)}:${templateId}:${path}`;
        }
        break;
      
      case 'ad_hygiene':
        // For AD findings: ad:{ruleId}:{domainNetBIOS}:{objectId|distinguishedName|samAccountName}
        const domain = finding.evidence?.domain || finding.target?.split('.')[1]?.toUpperCase() || 'DOMAIN';
        const objectId = finding.evidence?.username || finding.evidence?.computerName || finding.evidence?.groupName || finding.target;
        return `ad:${finding.name?.replace(/\s+/g, '_')}:${domain}:${objectId}`;
      
      case 'edr_av':
        // For EDR/AV: edr:{hostname}:{testType}
        const hostname = finding.hostname || finding.target;
        const testType = finding.deploymentMethod || 'eicar_test';
        return `edr:${normalizeHost(hostname)}:${testType}`;
      
      default:
        // Fallback for unknown journey types
        return `generic:${finding.type}:${normalizeHost(finding.target || finding.hostname)}:${finding.name}`;
    }

    return `fallback:${Date.now()}:${Math.random()}`;
  }

  /**
   * Analyzes findings using lifecycle-aware approach with upsert logic
   */
  async analyzeWithLifecycle(findings: any[], journeyType: string, journeyId: string, jobId?: string): Promise<Threat[]> {
    const threats: Threat[] = [];
    const observedKeys = new Set<string>();

    for (const finding of findings) {
      for (const rule of this.rules) {
        if (rule.matcher(finding)) {
          const correlationKey = this.computeCorrelationKey(finding, journeyType);
          observedKeys.add(correlationKey);

          const threatData = rule.createThreat(finding, undefined, jobId);
          
          // Find associated host for this threat
          const hostId = await this.findHostForThreat(finding, journeyType);
          
          // Use upsert logic with lifecycle fields
          const threat = await storage.upsertThreat({
            ...threatData,
            hostId, // Link threat to discovered host
            correlationKey,
            category: journeyType,
            lastSeenAt: new Date(),
          });

          threats.push(threat);
          console.log(`🔄 Threat upserted: ${threat.title} (Key: ${correlationKey})`);
          break; // Stop after first matching rule
        }
      }
    }

    return threats;
  }

  /**
   * Runs journey-specific post-processing for auto-closure logic
   */
  async runJourneyPostProcessing(journeyType: string, journeyId: string, jobId: string, findings: any[]): Promise<void> {
    switch (journeyType) {
      case 'attack_surface':
        await this.processAttackSurfaceClosures(journeyId, jobId, findings);
        break;
      
      case 'ad_hygiene':
        await this.processAdHygieneClosures(journeyId, jobId, findings);
        break;
      
      case 'edr_av':
        await this.processEdrAvClosures(journeyId, jobId, findings);
        break;
    }
  }

  /**
   * Process Attack Surface auto-closures
   */
  private async processAttackSurfaceClosures(journeyId: string, jobId: string, findings: any[]): Promise<void> {
    // Get hosts that were scanned in this job
    const scannedHosts = new Set<string>();
    findings.forEach(finding => {
      if (finding.target) {
        scannedHosts.add(finding.target.toLowerCase().trim());
      }
    });

    // Get observed correlation keys from this job
    const observedKeys = new Set<string>();
    findings.forEach(finding => {
      const key = this.computeCorrelationKey(finding, 'attack_surface');
      observedKeys.add(key);
    });

    // Find open threats from previous jobs of this journey
    const openThreats = await storage.listOpenThreatsByJourney(journeyId, 'attack_surface');
    
    for (const threat of openThreats) {
      if (!threat.correlationKey) continue;
      
      // Check if threat's host was in scope but threat wasn't observed
      const threatHost = this.extractHostFromCorrelationKey(threat.correlationKey);
      if (threatHost && scannedHosts.has(threatHost) && !observedKeys.has(threat.correlationKey)) {
        await storage.closeThreatSystem(threat.id, 'system');
        console.log(`🔒 Attack Surface threat auto-closed: ${threat.title} (not found in new scan)`);
      }
    }
  }

  /**
   * Process AD Hygiene auto-closures
   */
  private async processAdHygieneClosures(journeyId: string, jobId: string, findings: any[]): Promise<void> {
    // Get observed correlation keys from this job
    const observedKeys = new Set<string>();
    findings.forEach(finding => {
      const key = this.computeCorrelationKey(finding, 'ad_hygiene');
      observedKeys.add(key);
    });

    // Find all open AD threats from previous jobs of this journey
    const openThreats = await storage.listOpenThreatsByJourney(journeyId, 'ad_hygiene');
    
    for (const threat of openThreats) {
      if (!threat.correlationKey) continue;
      
      // If threat wasn't observed in this run, condition is fixed - close it
      if (!observedKeys.has(threat.correlationKey)) {
        await storage.closeThreatSystem(threat.id, 'system');
        console.log(`🔒 AD Hygiene threat auto-closed: ${threat.title} (condition resolved)`);
      }
    }
  }

  /**
   * Process EDR/AV auto-closures
   */
  private async processEdrAvClosures(journeyId: string, jobId: string, findings: any[]): Promise<void> {
    // Get tested endpoints from this job
    const testedEndpoints = new Map<string, any>();
    findings.forEach(finding => {
      if (finding.hostname) {
        testedEndpoints.set(finding.hostname.toLowerCase(), finding);
      }
    });

    // Get observed correlation keys from failures
    const observedFailureKeys = new Set<string>();
    findings.forEach(finding => {
      if (finding.type === 'edr_test' && finding.eicarRemoved === false && !finding.error) {
        const key = this.computeCorrelationKey(finding, 'edr_av');
        observedFailureKeys.add(key);
      }
    });

    // Find open EDR/AV threats from previous jobs
    const openThreats = await storage.listOpenThreatsByJourney(journeyId, 'edr_av');
    
    for (const threat of openThreats) {
      if (!threat.correlationKey) continue;
      
      const hostname = this.extractHostnameFromEdrKey(threat.correlationKey);
      if (hostname && testedEndpoints.has(hostname)) {
        // This endpoint was tested again
        if (!observedFailureKeys.has(threat.correlationKey)) {
          // Failure did not manifest - close threat
          await storage.closeThreatSystem(threat.id, 'system');
          console.log(`🔒 EDR/AV threat auto-closed: ${threat.title} (failure no longer manifests)`);
        }
        // If failure persists, it's already updated by upsert logic
      }
      // If endpoint wasn't tested, leave threat open (manual closure only)
    }
  }

  /**
   * Extract hostname from correlation key for different journey types
   */
  private extractHostFromCorrelationKey(correlationKey: string): string | null {
    const parts = correlationKey.split(':');
    if (parts.length >= 3) {
      return parts[2]; // host is usually the 3rd part
    }
    return null;
  }

  /**
   * Extract hostname from EDR correlation key
   */
  private extractHostnameFromEdrKey(correlationKey: string): string | null {
    // edr:{hostname}:{testType}
    const parts = correlationKey.split(':');
    if (parts.length >= 2 && parts[0] === 'edr') {
      return parts[1];
    }
    return null;
  }

  /**
   * Gets threat statistics
   */
  async getThreatStatistics(): Promise<{
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    newToday: number;
  }> {
    const stats = await storage.getThreatStats();
    
    // Get threats created today
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const allThreats = await storage.getThreats();
    const newToday = allThreats.filter(threat => 
      new Date(threat.createdAt) >= today
    ).length;

    return {
      ...stats,
      newToday,
    };
  }

  /**
   * Adds a custom threat rule
   */
  addRule(rule: ThreatRule): void {
    this.rules.push(rule);
  }

  /**
   * Gets all active rules
   */
  getRules(): ThreatRule[] {
    return this.rules;
  }

  /**
   * Manually creates a threat
   */
  async createManualThreat(threatData: InsertThreat): Promise<Threat> {
    return storage.createThreat({
      ...threatData,
      source: 'manual',
    });
  }

  /**
   * Finds the appropriate host for a threat based on the finding and journey type
   */
  private async findHostForThreat(finding: any, journeyType: string): Promise<string | null> {
    try {
      switch (journeyType) {
        case 'attack_surface':
          // For Attack Surface, use the target (IP or hostname) from the finding
          let target = finding.target || finding.ip || finding.host;
          
          // If no direct target, try to extract hostname from URL in evidence
          if (!target && finding.evidence?.url) {
            try {
              const url = new URL(finding.evidence.url);
              target = url.hostname;
            } catch {
              // If URL parsing fails, continue without target
            }
          }
          
          if (target) {
            const hosts = await hostService.findHostsByTarget(target);
            if (hosts.length > 0) {
              console.log(`🔗 Linking threat to host: ${hosts[0].name} (${target})`);
              return hosts[0].id;
            } else {
              // Debug: Count hosts for diagnosis but don't expose full inventory in logs
              const hostCount = (await storage.getHosts()).length;
              console.log(`🔍 Debug: Tentativa de busca para target '${target}' entre ${hostCount} hosts falhou`);
            }
          }
          break;

        case 'ad_hygiene':
          // For AD Hygiene, find the domain host using normalized domain extraction
          const domainHost = await this.findDomainHost(finding);
          if (domainHost) {
            console.log(`🔗 Linking AD threat to domain host: ${domainHost.name}`);
            return domainHost.id;
          }
          break;

        case 'edr_av':
          // For EDR/AV, use the hostname from the finding
          const hostname = finding.hostname || finding.target;
          if (hostname) {
            const hosts = await hostService.findHostsByTarget(hostname);
            if (hosts.length > 0) {
              console.log(`🔗 Linking EDR/AV threat to host: ${hosts[0].name} (${hostname})`);
              return hosts[0].id;
            }
          }
          break;
      }

      // If no host found, log for debugging
      const target = finding.target || finding.ip || finding.host || finding.hostname || 'unknown';
      console.log(`⚠️  No host found for threat (${journeyType}): ${target}`);
      return null;
    } catch (error) {
      console.error('❌ Error finding host for threat:', error);
      return null;
    }
  }

  /**
   * Finds and normalizes domain host for AD Hygiene threats
   */
  private async findDomainHost(finding: any): Promise<any | null> {
    // Extract domain from various possible sources, normalize consistently
    let domain = '';
    
    if (finding.evidence?.domain) {
      domain = finding.evidence.domain;
    } else if (finding.target) {
      // Handle both FQDN (corp.local) and NetBIOS (CORP) cases
      const parts = finding.target.split('.');
      if (parts.length > 1) {
        // FQDN case: use the first part as NetBIOS name
        domain = parts[0];
      } else {
        // Already NetBIOS case
        domain = finding.target;
      }
    } else {
      domain = 'unknown';
    }
    
    // Normalize domain name to lowercase for consistent matching
    const normalizedDomain = domain.toLowerCase();
    
    // Get all domain hosts and find matching one
    const domainHosts = await storage.getHosts({ type: 'domain' });
    const matchingDomain = domainHosts.find(h => 
      h.name.toLowerCase().includes(normalizedDomain) ||
      h.aliases?.some(alias => alias.toLowerCase().includes(normalizedDomain)) ||
      normalizedDomain.includes(h.name.toLowerCase())
    );
    
    return matchingDomain || null;
  }
}

export const threatEngine = new ThreatEngineService();
