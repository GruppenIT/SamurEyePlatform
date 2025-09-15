import { storage } from '../storage';
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

      // EDR/AV Rules
      {
        id: 'edr-eicar-not-removed',
        name: 'EDR/AV Falhou em Detectar EICAR',
        description: 'Arquivo EICAR não foi removido pelo EDR/AV',
        severity: 'medium',
        matcher: (finding) => 
          finding.type === 'edr_test' && finding.eicarRemoved === false,
        createThreat: (finding, assetId, jobId) => ({
          title: `EDR/AV falhou em detectar arquivo EICAR`,
          description: `Workstation ${finding.hostname} não removeu arquivo de teste EICAR`,
          severity: 'medium',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            hostname: finding.hostname,
            filePath: finding.filePath,
            testDuration: finding.testDuration,
            timestamp: finding.timestamp,
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
   * Processes job results and generates threats
   */
  async processJobResults(jobId: string): Promise<Threat[]> {
    const jobResult = await storage.getJobResult(jobId);
    if (!jobResult || !jobResult.artifacts) {
      return [];
    }

    const findings = jobResult.artifacts.findings || [];
    const job = await storage.getJob(jobId);
    
    return this.analyzeFindings(findings, undefined, jobId);
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
}

export const threatEngine = new ThreatEngineService();
