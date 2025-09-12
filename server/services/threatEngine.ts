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
          description: `Porta ${finding.port} (${finding.service}) está aberta e acessível`,
          severity: 'high',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            port: finding.port,
            service: finding.service,
            state: finding.state,
            version: finding.version,
          },
        }),
      },

      // AD Hygiene Rules
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

    for (const finding of findings) {
      for (const rule of this.rules) {
        if (rule.matcher(finding)) {
          try {
            const threatData = rule.createThreat(finding, assetId, jobId);
            const threat = await storage.createThreat(threatData);
            threats.push(threat);
            
            console.log(`Ameaça criada: ${threat.title} (${threat.severity})`);
          } catch (error) {
            console.error(`Erro ao criar ameaça para regra ${rule.id}:`, error);
          }
        }
      }
    }

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
