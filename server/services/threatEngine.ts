import { storage } from '../storage';
import { hostService } from './hostService';
import { type InsertThreat, type Threat } from '@shared/schema';
import { notificationService } from './notificationService';

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
      // NVD CVE Lookup - Known vulnerabilities from NIST database
      {
        id: 'nvd-cve-detected',
        name: 'Vulnerabilidade CVE Conhecida (NVD)',
        description: 'CVE conhecido encontrado na base NIST NVD',
        severity: 'high', // Will be overridden by finding.severity
        matcher: (finding) => finding.type === 'nvd_cve' && finding.cve,
        createThreat: (finding, assetId, jobId) => ({
          title: `${finding.cve}: ${finding.service} ${finding.version}`,
          description: finding.description || `CVE ${finding.cve} identificado para ${finding.service} ${finding.version}. ${finding.remediation || ''}`,
          severity: finding.severity || 'high',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            cve: finding.cve,
            cvssScore: finding.cvssScore,
            service: finding.service,
            version: finding.version,
            port: finding.port,
            host: finding.target,
            publishedDate: finding.publishedDate,
            remediation: finding.remediation,
            detectionMethod: 'nvd_api_lookup',
          },
        }),
      },
      // Nmap Vuln Script Detection - Active CVE validation
      {
        id: 'nmap-vuln-detected',
        name: 'Vulnerabilidade CVE Validada (Nmap)',
        description: 'CVE validado ativamente via nmap vuln scripts',
        severity: 'high', // Will be overridden by finding.severity
        matcher: (finding) => finding.type === 'nmap_vuln' && finding.cve,
        createThreat: (finding, assetId, jobId) => ({
          title: `${finding.cve}: ${finding.name || 'Vulnerabilidade confirmada'}`,
          description: finding.description || `CVE ${finding.cve} validado ativamente via nmap vuln scripts. ${finding.details || ''}`,
          severity: finding.severity || 'high',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            cve: finding.cve,
            name: finding.name,
            service: finding.service,
            port: finding.port,
            host: finding.target,
            details: finding.details,
            validationMethod: 'nmap_vuln_scripts',
          },
        }),
      },
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
      
      // Generic AD Security Rule - Captures ALL AD Security findings
      {
        id: 'ad-security-generic',
        name: 'AD Security Finding',
        description: 'Falha de segurança detectada no Active Directory',
        severity: 'medium',
        matcher: (finding) => 
          finding.type === 'ad_misconfiguration' ||
          finding.type === 'ad_vulnerability' ||
          finding.type === 'ad_hygiene',
        createThreat: (finding, assetId, jobId) => ({
          title: finding.name,
          description: finding.description || `Problema de segurança detectado: ${finding.name}`,
          severity: finding.severity,
          source: 'journey',
          assetId,
          jobId,
          category: finding.type,
          evidence: {
            target: finding.target,
            category: finding.category,
            testId: finding.evidence?.testId,
            command: finding.evidence?.command,
            stdout: finding.evidence?.stdout,
            stderr: finding.evidence?.stderr,
            exitCode: finding.evidence?.exitCode,
            recommendation: finding.recommendation,
          },
        }),
      },
      
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
        id: 'ad-domain-controller-not-found',
        name: 'Controlador de Domínio Não Encontrado',
        description: 'Nenhum controlador de domínio foi encontrado ou está acessível',
        severity: 'critical',
        matcher: (finding) => 
          finding.type === 'ad_misconfiguration' &&
          finding.name === 'Nenhum Controlador de Domínio Encontrado',
        createThreat: (finding, assetId, jobId) => ({
          title: `Controlador de domínio inacessível: ${finding.target}`,
          description: finding.description || 'Não foi possível conectar ou encontrar controladores de domínio ativos para o domínio especificado. Isso pode indicar problemas de conectividade de rede ou falha de infraestrutura.',
          severity: 'critical',
          source: 'journey',
          assetId,
          jobId,
          evidence: {
            target: finding.target,
            category: finding.category,
            errorType: finding.evidence?.errorType,
            connectionAttempts: finding.evidence?.connectionAttempts,
            recommendation: finding.recommendation || 'Verificar conectividade de rede com controladores de domínio. Confirmar se os serviços AD DS estão executando nos servidores de domínio.',
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
            
            // Recalculate host risk score if threat is linked to a host
            if (threat.hostId) {
              await this.recalculateHostRiskScore(threat.hostId).catch(err => 
                console.error(`⚠️ Erro ao recalcular escore de risco do host ${threat.hostId}:`, err)
              );
            }
            
            // Send notifications for new threats
            try {
              await notificationService.notifyThreatCreated(threat);
            } catch (notifError) {
              console.error(`⚠️ Erro ao enviar notificações para ameaça ${threat.id}:`, notifError);
              // Don't fail threat creation if notification fails
            }
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
    console.log(`🔍 PROCESS_JOB_RESULTS: Starting with jobId: ${jobId}`);
    
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

    console.log(`🔍 PROCESS_JOB_RESULTS: Journey ${job.journeyId}, Type: ${journey.type}, JobId: ${jobId}`);

    // Use new lifecycle-aware analysis
    const threats = await this.analyzeWithLifecycle(findings, journey.type, job.journeyId, jobId);
    
    console.log(`🔍 PROCESS_JOB_RESULTS: About to run post-processing with jobId: ${jobId}`);
    
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
      
      case 'ad_security':
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

    console.log(`🔍 ThreatEngine.analyzeWithLifecycle: Analisando ${findings.length} findings para journeyType '${journeyType}' (jobId: ${jobId})`);

    for (const finding of findings) {
      console.log(`📋 Finding: type=${finding.type}, name=${finding.name}, target=${finding.target}`);
      
      let matchedRule = false;
      for (const rule of this.rules) {
        if (rule.matcher(finding)) {
          matchedRule = true;
          console.log(`✅ Finding matched rule: ${rule.id}`);
          
          const correlationKey = this.computeCorrelationKey(finding, journeyType);
          observedKeys.add(correlationKey);

          const threatData = rule.createThreat(finding, undefined, jobId);
          
          // Find associated host for this threat
          const hostId = await this.findHostForThreat(finding, journeyType, jobId);
          console.log(`🔗 Host found for threat: ${hostId ? hostId : 'NULL'}`);
          
          // Use upsert logic with lifecycle fields
          const { threat, isNew } = await storage.upsertThreat({
            ...threatData,
            hostId, // Link threat to discovered host
            correlationKey,
            category: journeyType,
            lastSeenAt: new Date(),
          });

          threats.push(threat);
          console.log(`🔄 Threat upserted: ${threat.title} (Category: ${threat.category}, HostId: ${threat.hostId}, Key: ${correlationKey}, isNew: ${isNew})`);
          
          // Recalculate host risk score if threat is linked to a host
          if (threat.hostId) {
            console.log(`🔢 Recalculando risk score para host ${threat.hostId}...`);
            await this.recalculateHostRiskScore(threat.hostId).catch(err => 
              console.error(`⚠️ Erro ao recalcular escore de risco do host ${threat.hostId}:`, err)
            );
          }
          
          // Send email notification if this is a new threat
          if (isNew) {
            console.log(`📧 Sending notification for new threat: ${threat.id}`);
            await notificationService.notifyThreatCreated(threat);
          }
          
          break; // Stop after first matching rule
        }
      }
      
      if (!matchedRule) {
        console.log(`⚪ Nenhuma regra correspondeu ao finding: type=${finding.type}, name=${finding.name}`);
      }
    }

    console.log(`🎯 ThreatEngine.analyzeWithLifecycle: Criou ${threats.length} ameaças de ${findings.length} findings para journeyType '${journeyType}'`);
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
      
      case 'ad_security':
        await this.processAdSecurityClosures(journeyId, jobId, findings);
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
    console.log(`🔍 ATTACK_SURFACE_CLOSURES: Starting with journeyId: ${journeyId}, jobId: ${jobId}`);
    
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
    
    let skippedCurrentJobCount = 0;
    let closedCount = 0;
    let keptOpenCount = 0;
    let noCorrelationKeyCount = 0;
    let outOfScopeCount = 0;
    
    console.log(`📊 ATTACK_SURFACE_METRICS: Starting analysis - scannedHosts: ${scannedHosts.size}, observedKeys: ${observedKeys.size}, openThreats: ${openThreats.length}, currentJobId: ${jobId}`);
    
    for (const threat of openThreats) {
      if (!threat.correlationKey) {
        noCorrelationKeyCount++;
        continue;
      }
      
      // Skip ALL threats from the current job to prevent immediate closure
      if (threat.jobId === jobId) {
        console.log(`⏰ GUARD: Skipping Attack Surface threat from current job: ${threat.title} (jobId: ${jobId})`);
        skippedCurrentJobCount++;
        continue;
      }
      
      // Check if threat's host was in scope but threat wasn't observed
      const threatHost = this.extractHostFromCorrelationKey(threat.correlationKey);
      if (threatHost && scannedHosts.has(threatHost)) {
        if (!observedKeys.has(threat.correlationKey)) {
          console.log(`🔒 CLOSURE: Attack Surface threat ${threat.id} from job ${threat.jobId} - host ${threatHost} scanned but key "${threat.correlationKey}" not observed`);
          await storage.closeThreatSystem(threat.id, 'system');
          console.log(`✅ CLOSURE: Attack Surface threat ${threat.id} automatically closed - not found in new scan`);
          closedCount++;
        } else {
          console.log(`✅ KEEP_OPEN: Attack Surface threat ${threat.id} kept open - key ${threat.correlationKey} observed in current scan`);
          keptOpenCount++;
        }
      } else {
        console.log(`⚪ OUT_OF_SCOPE: Attack Surface threat ${threat.id} - host ${threatHost} not in current scan scope`);
        outOfScopeCount++;
      }
    }
    
    console.log(`✅ ATTACK_SURFACE_METRICS: Completed - skippedCurrentJob: ${skippedCurrentJobCount}, closed: ${closedCount}, keptOpen: ${keptOpenCount}, outOfScope: ${outOfScopeCount}, noCorrelationKey: ${noCorrelationKeyCount}, total: ${openThreats.length}`);
  }

  /**
   * Process AD Security auto-closures
   */
  private async processAdSecurityClosures(journeyId: string, jobId: string, findings: any[]): Promise<void> {
    console.log(`🔍 AD_SECURITY_CLOSURES: Starting with journeyId: ${journeyId}, jobId: ${jobId}`);
    
    // Get observed correlation keys from this job
    const observedKeys = new Set<string>();
    findings.forEach(finding => {
      const key = this.computeCorrelationKey(finding, 'ad_security');
      observedKeys.add(key);
    });

    // Find all open AD threats from previous jobs of this journey
    const openThreats = await storage.listOpenThreatsByJourney(journeyId, 'ad_security');
    
    let skippedCurrentJobCount = 0;
    let closedCount = 0;
    let keptOpenCount = 0;
    let noCorrelationKeyCount = 0;
    
    console.log(`📊 AD_SECURITY_METRICS: Starting analysis - observedKeys: ${observedKeys.size}, openThreats: ${openThreats.length}, currentJobId: ${jobId}`);
    
    for (const threat of openThreats) {
      if (!threat.correlationKey) {
        noCorrelationKeyCount++;
        continue;
      }
      
      // Skip ALL threats from the current job to prevent immediate closure
      if (threat.jobId === jobId) {
        console.log(`⏰ GUARD: Skipping AD threat from current job: ${threat.title} (jobId: ${jobId})`);
        skippedCurrentJobCount++;
        continue;
      }
      
      // SAFE AUTO-CLOSURE: Only close threats from previous jobs that weren't observed
      if (!observedKeys.has(threat.correlationKey)) {
        console.log(`🔒 CLOSURE: AD threat ${threat.id} from job ${threat.jobId} - key "${threat.correlationKey}" not observed in current scan`);
        await storage.closeThreatSystem(threat.id, 'system');
        console.log(`✅ CLOSURE: AD threat ${threat.id} automatically closed - not found in new scan (possible cleanup/remediation)`);
        closedCount++;
      } else {
        console.log(`✅ KEEP_OPEN: AD threat ${threat.id} kept open - key ${threat.correlationKey} observed in current scan`);
        keptOpenCount++;
      }
    }
    
    console.log(`✅ AD_SECURITY_METRICS: Completed - skippedCurrentJob: ${skippedCurrentJobCount}, closed: ${closedCount}, keptOpen: ${keptOpenCount}, noCorrelationKey: ${noCorrelationKeyCount}, total: ${openThreats.length}`);
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
      
      // Skip ALL threats from the current job to prevent immediate closure
      if (threat.jobId === jobId) {
        console.log(`⏰ Skipping EDR/AV threat from current job: ${threat.title} (jobId: ${jobId})`);
        continue;
      }
      
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
  private async findHostForThreat(finding: any, journeyType: string, jobId?: string): Promise<string | null> {
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

        case 'ad_security':
          // For AD Security, find the domain host - ALL threats link to the SAME domain host
          const domainHost = await this.findDomainHost(finding, jobId);
          if (domainHost) {
            console.log(`🔗 Linking AD threat to domain host: ${domainHost.name}`);
            return domainHost.id;
          } else {
            // If no domain host found, try to create one using the domain from credentials/job context
            let targetDomain = '';
            
            // Try to get domain from job credentials first (most reliable)
            if (jobId) {
              try {
                const job = await storage.getJob(jobId);
                if (job) {
                  const journey = await storage.getJourney(job.journeyId);
                  if (journey && journey.params.credentialId) {
                    const credential = await storage.getCredential(journey.params.credentialId);
                    if (credential && credential.domain) {
                      targetDomain = credential.domain;
                    }
                  } else if (journey && journey.params.domain) {
                    // Use domain from journey params if available
                    targetDomain = journey.params.domain;
                  }
                }
              } catch (error) {
                console.log(`⚠️  AD Security: Erro ao buscar domínio das credenciais:`, error);
              }
            }
            
            // Fallback to evidence.domain
            if (!targetDomain && finding.evidence?.domain) {
              targetDomain = finding.evidence.domain;
            }
            
            if (targetDomain && targetDomain !== 'unknown') {
              try {
                console.log(`🏠 AD Security: Criando host de domínio via hostService para '${targetDomain}'`);
                const newDomainHost = await hostService.createDomainHost(targetDomain, jobId || 'unknown');
                console.log(`✅ AD Security: Host de domínio criado: ${newDomainHost.name}`);
                return newDomainHost.id;
              } catch (error) {
                console.error(`❌ AD Security: Erro ao criar host de domínio:`, error);
              }
            } else {
              console.log(`⚠️  AD Security: Não foi possível determinar o domínio para criar host`);
            }
          }
          break;

        case 'edr_av':
          // For EDR/AV, use the hostname from the finding
          const hostname = finding.hostname || finding.target;
          if (hostname) {
            let hosts = await hostService.findHostsByTarget(hostname);
            if (hosts.length > 0) {
              console.log(`🔗 Linking EDR/AV threat to host: ${hosts[0].name} (${hostname})`);
              return hosts[0].id;
            } else {
              // Create host if not found (common in EDR-only environments)
              try {
                const newHost = await storage.upsertHost({
                  name: hostname.toLowerCase(),
                  description: `Host descoberto via teste EDR/AV (Job ID: ${jobId || 'unknown'})`,
                  type: 'desktop', // Assume desktop for EDR endpoints
                  family: 'windows_desktop', // Most EDR endpoints are Windows desktops
                  ips: [], // EDR tests may not have IP information
                  aliases: [],
                });
                console.log(`🏠 Host criado para EDR/AV: ${newHost.name} (${hostname})`);
                return newHost.id;
              } catch (error) {
                console.error(`❌ Erro ao criar host para EDR/AV ${hostname}:`, error);
              }
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
   * For AD Hygiene, ALL threats should be linked to the SAME domain host
   */
  private async findDomainHost(finding: any, jobId?: string): Promise<any | null> {
    // For AD Hygiene, the domain should be consistently extracted
    // Priority: evidence.domain > try to extract from various sources
    let domain = '';
    
    if (finding.evidence?.domain) {
      // Best source: explicit domain field
      domain = finding.evidence.domain;
    } else {
      // Try to extract domain from the journey context or findings
      // This requires looking at the job to get the domain being scanned
      if (jobId) {
        try {
          const job = await storage.getJob(jobId);
          if (job) {
            const journey = await storage.getJourney(job.journeyId);
            if (journey && journey.params.credentialId) {
              // Extract domain from credentials if available
              const credential = await storage.getCredential(journey.params.credentialId);
              if (credential && credential.domain) {
                domain = credential.domain;
              }
            } else if (journey && journey.params.domain) {
              // Use domain from journey params if available
              domain = journey.params.domain;
            }
          }
        } catch (error) {
          console.log(`⚠️  AD Hygiene: Erro ao buscar domínio do job ${jobId}:`, error);
        }
      }
      
      // Fallback: try to extract from target field patterns
      if (!domain && finding.target) {
        // Look for FQDN patterns like "gruppenhomologia.local"
        if (finding.target.includes('.') && !finding.target.startsWith('CN=')) {
          // Looks like FQDN
          domain = finding.target;
        }
      }
    }
    
    // Don't proceed if we don't have a valid domain
    if (!domain || domain === 'unknown') {
      console.log(`⚠️  AD Hygiene: Não foi possível identificar o domínio para vinculação`);
      return null;
    }
    
    // Normalize domain name to lowercase for consistent matching
    const normalizedDomain = domain.toLowerCase();
    console.log(`🔍 AD Hygiene: Buscando host do domínio '${normalizedDomain}'`);
    
    // Get all domain hosts and find matching one
    const domainHosts = await storage.getHosts({ type: 'domain' });
    
    // Try exact match first, then partial matches
    const matchingDomain = domainHosts.find(h => {
      const hostName = h.name.toLowerCase();
      const searchDomain = normalizedDomain;
      
      // Exact match
      if (hostName === searchDomain) return true;
      
      // Check aliases for exact match
      if (h.aliases?.some(alias => alias.toLowerCase() === searchDomain)) return true;
      
      // For NetBIOS vs FQDN matching
      const hostParts = hostName.split('.');
      const searchParts = searchDomain.split('.');
      
      // If one is NetBIOS and other is FQDN, compare base names
      if (hostParts.length !== searchParts.length) {
        const hostBase = hostParts[0];
        const searchBase = searchParts[0];
        return hostBase === searchBase;
      }
      
      return false;
    });
    
    if (matchingDomain) {
      console.log(`✅ AD Hygiene: Host de domínio encontrado: ${matchingDomain.name}`);
    } else {
      console.log(`❌ AD Hygiene: Nenhum host de domínio encontrado para '${normalizedDomain}'`);
    }
    
    return matchingDomain || null;
  }

  /**
   * Processes threats after a journey completes
   * Implements automatic closure and reactivation logic
   */
  async processJourneyCompletion(jobId: string): Promise<void> {
    try {
      console.log(`🔄 Processing journey completion for job ${jobId}`);
      
      const job = await storage.getJob(jobId);
      if (!job) {
        console.log(`⚠️  Job ${jobId} not found`);
        return;
      }

      const journey = await storage.getJourney(job.journeyId);
      if (!journey) {
        console.log(`⚠️  Journey ${job.journeyId} not found`);
        return;
      }

      // Check if there are previous completed jobs for this journey - skip closure on first run
      const previousJobs = await storage.getJobsByJourneyId(job.journeyId);
      const completedPreviousJobs = previousJobs.filter(j => j.id !== jobId && j.status === 'completed');
      
      if (completedPreviousJobs.length === 0) {
        console.log(`🆕 CLOSURE_METRICS: First-run detected for journey ${job.journeyId} - skipping auto-closure (previousJobsCount: 0, currentJobId: ${jobId})`);
        return;
      }

      // Get all open threats related to this asset/journey type
      const openThreats = await storage.listOpenThreatsByJourney(job.journeyId, journey.type);
      
      let skippedCurrentJobCount = 0;
      let closedCount = 0;
      let reactivatedCount = 0;
      
      console.log(`📊 CLOSURE_METRICS: Journey ${job.journeyId} analysis - openThreats: ${openThreats.length}, previousJobsCount: ${completedPreviousJobs.length}, currentJobId: ${jobId}`);

      // For each threat, check if it should be automatically closed or reactivated
      for (const threat of openThreats) {
        const result = await this.processReactivationLogic(threat, job, journey);
        if (result === 'skipped_current_job') {
          skippedCurrentJobCount++;
        } else if (result === 'closed') {
          closedCount++;
        } else if (result === 'reactivated') {
          reactivatedCount++;
        }
      }
      
      console.log(`✅ CLOSURE_METRICS: Journey ${job.journeyId} completed - skippedCurrentJob: ${skippedCurrentJobCount}, closed: ${closedCount}, reactivated: ${reactivatedCount}, processed: ${openThreats.length}`);

      console.log(`✅ Journey completion processing finished for job ${jobId}`);
    } catch (error) {
      console.error(`❌ Error processing journey completion for job ${jobId}:`, error);
    }
  }

  /**
   * Processes reactivation logic for specific threat based on journey results
   * Returns action taken for metrics: 'skipped_current_job' | 'closed' | 'reactivated' | 'no_action'
   */
  private async processReactivationLogic(threat: Threat, job: any, journey: any): Promise<string> {
    try {
      // CRITICAL: Never process threats from the current job to prevent immediate closure
      if (threat.jobId === job.id) {
        console.log(`⏰ GUARD: Skipping threat from current job: ${threat.title} (threatJobId: ${threat.jobId}, currentJobId: ${job.id})`);
        return 'skipped_current_job';
      }
      
      const threatFound = await this.isThreatStillPresent(threat, job, journey);
      console.log(`🔍 Threat ${threat.id} (${threat.title}) from job ${threat.jobId}: found=${threatFound}, status=${threat.status}`);
      
      switch (threat.status) {
        case 'investigating':
          // Threats under investigation remain in investigating status regardless of findings
          console.log(`🔍 LIFECYCLE: Threat ${threat.id} remains under investigation`);
          return 'no_action';
        
        case 'accepted_risk':
          // Threats with accepted risk should not be auto-closed or reactivated
          console.log(`🔒 LIFECYCLE: Threat ${threat.id} has accepted risk status - no automatic action`);
          return 'no_action';
          
        case 'mitigated':
          if (threatFound) {
            // Mitigated threat found again - reopen it
            await this.reactivateThreat(threat.id, 'Ameaça mitigada foi reencontrada durante nova varredura');
            console.log(`🔄 LIFECYCLE: Mitigated threat ${threat.id} reactivated - found again`);
            return 'reactivated';
          } else {
            // Mitigated threat not found - close it
            await this.closeThreatAutomatically(threat.id, 'Ameaça mitigada não foi reencontrada - considerada resolvida');
            console.log(`✅ LIFECYCLE: Mitigated threat ${threat.id} automatically closed - not found`);
            return 'closed';
          }
          break;
          
        case 'hibernated':
          if (threatFound) {
            // Hibernated threat found again - reopen it
            await this.reactivateThreat(threat.id, 'Ameaça hibernada foi reencontrada durante nova varredura');
            console.log(`🔄 LIFECYCLE: Hibernated threat ${threat.id} reactivated - found again`);
            return 'reactivated';
          }
          // If hibernated and not found, it remains hibernated until date expires
          break;
          
        case 'open':
          if (!threatFound) {
            // SAFE AUTO-CLOSURE: Only close threats that weren't found in new scan and are from previous jobs
            console.log(`🔒 LIFECYCLE: Closing open threat ${threat.id} from job ${threat.jobId} - not found in current job ${job.id}`);
            await this.closeThreatAutomatically(threat.id, 'Ameaça não foi reencontrada durante nova varredura (possível higienização)');
            console.log(`✅ LIFECYCLE: Open threat ${threat.id} automatically closed - not found (possible cleanup/remediation)`);
            return 'closed';
          }
          break;
      }
      return 'no_action';
    } catch (error) {
      console.error(`❌ Error processing reactivation logic for threat ${threat.id}:`, error);
      return 'error';
    }
  }

  /**
   * Checks if a threat is still present based on journey results
   */
  private async isThreatStillPresent(threat: Threat, job: any, journey: any): Promise<boolean> {
    // This is a simplified implementation - in a real system, you would
    // need to match the threat's evidence against the new findings
    
    // For now, we'll implement a basic correlation using correlationKey
    if (!threat.correlationKey) {
      return false; // Can't correlate without a key
    }

    try {
      // Get job results
      const jobResults = await storage.getJobResult(job.id);
      if (!jobResults || !jobResults.artifacts?.findings) {
        return false;
      }

      // Look for the same correlation key in the new findings
      const findings = Array.isArray(jobResults.artifacts.findings) ? jobResults.artifacts.findings : [];
      const matchingFinding = findings.find((finding: any) => {
        if (finding.correlationKey === threat.correlationKey) {
          return true;
        }
        
        // Additional correlation logic based on threat category
        switch (threat.category) {
          case 'port_exposure':
            return finding.type === 'port' && 
                   finding.port === threat.evidence?.port &&
                   finding.target === threat.evidence?.host;
                   
          case 'vulnerability':
            return finding.type === 'vulnerability' &&
                   finding.template === threat.evidence?.templateId;
                   
          case 'ad_misconfiguration':
          case 'ad_vulnerability':
          case 'ad_hygiene':
            return finding.type?.startsWith('ad_') &&
                   finding.name === threat.title;
                   
          case 'edr_failure':
            return finding.type === 'edr_test' &&
                   finding.hostname === threat.evidence?.hostname &&
                   finding.eicarRemoved === false;
                   
          default:
            return false;
        }
      });

      return !!matchingFinding;
    } catch (error) {
      console.error(`❌ Error checking threat presence for threat ${threat.id}:`, error);
      return false;
    }
  }

  /**
   * Reactivates a threat (changes status to open)
   */
  private async reactivateThreat(threatId: string, justification: string): Promise<void> {
    await this.updateThreatStatus(threatId, 'open', justification, 'system');
  }

  /**
   * Automatically closes a threat
   */
  private async closeThreatAutomatically(threatId: string, reason: string): Promise<void> {
    await this.updateThreatStatus(threatId, 'closed', reason, 'system');
  }

  /**
   * Updates threat status with history tracking
   */
  private async updateThreatStatus(threatId: string, newStatus: 'open' | 'investigating' | 'mitigated' | 'closed' | 'hibernated', justification: string, changedBy: string, hibernatedUntil?: Date): Promise<void> {
    const threat = await storage.getThreat(threatId);
    if (!threat) {
      throw new Error(`Threat ${threatId} not found`);
    }

    // Create status history entry
    await storage.createThreatStatusHistory({
      threatId,
      fromStatus: threat.status,
      toStatus: newStatus,
      justification,
      hibernatedUntil: hibernatedUntil || null,
      changedBy,
    });

    // Update threat
    await storage.updateThreat(threatId, {
      status: newStatus,
      statusChangedBy: changedBy,
      statusChangedAt: new Date(),
      statusJustification: justification,
      hibernatedUntil: hibernatedUntil || null,
    });

    // Recalculate host risk score after status change
    if (threat.hostId) {
      await this.recalculateHostRiskScore(threat.hostId).catch(err => 
        console.error(`⚠️ Erro ao recalcular escore de risco do host ${threat.hostId}:`, err)
      );
    }
  }

  /**
   * Activates hibernated threats that have passed their hibernation date
   */
  async activateHibernatedThreats(): Promise<void> {
    try {
      console.log(`🕒 Checking for hibernated threats to activate`);
      
      const now = new Date();
      const threats = await storage.getThreats();
      
      const hibernatedThreats = threats.filter(threat => 
        threat.status === 'hibernated' && 
        threat.hibernatedUntil && 
        new Date(threat.hibernatedUntil) <= now
      );

      console.log(`📊 Found ${hibernatedThreats.length} hibernated threats to activate`);

      for (const threat of hibernatedThreats) {
        await this.reactivateThreat(
          threat.id, 
          `Ameaça reativada automaticamente - período de hibernação expirou em ${threat.hibernatedUntil}`
        );
        console.log(`🔄 Hibernated threat ${threat.id} automatically reactivated`);
      }

      if (hibernatedThreats.length > 0) {
        console.log(`✅ Activated ${hibernatedThreats.length} hibernated threats`);
      }
    } catch (error) {
      console.error(`❌ Error activating hibernated threats:`, error);
    }
  }

  /**
   * Periodically checks and activates hibernated threats
   * Should be called by a scheduler
   */
  async startHibernationMonitor(): Promise<void> {
    // Check every hour for hibernated threats
    setInterval(async () => {
      await this.activateHibernatedThreats();
    }, 60 * 60 * 1000); // 1 hour

    // Initial check
    await this.activateHibernatedThreats();
  }

  /**
   * Calculate risk score for a host based on associated threats
   * Uses CVSS-based methodology with two metrics:
   * - riskScore: 0-100 classification based on highest severity
   * - rawScore: Sum of weighted threat scores (CVSS base values)
   */
  async calculateHostRiskScore(hostId: string): Promise<{ 
    riskScore: number; 
    rawScore: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  }> {
    try {
      // Get all threats for this host
      const threats = await storage.getThreats();
      const hostThreats = threats.filter(t => t.hostId === hostId);

      // Count threats by severity
      const severityCounts = {
        critical: hostThreats.filter(t => t.severity === 'critical').length,
        high: hostThreats.filter(t => t.severity === 'high').length,
        medium: hostThreats.filter(t => t.severity === 'medium').length,
        low: hostThreats.filter(t => t.severity === 'low').length,
      };

      // CVSS base scores for each severity
      const cvssScores = {
        critical: 10.0,
        high: 8.5,
        medium: 5.5,
        low: 2.5,
      };

      // Calculate raw score (sum of weighted threats)
      const rawScore = Math.round(
        severityCounts.critical * cvssScores.critical +
        severityCounts.high * cvssScores.high +
        severityCounts.medium * cvssScores.medium +
        severityCounts.low * cvssScores.low
      );

      // Calculate risk score (0-100) based on CVSS intervals
      let riskScore = 0;

      if (severityCounts.critical > 0) {
        // Critical threats present: 90-100 range
        riskScore = Math.min(100, 90 + (severityCounts.critical * 2));
      } else if (severityCounts.high > 0) {
        // High threats present: 70-89 range
        riskScore = Math.min(89, 70 + (severityCounts.high * 3));
      } else if (severityCounts.medium > 0) {
        // Medium threats present: 40-69 range
        riskScore = Math.min(69, 40 + (severityCounts.medium * 5));
      } else if (severityCounts.low > 0) {
        // Low threats present: 10-39 range
        riskScore = Math.min(39, 10 + (severityCounts.low * 5));
      } else {
        // No threats: 0-9 range (minimal risk)
        riskScore = 0;
      }

      return { 
        riskScore, 
        rawScore,
        criticalCount: severityCounts.critical,
        highCount: severityCounts.high,
        mediumCount: severityCounts.medium,
        lowCount: severityCounts.low,
      };
    } catch (error) {
      console.error(`❌ Error calculating risk score for host ${hostId}:`, error);
      return { riskScore: 0, rawScore: 0, criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0 };
    }
  }

  /**
   * Recalculate and update risk scores for a specific host
   */
  async recalculateHostRiskScore(hostId: string): Promise<void> {
    try {
      const { riskScore, rawScore, criticalCount, highCount, mediumCount, lowCount } = await this.calculateHostRiskScore(hostId);
      
      // Update host risk scores
      await storage.updateHost(hostId, { riskScore, rawScore });
      
      // Save snapshot to history for trend analysis
      await storage.createHostRiskHistory({
        hostId,
        riskScore,
        rawScore,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
      });
      
      console.log(`✅ Updated risk scores for host ${hostId}: riskScore=${riskScore}, rawScore=${rawScore}`);
    } catch (error) {
      console.error(`❌ Error recalculating risk score for host ${hostId}:`, error);
    }
  }

  /**
   * Recalculate risk scores for all hosts
   */
  async recalculateAllHostRiskScores(): Promise<void> {
    try {
      const hosts = await storage.getHosts();
      console.log(`🔄 Recalculating risk scores for ${hosts.length} hosts...`);
      
      for (const host of hosts) {
        await this.recalculateHostRiskScore(host.id);
      }
      
      console.log(`✅ Recalculated risk scores for all hosts`);
    } catch (error) {
      console.error(`❌ Error recalculating all host risk scores:`, error);
    }
  }
}

export const threatEngine = new ThreatEngineService();
