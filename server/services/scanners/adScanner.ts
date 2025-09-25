import { Client } from 'ldapts';
import { spawn } from 'child_process';
import dns from 'dns';
import { promisify } from 'util';
import { settingsService } from '../settingsService';

const dnsResolve = promisify(dns.resolve);

export interface ADFinding {
  type: 'ad_hygiene' | 'ad_vulnerability' | 'ad_misconfiguration';
  target: string;
  name: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: 'users' | 'groups' | 'computers' | 'policies' | 'configuration';
  description: string;
  evidence?: any;
  recommendation?: string;
}

export class ADScanner {
  private client: Client | null = null;
  private readonly commonDCPorts = [389, 636, 3268, 3269]; // LDAP, LDAPS, Global Catalog
  private baseDN: string = '';
  private domain: string = '';

  /**
   * Escaneia higiene do Active Directory
   */
  async scanADHygiene(
    domain: string,
    username: string,
    password: string,
    port?: number,
    enabledAnalyses?: {
      enableUsers?: boolean;
      enableGroups?: boolean;
      enableComputers?: boolean;
      enablePolicies?: boolean;
      enableConfiguration?: boolean;
      enableDomainConfiguration?: boolean;
    }
  ): Promise<ADFinding[]> {
    console.log(`Iniciando análise de higiene AD para domínio ${domain}`);
    
    const findings: ADFinding[] = [];

    try {
      // 1. Descobrir controladores de domínio
      const domainControllers = await this.discoverDomainControllers(domain);
      console.log(`Encontrados ${domainControllers.length} controladores de domínio`);

      if (domainControllers.length === 0) {
        findings.push({
          type: 'ad_misconfiguration',
          target: domain,
          name: 'Nenhum Controlador de Domínio Encontrado',
          severity: 'critical',
          category: 'configuration',
          description: 'Não foi possível localizar controladores de domínio para o domínio especificado',
          recommendation: 'Verificar configuração DNS e conectividade de rede'
        });
        return findings;
      }

      // 2. Conectar ao Active Directory
      const dcHost = domainControllers[0];
      this.domain = domain;
      this.baseDN = this.buildBaseDN(domain);
      console.log(`📍 Usando base DN: ${this.baseDN}`);
      await this.connectToAD(dcHost, username, password, domain, port);

      // 3. Análises de higiene (execução sequencial para evitar problemas de concorrência LDAP)
      console.log('📊 Iniciando análises de higiene AD...');
      
      // Valores padrão se não especificado - habilitar todas as análises
      const analyses = {
        enableUsers: true,
        enableGroups: true,
        enableComputers: true,
        enablePolicies: true,
        enableConfiguration: true,
        enableDomainConfiguration: true,
        ...enabledAnalyses
      };
      
      if (analyses.enableUsers) {
        const userAnalysis = await this.analyzeUsers();
        console.log(`✅ Análise de usuários concluída: ${userAnalysis.length} achados`);
        findings.push(...userAnalysis);
      } else {
        console.log('⏭️ Análise de usuários pulada (desabilitada)');
      }
      
      if (analyses.enableGroups) {
        const groupAnalysis = await this.analyzeGroups();
        console.log(`✅ Análise de grupos concluída: ${groupAnalysis.length} achados`);
        findings.push(...groupAnalysis);
      } else {
        console.log('⏭️ Análise de grupos pulada (desabilitada)');
      }
      
      if (analyses.enableComputers) {
        const computerAnalysis = await this.analyzeComputers();
        console.log(`✅ Análise de computadores concluída: ${computerAnalysis.length} achados`);
        findings.push(...computerAnalysis);
      } else {
        console.log('⏭️ Análise de computadores pulada (desabilitada)');
      }
      
      if (analyses.enablePolicies) {
        const policyAnalysis = await this.analyzePolicies();
        console.log(`✅ Análise de políticas concluída: ${policyAnalysis.length} achados`);
        findings.push(...policyAnalysis);
      } else {
        console.log('⏭️ Análise de políticas pulada (desabilitada)');
      }
      
      if (analyses.enableConfiguration) {
        const configAnalysis = await this.analyzeConfiguration();
        console.log(`✅ Análise de configuração concluída: ${configAnalysis.length} achados`);
        findings.push(...configAnalysis);
      } else {
        console.log('⏭️ Análise de configuração pulada (desabilitada)');
      }
      
      if (analyses.enableDomainConfiguration) {
        const domainConfigAnalysis = await this.analyzeDomainConfiguration();
        console.log(`✅ Análise de configuração de domínio concluída: ${domainConfigAnalysis.length} achados`);
        findings.push(...domainConfigAnalysis);
      } else {
        console.log('⏭️ Análise de configuração de domínio pulada (desabilitada)');
      }

    } catch (error) {
      console.error('Erro durante análise AD:', error);
      const errorMessage = error instanceof Error ? error.message : String(error);
      findings.push({
        type: 'ad_vulnerability',
        target: domain,
        name: 'Falha na Conexão AD',
        severity: 'high',
        category: 'configuration',
        description: `Erro ao conectar ao Active Directory: ${errorMessage}`,
        recommendation: 'Verificar credenciais, conectividade e configuração do domínio'
      });
    } finally {
      if (this.client) {
        this.client.unbind();
        this.client = null;
      }
    }

    return findings;
  }

  /**
   * Descobre controladores de domínio via DNS
   */
  private async discoverDomainControllers(domain: string): Promise<string[]> {
    const controllers: string[] = [];

    try {
      // Tentar SRV record para localizar DCs
      const srvRecord = `_ldap._tcp.${domain}`;
      const records = await dnsResolve(srvRecord, 'SRV') as any[];
      
      for (const record of records) {
        controllers.push(record.name);
      }
    } catch (error) {
      console.log('SRV lookup falhou, tentando método alternativo');
    }

    // Fallback: testar hosts comuns
    if (controllers.length === 0) {
      const commonNames = [`dc.${domain}`, `dc01.${domain}`, `dc1.${domain}`, domain];
      
      for (const hostname of commonNames) {
        try {
          await dnsResolve(hostname, 'A');
          controllers.push(hostname);
        } catch {
          // Host não encontrado, continuar
        }
      }
    }

    return controllers;
  }

  /**
   * Mapeia códigos de erro específicos do AD
   */
  private mapADError(error: Error): { message: string; isCredentialError: boolean } {
    const errorStr = error.message;
    
    // Extrair código de dados do erro AD (formato: "data 532" ou "data 52e")
    const dataMatch = errorStr.match(/data\s+(\w+)/i);
    if (!dataMatch) {
      return { message: errorStr, isCredentialError: false };
    }
    
    const code = dataMatch[1].toLowerCase();
    const codeInt = parseInt(code, 16) || parseInt(code, 10);
    
    switch (codeInt) {
      case 525:
      case 0x525:
        return {
          message: "Usuário não encontrado no AD - verifique o nome de usuário",
          isCredentialError: true
        };
      case 0x52e:
        return {
          message: "Credenciais inválidas (usuário/senha incorretos) - verifique usuário e senha",
          isCredentialError: true
        };
      case 530:
      case 0x530:
        return {
          message: "Conta não permitida para login neste horário",
          isCredentialError: true
        };
      case 531:
      case 0x531:
        return {
          message: "Conta não permitida para login nesta estação de trabalho",
          isCredentialError: true
        };
      case 532:
      case 0x532:
        return {
          message: "SENHA EXPIRADA - A senha da conta precisa ser alterada no AD. Use uma conta de serviço com 'senha nunca expira' ou atualize a senha desta conta.",
          isCredentialError: true
        };
      case 533:
      case 0x533:
        return {
          message: "Conta desabilitada - habilite a conta no AD ou use uma conta ativa",
          isCredentialError: true
        };
      case 701:
      case 0x701:
        return {
          message: "Conta expirada - a conta passou da data de expiração configurada no AD",
          isCredentialError: true
        };
      case 773:
      case 0x773:
        return {
          message: "RESET DE SENHA OBRIGATÓRIO - O administrador marcou que a senha deve ser alterada no próximo login. Altere a senha no AD.",
          isCredentialError: true
        };
      case 775:
      case 0x775:
        return {
          message: "Conta bloqueada - desbloquear a conta no AD antes de tentar novamente",
          isCredentialError: true
        };
      default:
        return {
          message: `Erro de autenticação AD (código ${code}): ${errorStr}`,
          isCredentialError: true
        };
    }
  }

  /**
   * Gera diferentes formatos de bind para tentar autenticação
   */
  private generateBindFormats(username: string, domain: string): string[] {
    const formats: string[] = [];
    
    // Se já contém @, usar como está primeiro
    if (username.includes('@')) {
      formats.push(username);
    }
    
    // Tentar UPN (User Principal Name)
    if (!username.includes('@')) {
      formats.push(`${username}@${domain}`);
    }
    
    // Tentar Down-Level Logon Name (DOMAIN\user)
    const netbiosDomain = domain.split('.')[0].toUpperCase();
    const downLevelFormat = `${netbiosDomain}\\${username.replace(/@.*$/, '')}`;
    if (!formats.includes(downLevelFormat)) {
      formats.push(downLevelFormat);
    }
    
    // Tentar apenas o nome de usuário (para alguns cenários)
    const plainUsername = username.replace(/@.*$/, '');
    if (!formats.includes(plainUsername)) {
      formats.push(plainUsername);
    }
    
    return formats;
  }

  /**
   * Conecta ao Active Directory
   */
  private async connectToAD(
    dcHost: string,
    username: string,
    password: string,
    domain: string,
    port?: number
  ): Promise<void> {
    let urls: string[];
    
    // Se uma porta específica foi fornecida, usar apenas ela
    if (port) {
      if (port === 389) {
        // Porta 389 = LDAP simples conforme solicitado pelo usuário
        urls = [`ldap://${dcHost}:389`];
        console.log('🔧 Usando protocolo LDAP na porta 389 conforme especificado');
      } else if (port === 636) {
        // Porta 636 = LDAPS
        urls = [`ldaps://${dcHost}:636`];
      } else {
        // Porta customizada - tentar LDAP simples
        urls = [`ldap://${dcHost}:${port}`];
      }
    } else {
      // Comportamento padrão: priorizar LDAPS por segurança
      urls = [
        `ldaps://${dcHost}:636`,
        `ldap://${dcHost}:389`
      ];
    }

    let lastError: Error | null = null;
    const allowInsecure = process.env.NODE_ENV === 'development';

    for (const url of urls) {
      // Permitir LDAP quando especificamente solicitado pelo usuário
      const isLdapExplicitlyRequested = port && url.startsWith('ldap://');
      
      // Em produção, bloquear LDAP não criptografado APENAS quando não foi explicitamente solicitado
      if (!allowInsecure && url.startsWith('ldap://') && !isLdapExplicitlyRequested) {
        console.warn('Conexão LDAP não criptografada bloqueada em ambiente de produção (não foi explicitamente solicitada)');
        continue;
      }
      
      // Avisar sobre uso de LDAP não criptografado
      if (url.startsWith('ldap://') && port === 389) {
        console.log('⚠️  Usando protocolo LDAP não criptografado na porta 389 conforme especificado');
      }

      try {
        console.log(`Tentando conectar via ${url}`);
        
        this.client = new Client({
          url,
          timeout: 10000,
          connectTimeout: 10000,
          // Habilitar validação de certificado em produção
          tlsOptions: url.startsWith('ldaps://') ? {
            rejectUnauthorized: process.env.NODE_ENV === 'production',
            minVersion: 'TLSv1.2',
          } : undefined,
        });

        // Tentar diferentes formatos de bind
        const bindFormats = this.generateBindFormats(username, domain);
        let bindError: Error | null = null;
        let successfulFormat = '';
        
        for (const bindDN of bindFormats) {
          try {
            console.log(`Tentando bind com formato: ${bindDN.includes('\\') ? bindDN.replace(/\\/g, '\\') : bindDN}`);
            await this.client.bind(bindDN, password);
            successfulFormat = bindDN;
            console.log(`✅ Conectado com sucesso via ${url} usando formato: ${bindDN.includes('\\') ? bindDN.replace(/\\/g, '\\') : bindDN}`);
            break;
          } catch (err) {
            bindError = err instanceof Error ? err : new Error(String(err));
            console.log(`Bind falhou para ${bindDN}: ${bindError.message}`);
          }
        }
        
        // Se todos os formatos falharam, lançar erro detalhado
        if (!successfulFormat && bindError) {
          const { message: detailedMessage, isCredentialError } = this.mapADError(bindError);
          throw new Error(`Falha na autenticação AD: ${detailedMessage}`);
        }
        
        // Avisar sobre conexão insegura
        if (url.startsWith('ldap://')) {
          console.warn('⚠️  ATENÇÃO: Conexão LDAP não criptografada em uso - não recomendado para produção');
        }
        
        return;
        
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        console.log(`Bind falhou em ${url}: ${lastError.message}`);
        
        if (this.client) {
          try {
            await this.client.unbind();
          } catch {
            // Ignorar erros de unbind
          }
          this.client = null;
        }
      }
    }

    throw new Error(`Falha ao conectar em todas as URLs LDAP tentadas. Último erro: ${lastError?.message}`);
  }

  /**
   * Analisa usuários do AD
   */
  private async analyzeUsers(): Promise<ADFinding[]> {
    const findings: ADFinding[] = [];

    if (!this.client) return findings;

    try {
      // Obter configurações do sistema
      const settings = await settingsService.getADHygieneSettings();
      
      // Buscar usuários com problemas de segurança
      const searchResults = await this.searchLDAP('(objectClass=user)', [
        'cn', 'sAMAccountName', 'userAccountControl', 'pwdLastSet',
        'lastLogon', 'adminCount', 'memberOf'
      ]);

      let usersWithPasswordNeverExpires = 0;
      let inactiveUsers = 0;
      let adminUsers = 0;
      let usersWithOldPasswords = 0;
      const domainAdminsWithOldPasswords: any[] = [];
      const specificInactiveUsers: any[] = [];

      const now = Date.now();
      const inactiveLimitMs = now - (settings.adInactiveUserLimitDays * 24 * 60 * 60 * 1000);
      const passwordAgeLimitMs = settings.adPasswordAgeLimitDays * 24 * 60 * 60 * 1000;

      // Primeiro, obter membros do grupo Domain Admins
      const domainAdminMembers = await this.getGroupMembers('Domain Admins');

      for (const user of searchResults) {
        const userAccountControl = parseInt(user.userAccountControl?.[0] || '0');
        const pwdLastSet = this.convertFileTimeToDate(user.pwdLastSet?.[0]);
        const lastLogon = this.convertFileTimeToDate(user.lastLogon?.[0]);
        const username = user.sAMAccountName?.[0] || user.cn?.[0] || 'Unknown';
        
        // Verificar se usuário está habilitado (bit 2 = ACCOUNTDISABLE)
        const isEnabled = !(userAccountControl & 0x0002);
        
        // Verificar se é Domain Admin
        const isDomainAdmin = domainAdminMembers.some(dn => 
          dn.toLowerCase().includes(`cn=${username.toLowerCase()}`)
        );

        // Senha nunca expira
        if (userAccountControl & 0x10000) {
          usersWithPasswordNeverExpires++;
        }

        // Usuários inativos - usando configuração do sistema
        if (lastLogon && lastLogon.getTime() < inactiveLimitMs && isEnabled) {
          inactiveUsers++;
          specificInactiveUsers.push({
            username,
            lastLogon: lastLogon.toISOString(),
            daysSinceLastLogon: Math.floor((now - lastLogon.getTime()) / (24 * 60 * 60 * 1000))
          });
        }

        // Usuários administrativos
        if (user.adminCount && parseInt(user.adminCount[0]) > 0) {
          adminUsers++;
        }

        // Senhas antigas - usando configuração do sistema
        if (pwdLastSet && (now - pwdLastSet.getTime()) > passwordAgeLimitMs) {
          usersWithOldPasswords++;
          
          // Verificação específica para Domain Admins - AMEAÇA CRÍTICA
          if (isDomainAdmin && isEnabled) {
            const daysSincePasswordChange = Math.floor((now - pwdLastSet.getTime()) / (24 * 60 * 60 * 1000));
            domainAdminsWithOldPasswords.push({
              username,
              daysSincePasswordChange,
              lastPasswordSet: pwdLastSet.toISOString(),
              lastLogon: lastLogon?.toISOString() || 'Never'
            });
          }
        }
      }

      // Gerar ameaças específicas para Domain Admins com senhas antigas
      for (const admin of domainAdminsWithOldPasswords) {
        findings.push({
          type: 'ad_vulnerability',
          target: this.domain, // Use domain as target for all AD findings
          name: 'Domain Admin com Senha Crítica Expirada',
          severity: 'critical',
          category: 'users',
          description: `Domain Admin "${admin.username}" não troca a senha há ${admin.daysSincePasswordChange} dias (limite: ${settings.adPasswordAgeLimitDays} dias)`,
          evidence: {
            username: admin.username,
            daysSincePasswordChange: admin.daysSincePasswordChange,
            lastPasswordSet: admin.lastPasswordSet,
            lastLogon: admin.lastLogon,
            passwordAgeLimit: settings.adPasswordAgeLimitDays,
            groupMembership: 'Domain Admins'
          },
          recommendation: 'Forçar troca imediata de senha para conta Domain Admin'
        });
      }

      // Gerar ameaças específicas para usuários inativos
      for (const inactiveUser of specificInactiveUsers) {
        findings.push({
          type: 'ad_hygiene',
          target: this.domain, // Use domain as target for all AD findings
          name: 'Usuário Inativo Detectado',
          severity: 'low',
          category: 'users',
          description: `Usuário "${inactiveUser.username}" inativo há ${inactiveUser.daysSinceLastLogon} dias (limite: ${settings.adInactiveUserLimitDays} dias)`,
          evidence: {
            username: inactiveUser.username,
            daysSinceLastLogon: inactiveUser.daysSinceLastLogon,
            lastLogon: inactiveUser.lastLogon,
            inactiveUserLimit: settings.adInactiveUserLimitDays
          },
          recommendation: 'Revisar e considerar desabilitar conta inativa'
        });
      }

      // Gerar findings baseados na análise
      if (usersWithPasswordNeverExpires > 0) {
        findings.push({
          type: 'ad_misconfiguration',
          target: this.domain, // Use domain as target for all AD findings
          name: 'Usuários com Senhas que Nunca Expiram',
          severity: 'medium',
          category: 'users',
          description: `${usersWithPasswordNeverExpires} usuários configurados com senhas que nunca expiram`,
          evidence: { count: usersWithPasswordNeverExpires },
          recommendation: 'Configurar política de expiração de senhas para todos os usuários'
        });
      }

      if (inactiveUsers > 0) {
        findings.push({
          type: 'ad_hygiene',
          target: this.domain, // Use domain as target for all AD findings
          name: 'Usuários Inativos Identificados',
          severity: 'low',
          category: 'users',
          description: `${inactiveUsers} usuários sem login há mais de 6 meses`,
          evidence: { count: inactiveUsers },
          recommendation: 'Revisar e desabilitar contas de usuários inativos'
        });
      }

      if (usersWithOldPasswords > 0) {
        findings.push({
          type: 'ad_vulnerability',
          target: this.domain, // Use domain as target for all AD findings
          name: 'Usuários com Senhas Antigas',
          severity: 'medium',
          category: 'users',
          description: `${usersWithOldPasswords} usuários com senhas não alteradas há mais de 90 dias`,
          evidence: { count: usersWithOldPasswords },
          recommendation: 'Forçar troca de senhas antigas e implementar política de rotação'
        });
      }

    } catch (error) {
      console.error('Erro ao analisar usuários:', error);
    }

    return findings;
  }

  /**
   * Analisa grupos do AD
   */
  private async analyzeGroups(): Promise<ADFinding[]> {
    const findings: ADFinding[] = [];

    if (!this.client) return findings;

    try {
      // Buscar grupos privilegiados
      const privilegedGroups = [
        'Domain Admins',
        'Enterprise Admins',
        'Schema Admins',
        'Administrators'
      ];

      for (const groupName of privilegedGroups) {
        const members = await this.getGroupMembers(groupName);
        
        if (members.length > 5) {
          findings.push({
            type: 'ad_misconfiguration',
            target: this.domain, // Use domain as target for all AD findings
            name: 'Grupo Privilegiado com Muitos Membros',
            severity: 'high',
            category: 'groups',
            description: `Grupo ${groupName} possui ${members.length} membros (recomendado: máximo 5)`,
            evidence: { memberCount: members.length, members, groupName },
            recommendation: 'Revisar e reduzir membros de grupos privilegiados'
          });
        }
      }

    } catch (error) {
      console.error('Erro ao analisar grupos:', error);
    }

    return findings;
  }

  /**
   * Analisa computadores do AD
   */
  private async analyzeComputers(): Promise<ADFinding[]> {
    const findings: ADFinding[] = [];

    if (!this.client) return findings;

    try {
      // Obter configurações do sistema
      const settings = await settingsService.getADHygieneSettings();
      
      const searchResults = await this.searchLDAP('(objectClass=computer)', [
        'cn', 'operatingSystem', 'operatingSystemVersion', 'lastLogon', 'dNSHostName'
      ]);

      let oldSystems = 0;
      let inactiveComputers = 0;
      const specificInactiveComputers: any[] = [];
      const specificObsoleteComputers: any[] = [];
      
      const now = Date.now();
      const inactiveLimitMs = now - (settings.adComputerInactiveDays * 24 * 60 * 60 * 1000);

      for (const computer of searchResults) {
        const os = computer.operatingSystem?.[0] || '';
        const lastLogon = this.convertFileTimeToDate(computer.lastLogon?.[0]);
        const computerName = computer.cn?.[0] || computer.dNSHostName?.[0] || 'Unknown';

        // Sistemas operacionais antigos
        if (os.includes('Windows 7') || os.includes('Windows XP') || os.includes('Server 2008') || os.includes('Server 2003')) {
          oldSystems++;
          specificObsoleteComputers.push({
            computerName,
            operatingSystem: os,
            osVersion: computer.operatingSystemVersion?.[0] || 'Unknown'
          });
        }

        // Computadores inativos - usando configuração do sistema
        if (lastLogon && lastLogon.getTime() < inactiveLimitMs) {
          inactiveComputers++;
          const daysSinceLastLogon = Math.floor((now - lastLogon.getTime()) / (24 * 60 * 60 * 1000));
          specificInactiveComputers.push({
            computerName,
            lastLogon: lastLogon.toISOString(),
            daysSinceLastLogon
          });
        }
      }

      // Gerar ameaças específicas para computadores inativos
      for (const inactiveComp of specificInactiveComputers) {
        findings.push({
          type: 'ad_hygiene',
          target: this.domain, // Use domain as target for all AD findings
          name: 'Computador Inativo no Domínio',
          severity: 'low',
          category: 'computers',
          description: `Computador "${inactiveComp.computerName}" inativo há ${inactiveComp.daysSinceLastLogon} dias (limite: ${settings.adComputerInactiveDays} dias)`,
          evidence: {
            computerName: inactiveComp.computerName,
            daysSinceLastLogon: inactiveComp.daysSinceLastLogon,
            lastLogon: inactiveComp.lastLogon,
            inactiveComputerLimit: settings.adComputerInactiveDays
          },
          recommendation: 'Revisar e considerar remover computador inativo do domínio'
        });
      }

      // Gerar ameaças específicas para sistemas obsoletos
      for (const obsoleteComp of specificObsoleteComputers) {
        findings.push({
          type: 'ad_vulnerability',
          target: this.domain, // Use domain as target for all AD findings
          name: 'Sistema Operacional Obsoleto',
          severity: 'medium',
          category: 'computers',
          description: `Computador "${obsoleteComp.computerName}" executa SO obsoleto: ${obsoleteComp.operatingSystem}`,
          evidence: {
            computerName: obsoleteComp.computerName,
            operatingSystem: obsoleteComp.operatingSystem,
            osVersion: obsoleteComp.osVersion
          },
          recommendation: 'Atualizar sistema operacional para versão suportada'
        });
      }

      if (oldSystems > 0) {
        findings.push({
          type: 'ad_vulnerability',
          target: this.domain, // Use domain as target for all AD findings
          name: 'Sistemas Operacionais Obsoletos',
          severity: 'high',
          category: 'computers',
          description: `${oldSystems} computadores executando sistemas operacionais sem suporte`,
          evidence: { count: oldSystems },
          recommendation: 'Atualizar ou substituir sistemas operacionais obsoletos'
        });
      }

      if (inactiveComputers > 0) {
        findings.push({
          type: 'ad_hygiene',
          target: this.domain, // Use domain as target for all AD findings
          name: 'Computadores Inativos',
          severity: 'low',
          category: 'computers',
          description: `${inactiveComputers} computadores sem atividade há mais de 3 meses`,
          evidence: { count: inactiveComputers },
          recommendation: 'Remover objetos de computadores inativos do domínio'
        });
      }

    } catch (error) {
      console.error('Erro ao analisar computadores:', error);
    }

    return findings;
  }

  /**
   * Descobre workstations do domínio para teste EDR/AV
   */
  async discoverWorkstations(domain: string, username: string, password: string, port?: number): Promise<string[]> {
    console.log(`Descobrindo workstations do domínio ${domain} para teste EDR/AV`);
    
    const workstations: string[] = [];

    try {
      // 1. Descobrir controladores de domínio
      const domainControllers = await this.discoverDomainControllers(domain);
      console.log(`Encontrados ${domainControllers.length} controladores de domínio`);

      if (domainControllers.length === 0) {
        console.error('Nenhum controlador de domínio encontrado');
        return workstations;
      }

      // 2. Conectar ao Active Directory
      const dcHost = domainControllers[0];
      this.domain = domain;
      this.baseDN = this.buildBaseDN(domain);
      console.log(`📍 Usando base DN: ${this.baseDN}`);
      await this.connectToAD(dcHost, username, password, domain, port);

      if (!this.client) {
        console.error('Falha ao conectar ao Active Directory');
        return workstations;
      }

      // 3. Buscar contas de computador ativas
      console.log('🔍 Buscando contas de computador no domínio...');
      
      // Filtro para buscar computadores ativos (não desabilitados)
      // userAccountControl & 2 = 0 significa que a conta não está desabilitada
      const filter = '(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))';
      
      const computers = await this.searchLDAP(filter, [
        'cn',
        'dNSHostName',
        'operatingSystem',
        'operatingSystemVersion',
        'lastLogonTimestamp',
        'userAccountControl'
      ]);

      console.log(`Encontrados ${computers.length} computadores no domínio`);

      for (const computer of computers) {
        const computerName = computer.cn?.[0];
        const dnsHostName = computer.dNSHostName?.[0];
        const operatingSystem = computer.operatingSystem?.[0] || '';
        const lastLogonTimestamp = computer.lastLogonTimestamp?.[0];

        // Incluir tanto workstations quanto servidores para teste EDR/AV
        const isServer = operatingSystem.toLowerCase().includes('server');
        if (isServer) {
          console.log(`✅ Servidor encontrado: ${computerName} (${operatingSystem})`);
        }

        // Verificar se teve logon recente (últimos 30 dias)
        let isActive = true;
        if (lastLogonTimestamp) {
          const lastLogon = this.convertFileTimeToDate(lastLogonTimestamp);
          if (lastLogon) {
            const thirtyDaysAgo = new Date();
            thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
            isActive = lastLogon > thirtyDaysAgo;
          }
        }

        if (!isActive) {
          console.log(`Pulando workstation inativa: ${computerName}`);
          continue;
        }

        // Usar dNSHostName se disponível, senão usar cn
        const hostName = dnsHostName || computerName;
        if (hostName) {
          workstations.push(hostName);
          if (!isServer) {
            console.log(`✅ Workstation encontrada: ${hostName} (${operatingSystem})`);
          }
        }
      }

      console.log(`Total de computadores descobertos: ${workstations.length} (workstations + servidores)`);

      // Se não encontrou computadores, log detalhado para troubleshooting
      if (workstations.length === 0) {
        console.warn(`⚠️ Nenhum computador ativo encontrado no domínio ${domain}`);
        console.warn('Verifique: 1) Conectividade LDAP, 2) Permissões da credencial, 3) Computadores ativos no domínio');
      }

    } catch (error) {
      console.error('Erro ao descobrir workstations:', error);
    } finally {
      // Desconectar do LDAP
      if (this.client) {
        try {
          await this.client.unbind();
          this.client = null;
        } catch (unbindError) {
          console.error('Erro ao desconectar do LDAP:', unbindError);
        }
      }
    }

    return workstations;
  }

  /**
   * Analisa políticas do AD
   */
  private async analyzePolicies(): Promise<ADFinding[]> {
    const findings: ADFinding[] = [];

    // Esta é uma implementação básica - em ambiente real seria necessário
    // acessar as GPOs e analisar configurações específicas
    findings.push({
      type: 'ad_hygiene',
      target: this.domain, // Use domain as target for all AD findings
      name: 'Análise de Políticas Limitada',
      severity: 'low',
      category: 'policies',
      description: 'Análise básica de políticas implementada. Análise completa requer ferramentas específicas',
      recommendation: 'Implementar análise detalhada de GPOs com ferramentas especializadas'
    });

    return findings;
  }

  /**
   * Analisa configuração geral do AD
   */
  private async analyzeConfiguration(): Promise<ADFinding[]> {
    const findings: ADFinding[] = [];

    if (!this.client) return findings;

    try {
      // Verificar configuração do domínio
      const domainConfig = await this.searchLDAP('(objectClass=domain)', [
        'lockoutDuration', 'lockoutThreshold', 'maxPwdAge', 'minPwdAge', 'minPwdLength'
      ]);

      if (domainConfig.length > 0) {
        const config = domainConfig[0];
        
        // Verificar política de senhas
        const minPwdLength = parseInt(config.minPwdLength?.[0] || '0');
        if (minPwdLength < 8) {
          findings.push({
            type: 'ad_vulnerability',
            target: this.domain, // Use domain as target for all AD findings
            name: 'Política de Senha Fraca',
            severity: 'medium',
            category: 'configuration',
            description: `Comprimento mínimo de senha configurado para ${minPwdLength} caracteres (recomendado: 8+)`,
            evidence: { currentMinLength: minPwdLength },
            recommendation: 'Configurar comprimento mínimo de senha para pelo menos 8 caracteres'
          });
        }

        // Verificar política de bloqueio
        const lockoutThreshold = parseInt(config.lockoutThreshold?.[0] || '0');
        if (lockoutThreshold === 0) {
          findings.push({
            type: 'ad_vulnerability',
            target: this.domain, // Use domain as target for all AD findings
            name: 'Política de Bloqueio Desabilitada',
            severity: 'medium',
            category: 'configuration',
            description: 'Política de bloqueio de conta não está configurada',
            recommendation: 'Configurar política de bloqueio após tentativas de login falhadas'
          });
        }
      }

    } catch (error) {
      console.error('Erro ao analisar configuração:', error);
    }

    return findings;
  }

  /**
   * Analisa configuração específica do domínio
   */
  private async analyzeDomainConfiguration(): Promise<ADFinding[]> {
    const findings: ADFinding[] = [];

    if (!this.client) return findings;

    try {
      // Obter configurações do sistema
      const settings = await settingsService.getADHygieneSettings();
      
      // Análise de grupos privilegiados com muitos membros
      const privilegedGroups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators'];
      
      for (const groupName of privilegedGroups) {
        try {
          const members = await this.getGroupMembers(groupName);
          
          if (members.length > settings.adMaxPrivilegedGroupMembers) {
            findings.push({
              type: 'ad_vulnerability',
              target: this.domain, // Use domain as target for all AD findings
              name: 'Grupo Privilegiado com Muitos Membros',
              severity: 'medium',
              category: 'groups',
              description: `Grupo "${groupName}" possui ${members.length} membros (limite recomendado: ${settings.adMaxPrivilegedGroupMembers})`,
              evidence: {
                groupName,
                memberCount: members.length,
                maxRecommendedMembers: settings.adMaxPrivilegedGroupMembers,
                members: members.slice(0, 10) // Primeiros 10 membros para evidência
              },
              recommendation: 'Revisar necessidade de todos os membros em grupos privilegiados'
            });
          }
        } catch (error) {
          console.error(`Erro ao analisar grupo ${groupName}:`, error);
        }
      }

      // Verificar configurações de domínio avançadas
      const domainRoot = await this.searchLDAP('(objectClass=domain)', [
        'distinguishedName', 'lockoutDuration', 'lockoutThreshold', 'maxPwdAge', 
        'minPwdAge', 'minPwdLength', 'pwdHistoryLength', 'pwdProperties'
      ]);

      if (domainRoot.length > 0) {
        const config = domainRoot[0];

        // Verificar histórico de senhas
        const pwdHistoryLength = parseInt(config.pwdHistoryLength?.[0] || '0');
        if (pwdHistoryLength < 12) {
          findings.push({
            type: 'ad_vulnerability',
            target: this.domain, // Use domain as target for all AD findings
            name: 'Histórico de Senhas Insuficiente',
            severity: 'low',
            category: 'configuration',
            description: `Histórico de senhas configurado para ${pwdHistoryLength} senhas (recomendado: 12+)`,
            evidence: { currentHistoryLength: pwdHistoryLength },
            recommendation: 'Configurar histórico de senhas para pelo menos 12 senhas anteriores'
          });
        }

        // Verificar complexidade de senhas
        const pwdProperties = parseInt(config.pwdProperties?.[0] || '0');
        const complexityEnabled = (pwdProperties & 0x1) !== 0;
        
        if (!complexityEnabled) {
          findings.push({
            type: 'ad_vulnerability',
            target: this.domain, // Use domain as target for all AD findings
            name: 'Complexidade de Senha Desabilitada',
            severity: 'high',
            category: 'configuration',
            description: 'Política de complexidade de senhas não está habilitada',
            evidence: { pwdProperties, complexityEnabled },
            recommendation: 'Habilitar política de complexidade de senhas no domínio'
          });
        }

        // Verificar idade máxima das senhas
        const maxPwdAge = parseInt(config.maxPwdAge?.[0] || '0');
        if (maxPwdAge === 0) {
          findings.push({
            type: 'ad_vulnerability',
            target: this.domain, // Use domain as target for all AD findings
            name: 'Senhas Sem Expiração',
            severity: 'medium',
            category: 'configuration',
            description: 'Senhas do domínio configuradas para nunca expirar',
            evidence: { maxPwdAge },
            recommendation: 'Configurar idade máxima para senhas (recomendado: 90 dias)'
          });
        }
      }

      // Verificar Trusts de domínio (se aplicável)
      try {
        const trusts = await this.searchLDAP('(objectClass=trustedDomain)', [
          'cn', 'trustDirection', 'trustType', 'trustAttributes'
        ]);

        for (const trust of trusts) {
          const trustName = trust.cn?.[0] || 'Unknown Trust';
          const trustDirection = parseInt(trust.trustDirection?.[0] || '0');
          
          // Trust bidirecional pode representar maior risco
          if (trustDirection === 3) { // Bidirectional trust
            findings.push({
              type: 'ad_hygiene',
              target: this.domain, // Use domain as target for all AD findings
              name: 'Trust Bidirecional Detectado',
              severity: 'low',
              category: 'configuration',
              description: `Trust bidirecional configurado com domínio "${trustName}"`,
              evidence: {
                trustName,
                trustDirection,
                trustType: trust.trustType?.[0],
                trustAttributes: trust.trustAttributes?.[0]
              },
              recommendation: 'Revisar necessidade de trusts bidirecionais e considerar torná-los unidirecionais'
            });
          }
        }
      } catch (error) {
        // Trusts podem não estar acessíveis dependendo dos privilégios
        console.log('Informações de trust não disponíveis com as credenciais atuais');
      }

    } catch (error) {
      console.error('Erro na análise de configuração do domínio:', error);
    }

    return findings;
  }

  /**
   * Constrói o DN base a partir do domínio
   */
  private buildBaseDN(domain: string): string {
    // Converter "gruppen.com.br" para "DC=gruppen,DC=com,DC=br"
    return domain.split('.').map(part => `DC=${part}`).join(',');
  }

  /**
   * Executa busca LDAP
   */
  private async searchLDAP(filter: string, attributes: string[], customBaseDN?: string): Promise<any[]> {
    if (!this.client) return [];

    const searchBase = customBaseDN || this.baseDN;
    console.log(`🔍 Buscando em: ${searchBase} com filtro: ${filter}`);

    try {
      const { searchEntries } = await this.client.search(searchBase, {
        filter,
        scope: 'sub',
        attributes
      });

      // Converter formato dos resultados para manter compatibilidade
      return searchEntries.map(entry => {
        const attributes: any = {};
        for (const [key, value] of Object.entries(entry)) {
          if (key !== 'dn' && key !== 'controls') {
            attributes[key] = Array.isArray(value) ? value : [value];
          }
        }
        return attributes;
      });
      
    } catch (error) {
      console.error('Erro na busca LDAP:', error);
      return [];
    }
  }

  /**
   * Obtém membros de um grupo
   */
  private async getGroupMembers(groupName: string): Promise<string[]> {
    try {
      const results = await this.searchLDAP(`(cn=${groupName})`, ['member']);
      
      if (results.length > 0 && results[0].member) {
        return results[0].member;
      }
    } catch (error) {
      console.error(`Erro ao buscar membros do grupo ${groupName}:`, error);
    }

    return [];
  }

  /**
   * Converte FileTime do Windows para Date
   */
  private convertFileTimeToDate(fileTimeString?: string): Date | null {
    if (!fileTimeString) return null;

    try {
      const fileTime = parseInt(fileTimeString);
      if (fileTime === 0) return null;

      // FileTime é o número de intervalos de 100 nanossegundos desde 1º janeiro de 1601
      const windowsEpoch = new Date('1601-01-01T00:00:00Z').getTime();
      const unixTime = windowsEpoch + (fileTime / 10000);
      
      return new Date(unixTime);
    } catch {
      return null;
    }
  }
}

export const adScanner = new ADScanner();