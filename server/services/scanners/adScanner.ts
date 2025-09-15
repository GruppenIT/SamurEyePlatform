import { Client } from 'ldapts';
import { spawn } from 'child_process';
import dns from 'dns';
import { promisify } from 'util';

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
    port?: number
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

      // 3. Análises de higiene
      const userAnalysis = await this.analyzeUsers();
      const groupAnalysis = await this.analyzeGroups();
      const computerAnalysis = await this.analyzeComputers();
      const policyAnalysis = await this.analyzePolicies();
      const configAnalysis = await this.analyzeConfiguration();

      findings.push(...userAnalysis);
      findings.push(...groupAnalysis);
      findings.push(...computerAnalysis);
      findings.push(...policyAnalysis);
      findings.push(...configAnalysis);

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
      // Permitir LDAP na porta 389 quando especificamente solicitado
      const isLdap389 = url === `ldap://${dcHost}:389` && port === 389;
      
      // Em produção, bloquear LDAP não criptografado EXCETO quando porta 389 for especificada
      if (!allowInsecure && url.startsWith('ldap://') && !isLdap389) {
        console.warn('Conexão LDAP não criptografada bloqueada em ambiente de produção');
        continue;
      }
      
      // Avisar sobre uso da porta 389
      if (isLdap389) {
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

        // Construir DN do usuário
        const userDN = username.includes('@') 
          ? username 
          : `${username}@${domain}`;

        await this.client.bind(userDN, password);
        console.log(`Conectado com sucesso via ${url}`);
        
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

    throw new Error(`Falha ao conectar em todas as URLs LDAP. ${!allowInsecure ? 'Apenas LDAPS é permitido em produção. ' : ''}Último erro: ${lastError?.message}`);
  }

  /**
   * Analisa usuários do AD
   */
  private async analyzeUsers(): Promise<ADFinding[]> {
    const findings: ADFinding[] = [];

    if (!this.client) return findings;

    try {
      // Buscar usuários com problemas de segurança
      const searchResults = await this.searchLDAP('(objectClass=user)', [
        'cn', 'sAMAccountName', 'userAccountControl', 'pwdLastSet',
        'lastLogon', 'adminCount', 'memberOf'
      ]);

      let usersWithPasswordNeverExpires = 0;
      let inactiveUsers = 0;
      let adminUsers = 0;
      let usersWithOldPasswords = 0;

      const now = Date.now();
      const sixMonthsAgo = now - (6 * 30 * 24 * 60 * 60 * 1000);

      for (const user of searchResults) {
        const userAccountControl = parseInt(user.userAccountControl?.[0] || '0');
        const pwdLastSet = this.convertFileTimeToDate(user.pwdLastSet?.[0]);
        const lastLogon = this.convertFileTimeToDate(user.lastLogon?.[0]);
        
        // Senha nunca expira
        if (userAccountControl & 0x10000) {
          usersWithPasswordNeverExpires++;
        }

        // Usuários inativos (sem login há 6 meses)
        if (lastLogon && lastLogon.getTime() < sixMonthsAgo) {
          inactiveUsers++;
        }

        // Usuários administrativos
        if (user.adminCount && parseInt(user.adminCount[0]) > 0) {
          adminUsers++;
        }

        // Senhas antigas (mais de 90 dias)
        if (pwdLastSet && (now - pwdLastSet.getTime()) > (90 * 24 * 60 * 60 * 1000)) {
          usersWithOldPasswords++;
        }
      }

      // Gerar findings baseados na análise
      if (usersWithPasswordNeverExpires > 0) {
        findings.push({
          type: 'ad_misconfiguration',
          target: 'Domain Users',
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
          target: 'Domain Users',
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
          target: 'Domain Users',
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
            target: groupName,
            name: 'Grupo Privilegiado com Muitos Membros',
            severity: 'high',
            category: 'groups',
            description: `Grupo ${groupName} possui ${members.length} membros (recomendado: máximo 5)`,
            evidence: { memberCount: members.length, members },
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
      const searchResults = await this.searchLDAP('(objectClass=computer)', [
        'cn', 'operatingSystem', 'operatingSystemVersion', 'lastLogon'
      ]);

      let oldSystems = 0;
      let inactiveComputers = 0;
      const now = Date.now();
      const threeMonthsAgo = now - (3 * 30 * 24 * 60 * 60 * 1000);

      for (const computer of searchResults) {
        const os = computer.operatingSystem?.[0] || '';
        const lastLogon = this.convertFileTimeToDate(computer.lastLogon?.[0]);

        // Sistemas operacionais antigos
        if (os.includes('Windows 7') || os.includes('Windows XP') || os.includes('Server 2008')) {
          oldSystems++;
        }

        // Computadores inativos
        if (lastLogon && lastLogon.getTime() < threeMonthsAgo) {
          inactiveComputers++;
        }
      }

      if (oldSystems > 0) {
        findings.push({
          type: 'ad_vulnerability',
          target: 'Domain Computers',
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
          target: 'Domain Computers',
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
   * Analisa políticas do AD
   */
  private async analyzePolicies(): Promise<ADFinding[]> {
    const findings: ADFinding[] = [];

    // Esta é uma implementação básica - em ambiente real seria necessário
    // acessar as GPOs e analisar configurações específicas
    findings.push({
      type: 'ad_hygiene',
      target: 'Group Policies',
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
            target: 'Domain Configuration',
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
            target: 'Domain Configuration',
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