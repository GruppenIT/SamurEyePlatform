import { spawn } from 'child_process';
import dns from 'dns';
import { promisify } from 'util';

const dnsResolve = promisify(dns.resolve);

export interface ADFinding {
  type: 'ad_hygiene' | 'ad_vulnerability' | 'ad_misconfiguration';
  target: string;
  name: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: 'users' | 'groups' | 'computers' | 'policies' | 'configuration' | 'kerberos' | 'shares' | 'inactive_accounts';
  description: string;
  evidence?: any;
  recommendation?: string;
}

interface PowerShellExecutionResult {
  success: boolean;
  stdout: string;
  stderr: string;
  exitCode: number;
}

interface ADSecurityTest {
  id: string;
  nome: string;
  powershell: string;
  severidade: 'critical' | 'high' | 'medium' | 'low';
  description?: string;
  recommendation?: string;
}

interface ADSecurityCategories {
  configuracoes_criticas?: boolean;
  gerenciamento_contas?: boolean;
  kerberos_delegacao?: boolean;
  compartilhamentos_gpos?: boolean;
  politicas_configuracao?: boolean;
  contas_inativas?: boolean;
}

export class ADScanner {
  private readonly commonDCPorts = [389, 636, 3268, 3269];
  private baseDN: string = '';
  private domain: string = '';

  /**
   * Escaneia segurança do Active Directory usando PowerShell via WinRM
   */
  async scanADSecurity(
    domain: string,
    username: string,
    password: string,
    dcHost?: string,
    enabledCategories?: ADSecurityCategories
  ): Promise<ADFinding[]> {
    console.log(`🔍 Iniciando análise de segurança AD para domínio ${domain}`);
    
    const findings: ADFinding[] = [];
    this.domain = domain;
    this.baseDN = this.buildBaseDN(domain);

    try {
      // 1. Descobrir DC se não especificado (com retry logic para DC secundário)
      let targetDC = dcHost;
      let dcList: string[] = [];
      
      if (!targetDC) {
        const domainControllers = await this.discoverDomainControllers(domain);
        console.log(`✅ Encontrados ${domainControllers.length} controladores de domínio via DNS`);

        if (domainControllers.length === 0) {
          findings.push({
            type: 'ad_misconfiguration',
            target: domain,
            name: 'Nenhum Controlador de Domínio Encontrado',
            severity: 'critical',
            category: 'configuration',
            description: 'Não foi possível localizar controladores de domínio para o domínio especificado via DNS',
            recommendation: 'Verificar configuração DNS e conectividade de rede. Especifique o IP do DC manualmente.'
          });
          return findings;
        }
        dcList = domainControllers;
        targetDC = domainControllers[0];
      } else {
        // dcHost is guaranteed to be defined here since we're in the else block
        dcList = [dcHost!];
      }

      console.log(`🎯 Usando DC primário: ${targetDC}`);

      // 2. Categorias habilitadas (padrão: todas)
      const categories: ADSecurityCategories = {
        configuracoes_criticas: true,
        gerenciamento_contas: true,
        kerberos_delegacao: true,
        compartilhamentos_gpos: true,
        politicas_configuracao: true,
        contas_inativas: true,
        ...enabledCategories
      };

      // 3. Executar testes por categoria
      if (categories.configuracoes_criticas) {
        console.log('🔴 Executando testes: Configurações Críticas...');
        const criticalFindings = await this.testConfiguracoesCriticas(targetDC, domain, username, password);
        findings.push(...criticalFindings);
        console.log(`✅ Configurações Críticas: ${criticalFindings.length} achados`);
      }

      if (categories.gerenciamento_contas) {
        console.log('👥 Executando testes: Gerenciamento de Contas...');
        const accountFindings = await this.testGerenciamentoContas(targetDC, domain, username, password);
        findings.push(...accountFindings);
        console.log(`✅ Gerenciamento de Contas: ${accountFindings.length} achados`);
      }

      if (categories.kerberos_delegacao) {
        console.log('🎫 Executando testes: Kerberos e Delegação...');
        const kerberosFindings = await this.testKerberosDelegacao(targetDC, domain, username, password);
        findings.push(...kerberosFindings);
        console.log(`✅ Kerberos e Delegação: ${kerberosFindings.length} achados`);
      }

      if (categories.compartilhamentos_gpos) {
        console.log('📂 Executando testes: Compartilhamentos e GPOs...');
        const shareFindings = await this.testCompartilhamentosGPOs(targetDC, domain, username, password);
        findings.push(...shareFindings);
        console.log(`✅ Compartilhamentos e GPOs: ${shareFindings.length} achados`);
      }

      if (categories.politicas_configuracao) {
        console.log('⚙️  Executando testes: Políticas e Configuração...');
        const policyFindings = await this.testPoliticasConfiguracao(targetDC, domain, username, password);
        findings.push(...policyFindings);
        console.log(`✅ Políticas e Configuração: ${policyFindings.length} achados`);
      }

      if (categories.contas_inativas) {
        console.log('💤 Executando testes: Contas Inativas...');
        const inactiveFindings = await this.testContasInativas(targetDC, domain, username, password);
        findings.push(...inactiveFindings);
        console.log(`✅ Contas Inativas: ${inactiveFindings.length} achados`);
      }

      console.log(`✅ Análise concluída: ${findings.length} achados totais`);
      return findings;

    } catch (error: any) {
      console.error('❌ Erro na análise AD Security:', error);
      findings.push({
        type: 'ad_misconfiguration',
        target: domain,
        name: 'Erro na Execução da Análise',
        severity: 'critical',
        category: 'configuration',
        description: `Falha ao executar análise de segurança: ${error.message}`,
        recommendation: 'Verificar credenciais, conectividade e permissões WinRM no controlador de domínio'
      });
      return findings;
    }
  }

  /**
   * Executa comando PowerShell remotamente via WinRM
   */
  private async executePowerShell(
    dcHost: string,
    domain: string,
    username: string,
    password: string,
    script: string
  ): Promise<PowerShellExecutionResult> {
    return new Promise((resolve) => {
      // Substituir placeholders no script
      const processedScript = script
        .replace(/\$baseDN/g, this.baseDN)
        .replace(/\$domainName/g, domain);

      // Construir comando PowerShell com credencial
      const fullScript = `
$securePassword = ConvertTo-SecureString '${password.replace(/'/g, "''")}' -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential('${domain}\\${username}', $securePassword)
Invoke-Command -ComputerName ${dcHost} -Credential $credential -ScriptBlock {
  ${processedScript}
}
`;

      // Executar PowerShell Core (pwsh) - funciona em Linux/Windows
      const powershell = spawn('pwsh', [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        fullScript
      ]);

      let stdout = '';
      let stderr = '';

      powershell.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      powershell.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      powershell.on('close', (code) => {
        resolve({
          success: code === 0,
          stdout,
          stderr,
          exitCode: code || 0
        });
      });

      // Timeout de 5 minutos por comando
      setTimeout(() => {
        powershell.kill();
        resolve({
          success: false,
          stdout,
          stderr: stderr + '\nTimeout: Comando excedeu 5 minutos',
          exitCode: -1
        });
      }, 300000);
    });
  }

  /**
   * Testes da Categoria: Configurações Críticas
   */
  private async testConfiguracoesCriticas(
    dcHost: string,
    domain: string,
    username: string,
    password: string
  ): Promise<ADFinding[]> {
    const findings: ADFinding[] = [];

    const tests: ADSecurityTest[] = [
      {
        id: 'dc_print_spooler',
        nome: 'Controlador de domínio com spooler de impressão ativado (PrintNightmare)',
        powershell: 'Get-Service -Name Spooler | Select-Object Name, Status | ConvertTo-Json',
        severidade: 'critical',
        description: 'O serviço Print Spooler está ativo no controlador de domínio, tornando-o vulnerável ao ataque PrintNightmare (CVE-2021-34527)',
        recommendation: 'Stop-Service -Name Spooler -Force; Set-Service -Name Spooler -StartupType Disabled'
      },
      {
        id: 'ldap_anonymous',
        nome: 'LDAP anônimo e sem assinatura permitido',
        powershell: `Get-ADObject -Identity 'CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$baseDN' -Properties dSHeuristics | Select-Object -Property dSHeuristics | ConvertTo-Json`,
        severidade: 'critical',
        description: 'O atributo dSHeuristics está configurado, potencialmente permitindo LDAP anônimo ou sem assinatura',
        recommendation: 'Remover o valor do atributo dSHeuristics via ADSI Edit'
      },
      {
        id: 'smbv1_enabled',
        nome: 'Sessão SMBv1 fraca permitida',
        powershell: 'Get-WindowsFeature -Name FS-SMB1 | Select-Object Name, InstallState | ConvertTo-Json',
        severidade: 'critical',
        description: 'O protocolo SMBv1 está habilitado, permitindo ataques como EternalBlue e WannaCry',
        recommendation: 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart'
      },
      {
        id: 'krbtgt_weak',
        nome: 'Conta KRBTGT fraca (Golden Ticket)',
        powershell: 'Get-ADUser -Identity krbtgt -Property PasswordLastSet | Select-Object Name, PasswordLastSet | ConvertTo-Json',
        severidade: 'critical',
        description: 'A senha da conta KRBTGT não foi alterada recentemente, permitindo ataques Golden Ticket',
        recommendation: 'Realizar reset de senha da conta KRBTGT usando script oficial da Microsoft'
      },
      {
        id: 'schema_permissions',
        nome: 'Alterações de permissões padrão na partição do esquema',
        powershell: `(Get-Acl 'AD:CN=Schema,CN=Configuration,$baseDN').Access | Where-Object {$_.IdentityReference -notmatch 'SYSTEM|Administrators|Schema Admins|Enterprise Admins'} | Select-Object IdentityReference, ActiveDirectoryRights | ConvertTo-Json`,
        severidade: 'critical',
        description: 'Foram detectadas permissões não padrão na partição do esquema do Active Directory',
        recommendation: 'Remover usuários/grupos não privilegiados das permissões do Schema via ADSI Edit'
      }
    ];

    for (const test of tests) {
      try {
        const result = await this.executePowerShell(dcHost, domain, username, password, test.powershell);
        
        if (result.success && result.stdout.trim()) {
          const hasIssue = this.analyzeTestResult(test.id, result.stdout);
          
          if (hasIssue) {
            findings.push({
              type: this.getTypeForTest(test.id),
              target: domain,
              name: test.nome,
              severity: test.severidade,
              category: 'configuration',
              description: test.description || `Teste ${test.nome} identificou problemas de segurança`,
              recommendation: test.recommendation || 'Revisar configuração conforme documentação de segurança Microsoft',
              evidence: {
                testId: test.id,
                output: result.stdout.substring(0, 1000) // Limitar tamanho
              }
            });
          }
        }
      } catch (error: any) {
        console.error(`❌ Erro no teste ${test.id}:`, error.message);
      }
    }

    return findings;
  }

  /**
   * Testes da Categoria: Gerenciamento de Contas
   */
  private async testGerenciamentoContas(
    dcHost: string,
    domain: string,
    username: string,
    password: string
  ): Promise<ADFinding[]> {
    const findings: ADFinding[] = [];

    const tests: ADSecurityTest[] = [
      {
        id: 'privileged_spn',
        nome: 'Usuários privilegiados com Service Principal Names (SPN) definidos',
        powershell: `Get-ADUser -Filter * -Properties servicePrincipalName, MemberOf | Where-Object {$_.servicePrincipalName -and ($_.MemberOf -match 'Admins')} | Select-Object Name, SamAccountName, servicePrincipalName | ConvertTo-Json`,
        severidade: 'high',
        description: 'Usuários com privilégios administrativos possuem SPNs configurados, vulneráveis a Kerberoasting',
        recommendation: 'Remover SPNs de contas administrativas ou usar contas de serviço gerenciadas (gMSA)'
      },
      {
        id: 'password_never_expires',
        nome: 'Contas com senha sem expiração',
        powershell: 'Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Property Name, PasswordNeverExpires | Select-Object Name, PasswordNeverExpires | ConvertTo-Json',
        severidade: 'high',
        description: 'Foram identificadas contas com senha configurada para nunca expirar',
        recommendation: 'Desabilitar a opção "Senha nunca expira" e implementar política de rotação de senhas'
      },
      {
        id: 'preauth_disabled',
        nome: 'Contas com pré-autenticação desativada',
        powershell: 'Get-ADUser -Filter * -Properties UserAccountControl | Where-Object {$_.UserAccountControl -band 0x400000} | Select-Object Name, SamAccountName | ConvertTo-Json',
        severidade: 'high',
        description: 'Contas com pré-autenticação Kerberos desativada, vulneráveis a AS-REP Roasting',
        recommendation: 'Habilitar pré-autenticação Kerberos para todas as contas'
      },
      {
        id: 'admin_account_weak',
        nome: 'Conta de administrador padrão fraca',
        powershell: `Get-ADUser -Identity 'Administrator' -Property PasswordLastSet, PasswordNeverExpires, LastLogonTimestamp | Select-Object Name, PasswordLastSet, PasswordNeverExpires, @{Name='LastLogon';Expression={[DateTime]::FromFileTime($_.LastLogonTimestamp)}} | ConvertTo-Json`,
        severidade: 'high',
        description: 'A conta Administrator padrão apresenta configurações de segurança fracas',
        recommendation: 'Configurar senha forte (15+ caracteres), alterar regularmente, e usar apenas quando necessário'
      },
      {
        id: 'dc_password_old',
        nome: 'Controladores de domínio com senha não alterada recentemente',
        powershell: 'Get-ADDomainController -Filter * | ForEach-Object { Get-ADComputer -Identity $_.Name -Property PasswordLastSet | Select-Object Name, PasswordLastSet } | ConvertTo-Json',
        severidade: 'high',
        description: 'Controladores de domínio com senhas de conta de computador não alteradas recentemente',
        recommendation: 'Investigar motivo da não rotação automática de senha e forçar reset se necessário'
      },
      {
        id: 'low_primary_group_id',
        nome: 'Contas com ID de grupo primário (PrimaryGroupID) menor que 1000',
        powershell: 'Get-ADUser -Filter {primaryGroupId -lt 1000} -Property primaryGroupId | Select-Object Name, primaryGroupId | ConvertTo-Json',
        severidade: 'high',
        description: 'Usuários com PrimaryGroupID baixo podem ter privilégios ocultos ou pertencer a grupos críticos',
        recommendation: 'Revisar contas identificadas e validar se a configuração é intencional'
      },
      {
        id: 'admin_count_set',
        nome: 'Atributo AdminCount definido para usuários padrão',
        powershell: 'Get-ADUser -Filter {admincount -gt 0} -Properties adminCount, MemberOf | Where-Object {-not ($_.MemberOf -match "Admins")} | Select-Object Name, SamAccountName, adminCount | ConvertTo-Json',
        severidade: 'high',
        description: 'Usuários não-admin com AdminCount=1 podem ter sido admins no passado e manter permissões residuais',
        recommendation: 'Revisar e remover AdminCount de usuários que não são mais administradores'
      },
      {
        id: 'trust_relationships',
        nome: 'Relações de confiança de alto risco',
        powershell: 'Get-ADTrust -Filter * | Select-Object Name, TrustType, TrustDirection, ForestTransitive | ConvertTo-Json',
        severidade: 'high',
        description: 'Foram identificadas relações de confiança de domínio que podem representar riscos de segurança',
        recommendation: 'Revisar necessidade de cada trust e remover os desnecessários ou não documentados'
      },
      {
        id: 'hidden_privileged_sid',
        nome: 'Contas com SID privilegiado oculto',
        powershell: 'Get-ADUser -Filter {admincount -gt 0} -Properties adminCount, sidHistory | Where-Object {$_.sidHistory} | Select-Object Name, SamAccountName, adminCount, sidHistory | ConvertTo-Json',
        severidade: 'high',
        description: 'Contas com SIDs privilegiados no atributo sidHistory podem ter privilégios ocultos',
        recommendation: 'Investigar e remover sidHistory não autorizado'
      },
      {
        id: 'pre_win2000_access',
        nome: 'Contas usando controle de acesso compatível com pré-Windows 2000',
        powershell: `Get-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access' -Recursive | Select-Object Name, SamAccountName | ConvertTo-Json`,
        severidade: 'medium',
        description: 'O grupo "Pre-Windows 2000 Compatible Access" contém membros, permitindo autenticação legada insegura',
        recommendation: 'Remover membros do grupo se não houver sistemas legados que dependam dele'
      }
    ];

    for (const test of tests) {
      try {
        const result = await this.executePowerShell(dcHost, domain, username, password, test.powershell);
        
        if (result.success && result.stdout.trim()) {
          const hasIssue = this.analyzeTestResult(test.id, result.stdout);
          
          if (hasIssue) {
            findings.push({
              type: this.getTypeForTest(test.id),
              target: domain,
              name: test.nome,
              severity: test.severidade,
              category: 'users',
              description: test.description || `Teste ${test.nome} identificou problemas de segurança`,
              recommendation: test.recommendation || 'Revisar configuração conforme melhores práticas de segurança',
              evidence: {
                testId: test.id,
                output: result.stdout.substring(0, 1000)
              }
            });
          }
        }
      } catch (error: any) {
        console.error(`❌ Erro no teste ${test.id}:`, error.message);
      }
    }

    return findings;
  }

  /**
   * Testes da Categoria: Kerberos e Delegação
   */
  private async testKerberosDelegacao(
    dcHost: string,
    domain: string,
    username: string,
    password: string
  ): Promise<ADFinding[]> {
    const findings: ADFinding[] = [];

    const tests: ADSecurityTest[] = [
      {
        id: 'krbtgt_rbcd',
        nome: 'Conta KRBTGT com delegação restrita baseada em recursos (RBCD) habilitada',
        powershell: `Get-ADUser -Identity 'krbtgt' -Property 'msDS-AllowedToDelegateTo' | Select-Object SamAccountName, 'msDS-AllowedToDelegateTo' | ConvertTo-Json`,
        severidade: 'high',
        description: 'A conta KRBTGT possui delegação configurada, o que nunca deveria ocorrer',
        recommendation: 'Remover imediatamente qualquer configuração de delegação da conta KRBTGT'
      },
      {
        id: 'gmsa_read_permissions',
        nome: 'Usuários padrão com permissão para leitura de senha de GMSA',
        powershell: 'Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword | Where-Object {$_.PrincipalsAllowedToRetrieveManagedPassword} | Select-Object Name, PrincipalsAllowedToRetrieveManagedPassword | ConvertTo-Json',
        severidade: 'high',
        description: 'Usuários não-autorizados têm permissão para ler senhas de contas de serviço gerenciadas (gMSA)',
        recommendation: 'Restringir PrincipalsAllowedToRetrieveManagedPassword apenas aos sistemas necessários'
      },
      {
        id: 'kerberos_vulnerabilities',
        nome: 'Avaliação de vulnerabilidades do Kerberos',
        powershell: `Get-ADUser -Filter * -Properties 'msDS-SupportedEncryptionTypes' | Where-Object {$_.'msDS-SupportedEncryptionTypes' -lt 16} | Select-Object Name, SamAccountName, 'msDS-SupportedEncryptionTypes' | ConvertTo-Json`,
        severidade: 'medium',
        description: 'Contas configuradas com tipos de criptografia Kerberos fracos (DES, RC4)',
        recommendation: 'Configurar suporte apenas para AES128 e AES256 (msDS-SupportedEncryptionTypes = 24 ou 28)'
      },
      {
        id: 'kerberos_rbcd_computers',
        nome: 'Comprometimento de conta de computador via delegação restrita baseada em recursos do Kerberos (RBCD)',
        powershell: 'Get-ADComputer -Filter * -Properties PrincipalsAllowedToDelegateToAccount | Where-Object {$_.PrincipalsAllowedToDelegateToAccount} | Select-Object Name, SamAccountName, PrincipalsAllowedToDelegateToAccount | ConvertTo-Json',
        severidade: 'medium',
        description: 'Computadores com delegação RBCD configurada podem ser comprometidos para obter acesso a outros sistemas',
        recommendation: 'Revisar e remover delegações desnecessárias, usar delegação restrita quando possível'
      },
      {
        id: 'rodc_kdc_access',
        nome: 'Direitos de acesso perigosos na conta KDC do RODC',
        powershell: `Get-ADDomainController -Filter {IsReadOnly -eq $true} | ForEach-Object { Get-ADComputer -Identity $_.Name -Properties 'msDS-RevealedUsers' | Select-Object Name, 'msDS-RevealedUsers' } | ConvertTo-Json`,
        severidade: 'high',
        description: 'Read-Only Domain Controllers com configurações de segurança inadequadas',
        recommendation: 'Revisar políticas de cache de credenciais e grupo "Allowed RODC Password Replication Group"'
      }
    ];

    for (const test of tests) {
      try {
        const result = await this.executePowerShell(dcHost, domain, username, password, test.powershell);
        
        if (result.success && result.stdout.trim()) {
          const hasIssue = this.analyzeTestResult(test.id, result.stdout);
          
          if (hasIssue) {
            findings.push({
              type: this.getTypeForTest(test.id),
              target: domain,
              name: test.nome,
              severity: test.severidade,
              category: 'configuration',
              description: test.description || `Teste ${test.nome} identificou problemas de segurança`,
              recommendation: test.recommendation || 'Revisar configuração de Kerberos conforme melhores práticas',
              evidence: {
                testId: test.id,
                output: result.stdout.substring(0, 1000)
              }
            });
          }
        }
      } catch (error: any) {
        console.error(`❌ Erro no teste ${test.id}:`, error.message);
      }
    }

    return findings;
  }

  /**
   * Testes da Categoria: Compartilhamentos e GPOs
   */
  private async testCompartilhamentosGPOs(
    dcHost: string,
    domain: string,
    username: string,
    password: string
  ): Promise<ADFinding[]> {
    const findings: ADFinding[] = [];

    const tests: ADSecurityTest[] = [
      {
        id: 'credentials_in_shares',
        nome: 'Coleta de credenciais a partir de compartilhamentos de domínio',
        powershell: `$paths = @('\\\\$domainName\\SYSVOL', '\\\\$domainName\\NETLOGON'); foreach ($path in $paths) { Get-ChildItem -Path $path -Recurse -Include *.ps1, *.vbs, *.bat, *.xml -ErrorAction SilentlyContinue | Select-String -Pattern 'password', 'pwd', 'pass', 'senha', 'segredo', 'credencial' -ErrorAction SilentlyContinue | Select-Object Path, LineNumber, Line } | ConvertTo-Json`,
        severidade: 'high',
        description: 'Foram encontradas credenciais ou palavras-chave relacionadas em arquivos nos compartilhamentos SYSVOL/NETLOGON',
        recommendation: 'Remover credenciais hard-coded de scripts. Usar credenciais gerenciadas ou Group Policy Preferences com criptografia AES256'
      },
      {
        id: 'sysvol_permissions',
        nome: 'Verificar objetos GPO sensíveis e permissões de arquivos',
        powershell: `$path = '\\\\$domainName\\SYSVOL'; $acl = Get-Acl -Path $path; $acl.Access | Where-Object {$_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|Authenticated Users|Server Operators|Enterprise Domain Controllers'} | Select-Object IdentityReference, FileSystemRights, AccessControlType | ConvertTo-Json`,
        severidade: 'high',
        description: 'Permissões não-padrão detectadas no compartilhamento SYSVOL',
        recommendation: 'Revisar e remover permissões excessivas. Manter apenas: Domain Admins, Enterprise Admins, SYSTEM, Authenticated Users (Read)'
      },
      {
        id: 'smb_signing_weak',
        nome: 'Assinatura SMB fraca',
        powershell: 'Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature | ConvertTo-Json',
        severidade: 'medium',
        description: 'Assinatura SMB não está configurada como obrigatória, permitindo ataques man-in-the-middle',
        recommendation: 'Habilitar "RequireSecuritySignature=True" via GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options'
      }
    ];

    for (const test of tests) {
      try {
        const result = await this.executePowerShell(dcHost, domain, username, password, test.powershell);
        
        if (result.success && result.stdout.trim()) {
          const hasIssue = this.analyzeTestResult(test.id, result.stdout);
          
          if (hasIssue) {
            findings.push({
              type: this.getTypeForTest(test.id),
              target: domain,
              name: test.nome,
              severity: test.severidade,
              category: 'policies',
              description: test.description || `Teste ${test.nome} identificou problemas de segurança`,
              recommendation: test.recommendation || 'Revisar permissões e configurações de compartilhamento',
              evidence: {
                testId: test.id,
                output: result.stdout.substring(0, 1000)
              }
            });
          }
        }
      } catch (error: any) {
        console.error(`❌ Erro no teste ${test.id}:`, error.message);
      }
    }

    return findings;
  }

  /**
   * Testes da Categoria: Políticas e Configuração
   */
  private async testPoliticasConfiguracao(
    dcHost: string,
    domain: string,
    username: string,
    password: string
  ): Promise<ADFinding[]> {
    const findings: ADFinding[] = [];

    const tests: ADSecurityTest[] = [
      {
        id: 'risky_uac_params',
        nome: 'Contas com parâmetros de controle de conta de usuário arriscados',
        powershell: 'Get-ADUser -Filter * -Property userAccountControl | Where-Object {($_.userAccountControl -band 0x10000) -or ($_.userAccountControl -band 0x80000)} | Select-Object Name, userAccountControl | ConvertTo-Json',
        severidade: 'high',
        description: 'Contas com flags UserAccountControl arriscadas (DONT_EXPIRE_PASSWORD, ENCRYPTED_TEXT_PWD_ALLOWED)',
        recommendation: 'Revisar e corrigir UserAccountControl. Valor padrão recomendado: 512'
      },
      {
        id: 'domain_functional_level',
        nome: 'Domínios com nível funcional desatualizado',
        powershell: 'Get-ADDomain | Select-Object DomainMode, DistinguishedName | ConvertTo-Json',
        severidade: 'medium',
        description: 'Nível funcional do domínio está desatualizado, perdendo recursos de segurança modernos',
        recommendation: 'Elevar nível funcional do domínio para a versão mais recente suportada'
      },
      {
        id: 'laps_not_enabled',
        nome: 'Solução LAPS não habilitada',
        powershell: `Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwd' -ResultSetSize 100 | Where-Object {$_.'ms-Mcs-AdmPwd' -eq $null} | Measure-Object | Select-Object Count | ConvertTo-Json`,
        severidade: 'medium',
        description: 'Microsoft LAPS não está configurado para gerenciar senhas de administrador local',
        recommendation: 'Implementar LAPS para rotação automática de senhas de administrador local'
      },
      {
        id: 'dns_admins_standard_users',
        nome: 'Contas de usuário padrão como administradores DNS',
        powershell: `Get-ADGroupMember -Identity 'DnsAdmins' -Recursive | Where-Object {$_.objectClass -eq 'user'} | Select-Object Name, SamAccountName | ConvertTo-Json`,
        severidade: 'medium',
        description: 'Usuários padrão são membros do grupo DnsAdmins, que tem privilégios elevados',
        recommendation: 'Remover usuários não-admin do grupo DnsAdmins'
      },
      {
        id: 'non_canonical_ace',
        nome: 'ACE não canônico em objetos',
        powershell: `$objects = Get-ADObject -Filter * -Properties nTSecurityDescriptor -ResultSetSize 1000; $nonCanonical = $objects | Where-Object {$_.nTSecurityDescriptor.AreAccessRulesCanonical -eq $false}; $nonCanonical | Select-Object DistinguishedName | ConvertTo-Json`,
        severidade: 'medium',
        description: 'Objetos com ACEs (Access Control Entries) em ordem não-canônica detectados',
        recommendation: 'Corrigir ordem das ACEs usando ferramentas administrativas ou scripts especializados'
      },
      {
        id: 'orphan_krbtgt_rodc',
        nome: 'Contas krbtgt de RODC órfãs',
        powershell: `Get-ADObject -Filter {(objectclass -eq 'user') -and (name -like 'krbtgt*')} -Properties 'msDS-KrbTgtLinkBl' | Where-Object {-not $_.'msDS-KrbTgtLinkBl'} | Select-Object Name, 'msDS-KrbTgtLinkBl' | ConvertTo-Json`,
        severidade: 'medium',
        description: 'Contas krbtgt órfãs de RODCs removidos permaneceram no domínio',
        recommendation: 'Remover contas krbtgt órfãs de RODCs que não existem mais'
      },
      {
        id: 'dsheuristics_dangerous',
        nome: 'Domínio com configuração de compatibilidade retroativa perigosa',
        powershell: `Get-ADObject -Identity 'CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$baseDN' -Properties dSHeuristics | Where-Object {$_.dSHeuristics} | Select-Object -ExpandProperty dSHeuristics | ConvertTo-Json`,
        severidade: 'medium',
        description: 'Atributo dSHeuristics configurado, potencialmente habilitando comportamentos legados inseguros',
        recommendation: 'Remover valor de dSHeuristics a menos que seja absolutamente necessário'
      }
    ];

    for (const test of tests) {
      try {
        const result = await this.executePowerShell(dcHost, domain, username, password, test.powershell);
        
        if (result.success && result.stdout.trim()) {
          const hasIssue = this.analyzeTestResult(test.id, result.stdout);
          
          if (hasIssue) {
            findings.push({
              type: this.getTypeForTest(test.id),
              target: domain,
              name: test.nome,
              severity: test.severidade,
              category: 'configuration',
              description: test.description || `Teste ${test.nome} identificou problemas de segurança`,
              recommendation: test.recommendation || 'Revisar e corrigir configuração do domínio',
              evidence: {
                testId: test.id,
                output: result.stdout.substring(0, 1000)
              }
            });
          }
        }
      } catch (error: any) {
        console.error(`❌ Erro no teste ${test.id}:`, error.message);
      }
    }

    return findings;
  }

  /**
   * Testes da Categoria: Contas Inativas
   */
  private async testContasInativas(
    dcHost: string,
    domain: string,
    username: string,
    password: string
  ): Promise<ADFinding[]> {
    const findings: ADFinding[] = [];

    const tests: ADSecurityTest[] = [
      {
        id: 'privileged_inactive',
        nome: 'Contas privilegiadas inativas',
        powershell: `$DaysInactive = 90; $InactiveDate = (Get-Date).AddDays(-$DaysInactive); Get-ADUser -Filter {Enabled -eq $True} -Properties LastLogonDate, MemberOf | Where-Object {($_.LastLogonDate -lt $InactiveDate) -and ($_.MemberOf -match 'Admins')} | Select-Object Name, SamAccountName, LastLogonDate | ConvertTo-Json`,
        severidade: 'medium',
        description: 'Contas com privilégios administrativos não utilizadas há mais de 90 dias',
        recommendation: 'Desabilitar ou remover contas privilegiadas inativas após aprovação'
      },
      {
        id: 'disabled_in_privileged_groups',
        nome: 'Contas desativadas em grupos privilegiados',
        powershell: `Get-ADUser -Filter {Enabled -eq $false} -Properties MemberOf | Where-Object {$_.MemberOf -match 'Admins'} | Select-Object Name, SamAccountName | ConvertTo-Json`,
        severidade: 'medium',
        description: 'Contas desabilitadas ainda são membros de grupos privilegiados',
        recommendation: 'Remover contas desabilitadas de grupos administrativos'
      },
      {
        id: 'gmsa_password_old',
        nome: 'Contas gMSA com senha não alterada recentemente',
        powershell: `$DaysThreshold = 90; $ThresholdDate = (Get-Date).AddDays(-$DaysThreshold); Get-ADServiceAccount -Filter * -Properties whenChanged | Where-Object {$_.whenChanged -lt $ThresholdDate} | Select-Object Name, SamAccountName, whenChanged | ConvertTo-Json`,
        severidade: 'medium',
        description: 'Contas de serviço gerenciadas (gMSA) sem alteração há mais de 90 dias',
        recommendation: 'Investigar motivo da ausência de rotação automática de senha'
      },
      {
        id: 'service_accounts_inactive',
        nome: 'Contas de serviço inativas há mais de 60 dias',
        powershell: `$daysInactive = 60; $limitDate = (Get-Date).AddDays(-$daysInactive); Get-ADUser -Filter {(servicePrincipalName -like '*') -and (LastLogonDate -lt $limitDate)} -Properties LastLogonDate, servicePrincipalName | Select-Object Name, LastLogonDate | ConvertTo-Json`,
        severidade: 'medium',
        description: 'Contas de serviço não utilizadas há mais de 60 dias',
        recommendation: 'Desabilitar contas de serviço inativas após validação com proprietários'
      },
      {
        id: 'servers_password_old',
        nome: 'Servidores com senhas não alteradas há mais de 60 dias',
        powershell: `$days = 60; $limitDate = (Get-Date).AddDays(-$days); Get-ADComputer -Filter {OperatingSystem -like '*Windows Server*'} -Properties PasswordLastSet | Where-Object {$_.PasswordLastSet -lt $limitDate} | Select-Object Name, PasswordLastSet | ConvertTo-Json`,
        severidade: 'medium',
        description: 'Servidores com senha de conta de computador não rotacionada há mais de 60 dias',
        recommendation: 'Investigar servidores inativos ou com problemas de comunicação com o DC'
      },
      {
        id: 'dormant_users',
        nome: 'Contas de usuário dormentes',
        powershell: `$days = 90; $date = (Get-Date).AddDays(-$days); Get-ADUser -Filter {(Enabled -eq $true) -and (LastLogonDate -lt $date)} -Properties LastLogonDate -ResultSetSize 100 | Select-Object Name, LastLogonDate | ConvertTo-Json`,
        severidade: 'low',
        description: 'Contas de usuário habilitadas sem login há mais de 90 dias',
        recommendation: 'Desabilitar contas dormentes após validação com gestores'
      }
    ];

    for (const test of tests) {
      try {
        const result = await this.executePowerShell(dcHost, domain, username, password, test.powershell);
        
        if (result.success && result.stdout.trim()) {
          const hasIssue = this.analyzeTestResult(test.id, result.stdout);
          
          if (hasIssue) {
            findings.push({
              type: this.getTypeForTest(test.id),
              target: domain,
              name: test.nome,
              severity: test.severidade,
              category: 'users',
              description: test.description || `Teste ${test.nome} identificou problemas de segurança`,
              recommendation: test.recommendation || 'Revisar e desabilitar contas inativas',
              evidence: {
                testId: test.id,
                output: result.stdout.substring(0, 1000)
              }
            });
          }
        }
      } catch (error: any) {
        console.error(`❌ Erro no teste ${test.id}:`, error.message);
      }
    }

    return findings;
  }

  /**
   * Analisa resultado do teste PowerShell para determinar se há problema
   */
  private analyzeTestResult(testId: string, output: string): boolean {
    try {
      // Parse JSON output
      const data = JSON.parse(output);
      
      // Se não há dados, não há problema
      if (!data || (Array.isArray(data) && data.length === 0)) {
        return false;
      }

      // Lógica específica por teste
      switch (testId) {
        case 'dc_print_spooler':
          return data.Status === 'Running';
        
        case 'smbv1_enabled':
          return data.InstallState === 'Installed';
        
        case 'krbtgt_weak':
          const passwordAge = Date.now() - new Date(data.PasswordLastSet).getTime();
          return passwordAge > (60 * 24 * 60 * 60 * 1000); // > 60 dias
        
        case 'ldap_anonymous':
        case 'dsheuristics_dangerous':
          return data && data.dSHeuristics;
        
        case 'laps_not_enabled':
          return data.Count && data.Count > 0;
        
        // Para a maioria dos testes, qualquer resultado indica problema
        default:
          return Array.isArray(data) ? data.length > 0 : !!data;
      }
    } catch (error) {
      // Se não é JSON ou há erro, assumir que há output = há problema
      return output.trim().length > 0 && !output.includes('[]') && !output.includes('null');
    }
  }

  /**
   * Mapeia ID do teste para tipo de finding apropriado
   */
  private getTypeForTest(testId: string): 'ad_hygiene' | 'ad_vulnerability' | 'ad_misconfiguration' {
    const criticalTests = ['dc_print_spooler', 'ldap_anonymous', 'smbv1_enabled', 'krbtgt_weak'];
    const vulnerabilityTests = ['privileged_spn', 'preauth_disabled', 'kerberos_vulnerabilities', 'credentials_in_shares'];
    
    if (criticalTests.includes(testId)) {
      return 'ad_misconfiguration';
    } else if (vulnerabilityTests.includes(testId)) {
      return 'ad_vulnerability';
    } else {
      return 'ad_hygiene';
    }
  }

  /**
   * Descobre controladores de domínio via DNS
   */
  private async discoverDomainControllers(domain: string): Promise<string[]> {
    try {
      const srvRecord = `_ldap._tcp.dc._msdcs.${domain}`;
      const records = await dnsResolve(srvRecord, 'SRV');
      
      if (!records || records.length === 0) {
        console.log(`⚠️  Nenhum registro SRV encontrado para ${srvRecord}`);
        return [];
      }

      const dcHosts = records.map((record: any) => record.name);
      return dcHosts;
    } catch (error: any) {
      console.error(`❌ Erro ao descobrir DCs via DNS: ${error.message}`);
      return [];
    }
  }

  /**
   * Constrói Base DN a partir do nome de domínio
   */
  private buildBaseDN(domain: string): string {
    return domain.split('.').map(part => `DC=${part}`).join(',');
  }
}
