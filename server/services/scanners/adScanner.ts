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

export interface ADSecurityTestResult {
  testId: string;
  testName: string;
  category: string;
  severityHint: 'low' | 'medium' | 'high' | 'critical';
  status: 'pass' | 'fail' | 'error' | 'skipped';
  evidence: Record<string, any>;
  description?: string;
  recommendation?: string;
}

export interface ADSecurityScanResult {
  findings: ADFinding[]; // Only tests that failed
  testResults: ADSecurityTestResult[]; // All 28 tests (pass/fail/error/skipped)
}

interface PowerShellExecutionResult {
  success: boolean;
  stdout: string;
  stderr: string;
  exitCode: number;
  command?: string; // Comando sanitizado (sem senha) para auditoria
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

// Template configuration for per-object findings
interface PerObjectFindingTemplate {
  titleTemplate: (objectName: string) => string;
  descriptionTemplate: (objectName: string, details?: Record<string, any>) => string;
  objectNameField: string; // Field name in PowerShell output to use as object identifier (e.g., 'SamAccountName', 'Name')
  objectType: 'user' | 'computer' | 'service_account' | 'group' | 'trust' | 'gmsa' | 'dc';
}

// Stdout/stderr size limits (bytes) to prevent memory/storage bloat
const MAX_RAW_STDOUT = 512_000;  // 512KB max raw capture from PowerShell process
const MAX_RAW_STDERR = 64_000;   // 64KB max raw stderr capture
const MAX_EVIDENCE_STDOUT = 2_000;  // Truncated stdout stored in evidence (generic tests)
const MAX_EVIDENCE_STDERR = 500;    // Truncated stderr stored in evidence (generic tests)
const MAX_PEROBJECT_STDOUT = 500;   // Truncated stdout for per-object findings
const MAX_PEROBJECT_STDERR = 200;   // Truncated stderr for per-object findings

export class ADScanner {
  private readonly commonDCPorts = [389, 636, 3268, 3269];
  private baseDN: string = '';
  private domain: string = '';

  /**
   * Helper para criar resultado de teste
   */
  private createTestResult(
    testId: string,
    testName: string,
    category: string,
    severityHint: 'low' | 'medium' | 'high' | 'critical',
    status: 'pass' | 'fail' | 'error' | 'skipped',
    evidence: Record<string, any>,
    description?: string,
    recommendation?: string
  ): ADSecurityTestResult {
    return {
      testId,
      testName,
      category,
      severityHint,
      status,
      evidence,
      description,
      recommendation,
    };
  }

  /**
   * Escaneia segurança do Active Directory usando PowerShell via WinRM
   */
  async scanADSecurity(
    domain: string,
    username: string,
    password: string,
    dcHost?: string,
    enabledCategories?: ADSecurityCategories
  ): Promise<ADSecurityScanResult> {
    console.log(`🔍 Iniciando análise de segurança AD para domínio ${domain}`);
    
    const findings: ADFinding[] = [];
    const testResults: ADSecurityTestResult[] = [];
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
          const errorFinding: ADFinding = {
            type: 'ad_misconfiguration',
            target: domain,
            name: 'Nenhum Controlador de Domínio Encontrado',
            severity: 'critical',
            category: 'configuration',
            description: 'Não foi possível localizar controladores de domínio para o domínio especificado via DNS',
            recommendation: 'Verificar configuração DNS e conectividade de rede. Especifique o IP do DC manualmente.'
          };
          findings.push(errorFinding);
          
          testResults.push(this.createTestResult(
            'test_dc_discovery_error',
            'Descoberta de Controladores de Domínio',
            'configuracoes_criticas',
            'critical',
            'error',
            { domainControllersFound: 0 },
            errorFinding.description,
            errorFinding.recommendation
          ));
          
          return { findings, testResults };
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

      // 3. Executar testes por categoria e rastrear ALL execution results
      const executionResults = new Map<string, any>(); // Map testName -> execution evidence
      
      if (categories.configuracoes_criticas) {
        console.log('🔴 Executando testes: Configurações Críticas...');
        const { findings: criticalFindings, executionResults: execResults } = await this.testConfiguracoesCriticas(targetDC, domain, username, password);
        findings.push(...criticalFindings);
        execResults.forEach((evidence, testName) => executionResults.set(testName, evidence));
        console.log(`✅ Configurações Críticas: ${criticalFindings.length} achados`);
      }

      if (categories.gerenciamento_contas) {
        console.log('👥 Executando testes: Gerenciamento de Contas...');
        const { findings: accountFindings, executionResults: execResults } = await this.testGerenciamentoContas(targetDC, domain, username, password);
        findings.push(...accountFindings);
        execResults.forEach((evidence, testName) => executionResults.set(testName, evidence));
        console.log(`✅ Gerenciamento de Contas: ${accountFindings.length} achados`);
      }

      if (categories.kerberos_delegacao) {
        console.log('🎫 Executando testes: Kerberos e Delegação...');
        const { findings: kerberosFindings, executionResults: execResults } = await this.testKerberosDelegacao(targetDC, domain, username, password);
        findings.push(...kerberosFindings);
        execResults.forEach((evidence, testName) => executionResults.set(testName, evidence));
        console.log(`✅ Kerberos e Delegação: ${kerberosFindings.length} achados`);
      }

      if (categories.compartilhamentos_gpos) {
        console.log('📂 Executando testes: Compartilhamentos e GPOs...');
        const { findings: shareFindings, executionResults: execResults } = await this.testCompartilhamentosGPOs(targetDC, domain, username, password);
        findings.push(...shareFindings);
        execResults.forEach((evidence, testName) => executionResults.set(testName, evidence));
        console.log(`✅ Compartilhamentos e GPOs: ${shareFindings.length} achados`);
      }

      if (categories.politicas_configuracao) {
        console.log('⚙️  Executando testes: Políticas e Configuração...');
        const { findings: policyFindings, executionResults: execResults } = await this.testPoliticasConfiguracao(targetDC, domain, username, password);
        findings.push(...policyFindings);
        execResults.forEach((evidence, testName) => executionResults.set(testName, evidence));
        console.log(`✅ Políticas e Configuração: ${policyFindings.length} achados`);
      }

      if (categories.contas_inativas) {
        console.log('💤 Executando testes: Contas Inativas...');
        const { findings: inactiveFindings, executionResults: execResults } = await this.testContasInativas(targetDC, domain, username, password);
        findings.push(...inactiveFindings);
        execResults.forEach((evidence, testName) => executionResults.set(testName, evidence));
        console.log(`✅ Contas Inativas: ${inactiveFindings.length} achados`);
      }

      // 4. Create test results from execution results  
      const findingsByTestId = new Map<string, ADFinding>();
      findings.forEach(finding => {
        // Try to extract testId from evidence
        if (finding.evidence && typeof finding.evidence === 'object' && 'testId' in finding.evidence) {
          findingsByTestId.set(finding.evidence.testId as string, finding);
        }
      });

      // Create test results from all executed tests
      let credentialErrorCount = 0;
      let connectionErrorCount = 0;
      const totalTests = executionResults.size;
      
      executionResults.forEach((evidence, testId) => {
        const finding = findingsByTestId.get(testId);
        
        // Check for connection/credential errors
        const hasCredentialError = evidence.stderr && (
          evidence.stderr.includes('credentials were rejected') ||
          evidence.stderr.includes('authentication failed') ||
          evidence.stderr.includes('Access is denied') ||
          evidence.stderr.includes('logon failure')
        );
        
        const hasConnectionError = evidence.stderr && (
          evidence.stderr.includes('WinRM connection') ||
          evidence.stderr.includes('connection refused') ||
          evidence.stderr.includes('timeout') ||
          evidence.stderr.includes('Timeout') ||
          evidence.stderr.includes('unreachable') ||
          evidence.stderr.includes('No such host')
        );
        
        if (hasCredentialError) credentialErrorCount++;
        if (hasConnectionError && !hasCredentialError) connectionErrorCount++;
        
        if (finding) {
          // Test failed - create "fail" result (vulnerability found)
          testResults.push(this.createTestResult(
            testId,
            finding.name,
            this.getCategoryForTestId(testId),
            finding.severity,
            'fail',
            evidence,
            finding.description,
            finding.recommendation
          ));
        } else if (hasCredentialError || (hasConnectionError && evidence.exitCode !== 0)) {
          // Test error - connection or credential issue
          const testMetadata = this.getTestMetadata(testId);
          const errorType = hasCredentialError ? 'Credenciais rejeitadas' : 'Erro de conexão';
          testResults.push(this.createTestResult(
            testId,
            testMetadata.name,
            testMetadata.category,
            testMetadata.severity,
            'error',
            evidence,
            `${errorType}: ${evidence.stderr?.substring(0, 200) || 'Erro desconhecido'}`,
            hasCredentialError 
              ? 'Verifique se as credenciais estão corretas e se a conta tem permissão para acesso remoto WinRM'
              : 'Verifique conectividade de rede com o DC e se o serviço WinRM está habilitado'
          ));
        } else {
          // Test passed - create "pass" result
          const testMetadata = this.getTestMetadata(testId);
          testResults.push(this.createTestResult(
            testId,
            testMetadata.name,
            testMetadata.category,
            testMetadata.severity,
            'pass',
            evidence,
            `Teste ${testMetadata.name} passou com sucesso`,
            undefined
          ));
        }
      });

      console.log(`✅ Análise concluída: ${findings.length} achados, ${testResults.length} resultados de teste`);
      
      // If ALL tests failed due to credential error, throw exception to fail the job
      if (credentialErrorCount > 0 && credentialErrorCount === totalTests) {
        console.error(`❌ TODOS os ${totalTests} testes falharam por erro de credencial`);
        throw new Error(`Falha de autenticação: As credenciais foram rejeitadas pelo servidor. Verifique usuário/senha e permissões WinRM.`);
      }
      
      // If majority of tests failed due to connection error, throw exception
      if (connectionErrorCount > 0 && connectionErrorCount === totalTests) {
        console.error(`❌ TODOS os ${totalTests} testes falharam por erro de conexão`);
        throw new Error(`Falha de conexão: Não foi possível conectar ao controlador de domínio. Verifique conectividade e se WinRM está habilitado.`);
      }
      
      return { findings, testResults };

    } catch (error: any) {
      console.error('❌ Erro na análise AD Security:', error);
      const errorFinding: ADFinding = {
        type: 'ad_misconfiguration',
        target: domain,
        name: 'Erro na Execução da Análise',
        severity: 'critical',
        category: 'configuration',
        description: `Falha ao executar análise de segurança: ${error.message}`,
        recommendation: 'Verificar credenciais, conectividade e permissões WinRM no controlador de domínio'
      };
      findings.push(errorFinding);
      
      testResults.push(this.createTestResult(
        'test_error_execution',
        'Erro na Execução da Análise',
        'configuracoes_criticas',
        'critical',
        'error',
        { error: error.message, stack: error.stack },
        errorFinding.description,
        errorFinding.recommendation
      ));
      
      return { findings, testResults };
    }
  }

  /**
   * Executa comando PowerShell remotamente via WinRM usando wrapper Python (pywinrm)
   */
  private async executePowerShell(
    dcHost: string,
    domain: string,
    username: string,
    password: string,
    script: string,
    testName?: string
  ): Promise<PowerShellExecutionResult> {
    return new Promise((resolve) => {
      // Substituir placeholders no script
      const processedScript = script
        .replace(/\$baseDN/g, this.baseDN)
        .replace(/\$domainName/g, domain);

      // Build qualified username - avoid double domain prefix
      // If username already contains \ or @, use as-is; otherwise prepend domain
      let qualifiedUsername: string;
      if (username.includes('\\') || username.includes('@')) {
        qualifiedUsername = username;
        console.log(`📝 Username já qualificado: ${username}`);
      } else {
        qualifiedUsername = `${domain}\\${username}`;
        console.log(`📝 Username qualificado com domínio: ${qualifiedUsername}`);
      }

      // Log do comando sendo executado (sem senha)
      const sanitizedScript = `
$credential = [PSCredential]::new('${qualifiedUsername}', [REDACTED])
Invoke-Command -ComputerName ${dcHost} -Credential $credential -ScriptBlock {
  ${processedScript}
}`;
      
      if (testName) {
        console.log(`🔧 PowerShell [${testName}]: Executando comando via WinRM no DC ${dcHost}`);
        console.log(`📝 Script:\n${processedScript.substring(0, 200)}...`);
      }

      // Detectar caminhos dinamicamente para suportar qualquer ambiente
      const installDir = process.env.INSTALL_DIR || process.cwd();
      const venvPath = process.env.VENV_PATH || `${installDir}/venv`;
      const pythonBin = `${venvPath}/bin/python`;
      const wrapperPath = `${installDir}/server/utils/winrm-wrapper.py`;

      // Executar wrapper Python via virtualenv (password via stdin para segurança)
      const winrm = spawn(pythonBin, [
        wrapperPath,
        '--host', dcHost,
        '--username', qualifiedUsername,
        '--script', processedScript,
        '--timeout', '300', // 5 minutos
        '--password-stdin'
      ]);

      // Handler de erro para evitar crash se Python/wrapper não existir
      winrm.on('error', (error) => {
        console.error(`❌ Erro ao executar wrapper Python: ${error.message}`);
        console.error(`Paths tentados: pythonBin=${pythonBin}, wrapper=${wrapperPath}`);
        resolve({
          success: false,
          stdout: '',
          stderr: `Erro ao executar wrapper WinRM: ${error.message}. Verifique se o virtualenv Python está configurado corretamente (execute install.sh).`,
          exitCode: -1,
          command: sanitizedScript,
        });
      });

      // Enviar senha via stdin para evitar exposição em ps/proc
      try {
        winrm.stdin.write(password + '\n');
        winrm.stdin.end();
      } catch (e) {
        console.error(`❌ Erro ao enviar senha via stdin: ${e}`);
      }

      let stdout = '';
      let stderr = '';

      winrm.stdout.on('data', (data) => {
        if (stdout.length < MAX_RAW_STDOUT) {
          stdout += data.toString();
          if (stdout.length > MAX_RAW_STDOUT) {
            stdout = stdout.substring(0, MAX_RAW_STDOUT);
          }
        }
      });

      winrm.stderr.on('data', (data) => {
        if (stderr.length < MAX_RAW_STDERR) {
          stderr += data.toString();
          if (stderr.length > MAX_RAW_STDERR) {
            stderr = stderr.substring(0, MAX_RAW_STDERR);
          }
        }
      });

      winrm.on('close', (code) => {
        clearTimeout(timeoutHandle); // Limpar timeout quando processo terminar
        
        if (testName) {
          console.log(`✅ PowerShell [${testName}]: Concluído (exitCode: ${code}, stdout: ${stdout.length} chars, stderr: ${stderr.length} chars)`);
        }
        
        // Tentar parsear resposta JSON do wrapper
        let result: PowerShellExecutionResult;
        try {
          if (stdout.trim()) {
            const parsed = JSON.parse(stdout);
            result = {
              success: parsed.exitCode === 0,
              stdout: parsed.stdout || '',
              stderr: parsed.stderr || parsed.error || '',
              exitCode: parsed.exitCode || 0,
              command: sanitizedScript,
            };
          } else {
            // Sem JSON - usar resposta raw
            result = {
              success: code === 0,
              stdout: '',
              stderr: stderr || 'Sem resposta do wrapper Python',
              exitCode: code || 1,
              command: sanitizedScript,
            };
          }
        } catch (e) {
          // Erro ao parsear JSON - usar resposta raw
          result = {
            success: false,
            stdout: stdout,
            stderr: stderr || `Erro ao parsear resposta JSON: ${e}`,
            exitCode: code || 1,
            command: sanitizedScript,
          };
        }
        
        resolve(result);
      });

      // Timeout de 6 minutos (margem de segurança além do timeout interno)
      const timeoutHandle = setTimeout(() => {
        winrm.kill();
        if (testName) {
          console.log(`⏱️  PowerShell [${testName}]: Timeout após 6 minutos`);
        }
        resolve({
          success: false,
          stdout: '',
          stderr: 'Timeout: Comando excedeu 6 minutos',
          exitCode: -1,
          command: sanitizedScript,
        });
      }, 360000);
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
  ): Promise<{ findings: ADFinding[], executionResults: Map<string, any> }> {
    const findings: ADFinding[] = [];
    const executionResults = new Map<string, any>();

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
        const result = await this.executePowerShell(dcHost, domain, username, password, test.powershell, test.nome);
        
        // Always save execution results for auditability (index by testId for consistency)
        const evidence = {
          testId: test.id,
          command: result.command || test.powershell,
          stdout: result.stdout.substring(0, MAX_EVIDENCE_STDOUT),
          stderr: result.stderr.substring(0, MAX_EVIDENCE_STDERR),
          exitCode: result.exitCode,
        };
        executionResults.set(test.id, evidence);
        
        // Process stdout regardless of exitCode (PowerShell may return 1 on success)
        if (result.stdout && result.stdout.trim()) {
          const hasIssue = this.analyzeTestResult(test.id, result.stdout);

          if (hasIssue) {
            // Try per-object findings if template exists
            const template = this.getPerObjectTemplate(test.id);
            if (template) {
              const perObjectFindings = this.createPerObjectFindings(test, domain, result.stdout, result);
              findings.push(...perObjectFindings);
            } else {
              // Domain-level finding with objectId for correlation
              findings.push({
                type: this.getTypeForTest(test.id),
                target: domain,
                name: test.nome,
                severity: test.severidade,
                category: 'configuration',
                description: test.description || `Teste ${test.nome} identificou problemas de segurança`,
                recommendation: test.recommendation || 'Revisar configuração conforme documentação de segurança Microsoft',
                evidence: { ...evidence, objectId: domain, domain }
              });
            }
          }
        }
      } catch (error: any) {
        console.error(`❌ Erro no teste ${test.id}:`, error.message);
        // Save error as evidence
        executionResults.set(test.id, {
          testId: test.id,
          command: test.powershell,
          stdout: '',
          stderr: error.message,
          exitCode: -1,
        });
      }
    }

    return { findings, executionResults };
  }

  /**
   * Testes da Categoria: Gerenciamento de Contas
   */
  private async testGerenciamentoContas(
    dcHost: string,
    domain: string,
    username: string,
    password: string
  ): Promise<{ findings: ADFinding[], executionResults: Map<string, any> }> {
    const findings: ADFinding[] = [];
    const executionResults = new Map<string, any>();

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
        const result = await this.executePowerShell(dcHost, domain, username, password, test.powershell, test.nome);
        
        // Always save execution results for auditability (index by testId for consistency)
        const evidence = {
          testId: test.id,
          command: result.command || test.powershell,
          stdout: result.stdout.substring(0, MAX_EVIDENCE_STDOUT),
          stderr: result.stderr.substring(0, MAX_EVIDENCE_STDERR),
          exitCode: result.exitCode,
        };
        executionResults.set(test.id, evidence);
        
        // Process stdout regardless of exitCode (PowerShell may return 1 on success)
        if (result.stdout && result.stdout.trim()) {
          const hasIssue = this.analyzeTestResult(test.id, result.stdout);
          
          if (hasIssue) {
            // Use per-object findings for tests that return object lists
            const perObjectFindings = this.createPerObjectFindings(test, domain, result.stdout, result);
            findings.push(...perObjectFindings);
          }
        }
      } catch (error: any) {
        console.error(`❌ Erro no teste ${test.id}:`, error.message);
        // Save error as evidence
        executionResults.set(test.id, {
          testId: test.id,
          command: test.powershell,
          stdout: '',
          stderr: error.message,
          exitCode: -1,
        });
      }
    }

    return { findings, executionResults };
  }

  /**
   * Testes da Categoria: Kerberos e Delegação
   */
  private async testKerberosDelegacao(
    dcHost: string,
    domain: string,
    username: string,
    password: string
  ): Promise<{ findings: ADFinding[], executionResults: Map<string, any> }> {
    const findings: ADFinding[] = [];
    const executionResults = new Map<string, any>();

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
        const result = await this.executePowerShell(dcHost, domain, username, password, test.powershell, test.nome);
        
        // Always save execution results for auditability (index by testId for consistency)
        const evidence = {
          testId: test.id,
          command: result.command || test.powershell,
          stdout: result.stdout.substring(0, MAX_EVIDENCE_STDOUT),
          stderr: result.stderr.substring(0, MAX_EVIDENCE_STDERR),
          exitCode: result.exitCode,
        };
        executionResults.set(test.id, evidence);
        
        // Process stdout regardless of exitCode (PowerShell may return 1 on success)
        if (result.stdout && result.stdout.trim()) {
          const hasIssue = this.analyzeTestResult(test.id, result.stdout);
          
          if (hasIssue) {
            // Use per-object findings for tests that return object lists
            const perObjectFindings = this.createPerObjectFindings(test, domain, result.stdout, result);
            findings.push(...perObjectFindings);
          }
        }
      } catch (error: any) {
        console.error(`❌ Erro no teste ${test.id}:`, error.message);
        // Save error as evidence
        executionResults.set(test.id, {
          testId: test.id,
          command: test.powershell,
          stdout: '',
          stderr: error.message,
          exitCode: -1,
        });
      }
    }

    return { findings, executionResults };
  }

  /**
   * Testes da Categoria: Compartilhamentos e GPOs
   */
  private async testCompartilhamentosGPOs(
    dcHost: string,
    domain: string,
    username: string,
    password: string
  ): Promise<{ findings: ADFinding[], executionResults: Map<string, any> }> {
    const findings: ADFinding[] = [];
    const executionResults = new Map<string, any>();

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
        const result = await this.executePowerShell(dcHost, domain, username, password, test.powershell, test.nome);
        
        // Store execution result for test evidence (ensures test appears in PASSOU/FALHOU list)
        const evidence = {
          testId: test.id,
          command: result.command || test.powershell,
          stdout: result.stdout.substring(0, MAX_EVIDENCE_STDOUT),
          stderr: result.stderr.substring(0, MAX_EVIDENCE_STDERR),
          exitCode: result.exitCode,
        };
        executionResults.set(test.id, evidence);

        // Process stdout regardless of exitCode (PowerShell may return 1 on success)
        if (result.stdout && result.stdout.trim()) {
          const hasIssue = this.analyzeTestResult(test.id, result.stdout);

          if (hasIssue) {
            const template = this.getPerObjectTemplate(test.id);
            if (template) {
              const perObjectFindings = this.createPerObjectFindings(test, domain, result.stdout, result);
              findings.push(...perObjectFindings);
            } else {
              findings.push({
                type: this.getTypeForTest(test.id),
                target: domain,
                name: test.nome,
                severity: test.severidade,
                category: 'policies',
                description: test.description || `Teste ${test.nome} identificou problemas de segurança`,
                recommendation: test.recommendation || 'Revisar permissões e configurações de compartilhamento',
                evidence: { ...evidence, objectId: domain, domain }
              });
            }
          }
        }
      } catch (error: any) {
        console.error(`❌ Erro no teste ${test.id}:`, error.message);
        // Register error as execution result so test still appears in the list
        executionResults.set(test.id, {
          command: test.powershell,
          stdout: '',
          stderr: error.message || 'Erro desconhecido',
          exitCode: -1,
          error: true,
        });
      }
    }

    return { findings, executionResults };
  }

  /**
   * Testes da Categoria: Políticas e Configuração
   */
  private async testPoliticasConfiguracao(
    dcHost: string,
    domain: string,
    username: string,
    password: string
  ): Promise<{ findings: ADFinding[], executionResults: Map<string, any> }> {
    const findings: ADFinding[] = [];
    const executionResults = new Map<string, any>();

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
        const result = await this.executePowerShell(dcHost, domain, username, password, test.powershell, test.nome);

        // Store execution result for test evidence (ensures test appears in PASSOU/FALHOU list)
        const evidence = {
          testId: test.id,
          command: result.command || test.powershell,
          stdout: result.stdout.substring(0, MAX_EVIDENCE_STDOUT),
          stderr: result.stderr.substring(0, MAX_EVIDENCE_STDERR),
          exitCode: result.exitCode,
        };
        executionResults.set(test.id, evidence);

        // Process stdout regardless of exitCode (PowerShell may return 1 on success)
        if (result.stdout && result.stdout.trim()) {
          const hasIssue = this.analyzeTestResult(test.id, result.stdout);

          if (hasIssue) {
            const template = this.getPerObjectTemplate(test.id);
            if (template) {
              const perObjectFindings = this.createPerObjectFindings(test, domain, result.stdout, result);
              findings.push(...perObjectFindings);
            } else {
              findings.push({
                type: this.getTypeForTest(test.id),
                target: domain,
                name: test.nome,
                severity: test.severidade,
                category: 'configuration',
                description: test.description || `Teste ${test.nome} identificou problemas de segurança`,
                recommendation: test.recommendation || 'Revisar e corrigir configuração do domínio',
                evidence: { ...evidence, objectId: domain, domain }
              });
            }
          }
        }
      } catch (error: any) {
        console.error(`❌ Erro no teste ${test.id}:`, error.message);
        // Register error as execution result so test still appears in the list
        executionResults.set(test.id, {
          command: test.powershell,
          stdout: '',
          stderr: error.message || 'Erro desconhecido',
          exitCode: -1,
          error: true,
        });
      }
    }

    return { findings, executionResults };
  }

  /**
   * Testes da Categoria: Contas Inativas
   */
  private async testContasInativas(
    dcHost: string,
    domain: string,
    username: string,
    password: string
  ): Promise<{ findings: ADFinding[], executionResults: Map<string, any> }> {
    const findings: ADFinding[] = [];
    const executionResults = new Map<string, any>();

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
        const result = await this.executePowerShell(dcHost, domain, username, password, test.powershell, test.nome);
        
        // Store execution result for test evidence
        executionResults.set(test.id, {
          command: result.command || test.powershell,
          stdout: result.stdout.substring(0, MAX_EVIDENCE_STDOUT),
          stderr: result.stderr.substring(0, MAX_EVIDENCE_STDERR),
          exitCode: result.exitCode,
        });
        
        // Process stdout regardless of exitCode (PowerShell may return 1 on success)
        if (result.stdout && result.stdout.trim()) {
          const hasIssue = this.analyzeTestResult(test.id, result.stdout);
          
          if (hasIssue) {
            // Use per-object findings for tests that return object lists
            const perObjectFindings = this.createPerObjectFindings(test, domain, result.stdout, result);
            findings.push(...perObjectFindings);
          }
        }
      } catch (error: any) {
        console.error(`❌ Erro no teste ${test.id}:`, error.message);
      }
    }

    return { findings, executionResults };
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
   * Get category for a test ID
   */
  private getCategoryForTestId(testId: string): string {
    const categoryMapping: Record<string, string> = {
      // Configurações Críticas
      'dc_print_spooler': 'configuracoes_criticas',
      'ldap_anonymous': 'configuracoes_criticas',
      'smbv1_enabled': 'configuracoes_criticas',
      'krbtgt_weak': 'configuracoes_criticas',
      'schema_permissions': 'configuracoes_criticas',
      
      // Gerenciamento de Contas
      'privileged_spn': 'gerenciamento_contas',
      'password_never_expires': 'gerenciamento_contas',
      'preauth_disabled': 'gerenciamento_contas',
      'admin_account_weak': 'gerenciamento_contas',
      'dc_password_old': 'gerenciamento_contas',
      'low_primary_group_id': 'gerenciamento_contas',
      'admin_count_set': 'gerenciamento_contas',
      'trust_relationships': 'gerenciamento_contas',
      'hidden_privileged_sid': 'gerenciamento_contas',
      'pre_win2000_access': 'gerenciamento_contas',
      
      // Kerberos e Delegação
      'krbtgt_rbcd': 'kerberos_delegacao',
      'unconstrained_delegation': 'kerberos_delegacao',
      'rbcd_high_privilege': 'kerberos_delegacao',
      'des_encryption': 'kerberos_delegacao',
      'rc4_only_accounts': 'kerberos_delegacao',
      'duplicate_spn': 'kerberos_delegacao',
      
      // Compartilhamentos e GPOs
      'credentials_in_shares': 'compartilhamentos_gpos',
      'sysvol_permissions': 'compartilhamentos_gpos',
      'gpo_weak_permissions': 'compartilhamentos_gpos',
      'orphaned_gpos': 'compartilhamentos_gpos',
      
      // Políticas e Configuração
      'risky_uac_params': 'politicas_configuracao',
      'domain_functional_level': 'politicas_configuracao',
      'ldap_signing': 'politicas_configuracao',
      'smb_signing_not_required': 'politicas_configuracao',
      'password_policy_weak': 'politicas_configuracao',
      'ldap_channel_binding': 'politicas_configuracao',
      
      // Contas Inativas
      'privileged_inactive': 'contas_inativas',
      'disabled_in_privileged_groups': 'contas_inativas',
      'computers_old_password': 'contas_inativas',
      'stale_computer_accounts': 'contas_inativas',
    };
    
    return categoryMapping[testId] || 'configuracoes_criticas';
  }

  /**
   * Get metadata for a test ID
   */
  private getTestMetadata(testId: string): { name: string; category: string; severity: 'low' | 'medium' | 'high' | 'critical' } {
    // This would ideally come from a centralized test registry
    // For now, return basic defaults based on category
    const category = this.getCategoryForTestId(testId);
    return {
      name: testId.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
      category,
      severity: 'medium'
    };
  }

  /**
   * Template configurations for per-object findings
   * Maps testId to template for generating individual findings per object
   */
  private getPerObjectTemplate(testId: string): PerObjectFindingTemplate | null {
    const templates: Record<string, PerObjectFindingTemplate> = {
      // testContasInativas tests
      'privileged_inactive': {
        titleTemplate: (name) => `Conta privilegiada inativa: ${name}`,
        descriptionTemplate: (name, details) => `A conta privilegiada ${name} está habilitada mas não é utilizada há mais de 90 dias${details?.LastLogonDate ? ` (último login: ${details.LastLogonDate})` : ''}`,
        objectNameField: 'SamAccountName',
        objectType: 'user',
      },
      'disabled_in_privileged_groups': {
        titleTemplate: (name) => `Conta desativada em grupo privilegiado: ${name}`,
        descriptionTemplate: (name) => `A conta ${name} está desabilitada mas ainda é membro de grupos administrativos, representando risco de reativação`,
        objectNameField: 'SamAccountName',
        objectType: 'user',
      },
      'gmsa_password_old': {
        titleTemplate: (name) => `Conta gMSA sem rotação de senha: ${name}`,
        descriptionTemplate: (name, details) => `A conta de serviço gerenciada ${name} não teve sua senha alterada há mais de 90 dias${details?.whenChanged ? ` (última alteração: ${details.whenChanged})` : ''}`,
        objectNameField: 'SamAccountName',
        objectType: 'gmsa',
      },
      'service_accounts_inactive': {
        titleTemplate: (name) => `Conta de serviço inativa: ${name}`,
        descriptionTemplate: (name, details) => `A conta de serviço ${name} não é utilizada há mais de 60 dias${details?.LastLogonDate ? ` (último login: ${details.LastLogonDate})` : ''}`,
        objectNameField: 'Name',
        objectType: 'service_account',
      },
      'servers_password_old': {
        titleTemplate: (name) => `Servidor com senha antiga: ${name}`,
        descriptionTemplate: (name, details) => `O servidor ${name} não teve sua senha de conta de computador rotacionada há mais de 60 dias${details?.PasswordLastSet ? ` (última alteração: ${details.PasswordLastSet})` : ''}`,
        objectNameField: 'Name',
        objectType: 'computer',
      },
      'dormant_users': {
        titleTemplate: (name) => `Conta de usuário dormente: ${name}`,
        descriptionTemplate: (name, details) => `A conta do usuário ${name} está habilitada e sem login há mais de 90 dias${details?.LastLogonDate ? ` (último login: ${details.LastLogonDate})` : ''}`,
        objectNameField: 'Name',
        objectType: 'user',
      },
      // testGerenciamentoContas tests
      'privileged_spn': {
        titleTemplate: (name) => `Usuário privilegiado com SPN: ${name}`,
        descriptionTemplate: (name, details) => `O usuário privilegiado ${name} possui Service Principal Names (SPN) configurados, tornando-o vulnerável a ataques de Kerberoasting${details?.servicePrincipalName ? ` (SPNs: ${Array.isArray(details.servicePrincipalName) ? details.servicePrincipalName.join(', ') : details.servicePrincipalName})` : ''}`,
        objectNameField: 'SamAccountName',
        objectType: 'user',
      },
      'password_never_expires': {
        titleTemplate: (name) => `Conta com senha sem expiração: ${name}`,
        descriptionTemplate: (name) => `A conta ${name} está configurada com senha que nunca expira, violando políticas de segurança`,
        objectNameField: 'Name',
        objectType: 'user',
      },
      'preauth_disabled': {
        titleTemplate: (name) => `Conta sem pré-autenticação Kerberos: ${name}`,
        descriptionTemplate: (name) => `A conta ${name} está com pré-autenticação Kerberos desativada, vulnerável a ataques AS-REP Roasting`,
        objectNameField: 'SamAccountName',
        objectType: 'user',
      },
      'admin_count_set': {
        titleTemplate: (name) => `AdminCount residual: ${name}`,
        descriptionTemplate: (name) => `A conta ${name} possui atributo AdminCount=1 mas não é mais membro de grupos administrativos, podendo ter permissões residuais`,
        objectNameField: 'SamAccountName',
        objectType: 'user',
      },
      'hidden_privileged_sid': {
        titleTemplate: (name) => `SID privilegiado oculto: ${name}`,
        descriptionTemplate: (name) => `A conta ${name} possui SIDs privilegiados no atributo sidHistory, podendo ter privilégios ocultos não aparentes`,
        objectNameField: 'SamAccountName',
        objectType: 'user',
      },
      'pre_win2000_access': {
        titleTemplate: (name) => `Acesso pré-Windows 2000: ${name}`,
        descriptionTemplate: (name) => `A conta ${name} é membro do grupo "Pre-Windows 2000 Compatible Access", permitindo autenticação legada insegura`,
        objectNameField: 'SamAccountName',
        objectType: 'user',
      },
      'low_primary_group_id': {
        titleTemplate: (name) => `PrimaryGroupID privilegiado: ${name}`,
        descriptionTemplate: (name, details) => `A conta ${name} possui PrimaryGroupID menor que 1000 (${details?.primaryGroupId || 'N/A'}), indicando possíveis privilégios ocultos`,
        objectNameField: 'Name',
        objectType: 'user',
      },
      // Additional tests that return object lists
      'unconstrained_delegation': {
        titleTemplate: (name) => `Delegação irrestrita: ${name}`,
        descriptionTemplate: (name) => `O computador ${name} está configurado com delegação Kerberos irrestrita, permitindo impersonação de qualquer usuário`,
        objectNameField: 'Name',
        objectType: 'computer',
      },
      'rbcd_high_privilege': {
        titleTemplate: (name) => `RBCD de alto privilégio: ${name}`,
        descriptionTemplate: (name) => `O objeto ${name} possui Resource-Based Constrained Delegation configurada de forma insegura`,
        objectNameField: 'Name',
        objectType: 'computer',
      },
      'des_encryption': {
        titleTemplate: (name) => `Criptografia DES habilitada: ${name}`,
        descriptionTemplate: (name) => `A conta ${name} suporta criptografia DES obsoleta e vulnerável`,
        objectNameField: 'SamAccountName',
        objectType: 'user',
      },
      'rc4_only_accounts': {
        titleTemplate: (name) => `Apenas RC4 habilitado: ${name}`,
        descriptionTemplate: (name) => `A conta ${name} está configurada para usar apenas criptografia RC4 (fraca)`,
        objectNameField: 'SamAccountName',
        objectType: 'user',
      },
      'duplicate_spn': {
        titleTemplate: (name) => `SPN duplicado: ${name}`,
        descriptionTemplate: (name) => `O Service Principal Name ${name} está registrado em múltiplas contas, causando problemas de autenticação Kerberos`,
        objectNameField: 'Name',
        objectType: 'user',
      },
      'trust_relationships': {
        titleTemplate: (name) => `Relação de confiança: ${name}`,
        descriptionTemplate: (name, details) => `Relação de confiança com domínio ${name} identificada${details?.TrustType ? ` (Tipo: ${details.TrustType}, Direção: ${details.TrustDirection || 'N/A'})` : ''}`,
        objectNameField: 'Name',
        objectType: 'trust',
      },
      'dc_password_old': {
        titleTemplate: (name) => `DC com senha antiga: ${name}`,
        descriptionTemplate: (name, details) => `O Controlador de Domínio ${name} não teve sua senha de conta de computador alterada recentemente${details?.PasswordLastSet ? ` (última alteração: ${details.PasswordLastSet})` : ''}`,
        objectNameField: 'Name',
        objectType: 'computer',
      },
      // testConfiguracoesCriticas - per-object tests
      'schema_permissions': {
        titleTemplate: (name) => `Permissão não-padrão no Schema: ${name}`,
        descriptionTemplate: (name, details) => `A entidade ${name} possui permissões não-padrão na partição do esquema do AD${details?.ActiveDirectoryRights ? ` (Direitos: ${details.ActiveDirectoryRights})` : ''}`,
        objectNameField: 'IdentityReference',
        objectType: 'user',
      },
      // testCompartilhamentosGPOs - per-object tests
      'credentials_in_shares': {
        titleTemplate: (name) => `Credencial exposta em compartilhamento: ${name}`,
        descriptionTemplate: (name, details) => `Arquivo ${name} contém credenciais ou palavras-chave sensíveis${details?.LineNumber ? ` (linha ${details.LineNumber})` : ''}`,
        objectNameField: 'Path',
        objectType: 'computer',
      },
      'sysvol_permissions': {
        titleTemplate: (name) => `Permissão excessiva no SYSVOL: ${name}`,
        descriptionTemplate: (name, details) => `A entidade ${name} possui permissões não-padrão no compartilhamento SYSVOL${details?.FileSystemRights ? ` (${details.FileSystemRights})` : ''}`,
        objectNameField: 'IdentityReference',
        objectType: 'user',
      },
      // testPoliticasConfiguracao - per-object tests
      'risky_uac_params': {
        titleTemplate: (name) => `UAC arriscado: ${name}`,
        descriptionTemplate: (name, details) => `A conta ${name} possui flags UserAccountControl arriscadas${details?.userAccountControl ? ` (UAC: ${details.userAccountControl})` : ''}`,
        objectNameField: 'Name',
        objectType: 'user',
      },
      'dns_admins_standard_users': {
        titleTemplate: (name) => `Usuário padrão como DnsAdmin: ${name}`,
        descriptionTemplate: (name) => `O usuário ${name} é membro do grupo DnsAdmins, que tem privilégios elevados no domínio`,
        objectNameField: 'SamAccountName',
        objectType: 'user',
      },
      'non_canonical_ace': {
        titleTemplate: (name) => `ACE não-canônico: ${name}`,
        descriptionTemplate: (name) => `O objeto ${name} possui Access Control Entries em ordem não-canônica, podendo causar comportamento inesperado de permissões`,
        objectNameField: 'DistinguishedName',
        objectType: 'computer',
      },
      'orphan_krbtgt_rodc': {
        titleTemplate: (name) => `KRBTGT RODC órfão: ${name}`,
        descriptionTemplate: (name) => `A conta krbtgt ${name} está órfã, pertencendo a um RODC que não existe mais no domínio`,
        objectNameField: 'Name',
        objectType: 'user',
      },
    };

    return templates[testId] || null;
  }

  /**
   * Creates individual findings for each object in the test result
   * Uses templates for personalized title/description per object
   * Falls back to generic per-object findings when no template exists
   */
  private createPerObjectFindings(
    test: ADSecurityTest,
    domain: string,
    output: string,
    result: PowerShellExecutionResult
  ): ADFinding[] {
    const findings: ADFinding[] = [];
    const template = this.getPerObjectTemplate(test.id);
    
    try {
      const data = JSON.parse(output);
      const objects = Array.isArray(data) ? data : [data];
      
      if (objects.length === 0) {
        return [];
      }
      
      // Determine if this test returns a list of objects that should be split
      // If only 1 object or non-list test, create single finding
      if (objects.length === 1 && !template) {
        // Single object without template - use legacy format
        return [{
          type: this.getTypeForTest(test.id),
          target: domain,
          name: test.nome,
          severity: test.severidade,
          category: 'users',
          description: test.description || `Teste ${test.nome} identificou problemas de segurança`,
          recommendation: test.recommendation || 'Revisar e corrigir os problemas identificados',
          evidence: {
            testId: test.id,
            domain: domain,
            command: result.command || test.powershell,
            stdout: result.stdout.substring(0, MAX_EVIDENCE_STDOUT),
            stderr: result.stderr.substring(0, MAX_EVIDENCE_STDERR),
            exitCode: result.exitCode,
          }
        }];
      }
      
      // Create individual finding for each object
      for (const obj of objects) {
        // Get unique identifier - prefer SamAccountName, then Name, then SID
        const samAccountName = obj.SamAccountName || obj.samAccountName;
        const objectSid = obj.SID || obj.sid || obj.objectSid;
        const objectName = samAccountName || obj.Name || obj.name || 'Unknown';
        // Use the most stable identifier available for correlation
        const stableId = samAccountName || objectSid || objectName;
        
        // Map objectType to appropriate category
        const objectType = template?.objectType || 'user';
        let category: ADFinding['category'] = 'users';
        if (objectType === 'computer' || objectType === 'dc') category = 'computers';
        else if (objectType === 'group') category = 'groups';
        else if (objectType === 'trust') category = 'configuration';
        else if (objectType === 'service_account' || objectType === 'gmsa') category = 'users'; // Service accounts are a type of user
        
        if (template) {
          // Use template for personalized finding
          findings.push({
            type: this.getTypeForTest(test.id),
            target: domain,
            name: template.titleTemplate(objectName),
            severity: test.severidade,
            category,
            description: template.descriptionTemplate(objectName, obj),
            recommendation: test.recommendation || 'Revisar e corrigir o problema identificado',
            evidence: {
              testId: test.id,
              objectId: stableId, // Use stable identifier for correlation
              objectName: objectName,
              objectType: template.objectType,
              objectData: obj,
              domain: domain,
              command: result.command || test.powershell,
              stdout: result.stdout.substring(0, MAX_PEROBJECT_STDOUT), // Truncated to avoid huge payloads
              stderr: result.stderr.substring(0, MAX_PEROBJECT_STDERR),
              exitCode: result.exitCode,
            }
          });
        } else {
          // Generic per-object finding (no template defined)
          findings.push({
            type: this.getTypeForTest(test.id),
            target: domain,
            name: `${test.nome}: ${objectName}`,
            severity: test.severidade,
            category,
            description: `${test.description || test.nome} - Objeto afetado: ${objectName}`,
            recommendation: test.recommendation || 'Revisar e corrigir o problema identificado',
            evidence: {
              testId: test.id,
              objectId: stableId, // Use stable identifier for correlation
              objectName: objectName,
              objectType: 'user',
              objectData: obj,
              domain: domain,
              command: result.command || test.powershell,
              stdout: result.stdout.substring(0, MAX_PEROBJECT_STDOUT),
              stderr: result.stderr.substring(0, MAX_PEROBJECT_STDERR),
              exitCode: result.exitCode,
            }
          });
        }
      }
      
      console.log(`✅ Criados ${findings.length} findings individuais para teste ${test.id}`);
      return findings;
      
    } catch (error) {
      console.error(`⚠️ Erro ao processar objetos para ${test.id}:`, error);
      // Fallback to single finding with full evidence
      return [{
        type: this.getTypeForTest(test.id),
        target: domain,
        name: test.nome,
        severity: test.severidade,
        category: 'users',
        description: test.description || `Teste ${test.nome} identificou problemas de segurança`,
        recommendation: test.recommendation || 'Revisar e corrigir os problemas identificados',
        evidence: {
          testId: test.id,
          domain: domain,
          command: result.command || test.powershell,
          stdout: result.stdout.substring(0, MAX_EVIDENCE_STDOUT),
          stderr: result.stderr.substring(0, MAX_EVIDENCE_STDERR),
          exitCode: result.exitCode,
        }
      }];
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
   * Descobre workstations do domínio via PowerShell/WinRM
   */
  async discoverWorkstations(
    domain: string,
    username: string,
    password: string,
    dcHost?: string
  ): Promise<string[]> {
    console.log(`🔍 Descobrindo workstations do domínio ${domain}...`);

    this.domain = domain;
    this.baseDN = this.buildBaseDN(domain);

    // PowerShell command to list all computer objects (workstations)
    const psCommand = `
      Get-ADComputer -Filter {OperatingSystem -like "*Windows*" -and Enabled -eq $true} -Properties DNSHostName, OperatingSystem | 
      Where-Object {$_.OperatingSystem -notlike "*Server*"} | 
      Select-Object -ExpandProperty DNSHostName
    `.trim();

    try {
      // Discover DC if not provided
      let targetDC = dcHost;
      if (!targetDC) {
        const dcs = await this.discoverDomainControllers(domain);
        if (dcs.length === 0) {
          throw new Error(`Nenhum controlador de domínio encontrado para ${domain}`);
        }
        targetDC = dcs[0];
        console.log(`🎯 Usando DC descoberto: ${targetDC}`);
      }

      const result = await this.executePowerShell(
        targetDC,
        domain,
        username,
        password,
        psCommand
      );

      if (result.success && result.stdout.trim()) {
        // Parse workstation list from stdout (one per line)
        const workstations = result.stdout
          .split('\n')
          .map((line: string) => line.trim())
          .filter((line: string) => line.length > 0 && line.includes('.'));

        console.log(`✅ Descobertas ${workstations.length} workstations`);
        return workstations;
      } else {
        console.log(`⚠️  Nenhuma workstation encontrada (exitCode: ${result.exitCode})`);
        return [];
      }
    } catch (error: any) {
      console.error(`❌ Erro ao descobrir workstations: ${error.message}`);
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
