import type { RecommendationContext, GeneratedRecommendation } from './types';

export function generate(ctx: RecommendationContext): GeneratedRecommendation {
  const ev = ctx.evidence;
  const target = ev.target || 'domínio';
  const recommendation = ev.recommendation || '';

  return {
    title: `Usuários com senhas antigas no domínio ${target}`,
    whatIsWrong: `Há usuários no AD do domínio "${target}" com senhas que não são alteradas há mais de 180 dias.`,
    businessImpact: `Senhas antigas têm maior probabilidade de já terem sido comprometidas em vazamentos de dados. A rotação periódica de senhas reduz a janela de exposição.`,
    fixSteps: [
      recommendation || `Identifique usuários com senhas antigas:`,
      `$Data = (Get-Date).AddDays(-180)`,
      `Get-ADUser -Filter {PasswordLastSet -lt $Data -and Enabled -eq $true} -Properties PasswordLastSet | Select-Object Name, SamAccountName, PasswordLastSet`,
      `Force a troca de senha no próximo login para os usuários identificados:`,
      `Get-ADUser -Filter {PasswordLastSet -lt $Data -and Enabled -eq $true} | Set-ADUser -ChangePasswordAtLogon $true`,
      `Configure a política de senha máxima no GPO: Configuração do Computador → Configurações do Windows → Configurações de Segurança → Políticas de Conta → Política de Senha → Tempo de vida máximo da senha: 90 dias.`,
    ].filter(Boolean),
    verificationStep: `Verifique que a política de expiração de senha está ativa e que os usuários identificados trocaram suas senhas.`,
    references: [
      'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age',
      'https://www.cisecurity.org/benchmark/microsoft_windows_server/',
    ],
    effortTag: 'minutes',
    roleRequired: 'security',
    hostSpecificData: { target },
  };
}
