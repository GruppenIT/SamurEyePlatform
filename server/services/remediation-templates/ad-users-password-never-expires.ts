import type { RecommendationContext, GeneratedRecommendation } from './types';

export function generate(ctx: RecommendationContext): GeneratedRecommendation {
  const ev = ctx.evidence;
  const target = ev.target || 'domínio';
  const recommendation = ev.recommendation || '';

  return {
    title: `Usuários com senha que nunca expira no domínio ${target}`,
    whatIsWrong: `Existem usuários no Active Directory do domínio "${target}" com a flag "Senha nunca expira" ativada.`,
    businessImpact: `Senhas que nunca expiram aumentam o risco de comprometimento de credenciais a longo prazo. Senhas antigas podem estar em uso por anos sem rotação obrigatória.`,
    fixSteps: [
      recommendation || `Identifique os usuários com senha que nunca expira:`,
      `Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires | Select-Object Name, SamAccountName`,
      `Para cada usuário afetado (exceto contas de serviço com justificativa), remova a flag:`,
      `Get-ADUser -Filter {PasswordNeverExpires -eq $true} | Set-ADUser -PasswordNeverExpires $false`,
      `Configure a política de expiração de senhas no domínio (recomendado: 90 dias ou conforme política interna).`,
      `Contas de serviço que precisam de senha permanente devem ser documentadas e monitoradas.`,
    ].filter(Boolean),
    verificationStep: `Execute: Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires | Measure-Object | Select-Object Count — o resultado deve ser zero ou apenas contas de serviço documentadas.`,
    references: [
      'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age',
    ],
    effortTag: 'minutes',
    roleRequired: 'sysadmin',
    hostSpecificData: { target },
  };
}
