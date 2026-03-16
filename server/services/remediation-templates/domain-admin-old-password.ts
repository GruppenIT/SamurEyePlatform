import type { RecommendationContext, GeneratedRecommendation } from './types';

export function generate(ctx: RecommendationContext): GeneratedRecommendation {
  const ev = ctx.evidence;
  const target = ev.target || 'domínio';
  const recommendation = ev.recommendation || '';

  return {
    title: `Administrador de domínio com senha antiga: ${target}`,
    whatIsWrong: `Uma ou mais contas de Domain Admin no domínio "${target}" não alteraram a senha há mais de 90 dias.`,
    businessImpact: `Senhas antigas de administradores de domínio representam alto risco: quanto mais antiga a senha, maior a probabilidade de já estar em listas de senhas comprometidas em ataques de credential stuffing.`,
    fixSteps: [
      recommendation || `Identifique Domain Admins com senhas antigas:`,
      `$Data = (Get-Date).AddDays(-90)`,
      `Get-ADGroupMember "Domain Admins" | Get-ADUser -Properties PasswordLastSet | Where-Object {$_.PasswordLastSet -lt $Data} | Select-Object Name, SamAccountName, PasswordLastSet`,
      `Force a troca de senha para os administradores identificados:`,
      `Set-ADUser -Identity <usuario> -ChangePasswordAtLogon $true`,
      `Defina uma nova senha forte (mínimo 20 caracteres) para contas de serviço administrativo.`,
      `Configure alertas de expiração de senha para contas de Domain Admin com 30 dias de antecedência.`,
    ].filter(Boolean),
    verificationStep: `Confirme que todas as contas de Domain Admin têm PasswordLastSet nos últimos 90 dias.`,
    references: [
      'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory',
    ],
    effortTag: 'minutes',
    roleRequired: 'security',
    hostSpecificData: { target },
  };
}
