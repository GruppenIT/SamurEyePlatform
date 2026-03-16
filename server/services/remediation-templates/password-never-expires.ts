import type { RecommendationContext, GeneratedRecommendation } from './types';

export function generate(ctx: RecommendationContext): GeneratedRecommendation {
  const ev = ctx.evidence;
  const target = ev.target || 'usuário';
  const recommendation = ev.recommendation || '';

  return {
    title: `Senha que nunca expira: ${target}`,
    whatIsWrong: `A conta "${target}" tem a flag "Senha nunca expira" ativada no Active Directory.`,
    businessImpact: `Senhas que nunca expiram podem permanecer em uso por anos sem rotação, aumentando o risco de credenciais comprometidas serem usadas indefinidamente.`,
    fixSteps: [
      recommendation || `Verifique a configuração da conta "${target}":`,
      `Get-ADUser -Identity "${target}" -Properties PasswordNeverExpires | Select-Object Name, PasswordNeverExpires`,
      `Remova a flag de senha que nunca expira (exceto para contas de serviço com justificativa):`,
      `Set-ADUser -Identity "${target}" -PasswordNeverExpires $false`,
      `Force a troca de senha na próxima autenticação:`,
      `Set-ADUser -Identity "${target}" -ChangePasswordAtLogon $true`,
      `Para contas de serviço que precisam de senha permanente, documente a exceção e monitore.`,
    ].filter(Boolean),
    verificationStep: `Execute: Get-ADUser "${target}" -Properties PasswordNeverExpires | Select-Object PasswordNeverExpires — deve retornar False.`,
    references: [
      'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age',
    ],
    effortTag: 'minutes',
    roleRequired: 'sysadmin',
    hostSpecificData: { target },
  };
}
