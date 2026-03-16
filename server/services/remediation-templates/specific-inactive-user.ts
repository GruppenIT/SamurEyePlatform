import type { RecommendationContext, GeneratedRecommendation } from './types';

export function generate(ctx: RecommendationContext): GeneratedRecommendation {
  const ev = ctx.evidence;
  const target = ev.target || 'usuário';
  const recommendation = ev.recommendation || '';

  return {
    title: `Usuário inativo específico: ${target}`,
    whatIsWrong: `A conta de usuário "${target}" está ativa no AD mas não realizou login há mais de 90 dias.`,
    businessImpact: `Contas inativas ativas representam risco de uso não autorizado, especialmente se as credenciais foram comprometidas sem que o usuário saiba.`,
    fixSteps: [
      recommendation || `Verifique o último login do usuário:`,
      `Get-ADUser -Identity "${target}" -Properties LastLogonDate | Select-Object Name, LastLogonDate, Enabled`,
      `Confirme com o gestor ou RH se a conta ainda é necessária.`,
      `Se não necessária, desabilite a conta:`,
      `Disable-ADAccount -Identity "${target}"`,
      `Mova para OU de quarentena e documente a desativação.`,
    ].filter(Boolean),
    verificationStep: `Execute: Get-ADUser -Identity "${target}" -Properties Enabled | Select-Object Enabled — deve retornar False.`,
    references: [
      'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-principals',
    ],
    effortTag: 'minutes',
    roleRequired: 'sysadmin',
    hostSpecificData: { target },
  };
}
