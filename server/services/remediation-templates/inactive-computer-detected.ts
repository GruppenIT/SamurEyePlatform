import type { RecommendationContext, GeneratedRecommendation } from './types';

export function generate(ctx: RecommendationContext): GeneratedRecommendation {
  const ev = ctx.evidence;
  const target = ev.target || 'computador';
  const recommendation = ev.recommendation || '';

  return {
    title: `Computador inativo detectado: ${target}`,
    whatIsWrong: `O computador "${target}" está ativo no AD mas não realizou login na rede há mais de 90 dias.`,
    businessImpact: `Computadores inativos com contas ativas podem ser explorados para persistência e acesso não autorizado à rede.`,
    fixSteps: [
      recommendation || `Verifique o último login do computador:`,
      `Get-ADComputer -Identity "${target}" -Properties LastLogonDate | Select-Object Name, LastLogonDate, Enabled`,
      `Confirme com o setor responsável se o equipamento ainda está em uso.`,
      `Se inativo, desabilite a conta do computador no AD:`,
      `Disable-ADAccount -Identity "${target}$"`,
      `Documente o descomissionamento no inventário de ativos.`,
    ].filter(Boolean),
    verificationStep: `Execute: Get-ADComputer -Identity "${target}" -Properties Enabled | Select-Object Enabled — deve retornar False.`,
    references: [
      'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-principals',
    ],
    effortTag: 'minutes',
    roleRequired: 'sysadmin',
    hostSpecificData: { target },
  };
}
