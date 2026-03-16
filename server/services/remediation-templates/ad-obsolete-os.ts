import type { RecommendationContext, GeneratedRecommendation } from './types';

export function generate(ctx: RecommendationContext): GeneratedRecommendation {
  const ev = ctx.evidence;
  const target = ev.target || 'domínio';
  const recommendation = ev.recommendation || '';

  return {
    title: `Sistemas operacionais obsoletos no AD: ${target}`,
    whatIsWrong: `Computadores com sistemas operacionais sem suporte (EOL) foram detectados no Active Directory do domínio "${target}".`,
    businessImpact: `Sistemas sem suporte não recebem patches de segurança, tornando-os vulneráveis a exploits conhecidos sem correção disponível.`,
    fixSteps: [
      recommendation || `Identifique computadores com SO obsoleto no AD:`,
      `Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion | Where-Object {$_.OperatingSystem -like "*2003*" -or $_.OperatingSystem -like "*XP*" -or $_.OperatingSystem -like "*Vista*" -or $_.OperatingSystem -like "*2008*"} | Select-Object Name, OperatingSystem`,
      `Planeje a migração ou atualização dos sistemas identificados.`,
      `Se a migração for inviável a curto prazo, isole os sistemas obsoletos em VLAN segmentada.`,
      `Implemente controles compensatórios: WAF, monitoramento reforçado, acesso restrito.`,
    ].filter(Boolean),
    verificationStep: `Execute novamente a consulta de SO obsoleto no AD e confirme que o número de sistemas afetados foi reduzido ou isolados.`,
    references: [
      'https://learn.microsoft.com/en-us/lifecycle/',
      'https://www.cisecurity.org/controls/continuous-vulnerability-management/',
    ],
    effortTag: 'weeks',
    roleRequired: 'sysadmin',
    hostSpecificData: { target },
  };
}
