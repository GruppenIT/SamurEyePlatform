import type { RecommendationContext, GeneratedRecommendation } from './types';

export function generate(ctx: RecommendationContext): GeneratedRecommendation {
  const ev = ctx.evidence;
  const target = ev.target || 'domínio';
  const recommendation = ev.recommendation || '';

  return {
    title: `Membros excessivos em grupos privilegiados no AD: ${target}`,
    whatIsWrong: `Grupos privilegiados (Domain Admins, Enterprise Admins, etc.) no domínio "${target}" possuem membros em excesso ou usuários que não deveriam ter esses privilégios.`,
    businessImpact: `Excesso de membros em grupos privilegiados aumenta a superficie de ataque para escalada de privilégios e comprometimento do domínio.`,
    fixSteps: [
      recommendation || `Revise os membros dos grupos privilegiados do AD:`,
      `Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select-Object Name, SamAccountName`,
      `Get-ADGroupMember -Identity "Enterprise Admins" -Recursive | Select-Object Name, SamAccountName`,
      `Remova usuários que não precisam de privilégios administrativos:`,
      `Remove-ADGroupMember -Identity "Domain Admins" -Members <usuario> -Confirm:$false`,
      `Implemente o princípio do menor privilégio — administradores devem usar contas separadas para tarefas administrativas.`,
      `Habilite auditoria de mudanças em grupos privilegiados.`,
    ].filter(Boolean),
    verificationStep: `Execute: Get-ADGroupMember "Domain Admins" | Measure-Object — número de membros deve ser mínimo (idealmente < 5).`,
    references: [
      'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models',
      'https://attack.mitre.org/techniques/T1078/002/',
    ],
    effortTag: 'hours',
    roleRequired: 'sysadmin',
    hostSpecificData: { target },
  };
}
