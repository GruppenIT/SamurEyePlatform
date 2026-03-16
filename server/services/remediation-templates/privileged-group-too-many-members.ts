import type { RecommendationContext, GeneratedRecommendation } from './types';

export function generate(ctx: RecommendationContext): GeneratedRecommendation {
  const ev = ctx.evidence;
  const target = ev.target || 'domínio';
  const recommendation = ev.recommendation || '';

  return {
    title: `Grupo privilegiado com muitos membros: ${target}`,
    whatIsWrong: `Um grupo privilegiado no domínio "${target}" possui mais membros do que o necessário, violando o princípio do menor privilégio.`,
    businessImpact: `Grupos privilegiados superlotados aumentam o risco de abuso de privilégios, comprometimento de contas e escalada de acesso.`,
    fixSteps: [
      recommendation || `Liste todos os membros do grupo privilegiado:`,
      `Get-ADGroupMember -Identity "<grupo_privilegiado>" -Recursive | Select-Object Name, SamAccountName, ObjectClass`,
      `Para cada membro, avalie se o nível de acesso é necessário para a função do usuário.`,
      `Remova membros sem justificativa:`,
      `Remove-ADGroupMember -Identity "<grupo_privilegiado>" -Members <usuario> -Confirm:$false`,
      `Documente os membros restantes e sua justificativa de acesso.`,
      `Implemente revisão semestral de membros em grupos privilegiados.`,
    ].filter(Boolean),
    verificationStep: `Execute: Get-ADGroupMember "<grupo>" | Measure-Object — número deve ser reduzido ao mínimo necessário.`,
    references: [
      'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models',
    ],
    effortTag: 'hours',
    roleRequired: 'sysadmin',
    hostSpecificData: { target },
  };
}
