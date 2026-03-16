import type { RecommendationContext, GeneratedRecommendation } from './types';

export function generate(ctx: RecommendationContext): GeneratedRecommendation {
  const ev = ctx.evidence;
  const target = ev.target || 'domínio';
  const recommendation = ev.recommendation || '';

  return {
    title: `Usuários inativos no Active Directory: ${target}`,
    whatIsWrong: `Existem contas de usuário ativas no AD do domínio "${target}" que não fizeram login há mais de 90 dias.`,
    businessImpact: `Contas inativas que permanecem habilitadas são vetores de ataque para acesso não autorizado, especialmente se as credenciais foram comprometidas sem que o usuário saiba.`,
    fixSteps: [
      recommendation || `Identifique usuários inativos (sem login há 90+ dias):`,
      `$Data = (Get-Date).AddDays(-90)`,
      `Get-ADUser -Filter {LastLogonDate -lt $Data -and Enabled -eq $true} -Properties LastLogonDate | Select-Object Name, SamAccountName, LastLogonDate`,
      `Desabilite as contas inativas após confirmar com o RH/gestor:`,
      `Get-ADUser -Filter {LastLogonDate -lt $Data -and Enabled -eq $true} | Disable-ADAccount`,
      `Mova as contas desabilitadas para uma OU de quarentena antes de excluir.`,
      `Implemente um processo de revisão periódica de contas inativas (recomendado: trimestral).`,
    ].filter(Boolean),
    verificationStep: `Execute novamente o relatório de usuários inativos e confirme que as contas identificadas foram desabilitadas.`,
    references: [
      'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-principals',
    ],
    effortTag: 'minutes',
    roleRequired: 'sysadmin',
    hostSpecificData: { target },
  };
}
