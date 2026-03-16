import type { RecommendationContext, GeneratedRecommendation } from './types';

export function generate(ctx: RecommendationContext): GeneratedRecommendation {
  const ev = ctx.evidence;
  const target = ev.target || 'domínio';
  const recommendation = ev.recommendation || '';

  return {
    title: `Computadores inativos no Active Directory: ${target}`,
    whatIsWrong: `Contas de computador inativas (sem login há 90+ dias) foram detectadas no AD do domínio "${target}".`,
    businessImpact: `Contas de computador ativas mas não utilizadas podem ser exploradas para persistência e movimentação lateral na rede.`,
    fixSteps: [
      recommendation || `Identifique computadores inativos no AD:`,
      `$Data = (Get-Date).AddDays(-90)`,
      `Get-ADComputer -Filter {LastLogonDate -lt $Data -and Enabled -eq $true} -Properties LastLogonDate | Select-Object Name, LastLogonDate`,
      `Desabilite os computadores inativos após verificação com o inventário de ativos:`,
      `Get-ADComputer -Filter {LastLogonDate -lt $Data -and Enabled -eq $true} | Disable-ADAccount`,
      `Mova as contas desabilitadas para OU de quarentena e revise em 30 dias antes de excluir.`,
    ].filter(Boolean),
    verificationStep: `Execute novamente o relatório de computadores inativos e confirme redução no número de contas ativas sem uso.`,
    references: [
      'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-principals',
    ],
    effortTag: 'minutes',
    roleRequired: 'sysadmin',
    hostSpecificData: { target },
  };
}
