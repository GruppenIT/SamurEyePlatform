import type { RecommendationContext, GeneratedRecommendation } from './types';

export function generate(ctx: RecommendationContext): GeneratedRecommendation {
  const ev = ctx.evidence;
  const target = ev.target || 'domínio';
  const recommendation = ev.recommendation || '';

  return {
    title: `Histórico de senha insuficiente no domínio: ${target}`,
    whatIsWrong: `O histórico de senhas no domínio "${target}" é muito curto, permitindo que usuários reutilizem senhas recentes.`,
    businessImpact: `Histórico insuficiente permite reutilização de senhas comprometidas, anulando os benefícios da rotação periódica.`,
    fixSteps: [
      recommendation || `Verifique o histórico de senha atual:`,
      `Get-ADDefaultDomainPasswordPolicy | Select-Object PasswordHistoryCount`,
      `Atualize o histórico para pelo menos 24 senhas:`,
      `Set-ADDefaultDomainPasswordPolicy -Identity ${target} -PasswordHistoryCount 24`,
      `Isso impede que usuários reciclem senhas anteriores durante os próximos 24 ciclos de troca.`,
    ].filter(Boolean),
    verificationStep: `Execute: Get-ADDefaultDomainPasswordPolicy | Select-Object PasswordHistoryCount — deve ser >= 24.`,
    references: [
      'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/enforce-password-history',
    ],
    effortTag: 'minutes',
    roleRequired: 'sysadmin',
    hostSpecificData: { target },
  };
}
