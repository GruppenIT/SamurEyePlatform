import type { RecommendationContext, GeneratedRecommendation } from './types';

export function generate(ctx: RecommendationContext): GeneratedRecommendation {
  const ev = ctx.evidence;
  const target = ev.target || 'domínio';
  const recommendation = ev.recommendation || '';

  return {
    title: `Senhas sem expiração configuradas no domínio: ${target}`,
    whatIsWrong: `A política de senhas do domínio "${target}" não exige expiração periódica de senhas.`,
    businessImpact: `Sem expiração de senha, credenciais comprometidas podem ser usadas indefinidamente sem que o ataque seja detectado.`,
    fixSteps: [
      recommendation || `Configure expiração de senha no domínio:`,
      `Set-ADDefaultDomainPasswordPolicy -Identity ${target} -MaxPasswordAge (New-TimeSpan -Days 90)`,
      `Configure alerta de expiração de senha com 14 dias de antecedência (padrão do Windows).`,
      `Exceção: contas de serviço com justificativa documentada podem ter senha permanente mas devem ser monitoradas.`,
    ].filter(Boolean),
    verificationStep: `Execute: Get-ADDefaultDomainPasswordPolicy | Select-Object MaxPasswordAge — deve ser <= 90 dias.`,
    references: [
      'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age',
    ],
    effortTag: 'minutes',
    roleRequired: 'sysadmin',
    hostSpecificData: { target },
  };
}
