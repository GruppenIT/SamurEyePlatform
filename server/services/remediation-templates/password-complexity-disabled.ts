import type { RecommendationContext, GeneratedRecommendation } from './types';

export function generate(ctx: RecommendationContext): GeneratedRecommendation {
  const ev = ctx.evidence;
  const target = ev.target || 'domínio';
  const recommendation = ev.recommendation || '';

  return {
    title: `Complexidade de senha desabilitada no domínio: ${target}`,
    whatIsWrong: `A política de complexidade de senha está desabilitada no domínio "${target}", permitindo senhas simples e facilmente adivinhadas.`,
    businessImpact: `Senhas sem requisito de complexidade são vulneráveis a ataques de dicionário e força bruta, facilitando o comprometimento de contas.`,
    fixSteps: [
      recommendation || `Habilite a complexidade de senha no domínio:`,
      `Set-ADDefaultDomainPasswordPolicy -Identity ${target} -ComplexityEnabled $true`,
      `A complexidade exige: maiúsculas, minúsculas, números e caracteres especiais.`,
      `Notifique os usuários sobre a nova política — eles precisarão alterar as senhas no próximo login.`,
      `Considere implementar Azure AD Password Protection para bloquear senhas comuns.`,
    ].filter(Boolean),
    verificationStep: `Execute: Get-ADDefaultDomainPasswordPolicy | Select-Object ComplexityEnabled — deve retornar True.`,
    references: [
      'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements',
    ],
    effortTag: 'minutes',
    roleRequired: 'sysadmin',
    hostSpecificData: { target },
  };
}
