import type { RecommendationContext, GeneratedRecommendation } from './types';

export function generate(ctx: RecommendationContext): GeneratedRecommendation {
  const ev = ctx.evidence;
  const target = ev.target || 'domínio';
  const recommendation = ev.recommendation || '';

  return {
    title: `Política de senhas fraca no domínio: ${target}`,
    whatIsWrong: `A política de senhas do domínio "${target}" não atende aos requisitos mínimos de segurança (comprimento, complexidade, histórico ou expiração).`,
    businessImpact: `Políticas de senha inadequadas facilitam ataques de força bruta, dicionário e reutilização de credenciais comprometidas.`,
    fixSteps: [
      recommendation || `Revise a política de senha atual do domínio:`,
      `Get-ADDefaultDomainPasswordPolicy`,
      `Atualize a política para atender ao mínimo recomendado:`,
      `Set-ADDefaultDomainPasswordPolicy -Identity ${target} -MinPasswordLength 14 -ComplexityEnabled $true -PasswordHistoryCount 24 -MaxPasswordAge (New-TimeSpan -Days 90) -MinPasswordAge (New-TimeSpan -Days 1)`,
      `Considere implementar Fine-Grained Password Policies para grupos específicos.`,
      `Habilite o Azure AD Password Protection ou similar para bloquear senhas comuns.`,
    ].filter(Boolean),
    verificationStep: `Execute: Get-ADDefaultDomainPasswordPolicy — verifique MinPasswordLength >= 14, ComplexityEnabled = True, MaxPasswordAge <= 90 dias.`,
    references: [
      'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy',
      'https://www.cisecurity.org/benchmark/microsoft_windows_server/',
    ],
    effortTag: 'minutes',
    roleRequired: 'sysadmin',
    hostSpecificData: { target },
  };
}
