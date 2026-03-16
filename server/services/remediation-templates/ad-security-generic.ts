import type { RecommendationContext, GeneratedRecommendation } from './types';

export function generate(ctx: RecommendationContext): GeneratedRecommendation {
  const ev = ctx.evidence;
  const target = ev.target || 'domínio';
  const recommendation = ev.recommendation || 'Revise a configuração de segurança do Active Directory conforme as melhores práticas.';
  const command = ev.command || '';
  const testId = ev.testId || '';

  const fixSteps: string[] = [
    recommendation,
    command ? `Comando de diagnóstico: ${command}` : '',
    testId ? `ID do teste de segurança: ${testId}` : '',
    `Consulte as diretrizes de segurança do Active Directory da Microsoft para o ambiente "${target}".`,
    `Implemente os controles de segurança recomendados pelas políticas CIS Benchmark para Active Directory.`,
  ].filter(Boolean);

  return {
    title: `Problema de segurança no Active Directory: ${target}`,
    whatIsWrong: `Foi detectado um problema de segurança no Active Directory do ambiente "${target}" que requer atenção.`,
    businessImpact: `Configurações inadequadas no Active Directory podem permitir escalada de privilégios, movimentação lateral e comprometimento do domínio.`,
    fixSteps,
    verificationStep: `Execute novamente o teste de segurança do AD para "${target}" e confirme que o problema foi resolvido.`,
    references: [
      'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory',
      'https://www.cisecurity.org/benchmark/microsoft_windows_server/',
    ],
    effortTag: 'hours',
    roleRequired: 'sysadmin',
    hostSpecificData: { target, testId },
  };
}
