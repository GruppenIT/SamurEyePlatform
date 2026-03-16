import type { RecommendationContext, GeneratedRecommendation } from './types';

export function generate(ctx: RecommendationContext): GeneratedRecommendation {
  const ev = ctx.evidence;
  const target = ev.target || 'domínio';
  const recommendation = ev.recommendation || '';

  return {
    title: `Controlador de domínio não encontrado: ${target}`,
    whatIsWrong: `Não foi possível localizar ou conectar ao controlador de domínio do ambiente "${target}" durante a varredura de segurança do AD.`,
    businessImpact: `A ausência ou inacessibilidade do controlador de domínio pode indicar problemas de replicação, falha de serviços críticos, ou configuração incorreta que impede a execução de auditorias de segurança.`,
    fixSteps: [
      recommendation || `Verifique o status dos controladores de domínio no ambiente "${target}":`,
      `dcdiag /test:connectivity /v`,
      `nltest /dsgetdc:${target}`,
      `Verifique se os serviços de AD DS estão rodando: Get-Service ADWS, NTDS, DNS, KDC`,
      `Confirme que as credenciais de serviço têm permissão de consulta LDAP ao domínio "${target}".`,
      `Verifique firewall: porta 389 (LDAP) e 636 (LDAPS) devem estar acessíveis ao agente de varredura.`,
    ].filter(Boolean),
    verificationStep: `Execute: nltest /dsgetdc:${target} — deve retornar um DC acessível sem erros.`,
    references: [
      'https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/troubleshoot-domain-controller-locator',
    ],
    effortTag: 'days',
    roleRequired: 'sysadmin',
    hostSpecificData: { target },
  };
}
