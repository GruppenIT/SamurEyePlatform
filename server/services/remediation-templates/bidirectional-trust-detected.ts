import type { RecommendationContext, GeneratedRecommendation } from './types';

export function generate(ctx: RecommendationContext): GeneratedRecommendation {
  const ev = ctx.evidence;
  const target = ev.target || 'domínio';
  const recommendation = ev.recommendation || '';

  return {
    title: `Confiança bidirecional entre domínios detectada: ${target}`,
    whatIsWrong: `Foi detectada uma relação de confiança bidirecional (bidirectional trust) no domínio "${target}", o que significa que usuários de ambos os domínios podem autenticar no outro.`,
    businessImpact: `Trusts bidirecionais ampliam o raio de impacto de um comprometimento: se um domínio for comprometido, o atacante pode mover-se lateralmente para o domínio confiante. Isso é especialmente crítico em relações entre domínios de diferentes organizações.`,
    fixSteps: [
      recommendation || `Revise as relações de confiança no domínio "${target}":`,
      `Get-ADTrust -Filter * | Select-Object Name, Direction, TrustType, TrustAttributes`,
      `Para cada trust bidirecional, avalie se a confiança realmente precisa ser nos dois sentidos.`,
      `Se possível, converta para confiança unidirecional (one-way trust):`,
      `Remove-ADTrust -Identity <trust_dn> -Confirm:$false`,
      `New-ADTrust -Name <dominio_remoto> -TrustType External -Direction Inbound`,
      `Implemente SID filtering para evitar escalada de privilégios via SID History.`,
      `Revise permissões de grupos de outros domínios confiáveis em recursos locais.`,
    ].filter(Boolean),
    verificationStep: `Execute: Get-ADTrust -Filter * | Where-Object {$_.Direction -eq "BiDirectional"} — deve retornar vazio ou lista justificada.`,
    references: [
      'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/forest-design-models',
      'https://attack.mitre.org/techniques/T1482/',
    ],
    effortTag: 'days',
    roleRequired: 'security',
    hostSpecificData: { target },
  };
}
