import type { RecommendationContext, GeneratedRecommendation } from './types';

export function generate(ctx: RecommendationContext): GeneratedRecommendation {
  const ev = ctx.evidence;
  const target = ev.target || 'host';
  const recommendation = ev.recommendation || '';

  return {
    title: `Sistema operacional obsoleto detectado: ${target}`,
    whatIsWrong: `O host "${target}" está executando um sistema operacional que atingiu o fim de vida (EOL) e não recebe mais patches de segurança.`,
    businessImpact: `Sistemas sem suporte são vulneráveis a exploits conhecidos sem patches disponíveis. São alvos preferenciais de ransomware e comprometimento de rede.`,
    fixSteps: [
      recommendation || `Identifique a versão exata do SO no host "${target}":`,
      `# Windows: winver ou Get-ComputerInfo | Select-Object OsName, OsVersion`,
      `# Linux: cat /etc/os-release`,
      `Planeje a migração para uma versão com suporte ativo.`,
      `Se migração imediata for inviável:`,
      `- Isole o sistema em VLAN segmentada sem acesso direto à internet.`,
      `- Implemente monitoramento reforçado e logs centralizados.`,
      `- Aplique controles compensatórios: WAF, EDR, HIPS.`,
      `Documente a exceção com aprovação de risco e prazo para migração.`,
    ].filter(Boolean),
    verificationStep: `Confirme a migração ou isolamento do host "${target}" e documente a nova versão de SO instalada.`,
    references: [
      'https://learn.microsoft.com/en-us/lifecycle/',
      'https://endoflife.date/',
    ],
    effortTag: 'weeks',
    roleRequired: 'sysadmin',
    hostSpecificData: { target },
  };
}
