import type { RecommendationContext, GeneratedRecommendation } from './types';

export function generate(ctx: RecommendationContext): GeneratedRecommendation {
  const ev = ctx.evidence;
  const hostname = ev.hostname || 'desconhecido';
  const filePath = ev.filePath || '';
  const deploymentMethod = ev.deploymentMethod || '';
  const eicarPersisted = ev.eicarPersisted;
  const recommendation = ev.recommendation || '';

  const fixSteps: string[] = [];

  if (recommendation) {
    fixSteps.push(recommendation);
  }

  const additionalSteps = [
    `Verifique o status do agente de EDR/AV no host ${hostname}: o agente está instalado, ativo e atualizado?`,
    `Confirme que o antivírus não está em modo passivo ou com proteção em tempo real desabilitada.`,
    deploymentMethod ? `Método de implantação detectado: "${deploymentMethod}". Verifique a configuração de implantação.` : '',
    filePath ? `Arquivo de teste EICAR localizado em: ${filePath}. Verifique por que não foi detectado.` : '',
    eicarPersisted ? `O arquivo EICAR persistiu após o teste, indicando que a proteção em tempo real não está funcionando. Reinicie o serviço do AV.` : '',
    `Atualize as assinaturas do antivírus para a versão mais recente.`,
    `Verifique exclusões de diretórios que possam estar impedindo a detecção.`,
    `Abra um chamado com o fornecedor do EDR/AV se o problema persistir após a reinicialização.`,
  ].filter(Boolean) as string[];
  fixSteps.push(...additionalSteps);

  return {
    title: `Falha no EDR/AV no host ${hostname}`,
    whatIsWrong: `O agente de EDR/Antivírus no host "${hostname}" falhou no teste de detecção EICAR, indicando que a proteção em tempo real pode estar comprometida.`,
    businessImpact: `Um endpoint sem proteção ativa de EDR/AV é vulnerável a malware, ransomware e ataques de endpoint, podendo resultar em perda de dados e comprometimento da rede.`,
    fixSteps,
    verificationStep: `Execute o teste EICAR novamente no host ${hostname} e confirme que o arquivo é detectado e removido imediatamente.`,
    references: [
      'https://www.eicar.org/download-anti-malware-testfile/',
      'https://attack.mitre.org/tactics/TA0040/',
    ],
    effortTag: 'hours',
    roleRequired: 'sysadmin',
    hostSpecificData: { hostname, filePath, deploymentMethod, eicarPersisted },
  };
}
