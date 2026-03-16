import type { RecommendationContext, GeneratedRecommendation, EffortTag } from './types';

// Effort varies by service category
function getEffortForCategory(serviceCategory?: string): EffortTag {
  switch (serviceCategory) {
    case 'database':
    case 'email':
      return 'hours';
    default:
      return 'minutes';
  }
}

function getFixStepsForService(
  host: string,
  port: string,
  service: string,
  serviceCategory: string | undefined,
  hostFamily: string,
): string[] {
  const isWindows = hostFamily === 'windows_server' || hostFamily === 'windows_desktop';
  const isLinux = hostFamily === 'linux';

  if (serviceCategory === 'admin') {
    if (service === 'ms-wbt-server' || port === '3389') {
      if (isWindows) {
        return [
          `# No host ${host} (PowerShell como Administrador):`,
          `Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1`,
          `netsh advfirewall firewall set rule group="remote desktop" new enable=No`,
          `# Ou restrinja o acesso via firewall para IPs específicos:`,
          `netsh advfirewall firewall add rule name="Block RDP External" dir=in action=block protocol=tcp localport=${port} remoteip=0.0.0.0/0`,
        ];
      }
      if (isLinux) {
        return [
          `# No host ${host}:`,
          `systemctl stop xrdp`,
          `systemctl disable xrdp`,
          `ufw deny ${port}/tcp`,
        ];
      }
      return [`Desabilite o serviço de área de trabalho remota exposto em ${host}:${port}.`];
    }
    if (service === 'ssh' || port === '22') {
      if (isLinux) {
        return [
          `# No host ${host}:`,
          `# Restrinja SSH a redes internas — edite /etc/ssh/sshd_config:`,
          `echo "ListenAddress <IP_INTERNO>" >> /etc/ssh/sshd_config`,
          `systemctl restart sshd`,
          `ufw deny 22/tcp from any`,
          `ufw allow 22/tcp from 10.0.0.0/8`,
        ];
      }
      return [`Restrinja o acesso SSH no host ${host}:${port} a endereços IP internos confiáveis.`];
    }
  }

  if (serviceCategory === 'database') {
    if (isWindows) {
      return [
        `# No host ${host} (PowerShell):`,
        `# Bloqueie a porta ${port} no firewall do Windows:`,
        `netsh advfirewall firewall add rule name="Block DB Port ${port}" dir=in action=block protocol=tcp localport=${port}`,
        `# Se o serviço ${service} não for necessário externamente, vincule-o a 127.0.0.1 na configuração.`,
      ];
    }
    if (isLinux) {
      return [
        `# No host ${host}:`,
        `ufw deny ${port}/tcp`,
        `# Edite a configuração do ${service} para ouvir apenas em 127.0.0.1`,
        `# Ex. MySQL: bind-address = 127.0.0.1`,
      ];
    }
    return [
      `Restrinja o acesso ao banco de dados em ${host}:${port} a conexões locais ou de subnets internas autorizadas.`,
      `Configure a instância para não expor a porta ${port} para a internet.`,
    ];
  }

  if (serviceCategory === 'sharing') {
    return [
      `Desabilite o compartilhamento de arquivos exposto em ${host}:${port}.`,
      `Verifique se SMB/NFS é necessário externamente; caso contrário, bloqueie a porta ${port} no firewall de borda.`,
      isWindows
        ? `Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force`
        : `systemctl stop smbd nmbd; ufw deny ${port}/tcp`,
    ];
  }

  if (serviceCategory === 'web') {
    return [
      `Revise se a aplicação web em ${host}:${port} deve ser acessível externamente.`,
      `Se não necessário, remova a regra de firewall que permite acesso à porta ${port}.`,
      `Se necessário, implemente autenticação e restrinja por IP de origem.`,
    ];
  }

  // Generic fallback
  return [
    `Revise o serviço "${service}" exposto em ${host}:${port}.`,
    `Bloqueie o acesso externo à porta ${port} se o serviço não for necessário na internet.`,
    `Implemente regras de firewall para limitar o acesso a fontes confiáveis.`,
  ];
}

export function generate(ctx: RecommendationContext): GeneratedRecommendation {
  const ev = ctx.evidence;
  const host = ev.host || ev.ip || 'desconhecido';
  const port = String(ev.port || '');
  const service = ev.service || 'serviço desconhecido';
  const serviceCategory = ev.serviceCategory;
  const serviceCategoryLabel = ev.serviceCategoryLabel || serviceCategory || 'serviço';
  const version = ev.version || '';

  const effortTag = getEffortForCategory(serviceCategory);
  const fixSteps = getFixStepsForService(host, port, service, serviceCategory, ctx.hostFamily);

  return {
    title: `Serviço exposto: ${service}${version ? ` ${version}` : ''} em ${host}:${port}`,
    whatIsWrong: `O serviço "${service}" está acessível externamente na porta ${port} do host ${host}, ampliando a superfície de ataque.`,
    businessImpact: `Serviços expostos desnecessariamente aumentam o risco de acesso não autorizado, exploração de vulnerabilidades e comprometimento de dados. Categoria: ${serviceCategoryLabel}.`,
    fixSteps,
    verificationStep: `Confirme que a porta ${port} não está mais acessível externamente: nmap -p ${port} ${host} --open`,
    references: [
      'https://www.cisecurity.org/benchmark/microsoft_windows_server/',
      'https://attack.mitre.org/techniques/T1133/',
    ],
    effortTag,
    roleRequired: 'sysadmin',
    hostSpecificData: { host, port, service, version, serviceCategory },
  };
}
