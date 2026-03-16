import type { RecommendationContext, GeneratedRecommendation } from './types';

export function generate(ctx: RecommendationContext): GeneratedRecommendation {
  const ev = ctx.evidence;
  const target = ev.target || 'domínio';
  const recommendation = ev.recommendation || '';

  return {
    title: `Senha expirada de Domain Admin crítico: ${target}`,
    whatIsWrong: `Uma conta de Domain Administrator crítica no domínio "${target}" está com senha expirada ou próxima da expiração.`,
    businessImpact: `Senhas expiradas de administradores críticos podem causar interrupção de serviços ou forçar o uso de senhas fracas em situações de emergência.`,
    fixSteps: [
      recommendation || `Identifique contas de Domain Admin com senha expirada:`,
      `Get-ADUser -Filter {PasswordExpired -eq $true -and MemberOf -like "*Domain Admins*"} -Properties PasswordExpired, PasswordLastSet | Select-Object Name, PasswordLastSet`,
      `Redefina a senha da conta imediatamente com uma senha forte (mínimo 20 caracteres, aleatória):`,
      `Set-ADAccountPassword -Identity <usuario> -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "<NOVA_SENHA_FORTE>" -Force)`,
      `Documente a nova senha em um gerenciador de senhas seguro (ex: CyberArk, 1Password for Teams).`,
      `Implemente alerta proativo de expiração de senha para contas privilegiadas com 30 dias de antecedência.`,
    ].filter(Boolean),
    verificationStep: `Execute: Get-ADUser <usuario> -Properties PasswordExpired | Select-Object PasswordExpired — deve retornar False.`,
    references: [
      'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models',
    ],
    effortTag: 'minutes',
    roleRequired: 'sysadmin',
    hostSpecificData: { target },
  };
}
