import { useAuth } from "@/hooks/useAuth";
import { AlertTriangle } from "lucide-react";
import { Link } from "wouter";

const SETUP_ADMIN_EMAIL = "admin@samureye.local";

export function SetupAdminBanner() {
  const { user } = useAuth() as any;
  if (user?.email !== SETUP_ADMIN_EMAIL) return null;
  return (
    <div
      role="alert"
      data-testid="banner-setup-admin"
      className="flex items-start gap-3 border-b border-yellow-500/40 bg-yellow-500/10 px-6 py-3 text-sm text-yellow-900 dark:text-yellow-100"
    >
      <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" aria-hidden="true" />
      <div className="flex-1">
        <p className="font-medium">Conta de setup inicial em uso</p>
        <p className="mt-0.5 text-xs leading-relaxed">
          Você está logado como <code className="font-mono">admin@samureye.local</code>. Esta conta serve apenas para a instalação do appliance.
          {" "}
          <Link href="/users" className="underline hover:no-underline" data-testid="link-manage-users">
            Crie contas nomeadas
          </Link>{" "}
          em Administração → Usuários e evite continuar logado aqui.
        </p>
      </div>
    </div>
  );
}
