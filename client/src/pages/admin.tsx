import { Link } from "wouter";
import { useQuery } from "@tanstack/react-query";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import { Card, CardContent } from "@/components/ui/card";
import {
  Users,
  Smartphone,
  SlidersHorizontal,
  ShieldCheck,
  Mail,
  Bell,
  CreditCard,
  History,
  Rocket,
  ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface TileItem {
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  description: string;
  iconClass: string;
}

interface TileGroup {
  label: string;
  items: TileItem[];
}

const groups: TileGroup[] = [
  {
    label: "Identidade & Acesso",
    items: [
      {
        href: "/admin/usuarios",
        icon: Users,
        title: "Usuários",
        description: "Contas, roles e permissões",
        iconClass: "text-blue-600",
      },
      {
        href: "/admin/sessoes",
        icon: Smartphone,
        title: "Sessões",
        description: "Dispositivos e acessos ativos",
        iconClass: "text-blue-600",
      },
    ],
  },
  {
    label: "Sistema",
    items: [
      {
        href: "/admin/configuracoes",
        icon: SlidersHorizontal,
        title: "Configurações Gerais",
        description: "Nome, timezone, localização e appliance",
        iconClass: "text-slate-600",
      },
      {
        href: "/admin/seguranca",
        icon: ShieldCheck,
        title: "Segurança Operacional",
        description: "Limites de jobs concorrentes e timeouts",
        iconClass: "text-slate-600",
      },
    ],
  },
  {
    label: "Comunicação",
    items: [
      {
        href: "/admin/mensageria",
        icon: Mail,
        title: "Mensageria",
        description: "Provedor de email: Google Workspace, M365 ou SMTP",
        iconClass: "text-violet-600",
      },
      {
        href: "/admin/notificacoes",
        icon: Bell,
        title: "Notificações",
        description: "Políticas de alerta e destinatários",
        iconClass: "text-violet-600",
      },
    ],
  },
  {
    label: "Plataforma",
    items: [
      {
        href: "/admin/subscricao",
        icon: CreditCard,
        title: "Subscrição",
        description: "Licença, plano e ativação do appliance",
        iconClass: "text-amber-600",
      },
      {
        href: "/admin/auditoria",
        icon: History,
        title: "Auditoria",
        description: "Histórico de ações administrativas",
        iconClass: "text-amber-600",
      },
    ],
  },
];

export default function Admin() {
  const { data: gsStatus } = useQuery<{
    completedCount: number;
    skippedCount: number;
    totalSteps: number;
    dismissed: boolean;
  }>({
    queryKey: ["/api/getting-started/status"],
    staleTime: 30_000,
  });

  const gsDone = gsStatus
    ? gsStatus.completedCount + gsStatus.skippedCount >= gsStatus.totalSteps
    : false;

  const gsProgress = gsStatus
    ? Math.round(
        ((gsStatus.completedCount + gsStatus.skippedCount) / gsStatus.totalSteps) * 100
      )
    : 0;

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <main className="flex-1 overflow-auto">
        <TopBar
          title="Administração"
          subtitle="Gerencie usuários, sistema, comunicação e plataforma"
        />
        <div className="p-6 space-y-8">
          {groups.map((group) => (
            <div key={group.label}>
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">
                {group.label}
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {group.items.map((item) => (
                  <Link key={item.href} href={item.href}>
                    <Card className="cursor-pointer hover:shadow-md transition-shadow hover:border-border/80">
                      <CardContent className="flex items-center gap-4 p-5">
                        <div className={cn("flex-shrink-0", item.iconClass)}>
                          <item.icon className="h-8 w-8" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="font-semibold text-sm">{item.title}</p>
                          <p className="text-sm text-muted-foreground truncate">
                            {item.description}
                          </p>
                        </div>
                        <ChevronRight className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                      </CardContent>
                    </Card>
                  </Link>
                ))}
                {group.label === "Plataforma" && (
                  <Link href="/getting-started">
                    <Card className="cursor-pointer hover:shadow-md transition-shadow hover:border-border/80">
                      <CardContent className="flex items-center gap-4 p-5">
                        <div className="flex-shrink-0 text-amber-600">
                          <Rocket className="h-8 w-8" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="font-semibold text-sm">Primeiros Passos</p>
                          <p className="text-sm text-muted-foreground truncate">
                            {gsDone
                              ? "Configuração concluída"
                              : gsStatus
                              ? `${gsStatus.completedCount} de ${gsStatus.totalSteps} etapas concluídas`
                              : "Guia de configuração inicial"}
                          </p>
                          {gsStatus && (
                            <div className="mt-2 h-1.5 w-full rounded-full bg-muted overflow-hidden">
                              <div
                                className={cn(
                                  "h-full rounded-full transition-all",
                                  gsDone ? "bg-green-500" : "bg-primary"
                                )}
                                style={{ width: `${gsProgress}%` }}
                              />
                            </div>
                          )}
                        </div>
                        <ChevronRight className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                      </CardContent>
                    </Card>
                  </Link>
                )}
              </div>
            </div>
          ))}
        </div>
      </main>
    </div>
  );
}
