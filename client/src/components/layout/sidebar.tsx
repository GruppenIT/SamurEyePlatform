import { Link, useLocation } from "wouter";
import { cn } from "@/lib/utils";
import { useAuth } from "@/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import {
  Shield,
  ShieldCheck,
  Server,
  Key,
  Route,
  Clock,
  AlertTriangle,
  List,
  Users,
  Settings,
  History,
  LogOut,
  Monitor,
  Bell,
  Smartphone,
  FileBarChart,
  CreditCard,
  ClipboardList,
} from "lucide-react";

interface NavItem {
  href: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: number;
  adminOnly?: boolean;
}

interface NavGroup {
  title?: string;
  items: NavItem[];
}

const navGroups: NavGroup[] = [
  {
    items: [
      { href: "/", label: "Postura", icon: ShieldCheck },
    ],
  },
  {
    title: "Superfície",
    items: [
      { href: "/assets", label: "Alvos", icon: Server },
      { href: "/hosts", label: "Hosts", icon: Monitor },
      { href: "/credentials", label: "Credenciais", icon: Key },
    ],
  },
  {
    title: "Operações",
    items: [
      { href: "/journeys", label: "Jornadas", icon: Route },
      { href: "/schedules", label: "Agendamentos", icon: Clock },
      { href: "/jobs", label: "Jobs", icon: List },
    ],
  },
  {
    title: "Inteligência",
    items: [
      { href: "/threats", label: "Ameaças", icon: AlertTriangle },
      { href: "/action-plan", label: "Plano de Acao", icon: ClipboardList },
      { href: "/relatorios", label: "Relatórios", icon: FileBarChart },
    ],
  },
];

const adminItems: NavItem[] = [
  { href: "/users", label: "Usuários", icon: Users, adminOnly: true },
  { href: "/sessions", label: "Sessões", icon: Smartphone, adminOnly: true },
  { href: "/notification-policies", label: "Notificações", icon: Bell, adminOnly: true },
  { href: "/subscription", label: "Subscrição", icon: CreditCard, adminOnly: true },
  { href: "/settings", label: "Configurações", icon: Settings, adminOnly: true },
  { href: "/audit", label: "Auditoria", icon: History, adminOnly: true },
];

export default function Sidebar() {
  const [location] = useLocation();
  const { user } = useAuth();
  const queryClient = useQueryClient();

  // Buscar ameaças críticas abertas para o contador do menu
  const { data: criticalThreats = [] } = useQuery({
    queryKey: ['/api/threats', { severity: 'critical', status: 'open' }],
    select: (data: any[]) => data?.filter((threat: any) => 
      threat.severity === 'critical' && threat.status === 'open'
    ) || []
  });

  const criticalThreatCount = criticalThreats.length;

  const { data: healthData } = useQuery<{ version?: string }>({
    queryKey: ['/api/health'],
    refetchInterval: 60_000, // refresh once per minute
    staleTime: 60_000,
  });
  const appVersion = healthData?.version;

  const isAdmin = user?.role === 'global_administrator';
  const canViewAdminItems = isAdmin;

  const logoutMutation = useMutation({
    mutationFn: async () => {
      await apiRequest('POST', '/api/auth/logout', {});
    },
    onSuccess: () => {
      // Limpa o cache de usuário e redireciona para landing
      queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
      queryClient.clear();
      window.location.href = '/';
    },
    onError: () => {
      // Em caso de erro, força redirecionamento
      queryClient.clear();
      window.location.href = '/';
    },
  });

  const handleLogout = () => {
    logoutMutation.mutate();
  };

  return (
    <aside className="w-64 bg-sidebar border-r border-sidebar-border flex flex-col">
      {/* Logo and Brand */}
      <div className="p-6 border-b border-sidebar-border">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 bg-sidebar-primary rounded-lg flex items-center justify-center">
            <Shield className="text-sidebar-primary-foreground text-xl" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-sidebar-foreground">SamurEye</h1>
            <p className="text-xs text-muted-foreground">Validação de Exposição</p>
          </div>
        </div>
      </div>
      
      {/* Navigation Menu */}
      <nav className="flex-1 py-4 overflow-y-auto">
        {navGroups.map((group, groupIndex) => (
          <div key={groupIndex} className={cn("px-3", groupIndex > 0 && "mt-4")}>
            {group.title && (
              <h3 className="px-3 mb-1 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                {group.title}
              </h3>
            )}
            <div className="space-y-1">
              {group.items.map((item) => {
                const isActive = item.href === '/'
                  ? location === '/' || location === '/postura'
                  : location === item.href || location.startsWith(item.href + '/');
                const showBadge = item.label === "Ameaças" && criticalThreatCount > 0;
                const badgeCount = item.label === "Ameaças" ? criticalThreatCount : item.badge;

                return (
                  <Link key={item.href} href={item.href}>
                    <div
                      className={cn(
                        "sidebar-item flex items-center px-3 py-2 text-sm font-medium rounded-md transition-colors cursor-pointer",
                        isActive
                          ? "active text-sidebar-foreground"
                          : "text-muted-foreground hover:text-sidebar-foreground"
                      )}
                      data-testid={`nav-${item.label.toLowerCase()}`}
                    >
                      <item.icon className="mr-3 h-4 w-4" />
                      {item.label}
                      {(showBadge || item.badge) && (
                        <span className="ml-auto bg-destructive text-destructive-foreground text-xs px-2 py-1 rounded-full" data-testid={`badge-${item.label.toLowerCase()}`}>
                          {badgeCount}
                        </span>
                      )}
                    </div>
                  </Link>
                );
              })}
            </div>
          </div>
        ))}

        {canViewAdminItems && (
          <div className="px-3 mt-4">
            <h3 className="px-3 mb-1 text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Administração
            </h3>
            <div className="space-y-1">
              {adminItems.map((item) => {
                const isActive = location === item.href || location.startsWith(item.href + '/');
                return (
                  <Link key={item.href} href={item.href}>
                    <div
                      className={cn(
                        "sidebar-item flex items-center px-3 py-2 text-sm font-medium rounded-md transition-colors cursor-pointer",
                        isActive
                          ? "active text-sidebar-foreground"
                          : "text-muted-foreground hover:text-sidebar-foreground"
                      )}
                      data-testid={`nav-admin-${item.label.toLowerCase()}`}
                    >
                      <item.icon className="mr-3 h-4 w-4" />
                      {item.label}
                    </div>
                  </Link>
                );
              })}
            </div>
          </div>
        )}
      </nav>
      
      {/* User Profile */}
      <div className="p-4 border-t border-sidebar-border">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 bg-secondary rounded-full flex items-center justify-center">
            <span className="text-secondary-foreground text-sm font-medium">
              {user?.firstName?.[0] || user?.email?.[0] || 'U'}
            </span>
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-sidebar-foreground truncate">
              {user?.firstName && user?.lastName
                ? `${user.firstName} ${user.lastName}`
                : user?.email || 'Usuário'
              }
            </p>
            <p className="text-xs text-muted-foreground truncate">
              {user?.role === 'global_administrator' && 'Administrador Global'}
              {user?.role === 'operator' && 'Operador'}
              {user?.role === 'read_only' && 'Somente Leitura'}
            </p>
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={handleLogout}
            className="text-muted-foreground hover:text-sidebar-foreground"
            data-testid="button-logout"
          >
            <LogOut className="h-4 w-4" />
          </Button>
        </div>
        {appVersion && (
          <p className="mt-2 text-[10px] text-muted-foreground/50 text-center select-all" title={`Build: ${appVersion}`}>
            v{appVersion}
          </p>
        )}
      </div>
    </aside>
  );
}
