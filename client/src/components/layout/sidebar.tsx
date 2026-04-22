import { useState, useEffect } from "react";
import { Link, useLocation } from "wouter";
import { cn } from "@/lib/utils";
import { useAuth } from "@/hooks/useAuth";
import { useQuery } from "@tanstack/react-query";
import { useTheme } from "@/hooks/useTheme";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
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
  Monitor,
  Bell,
  Smartphone,
  FileBarChart,
  CreditCard,
  ClipboardList,
  ChevronLeft,
  ChevronRight,
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
    title: "Inventário",
    items: [
      { href: "/assets", label: "Alvos", icon: Server },
      { href: "/hosts", label: "Hosts", icon: Monitor },
      { href: "/credentials", label: "Credenciais", icon: Key },
    ],
  },
  {
    title: "Execução",
    items: [
      { href: "/journeys", label: "Jornadas", icon: Route },
      { href: "/schedules", label: "Agendamentos", icon: Clock },
      { href: "/jobs", label: "Jobs", icon: List },
    ],
  },
  {
    title: "Análise",
    items: [
      { href: "/threats", label: "Ameaças", icon: AlertTriangle },
      { href: "/action-plan", label: "Plano de Ação", icon: ClipboardList },
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

const STORAGE_KEY = "samureye.sidebar.collapsed";

function readCollapsed(): boolean {
  try { return localStorage.getItem(STORAGE_KEY) === "true"; } catch { return false; }
}

function saveCollapsed(v: boolean) {
  try { localStorage.setItem(STORAGE_KEY, String(v)); } catch {}
  fetch("/api/user/preferences", {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sidebarCollapsed: v }),
    credentials: "include",
  }).catch(() => {});
}

export default function Sidebar() {
  const [location] = useLocation();
  const { user } = useAuth();
  const { resolvedTheme } = useTheme();
  const [collapsed, setCollapsed] = useState(readCollapsed);

  // Sync from backend on mount (fire-and-forget)
  useEffect(() => {
    fetch("/api/user/preferences", { credentials: "include" })
      .then((r) => r.json())
      .then((prefs) => {
        if (typeof prefs?.sidebarCollapsed === "boolean") {
          setCollapsed(prefs.sidebarCollapsed);
          try { localStorage.setItem(STORAGE_KEY, String(prefs.sidebarCollapsed)); } catch {}
        }
      })
      .catch(() => {});
  }, []);

  const toggle = () => {
    const next = !collapsed;
    setCollapsed(next);
    saveCollapsed(next);
  };

  const { data: criticalThreats = [] } = useQuery({
    queryKey: ["/api/threats", { severity: "critical", status: "open" }],
    select: (data: any[]) =>
      data?.filter((t: any) => t.severity === "critical" && t.status === "open") || [],
  });
  const criticalThreatCount = criticalThreats.length;

  const { data: healthData } = useQuery<{ version?: string }>({
    queryKey: ["/api/health"],
    refetchInterval: 60_000,
    staleTime: 60_000,
  });
  const appVersion = healthData?.version;

  const isAdmin = (user as any)?.role === "global_administrator";

  const logoSrc = resolvedTheme === "dark" ? "/logo.png" : "/Logos_white.png";

  function NavLink({ item }: { item: NavItem }) {
    const isActive =
      item.href === "/"
        ? location === "/" || location === "/postura"
        : location === item.href || location.startsWith(item.href + "/");
    const showBadge = item.label === "Ameaças" && criticalThreatCount > 0;

    const inner = (
      <Link key={item.href} href={item.href}>
        <div
          className={cn(
            "sidebar-item flex items-center px-3 py-2 text-sm font-medium rounded-md transition-colors cursor-pointer",
            collapsed && "justify-center px-2",
            isActive
              ? "active text-sidebar-foreground"
              : "text-muted-foreground hover:text-sidebar-foreground"
          )}
          data-testid={`nav-${item.label.toLowerCase()}`}
        >
          <item.icon className={cn("h-4 w-4 flex-shrink-0", !collapsed && "mr-3")} />
          {!collapsed && (
            <>
              <span className="truncate">{item.label}</span>
              {showBadge && (
                <span
                  className="ml-auto bg-destructive text-destructive-foreground text-xs px-2 py-0.5 rounded-full"
                  data-testid={`badge-${item.label.toLowerCase()}`}
                >
                  {criticalThreatCount}
                </span>
              )}
            </>
          )}
          {collapsed && showBadge && (
            <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-destructive" />
          )}
        </div>
      </Link>
    );

    if (collapsed) {
      return (
        <Tooltip>
          <TooltipTrigger asChild>{inner}</TooltipTrigger>
          <TooltipContent side="right">{item.label}</TooltipContent>
        </Tooltip>
      );
    }
    return inner;
  }

  return (
    <aside
      className={cn(
        "bg-sidebar border-r border-sidebar-border flex flex-col transition-all duration-200",
        collapsed ? "w-16" : "w-64"
      )}
    >
      {/* Header: logo + toggle */}
      <div className={cn(
        "flex items-center border-b border-sidebar-border flex-shrink-0",
        collapsed ? "px-3 py-4 justify-center" : "px-5 py-4 justify-between"
      )}>
        {!collapsed && (
          <img
            src={logoSrc}
            alt="SamurEye"
            className="h-8 object-contain"
            onError={(e) => {
              const img = e.target as HTMLImageElement;
              img.style.display = "none";
              img.nextElementSibling?.classList.remove("hidden");
            }}
          />
        )}
        {/* Fallback shield when image fails or collapsed */}
        <div className={cn(
          "w-8 h-8 bg-sidebar-primary rounded-lg flex items-center justify-center flex-shrink-0",
          !collapsed && "hidden"
        )}>
          <Shield className="w-4 h-4 text-sidebar-primary-foreground" />
        </div>

        <button
          onClick={toggle}
          aria-label={collapsed ? "Expandir menu" : "Recolher menu"}
          className={cn(
            "text-muted-foreground hover:text-sidebar-foreground transition-colors rounded p-1 hover:bg-sidebar-accent",
            collapsed && "mt-0"
          )}
        >
          {collapsed ? (
            <ChevronRight className="h-4 w-4" />
          ) : (
            <ChevronLeft className="h-4 w-4" />
          )}
        </button>
      </div>

      {/* Nav */}
      <nav className="flex-1 py-3 overflow-y-auto overflow-x-hidden">
        {navGroups.map((group, gi) => (
          <div key={gi} className={cn("px-2", gi > 0 && "mt-3")}>
            {group.title && !collapsed && (
              <p className="px-3 mb-1 text-[10px] font-semibold text-muted-foreground uppercase tracking-widest">
                {group.title}
              </p>
            )}
            {group.title && collapsed && <div className="border-t border-sidebar-border my-2 mx-1" />}
            <div className="space-y-0.5">
              {group.items.map((item) => (
                <NavLink key={item.href} item={item} />
              ))}
            </div>
          </div>
        ))}

        {isAdmin && (
          <div className="px-2 mt-3">
            {!collapsed ? (
              <p className="px-3 mb-1 text-[10px] font-semibold text-muted-foreground uppercase tracking-widest">
                Administração
              </p>
            ) : (
              <div className="border-t border-sidebar-border my-2 mx-1" />
            )}
            <div className="space-y-0.5">
              {adminItems.map((item) => (
                <NavLink key={item.href} item={item} />
              ))}
            </div>
          </div>
        )}
      </nav>

      {/* Footer */}
      {!collapsed && appVersion && (
        <div className="px-4 py-3 border-t border-sidebar-border">
          <p className="text-[10px] text-muted-foreground/50 text-center select-all">
            v{appVersion}
          </p>
        </div>
      )}
    </aside>
  );
}
