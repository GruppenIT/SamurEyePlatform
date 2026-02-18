import { useQuery } from "@tanstack/react-query";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import {
  Wifi, WifiOff, Database, Cpu, MemoryStick, Server,
  Heart, Shield, Clock, CheckCircle, XCircle, AlertTriangle,
  RefreshCw,
} from "lucide-react";
import { Button } from "@/components/ui/button";

interface SystemMetrics {
  cpu: number;
  memory: number;
  services: Array<{ name: string; status: string; color: string }>;
}

interface HealthData {
  status: string;
  version?: string;
  timestamp?: string;
}

interface SubscriptionStatus {
  configured: boolean;
  applianceId: string | null;
  status: string;
  tenantName: string | null;
  plan: string | null;
  expiresAt: string | null;
  lastHeartbeatAt: string | null;
  lastHeartbeatError: string | null;
  consecutiveFailures: number;
  consoleBaseUrl: string;
  readOnly: boolean;
}

function StatusDot({ ok, warn }: { ok: boolean; warn?: boolean }) {
  if (warn) return <span className="inline-block w-2 h-2 rounded-full bg-yellow-500" />;
  return <span className={`inline-block w-2 h-2 rounded-full ${ok ? 'bg-emerald-500' : 'bg-red-500'}`} />;
}

function timeAgo(iso: string | null | undefined): string {
  if (!iso) return "nunca";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "agora";
  if (mins < 60) return `${mins}min atrás`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h atrás`;
  return `${Math.floor(hours / 24)}d atrás`;
}

function subscriptionLabel(status: string): { text: string; variant: "default" | "secondary" | "destructive" | "outline" } {
  switch (status) {
    case "active": return { text: "Ativa", variant: "default" };
    case "grace_period": return { text: "Modo Grace", variant: "outline" };
    case "expired": return { text: "Expirada", variant: "destructive" };
    case "unreachable": return { text: "Inacessível", variant: "destructive" };
    case "not_configured": return { text: "Não Configurada", variant: "secondary" };
    default: return { text: status, variant: "secondary" };
  }
}

function cpuColor(value: number): string {
  if (value >= 90) return "bg-red-500";
  if (value >= 70) return "bg-yellow-500";
  return "bg-primary";
}

interface SystemStatusPopupProps {
  wsConnected: boolean;
}

export default function SystemStatusPopup({ wsConnected }: SystemStatusPopupProps) {
  const { data: metrics, refetch: refetchMetrics } = useQuery<SystemMetrics>({
    queryKey: ['/api/system/metrics'],
    refetchInterval: 10_000,
    staleTime: 5_000,
  });

  const { data: health } = useQuery<HealthData>({
    queryKey: ['/api/health'],
    refetchInterval: 30_000,
    staleTime: 30_000,
  });

  const { data: subscription, refetch: refetchSub } = useQuery<SubscriptionStatus>({
    queryKey: ['/api/subscription/status'],
    refetchInterval: 60_000,
    staleTime: 30_000,
  });

  const subLabel = subscriptionLabel(subscription?.status || "not_configured");

  const handleRefresh = () => {
    refetchMetrics();
    refetchSub();
  };

  // Overall status: red if any critical issue, yellow if warnings, green otherwise
  const hasError = !wsConnected || subscription?.status === 'expired' || subscription?.status === 'unreachable';
  const hasWarn = subscription?.status === 'grace_period' || (subscription?.consecutiveFailures ?? 0) > 0;

  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          className="flex items-center space-x-2 cursor-pointer rounded-md px-2 py-1 transition-colors hover:bg-secondary/50"
          data-testid="ws-status-indicator"
        >
          <span className={`status-indicator ${wsConnected ? 'status-success pulse-animation' : 'status-error'}`} />
          <span className="text-sm text-muted-foreground">
            {wsConnected ? 'Sistema Online' : 'Desconectado'}
          </span>
        </button>
      </PopoverTrigger>

      <PopoverContent align="end" side="bottom" className="w-80 p-0">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-border">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-primary" />
            <span className="text-sm font-semibold">Status do Appliance</span>
          </div>
          <Button variant="ghost" size="icon" className="h-6 w-6" onClick={handleRefresh}>
            <RefreshCw className="h-3 w-3" />
          </Button>
        </div>

        <div className="px-4 py-3 space-y-4">
          {/* Connection & Version */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                {wsConnected ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
                WebSocket
              </div>
              <span className={`text-xs font-medium ${wsConnected ? 'text-emerald-400' : 'text-red-400'}`}>
                {wsConnected ? 'Conectado' : 'Desconectado'}
              </span>
            </div>

            {health?.version && (
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <Server className="h-3 w-3" />
                  Versão
                </div>
                <span className="text-xs font-mono text-foreground select-all">v{health.version}</span>
              </div>
            )}
          </div>

          {/* Subscription */}
          <div className="space-y-2 pt-2 border-t border-border/50">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Shield className="h-3 w-3" />
                Subscrição
              </div>
              <Badge variant={subLabel.variant} className="text-[10px] h-5">
                {subLabel.text}
              </Badge>
            </div>

            {subscription?.configured && (
              <>
                {subscription.plan && (
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-muted-foreground pl-5">Plano</span>
                    <span className="text-xs text-foreground capitalize">{subscription.plan}</span>
                  </div>
                )}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Heart className="h-3 w-3" />
                    Heartbeat
                  </div>
                  <span className="text-xs text-muted-foreground">
                    {timeAgo(subscription.lastHeartbeatAt)}
                  </span>
                </div>
                {subscription.consecutiveFailures > 0 && (
                  <div className="flex items-center gap-1.5 text-xs text-yellow-400 pl-5">
                    <AlertTriangle className="h-3 w-3" />
                    {subscription.consecutiveFailures} falha{subscription.consecutiveFailures > 1 ? 's' : ''} consecutiva{subscription.consecutiveFailures > 1 ? 's' : ''}
                  </div>
                )}
                {subscription.lastHeartbeatError && subscription.consecutiveFailures > 0 && (
                  <p className="text-[10px] text-red-400/80 pl-5 truncate" title={subscription.lastHeartbeatError}>
                    {subscription.lastHeartbeatError}
                  </p>
                )}
                {subscription.readOnly && (
                  <div className="flex items-center gap-1.5 text-xs text-red-400 pl-5">
                    <XCircle className="h-3 w-3" />
                    Modo somente-leitura
                  </div>
                )}
              </>
            )}
          </div>

          {/* Services */}
          {metrics && (
            <div className="space-y-2 pt-2 border-t border-border/50">
              <span className="text-xs font-medium text-muted-foreground">Serviços</span>
              {metrics.services.map((svc, i) => (
                <div key={i} className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <StatusDot
                      ok={svc.color === 'status-success'}
                      warn={svc.color === 'status-warning'}
                    />
                    {svc.name}
                  </div>
                  <span className="text-xs text-foreground">{svc.status}</span>
                </div>
              ))}
            </div>
          )}

          {/* Resources */}
          {metrics && (
            <div className="space-y-3 pt-2 border-t border-border/50">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Cpu className="h-3 w-3" />
                    CPU
                  </div>
                  <span className="text-xs font-medium text-foreground">{metrics.cpu}%</span>
                </div>
                <Progress value={metrics.cpu} className={`h-1.5 [&>div]:${cpuColor(metrics.cpu)}`} />
              </div>
              <div>
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <MemoryStick className="h-3 w-3" />
                    Memória
                  </div>
                  <span className="text-xs font-medium text-foreground">{metrics.memory}%</span>
                </div>
                <Progress value={metrics.memory} className={`h-1.5 [&>div]:${cpuColor(metrics.memory)}`} />
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        {subscription?.configured && subscription.expiresAt && (
          <div className="px-4 py-2 border-t border-border bg-secondary/20 rounded-b-md">
            <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
              <Clock className="h-3 w-3" />
              Expira em {new Date(subscription.expiresAt).toLocaleDateString('pt-BR')}
            </div>
          </div>
        )}
      </PopoverContent>
    </Popover>
  );
}
