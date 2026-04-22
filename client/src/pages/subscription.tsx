import { useQuery } from "@tanstack/react-query";
import { useWebSocket } from "@/lib/websocket";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  CreditCard,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Clock,
  Shield,
  Globe,
  Monitor,
  Search,
  Server,
  Loader2,
} from "lucide-react";
import { differenceInDays, format } from "date-fns";
import { ptBR } from "date-fns/locale";

interface SubscriptionStatus {
  configured: boolean;
  applianceId: string | null;
  status: string;
  tenantName: string | null;
  plan: string | null;
  planSlug: string | null;
  maxAppliances: number | null;
  isTrial: boolean;
  durationDays: number | null;
  consoleMessage: string | null;
  expiresAt: string | null;
  features: string[];
  lastHeartbeatAt: string | null;
  lastHeartbeatError: string | null;
  consecutiveFailures: number;
  graceDeadline: string | null;
  consoleBaseUrl: string;
  activatedAt: string | null;
  readOnly: boolean;
}

const ALL_FEATURES = [
  { slug: "attack_surface", label: "Attack Surface", description: "Mapeamento de superfície de ataque", icon: Search },
  { slug: "ad_security", label: "AD Security", description: "Segurança do Active Directory", icon: Shield },
  { slug: "edr_av", label: "EDR/AV", description: "Endpoint Detection & Response / Antivírus", icon: Monitor },
  { slug: "web_application", label: "Web Application", description: "Varredura de aplicações web", icon: Globe },
];

function getStatusBadge(status: string, isTrial: boolean) {
  if (status === "active" && isTrial) {
    return (
      <Badge className="bg-yellow-600 text-white text-sm px-3 py-1">
        <Clock className="mr-1.5 h-3.5 w-3.5" />
        Trial
      </Badge>
    );
  }
  if (status === "active") {
    return (
      <Badge className="bg-green-600 text-white text-sm px-3 py-1">
        <CheckCircle className="mr-1.5 h-3.5 w-3.5" />
        Ativo
      </Badge>
    );
  }
  if (status === "expired") {
    return (
      <Badge variant="destructive" className="text-sm px-3 py-1">
        <XCircle className="mr-1.5 h-3.5 w-3.5" />
        Expirado
      </Badge>
    );
  }
  if (status === "grace_period") {
    return (
      <Badge className="bg-orange-600 text-white text-sm px-3 py-1">
        <AlertTriangle className="mr-1.5 h-3.5 w-3.5" />
        Carência
      </Badge>
    );
  }
  return (
    <Badge variant="secondary" className="text-sm px-3 py-1">
      {status}
    </Badge>
  );
}

function getExpirationText(expiresAt: string | null): { text: string; daysLeft: number | null } {
  if (!expiresAt) return { text: "Sem expiração", daysLeft: null };

  const expDate = new Date(expiresAt);
  const now = new Date();
  const daysLeft = differenceInDays(expDate, now);

  if (daysLeft < 0) {
    return { text: `Expirou ${format(expDate, "dd/MM/yyyy", { locale: ptBR })}`, daysLeft };
  }
  if (daysLeft === 0) {
    return { text: "Expira hoje", daysLeft: 0 };
  }
  if (daysLeft === 1) {
    return { text: "Expira amanhã", daysLeft: 1 };
  }
  return {
    text: `Expira em ${daysLeft} dias (${format(expDate, "dd/MM/yyyy", { locale: ptBR })})`,
    daysLeft,
  };
}

export default function Subscription() {
  const { connected } = useWebSocket();

  const { data: subscription, isLoading } = useQuery<SubscriptionStatus>({
    queryKey: ["/api/subscription/status"],
    refetchInterval: 60_000,
    staleTime: 30_000,
  });

  const expiration = subscription?.expiresAt
    ? getExpirationText(subscription.expiresAt)
    : { text: "Sem expiração", daysLeft: null };

  return (
    <div className="flex h-screen bg-background overflow-hidden">
      <Sidebar />

      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar
          title="Subscrição"
          subtitle="Gestão do plano e módulos habilitados"
          wsConnected={connected}
        />

        <main className="flex-1 overflow-auto p-8">
          <div className="max-w-5xl mx-auto space-y-6">
            {isLoading ? (
              <div className="flex items-center justify-center py-20">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
              </div>
            ) : !subscription?.configured ? (
              <Card>
                <CardContent className="py-12 text-center">
                  <CreditCard className="mx-auto h-12 w-12 text-muted-foreground mb-4" />
                  <h3 className="text-lg font-semibold text-foreground mb-2">
                    Nenhuma subscrição configurada
                  </h3>
                  <p className="text-muted-foreground">
                    Ative o appliance nas Configurações para conectar-se à console central e receber os dados de subscrição.
                  </p>
                </CardContent>
              </Card>
            ) : (
              <>
                {/* Expired banner */}
                {subscription.status === "expired" && (
                  <Alert variant="destructive">
                    <XCircle className="h-4 w-4" />
                    <AlertDescription className="font-medium">
                      {subscription.consoleMessage ||
                        "Subscrição expirada. O SamurEye está em modo somente-leitura. Entre em contato com o suporte para renovar."}
                    </AlertDescription>
                  </Alert>
                )}

                {/* Trial banner */}
                {subscription.isTrial && subscription.status === "active" && (
                  <Alert className="border-yellow-600/50 bg-yellow-600/10">
                    <Clock className="h-4 w-4 text-yellow-500" />
                    <AlertDescription className="text-yellow-200 font-medium">
                      Plano Trial
                      {expiration.daysLeft !== null && expiration.daysLeft >= 0
                        ? ` — ${expiration.daysLeft} ${expiration.daysLeft === 1 ? "dia restante" : "dias restantes"}`
                        : ""}
                    </AlertDescription>
                  </Alert>
                )}

                {/* Console message (if not expired — expired already shown above) */}
                {subscription.consoleMessage && subscription.status !== "expired" && (
                  <Alert className="border-blue-600/50 bg-blue-600/10">
                    <AlertTriangle className="h-4 w-4 text-blue-400" />
                    <AlertDescription className="text-blue-200">
                      {subscription.consoleMessage}
                    </AlertDescription>
                  </Alert>
                )}

                {/* Plan overview card */}
                <Card>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="flex items-center gap-2">
                        <CreditCard className="h-5 w-5" />
                        Plano de Subscrição
                      </CardTitle>
                      {getStatusBadge(subscription.status, subscription.isTrial)}
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                      {/* Plan name */}
                      <div>
                        <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">
                          Plano
                        </p>
                        <p className="text-lg font-semibold text-foreground">
                          {subscription.plan || "—"}
                        </p>
                      </div>

                      {/* Tenant */}
                      <div>
                        <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">
                          Tenant
                        </p>
                        <p className="text-lg font-semibold text-foreground">
                          {subscription.tenantName || "—"}
                        </p>
                      </div>

                      {/* Max appliances */}
                      <div>
                        <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">
                          Limite de Appliances
                        </p>
                        <p className="text-lg font-semibold text-foreground flex items-center gap-1.5">
                          <Server className="h-4 w-4 text-muted-foreground" />
                          {subscription.maxAppliances === -1 || subscription.maxAppliances === null
                            ? "Ilimitado"
                            : `${subscription.maxAppliances} ${subscription.maxAppliances === 1 ? "appliance" : "appliances"}`}
                        </p>
                      </div>

                      {/* Expiration */}
                      <div>
                        <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">
                          Validade
                        </p>
                        <p className={`text-lg font-semibold flex items-center gap-1.5 ${
                          expiration.daysLeft !== null && expiration.daysLeft < 0
                            ? "text-destructive"
                            : expiration.daysLeft !== null && expiration.daysLeft <= 30
                              ? "text-yellow-500"
                              : "text-foreground"
                        }`}>
                          <Clock className="h-4 w-4 text-muted-foreground" />
                          {expiration.text}
                        </p>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Features card */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Shield className="h-5 w-5" />
                      Módulos
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      {ALL_FEATURES.map((feature) => {
                        const isEnabled = subscription.features.includes(feature.slug);
                        const IconComponent = feature.icon;
                        return (
                          <div
                            key={feature.slug}
                            className={`flex items-center gap-4 rounded-lg border p-4 transition-colors ${
                              isEnabled
                                ? "border-primary/30 bg-primary/5"
                                : "border-border bg-muted/30 opacity-50"
                            }`}
                          >
                            <div
                              className={`flex h-10 w-10 items-center justify-center rounded-lg ${
                                isEnabled
                                  ? "bg-primary/20 text-primary"
                                  : "bg-muted text-muted-foreground"
                              }`}
                            >
                              <IconComponent className="h-5 w-5" />
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2">
                                <p className="font-medium text-foreground">
                                  {feature.label}
                                </p>
                                {isEnabled ? (
                                  <CheckCircle className="h-4 w-4 text-green-500 flex-shrink-0" />
                                ) : (
                                  <XCircle className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                                )}
                              </div>
                              <p className="text-sm text-muted-foreground">
                                {feature.description}
                              </p>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </CardContent>
                </Card>

                {/* Details card */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Server className="h-5 w-5" />
                      Detalhes da Conexão
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                      <div className="space-y-3">
                        <div>
                          <span className="text-muted-foreground">Appliance ID</span>
                          <p className="font-mono text-foreground">{subscription.applianceId || "—"}</p>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Console URL</span>
                          <p className="font-mono text-foreground">{subscription.consoleBaseUrl}</p>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Ativado em</span>
                          <p className="text-foreground">
                            {subscription.activatedAt
                              ? format(new Date(subscription.activatedAt), "dd/MM/yyyy 'às' HH:mm", { locale: ptBR })
                              : "—"}
                          </p>
                        </div>
                      </div>
                      <div className="space-y-3">
                        <div>
                          <span className="text-muted-foreground">Último heartbeat</span>
                          <p className="text-foreground">
                            {subscription.lastHeartbeatAt
                              ? format(new Date(subscription.lastHeartbeatAt), "dd/MM/yyyy 'às' HH:mm:ss", { locale: ptBR })
                              : "—"}
                          </p>
                        </div>
                        {subscription.lastHeartbeatError && (
                          <div>
                            <span className="text-muted-foreground">Último erro</span>
                            <p className="text-destructive">{subscription.lastHeartbeatError}</p>
                          </div>
                        )}
                        {subscription.consecutiveFailures > 0 && (
                          <div>
                            <span className="text-muted-foreground">Falhas consecutivas</span>
                            <p className="text-yellow-500">{subscription.consecutiveFailures}</p>
                          </div>
                        )}
                        {subscription.durationDays && (
                          <div>
                            <span className="text-muted-foreground">Duração do plano</span>
                            <p className="text-foreground">{subscription.durationDays} dias</p>
                          </div>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
