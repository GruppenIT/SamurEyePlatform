import { useState } from "react";
import { Link } from "wouter";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useWebSocket } from "@/lib/websocket";
import { apiRequest } from "@/lib/queryClient";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import { AdminBreadcrumb } from "@/components/admin/admin-breadcrumb";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  CheckCircle,
  Circle,
  MinusCircle,
  PartyPopper,
  Rocket,
} from "lucide-react";
import { format } from "date-fns";
import { ptBR } from "date-fns/locale";
import { cn } from "@/lib/utils";

interface StepStatus {
  id: string;
  completed: boolean;
  skippable: boolean;
  skipped: boolean;
  skipReason: string | null;
  skippedAt: string | null;
}

interface GettingStartedStatus {
  steps: StepStatus[];
  totalSteps: number;
  completedCount: number;
  skippedCount: number;
  dismissed: boolean;
}

const STEP_META: Record<string, { label: string; description: string; href: string }> = {
  appliance_config: {
    label: "Configurações do Appliance",
    description: "Defina o nome e localização do sistema",
    href: "/admin/configuracoes",
  },
  mensageria: {
    label: "Mensageria",
    description: "Configure o provedor de e-mail para notificações",
    href: "/admin/mensageria",
  },
  first_user: {
    label: "Primeiro Usuário Nominal",
    description: "Crie um usuário operacional (não administrador)",
    href: "/admin/usuarios",
  },
  journey_attack_surface: {
    label: "Jornada: Attack Surface",
    description: "Configure uma jornada de mapeamento de superfície de ataque",
    href: "/journeys",
  },
  journey_ad_security: {
    label: "Jornada: AD Security",
    description: "Configure uma jornada de segurança do Active Directory",
    href: "/journeys",
  },
  journey_edr_av: {
    label: "Jornada: EDR/AV",
    description: "Configure uma jornada de detecção e resposta de endpoint",
    href: "/journeys",
  },
  journey_web_application: {
    label: "Jornada: Web Application",
    description: "Configure uma jornada de varredura de aplicações web",
    href: "/journeys",
  },
  journey_api_security: {
    label: "Jornada: API Security",
    description: "Configure uma jornada de segurança de APIs",
    href: "/journeys",
  },
  notification_policy: {
    label: "Política de Notificação",
    description: "Configure alertas e destinatários para eventos de segurança",
    href: "/admin/notificacoes",
  },
  action_plan: {
    label: "Plano de Ação",
    description: "Crie um plano de remediação para ameaças identificadas",
    href: "/action-plan",
  },
};

const GROUPS = [
  {
    label: "CONFIGURAÇÃO INICIAL",
    subtitle: undefined as string | undefined,
    stepIds: ["appliance_config", "mensageria", "first_user"],
  },
  {
    label: "JORNADAS",
    subtitle: "Ignore etapas fora do escopo do seu contrato",
    stepIds: [
      "journey_attack_surface",
      "journey_ad_security",
      "journey_edr_av",
      "journey_web_application",
      "journey_api_security",
    ],
  },
  {
    label: "OPERAÇÃO",
    subtitle: undefined as string | undefined,
    stepIds: ["notification_policy", "action_plan"],
  },
];

function SkipDialog({
  open,
  onOpenChange,
  onConfirm,
  isPending,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onConfirm: (reason: string) => void;
  isPending: boolean;
}) {
  const [reason, setReason] = useState("");

  const handleConfirm = () => {
    onConfirm(reason);
    setReason("");
  };

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Ignorar esta etapa?</AlertDialogTitle>
          <AlertDialogDescription>
            Esta etapa ficará marcada como ignorada. Você pode retomá-la a qualquer momento.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <div className="space-y-2 py-2">
          <Label htmlFor="skip-reason">Motivo (opcional)</Label>
          <Textarea
            id="skip-reason"
            placeholder="Ex: Fora do escopo do contrato"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={2}
          />
        </div>
        <AlertDialogFooter>
          <AlertDialogCancel onClick={() => setReason("")}>Cancelar</AlertDialogCancel>
          <AlertDialogAction onClick={handleConfirm} disabled={isPending}>
            {isPending ? "Ignorando..." : "Ignorar etapa"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

function StepCard({
  step,
  dismissed,
  onSkip,
  onUnskip,
}: {
  step: StepStatus;
  dismissed: boolean;
  onSkip: (stepId: string) => void;
  onUnskip: (stepId: string) => void;
}) {
  const meta = STEP_META[step.id];
  if (!meta) return null;

  const isCompleted = step.completed;
  const isSkipped = !step.completed && step.skipped;
  const isPending = !step.completed && !step.skipped;

  return (
    <Card
      className={cn(
        "transition-colors",
        isCompleted && "border-green-500/30 bg-green-500/5",
        isSkipped && "border-amber-500/30 bg-amber-500/5"
      )}
    >
      <CardContent className="flex items-center gap-4 p-4">
        {/* State icon */}
        <div className="flex-shrink-0">
          {isCompleted && <CheckCircle className="h-5 w-5 text-green-500" />}
          {isSkipped && <MinusCircle className="h-5 w-5 text-amber-500" />}
          {isPending && <Circle className="h-5 w-5 text-muted-foreground" />}
        </div>

        {/* Label + description */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="font-medium text-sm">{meta.label}</p>
            {isCompleted && (
              <Badge className="bg-green-600/20 text-green-700 dark:text-green-400 border-green-500/30 text-xs">
                Concluída
              </Badge>
            )}
            {isSkipped && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Badge className="bg-amber-600/20 text-amber-700 dark:text-amber-400 border-amber-500/30 text-xs cursor-default">
                    Ignorada
                  </Badge>
                </TooltipTrigger>
                <TooltipContent>
                  {step.skipReason ? (
                    <span>
                      {step.skipReason}
                      {step.skippedAt && (
                        <>
                          {" — "}
                          {format(new Date(step.skippedAt), "dd/MM/yyyy", { locale: ptBR })}
                        </>
                      )}
                    </span>
                  ) : step.skippedAt ? (
                    <span>
                      Ignorada em{" "}
                      {format(new Date(step.skippedAt), "dd/MM/yyyy", { locale: ptBR })}
                    </span>
                  ) : (
                    <span>Sem justificativa</span>
                  )}
                </TooltipContent>
              </Tooltip>
            )}
            {isPending && (
              <Badge variant="secondary" className="text-xs">
                Pendente
              </Badge>
            )}
          </div>
          <p className="text-sm text-muted-foreground mt-0.5">{meta.description}</p>
        </div>

        {/* Actions */}
        {!dismissed && (
          <div className="flex items-center gap-2 flex-shrink-0">
            {isSkipped && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => onUnskip(step.id)}
              >
                Retomar
              </Button>
            )}
            {isPending && step.skippable && (
              <Button
                variant="ghost"
                size="sm"
                className="text-muted-foreground"
                onClick={() => onSkip(step.id)}
              >
                Ignorar
              </Button>
            )}
            <Link href={meta.href}>
              <Button
                variant={isCompleted ? "outline" : "default"}
                size="sm"
              >
                {isCompleted ? "Revisar" : "Configurar"} →
              </Button>
            </Link>
          </div>
        )}
        {dismissed && (
          <Link href={meta.href}>
            <Button variant="outline" size="sm">
              Revisar →
            </Button>
          </Link>
        )}
      </CardContent>
    </Card>
  );
}

export default function GettingStarted() {
  const { connected } = useWebSocket();
  const queryClient = useQueryClient();

  const [skipTargetId, setSkipTargetId] = useState<string | null>(null);

  const { data: status, isLoading } = useQuery<GettingStartedStatus>({
    queryKey: ["/api/getting-started/status"],
    staleTime: 30_000,
  });

  const skipMutation = useMutation({
    mutationFn: ({ stepId, reason }: { stepId: string; reason: string }) =>
      apiRequest("POST", "/api/getting-started/skip", { stepId, reason }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["/api/getting-started/status"] }),
  });

  const unskipMutation = useMutation({
    mutationFn: (stepId: string) =>
      apiRequest("DELETE", `/api/getting-started/skip/${stepId}`, undefined),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["/api/getting-started/status"] }),
  });

  const dismissMutation = useMutation({
    mutationFn: () => apiRequest("POST", "/api/getting-started/dismiss", {}),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["/api/getting-started/status"] }),
  });

  const handleSkipConfirm = (reason: string) => {
    if (!skipTargetId) return;
    skipMutation.mutate({ stepId: skipTargetId, reason });
    setSkipTargetId(null);
  };

  const progressValue = status
    ? ((status.completedCount + status.skippedCount) / status.totalSteps) * 100
    : 0;

  const allDone = status
    ? status.steps.every((s) => s.completed || s.skipped)
    : false;

  const dismissed = status?.dismissed ?? false;

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <main className="flex-1 overflow-auto">
        <TopBar
          title="Primeiros Passos"
          subtitle="Configure o SamurEye para começar a operar"
          wsConnected={connected}
        />
        <div className="p-6 space-y-8 max-w-3xl">
          <AdminBreadcrumb page="Primeiros Passos" />

          {/* Progress header */}
          {status && (
            <div className="space-y-2">
              <Progress value={progressValue} className="h-2" />
              <p className="text-sm text-muted-foreground">
                {status.completedCount} de {status.totalSteps} etapas concluídas
                {status.skippedCount > 0 &&
                  ` · ${status.skippedCount} ignorada${status.skippedCount > 1 ? "s" : ""}`}
              </p>
            </div>
          )}

          {/* Completion banner */}
          {allDone && !dismissed && (
            <Card className="border-green-500/30 bg-green-500/5">
              <CardContent className="flex items-center gap-4 p-5">
                <PartyPopper className="h-8 w-8 text-green-500 flex-shrink-0" />
                <div className="flex-1">
                  <p className="font-semibold text-foreground">Configuração concluída!</p>
                  <p className="text-sm text-muted-foreground">
                    O SamurEye está pronto para operar.
                  </p>
                </div>
                <Button
                  onClick={() => dismissMutation.mutate()}
                  disabled={dismissMutation.isPending}
                  variant="outline"
                >
                  {dismissMutation.isPending ? "Fechando..." : "Fechar este guia"}
                </Button>
              </CardContent>
            </Card>
          )}

          {/* Step groups */}
          {isLoading && (
            <div className="text-center py-12 text-muted-foreground">
              Carregando...
            </div>
          )}

          {status &&
            GROUPS.map((group) => {
              const groupSteps = group.stepIds
                .map((id) => status.steps.find((s) => s.id === id))
                .filter(Boolean) as StepStatus[];

              return (
                <div key={group.label} className="space-y-3">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                      {group.label}
                    </p>
                    {group.subtitle && (
                      <p className="text-xs text-muted-foreground mt-0.5">
                        {group.subtitle}
                      </p>
                    )}
                  </div>
                  <div className="space-y-2">
                    {groupSteps.map((step) => (
                      <StepCard
                        key={step.id}
                        step={step}
                        dismissed={dismissed}
                        onSkip={(id) => setSkipTargetId(id)}
                        onUnskip={(id) => unskipMutation.mutate(id)}
                      />
                    ))}
                  </div>
                </div>
              );
            })}
        </div>
      </main>

      <SkipDialog
        open={Boolean(skipTargetId)}
        onOpenChange={(open) => !open && setSkipTargetId(null)}
        onConfirm={handleSkipConfirm}
        isPending={skipMutation.isPending}
      />
    </div>
  );
}
