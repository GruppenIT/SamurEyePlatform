import { useRoute, useLocation } from "wouter";
import { useState } from "react";
import {
  useActionPlan,
  type ActionPlanDetail,
  type ActionPlanStatus,
  type ActionPlanPriority,
} from "@/hooks/useActionPlans";
import { useAuth } from "@/hooks/useAuth";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ArrowLeft, Pencil, PlayCircle } from "lucide-react";
import { STATUS_LABEL } from "@/components/action-plan/StatusTransitionDialog";

const PRIORITY_LABEL: Record<ActionPlanPriority, string> = {
  low: "Baixa",
  medium: "Média",
  high: "Alta",
  critical: "Crítica",
};

function statusVariant(
  s: ActionPlanStatus,
): "default" | "secondary" | "outline" | "destructive" {
  switch (s) {
    case "pending":
      return "secondary";
    case "in_progress":
      return "default";
    case "blocked":
      return "destructive";
    default:
      return "outline";
  }
}

function priorityVariant(p: ActionPlanPriority) {
  return p === "critical"
    ? "destructive"
    : p === "high"
      ? "default"
      : p === "medium"
        ? "secondary"
        : "outline";
}

export default function ActionPlanDetailPage() {
  const [, params] = useRoute("/action-plan/:id");
  const [, setLocation] = useLocation();
  const { user } = useAuth();
  const id = params?.id ?? "";

  const { data: plan, isLoading } = useActionPlan(
    id,
    "threats,comments,history",
  );

  if (!id) return null;
  if (isLoading)
    return (
      <PageShell>
        <div className="p-6 text-sm text-muted-foreground">Carregando...</div>
      </PageShell>
    );
  if (!plan)
    return (
      <PageShell>
        <div className="p-6 text-sm text-muted-foreground">
          Plano não encontrado.
        </div>
      </PageShell>
    );

  const currentUserId = (user as any)?.id as string | undefined;
  const canEdit =
    !!currentUserId &&
    (plan.createdBy?.id === currentUserId ||
      plan.assignee?.id === currentUserId);

  return (
    <PageShell>
      <div className="p-6 space-y-4 max-w-7xl">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setLocation("/action-plan")}
        >
          <ArrowLeft className="h-4 w-4 mr-1" /> Voltar
        </Button>

        <PlanHeader plan={plan} canEdit={canEdit} />

        <Tabs defaultValue="summary">
          <TabsList>
            <TabsTrigger value="summary">Sumário</TabsTrigger>
            <TabsTrigger value="comments">Comentários</TabsTrigger>
            <TabsTrigger value="threats">Ameaças</TabsTrigger>
            <TabsTrigger value="history">Histórico</TabsTrigger>
          </TabsList>
          <TabsContent value="summary">
            {/* Summary tab content in E3 */}
            <div className="py-4 text-sm text-muted-foreground">
              (Sumário — em breve)
            </div>
          </TabsContent>
          <TabsContent value="comments">
            <div className="py-4 text-sm text-muted-foreground">
              (Comentários — em breve)
            </div>
          </TabsContent>
          <TabsContent value="threats">
            <div className="py-4 text-sm text-muted-foreground">
              (Ameaças — em breve)
            </div>
          </TabsContent>
          <TabsContent value="history">
            <div className="py-4 text-sm text-muted-foreground">
              (Histórico — em breve)
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </PageShell>
  );
}

function PageShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-screen bg-background">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar title="Plano de Ação" subtitle="Detalhe do plano" />
        <main className="flex-1 overflow-y-auto">{children}</main>
      </div>
    </div>
  );
}

function PlanHeader({
  plan,
  canEdit,
}: {
  plan: ActionPlanDetail;
  canEdit: boolean;
}) {
  return (
    <Card>
      <CardContent className="p-4 space-y-3">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="font-mono text-xs text-muted-foreground">
              {plan.code}
            </div>
            <h1 className="text-xl font-semibold mt-0.5">{plan.title}</h1>
          </div>
          {canEdit && (
            <div className="flex gap-2 shrink-0">
              <Button size="sm" variant="outline">
                <Pencil className="h-4 w-4 mr-1" /> Editar
              </Button>
              <Button size="sm" variant="outline">
                <PlayCircle className="h-4 w-4 mr-1" /> Mudar Status
              </Button>
            </div>
          )}
        </div>

        <div className="flex flex-wrap gap-2 text-sm">
          <Badge variant={statusVariant(plan.status)}>
            {STATUS_LABEL[plan.status]}
          </Badge>
          <Badge variant={priorityVariant(plan.priority)}>
            {PRIORITY_LABEL[plan.priority]}
          </Badge>
          <span className="text-muted-foreground">
            Criado por <strong>{plan.createdBy?.name ?? "—"}</strong>
          </span>
          <span className="text-muted-foreground">
            Responsável:{" "}
            <strong>{plan.assignee?.name ?? "sem atribuição"}</strong>
          </span>
          <span className="text-muted-foreground">
            Criado: {new Date(plan.createdAt).toLocaleString("pt-BR")}
          </span>
          <span className="text-muted-foreground">
            Atualizado: {new Date(plan.updatedAt).toLocaleString("pt-BR")}
          </span>
        </div>
      </CardContent>
    </Card>
  );
}
