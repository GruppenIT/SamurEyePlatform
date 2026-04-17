import { useRoute, useLocation } from "wouter";
import { useState, useEffect } from "react";
import {
  useActionPlan,
  useUpdateActionPlan,
  useChangeActionPlanStatus,
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
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ArrowLeft, Pencil, PlayCircle } from "lucide-react";
import {
  STATUS_LABEL,
  StatusTransitionDialog,
} from "@/components/action-plan/StatusTransitionDialog";
import { AssigneeSelector } from "@/components/action-plan/AssigneeSelector";
import { RichTextEditor } from "@/components/rich-text/RichTextEditor";
import { RichTextRenderer } from "@/components/rich-text/RichTextRenderer";
import { useToast } from "@/hooks/use-toast";
import { CommentsTab } from "@/components/action-plan/CommentsTab";
import { ThreatsTab } from "@/components/action-plan/ThreatsTab";

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

  const [editOpen, setEditOpen] = useState(false);
  const [statusOpen, setStatusOpen] = useState(false);
  const changeStatus = useChangeActionPlanStatus();
  const { toast } = useToast();

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

  async function handleStatusConfirm(to: ActionPlanStatus, reason?: string) {
    try {
      await changeStatus.mutateAsync({ id: plan!.id, status: to, reason });
      toast({ title: "Status atualizado" });
    } catch (err: any) {
      toast({
        title: "Erro ao atualizar status",
        description: err.message,
        variant: "destructive",
      });
    }
  }

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

        <PlanHeader
          plan={plan}
          canEdit={canEdit}
          onEditClick={() => setEditOpen(true)}
          onStatusClick={() => setStatusOpen(true)}
        />

        <Tabs defaultValue="summary">
          <TabsList>
            <TabsTrigger value="summary">Sumário</TabsTrigger>
            <TabsTrigger value="comments">Comentários</TabsTrigger>
            <TabsTrigger value="threats">Ameaças</TabsTrigger>
            <TabsTrigger value="history">Histórico</TabsTrigger>
          </TabsList>
          <TabsContent value="summary">
            <SummaryTab plan={plan} />
          </TabsContent>
          <TabsContent value="comments">
            <CommentsTab planId={plan.id} planThreats={plan.threats ?? []} />
          </TabsContent>
          <TabsContent value="threats">
            <ThreatsTab planId={plan.id} canEdit={canEdit} />
          </TabsContent>
          <TabsContent value="history">
            <div className="py-4 text-sm text-muted-foreground">
              (Histórico — em breve)
            </div>
          </TabsContent>
        </Tabs>
      </div>

      <EditPlanDialog plan={plan} open={editOpen} onOpenChange={setEditOpen} />

      <StatusTransitionDialog
        open={statusOpen}
        onOpenChange={setStatusOpen}
        currentStatus={plan.status}
        onConfirm={handleStatusConfirm}
      />
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
  onEditClick,
  onStatusClick,
}: {
  plan: ActionPlanDetail;
  canEdit: boolean;
  onEditClick: () => void;
  onStatusClick: () => void;
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
              <Button size="sm" variant="outline" onClick={onEditClick}>
                <Pencil className="h-4 w-4 mr-1" /> Editar
              </Button>
              <Button size="sm" variant="outline" onClick={onStatusClick}>
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

// ─── Summary Tab ──────────────────────────────────────────────────────────────

function SummaryTab({ plan }: { plan: ActionPlanDetail }) {
  const threats = plan.threats ?? [];
  const comments = plan.comments ?? [];
  const bySeverity = {
    critical: threats.filter((t) => t.severity === "critical").length,
    high: threats.filter((t) => t.severity === "high").length,
    medium: threats.filter((t) => t.severity === "medium").length,
    low: threats.filter((t) => t.severity === "low").length,
  };

  return (
    <div className="py-4 space-y-4">
      {plan.status === "blocked" && plan.blockReason && (
        <div className="border border-amber-400/50 bg-amber-50 dark:bg-amber-950/20 rounded-md p-3 text-sm">
          <strong>Bloqueado:</strong> {plan.blockReason}
        </div>
      )}
      {plan.status === "cancelled" && plan.cancelReason && (
        <div className="border border-red-400/50 bg-red-50 dark:bg-red-950/20 rounded-md p-3 text-sm">
          <strong>Cancelado:</strong> {plan.cancelReason}
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
        <MetricCard label="Ameaças" value={threats.length} />
        <MetricCard
          label="Críticas"
          value={bySeverity.critical}
          tone="destructive"
        />
        <MetricCard label="Altas" value={bySeverity.high} />
        <MetricCard label="Médias" value={bySeverity.medium} />
        <MetricCard label="Comentários" value={comments.length} />
      </div>

      <Card>
        <CardContent className="p-4">
          <h3 className="text-sm font-semibold mb-2">Descrição</h3>
          {plan.description ? (
            <RichTextRenderer html={plan.description} />
          ) : (
            <p className="text-sm text-muted-foreground">Sem descrição.</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function MetricCard({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone?: "destructive";
}) {
  return (
    <Card
      className={tone === "destructive" ? "border-destructive/40" : undefined}
    >
      <CardContent className="p-3 text-center">
        <div className="text-2xl font-semibold">{value}</div>
        <div className="text-xs text-muted-foreground">{label}</div>
      </CardContent>
    </Card>
  );
}

// ─── Edit Plan Dialog ─────────────────────────────────────────────────────────

function EditPlanDialog({
  plan,
  open,
  onOpenChange,
}: {
  plan: ActionPlanDetail;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const [title, setTitle] = useState(plan.title);
  const [description, setDescription] = useState(plan.description ?? "");
  const [priority, setPriority] = useState<ActionPlanPriority>(plan.priority);
  const [assigneeId, setAssigneeId] = useState<string | null>(
    plan.assignee?.id ?? null,
  );
  const update = useUpdateActionPlan();
  const { toast } = useToast();

  useEffect(() => {
    if (open) {
      setTitle(plan.title);
      setDescription(plan.description ?? "");
      setPriority(plan.priority);
      setAssigneeId(plan.assignee?.id ?? null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, plan.id]);

  async function handleSubmit() {
    try {
      await update.mutateAsync({
        id: plan.id,
        data: {
          title,
          description: description || null,
          priority,
          assigneeId,
        },
      });
      toast({ title: "Plano atualizado" });
      onOpenChange(false);
    } catch (err: any) {
      toast({
        title: "Erro ao atualizar",
        description: err.message,
        variant: "destructive",
      });
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Editar plano</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <div>
            <Label>Título</Label>
            <Input value={title} onChange={(e) => setTitle(e.target.value)} />
          </div>
          <div>
            <Label>Descrição</Label>
            <RichTextEditor value={description} onChange={setDescription} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label>Prioridade</Label>
              <Select
                value={priority}
                onValueChange={(v) => setPriority(v as ActionPlanPriority)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="low">Baixa</SelectItem>
                  <SelectItem value="medium">Média</SelectItem>
                  <SelectItem value="high">Alta</SelectItem>
                  <SelectItem value="critical">Crítica</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Responsável</Label>
              <AssigneeSelector value={assigneeId} onChange={setAssigneeId} />
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancelar
          </Button>
          <Button onClick={handleSubmit} disabled={update.isPending}>
            {update.isPending ? "Salvando..." : "Salvar"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
