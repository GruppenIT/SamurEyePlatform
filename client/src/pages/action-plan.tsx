import { useState } from "react";
import { useLocation } from "wouter";
import { LayoutGrid, List, Plus, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useActionPlans, useChangeActionPlanStatus, type ActionPlanStatus, type ActionPlanPriority, type ActionPlanFilters, type ActionPlanListItem } from "@/hooks/useActionPlans";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { KanbanBoard } from "@/components/action-plan/KanbanBoard";
import { ActionPlanListTable } from "@/components/action-plan/ActionPlanListTable";
import { CreateActionPlanDialog } from "@/components/action-plan/CreateActionPlanDialog";
import { StatusTransitionDialog, STATUS_LABEL, STATUS_TRANSITIONS } from "@/components/action-plan/StatusTransitionDialog";
import { AssigneeSelector } from "@/components/action-plan/AssigneeSelector";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";

type ViewMode = "list" | "kanban";

const STATUS_OPTIONS: ActionPlanStatus[] = ["pending", "in_progress", "blocked", "done", "cancelled"];
const PRIORITY_OPTIONS: ActionPlanPriority[] = ["low", "medium", "high", "critical"];
const PRIORITY_LABEL: Record<ActionPlanPriority, string> = { low: "Baixa", medium: "Média", high: "Alta", critical: "Crítica" };

export default function ActionPlanPage() {
  const [, setLocation] = useLocation();
  const { user } = useAuth();
  const { toast } = useToast();

  const [view, setView] = useState<ViewMode>("list");
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<ActionPlanStatus | "all">("all");
  const [priorityFilter, setPriorityFilter] = useState<ActionPlanPriority | "all">("all");
  const [assigneeFilter, setAssigneeFilter] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);

  // Status transition dialog (used by kanban drops that need reason)
  const [transitionState, setTransitionState] = useState<{
    open: boolean; plan: ActionPlanListItem | null; preselectTo?: ActionPlanStatus;
  }>({ open: false, plan: null });

  const filters: ActionPlanFilters = {
    limit: 100,
    offset: 0,
    search: search.trim() || undefined,
    status: statusFilter === "all" ? undefined : statusFilter,
    priority: priorityFilter === "all" ? undefined : priorityFilter,
    assigneeId: assigneeFilter ?? undefined,
  };

  const { data, isLoading } = useActionPlans(filters);
  const changeStatus = useChangeActionPlanStatus();

  const currentUserId = (user as any)?.id as string | undefined;
  function canDragPlan(plan: ActionPlanListItem): boolean {
    if (!currentUserId) return false;
    return plan.createdBy?.id === currentUserId || plan.assignee?.id === currentUserId;
  }

  function transitionIsAllowed(from: ActionPlanStatus, to: ActionPlanStatus): boolean {
    return STATUS_TRANSITIONS.some((t) => t.from === from && t.to === to);
  }

  function transitionRequiresReason(from: ActionPlanStatus, to: ActionPlanStatus): boolean {
    const t = STATUS_TRANSITIONS.find((t) => t.from === from && t.to === to);
    return t?.requiresReason != null;
  }

  async function handleKanbanDrop(plan: ActionPlanListItem, toStatus: ActionPlanStatus) {
    if (plan.status === toStatus) return;
    if (!transitionIsAllowed(plan.status, toStatus)) {
      toast({ title: "Transição inválida", description: `Não é possível mover de ${STATUS_LABEL[plan.status]} para ${STATUS_LABEL[toStatus]}.`, variant: "destructive" });
      return;
    }
    if (transitionRequiresReason(plan.status, toStatus)) {
      setTransitionState({ open: true, plan, preselectTo: toStatus });
      return;
    }
    // No reason needed — apply directly.
    try {
      await changeStatus.mutateAsync({ id: plan.id, status: toStatus });
      toast({ title: "Status atualizado" });
    } catch (err: any) {
      toast({ title: "Erro ao mudar status", description: err.message ?? "Tente novamente.", variant: "destructive" });
    }
  }

  async function handleDialogConfirm(to: ActionPlanStatus, reason?: string) {
    const plan = transitionState.plan;
    if (!plan) return;
    const transition = STATUS_TRANSITIONS.find((t) => t.from === plan.status && t.to === to);
    const kind = transition?.requiresReason;
    try {
      await changeStatus.mutateAsync({
        id: plan.id,
        status: to,
        blockReason: kind === "block" ? reason : undefined,
        cancelReason: kind === "cancel" ? reason : undefined,
      });
      toast({ title: "Status atualizado" });
    } catch (err: any) {
      toast({ title: "Erro ao mudar status", description: err.message ?? "Tente novamente.", variant: "destructive" });
      throw err; // keep dialog open so the user can retry
    }
  }

  const items = data?.rows ?? [];

  return (
    <div className="flex h-screen bg-background">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar
          title="Planos de Ação"
          subtitle="Organize o trabalho de remediação em planos com responsáveis, status e comentários."
          actions={
            <Button onClick={() => setCreateOpen(true)}>
              <Plus className="h-4 w-4 mr-1" /> Novo plano
            </Button>
          }
        />
        <main className="flex-1 overflow-y-auto p-6 space-y-4">

          {/* Filter bar */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative flex-1 min-w-[200px] max-w-[400px]">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                className="pl-8"
                placeholder="Buscar por código ou título..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>

            <Select value={statusFilter} onValueChange={(v) => setStatusFilter(v as ActionPlanStatus | "all")}>
              <SelectTrigger className="w-[160px]"><SelectValue placeholder="Status" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Todos status</SelectItem>
                {STATUS_OPTIONS.map(s => <SelectItem key={s} value={s}>{STATUS_LABEL[s]}</SelectItem>)}
              </SelectContent>
            </Select>

            <Select value={priorityFilter} onValueChange={(v) => setPriorityFilter(v as ActionPlanPriority | "all")}>
              <SelectTrigger className="w-[160px]"><SelectValue placeholder="Prioridade" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Todas prioridades</SelectItem>
                {PRIORITY_OPTIONS.map(p => <SelectItem key={p} value={p}>{PRIORITY_LABEL[p]}</SelectItem>)}
              </SelectContent>
            </Select>

            <div className="w-[220px]">
              <AssigneeSelector value={assigneeFilter} onChange={setAssigneeFilter} />
            </div>

            <div className="ml-auto inline-flex rounded-md border">
              <Button
                variant={view === "list" ? "secondary" : "ghost"}
                size="sm"
                onClick={() => setView("list")}
                aria-pressed={view === "list"}
                aria-label="Visualização em lista"
              >
                <List className="h-4 w-4" />
              </Button>
              <Button
                variant={view === "kanban" ? "secondary" : "ghost"}
                size="sm"
                onClick={() => setView("kanban")}
                aria-pressed={view === "kanban"}
                aria-label="Visualização kanban"
              >
                <LayoutGrid className="h-4 w-4" />
              </Button>
            </div>
          </div>

          {isLoading ? (
            <div className="text-sm text-muted-foreground">Carregando...</div>
          ) : view === "list" ? (
            <ActionPlanListTable items={items} onRowClick={(p) => setLocation(`/action-plan/${p.id}`)} />
          ) : (
            <KanbanBoard items={items} canDrag={canDragPlan} onDropPlan={handleKanbanDrop} onClickCard={(p) => setLocation(`/action-plan/${p.id}`)} />
          )}

          {data && (
            <div className="text-xs text-muted-foreground">
              {data.total} plano(s). {items.length !== data.total && `Exibindo ${items.length}.`}
            </div>
          )}
        </main>
      </div>

      <CreateActionPlanDialog open={createOpen} onOpenChange={setCreateOpen} />
      {transitionState.plan && (
        <StatusTransitionDialog
          open={transitionState.open}
          onOpenChange={(o) => setTransitionState(s => ({ ...s, open: o }))}
          currentStatus={transitionState.plan.status}
          preselectTo={transitionState.preselectTo}
          onConfirm={handleDialogConfirm}
        />
      )}
    </div>
  );
}
