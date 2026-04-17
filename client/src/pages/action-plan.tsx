import { useState } from "react";
import { useLocation } from "wouter";
import { LayoutGrid, List, Plus, Search, ChevronDown } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
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

function summarizeSelection<T extends string>(selected: Set<T>, labelMap: Record<T, string>, emptyLabel: string): string {
  if (selected.size === 0) return emptyLabel;
  if (selected.size === 1) return labelMap[Array.from(selected)[0] as T];
  return `${selected.size} selecionados`;
}

export default function ActionPlanPage() {
  const [, setLocation] = useLocation();
  const { user } = useAuth();
  const { toast } = useToast();

  const [view, setView] = useState<ViewMode>("list");
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<Set<ActionPlanStatus>>(new Set());
  const [priorityFilter, setPriorityFilter] = useState<Set<ActionPlanPriority>>(new Set());
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
    status: statusFilter.size > 0 ? Array.from(statusFilter) : undefined,
    priority: priorityFilter.size > 0 ? Array.from(priorityFilter) : undefined,
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
    try {
      await changeStatus.mutateAsync({ id: plan.id, status: to, reason });
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

            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" className="w-[180px] justify-between">
                  <span className="truncate">{summarizeSelection(statusFilter, STATUS_LABEL, "Todos status")}</span>
                  <ChevronDown className="h-4 w-4 ml-2 opacity-50 shrink-0" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent className="w-[200px]">
                <DropdownMenuLabel>Status</DropdownMenuLabel>
                <DropdownMenuSeparator />
                {STATUS_OPTIONS.map(s => (
                  <DropdownMenuCheckboxItem
                    key={s}
                    checked={statusFilter.has(s)}
                    onCheckedChange={(checked) => {
                      setStatusFilter(prev => {
                        const next = new Set(prev);
                        if (checked) next.add(s); else next.delete(s);
                        return next;
                      });
                    }}
                    onSelect={(e) => e.preventDefault()}
                  >
                    {STATUS_LABEL[s]}
                  </DropdownMenuCheckboxItem>
                ))}
                {statusFilter.size > 0 && (
                  <>
                    <DropdownMenuSeparator />
                    <button
                      className="w-full text-left px-2 py-1.5 text-sm hover:bg-accent rounded-sm"
                      onClick={() => setStatusFilter(new Set())}
                    >
                      Limpar seleção
                    </button>
                  </>
                )}
              </DropdownMenuContent>
            </DropdownMenu>

            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" className="w-[180px] justify-between">
                  <span className="truncate">{summarizeSelection(priorityFilter, PRIORITY_LABEL, "Todas prioridades")}</span>
                  <ChevronDown className="h-4 w-4 ml-2 opacity-50 shrink-0" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent className="w-[200px]">
                <DropdownMenuLabel>Prioridade</DropdownMenuLabel>
                <DropdownMenuSeparator />
                {PRIORITY_OPTIONS.map(p => (
                  <DropdownMenuCheckboxItem
                    key={p}
                    checked={priorityFilter.has(p)}
                    onCheckedChange={(checked) => {
                      setPriorityFilter(prev => {
                        const next = new Set(prev);
                        if (checked) next.add(p); else next.delete(p);
                        return next;
                      });
                    }}
                    onSelect={(e) => e.preventDefault()}
                  >
                    {PRIORITY_LABEL[p]}
                  </DropdownMenuCheckboxItem>
                ))}
                {priorityFilter.size > 0 && (
                  <>
                    <DropdownMenuSeparator />
                    <button
                      className="w-full text-left px-2 py-1.5 text-sm hover:bg-accent rounded-sm"
                      onClick={() => setPriorityFilter(new Set())}
                    >
                      Limpar seleção
                    </button>
                  </>
                )}
              </DropdownMenuContent>
            </DropdownMenu>

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
