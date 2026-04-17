import {
  DndContext,
  DragEndEvent,
  PointerSensor,
  useSensor,
  useSensors,
  useDraggable,
  useDroppable,
} from "@dnd-kit/core";
import type { ActionPlanListItem, ActionPlanStatus } from "@/hooks/useActionPlans";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { cn } from "@/lib/utils";

export type KanbanColumn = { status: ActionPlanStatus; label: string };

export const KANBAN_COLUMNS: KanbanColumn[] = [
  { status: "pending", label: "Aberto" },
  { status: "in_progress", label: "Em Andamento" },
  { status: "blocked", label: "Bloqueado" },
  { status: "done", label: "Fechado" },
  { status: "cancelled", label: "Cancelado" },
];

export interface KanbanBoardProps {
  items: ActionPlanListItem[];
  /** Return true if the current user can drag this specific plan. */
  canDrag: (plan: ActionPlanListItem) => boolean;
  /** Fires when a plan is dropped into a different column. Parent decides what to do. */
  onDropPlan: (plan: ActionPlanListItem, toStatus: ActionPlanStatus) => void;
  /** Fires when a card is clicked (not dragged). Parent navigates. */
  onClickCard?: (plan: ActionPlanListItem) => void;
}

export function KanbanBoard({ items, canDrag, onDropPlan, onClickCard }: KanbanBoardProps) {
  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 5 } }),
  );

  function handleDragEnd(e: DragEndEvent) {
    if (!e.over) return;
    const toStatus = e.over.id as ActionPlanStatus;
    const plan = items.find((i) => i.id === e.active.id);
    if (!plan || plan.status === toStatus) return;
    onDropPlan(plan, toStatus);
  }

  return (
    <DndContext sensors={sensors} onDragEnd={handleDragEnd}>
      <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
        {KANBAN_COLUMNS.map((col) => (
          <Column
            key={col.status}
            column={col}
            items={items.filter((i) => i.status === col.status)}
            canDrag={canDrag}
            onClickCard={onClickCard}
          />
        ))}
      </div>
    </DndContext>
  );
}

function Column({
  column,
  items,
  canDrag,
  onClickCard,
}: {
  column: KanbanColumn;
  items: ActionPlanListItem[];
  canDrag: (p: ActionPlanListItem) => boolean;
  onClickCard?: (p: ActionPlanListItem) => void;
}) {
  const { setNodeRef, isOver } = useDroppable({ id: column.status });
  return (
    <div
      ref={setNodeRef}
      className={cn(
        "bg-muted/40 rounded-md p-2 min-h-[200px]",
        isOver && "bg-muted ring-2 ring-primary/30",
      )}
    >
      <div className="flex items-center justify-between mb-2 px-1">
        <h3 className="text-sm font-semibold">{column.label}</h3>
        <Badge variant="secondary" className="text-xs">
          {items.length}
        </Badge>
      </div>
      <div className="space-y-2">
        {items.map((plan) => (
          <KanbanCard
            key={plan.id}
            plan={plan}
            draggable={canDrag(plan)}
            onClick={onClickCard}
          />
        ))}
      </div>
    </div>
  );
}

function KanbanCard({
  plan,
  draggable,
  onClick,
}: {
  plan: ActionPlanListItem;
  draggable: boolean;
  onClick?: (p: ActionPlanListItem) => void;
}) {
  const { setNodeRef, attributes, listeners, transform, isDragging } =
    useDraggable({ id: plan.id, disabled: !draggable });

  const style = transform
    ? { transform: `translate(${transform.x}px, ${transform.y}px)` }
    : undefined;

  return (
    <Card
      ref={setNodeRef}
      style={style}
      {...(draggable ? { ...attributes, ...listeners } : {})}
      onClick={() => {
        if (!isDragging) onClick?.(plan);
      }}
      className={cn(
        "p-2 text-sm bg-background",
        draggable ? "cursor-grab active:cursor-grabbing" : "cursor-pointer",
        isDragging && "opacity-50 shadow-lg",
      )}
    >
      <div className="font-mono text-xs text-muted-foreground">{plan.code}</div>
      <div className="font-medium line-clamp-2">{plan.title}</div>
      <div className="mt-1 flex items-center justify-between">
        <PriorityBadge priority={plan.priority} />
        {plan.assignee && (
          <span className="text-xs text-muted-foreground truncate max-w-[80px]">
            {plan.assignee.name}
          </span>
        )}
      </div>
      <div className="mt-1 text-xs text-muted-foreground">
        {plan.threatCount} ameaça{plan.threatCount === 1 ? "" : "s"}
      </div>
    </Card>
  );
}

function PriorityBadge({ priority }: { priority: ActionPlanListItem["priority"] }) {
  const map = {
    low: { label: "Baixa", variant: "outline" as const },
    medium: { label: "Média", variant: "secondary" as const },
    high: { label: "Alta", variant: "default" as const },
    critical: { label: "Crítica", variant: "destructive" as const },
  };
  const { label, variant } = map[priority] ?? map.medium;
  return (
    <Badge variant={variant} className="text-xs">
      {label}
    </Badge>
  );
}
