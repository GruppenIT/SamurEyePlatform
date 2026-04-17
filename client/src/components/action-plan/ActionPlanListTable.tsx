import type { ActionPlanListItem } from "@/hooks/useActionPlans";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { STATUS_LABEL } from "./StatusTransitionDialog";

const PRIORITY_LABEL: Record<ActionPlanListItem["priority"], string> = {
  low: "Baixa", medium: "Média", high: "Alta", critical: "Crítica",
};

interface ActionPlanListTableProps {
  items: ActionPlanListItem[];
  onRowClick: (plan: ActionPlanListItem) => void;
}

function statusVariant(s: ActionPlanListItem["status"]): "default"|"secondary"|"outline"|"destructive" {
  switch (s) {
    case "pending": return "secondary";
    case "in_progress": return "default";
    case "blocked": return "destructive";
    case "done": return "outline";
    case "cancelled": return "outline";
  }
}

function priorityVariant(p: ActionPlanListItem["priority"]): "default"|"secondary"|"outline"|"destructive" {
  return p === "critical" ? "destructive" : p === "high" ? "default" : p === "medium" ? "secondary" : "outline";
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleString("pt-BR", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

export function ActionPlanListTable({ items, onRowClick }: ActionPlanListTableProps) {
  if (items.length === 0) {
    return <div className="p-8 text-center text-muted-foreground">Nenhum plano encontrado.</div>;
  }
  return (
    <div className="border rounded-md overflow-hidden">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[130px]">Código</TableHead>
            <TableHead>Título</TableHead>
            <TableHead className="w-[110px]">Status</TableHead>
            <TableHead className="w-[100px]">Prioridade</TableHead>
            <TableHead className="w-[180px]">Responsável</TableHead>
            <TableHead className="w-[100px]">Ameaças</TableHead>
            <TableHead className="w-[140px]">Criado</TableHead>
            <TableHead className="w-[140px]">Atualizado</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.map(p => (
            <TableRow key={p.id} className="cursor-pointer hover:bg-accent/40" onClick={() => onRowClick(p)}>
              <TableCell className="font-mono text-xs">{p.code}</TableCell>
              <TableCell className="font-medium">{p.title}</TableCell>
              <TableCell><Badge variant={statusVariant(p.status)}>{STATUS_LABEL[p.status]}</Badge></TableCell>
              <TableCell><Badge variant={priorityVariant(p.priority)}>{PRIORITY_LABEL[p.priority]}</Badge></TableCell>
              <TableCell className="text-sm">{p.assignee?.name ?? <span className="text-muted-foreground">—</span>}</TableCell>
              <TableCell className="text-sm">{p.threatCount}</TableCell>
              <TableCell className="text-xs text-muted-foreground">{fmtDate(p.createdAt)}</TableCell>
              <TableCell className="text-xs text-muted-foreground">{fmtDate(p.updatedAt)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
