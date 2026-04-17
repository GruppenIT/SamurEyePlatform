import { useActionPlanHistory, type ActionPlanHistoryEntry } from "@/hooks/useActionPlans";
import { Card, CardContent } from "@/components/ui/card";
import {
  CircleDot,
  FileEdit,
  UserCog,
  Flag,
  Pin,
  Link2,
  Unlink,
  MessageSquare,
  MessageSquarePlus,
  Plus,
} from "lucide-react";

interface HistoryTabProps {
  planId: string;
}

const ACTION_LABEL: Record<string, string> = {
  created: "Plano criado",
  status_changed: "Status alterado",
  assignee_changed: "Responsável alterado",
  title_changed: "Título alterado",
  description_changed: "Descrição alterada",
  priority_changed: "Prioridade alterada",
  threat_added: "Ameaça adicionada",
  threat_removed: "Ameaça removida",
  comment_added: "Comentário adicionado",
  comment_edited: "Comentário editado",
};

function actionIcon(action: string) {
  switch (action) {
    case "created":
      return <CircleDot className="h-4 w-4" />;
    case "status_changed":
      return <Flag className="h-4 w-4" />;
    case "assignee_changed":
      return <UserCog className="h-4 w-4" />;
    case "title_changed":
    case "description_changed":
      return <FileEdit className="h-4 w-4" />;
    case "priority_changed":
      return <Pin className="h-4 w-4" />;
    case "threat_added":
      return <Link2 className="h-4 w-4" />;
    case "threat_removed":
      return <Unlink className="h-4 w-4" />;
    case "comment_added":
      return <MessageSquarePlus className="h-4 w-4" />;
    case "comment_edited":
      return <MessageSquare className="h-4 w-4" />;
    default:
      return <Plus className="h-4 w-4" />;
  }
}

function renderDetails(entry: ActionPlanHistoryEntry): string | null {
  const d = entry.detailsJson as any;
  if (!d) return null;
  switch (entry.action) {
    case "status_changed": {
      const parts = [];
      if (d.from && d.to) parts.push(`de ${d.from} para ${d.to}`);
      if (d.reason) parts.push(`— ${d.reason}`);
      return parts.join(" ") || null;
    }
    case "title_changed":
      return d.from !== undefined ? `"${d.from}" → "${d.to}"` : null;
    case "priority_changed":
      return `${d.from} → ${d.to}`;
    case "assignee_changed":
      return null;
    case "threat_added":
    case "threat_removed":
      return d.threatId ? `ameaça ${(d.threatId as string).slice(0, 8)}...` : null;
    case "created":
      return d.code ? `código ${d.code}` : null;
    default:
      return null;
  }
}

export function HistoryTab({ planId }: HistoryTabProps) {
  const { data: entries = [], isLoading } = useActionPlanHistory(planId);

  if (isLoading)
    return (
      <div className="py-4 text-sm text-muted-foreground">Carregando...</div>
    );
  if (entries.length === 0)
    return (
      <div className="py-4 text-sm text-muted-foreground">Sem eventos.</div>
    );

  return (
    <div className="py-4">
      <ol className="relative border-l border-border ml-3 space-y-4">
        {entries.map((e) => {
          const details = renderDetails(e);
          return (
            <li key={e.id} className="pl-6 relative">
              <div className="absolute -left-[9px] top-1 w-4 h-4 rounded-full bg-background border flex items-center justify-center">
                {actionIcon(e.action)}
              </div>
              <Card>
                <CardContent className="p-3">
                  <div className="text-sm font-medium">
                    {ACTION_LABEL[e.action] ?? e.action}
                  </div>
                  {details && (
                    <div className="text-xs text-muted-foreground mt-0.5">
                      {details}
                    </div>
                  )}
                  <div className="text-xs text-muted-foreground mt-1">
                    <strong>{e.actor?.name ?? "—"}</strong> ·{" "}
                    {new Date(e.createdAt).toLocaleString("pt-BR")}
                  </div>
                </CardContent>
              </Card>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
