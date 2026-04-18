import { useState } from "react";
import {
  useActionPlanComments,
  useCreateComment,
  useUpdateComment,
  type ActionPlanComment,
  type ActionPlanThreatItem,
} from "@/hooks/useActionPlans";
import { RichTextEditor } from "@/components/rich-text/RichTextEditor";
import { RichTextRenderer } from "@/components/rich-text/RichTextRenderer";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { Pencil, Check, X } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";

interface CommentsTabProps {
  planId: string;
  planThreats: ActionPlanThreatItem[];
}

export function CommentsTab({ planId, planThreats }: CommentsTabProps) {
  const { user } = useAuth();
  const { toast } = useToast();
  const { data: comments = [], isLoading } = useActionPlanComments(planId);
  const create = useCreateComment();

  const [newContent, setNewContent] = useState("");
  const [newThreatIds, setNewThreatIds] = useState<Set<string>>(new Set());

  async function handleCreate() {
    if (!newContent.trim()) return;
    try {
      await create.mutateAsync({
        id: planId,
        content: newContent,
        threatIds: newThreatIds.size > 0 ? Array.from(newThreatIds) : undefined,
      });
      setNewContent("");
      setNewThreatIds(new Set());
      toast({ title: "Comentário adicionado" });
    } catch (err: any) {
      toast({ title: "Erro", description: err.message, variant: "destructive" });
    }
  }

  function toggleThreat(tid: string) {
    setNewThreatIds((prev) => {
      const next = new Set(prev);
      if (next.has(tid)) next.delete(tid);
      else next.add(tid);
      return next;
    });
  }

  const currentUserId = (user as any)?.id as string | undefined;

  return (
    <div className="py-4 space-y-4">
      <Card>
        <CardContent className="p-4 space-y-3">
          <Label>Novo comentário</Label>
          <RichTextEditor
            value={newContent}
            onChange={setNewContent}
            placeholder="Descreva o progresso, decisões ou dúvidas..."
          />
          {planThreats.length > 0 && (
            <div>
              <Label className="text-xs text-muted-foreground">
                Associar a ameaças deste plano (opcional)
              </Label>
              <div className="flex flex-wrap gap-2 mt-1">
                {planThreats.map((t) => (
                  <label
                    key={t.id}
                    className="inline-flex items-center gap-1.5 text-xs border rounded px-2 py-1 cursor-pointer hover:bg-accent"
                  >
                    <Checkbox
                      checked={newThreatIds.has(t.id)}
                      onCheckedChange={() => toggleThreat(t.id)}
                    />
                    <span className="max-w-[200px] truncate">{t.title}</span>
                  </label>
                ))}
              </div>
            </div>
          )}
          <div className="flex justify-end">
            <Button
              onClick={handleCreate}
              disabled={!newContent.trim() || create.isPending}
            >
              {create.isPending ? "Publicando..." : "Publicar comentário"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {isLoading && (
        <div className="text-sm text-muted-foreground">
          Carregando comentários...
        </div>
      )}

      {comments.map((c) => (
        <CommentItem
          key={c.id}
          comment={c}
          planId={planId}
          canEdit={c.author?.id === currentUserId}
        />
      ))}

      {!isLoading && comments.length === 0 && (
        <div className="text-sm text-muted-foreground text-center py-8">
          Nenhum comentário ainda.
        </div>
      )}
    </div>
  );
}

function CommentItem({
  comment,
  planId,
  canEdit,
}: {
  comment: ActionPlanComment;
  planId: string;
  canEdit: boolean;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(comment.content);
  const update = useUpdateComment();
  const { toast } = useToast();

  async function handleSave() {
    try {
      await update.mutateAsync({
        id: planId,
        commentId: comment.id,
        content: draft,
      });
      setEditing(false);
      toast({ title: "Comentário atualizado" });
    } catch (err: any) {
      toast({ title: "Erro", description: err.message, variant: "destructive" });
    }
  }

  return (
    <Card>
      <CardContent className="p-4 space-y-2">
        <div className="flex items-center justify-between">
          <div className="text-sm">
            <strong>{comment.author?.name ?? "—"}</strong>
            <span className="text-muted-foreground ml-2 text-xs">
              {new Date(comment.createdAt).toLocaleString("pt-BR")}
              {comment.updatedAt && (
                <> · editado {new Date(comment.updatedAt).toLocaleString("pt-BR")}</>
              )}
            </span>
          </div>
          {canEdit && !editing && (
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                setDraft(comment.content);
                setEditing(true);
              }}
            >
              <Pencil className="h-3 w-3" />
            </Button>
          )}
        </div>

        {editing ? (
          <>
            <RichTextEditor value={draft} onChange={setDraft} />
            <div className="flex gap-2 justify-end">
              <Button
                size="sm"
                variant="outline"
                onClick={() => setEditing(false)}
              >
                <X className="h-3 w-3 mr-1" />
                Cancelar
              </Button>
              <Button
                size="sm"
                onClick={handleSave}
                disabled={update.isPending}
              >
                <Check className="h-3 w-3 mr-1" />
                Salvar
              </Button>
            </div>
          </>
        ) : (
          <>
            <RichTextRenderer html={comment.content} />
            {comment.threats.length > 0 && (
              <div className="flex flex-wrap gap-1 pt-2">
                {comment.threats.map((t) => (
                  <Badge key={t.id} variant="outline" className="text-xs">
                    {t.title}
                  </Badge>
                ))}
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
