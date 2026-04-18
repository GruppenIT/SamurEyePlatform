import { useState } from "react";
import {
  useActionPlanThreats,
  useRemoveThreat,
  useAssociateThreats,
  useActionPlanComments,
  type ActionPlanThreatItem,
} from "@/hooks/useActionPlans";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ClipboardList, Plus, Trash2 } from "lucide-react";
import { ThreatPickerDialog } from "./ThreatPickerDialog";
import { RichTextRenderer } from "@/components/rich-text/RichTextRenderer";
import { useToast } from "@/hooks/use-toast";

interface ThreatsTabProps {
  planId: string;
  canEdit: boolean;
}

export function ThreatsTab({ planId, canEdit }: ThreatsTabProps) {
  const { data: threats = [], isLoading } = useActionPlanThreats(planId);
  const associate = useAssociateThreats();
  const remove = useRemoveThreat();
  const { toast } = useToast();

  const [pickerOpen, setPickerOpen] = useState(false);
  const [drawerThreatId, setDrawerThreatId] = useState<string | null>(null);
  const [removeConfirm, setRemoveConfirm] = useState<ActionPlanThreatItem | null>(null);

  async function handleAssociate(ids: string[]) {
    try {
      await associate.mutateAsync({ id: planId, threatIds: ids });
      toast({ title: `${ids.length} ameaça(s) associada(s)` });
    } catch (err: any) {
      toast({ title: "Erro", description: err.message, variant: "destructive" });
    }
  }

  async function handleRemove(threat: ActionPlanThreatItem) {
    try {
      await remove.mutateAsync({ id: planId, threatId: threat.id });
      toast({ title: "Ameaça removida do plano" });
    } catch (err: any) {
      toast({ title: "Erro", description: err.message, variant: "destructive" });
    } finally {
      setRemoveConfirm(null);
    }
  }

  const excludedIds = threats.map((t) => t.id);

  return (
    <div className="py-4 space-y-3">
      {canEdit && (
        <div className="flex justify-end">
          <Button size="sm" onClick={() => setPickerOpen(true)}>
            <Plus className="h-4 w-4 mr-1" /> Associar ameaças
          </Button>
        </div>
      )}

      {isLoading ? (
        <div className="text-sm text-muted-foreground">Carregando...</div>
      ) : (
        <div className="border rounded-md">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[100px]">Severidade</TableHead>
                <TableHead>Título</TableHead>
                <TableHead className="w-[110px]">Status</TableHead>
                <TableHead className="w-[60px] text-center">
                  Comentários
                </TableHead>
                {canEdit && <TableHead className="w-[60px]"></TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {threats.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={canEdit ? 5 : 4}
                    className="text-center text-muted-foreground py-6"
                  >
                    Nenhuma ameaça associada.
                  </TableCell>
                </TableRow>
              )}
              {threats.map((t) => (
                <TableRow key={t.id}>
                  <TableCell>
                    <Badge
                      variant={
                        t.severity === "critical" ? "destructive" : "secondary"
                      }
                      className="text-xs"
                    >
                      {t.severity}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-medium">{t.title}</TableCell>
                  <TableCell className="text-xs">{t.status}</TableCell>
                  <TableCell className="text-center">
                    <button
                      disabled={!t.hasComments}
                      onClick={() => setDrawerThreatId(t.id)}
                      className="p-1 rounded hover:bg-accent disabled:opacity-30 disabled:cursor-not-allowed"
                      aria-label="Ver comentários sobre esta ameaça"
                    >
                      <ClipboardList
                        className={`h-4 w-4 ${t.hasComments ? "text-primary" : "text-muted-foreground"}`}
                      />
                    </button>
                  </TableCell>
                  {canEdit && (
                    <TableCell>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => setRemoveConfirm(t)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <ThreatPickerDialog
        open={pickerOpen}
        onOpenChange={setPickerOpen}
        excludedIds={excludedIds}
        onConfirm={handleAssociate}
      />

      <Dialog
        open={!!removeConfirm}
        onOpenChange={(o) => !o && setRemoveConfirm(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Remover ameaça do plano?</DialogTitle>
          </DialogHeader>
          <p className="text-sm">
            Remover <strong>{removeConfirm?.title}</strong> deste plano.
            Comentários associados a esta ameaça perderão a ligação, mas os
            comentários permanecerão no plano.
          </p>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRemoveConfirm(null)}>
              Cancelar
            </Button>
            <Button
              variant="destructive"
              onClick={() => removeConfirm && handleRemove(removeConfirm)}
              disabled={remove.isPending}
            >
              {remove.isPending ? "Removendo..." : "Remover"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {drawerThreatId && (
        <CommentsForThreatDrawer
          planId={planId}
          threatId={drawerThreatId}
          onClose={() => setDrawerThreatId(null)}
        />
      )}
    </div>
  );
}

function CommentsForThreatDrawer({
  planId,
  threatId,
  onClose,
}: {
  planId: string;
  threatId: string;
  onClose: () => void;
}) {
  const { data = [], isLoading } = useActionPlanComments(planId, threatId);
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Comentários sobre esta ameaça</DialogTitle>
        </DialogHeader>
        {isLoading && (
          <div className="text-sm text-muted-foreground">Carregando...</div>
        )}
        {!isLoading && data.length === 0 && (
          <div className="text-sm text-muted-foreground">
            Nenhum comentário vinculado.
          </div>
        )}
        <div className="space-y-3">
          {data.map((c) => (
            <div key={c.id} className="border rounded-md p-3">
              <div className="text-xs text-muted-foreground mb-1">
                <strong>{c.author?.name ?? "—"}</strong> ·{" "}
                {new Date(c.createdAt).toLocaleString("pt-BR")}
              </div>
              <RichTextRenderer html={c.content} />
            </div>
          ))}
        </div>
      </DialogContent>
    </Dialog>
  );
}
