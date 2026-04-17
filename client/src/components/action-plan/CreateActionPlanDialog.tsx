import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useState, useEffect } from "react";
import { useCreateActionPlan, type ActionPlanPriority } from "@/hooks/useActionPlans";
import { AssigneeSelector } from "./AssigneeSelector";
import { RichTextEditor } from "@/components/rich-text/RichTextEditor";
import { useToast } from "@/hooks/use-toast";
import { useLocation } from "wouter";

interface CreateActionPlanDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Optionally pre-associate threats when created (e.g., from /threats bulk action). */
  initialThreatIds?: string[];
  /** Optional: auto-navigate to detail after creation. Default true. */
  navigateOnSuccess?: boolean;
  onCreated?: (planId: string) => void;
}

export function CreateActionPlanDialog({ open, onOpenChange, initialThreatIds, navigateOnSuccess = true, onCreated }: CreateActionPlanDialogProps) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [priority, setPriority] = useState<ActionPlanPriority>("medium");
  const [assigneeId, setAssigneeId] = useState<string | null>(null);
  const [, setLocation] = useLocation();
  const { toast } = useToast();

  const createMutation = useCreateActionPlan();
  const submitting = createMutation.isPending;

  useEffect(() => {
    if (open) {
      setTitle("");
      setDescription("");
      setPriority("medium");
      setAssigneeId(null);
    }
  }, [open]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!title.trim()) return;
    try {
      const plan = await createMutation.mutateAsync({
        title: title.trim(),
        description: description || undefined,
        priority,
        assigneeId: assigneeId ?? undefined,
      });
      toast({ title: "Plano criado", description: `Código ${plan.code}` });
      onCreated?.(plan.id);
      onOpenChange(false);
      if (navigateOnSuccess) setLocation(`/action-plan/${plan.id}`);
    } catch (err: any) {
      toast({ title: "Erro ao criar plano", description: err.message ?? "Tente novamente.", variant: "destructive" });
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Novo plano de ação</DialogTitle>
          {initialThreatIds && initialThreatIds.length > 0 && (
            <DialogDescription>{initialThreatIds.length} ameaça(s) serão associadas ao plano.</DialogDescription>
          )}
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <Label htmlFor="title">Título *</Label>
            <Input id="title" value={title} onChange={(e) => setTitle(e.target.value)} maxLength={255} required />
          </div>

          <div>
            <Label>Descrição</Label>
            <RichTextEditor value={description} onChange={setDescription} placeholder="Detalhe o escopo do plano..." />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label>Prioridade</Label>
              <Select value={priority} onValueChange={(v) => setPriority(v as ActionPlanPriority)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
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

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={submitting}>Cancelar</Button>
            <Button type="submit" disabled={!title.trim() || submitting}>
              {submitting ? "Criando..." : "Criar plano"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
