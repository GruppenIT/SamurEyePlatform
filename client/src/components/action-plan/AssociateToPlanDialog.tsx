import { useState, useEffect } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useActionPlans, useAssociateThreats, type ActionPlanListItem } from "@/hooks/useActionPlans";
import { CreateActionPlanDialog } from "./CreateActionPlanDialog";
import { useToast } from "@/hooks/use-toast";

interface AssociateToPlanDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  threatIds: string[];
  onSuccess?: () => void;
}

export function AssociateToPlanDialog({ open, onOpenChange, threatIds, onSuccess }: AssociateToPlanDialogProps) {
  const [mode, setMode] = useState<"existing"|"new">("existing");
  const [selectedPlanId, setSelectedPlanId] = useState<string>("");
  const [createOpen, setCreateOpen] = useState(false);
  const { toast } = useToast();

  // Fetch only non-terminal plans to associate with
  const { data: listData } = useActionPlans({
    status: ["pending","in_progress","blocked"],
    limit: 100,
  });
  const plans: ActionPlanListItem[] = listData?.rows ?? [];

  const associate = useAssociateThreats();

  useEffect(() => { if (open) { setMode("existing"); setSelectedPlanId(""); } }, [open]);

  async function handleConfirm() {
    if (mode === "existing") {
      if (!selectedPlanId) return;
      try {
        await associate.mutateAsync({ id: selectedPlanId, threatIds });
        toast({ title: `${threatIds.length} ameaça(s) associada(s)` });
        onSuccess?.();
        onOpenChange(false);
      } catch (err: any) {
        toast({ title: "Erro", description: err.message, variant: "destructive" });
      }
    } else {
      // "new" — open create dialog. It will handle navigation.
      onOpenChange(false);
      setCreateOpen(true);
    }
  }

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Associar {threatIds.length} ameaça(s) a um plano</DialogTitle>
          </DialogHeader>

          <RadioGroup value={mode} onValueChange={(v) => setMode(v as "existing"|"new")} className="space-y-2">
            <div className="flex items-center space-x-2">
              <RadioGroupItem value="existing" id="mode-existing" />
              <Label htmlFor="mode-existing">Plano existente</Label>
            </div>
            <div className="flex items-center space-x-2">
              <RadioGroupItem value="new" id="mode-new" />
              <Label htmlFor="mode-new">Novo plano</Label>
            </div>
          </RadioGroup>

          {mode === "existing" && (
            <div>
              <Label>Escolher plano</Label>
              <Select value={selectedPlanId} onValueChange={setSelectedPlanId}>
                <SelectTrigger>
                  <SelectValue placeholder={plans.length === 0 ? "Nenhum plano ativo" : "Selecione..."} />
                </SelectTrigger>
                <SelectContent>
                  {plans.map(p => (
                    <SelectItem key={p.id} value={p.id}>
                      <span className="font-mono text-xs mr-2">{p.code}</span>
                      {p.title}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}

          <DialogFooter>
            <Button variant="outline" onClick={() => onOpenChange(false)} disabled={associate.isPending}>Cancelar</Button>
            <Button
              onClick={handleConfirm}
              disabled={associate.isPending || (mode === "existing" && !selectedPlanId)}
            >
              {mode === "new" ? "Criar plano" : (associate.isPending ? "Associando..." : "Associar")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <CreateActionPlanDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        initialThreatIds={threatIds}
        onCreated={() => onSuccess?.()}
      />
    </>
  );
}
