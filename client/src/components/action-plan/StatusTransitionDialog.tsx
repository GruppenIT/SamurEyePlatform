import { useState, useEffect } from "react";
import type { ActionPlanStatus } from "@/hooks/useActionPlans";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

// MIRROR of server/services/actionPlanService.ts STATUS_TRANSITIONS.
// Keep in sync manually; tested by backend validation as safety net.
export type TransitionReasonKind = "block" | "cancel" | "unblock" | null;

export interface StatusTransition {
  from: ActionPlanStatus;
  to: ActionPlanStatus;
  requiresReason: TransitionReasonKind;
}

export const STATUS_TRANSITIONS: StatusTransition[] = [
  { from: "pending", to: "in_progress", requiresReason: null },
  { from: "pending", to: "blocked", requiresReason: "block" },
  { from: "pending", to: "cancelled", requiresReason: "cancel" },
  { from: "in_progress", to: "blocked", requiresReason: "block" },
  { from: "in_progress", to: "done", requiresReason: null },
  { from: "in_progress", to: "cancelled", requiresReason: "cancel" },
  { from: "blocked", to: "pending", requiresReason: "unblock" },
  { from: "blocked", to: "in_progress", requiresReason: "unblock" },
  { from: "blocked", to: "cancelled", requiresReason: "cancel" },
];

export const STATUS_LABEL: Record<ActionPlanStatus, string> = {
  pending: "Pendente",
  in_progress: "Em Progresso",
  blocked: "Bloqueado",
  done: "Concluído",
  cancelled: "Cancelado",
};

interface StatusTransitionDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  currentStatus: ActionPlanStatus;
  /** If provided, pre-select this target (used when dropped in kanban). */
  preselectTo?: ActionPlanStatus;
  onConfirm: (to: ActionPlanStatus, reason?: string) => void | Promise<void>;
}

export function StatusTransitionDialog({
  open,
  onOpenChange,
  currentStatus,
  preselectTo,
  onConfirm,
}: StatusTransitionDialogProps) {
  const allowed = STATUS_TRANSITIONS.filter((t) => t.from === currentStatus);
  const [to, setTo] = useState<ActionPlanStatus | "">("");
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (open) {
      setTo(
        preselectTo && allowed.some((t) => t.to === preselectTo)
          ? preselectTo
          : "",
      );
      setReason("");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, preselectTo, currentStatus]);

  const transition = allowed.find((t) => t.to === to);
  const needReason = transition?.requiresReason != null;
  const canSubmit = !!transition && (!needReason || reason.trim().length >= 3);

  async function handleConfirm() {
    if (!transition) return;
    setSubmitting(true);
    try {
      await onConfirm(transition.to, needReason ? reason.trim() : undefined);
      onOpenChange(false);
    } finally {
      setSubmitting(false);
    }
  }

  const reasonLabel = {
    block: "Motivo do bloqueio",
    cancel: "Motivo do cancelamento",
    unblock: "Justificativa de desbloqueio",
  } as const;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Alterar status do plano</DialogTitle>
          <DialogDescription>
            Status atual: <strong>{STATUS_LABEL[currentStatus]}</strong>
          </DialogDescription>
        </DialogHeader>

        {allowed.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Este status é final. Nenhuma transição disponível.
          </p>
        ) : (
          <div className="space-y-3">
            <div>
              <Label>Novo status</Label>
              <Select
                value={to}
                onValueChange={(v) => setTo(v as ActionPlanStatus)}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Selecione..." />
                </SelectTrigger>
                <SelectContent>
                  {allowed.map((t) => (
                    <SelectItem key={t.to} value={t.to}>
                      {STATUS_LABEL[t.to]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {needReason && (
              <div>
                <Label>
                  {reasonLabel[
                    transition!.requiresReason as keyof typeof reasonLabel
                  ]}{" "}
                  *
                </Label>
                <Textarea
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  rows={3}
                  placeholder="Mínimo 3 caracteres"
                />
              </div>
            )}
          </div>
        )}

        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={submitting}
          >
            Cancelar
          </Button>
          <Button onClick={handleConfirm} disabled={!canSubmit || submitting}>
            {submitting ? "Aplicando..." : "Confirmar"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
