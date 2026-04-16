import { useEffect, useState } from "react";
import { useLocation } from "wouter";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useAuth } from "@/hooks/useAuth";

export function MfaInvitationDialog() {
  const { user, isLoading } = useAuth() as any;
  const [, setLocation] = useLocation();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [doNotRemind, setDoNotRemind] = useState(false);

  useEffect(() => {
    if (isLoading) return;
    if (!user) return;
    if (user.pendingMfa) return;
    if (user.mfaEnabled) return;
    if (user.mfaInvitationDismissed) return;
    setOpen(true);
  }, [user, isLoading]);

  const dismissMutation = useMutation({
    mutationFn: async () => apiRequest("PUT", "/api/auth/me/mfa-invitation-dismissed"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
    },
  });

  const handleLater = async () => {
    if (doNotRemind) await dismissMutation.mutateAsync();
    setOpen(false);
  };

  const handleConfigure = async () => {
    if (doNotRemind) await dismissMutation.mutateAsync();
    setOpen(false);
    setLocation("/account/mfa");
  };

  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogContent data-testid="dialog-mfa-invitation">
        <AlertDialogHeader>
          <AlertDialogTitle>Proteja sua conta com MFA</AlertDialogTitle>
          <AlertDialogDescription>
            A autenticação de dois fatores adiciona uma camada extra de segurança à sua conta.
            Basta instalar um app autenticador (Google Authenticator, Authy, 1Password) e escanear um QR code.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <div className="flex items-center gap-2">
          <Checkbox
            id="do-not-remind"
            checked={doNotRemind}
            onCheckedChange={(v) => setDoNotRemind(v === true)}
            data-testid="checkbox-do-not-remind"
          />
          <Label htmlFor="do-not-remind" className="text-sm">
            Não lembrar novamente
          </Label>
        </div>
        <AlertDialogFooter>
          <AlertDialogCancel onClick={handleLater} data-testid="button-mfa-later">Deixar pra depois</AlertDialogCancel>
          <AlertDialogAction onClick={handleConfigure} data-testid="button-mfa-configure">Configurar agora</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
