import { useState } from "react";
import { useLocation } from "wouter";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { PasswordChecklist, isPasswordStrong } from "@/components/account/password-checklist";
import { Loader2 } from "lucide-react";

function getToken(): string {
  const qs = new URLSearchParams(window.location.search);
  return qs.get("token") ?? "";
}

export default function ResetPassword() {
  const { toast } = useToast();
  const [, setLocation] = useLocation();
  const token = getToken();
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const verifyQuery = useQuery<{ valid: boolean }>({
    queryKey: [`/api/auth/password-reset/verify?token=${encodeURIComponent(token)}`],
    enabled: !!token,
    retry: false,
  });

  const confirmMutation = useMutation({
    mutationFn: async () =>
      apiRequest("POST", "/api/auth/password-reset/confirm", { token, newPassword: password }),
    onSuccess: () => {
      toast({ title: "Senha atualizada", description: "Faça login com a nova senha." });
      setLocation("/login");
    },
    onError: (err: any) => {
      toast({
        title: "Falha ao redefinir",
        description: err?.message || "Verifique o link e a nova senha.",
        variant: "destructive",
      });
    },
  });

  if (!token || verifyQuery.isError || verifyQuery.data?.valid === false) {
    return (
      <div className="flex h-screen items-center justify-center bg-background px-4">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle>Link inválido ou expirado</CardTitle>
            <CardDescription>
              O link de recuperação não é mais válido. Solicite um novo.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button className="w-full" onClick={() => setLocation("/forgot-password")} data-testid="button-request-new-link">
              Solicitar novo link
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (verifyQuery.isLoading) {
    return (
      <div className="flex h-screen items-center justify-center bg-background">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const strongEnough = isPasswordStrong(password);
  const matches = password.length > 0 && password === confirmPassword;

  return (
    <div className="flex h-screen items-center justify-center bg-background px-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Definir nova senha</CardTitle>
          <CardDescription>Escolha uma senha forte que atenda aos requisitos abaixo.</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (!strongEnough || !matches || confirmMutation.isPending) return;
              confirmMutation.mutate();
            }}
            className="space-y-4"
          >
            <div>
              <Label htmlFor="new-password">Nova senha</Label>
              <Input
                id="new-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
                autoFocus
                required
                data-testid="input-new-password"
              />
              <PasswordChecklist password={password} />
            </div>
            <div>
              <Label htmlFor="confirm-password">Confirmar nova senha</Label>
              <Input
                id="confirm-password"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                autoComplete="new-password"
                required
                data-testid="input-confirm-password"
              />
              {confirmPassword.length > 0 && !matches && (
                <p className="mt-1 text-xs text-destructive">As senhas não coincidem.</p>
              )}
            </div>
            <Button
              type="submit"
              className="w-full"
              disabled={!strongEnough || !matches || confirmMutation.isPending}
              data-testid="button-reset-submit"
            >
              {confirmMutation.isPending ? "Atualizando..." : "Redefinir senha"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
