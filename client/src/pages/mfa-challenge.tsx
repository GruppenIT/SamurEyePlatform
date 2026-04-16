import { useEffect, useState } from "react";
import { useLocation } from "wouter";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@/components/ui/input-otp";
import { useToast } from "@/hooks/use-toast";

interface ChallengeState {
  useRecoveryCode: boolean;
  emailDeliveryAvailable: boolean;
}

export default function MfaChallengePage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [, setLocation] = useLocation();
  const [token, setToken] = useState("");
  const [state, setState] = useState<ChallengeState>({ useRecoveryCode: false, emailDeliveryAvailable: false });

  useEffect(() => {
    const cached = sessionStorage.getItem("mfa-email-available");
    setState((s) => ({ ...s, emailDeliveryAvailable: cached === "true" }));
  }, []);

  const verifyMutation = useMutation({
    mutationFn: async () => apiRequest("POST", "/api/auth/mfa/verify", { token }),
    onSuccess: async () => {
      sessionStorage.removeItem("mfa-email-available");
      await queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
      setLocation("/");
    },
    onError: (err: any) => {
      toast({ title: "Código inválido", description: err?.message || "Tente novamente.", variant: "destructive" });
      setToken("");
    },
  });

  const emailMutation = useMutation({
    mutationFn: async () => apiRequest("POST", "/api/auth/mfa/email"),
    onSuccess: () => toast({ title: "Código enviado", description: "Verifique sua caixa de entrada." }),
    onError: (err: any) => toast({ title: "Erro", description: err?.message || "Falha ao enviar.", variant: "destructive" }),
  });

  const logoutMutation = useMutation({
    mutationFn: async () => apiRequest("POST", "/api/auth/logout"),
    onSuccess: () => { window.location.href = "/login"; },
  });

  const sanitized = state.useRecoveryCode
    ? token.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 12)
    : token.replace(/\D/g, "").slice(0, 6);

  return (
    <div className="flex h-screen items-center justify-center bg-background">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Verificação em duas etapas</CardTitle>
          <CardDescription>
            {state.useRecoveryCode
              ? "Digite um dos seus códigos de recuperação."
              : "Digite o código de 6 dígitos do seu app autenticador."}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (sanitized && !verifyMutation.isPending) verifyMutation.mutate();
            }}
            className="space-y-4"
          >
            {state.useRecoveryCode ? (
              <div>
                <Label htmlFor="mfa-token">Código de recuperação</Label>
                <Input
                  id="mfa-token"
                  value={sanitized}
                  onChange={(e) => setToken(e.target.value)}
                  maxLength={12}
                  inputMode="text"
                  autoComplete="one-time-code"
                  className="font-mono"
                  placeholder="abc123def456"
                  data-testid="input-mfa-token"
                  autoFocus
                />
              </div>
            ) : (
              <div className="flex flex-col items-center gap-2">
                <Label htmlFor="mfa-token" className="self-start">Código do app autenticador</Label>
                <InputOTP
                  id="mfa-token"
                  maxLength={6}
                  value={sanitized}
                  onChange={(value) => setToken(value)}
                  onComplete={(value) => {
                    if (!verifyMutation.isPending) {
                      setToken(value);
                      verifyMutation.mutate();
                    }
                  }}
                  autoFocus
                  inputMode="numeric"
                  pattern="^[0-9]*$"
                  data-testid="input-mfa-token"
                >
                  <InputOTPGroup>
                    <InputOTPSlot index={0} className="h-14 w-14 text-2xl" />
                    <InputOTPSlot index={1} className="h-14 w-14 text-2xl" />
                    <InputOTPSlot index={2} className="h-14 w-14 text-2xl" />
                    <InputOTPSlot index={3} className="h-14 w-14 text-2xl" />
                    <InputOTPSlot index={4} className="h-14 w-14 text-2xl" />
                    <InputOTPSlot index={5} className="h-14 w-14 text-2xl" />
                  </InputOTPGroup>
                </InputOTP>
              </div>
            )}
            <Button
              type="submit"
              disabled={!sanitized || verifyMutation.isPending}
              className="w-full"
              data-testid="button-verify-mfa"
            >
              {verifyMutation.isPending ? "Validando..." : "Validar"}
            </Button>
          </form>

          <div className="flex flex-col gap-2 pt-2 text-sm">
            {state.emailDeliveryAvailable && !state.useRecoveryCode && (
              <button
                type="button"
                onClick={() => emailMutation.mutate()}
                disabled={emailMutation.isPending}
                className="text-primary hover:underline text-left"
                data-testid="button-send-email"
              >
                {emailMutation.isPending ? "Enviando..." : "Receber código por e-mail"}
              </button>
            )}
            <button
              type="button"
              onClick={() => { setState((s) => ({ ...s, useRecoveryCode: !s.useRecoveryCode })); setToken(""); }}
              className="text-primary hover:underline text-left"
              data-testid="button-toggle-recovery"
            >
              {state.useRecoveryCode ? "Voltar a usar código do app" : "Usar código de recuperação"}
            </button>
            <button
              type="button"
              onClick={() => logoutMutation.mutate()}
              className="text-muted-foreground hover:text-foreground text-left"
              data-testid="button-logout"
            >
              Sair
            </button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
