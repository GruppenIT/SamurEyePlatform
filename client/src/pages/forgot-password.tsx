import { useState } from "react";
import { Link } from "wouter";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [submitted, setSubmitted] = useState(false);

  const requestMutation = useMutation({
    mutationFn: async () => apiRequest("POST", "/api/auth/password-reset/request", { email }),
    onSettled: () => setSubmitted(true),
  });

  return (
    <div className="flex h-screen items-center justify-center bg-background px-4">
      <Card className="w-full max-w-md">
        {!submitted ? (
          <>
            <CardHeader>
              <CardTitle>Recuperar senha</CardTitle>
              <CardDescription>
                Informe o e-mail da sua conta. Enviaremos um link para redefinir a senha.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form
                onSubmit={(e) => { e.preventDefault(); requestMutation.mutate(); }}
                className="space-y-4"
              >
                <div>
                  <Label htmlFor="email">E-mail</Label>
                  <Input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    autoComplete="email"
                    autoFocus
                    required
                    data-testid="input-forgot-email"
                  />
                </div>
                <Button
                  type="submit"
                  className="w-full"
                  disabled={!email.includes("@") || requestMutation.isPending}
                  data-testid="button-forgot-submit"
                >
                  {requestMutation.isPending ? "Enviando..." : "Enviar link"}
                </Button>
                <div className="text-center text-sm">
                  <Link href="/login" className="text-primary hover:underline" data-testid="link-back-to-login">
                    Voltar ao login
                  </Link>
                </div>
              </form>
            </CardContent>
          </>
        ) : (
          <>
            <CardHeader>
              <CardTitle>Verifique sua caixa de entrada</CardTitle>
              <CardDescription>
                Se o e-mail existir em nossa base, você receberá um link para redefinir sua senha em alguns instantes. O link expira em 30 minutos.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Link href="/login">
                <Button variant="outline" className="w-full" data-testid="button-back-to-login-after">
                  Voltar ao login
                </Button>
              </Link>
            </CardContent>
          </>
        )}
      </Card>
    </div>
  );
}
