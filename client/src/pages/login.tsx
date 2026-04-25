import { useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Eye, EyeOff, Loader2, LogIn } from "lucide-react";
import { IS_DEMO, DEMO_EMAIL, DEMO_PASSWORD } from "@/hooks/useDemo";
import { Link, useLocation } from "wouter";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { useTheme } from "@/hooks/useTheme";

const loginSchema = z.object({
  email: z.string().email("Email inválido"),
  password: z.string().min(1, "Senha é obrigatória"),
});

type LoginForm = z.infer<typeof loginSchema>;

export default function Login() {
  const [, setLocation] = useLocation();
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const queryClient = useQueryClient();
  const { resolvedTheme } = useTheme();

  const featuresQuery = useQuery<{ passwordRecoveryAvailable: boolean }>({
    queryKey: ["/api/auth/features"],
    retry: false,
  });

  const form = useForm<LoginForm>({
    resolver: zodResolver(loginSchema),
    defaultValues: IS_DEMO
      ? { email: DEMO_EMAIL, password: DEMO_PASSWORD }
      : { email: "", password: "" },
  });

  const loginMutation = useMutation({
    mutationFn: async (data: LoginForm) => {
      const response = await apiRequest('POST', '/api/auth/login', data);
      return await response.json();
    },
    onSuccess: async (data: any) => {
      if (data?.pendingMfa) {
        sessionStorage.setItem("mfa-email-available", data.emailDeliveryAvailable ? "true" : "false");
        await queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
        setLocation("/mfa-challenge");
        return;
      }
      await queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
      if (data?.user?.mustChangePassword) {
        setLocation("/change-password");
      } else {
        setLocation("/");
      }
    },
    onError: (error: any) => {
      setError(error.message || "Erro ao fazer login");
    },
  });

  const onSubmit = (data: LoginForm) => {
    setError(null);
    loginMutation.mutate(data);
  };

  const base = import.meta.env.BASE_URL;
  const logoSrc = `${base}Logos_white.png`;

  return (
    <div
      className="min-h-screen flex items-center justify-center px-4"
      style={{
        backgroundImage: `url('${base}Logon_bg.png')`,
        backgroundSize: "cover",
        backgroundPosition: "center",
      }}
    >
      {/* Overlay */}
      <div className="absolute inset-0 bg-black/40" />

      <Card className="relative z-10 w-full max-w-md shadow-2xl bg-card backdrop-blur-sm border-border">
        <CardContent className="pt-8 pb-8 px-8">
          {/* Logo */}
          <div className="flex justify-center mb-8">
            <img
              src={logoSrc}
              alt="SamurEye"
              className="h-12 object-contain"
              onError={(e) => {
                // Fallback: hide broken image
                (e.target as HTMLImageElement).style.display = 'none';
              }}
            />
          </div>

          <h1 className="text-xl font-bold text-card-foreground text-center mb-1">
            Bem-vindo de volta
          </h1>
          <p className="text-sm text-muted-foreground text-center mb-6">
            Entre na sua conta para acessar a plataforma
          </p>

          {IS_DEMO && (
            <div className="mb-5 rounded-lg border border-amber-400/40 bg-amber-50 dark:bg-amber-950/30 p-4">
              <p className="text-xs font-semibold text-amber-700 dark:text-amber-400 mb-2 uppercase tracking-wide">
                Acesso de demonstração
              </p>
              <div className="space-y-1 text-sm text-amber-900 dark:text-amber-300 font-mono">
                <div><span className="text-amber-600 dark:text-amber-500">Usuário: </span>{DEMO_EMAIL}</div>
                <div><span className="text-amber-600 dark:text-amber-500">Senha: </span>{DEMO_PASSWORD}</div>
              </div>
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="mt-3 w-full border-amber-400 text-amber-700 hover:bg-amber-100 dark:text-amber-400 dark:hover:bg-amber-900/40 text-xs"
                onClick={() => {
                  form.setValue("email", DEMO_EMAIL);
                  form.setValue("password", DEMO_PASSWORD);
                }}
              >
                <LogIn className="mr-2 h-3 w-3" />
                Usar credenciais de demonstração
              </Button>
            </div>
          )}

          {error && (
            <Alert className="mb-4" variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <FormField
                control={form.control}
                name="email"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Email</FormLabel>
                    <FormControl>
                      <Input
                        {...field}
                        type="email"
                        placeholder="seu@email.com"
                        data-testid="input-email"
                        disabled={loginMutation.isPending}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="password"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Senha</FormLabel>
                    <FormControl>
                      <div className="relative">
                        <Input
                          {...field}
                          type={showPassword ? "text" : "password"}
                          placeholder="Sua senha"
                          data-testid="input-password"
                          disabled={loginMutation.isPending}
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                          onClick={() => setShowPassword(!showPassword)}
                          disabled={loginMutation.isPending}
                          data-testid="button-toggle-password"
                        >
                          {showPassword ? (
                            <EyeOff className="h-4 w-4 text-muted-foreground" />
                          ) : (
                            <Eye className="h-4 w-4 text-muted-foreground" />
                          )}
                        </Button>
                      </div>
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <Button
                type="submit"
                className="w-full mt-2"
                disabled={loginMutation.isPending}
                data-testid="button-submit"
              >
                {loginMutation.isPending && (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                )}
                Entrar
              </Button>

              {featuresQuery.data?.passwordRecoveryAvailable && (
                <p className="text-center text-sm text-muted-foreground">
                  <Link href="/forgot-password" className="text-primary hover:underline" data-testid="link-forgot-password">
                    Esqueci minha senha
                  </Link>
                </p>
              )}
            </form>
          </Form>
        </CardContent>
      </Card>
    </div>
  );
}
