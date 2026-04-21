import { useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Eye, EyeOff, Loader2 } from "lucide-react";
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
    defaultValues: { email: "", password: "" },
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

  const logoSrc = resolvedTheme === 'dark' ? '/Logos_white.png' : '/logo.png';

  return (
    <div
      className="min-h-screen flex items-center justify-center px-4"
      style={{
        backgroundImage: "url('/Logon_bg.png')",
        backgroundSize: "cover",
        backgroundPosition: "center",
      }}
    >
      {/* Overlay */}
      <div className="absolute inset-0 bg-black/40" />

      <Card className="relative z-10 w-full max-w-md shadow-2xl bg-card/95 backdrop-blur-sm border-border">
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

          <h1 className="text-xl font-semibold text-foreground text-center mb-1">
            Bem-vindo de volta
          </h1>
          <p className="text-sm text-muted-foreground text-center mb-6">
            Entre na sua conta para acessar a plataforma
          </p>

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
