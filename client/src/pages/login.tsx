import { useState, useEffect } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Eye, EyeOff, Loader2, LogIn, Copy, Check } from "lucide-react";
import { IS_DEMO } from "@/hooks/useDemo";
import { Link, useLocation } from "wouter";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { useTheme } from "@/hooks/useTheme";

// ── CNPJ helpers ──────────────────────────────────────────────────────────────

function maskCnpj(value: string): string {
  const d = value.replace(/\D/g, '').slice(0, 14);
  if (d.length <= 2) return d;
  if (d.length <= 5) return `${d.slice(0, 2)}.${d.slice(2)}`;
  if (d.length <= 8) return `${d.slice(0, 2)}.${d.slice(2, 5)}.${d.slice(5)}`;
  if (d.length <= 12) return `${d.slice(0, 2)}.${d.slice(2, 5)}.${d.slice(5, 8)}/${d.slice(8)}`;
  return `${d.slice(0, 2)}.${d.slice(2, 5)}.${d.slice(5, 8)}/${d.slice(8, 12)}-${d.slice(12)}`;
}

function validateCnpj(cnpj: string): boolean {
  const d = cnpj.replace(/\D/g, '');
  if (d.length !== 14 || /^(\d)\1+$/.test(d)) return false;
  const w1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
  const w2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
  const calc = (digits: string, weights: number[]) => {
    const sum = weights.reduce((acc, w, i) => acc + parseInt(digits[i]) * w, 0);
    const rem = sum % 11;
    return rem < 2 ? 0 : 11 - rem;
  };
  return calc(d, w1) === parseInt(d[12]) && calc(d, w2) === parseInt(d[13]);
}

// ── Schemas ───────────────────────────────────────────────────────────────────

const loginSchema = z.object({
  email: z.string().email("Email inválido"),
  password: z.string().min(1, "Senha é obrigatória"),
});

const registerSchema = z.object({
  name: z.string().min(2, "Nome deve ter ao menos 2 caracteres"),
  company: z.string().min(2, "Empresa deve ter ao menos 2 caracteres"),
  cnpj: z.string().refine(validateCnpj, "CNPJ inválido"),
  email: z.string().email("Email inválido"),
});

type LoginForm = z.infer<typeof loginSchema>;
type RegisterForm = z.infer<typeof registerSchema>;

// ── Component ─────────────────────────────────────────────────────────────────

const REGISTER_DRAFT_KEY = "demo.register.draft";

function readDraft(): Partial<RegisterForm> {
  try { return JSON.parse(sessionStorage.getItem(REGISTER_DRAFT_KEY) ?? "{}"); } catch { return {}; }
}

type DemoView = 'register' | 'credentials' | 'login';

interface GeneratedCredentials {
  email: string;
  password: string;
  expiresAt: string;
}

export default function Login() {
  const [, setLocation] = useLocation();
  const [showPassword, setShowPassword] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [demoView, setDemoView] = useState<DemoView>('register');
  const [credentials, setCredentials] = useState<GeneratedCredentials | null>(null);
  const [copied, setCopied] = useState(false);
  const queryClient = useQueryClient();
  const { resolvedTheme } = useTheme();

  const featuresQuery = useQuery<{ passwordRecoveryAvailable: boolean }>({
    queryKey: ["/api/auth/features"],
    retry: false,
  });

  // Login form
  const loginForm = useForm<LoginForm>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: "", password: "" },
  });

  // Register form — restores draft from sessionStorage on mount
  const _draft = readDraft();
  const registerForm = useForm<RegisterForm>({
    resolver: zodResolver(registerSchema),
    defaultValues: { name: _draft.name ?? "", company: _draft.company ?? "", cnpj: _draft.cnpj ?? "", email: _draft.email ?? "" },
  });

  // Persist draft while user fills the form
  const watchedRegister = registerForm.watch();
  useEffect(() => {
    try { sessionStorage.setItem(REGISTER_DRAFT_KEY, JSON.stringify(watchedRegister)); } catch {}
  }, [watchedRegister]);

  // Login mutation
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
      setLoginError(error.message || "Erro ao fazer login");
    },
  });

  // Register mutation
  const registerMutation = useMutation({
    mutationFn: async (data: RegisterForm) => {
      const response = await apiRequest('POST', '/api/demo/register', data);
      if (!response.ok) {
        const body = await response.json();
        throw new Error(body.message || 'Erro ao solicitar acesso');
      }
      return await response.json() as GeneratedCredentials;
    },
    onSuccess: (data) => {
      try { sessionStorage.removeItem(REGISTER_DRAFT_KEY); } catch {}
      setCredentials(data);
      setDemoView('credentials');
    },
  });

  const onLoginSubmit = (data: LoginForm) => {
    setLoginError(null);
    loginMutation.mutate(data);
  };

  const onRegisterSubmit = (data: RegisterForm) => {
    registerMutation.mutate(data);
  };

  const handleUseCredentials = () => {
    if (credentials) {
      loginForm.setValue("email", credentials.email);
      loginForm.setValue("password", credentials.password);
      setDemoView('login');
    }
  };

  const handleCopy = async () => {
    if (!credentials) return;
    await navigator.clipboard.writeText(`Email: ${credentials.email}\nSenha: ${credentials.password}`);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
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
      <div className="absolute inset-0 bg-black/40" />

      <Card className="relative z-10 w-full max-w-md shadow-2xl bg-card backdrop-blur-sm border-border">
        <CardContent className="pt-8 pb-8 px-8">
          {/* Logo */}
          <div className="flex justify-center mb-8">
            <img
              src={logoSrc}
              alt="SamurEye"
              className="h-12 object-contain"
              onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }}
            />
          </div>

          {/* ── DEMO MODE ─────────────────────────────────────────────── */}
          {IS_DEMO && (
            <>
              {/* Register view */}
              {demoView === 'register' && (
                <>
                  <h1 className="text-xl font-bold text-card-foreground text-center mb-1">
                    Acesso ao ambiente de demonstração
                  </h1>
                  <p className="text-sm text-muted-foreground text-center mb-6">
                    Preencha seus dados para receber credenciais de acesso válidas por{' '}
                    <span className="font-semibold text-amber-600 dark:text-amber-400">24 horas</span>.
                  </p>

                  {registerMutation.isError && (
                    <Alert className="mb-4" variant="destructive">
                      <AlertDescription>{(registerMutation.error as Error).message}</AlertDescription>
                    </Alert>
                  )}

                  <Form {...registerForm}>
                    <form onSubmit={registerForm.handleSubmit(onRegisterSubmit)} className="space-y-4">
                      <FormField
                        control={registerForm.control}
                        name="name"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Nome completo</FormLabel>
                            <FormControl>
                              <Input {...field} placeholder="João da Silva" disabled={registerMutation.isPending} />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      <FormField
                        control={registerForm.control}
                        name="company"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Empresa</FormLabel>
                            <FormControl>
                              <Input {...field} placeholder="Acme Tecnologia Ltda" disabled={registerMutation.isPending} />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      <FormField
                        control={registerForm.control}
                        name="cnpj"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>CNPJ</FormLabel>
                            <FormControl>
                              <Input
                                {...field}
                                placeholder="00.000.000/0001-00"
                                inputMode="numeric"
                                disabled={registerMutation.isPending}
                                onChange={(e) => {
                                  field.onChange(maskCnpj(e.target.value));
                                }}
                              />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      <FormField
                        control={registerForm.control}
                        name="email"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Email corporativo</FormLabel>
                            <FormControl>
                              <Input {...field} type="email" placeholder="joao@empresa.com.br" disabled={registerMutation.isPending} />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />

                      <Button type="submit" className="w-full mt-2" disabled={registerMutation.isPending}>
                        {registerMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                        Solicitar acesso de demonstração
                      </Button>
                    </form>
                  </Form>

                  <p className="mt-5 text-center text-sm text-muted-foreground">
                    Já possui credenciais?{' '}
                    <button
                      type="button"
                      className="text-primary hover:underline"
                      onClick={() => setDemoView('login')}
                    >
                      Entrar
                    </button>
                  </p>
                </>
              )}

              {/* Credentials view */}
              {demoView === 'credentials' && credentials && (
                <>
                  <h1 className="text-xl font-bold text-card-foreground text-center mb-1">
                    Acesso criado com sucesso!
                  </h1>
                  <p className="text-sm text-muted-foreground text-center mb-6">
                    Guarde suas credenciais. O acesso expira em 24 horas.
                  </p>

                  <div className="rounded-lg border border-green-400/40 bg-green-50 dark:bg-green-950/30 p-4 mb-4">
                    <div className="space-y-2 text-sm font-mono">
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">Email:</span>
                        <span className="font-semibold text-foreground">{credentials.email}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">Senha:</span>
                        <span className="font-semibold text-foreground tracking-widest">{credentials.password}</span>
                      </div>
                    </div>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="mt-3 w-full border-green-400 text-green-700 hover:bg-green-100 dark:text-green-400 dark:hover:bg-green-900/40 text-xs"
                      onClick={handleCopy}
                    >
                      {copied ? <Check className="mr-2 h-3 w-3" /> : <Copy className="mr-2 h-3 w-3" />}
                      {copied ? 'Copiado!' : 'Copiar credenciais'}
                    </Button>
                  </div>

                  <Button type="button" className="w-full" onClick={handleUseCredentials}>
                    <LogIn className="mr-2 h-4 w-4" />
                    Entrar agora
                  </Button>
                </>
              )}

              {/* Login view (demo mode) */}
              {demoView === 'login' && (
                <>
                  <h1 className="text-xl font-bold text-card-foreground text-center mb-1">
                    Entrar na demonstração
                  </h1>
                  <p className="text-sm text-muted-foreground text-center mb-6">
                    Use as credenciais recebidas no cadastro.
                  </p>

                  {loginError && (
                    <Alert className="mb-4" variant="destructive">
                      <AlertDescription>{loginError}</AlertDescription>
                    </Alert>
                  )}

                  <Form {...loginForm}>
                    <form onSubmit={loginForm.handleSubmit(onLoginSubmit)} className="space-y-4">
                      <FormField
                        control={loginForm.control}
                        name="email"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Email</FormLabel>
                            <FormControl>
                              <Input {...field} type="email" placeholder="seu@email.com" disabled={loginMutation.isPending} />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      <FormField
                        control={loginForm.control}
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
                                  disabled={loginMutation.isPending}
                                />
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="sm"
                                  className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                                  onClick={() => setShowPassword(!showPassword)}
                                  disabled={loginMutation.isPending}
                                >
                                  {showPassword
                                    ? <EyeOff className="h-4 w-4 text-muted-foreground" />
                                    : <Eye className="h-4 w-4 text-muted-foreground" />}
                                </Button>
                              </div>
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      <Button type="submit" className="w-full mt-2" disabled={loginMutation.isPending}>
                        {loginMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                        Entrar
                      </Button>
                    </form>
                  </Form>

                  <p className="mt-5 text-center text-sm text-muted-foreground">
                    Ainda não tem acesso?{' '}
                    <button
                      type="button"
                      className="text-primary hover:underline"
                      onClick={() => setDemoView('register')}
                    >
                      Solicitar agora
                    </button>
                  </p>
                </>
              )}
            </>
          )}

          {/* ── NORMAL MODE ───────────────────────────────────────────── */}
          {!IS_DEMO && (
            <>
              <h1 className="text-xl font-bold text-card-foreground text-center mb-1">
                Bem-vindo de volta
              </h1>
              <p className="text-sm text-muted-foreground text-center mb-6">
                Entre na sua conta para acessar a plataforma
              </p>

              {loginError && (
                <Alert className="mb-4" variant="destructive">
                  <AlertDescription>{loginError}</AlertDescription>
                </Alert>
              )}

              <Form {...loginForm}>
                <form onSubmit={loginForm.handleSubmit(onLoginSubmit)} className="space-y-4">
                  <FormField
                    control={loginForm.control}
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
                    control={loginForm.control}
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
                              {showPassword
                                ? <EyeOff className="h-4 w-4 text-muted-foreground" />
                                : <Eye className="h-4 w-4 text-muted-foreground" />}
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
                    {loginMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
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
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
