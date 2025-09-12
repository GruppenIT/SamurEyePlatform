import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Shield, Eye, EyeOff, Loader2, CheckCircle2 } from "lucide-react";
import { useLocation } from "wouter";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { changePasswordSchema, type ChangePassword } from "@shared/schema";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage, FormDescription } from "@/components/ui/form";

export default function ChangePasswordPage() {
  const [, setLocation] = useLocation();
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const queryClient = useQueryClient();

  const form = useForm<ChangePassword>({
    resolver: zodResolver(changePasswordSchema),
    defaultValues: {
      currentPassword: "",
      newPassword: "",
      confirmPassword: "",
    },
  });

  const changePasswordMutation = useMutation({
    mutationFn: async (data: ChangePassword) => {
      const response = await apiRequest('POST', '/api/auth/change-password', data);
      return response;
    },
    onSuccess: (data) => {
      // Invalida cache de usuário com novos dados
      queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
      
      // Redireciona para dashboard
      setLocation("/");
    },
    onError: (error: any) => {
      // O erro será exibido pelo formulário
      console.error("Erro ao alterar senha:", error);
    },
  });

  const onSubmit = (data: ChangePassword) => {
    changePasswordMutation.mutate(data);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background px-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <div className="w-16 h-16 bg-amber-100 dark:bg-amber-900 rounded-2xl flex items-center justify-center">
              <Shield className="w-8 h-8 text-amber-600 dark:text-amber-400" />
            </div>
          </div>
          <CardTitle className="text-2xl font-bold text-amber-700 dark:text-amber-400">
            Troca de Senha Obrigatória
          </CardTitle>
          <CardDescription className="text-center">
            Para sua segurança, você deve alterar a senha padrão antes de continuar
          </CardDescription>
        </CardHeader>

        <CardContent>
          {changePasswordMutation.error && (
            <Alert variant="destructive" className="mb-4">
              <AlertDescription data-testid="error-message">
                {(changePasswordMutation.error as any)?.message || "Erro ao alterar senha"}
              </AlertDescription>
            </Alert>
          )}

          {changePasswordMutation.isSuccess && (
            <Alert className="mb-4 border-green-200 bg-green-50 dark:bg-green-900/20">
              <CheckCircle2 className="h-4 w-4 text-green-600 dark:text-green-400" />
              <AlertDescription className="text-green-700 dark:text-green-400" data-testid="success-message">
                Senha alterada com sucesso! Redirecionando...
              </AlertDescription>
            </Alert>
          )}

          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <FormField
                control={form.control}
                name="currentPassword"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Senha Atual</FormLabel>
                    <FormControl>
                      <div className="relative">
                        <Input
                          type={showCurrentPassword ? "text" : "password"}
                          placeholder="Digite sua senha atual"
                          data-testid="input-current-password"
                          {...field}
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                          data-testid="button-toggle-current-password"
                          onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                        >
                          {showCurrentPassword ? (
                            <EyeOff className="h-4 w-4" />
                          ) : (
                            <Eye className="h-4 w-4" />
                          )}
                        </Button>
                      </div>
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="newPassword"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Nova Senha</FormLabel>
                    <FormControl>
                      <div className="relative">
                        <Input
                          type={showNewPassword ? "text" : "password"}
                          placeholder="Digite sua nova senha"
                          data-testid="input-new-password"
                          {...field}
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                          data-testid="button-toggle-new-password"
                          onClick={() => setShowNewPassword(!showNewPassword)}
                        >
                          {showNewPassword ? (
                            <EyeOff className="h-4 w-4" />
                          ) : (
                            <Eye className="h-4 w-4" />
                          )}
                        </Button>
                      </div>
                    </FormControl>
                    <FormDescription className="text-xs text-muted-foreground">
                      Mínimo 12 caracteres, incluindo: maiúscula, minúscula, número e símbolo
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="confirmPassword"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Confirmar Nova Senha</FormLabel>
                    <FormControl>
                      <div className="relative">
                        <Input
                          type={showConfirmPassword ? "text" : "password"}
                          placeholder="Confirme sua nova senha"
                          data-testid="input-confirm-password"
                          {...field}
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                          data-testid="button-toggle-confirm-password"
                          onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                        >
                          {showConfirmPassword ? (
                            <EyeOff className="h-4 w-4" />
                          ) : (
                            <Eye className="h-4 w-4" />
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
                className="w-full"
                disabled={changePasswordMutation.isPending}
                data-testid="button-submit"
              >
                {changePasswordMutation.isPending ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Alterando senha...
                  </>
                ) : (
                  "Alterar Senha"
                )}
              </Button>
            </form>
          </Form>

          <div className="mt-6 text-center text-xs text-muted-foreground">
            <p>Esta é uma medida de segurança obrigatória.</p>
            <p>Você só precisará fazer isso uma única vez.</p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}