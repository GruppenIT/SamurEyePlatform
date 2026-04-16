import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
import { useWebSocket } from "@/lib/websocket";
import { ShieldCheck, ShieldOff } from "lucide-react";

interface SetupData {
  otpauthUrl: string;
  qrCodeSvg: string;
  backupCodes: string[];
}

function CodesPanel({ codes }: { codes: string[] }) {
  const { toast } = useToast();
  const allText = codes.join("\n");
  return (
    <div className="rounded-md border border-border bg-muted/20 p-3">
      <ol className="space-y-1 font-mono text-sm">
        {codes.map((c, i) => <li key={i} data-testid={`backup-code-${i}`}>{c}</li>)}
      </ol>
      <div className="mt-3 flex gap-2">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => {
            navigator.clipboard.writeText(allText);
            toast({ title: "Copiado", description: "Códigos de recuperação copiados." });
          }}
          data-testid="button-copy-codes"
        >
          Copiar
        </Button>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => {
            const blob = new Blob([allText], { type: "text/plain" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = "samureye-mfa-backup-codes.txt";
            a.click();
            URL.revokeObjectURL(url);
          }}
          data-testid="button-download-codes"
        >
          Baixar .txt
        </Button>
      </div>
      <p className="mt-3 text-xs text-muted-foreground">
        Guarde esses códigos em um local seguro. Cada código só pode ser usado uma vez e não será mostrado novamente.
      </p>
    </div>
  );
}

export default function AccountMfaPage() {
  const { toast } = useToast();
  const { user } = useAuth() as any;
  const { connected } = useWebSocket();
  const queryClient = useQueryClient();

  const [setup, setSetup] = useState<SetupData | null>(null);
  const [token, setToken] = useState("");
  const [disablePassword, setDisablePassword] = useState("");
  const [disableToken, setDisableToken] = useState("");
  const [regenPassword, setRegenPassword] = useState("");
  const [newCodes, setNewCodes] = useState<string[] | null>(null);

  const mfaEnabled = user?.mfaEnabled === true;

  const setupMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/auth/mfa/setup");
      return (await res.json()) as SetupData;
    },
    onSuccess: (data) => setSetup(data),
  });

  const enableMutation = useMutation({
    mutationFn: async () => apiRequest("POST", "/api/auth/mfa/enable", { token }),
    onSuccess: () => {
      toast({ title: "MFA ativado", description: "Próximos logins pedirão o código TOTP." });
      setSetup(null);
      setToken("");
      queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
    },
    onError: (err: any) => toast({ title: "Erro", description: err?.message || "Falha ao ativar", variant: "destructive" }),
  });

  const disableMutation = useMutation({
    mutationFn: async () => apiRequest("POST", "/api/auth/mfa/disable", { currentPassword: disablePassword, token: disableToken }),
    onSuccess: () => {
      toast({ title: "MFA desativado" });
      setDisablePassword("");
      setDisableToken("");
      queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
    },
    onError: (err: any) => toast({ title: "Erro", description: err?.message || "Falha ao desativar", variant: "destructive" }),
  });

  const regenMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/auth/mfa/recovery-codes/regenerate", { currentPassword: regenPassword });
      return (await res.json()) as { backupCodes: string[] };
    },
    onSuccess: (data) => {
      setNewCodes(data.backupCodes);
      setRegenPassword("");
      toast({ title: "Códigos regenerados" });
    },
    onError: (err: any) => toast({ title: "Erro", description: err?.message || "Falha ao regenerar", variant: "destructive" }),
  });

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <main className="flex-1 overflow-auto">
        <TopBar title="Gerenciar MFA" subtitle="Autenticação em dois fatores" wsConnected={connected} />
        <div className="p-6 space-y-6 max-w-3xl">

          {!mfaEnabled && !setup && (
            <Card>
              <CardHeader><CardTitle className="flex items-center gap-2"><ShieldCheck className="h-5 w-5" /> MFA desativado</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-muted-foreground">
                  Adicione uma camada extra de segurança. Você precisará de um aplicativo autenticador (Google Authenticator, Authy, 1Password, etc.).
                </p>
                <Button onClick={() => setupMutation.mutate()} disabled={setupMutation.isPending} data-testid="button-start-mfa-setup">
                  {setupMutation.isPending ? "Preparando..." : "Configurar MFA"}
                </Button>
              </CardContent>
            </Card>
          )}

          {!mfaEnabled && setup && (
            <Card>
              <CardHeader><CardTitle>Configure seu app autenticador</CardTitle></CardHeader>
              <CardContent className="space-y-6">
                <div className="grid gap-6 md:grid-cols-2">
                  <div>
                    <Label className="text-sm">1. Escaneie o QR code</Label>
                    <div
                      className="mt-2 inline-block rounded-md border border-border bg-white p-3"
                      dangerouslySetInnerHTML={{ __html: setup.qrCodeSvg }}
                    />
                    <p className="mt-2 text-xs text-muted-foreground break-all">
                      Ou copie manualmente: <code className="font-mono">{setup.otpauthUrl}</code>
                    </p>
                  </div>
                  <div>
                    <Label className="text-sm">2. Guarde os códigos de recuperação</Label>
                    <div className="mt-2">
                      <CodesPanel codes={setup.backupCodes} />
                    </div>
                  </div>
                </div>
                <Separator />
                <div>
                  <Label htmlFor="confirm-token">3. Digite o código de 6 dígitos gerado pelo app</Label>
                  <div className="flex gap-2 mt-2">
                    <Input
                      id="confirm-token"
                      value={token}
                      onChange={(e) => setToken(e.target.value.replace(/\D/g, "").slice(0, 6))}
                      maxLength={6}
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      placeholder="000000"
                      data-testid="input-confirm-token"
                    />
                    <Button
                      onClick={() => enableMutation.mutate()}
                      disabled={token.length !== 6 || enableMutation.isPending}
                      data-testid="button-enable-mfa"
                    >
                      {enableMutation.isPending ? "Ativando..." : "Ativar"}
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {mfaEnabled && (
            <>
              <Card>
                <CardHeader><CardTitle className="flex items-center gap-2"><ShieldCheck className="h-5 w-5 text-green-500" /> MFA ativado</CardTitle></CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <p>Próximos logins exigirão o código TOTP gerado pelo seu aplicativo autenticador.</p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader><CardTitle>Regenerar códigos de recuperação</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  {newCodes ? (
                    <CodesPanel codes={newCodes} />
                  ) : (
                    <>
                      <Label htmlFor="regen-password">Confirme sua senha atual</Label>
                      <Input id="regen-password" type="password" value={regenPassword} onChange={(e) => setRegenPassword(e.target.value)} data-testid="input-regen-password" />
                      <Button onClick={() => regenMutation.mutate()} disabled={!regenPassword || regenMutation.isPending} data-testid="button-regenerate-codes">
                        {regenMutation.isPending ? "Regenerando..." : "Gerar novos códigos"}
                      </Button>
                    </>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader><CardTitle className="flex items-center gap-2"><ShieldOff className="h-5 w-5" /> Desativar MFA</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  <Label htmlFor="disable-password">Senha atual</Label>
                  <Input id="disable-password" type="password" value={disablePassword} onChange={(e) => setDisablePassword(e.target.value)} data-testid="input-disable-password" />
                  <Label htmlFor="disable-token">Código TOTP atual</Label>
                  <Input
                    id="disable-token"
                    value={disableToken}
                    onChange={(e) => setDisableToken(e.target.value.replace(/\D/g, "").slice(0, 6))}
                    maxLength={6}
                    inputMode="numeric"
                    placeholder="000000"
                    data-testid="input-disable-token"
                  />
                  <Button variant="destructive" onClick={() => disableMutation.mutate()} disabled={!disablePassword || disableToken.length !== 6 || disableMutation.isPending} data-testid="button-disable-mfa">
                    {disableMutation.isPending ? "Desativando..." : "Desativar MFA"}
                  </Button>
                </CardContent>
              </Card>
            </>
          )}
        </div>
      </main>
    </div>
  );
}
