import { Link } from "wouter";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import { Card, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { KeyRound, ShieldCheck } from "lucide-react";
import { useWebSocket } from "@/lib/websocket";

export default function AccountPage() {
  const { connected } = useWebSocket();
  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <main className="flex-1 overflow-auto">
        <TopBar title="Minha Conta" subtitle="Gerencie sua conta e segurança" wsConnected={connected} />
        <div className="p-6 space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <Link href="/change-password">
              <Card className="cursor-pointer transition-colors hover:border-primary/50" data-testid="card-change-password">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <KeyRound className="h-5 w-5" />
                    Trocar senha
                  </CardTitle>
                  <CardDescription>Atualize a senha da sua conta.</CardDescription>
                </CardHeader>
              </Card>
            </Link>
            <Link href="/account/mfa">
              <Card className="cursor-pointer transition-colors hover:border-primary/50" data-testid="card-mfa">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <ShieldCheck className="h-5 w-5" />
                    MFA (autenticação em dois fatores)
                  </CardTitle>
                  <CardDescription>Configure ou gerencie seu segundo fator de autenticação.</CardDescription>
                </CardHeader>
              </Card>
            </Link>
          </div>
        </div>
      </main>
    </div>
  );
}
