import { useEffect } from "react";
import { useWebSocket } from "@/lib/websocket";
import { queryClient } from "@/lib/queryClient";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import PostureHero from "@/components/dashboard/posture-hero";
import TopActions from "@/components/dashboard/top-actions";
import JourneyCoverage from "@/components/dashboard/journey-coverage";
import JourneyComparison from "@/components/dashboard/journey-comparison";

export default function Postura() {
  const { connected, lastMessage } = useWebSocket();

  useEffect(() => {
    if (
      lastMessage?.type === "jobUpdate" &&
      ["completed", "failed", "timeout"].includes(lastMessage.data?.status)
    ) {
      queryClient.invalidateQueries({ queryKey: ["/api/posture/history"] });
      queryClient.invalidateQueries({ queryKey: ["/api/posture/coverage"] });
      queryClient.invalidateQueries({ queryKey: ["/api/recommendations/top"] });
      queryClient.invalidateQueries({ queryKey: ["/api/threats"] });
    }
  }, [lastMessage]);

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <main className="flex-1 overflow-hidden">
        <TopBar
          title="Postura de Seguranca"
          subtitle="Visao consolidada da exposicao e riscos"
          wsConnected={connected}
        />
        <div className="p-6 space-y-6 overflow-auto h-[calc(100%-4rem)]">
          {/* Posture Hero — score, delta, sparkline */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-base">Pontuacao de Postura</CardTitle>
              <CardDescription>
                Baseado em snapshots de postura das jornadas executadas
              </CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <PostureHero />
            </CardContent>
          </Card>

          {/* Top 3 Priority Actions */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-base">Acoes Prioritarias</CardTitle>
              <CardDescription>
                As 3 acoes com maior impacto na postura
              </CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <TopActions />
            </CardContent>
          </Card>

          {/* Journey Coverage Grid */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-base">Cobertura de Jornadas</CardTitle>
              <CardDescription>
                Status das ultimas execucoes por tipo de jornada
              </CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <JourneyCoverage />
            </CardContent>
          </Card>

          {/* Journey Comparison — delta between current and previous run */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-base">Comparacao entre Execucoes</CardTitle>
              <CardDescription>
                Delta entre a execucao atual e a anterior
              </CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <JourneyComparison />
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
}
