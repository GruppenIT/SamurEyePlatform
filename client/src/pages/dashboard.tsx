import { useEffect, useState, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import { useWebSocket } from "@/lib/websocket";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import { Button } from "@/components/ui/button";
import { Search, Plus } from "lucide-react";
import { Link } from "wouter";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import MetricsOverview from "@/components/dashboard/metrics-overview";
import ActiveJobs from "@/components/dashboard/active-jobs";
import RecentThreats from "@/components/dashboard/recent-threats";
import AttentionRequired from "@/components/dashboard/attention-required";
import SystemHealth from "@/components/dashboard/system-health";
import UpcomingSchedules from "@/components/dashboard/upcoming-schedules";

function useLastUpdated() {
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());

  const refresh = useCallback(() => {
    setLastUpdated(new Date());
  }, []);

  // Update every 10 seconds to keep timestamp fresh
  useEffect(() => {
    const interval = setInterval(() => {
      setLastUpdated(new Date());
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  const formatTime = () => {
    return lastUpdated.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
  };

  return { formatTime, refresh };
}

export default function Dashboard() {
  const { toast } = useToast();
  const { isAuthenticated, isLoading } = useAuth();
  const { connected, lastMessage } = useWebSocket();
  const { formatTime } = useLastUpdated();

  // Redirect to home if not authenticated
  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      toast({
        title: "Não autorizado",
        description: "Você foi desconectado. Fazendo login novamente...",
        variant: "destructive",
      });
      setTimeout(() => {
        window.location.href = "/api/login";
      }, 500);
      return;
    }
  }, [isAuthenticated, isLoading, toast]);

  // Handle WebSocket messages
  useEffect(() => {
    if (lastMessage) {
      switch (lastMessage.type) {
        case 'jobUpdate':
          // Job updates will be handled by individual components
          break;
        case 'threatCreated':
          toast({
            title: "Nova Ameaça Detectada",
            description: `Ameaça ${lastMessage.data?.severity || 'unknown'} foi criada`,
            variant: "destructive",
          });
          break;
        case 'connected':
          break;
      }
    }
  }, [lastMessage, toast]);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <div className="w-16 h-16 border-4 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-muted-foreground">Carregando...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return null; // Will redirect via useEffect
  }

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />

      <main className="flex-1 overflow-auto">
        <TopBar
          title="Dashboard de Segurança"
          subtitle={`Visão geral da postura de segurança \u2022 Atualizado às ${formatTime()}`}
          wsConnected={connected}
        />

        <div className="p-6 space-y-6">
          {/* Quick Actions */}
          <div className="flex justify-end gap-3">
            <Link href="/journeys">
              <Button variant="secondary" data-testid="button-quick-scan">
                <Search className="mr-2 h-4 w-4" />
                Varredura Rápida
              </Button>
            </Link>
            <Link href="/journeys">
              <Button data-testid="button-new-journey">
                <Plus className="mr-2 h-4 w-4" />
                Nova Jornada de Teste
              </Button>
            </Link>
          </div>

          {/* Metrics Overview */}
          <MetricsOverview />

          {/* Attention Required (only renders if there are alerts) */}
          <AttentionRequired />

          {/* Current Jobs and Threats */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <ActiveJobs />
            <RecentThreats />
          </div>

          {/* System Health */}
          <SystemHealth />

          {/* Schedule Overview */}
          <UpcomingSchedules />
        </div>
      </main>
    </div>
  );
}
