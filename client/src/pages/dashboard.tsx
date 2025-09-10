import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import { useWebSocket } from "@/lib/websocket";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import MetricsOverview from "@/components/dashboard/metrics-overview";
import ActiveJobs from "@/components/dashboard/active-jobs";
import RecentThreats from "@/components/dashboard/recent-threats";
import QuickActions from "@/components/dashboard/quick-actions";
import SystemHealth from "@/components/dashboard/system-health";
import UpcomingSchedules from "@/components/dashboard/upcoming-schedules";

export default function Dashboard() {
  const { toast } = useToast();
  const { isAuthenticated, isLoading } = useAuth();
  const { connected, lastMessage } = useWebSocket();

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
          console.log('WebSocket conectado ao SamurEye');
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
          subtitle="Visão geral da postura de segurança organizacional"
          wsConnected={connected}
        />
        
        <div className="p-6 space-y-6">
          {/* Metrics Overview */}
          <MetricsOverview />
          
          {/* Current Jobs and Threats */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <ActiveJobs />
            <RecentThreats />
          </div>
          
          {/* Journey Management and Quick Actions */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <QuickActions />
            <div className="lg:col-span-2">
              <SystemHealth />
            </div>
          </div>
          
          {/* Schedule Overview */}
          <UpcomingSchedules />
        </div>
      </main>
    </div>
  );
}
