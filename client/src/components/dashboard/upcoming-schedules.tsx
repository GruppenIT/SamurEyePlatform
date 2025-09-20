import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Clock, Server, Users, Percent } from "lucide-react";
import { Link } from "wouter";
import { Schedule } from "@shared/schema";

export default function UpcomingSchedules() {
  const { data: schedules = [], isLoading } = useQuery<Schedule[]>({
    queryKey: ["/api/schedules"],
  });

  const getScheduleIcon = (kind: string) => {
    switch (kind) {
      case 'recurring':
        return Clock;
      case 'once':
        return Clock;
      default:
        return Clock;
    }
  };

  const formatNextRun = (schedule: Schedule) => {
    if (schedule.kind === 'once' && schedule.onceAt) {
      const date = new Date(schedule.onceAt);
      const now = new Date();
      const diffDays = Math.ceil((date.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
      
      if (diffDays === 0) {
        return `Hoje, ${date.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })}`;
      } else if (diffDays === 1) {
        return `Amanhã, ${date.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })}`;
      } else {
        return `Em ${diffDays} dias, ${date.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })}`;
      }
    }
    
    if (schedule.kind === 'recurring' && schedule.cronExpression) {
      // For demo purposes, show simplified schedule info
      return "Próxima execução programada";
    }
    
    return "Agendamento pendente";
  };

  const getScheduleTypeInfo = (schedule: Schedule) => {
    // This would normally come from the journey data
    return {
      type: "Jornada Personalizada",
      assets: "Múltiplos alvos",
    };
  };

  if (isLoading) {
    return (
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle>Próximas Execuções</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="animate-pulse">
                <div className="h-24 bg-muted rounded-lg"></div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  const activeSchedules = schedules.filter(s => s.enabled);

  return (
    <Card className="bg-card border-border">
      <CardHeader className="border-b border-border">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="text-lg font-semibold text-foreground">
              Próximas Execuções
            </CardTitle>
            <p className="text-sm text-muted-foreground mt-1">
              Agendamentos programados
            </p>
          </div>
          <Link href="/schedules">
            <a className="text-primary hover:text-primary/80 text-sm font-medium" data-testid="link-manage-schedules">
              Gerenciar agendamentos
            </a>
          </Link>
        </div>
      </CardHeader>
      <CardContent className="p-6">
        {activeSchedules.length === 0 ? (
          <div className="text-center py-8">
            <p className="text-muted-foreground">Nenhum agendamento ativo encontrado</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {activeSchedules.slice(0, 6).map((schedule) => {
              const scheduleInfo = getScheduleTypeInfo(schedule);
              
              return (
                <div 
                  key={schedule.id} 
                  className="p-4 bg-muted/30 rounded-lg border border-border"
                  data-testid={`schedule-${schedule.id}`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <h4 className="font-medium text-foreground">
                        {schedule.name}
                      </h4>
                      <p className="text-sm text-muted-foreground mt-1">
                        {scheduleInfo.type} • {schedule.kind === 'recurring' ? 'Recorrente' : 'Único'}
                      </p>
                      <div className="mt-3 flex items-center space-x-2">
                        <Clock className="h-4 w-4 text-muted-foreground" />
                        <span className="text-sm text-muted-foreground">
                          {formatNextRun(schedule)}
                        </span>
                      </div>
                      <div className="mt-1 flex items-center space-x-2">
                        <Server className="h-4 w-4 text-muted-foreground" />
                        <span className="text-sm text-muted-foreground">
                          {scheduleInfo.assets}
                        </span>
                      </div>
                    </div>
                    <div className="ml-4">
                      <Badge 
                        variant={schedule.enabled ? "default" : "secondary"}
                        className={schedule.enabled ? "bg-primary/20 text-primary" : ""}
                      >
                        {schedule.enabled ? 'Ativo' : 'Pausado'}
                      </Badge>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
