import { Button } from "@/components/ui/button";
import { Search, Plus, Shield } from "lucide-react";

interface TopBarProps {
  title: string;
  subtitle: string;
  wsConnected?: boolean;
  actions?: React.ReactNode;
}

export default function TopBar({ title, subtitle, wsConnected = false, actions }: TopBarProps) {
  return (
    <header className="bg-card border-b border-border p-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-foreground" data-testid="topbar-title">
            {title}
          </h2>
          <p className="text-muted-foreground" data-testid="topbar-subtitle">
            {subtitle}
          </p>
        </div>
        <div className="flex items-center space-x-4">
          {/* Real-time status indicator */}
          <div className="flex items-center space-x-2">
            <span 
              className={`status-indicator ${wsConnected ? 'status-success pulse-animation' : 'status-error'}`}
              data-testid="ws-status-indicator"
            ></span>
            <span className="text-sm text-muted-foreground">
              {wsConnected ? 'Sistema Online' : 'Desconectado'}
            </span>
          </div>
          
          {/* Default actions or custom actions */}
          {actions || (
            <>
              <Button 
                className="bg-primary text-primary-foreground hover:bg-primary/90 transition-colors" 
                data-testid="button-quick-scan"
              >
                <Search className="mr-2 h-4 w-4" />
                Varredura Rápida
              </Button>
              
              <Button 
                variant="secondary"
                data-testid="button-new-journey"
              >
                <Plus className="mr-2 h-4 w-4" />
                Nova Jornada
              </Button>
            </>
          )}
        </div>
      </div>
    </header>
  );
}
