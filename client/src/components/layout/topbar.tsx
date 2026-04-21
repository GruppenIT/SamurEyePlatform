import { Button } from "@/components/ui/button";
import { Search, Plus } from "lucide-react";
import { Link } from "wouter";
import SystemStatusPopup from "@/components/system-status-popup";
import { UserMenu } from "@/components/account/user-menu";
import { ThemeToggle } from "@/components/theme-toggle";

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
          {/* System status popup (click to expand) */}
          <SystemStatusPopup wsConnected={wsConnected} />
          <ThemeToggle />

          {/* Default actions or custom actions */}
          {actions || (
            <>
              <Link href="/journeys">
                <Button
                  className="bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
                  data-testid="button-quick-scan"
                >
                  <Search className="mr-2 h-4 w-4" />
                  Varredura Rápida
                </Button>
              </Link>

              <Link href="/journeys">
                <Button
                  variant="secondary"
                  data-testid="button-new-journey"
                >
                  <Plus className="mr-2 h-4 w-4" />
                  Nova Jornada
                </Button>
              </Link>
            </>
          )}
          <UserMenu />
        </div>
      </div>
    </header>
  );
}
