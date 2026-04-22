import SystemStatusPopup from "@/components/system-status-popup";
import { UserMenu } from "@/components/account/user-menu";
import { ThemeToggle } from "@/components/theme-toggle";

interface TopBarProps {
  title: string;
  subtitle: string;
  wsConnected?: boolean;
}

export default function TopBar({ title, subtitle, wsConnected = false }: TopBarProps) {
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
          <SystemStatusPopup wsConnected={wsConnected} />
          <ThemeToggle />
          <UserMenu />
        </div>
      </div>
    </header>
  );
}
