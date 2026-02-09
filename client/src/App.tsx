import { Switch, Route, Redirect } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Shield, AlertTriangle, RefreshCw } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";
import { Component, type ErrorInfo, type ReactNode } from "react";
import NotFound from "@/pages/not-found";
import Landing from "@/pages/landing";
import Login from "@/pages/login";
import ChangePassword from "@/pages/change-password";
import Dashboard from "@/pages/dashboard";
import Assets from "@/pages/assets";
import Hosts from "@/pages/hosts";
import Credentials from "@/pages/credentials";
import Journeys from "@/pages/journeys";
import Schedules from "@/pages/schedules";
import Jobs from "@/pages/jobs";
import Threats from "@/pages/threats";
import Users from "@/pages/users";
import Sessions from "@/pages/sessions";
import Settings from "@/pages/settings";
import Audit from "@/pages/audit";
import NotificationPolicies from "@/pages/notification-policies";

// Error Boundary to prevent full white screen on render errors
interface ErrorBoundaryState {
  hasError: boolean;
  error?: Error;
}

class ErrorBoundary extends Component<{ children: ReactNode }, ErrorBoundaryState> {
  constructor(props: { children: ReactNode }) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('ErrorBoundary caught error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-background px-4">
          <div className="text-center max-w-md">
            <div className="w-16 h-16 bg-destructive/10 rounded-2xl flex items-center justify-center mx-auto mb-4">
              <AlertTriangle className="w-8 h-8 text-destructive" />
            </div>
            <h1 className="text-xl font-semibold text-foreground mb-2">Erro na Aplicação</h1>
            <p className="text-muted-foreground mb-4">
              Ocorreu um erro inesperado. Tente recarregar a página.
            </p>
            <button
              onClick={() => window.location.reload()}
              className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
            >
              <RefreshCw className="w-4 h-4" />
              Recarregar
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

// Admin-only route guard component
function AdminRoute({ component: PageComponent }: { component: React.ComponentType }) {
  const { user } = useAuth();
  if ((user as any)?.role !== 'global_administrator') {
    return <Redirect to="/dashboard" />;
  }
  return <PageComponent />;
}

function Router() {
  const { isAuthenticated, mustChangePassword, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-center">
          <div className="w-16 h-16 bg-primary rounded-2xl flex items-center justify-center mx-auto mb-4">
            <Shield className="w-8 h-8 text-primary-foreground animate-pulse" />
          </div>
          <p className="text-muted-foreground">Carregando...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <Switch>
        <Route path="/" component={Landing} />
        <Route path="/login" component={Login} />
        {/* Redirect any other path to login */}
        <Route>{() => <Redirect to="/login" />}</Route>
      </Switch>
    );
  }

  if (mustChangePassword) {
    return (
      <Switch>
        <Route path="/change-password" component={ChangePassword} />
        <Route>{() => <Redirect to="/change-password" />}</Route>
      </Switch>
    );
  }

  return (
    <Switch>
      {/* Public redirect */}
      <Route path="/" component={Dashboard} />
      <Route path="/dashboard" component={Dashboard} />

      {/* Operator+ routes */}
      <Route path="/assets" component={Assets} />
      <Route path="/ativos" component={Hosts} />
      <Route path="/hosts" component={Hosts} />
      <Route path="/credentials" component={Credentials} />
      <Route path="/journeys" component={Journeys} />
      <Route path="/schedules" component={Schedules} />
      <Route path="/jobs" component={Jobs} />
      <Route path="/threats" component={Threats} />
      <Route path="/sessions" component={Sessions} />

      {/* Admin-only routes */}
      <Route path="/users">{() => <AdminRoute component={Users} />}</Route>
      <Route path="/settings">{() => <AdminRoute component={Settings} />}</Route>
      <Route path="/notification-policies">{() => <AdminRoute component={NotificationPolicies} />}</Route>
      <Route path="/audit">{() => <AdminRoute component={Audit} />}</Route>

      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <div className="min-h-screen bg-background text-foreground">
            <Toaster />
            <Router />
          </div>
        </TooltipProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}

export default App;
