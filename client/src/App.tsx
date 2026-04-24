import { Switch, Route, Redirect } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider } from "@/components/theme-provider";
import { Shield, AlertTriangle, RefreshCw } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";
import { Component, type ErrorInfo, type ReactNode } from "react";
import NotFound from "@/pages/not-found";
import Login from "@/pages/login";
import ChangePassword from "@/pages/change-password";
import ForgotPassword from "@/pages/forgot-password";
import ResetPassword from "@/pages/reset-password";
import Postura from "@/pages/postura";
import Relatorios from "@/pages/relatorios";
import Assets from "@/pages/assets";
import Hosts from "@/pages/hosts";
import Credentials from "@/pages/credentials";
import Journeys from "@/pages/journeys";
import ApiDiscovery from "@/pages/api-discovery";
import Schedules from "@/pages/schedules";
import Jobs from "@/pages/jobs";
import Threats from "@/pages/threats";
import ActionPlan from "@/pages/action-plan";
import ActionPlanDetail from "@/pages/action-plan-detail";
import Users from "@/pages/users";
import Sessions from "@/pages/sessions";
import Audit from "@/pages/audit";
import Subscription from "@/pages/subscription";
import Admin from "@/pages/admin";
import AdminConfiguracoes from "@/pages/admin-configuracoes";
import AdminSeguranca from "@/pages/admin-seguranca";
import AdminMensageria from "@/pages/admin-mensageria";
import AdminNotificacoes from "@/pages/admin-notificacoes";
import SubscriptionBanner from "@/components/subscription-banner";
import { SetupAdminBanner } from "@/components/layout/setup-admin-banner";
import { MfaInvitationDialog } from "@/components/account/mfa-invitation-dialog";
import AccountPage from "@/pages/account";
import AccountMfaPage from "@/pages/account-mfa";
import MfaChallengePage from "@/pages/mfa-challenge";

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
    return <Redirect to="/" />;
  }
  return <PageComponent />;
}

function Router() {
  const { isAuthenticated, mustChangePassword, isLoading, user } = useAuth();

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
        <Route path="/login" component={Login} />
        <Route path="/forgot-password" component={ForgotPassword} />
        <Route path="/reset-password" component={ResetPassword} />
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

  const pendingMfa = (user as any)?.pendingMfa === true;
  if (pendingMfa) {
    return (
      <Switch>
        <Route path="/mfa-challenge" component={MfaChallengePage} />
        <Route>{() => <Redirect to="/mfa-challenge" />}</Route>
      </Switch>
    );
  }

  return (
    <>
      <SetupAdminBanner />
      <Switch>
        <Route path="/" component={Postura} />
        <Route path="/postura" component={Postura} />

        {/* Operator+ routes */}
        <Route path="/relatorios" component={Relatorios} />
        <Route path="/assets" component={Assets} />
        <Route path="/ativos" component={Hosts} />
        <Route path="/hosts" component={Hosts} />
        <Route path="/credentials" component={Credentials} />
        <Route path="/journeys" component={Journeys} />
        <Route path="/journeys/api" component={ApiDiscovery} />
        <Route path="/schedules" component={Schedules} />
        <Route path="/jobs" component={Jobs} />
        <Route path="/threats" component={Threats} />
        <Route path="/action-plan/:id" component={ActionPlanDetail} />
        <Route path="/action-plan" component={ActionPlan} />
        <Route path="/account" component={AccountPage} />
        <Route path="/account/mfa" component={AccountMfaPage} />
        <Route path="/change-password" component={ChangePassword} />
        {/* After successful MFA verify the user may momentarily still be on /mfa-challenge — send them home. */}
        <Route path="/mfa-challenge">{() => <Redirect to="/" />}</Route>

        {/* Admin hub + sub-routes */}
        <Route path="/admin">{() => <AdminRoute component={Admin} />}</Route>
        <Route path="/admin/usuarios">{() => <AdminRoute component={Users} />}</Route>
        <Route path="/admin/sessoes">{() => <AdminRoute component={Sessions} />}</Route>
        <Route path="/admin/configuracoes">{() => <AdminRoute component={AdminConfiguracoes} />}</Route>
        <Route path="/admin/seguranca">{() => <AdminRoute component={AdminSeguranca} />}</Route>
        <Route path="/admin/mensageria">{() => <AdminRoute component={AdminMensageria} />}</Route>
        <Route path="/admin/notificacoes">{() => <AdminRoute component={AdminNotificacoes} />}</Route>
        <Route path="/admin/subscricao">{() => <AdminRoute component={Subscription} />}</Route>
        <Route path="/admin/auditoria">{() => <AdminRoute component={Audit} />}</Route>

        {/* Legacy redirects — rotas antigas apontam para /admin/* */}
        <Route path="/users">{() => <Redirect to="/admin/usuarios" />}</Route>
        <Route path="/sessions">{() => <Redirect to="/admin/sessoes" />}</Route>
        <Route path="/settings">{() => <Redirect to="/admin/configuracoes" />}</Route>
        <Route path="/notification-policies">{() => <Redirect to="/admin/notificacoes" />}</Route>
        <Route path="/subscription">{() => <Redirect to="/admin/subscricao" />}</Route>
        <Route path="/audit">{() => <Redirect to="/admin/auditoria" />}</Route>

        <Route component={NotFound} />
      </Switch>
      <MfaInvitationDialog />
    </>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <div className="min-h-screen bg-background text-foreground flex flex-col">
            <SubscriptionBanner />
            <Toaster />
            <div className="flex-1">
              <Router />
            </div>
          </div>
        </TooltipProvider>
      </QueryClientProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}

export default App;
