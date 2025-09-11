import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Shield } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";
import { ChangePasswordModal } from "@/components/change-password-modal";
import NotFound from "@/pages/not-found";
import Landing from "@/pages/landing";
import Login from "@/pages/login";
import Dashboard from "@/pages/dashboard";
import Assets from "@/pages/assets";
import Credentials from "@/pages/credentials";
import Journeys from "@/pages/journeys";
import Schedules from "@/pages/schedules";
import Jobs from "@/pages/jobs";
import Threats from "@/pages/threats";
import Users from "@/pages/users";
import Settings from "@/pages/settings";
import Audit from "@/pages/audit";

function Router() {
  const { isAuthenticated, isLoading, user } = useAuth();

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

  return (
    <Switch>
      {!isAuthenticated ? (
        <>
          <Route path="/" component={Landing} />
          <Route path="/login" component={Login} />
        </>
      ) : (
        <>
          {/* Change Password Modal - appears for authenticated users who must change password */}
          {(user as any)?.mustChangePassword && (
            <ChangePasswordModal open={true} mustChange={true} />
          )}
          
          <Route path="/" component={Dashboard} />
          <Route path="/assets" component={Assets} />
          <Route path="/credentials" component={Credentials} />
          <Route path="/journeys" component={Journeys} />
          <Route path="/schedules" component={Schedules} />
          <Route path="/jobs" component={Jobs} />
          <Route path="/threats" component={Threats} />
          <Route path="/users" component={Users} />
          <Route path="/settings" component={Settings} />
          <Route path="/audit" component={Audit} />
        </>
      )}
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <div className="min-h-screen bg-background text-foreground">
          <Toaster />
          <Router />
        </div>
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
