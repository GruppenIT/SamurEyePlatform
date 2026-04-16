import { useLocation } from "wouter";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { useAuth } from "@/hooks/useAuth";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { LogOut, User, KeyRound, ShieldCheck } from "lucide-react";

function initials(user: { firstName?: string; lastName?: string; email?: string } | undefined | null): string {
  if (!user) return "?";
  const a = (user.firstName || user.email || "?").charAt(0);
  const b = (user.lastName || "").charAt(0);
  return (a + b).toUpperCase();
}

function translateRole(role: string | undefined): string {
  if (role === "global_administrator") return "Administrador Global";
  if (role === "operator") return "Operador";
  if (role === "read_only") return "Somente Leitura";
  return "";
}

export function UserMenu() {
  const { user } = useAuth() as any;
  const [, setLocation] = useLocation();

  const logoutMutation = useMutation({
    mutationFn: async () => apiRequest("POST", "/api/auth/logout"),
    onSuccess: () => {
      window.location.href = "/login";
    },
  });

  const displayName = user?.firstName && user?.lastName
    ? `${user.firstName} ${user.lastName}`
    : user?.email || "Usuário";

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="rounded-full"
          data-testid="button-user-menu"
          aria-label="Menu da conta"
        >
          <Avatar className="h-8 w-8">
            <AvatarFallback className="text-xs font-medium">{initials(user)}</AvatarFallback>
          </Avatar>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-64">
        <DropdownMenuLabel className="font-normal">
          <div className="flex flex-col space-y-1">
            <p className="text-sm font-medium leading-none">{displayName}</p>
            {user?.email && (
              <p className="text-xs leading-none text-muted-foreground">{user.email}</p>
            )}
            {user?.role && (
              <p className="text-xs leading-none text-muted-foreground">{translateRole(user.role)}</p>
            )}
          </div>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem onClick={() => setLocation("/account")} data-testid="menu-account">
          <User className="mr-2 h-4 w-4" /> Minha Conta
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => setLocation("/change-password")} data-testid="menu-change-password">
          <KeyRound className="mr-2 h-4 w-4" /> Trocar senha
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => setLocation("/account/mfa")} data-testid="menu-mfa">
          <ShieldCheck className="mr-2 h-4 w-4" /> Gerenciar MFA
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          className="text-destructive focus:text-destructive"
          onClick={() => logoutMutation.mutate()}
          data-testid="menu-logout"
        >
          <LogOut className="mr-2 h-4 w-4" /> Sair
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
