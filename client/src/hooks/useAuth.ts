import { useQuery } from "@tanstack/react-query";

interface AuthUser {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: 'global_administrator' | 'operator' | 'read_only';
  mustChangePassword: boolean;
  pendingMfa?: boolean;
  mfaEnabled?: boolean;
  profileImageUrl?: string | null;
}

export function useAuth() {
  const { data: user, isLoading } = useQuery<AuthUser | null>({
    queryKey: ["/api/auth/user"],
    retry: false,
  });

  const isAuthenticated = !!user;
  const mustChangePassword = user?.mustChangePassword === true;

  return {
    user,
    isLoading,
    isAuthenticated,
    mustChangePassword,
  };
}
