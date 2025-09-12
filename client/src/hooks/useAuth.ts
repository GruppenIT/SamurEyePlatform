import { useQuery } from "@tanstack/react-query";

export function useAuth() {
  const { data: user, isLoading } = useQuery({
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
