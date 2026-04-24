export const IS_DEMO = import.meta.env.VITE_DEMO_MODE === "true";
export const DEMO_EMAIL = "demo@samureye.com.br";
export const DEMO_PASSWORD = "Demo@2026!";

export function useIsDemo() {
  return IS_DEMO;
}
