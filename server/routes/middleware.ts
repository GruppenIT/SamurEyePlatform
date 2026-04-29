import { z } from "zod";
import { userRoleEnum } from "@shared/schema";
import { subscriptionService } from "../services/subscriptionService";

// Simple cookie parser (avoids extra dependency)
export function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  cookieHeader.split(';').forEach(pair => {
    const idx = pair.indexOf('=');
    if (idx > 0) {
      const key = pair.substring(0, idx).trim();
      const val = decodeURIComponent(pair.substring(idx + 1).trim());
      cookies[key] = val;
    }
  });
  return cookies;
}

// Admin role check middleware
export function requireAdmin(req: any, res: any, next: any) {
  if (req.user?.role !== 'global_administrator') {
    return res.status(403).json({ message: "Acesso negado. Apenas administradores podem acessar este recurso." });
  }
  next();
}

// Operator or Admin role check middleware (blocks read_only from write operations)
export function requireOperator(req: any, res: any, next: any) {
  const role = req.user?.role;
  if (role !== 'global_administrator' && role !== 'operator') {
    return res.status(403).json({ message: "Acesso negado. Usuários somente-leitura não podem realizar esta operação." });
  }
  next();
}

// Any authenticated role — allows operator, global_administrator, and readonly_analyst.
// Use for read-only endpoints where audit/analyst access is intentional.
export function requireAnyRole(req: any, res: any, next: any) {
  const role = req.user?.role;
  const validRoleValues = ['global_administrator', 'operator', 'readonly_analyst'];
  if (!role || !validRoleValues.includes(role)) {
    return res.status(403).json({ message: "Acesso negado." });
  }
  next();
}

// Subscription read-only middleware: blocks write operations when subscription is expired
// Allows: GET requests, login/logout, subscription management, settings reads
export function requireActiveSubscription(req: any, res: any, next: any) {
  // Always allow GET/HEAD/OPTIONS (read operations)
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

  // Always allow auth routes (login, logout, password change, password reset)
  if (req.path.startsWith('/api/login') || req.path.startsWith('/api/logout') || req.path.startsWith('/api/change-password')) return next();
  if (req.path.startsWith('/api/auth/password-reset/')) return next();

  // Always allow subscription management (so admin can fix it)
  if (req.path.startsWith('/api/subscription')) return next();
  if (req.path.startsWith('/api/demo/')) return next();

  // Check if read-only mode is active
  if (subscriptionService.isReadOnly()) {
    return res.status(403).json({
      message: "Subscrição expirada. O SamurEye está em modo somente-leitura. Atualize sua subscrição para continuar.",
      code: "SUBSCRIPTION_EXPIRED",
    });
  }

  next();
}

// Demo read-only guard — blocks all write operations when DEMO_MODE=true.
// No-op in normal mode. Rotas de auth sempre permitidas para possibilitar login.
const DEMO_AUTH_PATHS = ['/api/auth/', '/api/login', '/api/logout', '/api/change-password', '/api/demo/register'];

export function demoReadOnlyGuard(req: any, res: any, next: any) {
  if (process.env.DEMO_MODE !== 'true') return next();
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (DEMO_AUTH_PATHS.some(p => req.path.startsWith(p))) return next();
  return res.status(403).json({
    error: 'demo_readonly',
    message: 'Instância de demonstração — operações de escrita estão desabilitadas.',
  });
}

// Validation schemas for PATCH operations
export const patchAssetSchema = z.object({
  type: z.enum(['host', 'range', 'web_application']).optional(),
  value: z.string().min(1).optional(),
  tags: z.array(z.string()).optional(),
}).strict();

export const patchJourneySchema = z.object({
  name: z.string().min(1).optional(),
  description: z.string().optional(),
  params: z.record(z.any()).optional(),
  targetSelectionMode: z.enum(['individual', 'by_tag']).optional(),
  selectedTags: z.array(z.string()).optional(),
  enableCveDetection: z.boolean().optional(),
  credentials: z.array(z.object({
    credentialId: z.string().uuid(),
    protocol: z.enum(['ssh', 'wmi', 'snmp']),
    priority: z.number().int().min(0).default(0),
  })).optional(),
}).strict();

export const patchCredentialSchema = z.object({
  name: z.string().min(1).optional(),
  type: z.enum(['ssh', 'wmi', 'omi', 'ad']).optional(),
  username: z.string().min(1).optional(),
  secret: z.string().optional(),
  hostOverride: z.string().nullable().optional(),
  port: z.number().int().positive().nullable().optional(),
  domain: z.string().nullable().optional(),
}).strict();

export const patchThreatSchema = z.object({
  title: z.string().min(1).optional(),
  description: z.string().optional(),
  severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  assignedTo: z.string().nullable().optional(),
}).strict();

// Validate role against enum values
export const validRoles = userRoleEnum.enumValues;

// HTML sanitization for email content
export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Journey credential validation schema
export const journeyCredentialInputSchema = z.object({
  credentialId: z.string().uuid("ID de credencial inválido"),
  protocol: z.enum(['ssh', 'wmi', 'snmp'] as const, { errorMap: () => ({ message: "Protocolo inválido" }) }),
  priority: z.number().int().min(0).default(0),
});
