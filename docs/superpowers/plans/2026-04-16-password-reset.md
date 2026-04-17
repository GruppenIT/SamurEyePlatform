# Password Reset Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable self-service password reset via email (link-based, 30-min single-use token) from the login page, conditional on messaging being configured and tested in `/settings`; reinforce the password policy (min 12 chars + upper + lower + digit + special) across both reset and change-password, extracted into a shared Zod schema.

**Architecture:** New `password_reset_tokens` table (hashed tokens, one-shot). Public endpoints `GET /api/auth/features`, `POST /password-reset/request` (always 202), `GET /password-reset/verify`, `POST /password-reset/confirm`. Reset invalidates all of the user's active sessions via the existing `storage.deleteActiveSessionsByUserId`. MFA is not touched — next login still goes through `/mfa-challenge`. Frontend: conditional link on `/login`, new `/forgot-password` and `/reset-password` pages.

**Tech Stack:** Drizzle (schema + push), `crypto.randomBytes` + `bcryptjs` for tokens, `emailService` for delivery, shadcn/ui (Card, Input, Button, Label), wouter, react-query, react-hook-form + zod.

**Spec:** `docs/superpowers/specs/2026-04-16-password-reset-design.md`.

**Verification:** `npm run check` (baseline errors in unrelated files stay), `npx vite build`, manual QA after deploy.

**Note:** `changePasswordSchema` in `shared/schema.ts` (line ~729) already enforces the exact complexity we need. Task 2 extracts it into a reusable `passwordComplexitySchema` so reset can reuse it with zero drift.

---

## File Structure

| Path | Action | Responsibility |
| --- | --- | --- |
| `shared/schema.ts` | Modify | Add `passwordComplexitySchema` + `password_reset_tokens` table + types |
| `server/storage/password-reset.ts` | Create | CRUD on `password_reset_tokens` |
| `server/storage/interface.ts` | Modify | Method signatures for new storage helpers |
| `server/storage/index.ts` | Modify | Wire password-reset helpers |
| `server/services/passwordResetService.ts` | Create | Token gen, hashing, email send |
| `server/routes/auth-password-reset.ts` | Create | 4 public endpoints |
| `server/routes/index.ts` | Modify | Register the new route module |
| `client/src/pages/login.tsx` | Modify | Conditional "Esqueci minha senha" link via /api/auth/features |
| `client/src/pages/forgot-password.tsx` | Create | Email entry page |
| `client/src/pages/reset-password.tsx` | Create | Token verify + new password form with checklist |
| `client/src/components/account/password-checklist.tsx` | Create | Live requirements indicator (reused in reset + change-password) |
| `client/src/pages/change-password.tsx` | Modify | Add `<PasswordChecklist>` widget under the "nova senha" field |
| `client/src/App.tsx` | Modify | Register `/forgot-password` and `/reset-password` in unauthenticated branch |

---

## Task 1: Schema — `passwordComplexitySchema` + `password_reset_tokens`

**Files:** `shared/schema.ts`.

- [ ] **Step 1: Extract `passwordComplexitySchema` above `changePasswordSchema` (~line 729)**

Find:

```ts
// Schema para troca de senha
export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, "Senha atual é obrigatória"),
  newPassword: z.string().min(12, "Nova senha deve ter pelo menos 12 caracteres")
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])/, 
      "Nova senha deve conter ao menos: 1 minúscula, 1 maiúscula, 1 número e 1 símbolo especial"),
```

Replace with:

```ts
// Shared password policy (min 12 chars + upper + lower + digit + special)
export const passwordComplexitySchema = z.string()
  .min(12, "Senha deve ter pelo menos 12 caracteres")
  .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])/,
    "Senha deve conter ao menos: 1 minúscula, 1 maiúscula, 1 número e 1 símbolo especial");

// Schema para troca de senha
export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, "Senha atual é obrigatória"),
  newPassword: passwordComplexitySchema,
```

Close the object as before.

- [ ] **Step 2: Add `passwordResetTokens` table**

At the end of the tables block (before the Zod schema exports / `// Types` section), add:

```ts
export const passwordResetTokens = pgTable("password_reset_tokens", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").references(() => users.id, { onDelete: 'cascade' }).notNull(),
  tokenHash: text("token_hash").notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  consumedAt: timestamp("consumed_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
}, (table) => [
  index("idx_password_reset_tokens_user_active").on(table.userId, table.expiresAt),
]);

export type PasswordResetToken = typeof passwordResetTokens.$inferSelect;
export type InsertPasswordResetToken = typeof passwordResetTokens.$inferInsert;
```

- [ ] **Step 3: Add `confirmPasswordResetSchema`**

Just below `changePasswordSchema`, add:

```ts
export const confirmPasswordResetSchema = z.object({
  token: z.string().min(1, "Token obrigatório"),
  newPassword: passwordComplexitySchema,
});

export type ConfirmPasswordReset = z.infer<typeof confirmPasswordResetSchema>;
```

- [ ] **Step 4: Push schema**

```bash
cd /opt/samureye && npm run db:push
```
Expected: ALTER/CREATE applied.

- [ ] **Step 5: Verify DB**

```bash
set -a && . ./.env && set +a && psql "$DATABASE_URL" -c "\d password_reset_tokens"
```
Expected: table exists with 6 columns + index.

- [ ] **Step 6: Type-check**

```bash
npm run check 2>&1 | grep "shared/schema" | head
```
Expected: no lines.

- [ ] **Step 7: Commit**

```bash
git add shared/schema.ts
git commit -m "feat(schema): extract passwordComplexitySchema and add password_reset_tokens table"
```

---

## Task 2: Storage — password_reset helpers

**Files:** `server/storage/password-reset.ts` (create), `server/storage/interface.ts`, `server/storage/index.ts`.

- [ ] **Step 1: Create `server/storage/password-reset.ts`**

```ts
import { db } from "../db";
import { and, eq, gt, isNull, lt } from "drizzle-orm";
import { passwordResetTokens } from "@shared/schema";
import type { PasswordResetToken, InsertPasswordResetToken } from "@shared/schema";

export async function createPasswordResetToken(data: InsertPasswordResetToken): Promise<PasswordResetToken> {
  const [row] = await db.insert(passwordResetTokens).values(data).returning();
  return row;
}

export async function getActivePasswordResetTokens(): Promise<PasswordResetToken[]> {
  const now = new Date();
  return db
    .select()
    .from(passwordResetTokens)
    .where(and(
      isNull(passwordResetTokens.consumedAt),
      gt(passwordResetTokens.expiresAt, now),
    ));
}

export async function consumePasswordResetToken(id: string): Promise<void> {
  await db
    .update(passwordResetTokens)
    .set({ consumedAt: new Date() })
    .where(eq(passwordResetTokens.id, id));
}

export async function consumeAllPasswordResetTokensForUser(userId: string): Promise<void> {
  await db
    .update(passwordResetTokens)
    .set({ consumedAt: new Date() })
    .where(and(
      eq(passwordResetTokens.userId, userId),
      isNull(passwordResetTokens.consumedAt),
    ));
}

export async function cleanupOldPasswordResetTokens(userId: string): Promise<void> {
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
  await db
    .delete(passwordResetTokens)
    .where(and(
      eq(passwordResetTokens.userId, userId),
      lt(passwordResetTokens.createdAt, cutoff),
    ));
}
```

- [ ] **Step 2: Extend interface**

In `server/storage/interface.ts`, import the token types at the top (append to existing `@shared/schema` import):

```ts
import type { ..., PasswordResetToken, InsertPasswordResetToken } from "@shared/schema";
```

Add a new block in `IStorage`:

```ts
  // Password reset tokens
  createPasswordResetToken(data: InsertPasswordResetToken): Promise<PasswordResetToken>;
  getActivePasswordResetTokens(): Promise<PasswordResetToken[]>;
  consumePasswordResetToken(id: string): Promise<void>;
  consumeAllPasswordResetTokensForUser(userId: string): Promise<void>;
  cleanupOldPasswordResetTokens(userId: string): Promise<void>;
```

- [ ] **Step 3: Wire in `server/storage/index.ts`**

Add import:

```ts
import * as passwordResetOps from "./password-reset";
```

In the class body:

```ts
  createPasswordResetToken = passwordResetOps.createPasswordResetToken;
  getActivePasswordResetTokens = passwordResetOps.getActivePasswordResetTokens;
  consumePasswordResetToken = passwordResetOps.consumePasswordResetToken;
  consumeAllPasswordResetTokensForUser = passwordResetOps.consumeAllPasswordResetTokensForUser;
  cleanupOldPasswordResetTokens = passwordResetOps.cleanupOldPasswordResetTokens;
```

- [ ] **Step 4: Type-check**

```bash
npm run check 2>&1 | grep -E "storage/password-reset|storage/interface|storage/index" | head
```

- [ ] **Step 5: Commit**

```bash
git add server/storage/password-reset.ts server/storage/interface.ts server/storage/index.ts
git commit -m "feat(storage): add password reset token helpers"
```

---

## Task 3: `passwordResetService`

**Files:** `server/services/passwordResetService.ts`.

- [ ] **Step 1: Create**

```ts
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { storage } from '../storage';
import { emailService } from './emailService';
import { createLogger } from '../lib/logger';

const log = createLogger('password-reset');

const TOKEN_BYTES = 32;
const TOKEN_TTL_MS = 30 * 60 * 1000; // 30 minutes
const BCRYPT_COST = 10;
const EMAIL_WINDOW_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

export interface PasswordResetRequestContext {
  baseUrl: string;
}

export class PasswordResetService {
  async isDeliveryAvailable(): Promise<boolean> {
    const settings = await storage.getEmailSettings();
    if (!settings?.lastTestSuccessAt) return false;
    return settings.lastTestSuccessAt.getTime() > Date.now() - EMAIL_WINDOW_MS;
  }

  generateToken(): string {
    return crypto.randomBytes(TOKEN_BYTES).toString('base64url');
  }

  async hashToken(token: string): Promise<string> {
    return bcrypt.hash(token, BCRYPT_COST);
  }

  async sendResetEmail(email: string, link: string): Promise<void> {
    const settings = await storage.getEmailSettings();
    if (!settings) throw new Error('mensageria não configurada');
    await emailService.sendEmail(settings, {
      to: email,
      subject: 'Recuperação de senha SamurEye',
      html: `
        <p>Você solicitou a redefinição de senha para sua conta SamurEye.</p>
        <p>Clique no link abaixo (válido por 30 minutos):</p>
        <p><a href="${link}">${link}</a></p>
        <p>Se você não fez essa solicitação, ignore este e-mail — sua senha permanece inalterada.</p>
      `,
    });
  }

  computeExpiresAt(): Date {
    return new Date(Date.now() + TOKEN_TTL_MS);
  }

  async findTokenMatch(rawToken: string): Promise<{ token: typeof storage extends { getActivePasswordResetTokens(): Promise<infer T> } ? T extends Array<infer U> ? U : never : never } | null> {
    // Typed as a narrowed subset of PasswordResetToken via inference so we don't have to re-import.
    const tokens = await storage.getActivePasswordResetTokens();
    for (const t of tokens) {
      if (await bcrypt.compare(rawToken, t.tokenHash)) {
        return { token: t } as any;
      }
    }
    return null;
  }
}

export const passwordResetService = new PasswordResetService();
```

(The `findTokenMatch` complex return type is just to avoid an extra import; if TypeScript complains, replace the return type with `Promise<{ token: PasswordResetToken } | null>` and import `PasswordResetToken`. Either is acceptable.)

- [ ] **Step 2: Type-check**

```bash
npm run check 2>&1 | grep "passwordResetService" | head
```

If errors appear around `findTokenMatch` return type, simplify to:

```ts
import type { PasswordResetToken } from '@shared/schema';
// ...
async findTokenMatch(rawToken: string): Promise<{ token: PasswordResetToken } | null> {
  const tokens = await storage.getActivePasswordResetTokens();
  for (const t of tokens) {
    if (await bcrypt.compare(rawToken, t.tokenHash)) return { token: t };
  }
  return null;
}
```

- [ ] **Step 3: Commit**

```bash
git add server/services/passwordResetService.ts
git commit -m "feat(password-reset): add service for token gen/hash/email"
```

---

## Task 4: Routes — 4 public endpoints

**Files:** `server/routes/auth-password-reset.ts` (create), `server/routes/index.ts`.

- [ ] **Step 1: Create `server/routes/auth-password-reset.ts`**

```ts
import type { Express } from "express";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import { storage } from "../storage";
import { passwordResetService } from "../services/passwordResetService";
import { confirmPasswordResetSchema } from "@shared/schema";
import { createLogger } from "../lib/logger";

const log = createLogger('routes:password-reset');

const MAX_IP_REQUESTS = 5; // aligned with existing login_attempts helper (blocks after 5)
const IP_HASH = (ip: string) => crypto.createHash('sha256').update(ip).digest('hex').slice(0, 16);
const EMAIL_HASH = (email: string) => crypto.createHash('sha256').update(email.trim().toLowerCase()).digest('hex').slice(0, 16);

async function isBlocked(key: string): Promise<boolean> {
  const attempt = await storage.getLoginAttempt(key);
  if (!attempt?.blockedUntil) return false;
  return new Date() < attempt.blockedUntil;
}

export function registerAuthPasswordResetRoutes(app: Express) {
  // GET /api/auth/features — public, unauthenticated
  app.get('/api/auth/features', async (_req, res) => {
    try {
      const passwordRecoveryAvailable = await passwordResetService.isDeliveryAvailable();
      res.json({ passwordRecoveryAvailable });
    } catch (error) {
      log.error({ err: error }, 'features check failed');
      res.json({ passwordRecoveryAvailable: false });
    }
  });

  // POST /api/auth/password-reset/request — always 202
  app.post('/api/auth/password-reset/request', async (req, res) => {
    const rawEmail = String(req.body?.email ?? '').trim().toLowerCase();
    const clientIp = req.ip || 'unknown';
    const ipKey = `pwreset:ip:${IP_HASH(clientIp)}`;
    const emailKey = rawEmail ? `pwreset:email:${EMAIL_HASH(rawEmail)}` : null;

    const always202 = () =>
      res.status(202).json({ message: "Se o e-mail existir em nossa base, enviaremos um link em instantes." });

    try {
      if (!rawEmail || !rawEmail.includes('@')) return always202();
      if (await isBlocked(ipKey)) return always202();
      if (emailKey && await isBlocked(emailKey)) return always202();
      if (!(await passwordResetService.isDeliveryAvailable())) {
        log.warn('password reset requested but messaging not ready');
        return always202();
      }
      const user = await storage.getUserByEmail(rawEmail);
      if (!user) return always202();

      await storage.cleanupOldPasswordResetTokens(user.id);
      const raw = passwordResetService.generateToken();
      const tokenHash = await passwordResetService.hashToken(raw);
      await storage.createPasswordResetToken({
        userId: user.id,
        tokenHash,
        expiresAt: passwordResetService.computeExpiresAt(),
      });

      const proto = req.headers['x-forwarded-proto'] ?? req.protocol ?? 'https';
      const host = req.headers['x-forwarded-host'] ?? req.get('host');
      const link = `${proto}://${host}/reset-password?token=${encodeURIComponent(raw)}`;

      try {
        await passwordResetService.sendResetEmail(user.email, link);
        await storage.logAudit({
          actorId: user.id,
          action: 'user.password_reset.request',
          objectType: 'user',
          objectId: user.id,
          before: null,
          after: { ip: clientIp },
        });
      } catch (mailErr) {
        log.error({ err: mailErr, userId: user.id }, 'failed to send reset email');
      }

      await storage.upsertLoginAttempt(ipKey, true);
      if (emailKey) await storage.upsertLoginAttempt(emailKey, true);
      return always202();
    } catch (error) {
      log.error({ err: error }, 'password reset request failed');
      return always202();
    }
  });

  // GET /api/auth/password-reset/verify?token=...
  app.get('/api/auth/password-reset/verify', async (req, res) => {
    try {
      const token = String(req.query?.token ?? '');
      if (!token) return res.status(410).json({ valid: false });
      const match = await passwordResetService.findTokenMatch(token);
      if (!match) return res.status(410).json({ valid: false });
      res.json({ valid: true });
    } catch (error) {
      log.error({ err: error }, 'password reset verify failed');
      res.status(500).json({ valid: false });
    }
  });

  // POST /api/auth/password-reset/confirm
  app.post('/api/auth/password-reset/confirm', async (req, res) => {
    const clientIp = req.ip || 'unknown';
    const ipKey = `pwreset:confirm:ip:${IP_HASH(clientIp)}`;
    try {
      if (await isBlocked(ipKey)) {
        return res.status(429).json({ message: "Muitas tentativas. Aguarde 15 minutos." });
      }
      const parsed = confirmPasswordResetSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({
          message: "Dados inválidos",
          errors: parsed.error.flatten(),
        });
      }
      const { token, newPassword } = parsed.data;

      const match = await passwordResetService.findTokenMatch(token);
      if (!match) {
        await storage.upsertLoginAttempt(ipKey, true);
        return res.status(401).json({ message: "Link inválido ou expirado" });
      }

      const userId = match.token.userId;
      const newHash = await bcrypt.hash(newPassword, 12);

      await storage.updateUserPassword(userId, newHash);
      await storage.setMustChangePassword(userId, false);
      await storage.consumePasswordResetToken(match.token.id);
      await storage.consumeAllPasswordResetTokensForUser(userId);
      await storage.deleteActiveSessionsByUserId(userId);
      await storage.resetLoginAttempts(ipKey);

      await storage.logAudit({
        actorId: userId,
        action: 'user.password_reset.success',
        objectType: 'user',
        objectId: userId,
        before: null,
        after: { ip: clientIp },
      });

      res.json({ message: "Senha atualizada. Faça login novamente." });
    } catch (error) {
      log.error({ err: error }, 'password reset confirm failed');
      res.status(500).json({ message: "Falha ao redefinir a senha" });
    }
  });
}
```

- [ ] **Step 2: Register in `server/routes/index.ts`**

Add import and call:

```ts
import { registerAuthPasswordResetRoutes } from "./auth-password-reset";
```

Inside `registerRoutes`, near other `register*` calls:

```ts
  registerAuthPasswordResetRoutes(app);
```

- [ ] **Step 3: Type-check**

```bash
npm run check 2>&1 | grep -E "auth-password-reset|routes/index" | head
```

- [ ] **Step 4: Commit**

```bash
git add server/routes/auth-password-reset.ts server/routes/index.ts
git commit -m "feat(auth): add password reset routes (features/request/verify/confirm)"
```

---

## Task 5: Frontend — PasswordChecklist component

**Files:** `client/src/components/account/password-checklist.tsx`.

- [ ] **Step 1: Create**

```tsx
import { Check, X } from "lucide-react";

interface PasswordChecklistProps {
  password: string;
}

const RULES = [
  { label: "Pelo menos 12 caracteres", test: (p: string) => p.length >= 12 },
  { label: "1 letra maiúscula (A-Z)", test: (p: string) => /[A-Z]/.test(p) },
  { label: "1 letra minúscula (a-z)", test: (p: string) => /[a-z]/.test(p) },
  { label: "1 dígito (0-9)", test: (p: string) => /\d/.test(p) },
  { label: "1 caractere especial (!@#... etc.)", test: (p: string) => /[^A-Za-z0-9]/.test(p) },
];

export function PasswordChecklist({ password }: PasswordChecklistProps) {
  return (
    <ul className="mt-2 space-y-1 text-xs" data-testid="password-checklist">
      {RULES.map((rule) => {
        const ok = rule.test(password);
        const Icon = ok ? Check : X;
        return (
          <li key={rule.label} className={ok ? "flex items-center gap-1.5 text-green-600 dark:text-green-400" : "flex items-center gap-1.5 text-muted-foreground"}>
            <Icon className="h-3.5 w-3.5" aria-hidden="true" />
            <span>{rule.label}</span>
          </li>
        );
      })}
    </ul>
  );
}

export function isPasswordStrong(password: string): boolean {
  return RULES.every((r) => r.test(password));
}
```

- [ ] **Step 2: Type-check**

```bash
npm run check 2>&1 | grep "password-checklist" | head
```

- [ ] **Step 3: Commit**

```bash
git add client/src/components/account/password-checklist.tsx
git commit -m "feat(account): add reusable PasswordChecklist component"
```

---

## Task 6: /forgot-password page

**Files:** `client/src/pages/forgot-password.tsx`.

- [ ] **Step 1: Create**

```tsx
import { useState } from "react";
import { Link } from "wouter";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [submitted, setSubmitted] = useState(false);

  const requestMutation = useMutation({
    mutationFn: async () => apiRequest("POST", "/api/auth/password-reset/request", { email }),
    onSettled: () => setSubmitted(true),
  });

  return (
    <div className="flex h-screen items-center justify-center bg-background px-4">
      <Card className="w-full max-w-md">
        {!submitted ? (
          <>
            <CardHeader>
              <CardTitle>Recuperar senha</CardTitle>
              <CardDescription>
                Informe o e-mail da sua conta. Enviaremos um link para redefinir a senha.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form
                onSubmit={(e) => { e.preventDefault(); requestMutation.mutate(); }}
                className="space-y-4"
              >
                <div>
                  <Label htmlFor="email">E-mail</Label>
                  <Input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    autoComplete="email"
                    autoFocus
                    required
                    data-testid="input-forgot-email"
                  />
                </div>
                <Button
                  type="submit"
                  className="w-full"
                  disabled={!email.includes("@") || requestMutation.isPending}
                  data-testid="button-forgot-submit"
                >
                  {requestMutation.isPending ? "Enviando..." : "Enviar link"}
                </Button>
                <div className="text-center text-sm">
                  <Link href="/login" className="text-primary hover:underline" data-testid="link-back-to-login">
                    Voltar ao login
                  </Link>
                </div>
              </form>
            </CardContent>
          </>
        ) : (
          <>
            <CardHeader>
              <CardTitle>Verifique sua caixa de entrada</CardTitle>
              <CardDescription>
                Se o e-mail existir em nossa base, você receberá um link para redefinir sua senha em alguns instantes. O link expira em 30 minutos.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Link href="/login">
                <Button variant="outline" className="w-full" data-testid="button-back-to-login-after">
                  Voltar ao login
                </Button>
              </Link>
            </CardContent>
          </>
        )}
      </Card>
    </div>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add client/src/pages/forgot-password.tsx
git commit -m "feat(auth): add /forgot-password page"
```

---

## Task 7: /reset-password page

**Files:** `client/src/pages/reset-password.tsx`.

- [ ] **Step 1: Create**

```tsx
import { useState } from "react";
import { useLocation } from "wouter";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { PasswordChecklist, isPasswordStrong } from "@/components/account/password-checklist";
import { Loader2 } from "lucide-react";

function getToken(): string {
  const qs = new URLSearchParams(window.location.search);
  return qs.get("token") ?? "";
}

export default function ResetPassword() {
  const { toast } = useToast();
  const [, setLocation] = useLocation();
  const token = getToken();
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const verifyQuery = useQuery<{ valid: boolean }>({
    queryKey: [`/api/auth/password-reset/verify?token=${encodeURIComponent(token)}`],
    enabled: !!token,
    retry: false,
  });

  const confirmMutation = useMutation({
    mutationFn: async () =>
      apiRequest("POST", "/api/auth/password-reset/confirm", { token, newPassword: password }),
    onSuccess: () => {
      toast({ title: "Senha atualizada", description: "Faça login com a nova senha." });
      setLocation("/login");
    },
    onError: (err: any) => {
      toast({
        title: "Falha ao redefinir",
        description: err?.message || "Verifique o link e a nova senha.",
        variant: "destructive",
      });
    },
  });

  if (!token || verifyQuery.isError || verifyQuery.data?.valid === false) {
    return (
      <div className="flex h-screen items-center justify-center bg-background px-4">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle>Link inválido ou expirado</CardTitle>
            <CardDescription>
              O link de recuperação não é mais válido. Solicite um novo.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button className="w-full" onClick={() => setLocation("/forgot-password")} data-testid="button-request-new-link">
              Solicitar novo link
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (verifyQuery.isLoading) {
    return (
      <div className="flex h-screen items-center justify-center bg-background">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const strongEnough = isPasswordStrong(password);
  const matches = password.length > 0 && password === confirmPassword;

  return (
    <div className="flex h-screen items-center justify-center bg-background px-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Definir nova senha</CardTitle>
          <CardDescription>Escolha uma senha forte que atenda aos requisitos abaixo.</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (!strongEnough || !matches || confirmMutation.isPending) return;
              confirmMutation.mutate();
            }}
            className="space-y-4"
          >
            <div>
              <Label htmlFor="new-password">Nova senha</Label>
              <Input
                id="new-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
                autoFocus
                required
                data-testid="input-new-password"
              />
              <PasswordChecklist password={password} />
            </div>
            <div>
              <Label htmlFor="confirm-password">Confirmar nova senha</Label>
              <Input
                id="confirm-password"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                autoComplete="new-password"
                required
                data-testid="input-confirm-password"
              />
              {confirmPassword.length > 0 && !matches && (
                <p className="mt-1 text-xs text-destructive">As senhas não coincidem.</p>
              )}
            </div>
            <Button
              type="submit"
              className="w-full"
              disabled={!strongEnough || !matches || confirmMutation.isPending}
              data-testid="button-reset-submit"
            >
              {confirmMutation.isPending ? "Atualizando..." : "Redefinir senha"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add client/src/pages/reset-password.tsx
git commit -m "feat(auth): add /reset-password page with live checklist"
```

---

## Task 8: Wire up /login conditional link + register routes

**Files:** `client/src/pages/login.tsx`, `client/src/App.tsx`.

- [ ] **Step 1: Add feature flag query + link in `login.tsx`**

Read the current file around the submit button (approximately after the Button inside the form — search for `button-login`).

Add near the top of the component:

```tsx
import { useQuery } from "@tanstack/react-query";
import { Link } from "wouter";
```

Inside the component function, before `return`:

```tsx
  const featuresQuery = useQuery<{ passwordRecoveryAvailable: boolean }>({
    queryKey: ["/api/auth/features"],
    retry: false,
  });
```

In the JSX, immediately AFTER the "Entrar" submit Button and before the closing `</form>`, add:

```tsx
            {featuresQuery.data?.passwordRecoveryAvailable && (
              <div className="text-center text-sm">
                <Link href="/forgot-password" className="text-primary hover:underline" data-testid="link-forgot-password">
                  Esqueci minha senha
                </Link>
              </div>
            )}
```

- [ ] **Step 2: Register routes in `App.tsx`**

Add imports at the top:

```tsx
import ForgotPassword from "@/pages/forgot-password";
import ResetPassword from "@/pages/reset-password";
```

In the `!isAuthenticated` branch — the Switch that currently has `/` and `/login` — add the two routes BEFORE the catch-all:

```tsx
    return (
      <Switch>
        <Route path="/" component={Landing} />
        <Route path="/login" component={Login} />
        <Route path="/forgot-password" component={ForgotPassword} />
        <Route path="/reset-password" component={ResetPassword} />
        <Route>{() => <Redirect to="/login" />}</Route>
      </Switch>
    );
```

- [ ] **Step 3: Type-check + build**

```bash
npm run check 2>&1 | grep -E "pages/login|App.tsx|pages/forgot|pages/reset" | grep -v "Property 'role'" | head
npx vite build 2>&1 | tail -3
```

- [ ] **Step 4: Commit**

```bash
git add client/src/pages/login.tsx client/src/App.tsx
git commit -m "feat(auth): conditional 'Esqueci minha senha' link + route registration"
```

---

## Task 9: Add checklist to /change-password

**Files:** `client/src/pages/change-password.tsx`.

- [ ] **Step 1: Import + render checklist**

Read the current file:

```bash
grep -n "newPassword\|Nova senha" /opt/samureye/client/src/pages/change-password.tsx | head
```

Add import near the top:

```tsx
import { PasswordChecklist } from "@/components/account/password-checklist";
```

Locate the Input whose `id` or name is `newPassword` (or `new_password`). Add `<PasswordChecklist password={watchedValue} />` immediately below it, where `watchedValue` is the current value of the new password field. If the page uses `react-hook-form`, use `form.watch("newPassword")`; if it uses `useState`, pass the state variable.

Example adaptation:

```tsx
<FormField
  control={form.control}
  name="newPassword"
  render={({ field }) => (
    <FormItem>
      <FormLabel>Nova senha</FormLabel>
      <FormControl>
        <Input type="password" {...field} data-testid="input-new-password" />
      </FormControl>
      <PasswordChecklist password={field.value ?? ""} />
      <FormMessage />
    </FormItem>
  )}
/>
```

- [ ] **Step 2: Type-check**

```bash
npm run check 2>&1 | grep "change-password" | head
```

- [ ] **Step 3: Commit**

```bash
git add client/src/pages/change-password.tsx
git commit -m "feat(auth): show PasswordChecklist on /change-password"
```

---

## Task 10: Deploy + QA

- [ ] **Step 1: Final verification**

```bash
cd /opt/samureye && npm run check 2>&1 | grep -E "password-reset|passwordResetService|forgot-password|reset-password|password-checklist|auth-password-reset" | grep -v "Property 'role'" | head
npx vite build 2>&1 | tail -3
```
Expected: no new errors from our files; build passes.

- [ ] **Step 2: Deploy**

```bash
deploy-samureye
```

- [ ] **Step 3: Runtime QA checklist**

In a browser:

1. Com mensageria testada (lastTestSuccessAt < 30d), a `/login` mostra link "Esqueci minha senha".
2. Sem mensageria testada, o link não aparece.
3. `/forgot-password` com e-mail inexistente → resposta "Se o e-mail existir…" (nenhum e-mail sai).
4. `/forgot-password` com e-mail válido e user existente → e-mail chega em poucos segundos com link `/reset-password?token=...`.
5. Clicar no link abre a tela "Definir nova senha" com checklist ao lado do input. Enquanto a senha não atende a política, botão fica desativado.
6. Senha que atende a política + confirmação coincidente → botão habilita; submit atualiza a senha e redireciona pra `/login`.
7. Tentar reutilizar o mesmo link depois do sucesso → "Link inválido ou expirado".
8. Após reset, se outra aba do mesmo user estava logada, próxima requisição retorna 401 (sessões invalidadas).
9. Usuário com MFA ativo: após reset, login com nova senha ainda pede TOTP em `/mfa-challenge`.
10. `/change-password` mostra o mesmo checklist abaixo do campo "Nova senha".
11. Rate limit: fazer 6 requests em rajada a `/request` com mesmo IP → a partir do 6º, sem efeito (sempre 202, mas e-mail não sai).

- [ ] **Step 4: Fix + re-deploy if any QA item fails**

```bash
git add -A
git commit -m "fix(password-reset): QA follow-up"
deploy-samureye
```

---

## Self-Review (against spec)

- **Spec §4 schema** — Task 1.
- **Spec §5.1 /features** — Task 4 Step 1.
- **Spec §5.2 /request** (202 invariante + rate limit + mail silencioso) — Task 4.
- **Spec §5.3 /verify** — Task 4.
- **Spec §5.4 /confirm** (política, consume, invalida sessões, audit) — Task 4.
- **Spec §6.1 link no login** — Task 8.
- **Spec §6.2 /forgot-password** — Task 6.
- **Spec §6.3 /reset-password** — Task 7.
- **Spec §6.4 App.tsx** — Task 8.
- **Spec §6.5 política unificada** — Task 1 (schema) + Task 5 (componente) + Task 9 (change-password).
- **Spec §7 e-mail template** — Task 3.
- **Spec §8 arquivos** — todos cobertos.
- **Spec §9 critérios 1-10** — Task 10 QA.
- **Spec §10 segurança** — implícito no design (hash, rate limit, 202 invariante, 30min TTL, sessões invalidadas).
