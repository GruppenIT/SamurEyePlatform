# Getting Started — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a 10-step onboarding checklist (`/getting-started`) for `global_administrator` users, with server-computed completion status, skip-with-justification for 6 skippable steps, sidebar badge, and a permanent tile in the `/admin` hub.

**Architecture:** A new `server/routes/getting-started.ts` file exposes 4 endpoints; completion is computed from real DB data (settings, email_settings, users, journeys, notification_policies, action_plans) with no new tables. Skip and dismiss state are stored in the existing `settings` table as JSON blobs. The frontend page uses a single react-query against `GET /api/getting-started/status` (30 s stale time) and mutations for skip/unskip/dismiss.

**Tech Stack:** Express + Drizzle ORM (server), React 18 + TypeScript + wouter + @tanstack/react-query + shadcn/ui + lucide-react (client), Tailwind CSS.

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `server/routes/getting-started.ts` | Create | 4 API endpoints — GET status, POST skip, DELETE skip, POST dismiss |
| `server/routes/index.ts` | Modify | Register `registerGettingStartedRoutes` |
| `client/src/pages/getting-started.tsx` | Create | Full page — progress bar, 3 groups, step cards, skip modal, dismiss banner |
| `client/src/App.tsx` | Modify | Add `/getting-started` route with AdminRoute |
| `client/src/components/layout/sidebar.tsx` | Modify | Add "Primeiros Passos" item (with badge) between Postura and Inventário |
| `client/src/pages/admin.tsx` | Modify | Add "Primeiros Passos" tile with mini progress bar to Plataforma group |

---

## Task 1: Server route — GET /api/getting-started/status

**Files:**
- Create: `server/routes/getting-started.ts`

- [ ] **Step 1: Create the file with imports, constants, and the computeCompletion helper**

```typescript
// server/routes/getting-started.ts
import type { Express } from "express";
import { storage } from "../storage";
import { db } from "../db";
import {
  journeys,
  users,
  notificationPolicies,
  actionPlans,
} from "@shared/schema";
import { count } from "drizzle-orm";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { requireAdmin } from "./middleware";
import { createLogger } from "../lib/logger";

const log = createLogger("routes:getting-started");

const STEP_IDS = [
  "appliance_config",
  "mensageria",
  "first_user",
  "journey_attack_surface",
  "journey_ad_security",
  "journey_edr_av",
  "journey_web_application",
  "journey_api_security",
  "notification_policy",
  "action_plan",
] as const;

type StepId = (typeof STEP_IDS)[number];

const SKIPPABLE = new Set<StepId>([
  "journey_attack_surface",
  "journey_ad_security",
  "journey_edr_av",
  "journey_web_application",
  "journey_api_security",
  "notification_policy",
]);

interface StepStatus {
  id: StepId;
  completed: boolean;
  skippable: boolean;
  skipped: boolean;
  skipReason: string | null;
  skippedAt: string | null;
}

async function computeCompletion(): Promise<Record<StepId, boolean>> {
  const [allSettings, emailSettings, allUsers, journeyRows, policyCount, planCount] =
    await Promise.all([
      storage.getAllSettings(),
      storage.getEmailSettings(),
      storage.getAllUsers(),
      db.select({ type: journeys.type }).from(journeys),
      db.select({ count: count() }).from(notificationPolicies),
      db.select({ count: count() }).from(actionPlans),
    ]);

  const settingsMap = Object.fromEntries(allSettings.map((s) => [s.key, s.value]));
  const journeyTypes = new Set(journeyRows.map((j) => j.type));

  return {
    appliance_config:
      Boolean(settingsMap["applianceName"]) && Boolean(settingsMap["locationType"]),
    mensageria: Boolean(emailSettings?.smtpHost),
    first_user: allUsers.some((u) => u.role !== "global_administrator"),
    journey_attack_surface: journeyTypes.has("attack_surface"),
    journey_ad_security: journeyTypes.has("ad_security"),
    journey_edr_av: journeyTypes.has("edr_av"),
    journey_web_application: journeyTypes.has("web_application"),
    journey_api_security: journeyTypes.has("api_security"),
    notification_policy: Number(policyCount[0].count) > 0,
    action_plan: Number(planCount[0].count) > 0,
  };
}

export function registerGettingStartedRoutes(app: Express) {
  // placeholder — endpoints added in next steps
}
```

- [ ] **Step 2: Add the GET /api/getting-started/status endpoint inside `registerGettingStartedRoutes`**

Replace the placeholder body with:

```typescript
export function registerGettingStartedRoutes(app: Express) {
  app.get(
    "/api/getting-started/status",
    isAuthenticatedWithPasswordCheck,
    requireAdmin,
    async (req: any, res) => {
      try {
        const [completion, skippedSetting, dismissedSetting] = await Promise.all([
          computeCompletion(),
          storage.getSetting("gettingStarted.skipped"),
          storage.getSetting("gettingStarted.dismissed"),
        ]);

        const skipped = (skippedSetting?.value ?? {}) as Record<
          string,
          { at: string; reason: string }
        >;
        const dismissed = Boolean(dismissedSetting?.value);

        const steps: StepStatus[] = STEP_IDS.map((id) => {
          const entry = skipped[id];
          return {
            id,
            completed: completion[id],
            skippable: SKIPPABLE.has(id),
            skipped: Boolean(entry),
            skipReason: entry?.reason || null,
            skippedAt: entry?.at || null,
          };
        });

        const completedCount = steps.filter((s) => s.completed).length;
        const skippedCount = steps.filter((s) => !s.completed && s.skipped).length;

        res.json({
          steps,
          totalSteps: STEP_IDS.length,
          completedCount,
          skippedCount,
          dismissed,
        });
      } catch (error) {
        log.error({ err: error }, "failed to fetch getting-started status");
        res.status(500).json({ message: "Falha ao buscar status do guia inicial" });
      }
    }
  );
}
```

- [ ] **Step 3: Verify TypeScript compiles (client only, server errors are pre-existing)**

```bash
npx tsc --noEmit 2>&1 | grep "getting-started"
```

Expected: no output (no errors in the new file).

- [ ] **Step 4: Commit**

```bash
git add server/routes/getting-started.ts
git commit -m "feat(getting-started): server route file with GET /api/getting-started/status"
```

---

## Task 2: Server mutations + route registration

**Files:**
- Modify: `server/routes/getting-started.ts` (add 3 more endpoints)
- Modify: `server/routes/index.ts` (register routes)

- [ ] **Step 1: Add POST /api/getting-started/skip inside `registerGettingStartedRoutes`, after the GET endpoint**

```typescript
  app.post(
    "/api/getting-started/skip",
    isAuthenticatedWithPasswordCheck,
    requireAdmin,
    async (req: any, res) => {
      try {
        const { stepId, reason = "" } = req.body ?? {};
        if (!(STEP_IDS as readonly string[]).includes(stepId)) {
          return res.status(400).json({ message: "Step ID inválido" });
        }
        if (!SKIPPABLE.has(stepId as StepId)) {
          return res.status(400).json({ message: "Esta etapa não pode ser ignorada" });
        }
        const existing = await storage.getSetting("gettingStarted.skipped");
        const map = (existing?.value ?? {}) as Record<string, any>;
        map[stepId] = { at: new Date().toISOString(), reason: String(reason) };
        await storage.setSetting("gettingStarted.skipped", map, req.user.id);
        res.json({ ok: true });
      } catch (error) {
        log.error({ err: error }, "failed to skip step");
        res.status(500).json({ message: "Falha ao ignorar etapa" });
      }
    }
  );
```

- [ ] **Step 2: Add DELETE /api/getting-started/skip/:stepId**

```typescript
  app.delete(
    "/api/getting-started/skip/:stepId",
    isAuthenticatedWithPasswordCheck,
    requireAdmin,
    async (req: any, res) => {
      try {
        const { stepId } = req.params;
        if (!(STEP_IDS as readonly string[]).includes(stepId)) {
          return res.status(400).json({ message: "Step ID inválido" });
        }
        const existing = await storage.getSetting("gettingStarted.skipped");
        const map = (existing?.value ?? {}) as Record<string, any>;
        delete map[stepId];
        await storage.setSetting("gettingStarted.skipped", map, req.user.id);
        res.json({ ok: true });
      } catch (error) {
        log.error({ err: error }, "failed to unskip step");
        res.status(500).json({ message: "Falha ao retomar etapa" });
      }
    }
  );
```

- [ ] **Step 3: Add POST /api/getting-started/dismiss**

```typescript
  app.post(
    "/api/getting-started/dismiss",
    isAuthenticatedWithPasswordCheck,
    requireAdmin,
    async (req: any, res) => {
      try {
        const [completion, skippedSetting] = await Promise.all([
          computeCompletion(),
          storage.getSetting("gettingStarted.skipped"),
        ]);
        const skipped = (skippedSetting?.value ?? {}) as Record<string, any>;
        const allDone = STEP_IDS.every((id) => completion[id] || Boolean(skipped[id]));
        if (!allDone) {
          return res
            .status(400)
            .json({ message: "Há etapas pendentes — conclua ou ignore-as antes de fechar" });
        }
        await storage.setSetting(
          "gettingStarted.dismissed",
          { at: new Date().toISOString() },
          req.user.id
        );
        res.json({ ok: true });
      } catch (error) {
        log.error({ err: error }, "failed to dismiss getting-started");
        res.status(500).json({ message: "Falha ao fechar guia" });
      }
    }
  );
```

- [ ] **Step 4: Register routes in `server/routes/index.ts`**

Add import at the top of `server/routes/index.ts` alongside the other route imports:
```typescript
import { registerGettingStartedRoutes } from "./getting-started";
```

Add the call inside `registerRoutes`, after `registerActionPlanRoutes(app);`:
```typescript
  registerGettingStartedRoutes(app);
```

- [ ] **Step 5: Verify TypeScript compiles**

```bash
npx tsc --noEmit 2>&1 | grep "getting-started"
```

Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add server/routes/getting-started.ts server/routes/index.ts
git commit -m "feat(getting-started): POST skip/unskip, POST dismiss, register routes"
```

---

## Task 3: Frontend page `/getting-started`

**Files:**
- Create: `client/src/pages/getting-started.tsx`

- [ ] **Step 1: Create the file with types, metadata constants, and imports**

```tsx
// client/src/pages/getting-started.tsx
import { useState } from "react";
import { Link } from "wouter";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useWebSocket } from "@/lib/websocket";
import { apiRequest } from "@/lib/queryClient";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import { AdminBreadcrumb } from "@/components/admin/admin-breadcrumb";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  CheckCircle,
  Circle,
  MinusCircle,
  PartyPopper,
  Rocket,
} from "lucide-react";
import { format } from "date-fns";
import { ptBR } from "date-fns/locale";
import { cn } from "@/lib/utils";

interface StepStatus {
  id: string;
  completed: boolean;
  skippable: boolean;
  skipped: boolean;
  skipReason: string | null;
  skippedAt: string | null;
}

interface GettingStartedStatus {
  steps: StepStatus[];
  totalSteps: number;
  completedCount: number;
  skippedCount: number;
  dismissed: boolean;
}

const STEP_META: Record<string, { label: string; description: string; href: string }> = {
  appliance_config: {
    label: "Configurações do Appliance",
    description: "Defina o nome e localização do sistema",
    href: "/admin/configuracoes",
  },
  mensageria: {
    label: "Mensageria",
    description: "Configure o provedor de e-mail para notificações",
    href: "/admin/mensageria",
  },
  first_user: {
    label: "Primeiro Usuário Nominal",
    description: "Crie um usuário operacional (não administrador)",
    href: "/admin/usuarios",
  },
  journey_attack_surface: {
    label: "Jornada: Attack Surface",
    description: "Configure uma jornada de mapeamento de superfície de ataque",
    href: "/journeys",
  },
  journey_ad_security: {
    label: "Jornada: AD Security",
    description: "Configure uma jornada de segurança do Active Directory",
    href: "/journeys",
  },
  journey_edr_av: {
    label: "Jornada: EDR/AV",
    description: "Configure uma jornada de detecção e resposta de endpoint",
    href: "/journeys",
  },
  journey_web_application: {
    label: "Jornada: Web Application",
    description: "Configure uma jornada de varredura de aplicações web",
    href: "/journeys",
  },
  journey_api_security: {
    label: "Jornada: API Security",
    description: "Configure uma jornada de segurança de APIs",
    href: "/journeys",
  },
  notification_policy: {
    label: "Política de Notificação",
    description: "Configure alertas e destinatários para eventos de segurança",
    href: "/admin/notificacoes",
  },
  action_plan: {
    label: "Plano de Ação",
    description: "Crie um plano de remediação para ameaças identificadas",
    href: "/action-plan",
  },
};

const GROUPS = [
  {
    label: "CONFIGURAÇÃO INICIAL",
    subtitle: undefined as string | undefined,
    stepIds: ["appliance_config", "mensageria", "first_user"],
  },
  {
    label: "JORNADAS",
    subtitle: "Ignore etapas fora do escopo do seu contrato",
    stepIds: [
      "journey_attack_surface",
      "journey_ad_security",
      "journey_edr_av",
      "journey_web_application",
      "journey_api_security",
    ],
  },
  {
    label: "OPERAÇÃO",
    subtitle: undefined as string | undefined,
    stepIds: ["notification_policy", "action_plan"],
  },
];
```

- [ ] **Step 2: Add the SkipDialog sub-component (after the constants)**

```tsx
function SkipDialog({
  open,
  onOpenChange,
  onConfirm,
  isPending,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onConfirm: (reason: string) => void;
  isPending: boolean;
}) {
  const [reason, setReason] = useState("");

  const handleConfirm = () => {
    onConfirm(reason);
    setReason("");
  };

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Ignorar esta etapa?</AlertDialogTitle>
          <AlertDialogDescription>
            Esta etapa ficará marcada como ignorada. Você pode retomá-la a qualquer momento.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <div className="space-y-2 py-2">
          <Label htmlFor="skip-reason">Motivo (opcional)</Label>
          <Textarea
            id="skip-reason"
            placeholder="Ex: Fora do escopo do contrato"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={2}
          />
        </div>
        <AlertDialogFooter>
          <AlertDialogCancel onClick={() => setReason("")}>Cancelar</AlertDialogCancel>
          <AlertDialogAction onClick={handleConfirm} disabled={isPending}>
            {isPending ? "Ignorando..." : "Ignorar etapa"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
```

- [ ] **Step 3: Add the StepCard sub-component (after SkipDialog)**

```tsx
function StepCard({
  step,
  dismissed,
  onSkip,
  onUnskip,
}: {
  step: StepStatus;
  dismissed: boolean;
  onSkip: (stepId: string) => void;
  onUnskip: (stepId: string) => void;
}) {
  const meta = STEP_META[step.id];
  if (!meta) return null;

  const isCompleted = step.completed;
  const isSkipped = !step.completed && step.skipped;
  const isPending = !step.completed && !step.skipped;

  return (
    <Card
      className={cn(
        "transition-colors",
        isCompleted && "border-green-500/30 bg-green-500/5",
        isSkipped && "border-amber-500/30 bg-amber-500/5"
      )}
    >
      <CardContent className="flex items-center gap-4 p-4">
        {/* State icon */}
        <div className="flex-shrink-0">
          {isCompleted && <CheckCircle className="h-5 w-5 text-green-500" />}
          {isSkipped && <MinusCircle className="h-5 w-5 text-amber-500" />}
          {isPending && <Circle className="h-5 w-5 text-muted-foreground" />}
        </div>

        {/* Label + description */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="font-medium text-sm">{meta.label}</p>
            {isCompleted && (
              <Badge className="bg-green-600/20 text-green-700 dark:text-green-400 border-green-500/30 text-xs">
                Concluída
              </Badge>
            )}
            {isSkipped && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Badge className="bg-amber-600/20 text-amber-700 dark:text-amber-400 border-amber-500/30 text-xs cursor-default">
                    Ignorada
                  </Badge>
                </TooltipTrigger>
                <TooltipContent>
                  {step.skipReason ? (
                    <span>
                      {step.skipReason}
                      {step.skippedAt && (
                        <>
                          {" — "}
                          {format(new Date(step.skippedAt), "dd/MM/yyyy", { locale: ptBR })}
                        </>
                      )}
                    </span>
                  ) : step.skippedAt ? (
                    <span>
                      Ignorada em{" "}
                      {format(new Date(step.skippedAt), "dd/MM/yyyy", { locale: ptBR })}
                    </span>
                  ) : (
                    <span>Sem justificativa</span>
                  )}
                </TooltipContent>
              </Tooltip>
            )}
            {isPending && (
              <Badge variant="secondary" className="text-xs">
                Pendente
              </Badge>
            )}
          </div>
          <p className="text-sm text-muted-foreground mt-0.5">{meta.description}</p>
        </div>

        {/* Actions */}
        {!dismissed && (
          <div className="flex items-center gap-2 flex-shrink-0">
            {isSkipped && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => onUnskip(step.id)}
              >
                Retomar
              </Button>
            )}
            {isPending && step.skippable && (
              <Button
                variant="ghost"
                size="sm"
                className="text-muted-foreground"
                onClick={() => onSkip(step.id)}
              >
                Ignorar
              </Button>
            )}
            <Link href={meta.href}>
              <Button
                variant={isCompleted ? "outline" : "default"}
                size="sm"
              >
                {isCompleted ? "Revisar" : "Configurar"} →
              </Button>
            </Link>
          </div>
        )}
        {dismissed && (
          <Link href={meta.href}>
            <Button variant="outline" size="sm">
              Revisar →
            </Button>
          </Link>
        )}
      </CardContent>
    </Card>
  );
}
```

- [ ] **Step 4: Add the main GettingStarted page component (after StepCard)**

```tsx
export default function GettingStarted() {
  const { connected } = useWebSocket();
  const queryClient = useQueryClient();

  const [skipTargetId, setSkipTargetId] = useState<string | null>(null);

  const { data: status, isLoading } = useQuery<GettingStartedStatus>({
    queryKey: ["/api/getting-started/status"],
    staleTime: 30_000,
  });

  const skipMutation = useMutation({
    mutationFn: ({ stepId, reason }: { stepId: string; reason: string }) =>
      apiRequest("POST", "/api/getting-started/skip", { stepId, reason }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["/api/getting-started/status"] }),
  });

  const unskipMutation = useMutation({
    mutationFn: (stepId: string) =>
      apiRequest("DELETE", `/api/getting-started/skip/${stepId}`, undefined),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["/api/getting-started/status"] }),
  });

  const dismissMutation = useMutation({
    mutationFn: () => apiRequest("POST", "/api/getting-started/dismiss", {}),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["/api/getting-started/status"] }),
  });

  const handleSkipConfirm = (reason: string) => {
    if (!skipTargetId) return;
    skipMutation.mutate({ stepId: skipTargetId, reason });
    setSkipTargetId(null);
  };

  const progressValue = status
    ? ((status.completedCount + status.skippedCount) / status.totalSteps) * 100
    : 0;

  const allDone = status
    ? status.steps.every((s) => s.completed || s.skipped)
    : false;

  const dismissed = status?.dismissed ?? false;

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <main className="flex-1 overflow-auto">
        <TopBar
          title="Primeiros Passos"
          subtitle="Configure o SamurEye para começar a operar"
          wsConnected={connected}
        />
        <div className="p-6 space-y-8 max-w-3xl">
          <AdminBreadcrumb page="Primeiros Passos" />

          {/* Progress header */}
          {status && (
            <div className="space-y-2">
              <Progress value={progressValue} className="h-2" />
              <p className="text-sm text-muted-foreground">
                {status.completedCount} de {status.totalSteps} etapas concluídas
                {status.skippedCount > 0 &&
                  ` · ${status.skippedCount} ignorada${status.skippedCount > 1 ? "s" : ""}`}
              </p>
            </div>
          )}

          {/* Completion banner */}
          {allDone && !dismissed && (
            <Card className="border-green-500/30 bg-green-500/5">
              <CardContent className="flex items-center gap-4 p-5">
                <PartyPopper className="h-8 w-8 text-green-500 flex-shrink-0" />
                <div className="flex-1">
                  <p className="font-semibold text-foreground">Configuração concluída!</p>
                  <p className="text-sm text-muted-foreground">
                    O SamurEye está pronto para operar.
                  </p>
                </div>
                <Button
                  onClick={() => dismissMutation.mutate()}
                  disabled={dismissMutation.isPending}
                  variant="outline"
                >
                  {dismissMutation.isPending ? "Fechando..." : "Fechar este guia"}
                </Button>
              </CardContent>
            </Card>
          )}

          {/* Step groups */}
          {isLoading && (
            <div className="text-center py-12 text-muted-foreground">
              Carregando...
            </div>
          )}

          {status &&
            GROUPS.map((group) => {
              const groupSteps = group.stepIds
                .map((id) => status.steps.find((s) => s.id === id))
                .filter(Boolean) as StepStatus[];

              return (
                <div key={group.label} className="space-y-3">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                      {group.label}
                    </p>
                    {group.subtitle && (
                      <p className="text-xs text-muted-foreground mt-0.5">
                        {group.subtitle}
                      </p>
                    )}
                  </div>
                  <div className="space-y-2">
                    {groupSteps.map((step) => (
                      <StepCard
                        key={step.id}
                        step={step}
                        dismissed={dismissed}
                        onSkip={(id) => setSkipTargetId(id)}
                        onUnskip={(id) => unskipMutation.mutate(id)}
                      />
                    ))}
                  </div>
                </div>
              );
            })}
        </div>
      </main>

      <SkipDialog
        open={Boolean(skipTargetId)}
        onOpenChange={(open) => !open && setSkipTargetId(null)}
        onConfirm={handleSkipConfirm}
        isPending={skipMutation.isPending}
      />
    </div>
  );
}
```

- [ ] **Step 5: Verify TypeScript for the new page**

```bash
npx tsc --noEmit 2>&1 | grep "getting-started"
```

Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add client/src/pages/getting-started.tsx
git commit -m "feat(getting-started): frontend page with step cards, skip modal, dismiss banner"
```

---

## Task 4: Wire up — App.tsx + sidebar + admin hub tile

**Files:**
- Modify: `client/src/App.tsx`
- Modify: `client/src/components/layout/sidebar.tsx`
- Modify: `client/src/pages/admin.tsx`

- [ ] **Step 1: Add the route in `client/src/App.tsx`**

Add import alongside the other admin page imports (after the existing admin imports):
```typescript
import GettingStarted from "@/pages/getting-started";
```

Add the route inside the authenticated Router's `<Switch>`, after the `/admin/auditoria` route:
```tsx
<Route path="/getting-started">{() => <AdminRoute component={GettingStarted} />}</Route>
```

- [ ] **Step 2: Update `client/src/components/layout/sidebar.tsx` — add import and query**

Add `Rocket` and `Fragment` to the existing imports:

```typescript
// In the lucide-react import block, add Rocket:
import {
  Shield,
  ShieldCheck,
  Server,
  Key,
  Route,
  Clock,
  AlertTriangle,
  List,
  Monitor,
  FileBarChart,
  ClipboardList,
  LayoutDashboard,
  Rocket,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
```

Add `Fragment` to the React import (top of file):
```typescript
import { useState, useEffect, Fragment } from "react";
```

Add a new query for getting-started status inside the `Sidebar` component (after the `criticalThreats` query):

```tsx
  const { data: gettingStartedStatus } = useQuery<{
    steps: Array<{ id: string; completed: boolean; skipped: boolean }>;
    dismissed: boolean;
  }>({
    queryKey: ["/api/getting-started/status"],
    enabled: isAdmin,
    staleTime: 30_000,
    refetchInterval: 60_000,
  });

  const gettingStartedPendingCount =
    gettingStartedStatus?.steps.filter((s) => !s.completed && !s.skipped).length ?? 0;

  const showGettingStarted = isAdmin && !gettingStartedStatus?.dismissed;
```

- [ ] **Step 3: Update the NavLink component's badge logic to support the Getting Started badge**

Inside `function NavLink`, change the `showBadge` line from:
```tsx
const showBadge = item.label === "Ameaças" && criticalThreatCount > 0;
```
to:
```tsx
const showBadge =
  (item.label === "Ameaças" && criticalThreatCount > 0) ||
  (item.href === "/getting-started" && gettingStartedPendingCount > 0);
const badgeValue =
  item.href === "/getting-started" ? gettingStartedPendingCount : criticalThreatCount;
```

Then replace all uses of `criticalThreatCount` inside the badge JSX with `badgeValue`:
- `{criticalThreatCount}` → `{badgeValue}` (the badge span inside the non-collapsed branch)

- [ ] **Step 4: Inject "Primeiros Passos" between group[0] (Postura) and group[1] (Inventário)**

In the `{navGroups.map((group, gi) => (` section, wrap the existing `<div>` in a `<Fragment>` and inject the Getting Started item after `gi === 0`:

Replace:
```tsx
        {navGroups.map((group, gi) => (
          <div key={gi} className={cn("px-2", gi > 0 && "mt-3")}>
```
with:
```tsx
        {navGroups.map((group, gi) => (
          <Fragment key={gi}>
          <div className={cn("px-2", gi > 0 && "mt-3")}>
```

And after the closing `</div>` of the group's `<div>` (and before the closing of the `Fragment`), add:
```tsx
          </div>
          {gi === 0 && showGettingStarted && (
            <div className="px-2">
              <div className="border-t border-sidebar-border my-2 mx-1" />
              <div className="space-y-0.5">
                <NavLink
                  item={{
                    href: "/getting-started",
                    label: "Primeiros Passos",
                    icon: Rocket,
                  }}
                />
              </div>
            </div>
          )}
          </Fragment>
```

- [ ] **Step 5: Add the "Primeiros Passos" tile to `client/src/pages/admin.tsx`**

Add `Rocket` to the lucide-react imports in `admin.tsx`:
```typescript
import {
  Users,
  Smartphone,
  SlidersHorizontal,
  ShieldCheck,
  Mail,
  Bell,
  CreditCard,
  History,
  Rocket,
  ChevronRight,
} from "lucide-react";
```

Add `useQuery` import:
```typescript
import { useQuery } from "@tanstack/react-query";
```

Add the query inside the `Admin` component, before the return:
```tsx
  const { data: gsStatus } = useQuery<{
    completedCount: number;
    skippedCount: number;
    totalSteps: number;
    dismissed: boolean;
  }>({
    queryKey: ["/api/getting-started/status"],
    staleTime: 30_000,
  });

  const gsDone = gsStatus
    ? gsStatus.completedCount + gsStatus.skippedCount >= gsStatus.totalSteps
    : false;

  const gsProgress = gsStatus
    ? Math.round(
        ((gsStatus.completedCount + gsStatus.skippedCount) / gsStatus.totalSteps) * 100
      )
    : 0;
```

In the groups render, after the `{group.items.map(...)}` grid but still inside the Plataforma group, add the Getting Started tile. Change the grid render section to:

```tsx
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {group.items.map((item) => (
                  <Link key={item.href} href={item.href}>
                    <Card className="cursor-pointer hover:shadow-md transition-shadow hover:border-border/80">
                      <CardContent className="flex items-center gap-4 p-5">
                        <div className={cn("flex-shrink-0", item.iconClass)}>
                          <item.icon className="h-8 w-8" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="font-semibold text-sm">{item.title}</p>
                          <p className="text-sm text-muted-foreground truncate">
                            {item.description}
                          </p>
                        </div>
                        <ChevronRight className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                      </CardContent>
                    </Card>
                  </Link>
                ))}
                {group.label === "Plataforma" && (
                  <Link href="/getting-started">
                    <Card className="cursor-pointer hover:shadow-md transition-shadow hover:border-border/80">
                      <CardContent className="flex items-center gap-4 p-5">
                        <div className="flex-shrink-0 text-amber-600">
                          <Rocket className="h-8 w-8" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="font-semibold text-sm">Primeiros Passos</p>
                          <p className="text-sm text-muted-foreground truncate">
                            {gsDone
                              ? "Configuração concluída"
                              : gsStatus
                              ? `${gsStatus.completedCount} de ${gsStatus.totalSteps} etapas concluídas`
                              : "Guia de configuração inicial"}
                          </p>
                          {gsStatus && (
                            <div className="mt-2 h-1.5 w-full rounded-full bg-muted overflow-hidden">
                              <div
                                className={cn(
                                  "h-full rounded-full transition-all",
                                  gsDone ? "bg-green-500" : "bg-primary"
                                )}
                                style={{ width: `${gsProgress}%` }}
                              />
                            </div>
                          )}
                        </div>
                        <ChevronRight className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                      </CardContent>
                    </Card>
                  </Link>
                )}
              </div>
```

- [ ] **Step 6: Verify TypeScript compiles (client only)**

```bash
npx tsc --noEmit 2>&1 | grep "client/src"
```

Expected: no output (zero client-side errors).

- [ ] **Step 7: Commit**

```bash
git add client/src/App.tsx client/src/components/layout/sidebar.tsx client/src/pages/admin.tsx
git commit -m "feat(getting-started): wire up route, sidebar badge, admin hub tile"
```
