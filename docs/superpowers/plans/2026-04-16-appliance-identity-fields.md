# Appliance Identity Fields Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three editable fields (Appliance Name, Location Type, Location Detail) to the Geral tab of `/settings`, persist them via the existing key-value settings store, emit them in the heartbeat `identity` block, and trigger an out-of-band heartbeat after save.

**Architecture:** Same-app change in the SamurEye appliance. `shared/schema.ts` gets a new optional `identity` block on `heartbeatRequestSchema`. `telemetryService` reads the three keys via `storage.getSetting()` and includes the block when any key exists. A new admin-only endpoint `POST /api/appliance/heartbeat-now` triggers `subscriptionService.sendHeartbeat()` fire-and-forget. The client extends `formData` with the three strings and calls the new endpoint after a successful global save.

**Tech Stack:** Zod (schema), Drizzle (settings table), React + shadcn/ui (Input, Select, Textarea, Separator), `@/lib/queryClient` `apiRequest` helper, `useMutation`.

**Spec:** `docs/superpowers/specs/2026-04-16-appliance-identity-fields-design.md`.

**Verification approach:** `npm run check` for TypeScript (baseline has pre-existing unrelated errors — only count new ones from our files) + `npx vite build` for build health. Runtime QA happens via the existing production deploy flow; there is no client test harness.

---

## File Structure

| Path | Action | Responsibility |
| --- | --- | --- |
| `shared/schema.ts` | Modify | Add optional `identity` block to `heartbeatRequestSchema` |
| `server/services/telemetryService.ts` | Modify | Collect `identity` block from settings storage |
| `server/routes/admin.ts` | Modify | Add `POST /api/appliance/heartbeat-now` endpoint |
| `client/src/pages/settings.tsx` | Modify | Extend `SettingsForm`, render 3 new fields, trigger out-of-band heartbeat after save |

Settings keys used (strings stored in the `settings` table):
- `applianceName` — max 100
- `locationType` — one of `""`, `matriz`, `filial`, `datacenter`, `nuvem`, `outro`
- `locationDetail` — max 200

---

## Task 1: Extend heartbeat schema with optional identity block

**Files:**
- Modify: `shared/schema.ts:1051-1101` (`heartbeatRequestSchema`)

- [ ] **Step 1: Add the `identity` block to `heartbeatRequestSchema`**

Open `shared/schema.ts`. Find the block that starts with `export const heartbeatRequestSchema = z.object({` (around line 1051). Locate the field `commandResults: z.array(commandResultSchema).optional(),` which is the last field before the closing `});`. Immediately above that line, add:

```ts
  identity: z.object({
    applianceName: z.string().max(100),
    locationType: z.string().max(50),
    locationDetail: z.string().max(200),
  }).optional(),
```

The final schema should read (context, not a literal replacement):

```ts
export const heartbeatRequestSchema = z.object({
  applianceId: z.string(),
  version: z.string(),
  timestamp: z.string().datetime(),
  system: z.object({ /* unchanged */ }).optional(),
  performance: z.object({ /* unchanged */ }),
  threatStats: z.object({ /* unchanged */ }),
  usage: z.object({ /* unchanged */ }),
  identity: z.object({
    applianceName: z.string().max(100),
    locationType: z.string().max(50),
    locationDetail: z.string().max(200),
  }).optional(),
  commandResults: z.array(commandResultSchema).optional(),
});
```

- [ ] **Step 2: Type-check**

Run: `npm run check 2>&1 | grep "shared/schema" | grep -v "/usr/lib" | head`
Expected: no lines (no errors from `shared/schema.ts`).

- [ ] **Step 3: Commit**

```bash
git add shared/schema.ts
git commit -m "feat(schema): add optional identity block to heartbeat request"
```

---

## Task 2: Emit identity block from telemetryService

**Files:**
- Modify: `server/services/telemetryService.ts:1-40` (imports + `collect` method) plus a new helper method

- [ ] **Step 1: Import `storage`**

At the top of `server/services/telemetryService.ts`, below the existing imports, add:

```ts
import { storage } from '../storage';
```

If the import already exists (verify with grep), skip this step.

- [ ] **Step 2: Add the private helper `collectIdentity`**

Inside the `TelemetryService` class, immediately after the `collect(applianceId)` method (around line 40), insert this method:

```ts
  private async collectIdentity(): Promise<HeartbeatRequest['identity'] | undefined> {
    const [nameSetting, typeSetting, detailSetting] = await Promise.all([
      storage.getSetting('applianceName'),
      storage.getSetting('locationType'),
      storage.getSetting('locationDetail'),
    ]);

    // Omit the block entirely when the user has never configured any of the three fields.
    // A setting that exists with value "" means the user explicitly cleared it and the
    // console should receive "" (which it converts to NULL).
    if (!nameSetting && !typeSetting && !detailSetting) {
      return undefined;
    }

    const asString = (s: typeof nameSetting): string => {
      if (!s) return '';
      return typeof s.value === 'string' ? s.value : '';
    };

    return {
      applianceName: asString(nameSetting),
      locationType: asString(typeSetting),
      locationDetail: asString(detailSetting),
    };
  }
```

- [ ] **Step 3: Include identity in the payload returned by `collect`**

Replace the body of `collect(applianceId)` (lines ~23-40) with this version, which adds `identity` to the Promise.all + return shape:

```ts
  async collect(applianceId: string): Promise<HeartbeatRequest> {
    const [system, performance, threatStats, usage, identity] = await Promise.all([
      this.collectSystem(),
      this.collectPerformance(),
      this.collectThreatStats(),
      this.collectUsage(),
      this.collectIdentity(),
    ]);

    const payload: HeartbeatRequest = {
      applianceId,
      version: APP_VERSION,
      timestamp: new Date().toISOString(),
      system,
      performance,
      threatStats,
      usage,
    };

    if (identity) {
      payload.identity = identity;
    }

    return payload;
  }
```

- [ ] **Step 4: Type-check**

Run: `npm run check 2>&1 | grep "telemetryService" | grep -v "/usr/lib" | head`
Expected: no lines.

- [ ] **Step 5: Commit**

```bash
git add server/services/telemetryService.ts
git commit -m "feat(telemetry): emit identity block in heartbeat when appliance fields are set"
```

---

## Task 3: Out-of-band heartbeat endpoint

**Files:**
- Modify: `server/routes/admin.ts` — add new route near the other `/api/email-settings` routes

- [ ] **Step 1: Locate where to add the route**

Open `server/routes/admin.ts`. Find the end of the `POST /api/email-settings/test` handler (around line 219, just before `// Subscription management routes` comment). Insert the new handler immediately after that closing brace and before the subscription section.

- [ ] **Step 2: Verify `subscriptionService` is importable**

Search for an existing import of `subscriptionService` in `admin.ts`:

Run: `grep -n "subscriptionService" /opt/samureye/server/routes/admin.ts`

If there is NO import, add at the top of the file (next to the other service imports, after `emailService`):

```ts
import { subscriptionService } from '../services/subscriptionService';
```

Check how `subscriptionService` is exported from `/opt/samureye/server/services/subscriptionService.ts`:

Run: `grep -n "export" /opt/samureye/server/services/subscriptionService.ts | head`

Use the same import shape (named vs default) that matches the export. If it is `export const subscriptionService = ...` use the named import above; if it is `export default new SubscriptionService()` change the import to `import subscriptionService from '../services/subscriptionService';`.

- [ ] **Step 3: Add the handler**

Paste this block just before the `// ═══════════════════════════════════════════════════════════\n  // Subscription management routes` comment:

```ts
  app.post('/api/appliance/heartbeat-now', isAuthenticatedWithPasswordCheck, requireAdmin, async (req, res) => {
    try {
      const sub = await storage.getSubscription();
      if (!sub || !sub.apiKey) {
        return res.status(400).json({ message: "Subscription não configurada — heartbeat indisponível" });
      }

      // Fire-and-forget: respond 202 immediately, let sendHeartbeat finish in background.
      // Any failure is already logged inside subscriptionService and visible in next cached status.
      subscriptionService.sendHeartbeat().catch((err) => {
        log.warn({ err }, 'out-of-band heartbeat failed');
      });

      res.status(202).json({ message: "Heartbeat disparado" });
    } catch (error) {
      log.error({ err: error }, 'failed to trigger out-of-band heartbeat');
      res.status(500).json({ message: "Falha ao disparar heartbeat" });
    }
  });
```

- [ ] **Step 4: Type-check**

Run: `npm run check 2>&1 | grep "admin.ts" | grep -v "/usr/lib" | grep -v "Property 'role'" | head`
Expected: no lines (the pre-existing `Property 'role'` errors on `useAuth` do not apply to `admin.ts`; any line here would be new).

- [ ] **Step 5: Commit**

```bash
git add server/routes/admin.ts
git commit -m "feat(admin): add POST /api/appliance/heartbeat-now for out-of-band sync"
```

---

## Task 4: Extend client SettingsForm with identity fields

**Files:**
- Modify: `client/src/pages/settings.tsx` — `SettingsForm` interface (line 33) and `formData` default state (line 85)

- [ ] **Step 1: Extend the `SettingsForm` interface**

Find (around line 33):

```ts
interface SettingsForm {
  // System Settings
  systemName: string;
  systemDescription: string;
  systemTimezone: string;

  // Security Settings
  sessionTimeout: number;
  maxConcurrentJobs: number;
  jobTimeout: number;

  // AD Hygiene Thresholds
  adPasswordAgeThreshold: number;
  adInactiveUserThreshold: number;

  // Notification Settings
  enableEmailAlerts: boolean;
  alertEmail: string;
  criticalThreatAlert: boolean;
  jobFailureAlert: boolean;
}
```

Replace with:

```ts
interface SettingsForm {
  // System Settings
  systemName: string;
  systemDescription: string;
  systemTimezone: string;

  // Appliance Identity & Location
  applianceName: string;
  locationType: string;
  locationDetail: string;

  // Security Settings
  sessionTimeout: number;
  maxConcurrentJobs: number;
  jobTimeout: number;

  // AD Hygiene Thresholds
  adPasswordAgeThreshold: number;
  adInactiveUserThreshold: number;

  // Notification Settings
  enableEmailAlerts: boolean;
  alertEmail: string;
  criticalThreatAlert: boolean;
  jobFailureAlert: boolean;
}
```

- [ ] **Step 2: Extend the `formData` initial state**

Find (around line 85):

```ts
  const [formData, setFormData] = useState<SettingsForm>({
    systemName: 'SamurEye',
    systemDescription: 'Plataforma de Validação de Exposição Adversarial',
    systemTimezone: 'America/Sao_Paulo',
    sessionTimeout: 3600,
    maxConcurrentJobs: 3,
    jobTimeout: 1800,
    adPasswordAgeThreshold: 90,
    adInactiveUserThreshold: 180,
    enableEmailAlerts: false,
    alertEmail: '',
    criticalThreatAlert: true,
    jobFailureAlert: true,
  });
```

Replace with:

```ts
  const [formData, setFormData] = useState<SettingsForm>({
    systemName: 'SamurEye',
    systemDescription: 'Plataforma de Validação de Exposição Adversarial',
    systemTimezone: 'America/Sao_Paulo',
    applianceName: '',
    locationType: '',
    locationDetail: '',
    sessionTimeout: 3600,
    maxConcurrentJobs: 3,
    jobTimeout: 1800,
    adPasswordAgeThreshold: 90,
    adInactiveUserThreshold: 180,
    enableEmailAlerts: false,
    alertEmail: '',
    criticalThreatAlert: true,
    jobFailureAlert: true,
  });
```

- [ ] **Step 3: Type-check**

Run: `npm run check 2>&1 | grep "settings.tsx" | grep -v "Property 'role'" | head`
Expected: no new errors (only the four pre-existing `Property 'role'` lines, unchanged).

- [ ] **Step 4: Commit**

```bash
git add client/src/pages/settings.tsx
git commit -m "feat(settings): extend SettingsForm with appliance identity fields"
```

---

## Task 5: Render the three new fields in the Geral tab

**Files:**
- Modify: `client/src/pages/settings.tsx` — inside `<TabsContent value="geral">` → `<CardContent className="space-y-4">`, after the `Timeout de Sessão` block

- [ ] **Step 1: Insert the new UI block**

Open `client/src/pages/settings.tsx`. Locate the `Timeout de Sessão` block inside the Geral tab (search for `input-session-timeout`). That block looks like:

```tsx
                    <div>
                      <Label htmlFor="sessionTimeout">Timeout de Sessão (segundos)</Label>
                      <Input
                        id="sessionTimeout"
                        type="number"
                        value={formData.sessionTimeout}
                        onChange={(e) => handleInputChange('sessionTimeout', parseInt(e.target.value))}
                        data-testid="input-session-timeout"
                      />
                      <p className="text-sm text-muted-foreground mt-1">
                        Tempo para expirar sessões inativas
                      </p>
                    </div>
```

Immediately AFTER the closing `</div>` of that block and BEFORE `</CardContent>`, add the following JSX:

```tsx
                    <Separator />

                    <div>
                      <h3 className="text-base font-semibold">Identificação e Localização</h3>
                      <p className="mt-2 rounded-md border border-dashed border-border bg-muted/20 px-3 py-2 text-sm text-muted-foreground">
                        Estes campos são enviados ao console no próximo heartbeat e usados para organizar seus appliances por localização.
                      </p>
                    </div>

                    <div>
                      <Label htmlFor="applianceName">Nome do Appliance</Label>
                      <Input
                        id="applianceName"
                        value={formData.applianceName}
                        maxLength={100}
                        onChange={(e) => handleInputChange('applianceName', e.target.value)}
                        placeholder="sam-sp-dc01"
                        data-testid="input-appliance-name"
                      />
                      <p className="text-sm text-muted-foreground mt-1">
                        Um apelido amigável para identificar este appliance (ex.: sam-sp-dc01). Aparece no dashboard do cliente e na página de detalhe.
                      </p>
                    </div>

                    <div>
                      <Label htmlFor="locationType">Tipo de Localização</Label>
                      <Select
                        value={formData.locationType || '__none__'}
                        onValueChange={(value) => handleInputChange('locationType', value === '__none__' ? '' : value)}
                      >
                        <SelectTrigger id="locationType" data-testid="select-location-type">
                          <SelectValue placeholder="Não definido" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="__none__">Não definido</SelectItem>
                          <SelectItem value="matriz">Matriz</SelectItem>
                          <SelectItem value="filial">Filial</SelectItem>
                          <SelectItem value="datacenter">Datacenter</SelectItem>
                          <SelectItem value="nuvem">Nuvem</SelectItem>
                          <SelectItem value="outro">Outro</SelectItem>
                        </SelectContent>
                      </Select>
                      <p className="text-sm text-muted-foreground mt-1">
                        Escolha o tipo que melhor descreve onde este appliance está instalado. Appliances com o mesmo tipo e detalhe de localização serão agrupados juntos no painel do cliente.
                      </p>
                    </div>

                    <div>
                      <Label htmlFor="locationDetail">Detalhes da Localização</Label>
                      <Input
                        id="locationDetail"
                        value={formData.locationDetail}
                        maxLength={200}
                        onChange={(e) => handleInputChange('locationDetail', e.target.value)}
                        placeholder="DC Equinix SP4 - Sala 3"
                        data-testid="input-location-detail"
                      />
                      <p className="text-sm text-muted-foreground mt-1">
                        Complemento que torna a localização única (ex.: São Paulo - Av. Paulista 1000, Filial Curitiba, AWS us-east-1, DC Equinix SP4). Appliances que compartilham o mesmo tipo e o mesmo detalhe são exibidos no mesmo grupo no dashboard.
                      </p>
                    </div>
```

Note on the `__none__` sentinel: shadcn's `Select` does not allow `SelectItem` with `value=""` (it throws at runtime). Use `__none__` as the UI sentinel for the empty state; `handleInputChange` normalizes it back to `""` before storing in `formData`. The saved setting value is `""`, matching the spec.

- [ ] **Step 2: Verify `Separator` is imported**

Run: `grep -n "import.*Separator" /opt/samureye/client/src/pages/settings.tsx`

If no result, add `Separator` to the existing shadcn imports at the top of the file — find the line that imports from `@/components/ui/separator` and keep it; otherwise add `import { Separator } from "@/components/ui/separator";` after the other shadcn imports.

- [ ] **Step 3: Type-check**

Run: `npm run check 2>&1 | grep "settings.tsx" | grep -v "Property 'role'" | head`
Expected: no new errors.

- [ ] **Step 4: Commit**

```bash
git add client/src/pages/settings.tsx
git commit -m "feat(settings): render appliance identity fields in Geral tab"
```

---

## Task 6: Trigger out-of-band heartbeat after a successful save

**Files:**
- Modify: `client/src/pages/settings.tsx` — `handleSave` function (around line 257, search for `const handleSave`)

- [ ] **Step 1: Locate `handleSave`**

Find the function that matches:

```tsx
  const handleSave = async () => {
    const updates = Object.entries(formData).map(([key, value]) => ({ key, value }));

    try {
      await Promise.all(
        updates.map(update => updateSettingMutation.mutateAsync(update))
      );

      toast({
        title: "Sucesso",
        description: "Configurações salvas com sucesso",
      });
    } catch (error) {
      // Error handling is done in the mutation
    }
  };
```

- [ ] **Step 2: Fire the out-of-band heartbeat after success**

Replace that function with:

```tsx
  const handleSave = async () => {
    const updates = Object.entries(formData).map(([key, value]) => ({ key, value }));

    try {
      await Promise.all(
        updates.map(update => updateSettingMutation.mutateAsync(update))
      );

      toast({
        title: "Sucesso",
        description: "Configurações salvas com sucesso",
      });

      // Fire-and-forget: notify the console immediately with the new identity block.
      // Any failure is logged server-side and a regular heartbeat will reconcile on the next cycle.
      apiRequest('POST', '/api/appliance/heartbeat-now').catch(() => {
        /* swallowed on purpose — non-blocking */
      });
    } catch (error) {
      // Error handling is done in the mutation
    }
  };
```

- [ ] **Step 3: Verify `apiRequest` is imported**

Run: `grep -n "apiRequest" /opt/samureye/client/src/pages/settings.tsx | head -3`

The import already exists (used by other mutations in this file). If the grep shows usage but no `import` line, add `import { apiRequest } from "@/lib/queryClient";` near the other `@/lib` imports.

- [ ] **Step 4: Type-check**

Run: `npm run check 2>&1 | grep "settings.tsx" | grep -v "Property 'role'" | head`
Expected: no new errors.

- [ ] **Step 5: Commit**

```bash
git add client/src/pages/settings.tsx
git commit -m "feat(settings): trigger out-of-band heartbeat after Geral save"
```

---

## Task 7: Manual QA and deploy verification

**Files:** None — verification only.

- [ ] **Step 1: Frontend build sanity check**

Run: `set -a && . ./.env && set +a && npx vite build 2>&1 | tail -5`
Expected: `✓ built in <N>s` and no error lines.

- [ ] **Step 2: Type-check one final time**

Run: `npm run check 2>&1 | grep -E "shared/schema|telemetryService|admin.ts|settings.tsx" | grep -v "Property 'role'" | head`
Expected: no lines (only the four pre-existing `Property 'role'` errors on `useAuth` remain across the file).

- [ ] **Step 3: Deploy**

Run: `deploy-samureye`
Expected: `git pull` → `npm run build` → `sudo systemctl restart samureye-api` → `git push` all succeed.

- [ ] **Step 4: Runtime QA checklist**

Load `/settings` in the browser as a global administrator and verify:

1. Aba Geral tem a nova seção "Identificação e Localização" depois do Timeout de Sessão, com callout cinza explicando que os dados vão para o console no próximo heartbeat.
2. Campo Nome do Appliance aceita até 100 caracteres; o helper aparece em português.
3. Select Tipo de Localização mostra 6 opções: Não definido, Matriz, Filial, Datacenter, Nuvem, Outro. Valor "Não definido" é estado válido (ao salvar resulta em string vazia).
4. Campo Detalhes da Localização aceita até 200 caracteres; helper com os exemplos do spec aparece.
5. Preencher os três campos + clicar em "Salvar Alterações" mostra toast "Configurações salvas com sucesso" imediato.
6. Em ~1 minuto, o appliance aparece no grupo correto em `www.samureye.com.br/cliente`.
7. Limpar os três campos (voltar para "Não definido" no select e apagar os textos) + salvar faz o console reclassificar para "Sem localidade" após o próximo heartbeat.
8. Logs do appliance (`journalctl -u samureye-api --since "5 minutes ago"`) mostram "heartbeat OK" após o save, sem erros 4xx/5xx.
9. Nenhuma regressão nas demais abas (Segurança, AD Security, Notificações, Mensageria, Subscrição) ou nos outros campos da aba Geral.

- [ ] **Step 5: If any QA step fails, fix and recommit**

Fix inline, `deploy-samureye` again, re-run the relevant checklist items. Otherwise no commit needed.

---

## Self-Review (performed against spec)

- **Spec §2 Objetivos 1–4** — Task 5 (UI fields) + Task 4 (form state) + Task 2 (identity emission) + Task 6 (out-of-band heartbeat).
- **Spec §4.1 Bloco `identity` no heartbeat** — Task 1 (schema) + Task 2 (emission).
- **Spec §4.2 Validação no cliente** — Task 5 (`maxLength`, sentinel for empty select).
- **Spec §4.3 Endpoint out-of-band** — Task 3.
- **Spec §5 UI layout** — Task 5.
- **Spec §6 Fluxo de salvar** — Task 6.
- **Spec §7 Chaves de settings** — Task 4 (state) + Task 2 (reads those three keys).
- **Spec §8 Arquivos afetados** — Task 1–6 touch exactly the listed files; no others.
- **Spec §9 Critérios de aceite 1–7** — Task 7 QA checklist.
- **Spec §10 Riscos** — Task 3's handler responds 202 before the heartbeat completes and swallows errors client-side.
