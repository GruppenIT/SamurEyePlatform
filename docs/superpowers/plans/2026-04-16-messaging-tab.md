# Mensageria Tab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the "SMTP" tab in `/settings` with a "Mensageria" tab that exposes three provider options (Google Workspace, Microsoft 365, SMTP tradicional) with inline setup guides, a "Configurado" check badge on the persisted provider, and a preserved test-email flow.

**Architecture:** Purely frontend change. Two small new components under `client/src/components/settings/` (provider card, provider guide) plus targeted edits inside `client/src/pages/settings.tsx`. No backend, schema, or API changes — the existing `authType` contract (`password` / `oauth2_gmail` / `oauth2_microsoft`) remains. Provider selection drives a radio-group UI and sets host/port/TLS defaults for the OAuth providers.

**Tech Stack:** React 18 + TypeScript, shadcn/ui primitives (Card, Collapsible, Button, Input, Label, Separator, Switch, Tabs), Tailwind CSS, `lucide-react` icons, inline SVG brand marks. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-04-16-messaging-tab-design.md`.

**Verification approach:** The repo has no client-side test harness (Vitest is configured for `server/**/*.test.ts` only). Per-task verification uses `npm run check` (TypeScript) as the automated gate and explicit manual QA steps against the dev server for the final integration task.

---

## File Structure

| Path | Action | Responsibility |
| --- | --- | --- |
| `client/src/components/settings/provider-logos.tsx` | Create | Inline SVG React components for Google and Microsoft brand marks |
| `client/src/components/settings/MessagingProviderCard.tsx` | Create | Radio-role button card with logo, title, subtitle, "Configurado" badge, selected/hover/focus states |
| `client/src/components/settings/MessagingProviderGuide.tsx` | Create | Collapsible with static per-provider setup steps |
| `client/src/pages/settings.tsx` | Modify | Rename SMTP tab → Mensageria, replace tab body, add provider-driven defaults |

## Preserved `data-testid`s

All of these must survive the refactor (rendered conditionally when the matching provider is selected):

`input-smtp-host`, `input-smtp-port`, `switch-smtp-secure`, `input-auth-user`, `input-auth-password`, `input-oauth2-client-id`, `input-oauth2-client-secret`, `input-oauth2-refresh-token`, `input-oauth2-tenant-id`, `input-from-email`, `input-from-name`, `button-save-email-settings`, `input-test-email`, `button-test-email`.

New test ids added by this plan:
- `card-messaging-provider-google`
- `card-messaging-provider-microsoft`
- `card-messaging-provider-smtp`
- `badge-messaging-provider-configured-{google|microsoft|smtp}`
- `button-messaging-provider-guide-toggle`

---

## Task 1: Scaffold provider logo SVGs

**Files:**
- Create: `client/src/components/settings/provider-logos.tsx`

- [ ] **Step 1: Create the file with Google and Microsoft SVG components**

Write this content to `client/src/components/settings/provider-logos.tsx`:

```tsx
import type { SVGProps } from "react";

export function GoogleWorkspaceLogo(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg" aria-hidden="true" {...props}>
      <path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3a12 12 0 0 1-11.3 8A12 12 0 1 1 24 12a12 12 0 0 1 8.5 3.3l5.7-5.7A20 20 0 1 0 44 24a20 20 0 0 0-.4-3.5z"/>
      <path fill="#FF3D00" d="M6.3 14.7l6.6 4.8A12 12 0 0 1 24 12a12 12 0 0 1 8.5 3.3l5.7-5.7A20 20 0 0 0 6.3 14.7z"/>
      <path fill="#4CAF50" d="M24 44c5 0 9.7-1.9 13.2-5l-6.1-5.2A12 12 0 0 1 24 36a12 12 0 0 1-11.3-8l-6.5 5A20 20 0 0 0 24 44z"/>
      <path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3a12 12 0 0 1-4.2 5.8l6.1 5.2A20 20 0 0 0 44 24a20 20 0 0 0-.4-3.5z"/>
    </svg>
  );
}

export function MicrosoftLogo(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true" {...props}>
      <rect x="1" y="1" width="10" height="10" fill="#F25022"/>
      <rect x="13" y="1" width="10" height="10" fill="#7FBA00"/>
      <rect x="1" y="13" width="10" height="10" fill="#00A4EF"/>
      <rect x="13" y="13" width="10" height="10" fill="#FFB900"/>
    </svg>
  );
}
```

- [ ] **Step 2: Type-check**

Run: `npm run check`
Expected: PASS (no new errors).

- [ ] **Step 3: Commit**

```bash
git add client/src/components/settings/provider-logos.tsx
git commit -m "feat(settings): add Google and Microsoft brand logo SVG components"
```

---

## Task 2: Build `MessagingProviderCard`

**Files:**
- Create: `client/src/components/settings/MessagingProviderCard.tsx`

- [ ] **Step 1: Write the component**

Write this content to `client/src/components/settings/MessagingProviderCard.tsx`:

```tsx
import type { ReactNode } from "react";
import { CheckCircle2 } from "lucide-react";
import { cn } from "@/lib/utils";

export interface MessagingProviderCardProps {
  id: "google" | "microsoft" | "smtp";
  name: string;
  subtitle: string;
  logo: ReactNode;
  selected: boolean;
  configured: boolean;
  onSelect: () => void;
}

export function MessagingProviderCard({
  id,
  name,
  subtitle,
  logo,
  selected,
  configured,
  onSelect,
}: MessagingProviderCardProps) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={selected}
      aria-label={`Provedor ${name}${configured ? " (configurado)" : ""}`}
      onClick={onSelect}
      data-testid={`card-messaging-provider-${id}`}
      className={cn(
        "relative flex min-h-[120px] w-full flex-col items-start gap-2 rounded-lg border bg-card p-4 text-left transition-colors",
        "hover:border-primary/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        selected
          ? "border-primary bg-primary/5 ring-2 ring-primary"
          : "border-border",
      )}
    >
      {configured && (
        <span
          data-testid={`badge-messaging-provider-configured-${id}`}
          className="absolute right-3 top-3 inline-flex items-center gap-1 rounded-full bg-green-500/10 px-2 py-0.5 text-xs font-medium text-green-600 dark:text-green-400"
        >
          <CheckCircle2 className="h-3.5 w-3.5" />
          Configurado
        </span>
      )}
      <div className="flex h-8 w-8 items-center justify-center">{logo}</div>
      <div>
        <div className="text-base font-semibold leading-tight">{name}</div>
        <div className="mt-0.5 text-sm text-muted-foreground">{subtitle}</div>
      </div>
    </button>
  );
}
```

- [ ] **Step 2: Type-check**

Run: `npm run check`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add client/src/components/settings/MessagingProviderCard.tsx
git commit -m "feat(settings): add MessagingProviderCard component"
```

---

## Task 3: Build `MessagingProviderGuide`

**Files:**
- Create: `client/src/components/settings/MessagingProviderGuide.tsx`

- [ ] **Step 1: Write the component with static per-provider steps**

Write this content to `client/src/components/settings/MessagingProviderGuide.tsx`:

```tsx
import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";

type Provider = "google" | "microsoft" | "smtp";

interface Step {
  text: string;
}

const GUIDES: Record<Provider, { title: string; steps: Step[] }> = {
  google: {
    title: "Como configurar no Google Workspace",
    steps: [
      { text: "Crie um projeto no Google Cloud Console e habilite a Gmail API." },
      { text: "Configure a tela de consentimento OAuth e publique o app em produção (evita expiração do refresh token em 7 dias)." },
      { text: "Crie uma credencial OAuth 2.0 do tipo \"Aplicativo da Web\" e adicione um URI de redirecionamento válido." },
      { text: "Copie o Client ID e o Client Secret gerados." },
      { text: "Obtenha o Refresh Token via OAuth 2.0 Playground com o escopo https://mail.google.com/ e a opção \"Use your own OAuth credentials\"." },
      { text: "Cole Client ID, Client Secret e Refresh Token nos campos abaixo e salve." },
    ],
  },
  microsoft: {
    title: "Como configurar no Microsoft 365",
    steps: [
      { text: "No Azure Portal, registre um app em Microsoft Entra ID > Registros de aplicativo." },
      { text: "Na visão geral, copie o Application (Client) ID e o Directory (Tenant) ID." },
      { text: "Em Certificados e segredos, crie um Client Secret e copie o valor imediatamente." },
      { text: "Em Permissões de API, adicione a permissão de aplicativo SMTP.SendAsApp (Office 365 Exchange Online) e conceda consentimento do admin." },
      { text: "Registre o Service Principal no Exchange Online via PowerShell (New-ServicePrincipal) e conceda SendAs à caixa remetente." },
      { text: "No Microsoft 365 Admin Center, habilite SMTP Autenticado para a caixa de correio remetente." },
      { text: "Obtenha o Refresh Token via Authorization Code Flow com scope offline_access https://outlook.office365.com/.default." },
      { text: "Cole Client ID, Tenant ID, Client Secret e Refresh Token nos campos abaixo e salve." },
    ],
  },
  smtp: {
    title: "Como configurar no seu servidor SMTP",
    steps: [
      { text: "Obtenha do seu provedor: servidor SMTP, porta (normalmente 587) e se TLS/SSL é exigido." },
      { text: "Identifique ou crie um usuário com permissão para enviar e-mails pelo servidor." },
      { text: "Gere uma senha de aplicativo se o provedor exigir autenticação de dois fatores." },
      { text: "Preencha host, porta, TLS, usuário e senha nos campos abaixo e salve." },
    ],
  },
};

export interface MessagingProviderGuideProps {
  provider: Provider;
  defaultOpen?: boolean;
  fullGuideHref?: string;
}

export function MessagingProviderGuide({
  provider,
  defaultOpen = true,
  fullGuideHref,
}: MessagingProviderGuideProps) {
  const [open, setOpen] = useState(defaultOpen);
  const { title, steps } = GUIDES[provider];

  return (
    <Collapsible open={open} onOpenChange={setOpen} className="rounded-lg border border-border bg-muted/30">
      <CollapsibleTrigger
        data-testid="button-messaging-provider-guide-toggle"
        className="flex w-full items-center justify-between gap-2 rounded-t-lg px-4 py-3 text-left text-sm font-medium hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <span>{title}</span>
        {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
      </CollapsibleTrigger>
      <CollapsibleContent className="px-4 pb-4">
        <ol className="list-decimal space-y-2 pl-5 text-sm text-muted-foreground">
          {steps.map((step, index) => (
            <li key={index}>{step.text}</li>
          ))}
        </ol>
        {fullGuideHref && (
          <a
            href={fullGuideHref}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-3 inline-block text-sm font-medium text-primary hover:underline"
          >
            Ver guia completo
          </a>
        )}
      </CollapsibleContent>
    </Collapsible>
  );
}
```

- [ ] **Step 2: Type-check**

Run: `npm run check`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add client/src/components/settings/MessagingProviderGuide.tsx
git commit -m "feat(settings): add MessagingProviderGuide component with per-provider steps"
```

---

## Task 4: Rename tab SMTP → Mensageria

**Files:**
- Modify: `client/src/pages/settings.tsx:353-356` (TabsTrigger), `:597-598` (TabsContent value)

- [ ] **Step 1: Replace the SMTP `TabsTrigger`**

Open `client/src/pages/settings.tsx` and find the block at lines 353–356:

```tsx
                <TabsTrigger value="smtp" className="flex items-center gap-2">
                  <Globe className="h-4 w-4" />
                  SMTP
                </TabsTrigger>
```

Replace it with:

```tsx
                <TabsTrigger value="mensageria" className="flex items-center gap-2">
                  <Inbox className="h-4 w-4" />
                  Mensageria
                </TabsTrigger>
```

- [ ] **Step 2: Update the Lucide import**

Find the existing `lucide-react` import near the top of the file and add `Inbox` to the list (keep `Globe` if still used elsewhere — verify with `grep Globe client/src/pages/settings.tsx`; remove only if no remaining references). Example:

```tsx
import { Inbox, /* existing icons */ } from "lucide-react";
```

- [ ] **Step 3: Rename the TabsContent value**

Find:

```tsx
              {/* Tab: SMTP */}
              <TabsContent value="smtp">
```

Replace with:

```tsx
              {/* Tab: Mensageria */}
              <TabsContent value="mensageria">
```

- [ ] **Step 4: Type-check**

Run: `npm run check`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add client/src/pages/settings.tsx
git commit -m "feat(settings): rename SMTP tab to Mensageria"
```

---

## Task 5: Introduce provider selection state and helpers

**Files:**
- Modify: `client/src/pages/settings.tsx` — imports and `SettingsPage` component body

- [ ] **Step 1: Import new components**

Add to the import section at the top of `client/src/pages/settings.tsx`:

```tsx
import { MessagingProviderCard } from "@/components/settings/MessagingProviderCard";
import { MessagingProviderGuide } from "@/components/settings/MessagingProviderGuide";
import { GoogleWorkspaceLogo, MicrosoftLogo } from "@/components/settings/provider-logos";
import { ServerCog } from "lucide-react";
```

(If `ServerCog` is not already imported from `lucide-react`, add it to the existing import statement.)

- [ ] **Step 2: Add a helper to map `authType` ↔ provider id**

Immediately below the existing `const [testEmail, setTestEmail] = useState('');` line (≈ line 88), add:

```tsx
type MessagingProvider = "google" | "microsoft" | "smtp";

const PROVIDER_TO_AUTH_TYPE: Record<MessagingProvider, "oauth2_gmail" | "oauth2_microsoft" | "password"> = {
  google: "oauth2_gmail",
  microsoft: "oauth2_microsoft",
  smtp: "password",
};

const AUTH_TYPE_TO_PROVIDER: Record<"oauth2_gmail" | "oauth2_microsoft" | "password", MessagingProvider> = {
  oauth2_gmail: "google",
  oauth2_microsoft: "microsoft",
  password: "smtp",
};

const PROVIDER_DEFAULTS: Record<MessagingProvider, { smtpHost: string; smtpPort: number; smtpSecure: boolean } | null> = {
  google: { smtpHost: "smtp.gmail.com", smtpPort: 587, smtpSecure: true },
  microsoft: { smtpHost: "smtp.office365.com", smtpPort: 587, smtpSecure: true },
  smtp: null,
};
```

- [ ] **Step 3: Derive the selected provider from `emailSettings.authType`**

Below the helpers just added, add:

```tsx
const selectedProvider: MessagingProvider = AUTH_TYPE_TO_PROVIDER[emailSettings.authType];
```

- [ ] **Step 4: Add a `configured` predicate driven by `emailSettingsData`**

Below `selectedProvider`, add:

```tsx
function isProviderConfigured(provider: MessagingProvider): boolean {
  if (!emailSettingsData) return false;
  if (emailSettingsData.authType !== PROVIDER_TO_AUTH_TYPE[provider]) return false;
  if (provider === "smtp") {
    return Boolean(emailSettingsData.authUser);
  }
  return Boolean(emailSettingsData.oauth2ClientId);
}
```

- [ ] **Step 5: Add handlers to switch providers (with defaults) and manage radio-group keyboard navigation**

Below `isProviderConfigured`, add:

```tsx
const PROVIDER_ORDER: MessagingProvider[] = ["google", "microsoft", "smtp"];

const handleSelectProvider = (provider: MessagingProvider) => {
  setEmailSettings((prev) => {
    const defaults = PROVIDER_DEFAULTS[provider];
    return {
      ...prev,
      authType: PROVIDER_TO_AUTH_TYPE[provider],
      smtpHost: defaults ? defaults.smtpHost : prev.smtpHost,
      smtpPort: defaults ? defaults.smtpPort : prev.smtpPort,
      smtpSecure: defaults ? defaults.smtpSecure : prev.smtpSecure,
    };
  });
};

const handleProviderKeyDown = (provider: MessagingProvider) =>
  (event: React.KeyboardEvent<HTMLButtonElement>) => {
    const keys = ["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"];
    if (!keys.includes(event.key)) return;
    event.preventDefault();
    const currentIndex = PROVIDER_ORDER.indexOf(provider);
    const delta = event.key === "ArrowRight" || event.key === "ArrowDown" ? 1 : -1;
    const nextIndex = (currentIndex + delta + PROVIDER_ORDER.length) % PROVIDER_ORDER.length;
    const nextProvider = PROVIDER_ORDER[nextIndex];
    handleSelectProvider(nextProvider);
    const nextCard = document.querySelector<HTMLButtonElement>(
      `[data-testid="card-messaging-provider-${nextProvider}"]`,
    );
    nextCard?.focus();
  };
```

(The `React.KeyboardEvent` type comes from the top-level `import * as React from "react"` or a named `KeyboardEvent` import — use whichever pattern already exists in `settings.tsx`; if the file imports the default React namespace, `React.KeyboardEvent` works without a new import.)

- [ ] **Step 6: Type-check**

Run: `npm run check`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add client/src/pages/settings.tsx
git commit -m "feat(settings): add provider selection state and defaults for messaging tab"
```

---

## Task 6: Rewrite the Mensageria `TabsContent` body

**Files:**
- Modify: `client/src/pages/settings.tsx` — body of `<TabsContent value="mensageria">` (previously lines 598–835)

- [ ] **Step 1: Replace the entire tab body**

Locate the block that starts at `<TabsContent value="mensageria">` and ends at the matching `</TabsContent>` (just before `{/* Tab: Subscrição */}`). Replace the whole block with:

```tsx
              {/* Tab: Mensageria */}
              <TabsContent value="mensageria">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center space-x-2">
                      <Inbox className="h-5 w-5" />
                      <span>Mensageria</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    <p className="text-sm text-muted-foreground">
                      Configure como o SamurEye envia e-mails de notificação. Escolha um provedor e preencha suas credenciais.
                    </p>

                    <div
                      role="radiogroup"
                      aria-label="Provedor de mensageria"
                      className="grid grid-cols-1 gap-4 md:grid-cols-3"
                    >
                      <MessagingProviderCard
                        id="google"
                        name="Google Workspace"
                        subtitle="OAuth2 — recomendado"
                        logo={<GoogleWorkspaceLogo className="h-7 w-7" />}
                        selected={selectedProvider === "google"}
                        configured={isProviderConfigured("google")}
                        onSelect={() => handleSelectProvider("google")}
                        tabIndex={selectedProvider === "google" ? 0 : -1}
                        onKeyDown={handleProviderKeyDown("google")}
                      />
                      <MessagingProviderCard
                        id="microsoft"
                        name="Microsoft 365"
                        subtitle="OAuth2 — recomendado"
                        logo={<MicrosoftLogo className="h-7 w-7" />}
                        selected={selectedProvider === "microsoft"}
                        configured={isProviderConfigured("microsoft")}
                        onSelect={() => handleSelectProvider("microsoft")}
                        tabIndex={selectedProvider === "microsoft" ? 0 : -1}
                        onKeyDown={handleProviderKeyDown("microsoft")}
                      />
                      <MessagingProviderCard
                        id="smtp"
                        name="SMTP tradicional"
                        subtitle="Usuário e senha — legado"
                        logo={<ServerCog className="h-7 w-7 text-muted-foreground" />}
                        selected={selectedProvider === "smtp"}
                        configured={isProviderConfigured("smtp")}
                        onSelect={() => handleSelectProvider("smtp")}
                        tabIndex={selectedProvider === "smtp" ? 0 : -1}
                        onKeyDown={handleProviderKeyDown("smtp")}
                      />
                    </div>

                    <MessagingProviderGuide
                      provider={selectedProvider}
                      defaultOpen={!isProviderConfigured(selectedProvider)}
                    />

                    {selectedProvider === "smtp" ? (
                      <div className="space-y-4">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div>
                            <Label htmlFor="smtpHost">Servidor SMTP</Label>
                            <Input
                              id="smtpHost"
                              placeholder="smtp.seudominio.com"
                              value={emailSettings.smtpHost}
                              onChange={(e) => handleEmailSettingChange('smtpHost', e.target.value)}
                              data-testid="input-smtp-host"
                            />
                          </div>
                          <div>
                            <Label htmlFor="smtpPort">Porta</Label>
                            <Input
                              id="smtpPort"
                              type="number"
                              placeholder="587"
                              value={emailSettings.smtpPort}
                              onChange={(e) => handleEmailSettingChange('smtpPort', parseInt(e.target.value))}
                              data-testid="input-smtp-port"
                            />
                          </div>
                        </div>

                        <div className="flex items-center justify-between">
                          <div>
                            <Label htmlFor="smtpSecure">Conexão Segura (TLS/SSL)</Label>
                            <p className="text-sm text-muted-foreground">
                              Usar conexão criptografada (recomendado)
                            </p>
                          </div>
                          <Switch
                            id="smtpSecure"
                            checked={emailSettings.smtpSecure}
                            onCheckedChange={(checked) => handleEmailSettingChange('smtpSecure', checked)}
                            data-testid="switch-smtp-secure"
                          />
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div>
                            <Label htmlFor="authUser">Usuário SMTP</Label>
                            <Input
                              id="authUser"
                              placeholder="usuario@dominio.com"
                              value={emailSettings.authUser}
                              onChange={(e) => handleEmailSettingChange('authUser', e.target.value)}
                              data-testid="input-auth-user"
                            />
                          </div>
                          <div>
                            <Label htmlFor="authPassword">Senha SMTP</Label>
                            <Input
                              id="authPassword"
                              type="password"
                              placeholder="••••••••"
                              value={emailSettings.authPasswordPlain}
                              onChange={(e) => handleEmailSettingChange('authPasswordPlain', e.target.value)}
                              data-testid="input-auth-password"
                            />
                            <p className="text-sm text-muted-foreground mt-1">
                              Deixe em branco para manter a senha atual
                            </p>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        <p className="rounded-md border border-dashed border-border bg-muted/20 px-3 py-2 text-xs text-muted-foreground">
                          Servidor: <code>{emailSettings.smtpHost}</code> · Porta: <code>{emailSettings.smtpPort}</code> · TLS {emailSettings.smtpSecure ? "ativo" : "desativado"}
                        </p>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div>
                            <Label htmlFor="oauth2ClientId">Client ID</Label>
                            <Input
                              id="oauth2ClientId"
                              placeholder={selectedProvider === "google" ? "seu-client-id.apps.googleusercontent.com" : "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"}
                              value={emailSettings.oauth2ClientId}
                              onChange={(e) => handleEmailSettingChange('oauth2ClientId', e.target.value)}
                              data-testid="input-oauth2-client-id"
                            />
                          </div>
                          <div>
                            <Label htmlFor="oauth2ClientSecret">Client Secret</Label>
                            <Input
                              id="oauth2ClientSecret"
                              type="password"
                              placeholder="••••••••"
                              value={emailSettings.oauth2ClientSecretPlain}
                              onChange={(e) => handleEmailSettingChange('oauth2ClientSecretPlain', e.target.value)}
                              data-testid="input-oauth2-client-secret"
                            />
                            <p className="text-sm text-muted-foreground mt-1">
                              Deixe em branco para manter o secret atual
                            </p>
                          </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div>
                            <Label htmlFor="oauth2RefreshToken">Refresh Token</Label>
                            <Input
                              id="oauth2RefreshToken"
                              type="password"
                              placeholder="••••••••"
                              value={emailSettings.oauth2RefreshTokenPlain}
                              onChange={(e) => handleEmailSettingChange('oauth2RefreshTokenPlain', e.target.value)}
                              data-testid="input-oauth2-refresh-token"
                            />
                            <p className="text-sm text-muted-foreground mt-1">
                              Deixe em branco para manter o token atual
                            </p>
                          </div>
                          {selectedProvider === "microsoft" && (
                            <div>
                              <Label htmlFor="oauth2TenantId">Tenant ID</Label>
                              <Input
                                id="oauth2TenantId"
                                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                                value={emailSettings.oauth2TenantId}
                                onChange={(e) => handleEmailSettingChange('oauth2TenantId', e.target.value)}
                                data-testid="input-oauth2-tenant-id"
                              />
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    <Separator />

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <Label htmlFor="fromEmail">E-mail Remetente</Label>
                        <Input
                          id="fromEmail"
                          type="email"
                          placeholder="notificacoes@empresa.com"
                          value={emailSettings.fromEmail}
                          onChange={(e) => handleEmailSettingChange('fromEmail', e.target.value)}
                          data-testid="input-from-email"
                        />
                      </div>
                      <div>
                        <Label htmlFor="fromName">Nome do Remetente</Label>
                        <Input
                          id="fromName"
                          placeholder="SamurEye Notificações"
                          value={emailSettings.fromName}
                          onChange={(e) => handleEmailSettingChange('fromName', e.target.value)}
                          data-testid="input-from-name"
                        />
                      </div>
                    </div>

                    <Separator />

                    <div className="flex gap-2">
                      <Button
                        onClick={handleSaveEmailSettings}
                        disabled={saveEmailSettingsMutation.isPending}
                        data-testid="button-save-email-settings"
                      >
                        <Save className="mr-2 h-4 w-4" />
                        {saveEmailSettingsMutation.isPending ? 'Salvando...' : 'Salvar configurações de mensageria'}
                      </Button>
                    </div>

                    <Separator />

                    <div className="space-y-2">
                      <Label htmlFor="testEmail">Testar envio</Label>
                      <div className="flex gap-2">
                        <Input
                          id="testEmail"
                          type="email"
                          placeholder="seu-email@dominio.com"
                          value={testEmail}
                          onChange={(e) => setTestEmail(e.target.value)}
                          data-testid="input-test-email"
                        />
                        <Button
                          variant="outline"
                          onClick={handleTestEmail}
                          disabled={testEmailMutation.isPending}
                          data-testid="button-test-email"
                        >
                          {testEmailMutation.isPending ? 'Enviando...' : 'Enviar teste'}
                        </Button>
                      </div>
                      <p className="text-sm text-muted-foreground">
                        Envie um e-mail de teste para verificar se as configurações estão corretas
                      </p>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>
```

- [ ] **Step 2: Type-check**

Run: `npm run check`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add client/src/pages/settings.tsx
git commit -m "feat(settings): replace SMTP form with provider-driven Mensageria layout"
```

---

## Task 7: Ensure initial provider selection matches persisted data

**Files:**
- Modify: `client/src/pages/settings.tsx` — `useEffect` that hydrates `emailSettings` from `emailSettingsData` (currently lines 204–221)

This useEffect already sets `authType` from the server payload, which in turn drives `selectedProvider` via the derived mapping. Verify and harden:

- [ ] **Step 1: Confirm the hydration effect sets a sensible default when no data exists**

In `client/src/pages/settings.tsx`, locate:

```tsx
  // Load email settings when data is available
  useEffect(() => {
    if (emailSettingsData && emailSettingsData.smtpHost) {
      setEmailSettings({
        smtpHost: emailSettingsData.smtpHost,
        smtpPort: emailSettingsData.smtpPort,
        smtpSecure: emailSettingsData.smtpSecure,
        authType: emailSettingsData.authType || 'password',
        authUser: emailSettingsData.authUser || '',
        authPasswordPlain: '',
        oauth2ClientId: emailSettingsData.oauth2ClientId || '',
        oauth2ClientSecretPlain: '',
        oauth2RefreshTokenPlain: '',
        oauth2TenantId: emailSettingsData.oauth2TenantId || '',
        fromEmail: emailSettingsData.fromEmail,
        fromName: emailSettingsData.fromName,
      });
    }
  }, [emailSettingsData]);
```

Leave the effect as-is — when `emailSettingsData` is null/empty, the initial `useState` default keeps `authType: 'password'` which resolves to the SMTP card being preselected. Confirm this matches the spec's "when nothing is configured, no card shows the Configurado badge but a provider is pre-selected so the form is usable."

If the preference is "nothing pre-selected when no data exists," replace the initial `useState` `authType` value (≈ line 77) with `'password'` and add a separate boolean `hasUserPickedProvider` — **do not do this unless explicitly requested**; the default pre-selection is preferred for usability per the spec.

- [ ] **Step 2: Type-check**

Run: `npm run check`
Expected: PASS (no code changes in this task unless the optional branch above is taken).

- [ ] **Step 3: No commit needed (no code change)**

---

## Task 8: Manual QA against the dev server

**Files:** None — verification only.

- [ ] **Step 1: Start the dev server**

Run: `npm run dev`
Expected: Server boots; Vite prints the local URL.

- [ ] **Step 2: Load `/settings` as a global administrator and open the Mensageria tab**

Verification checklist (check each):

1. Tab labeled **Mensageria** with an `Inbox` icon; no "SMTP" label remains in the tab bar.
2. Three cards visible: **Google Workspace**, **Microsoft 365**, **SMTP tradicional**, each showing the correct logo.
3. One card is pre-selected (ring + tinted background) matching the persisted `authType` — or SMTP by default when nothing is configured.
4. If the backend returned credentials, that provider's card shows the green **Configurado** badge.
5. Clicking each card toggles selection; form fields below update accordingly.
6. Google and Microsoft cards show the read-only host/port/TLS summary with correct values (`smtp.gmail.com:587 TLS ativo` / `smtp.office365.com:587 TLS ativo`).
7. SMTP card shows editable host/port/TLS/user/password fields.
8. "Como configurar no {provedor}" panel toggles open/closed via its header; steps are legible.
9. "Salvar configurações de mensageria" triggers the toast "Configurações de e-mail salvas com sucesso" on success.
10. "Enviar teste" with a valid address triggers the toast "E-mail de teste enviado com sucesso" on success.
11. Keyboard: Tab enters the radio group, arrow keys/Tab move between cards, Space/Enter selects.
12. No console errors during these interactions.

- [ ] **Step 3: Smoke-check other Settings tabs**

Click through Geral, Segurança, AD Security, Notificações, Subscrição — confirm none of them show regressions (labels, save button, form fields render normally).

- [ ] **Step 4: Stop the dev server**

Ctrl-C the `npm run dev` process.

- [ ] **Step 5: Final commit if any QA fix was required**

If any QA fix was applied, commit it with:

```bash
git add -A
git commit -m "fix(settings): QA follow-up for Mensageria tab"
```

Otherwise no commit.

---

## Self-Review Notes (performed against the spec)

- **Spec §2 Objetivo** → covered by Tasks 1–6.
- **Spec §4 Mapeamento** → encoded in `PROVIDER_TO_AUTH_TYPE` and `PROVIDER_DEFAULTS` (Task 5).
- **Spec §5.1 Cabeçalho** → Task 6 body.
- **Spec §5.2 Grid de cards** → Tasks 2 and 6.
- **Spec §5.3.1 Guide** → Task 3 (component) + Task 6 (mount) with `defaultOpen` tied to `!isProviderConfigured(selectedProvider)`.
- **Spec §5.3.2 Campos por provedor** → Task 6 conditional branches.
- **Spec §5.3.3 Remetente** → Task 6 common block.
- **Spec §5.4 Ações** → Task 6 (Save + Test).
- **Spec §6 Fluxo de dados / "Configurado"** → Task 5 (`isProviderConfigured`) + Task 7 (hydration).
- **Spec §7 Estados visuais** → Task 2 (card classes).
- **Spec §8 Componentes e `data-testid`s** → preserved list in the top-of-plan checklist; Task 6 keeps every existing id.
- **Spec §9 Critérios de aceite** → covered by Task 8 checklist.
- **Spec §10 Riscos** → `fullGuideHref` is **not** passed in Task 6, so no risk of a broken link; the "Ver guia completo" link is wired into the component API but intentionally left unused until Vite static serving is validated — adding it later is a one-line change.
