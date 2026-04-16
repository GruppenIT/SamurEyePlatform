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
