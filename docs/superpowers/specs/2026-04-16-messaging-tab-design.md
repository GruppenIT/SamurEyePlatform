# Design Spec — Aba "Mensageria" em `/settings`

**Data:** 2026-04-16
**Branch:** `feat/webapp-journey-revisions`
**Autor:** Claude (brainstorming + ui-ux-pro-max)

## 1. Problema

Hoje, em `/settings`, existe uma aba **SMTP** que expõe um único formulário com um `<Select>` de `authType` (password / oauth2_gmail / oauth2_microsoft). O usuário admin precisa:

1. Descobrir sozinho que OAuth2 Gmail ou MS 365 é possível dentro do dropdown.
2. Sair do produto para encontrar como obter Client ID / Secret / Refresh Token.
3. Preencher manualmente host/porta mesmo para provedores cujos valores são bem conhecidos.

Não há pistas visuais de qual provedor está configurado nem instruções contextuais.

## 2. Objetivo

Substituir a aba **SMTP** por uma aba **Mensageria** que:

- Ofereça três opções de provedor lado a lado: **Google Workspace**, **Microsoft 365**, **SMTP tradicional**.
- Mostre um passo a passo contextual (dentro da própria UI) para configurar o lado do provedor de e-mail.
- Marque com um "check" o provedor que está configurado e ativo.
- Mantenha o botão de envio de e-mail de teste.

**Não-objetivos:**

- Não mudar o modelo de dados no backend. Só há um provedor ativo por vez — a UI reflete isso.
- Não adicionar novos provedores (SES, SendGrid, etc.).
- Não tornar a instalação "zero-clique": credenciais OAuth continuam obtidas fora do SamurEye.

## 3. Premissas validadas no código

- `client/src/pages/settings.tsx` — aba `TabsContent value="smtp"` (linhas ~597–835) contém o formulário inteiro e o teste de envio.
- Backend já aceita `authType: 'password' | 'oauth2_gmail' | 'oauth2_microsoft'` em `POST /api/email-settings` (`server/routes/admin.ts` linha 55) e já valida cada fluxo.
- `GET /api/email-settings` retorna campos sensíveis como `'[ENCRYPTED]'` quando preenchidos — é possível derivar "configurado" consultando `authType` + presença de `oauth2ClientId`/`authUser`.
- Documento `OAUTH2_EMAIL_SETUP.md` na raiz contém o passo a passo completo para Gmail e MS 365 em português; será a fonte de verdade do conteúdo inline.

## 4. Mapeamento de provedor → `authType`

| Card na UI           | `authType` enviado | Host padrão          | Porta | TLS |
| -------------------- | ------------------ | -------------------- | ----- | --- |
| Google Workspace     | `oauth2_gmail`     | `smtp.gmail.com`     | 587   | on  |
| Microsoft 365        | `oauth2_microsoft` | `smtp.office365.com` | 587   | on  |
| SMTP tradicional     | `password`         | (editável)           | (edit)| (edit) |

Host/porta/TLS para Google e MS 365 são pré-preenchidos e **read-only** na UI para eliminar erros comuns. O backend continua recebendo e persistindo os valores normalmente.

## 5. Layout

Um único `Card` dentro da `TabsContent value="mensageria"`, composto de quatro blocos verticais:

### 5.1. Cabeçalho
- `CardTitle`: "Mensageria".
- Parágrafo: "Configure como o SamurEye envia e-mails de notificação. Escolha um provedor e preencha suas credenciais."

### 5.2. Grid de provider cards
- `div role="radiogroup" aria-label="Provedor de mensageria"` com `grid grid-cols-1 md:grid-cols-3 gap-4`.
- Cada card é um componente `MessagingProviderCard` renderizado como `<button type="button" role="radio" aria-checked={selected}>`.

Cada card contém:
- Logo: SVG inline oficial simplificado para Google e Microsoft; `lucide-react` `ServerCog` para SMTP. Cor monocromática do tema (não emoji — WCAG `no-emoji-icons`).
- Título (`text-base font-semibold`): "Google Workspace" / "Microsoft 365" / "SMTP tradicional".
- Subtítulo (`text-sm text-muted-foreground`): "OAuth2 — recomendado" / "OAuth2 — recomendado" / "Usuário e senha — legado".
- Badge de status (canto superior direito do card):
  - **Configurado ativo** (`authType` persistido == provedor && credenciais presentes): `CheckCircle2` verde (`text-green-500`) + texto "Configurado". Ícone + texto para não depender só de cor.
  - **Não configurado**: sem badge.
- Estados visuais:
  - Default: `border border-border bg-card`.
  - Hover: `border-primary/50`.
  - Selecionado (`aria-checked=true`): `ring-2 ring-primary border-primary bg-primary/5`.
  - Foco de teclado: `focus-visible:ring-2 focus-visible:ring-ring`.
- Touch target: padding interno mínimo de 16px; altura mínima 120px (≥44px atendido com folga).

Acessibilidade: teclado navega entre cards com setas e Tab (radiogroup), Space/Enter seleciona.

### 5.3. Painel do provedor selecionado

Abaixo do grid, aparecem dois subcomponentes condicionados ao card selecionado:

**5.3.1. `MessagingProviderGuide` (Collapsible shadcn)**
- Cabeçalho: "Como configurar no {provedor}" com chevron.
- Default: aberto se o provedor não está configurado ativo; fechado se está. Estado controlado localmente.
- Corpo: lista ordenada de passos curtos (≤7 itens), derivada de `OAUTH2_EMAIL_SETUP.md`. Conteúdo exato:
  - **Google Workspace** (resumo):
    1. Criar projeto no Google Cloud Console e habilitar Gmail API.
    2. Configurar tela de consentimento OAuth e publicar em produção.
    3. Criar credencial OAuth 2.0 do tipo "Aplicativo da Web".
    4. Copiar Client ID e Client Secret.
    5. Obter Refresh Token via OAuth Playground com escopo `https://mail.google.com/`.
    6. Colar Client ID, Client Secret e Refresh Token nos campos abaixo.
  - **Microsoft 365** (resumo):
    1. Registrar app no Azure Portal (Microsoft Entra ID).
    2. Copiar Application (Client) ID e Directory (Tenant) ID.
    3. Criar Client Secret e copiar o valor antes de sair da página.
    4. Adicionar permissão de aplicativo `SMTP.SendAsApp` no Office 365 Exchange Online e conceder consentimento de admin.
    5. Registrar Service Principal via PowerShell no Exchange Online.
    6. Habilitar SMTP Autenticado para a caixa de correio remetente.
    7. Obter Refresh Token via Authorization Code Flow (scope `offline_access https://outlook.office365.com/.default`).
    8. Colar Client ID, Tenant ID, Client Secret e Refresh Token abaixo.
  - **SMTP tradicional** (resumo):
    1. Obter do provedor de e-mail: servidor, porta (normalmente 587), e se TLS/SSL é exigido.
    2. Criar/identificar um usuário de envio com permissão para enviar e-mails.
    3. Gerar uma senha de aplicativo, se o provedor exigir 2FA.
    4. Preencher host, porta, TLS, usuário e senha abaixo.
- Linha final do guia: link `<a href="/OAUTH2_EMAIL_SETUP.md" target="_blank" rel="noopener">Ver guia completo</a>` — aplicável apenas aos dois cards OAuth2. (Se o arquivo não for web-servido, trocar para link para a documentação pública correspondente — decisão no plano de implementação.)

**5.3.2. Campos de credenciais específicos do provedor**

- **Google Workspace:**
  - Client ID (text)
  - Client Secret (password, placeholder "••••••••", helper "Deixe em branco para manter o secret atual")
  - Refresh Token (password, mesma regra de placeholder)
  - Host/Porta/TLS aparecem em linha compacta read-only: "Servidor: `smtp.gmail.com` · Porta: `587` · TLS ativo".
- **Microsoft 365:**
  - Client ID, Tenant ID (texto)
  - Client Secret, Refresh Token (password com mesma regra)
  - Host/Porta/TLS read-only: "Servidor: `smtp.office365.com` · Porta: `587` · TLS ativo".
- **SMTP tradicional:**
  - Host, Porta (editáveis)
  - Switch TLS/SSL (editável)
  - Usuário SMTP, Senha SMTP (password com regra "deixe em branco…")

**5.3.3. Remetente (comum aos três)**
- E-mail Remetente (email)
- Nome do Remetente (text)

### 5.4. Ações

- Botão primário: "Salvar configurações de mensageria" (`data-testid="button-save-email-settings"`).
- Separator.
- Bloco "Testar envio": label + input de e-mail + botão secundário "Enviar teste" (`variant="outline"`, `data-testid="button-test-email"`), como já existe hoje.

## 6. Fluxo de dados

- Carregamento: `GET /api/email-settings` → se `data.authType` existe e campos-chave preenchidos, marca o card correspondente com badge "Configurado" e seleciona-o por default; caso contrário, nenhum card selecionado e o painel inferior mostra apenas uma dica ("Selecione um provedor acima para começar").
- Seleção de card: setar `emailSettings.authType` localmente + aplicar defaults (host/porta/TLS) para Google e MS 365. Credenciais existentes **não** são apagadas — só atualizadas se o usuário digitar algo novo.
- Envio: `POST /api/email-settings` com o mesmo payload atual (schema não muda).
- Teste: `POST /api/email-settings/test` (inalterado).

### Regra de "Configurado"

Um provedor é exibido como **Configurado** quando:

- `emailSettingsData.authType === providerAuthType`, **e**
- Para OAuth2: `oauth2ClientId` não-vazio (o secret/refresh vêm como `[ENCRYPTED]` indicando que foram salvos).
- Para password: `authUser` não-vazio.

Como só um `authType` é persistido por vez, no máximo um card exibe o check simultaneamente. Esta é a interpretação explícita do requisito "quando uma opção for configurada, ela deverá aparecer com um check".

## 7. Estados visuais

| Estado do card                 | Aparência                                         |
| ------------------------------ | ------------------------------------------------- |
| Não selecionado, não config.   | Borda neutra                                      |
| Hover                          | Borda primária a 50% opacidade                    |
| Selecionado (radio)            | `ring-2 ring-primary` + `bg-primary/5`            |
| Configurado (qualquer seleção) | Badge "✓ Configurado" verde visível no card       |
| Foco de teclado                | Focus-ring padrão shadcn                          |

Ao digitar qualquer credencial nova sem salvar ainda, não há mudança no badge (ele reflete o persistido, não o rascunho local).

## 8. Componentes e arquivos afetados

### Novos componentes
- `client/src/components/settings/MessagingProviderCard.tsx` — card de provedor (`{ id, name, subtitle, logo, selected, configured, onSelect }`).
- `client/src/components/settings/MessagingProviderGuide.tsx` — Collapsible com passos por provedor (recebe `provider`).

### Arquivo alterado
- `client/src/pages/settings.tsx`:
  - Renomear `TabsTrigger value="smtp"` → `value="mensageria"` e label "SMTP" → "Mensageria".
  - Substituir todo o conteúdo de `<TabsContent value="smtp">` pelo novo layout usando os dois componentes novos.
  - Preservar todos os `data-testid` existentes para não quebrar possíveis testes E2E (em particular `input-smtp-host`, `input-smtp-port`, `switch-smtp-secure`, `input-auth-user`, `input-auth-password`, `input-oauth2-client-id`, `input-oauth2-client-secret`, `input-oauth2-refresh-token`, `input-oauth2-tenant-id`, `input-from-email`, `input-from-name`, `button-save-email-settings`, `input-test-email`, `button-test-email`).

### Arquivos **não** alterados
- `server/routes/admin.ts`, `server/services/emailService.ts`.
- `shared/schema.ts` (modelo de dados).
- `OAUTH2_EMAIL_SETUP.md` (permanece como fonte de verdade do guia completo).

## 9. Critérios de aceite

1. Em `/settings`, a aba antiga "SMTP" aparece como "Mensageria" com ícone Lucide `Inbox` (evita conflito com `Mail` já usado em "Notificações").
2. A aba mostra três cards: Google Workspace, Microsoft 365, SMTP tradicional.
3. Clicar em um card seleciona-o (borda primária + ring); o painel inferior mostra passo a passo + campos específicos do provedor.
4. O provedor atualmente configurado no backend exibe um check verde + texto "Configurado" no seu card, independente de qual está selecionado.
5. Ao selecionar Google Workspace ou Microsoft 365, host/porta/TLS são mostrados como informação read-only com os valores corretos e são enviados ao backend no Save.
6. "Salvar configurações de mensageria" persiste via `POST /api/email-settings` com o mesmo schema atual; credenciais em branco preservam o valor criptografado existente.
7. "Enviar teste" continua chamando `POST /api/email-settings/test` e exibe toast de sucesso/erro como hoje.
8. Navegação por teclado funciona: Tab chega no grid, setas movem entre cards, Space/Enter seleciona.
9. Sem regressão: a aba não introduz mudanças em Geral, Segurança, AD Security, Notificações ou Subscrição.

## 10. Riscos e mitigações

- **Risco:** Link `/OAUTH2_EMAIL_SETUP.md` pode não ser servido pelo Vite em produção.
  - **Mitigação:** validar no plano de implementação; se não for servido, incluir como arquivo estático em `client/public/` ou omitir o link (o guia resumido inline já cobre o essencial).
- **Risco:** Preservar todos os `data-testid` atuais ao mover DOM. Se um `data-testid` depende de um campo que só existe para o provedor selecionado, o teste precisa selecionar o card primeiro.
  - **Mitigação:** manter os mesmos IDs nos mesmos inputs; no plano de implementação checar `tests/` e `e2e/` antes de alterar.
- **Risco:** Usuário seleciona um card e perde rascunho ao trocar para outro.
  - **Mitigação:** guia + subtexto indicando que trocar de provedor não apaga credenciais já salvas; o rascunho local é descartado quando o `authType` muda, mas os dados persistidos permanecem até o próximo Save.

## 11. Fora de escopo

- Armazenar credenciais de múltiplos provedores simultaneamente (exige mudança de schema).
- Suportar outros provedores (SES, SendGrid, Mailgun).
- Internacionalização além do português brasileiro já presente.
- Qualquer alteração em rotas de API.
