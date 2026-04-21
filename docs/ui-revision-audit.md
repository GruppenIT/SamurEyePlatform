# SamurEye UI — Auditoria Fase 0

> Produzido em: 2026-04-21  
> Propósito: Inventário completo do estado atual antes de qualquer alteração de código.  
> Instrução: **Não iniciar Fase 1 sem revisão e aprovação humana deste documento.**

---

## 1. Inventário de Rotas

### 1.1 Rotas Públicas (usuário não autenticado)

| Path | Componente | Guard | Papéis permitidos | Observações |
|---|---|---|---|---|
| `/` | `Landing` | Nenhum | Público | Página de marketing/landing com hero, features, CTA — **a remover na Fase 2** |
| `/login` | `Login` | Nenhum | Público | Formulário de login |
| `/forgot-password` | `ForgotPassword` | Nenhum | Público | Só exibido se `passwordRecoveryAvailable` via `/api/auth/features` |
| `/reset-password` | `ResetPassword` | Nenhum | Público | Chegada via link de e-mail |

> **Nota de risco:** A rota `/` para usuário não autenticado renderiza a `Landing` — página de marketing com conteúdo público. Para usuário autenticado, a mesma rota `/` renderiza `Postura`. Dois componentes distintos compartilham o mesmo path, dependendo do estado de autenticação.

### 1.2 Estados intermediários de autenticação

| Estado | Rota obrigatória | Componente | Comportamento |
|---|---|---|---|
| `mustChangePassword = true` | `/change-password` | `ChangePassword` | Todas as outras rotas redirecionam aqui |
| `pendingMfa = true` | `/mfa-challenge` | `MfaChallengePage` | Todas as outras rotas redirecionam aqui |

### 1.3 Rotas Autenticadas — Todos os papéis

| Path | Componente | Guard | Papéis | Observações |
|---|---|---|---|---|
| `/` e `/postura` | `Postura` | `isAuthenticated` | Todos | Dashboard principal de postura |
| `/relatorios` | `Relatorios` | `isAuthenticated` | Todos | Relatórios por tipo de jornada |
| `/assets` | `Assets` | `isAuthenticated` | Todos | Gestão de ativos/alvos |
| `/ativos` e `/hosts` | `Hosts` | `isAuthenticated` | Todos | Hosts descobertos |
| `/credentials` | `Credentials` | `isAuthenticated` | Todos | Credenciais |
| `/journeys` | `Journeys` | `isAuthenticated` | Todos | Lista e criação de jornadas |
| `/journeys/api` | `ApiDiscovery` | `isAuthenticated` | Todos | Discovery de APIs (jornada dedicada) |
| `/schedules` | `Schedules` | `isAuthenticated` | Todos | Agendamentos |
| `/jobs` | `Jobs` | `isAuthenticated` | Todos | Fila de execução |
| `/threats` | `Threats` | `isAuthenticated` | Todos | Threat Intelligence |
| `/action-plan` | `ActionPlan` | `isAuthenticated` | Todos | Plano de ação |
| `/action-plan/:id` | `ActionPlanDetail` | `isAuthenticated` | Todos | Detalhe do plano |
| `/sessions` | `Sessions` | `isAuthenticated` | Todos | Sessões ativas do usuário corrente |
| `/account` | `AccountPage` | `isAuthenticated` | Todos | Conta do usuário |
| `/account/mfa` | `AccountMfaPage` | `isAuthenticated` | Todos | Configuração de MFA |
| `/change-password` | `ChangePassword` | `isAuthenticated` | Todos | Troca de senha |

### 1.4 Rotas Admin-Only (`global_administrator`)

| Path | Componente | Guard | Observações |
|---|---|---|---|
| `/users` | `Users` | `AdminRoute` | CRUD de usuários e papéis |
| `/subscription` | `Subscription` | `AdminRoute` | Licenciamento e heartbeat ao console |
| `/settings` | `Settings` | `AdminRoute` | Configurações globais do appliance |
| `/notification-policies` | `NotificationPolicies` | `AdminRoute` | Políticas de alertas |
| `/audit` | `Audit` | `AdminRoute` | Log de auditoria de ações |

**Implementação do guard:**
```typescript
// App.tsx:89-95
function AdminRoute({ component: PageComponent }) {
  const { user } = useAuth();
  if (user?.role !== 'global_administrator') return <Redirect to="/" />;
  return <PageComponent />;
}
```

> **Nota de segurança:** Guard correto — redireciona silenciosamente para `/` sem expor mensagem de "acesso negado". Manter comportamento.

### 1.5 Papéis existentes

| Papel | Valor interno | Label pt-BR |
|---|---|---|
| Administrador Global | `global_administrator` | Administrador Global |
| Operador | `operator` | Operador |
| Somente Leitura | `read_only` | Somente Leitura |

> **Atenção:** As rotas autenticadas (seção 1.3) NÃO diferenciam `operator` de `read_only` a nível de rota — o controle granular por papel ocorre dentro de cada componente ou no backend. Manter esse padrão inalterado nesta revisão.

---

## 2. Inventário da Sidebar e Header

### 2.1 Sidebar (`client/src/components/layout/sidebar.tsx`)

**Dimensões e comportamento atual:**
- Largura fixa: `w-64` (256px)
- Sem modo colapsado/expandido
- Fundo: `bg-sidebar` (CSS var `--sidebar`)
- Borda direita: `border-sidebar-border`
- Scroll vertical na área de navegação

**Logo/Marca (linhas 108–117):**
- **NÃO usa arquivo de imagem** — usa ícone `Shield` do `lucide-react`
- Container: `w-10 h-10 bg-sidebar-primary rounded-lg`
- Texto: "SamurEye" em `text-lg font-bold` + tagline "Validação de Exposição" em `text-xs text-muted-foreground`

**Grupo 1 — (sem título):**
| Label | Ícone | Rota | Papel mínimo |
|---|---|---|---|
| Postura | `ShieldCheck` | `/` | Todos |

**Grupo 2 — Superfície:**
| Label | Ícone | Rota | Papel mínimo |
|---|---|---|---|
| Alvos | `Server` | `/assets` | Todos |
| Hosts | `Monitor` | `/hosts` | Todos |
| Credenciais | `Key` | `/credentials` | Todos |

**Grupo 3 — Operações:**
| Label | Ícone | Rota | Papel mínimo |
|---|---|---|---|
| Jornadas | `Route` | `/journeys` | Todos |
| API Discovery | `Globe` | `/journeys/api` | Todos |
| Agendamentos | `Clock` | `/schedules` | Todos |
| Jobs | `List` | `/jobs` | Todos |

**Grupo 4 — Inteligência:**
| Label | Ícone | Rota | Papel mínimo | Badge dinâmico |
|---|---|---|---|---|
| Ameaças | `AlertTriangle` | `/threats` | Todos | Contagem de críticas abertas (vermelho) |
| Plano de Acao | `ClipboardList` | `/action-plan` | Todos | — |
| Relatórios | `FileBarChart` | `/relatorios` | Todos | — |

**Grupo 5 — Administração (visível apenas para `global_administrator`):**
| Label | Ícone | Rota | Papel mínimo |
|---|---|---|---|
| Usuários | `Users` | `/users` | `global_administrator` |
| Sessões | `Smartphone` | `/sessions` | `global_administrator` |
| Notificações | `Bell` | `/notification-policies` | `global_administrator` |
| Subscrição | `CreditCard` | `/subscription` | `global_administrator` |
| Configurações | `Settings` | `/settings` | `global_administrator` |
| Auditoria | `History` | `/audit` | `global_administrator` |

> **Observação:** Sessões aparece tanto no grupo Admin quanto como rota acessível a todos (`/sessions`). Verificar se é a mesma página ou versões diferentes (admin vê todas as sessões, usuário comum vê apenas as próprias). Tratar com cuidado na reorganização.

**Comportamento de badge:**
- Query: `GET /api/threats?severity=critical&status=open`
- Exibido no item "Ameaças" se `count > 0`
- Refresca a cada re-render (sem `refetchInterval` definido para o badge)

**Versão do app:**
- Query: `GET /api/health` com `refetchInterval: 60_000`
- Exibido no rodapé da sidebar: `v{version}`

### 2.2 TopBar (`client/src/components/layout/topbar.tsx`)

**Props aceitas:**
```typescript
{ title: string; subtitle: string; wsConnected?: boolean; actions?: ReactNode }
```

**Conteúdo fixo (não via props):**
- `SystemStatusPopup` (status WS/conexão)
- Botão "Varredura Rápida" → `/journeys` (ícone `Search`)
- Botão "Nova Jornada" → `/journeys` (ícone `Plus`)
- `UserMenu` (avatar com iniciais, dropdown)

**UserMenu (`client/src/components/account/user-menu.tsx`):**
- Avatar com iniciais do usuário
- Nome + e-mail + papel (traduzido)
- Links: Minha Conta, Trocar senha, Gerenciar MFA, Sair

> **Ausências no TopBar:** Sem toggle de tema, sem breadcrumb, sem busca global. Todos esses elementos precisam ser adicionados conforme R2 e R4.

---

## 3. Inventário de `/settings`

**Arquivo:** `client/src/pages/settings.tsx` (1.385 linhas)  
**Backend:** `server/routes/admin.ts` + `server/services/settingsService.ts`  
**Tabelas DB:** `settings` (key-value), `email_settings`, `appliance_subscription`

### 3.1 Aba "Geral"

| Campo | Chave no DB | Tipo | Default | Classificação |
|---|---|---|---|---|
| Nome do sistema | `systemName` | string | `'SamurEye'` | `KEEP_GLOBAL` — identidade do appliance |
| Descrição do sistema | `systemDescription` | string | `'Plataforma de Validação de Exposição Adversarial'` | `KEEP_GLOBAL` |
| Fuso horário | `systemTimezone` | string (enum IANA) | `'America/Sao_Paulo'` | `KEEP_GLOBAL` — afeta todos os agendamentos |
| Nome do appliance | `applianceName` | string | `''` | `KEEP_GLOBAL` — enviado ao console na telemetria |
| Tipo de localização | `locationType` | enum | `''` | `KEEP_GLOBAL` — metadado organizacional do console |
| Detalhe da localização | `locationDetail` | string | `''` | `KEEP_GLOBAL` — metadado organizacional |
| Timeout de sessão | `sessionTimeout` | number (segundos) | `3600` | `KEEP_GLOBAL` — política de segurança de sessão |

### 3.2 Aba "Segurança"

| Campo | Chave no DB | Tipo | Default | Classificação |
|---|---|---|---|---|
| Máx. jobs simultâneos | `maxConcurrentJobs` | number (1–10) | `3` | `KEEP_GLOBAL` — recurso do appliance, não de jornada |
| Timeout de job | `jobTimeout` | number (segundos) | `1800` | `KEEP_GLOBAL` — limite de recursos do appliance |

### 3.3 Aba "AD Security" (⚠️ candidata à migração)

| Campo | Chave no DB | Tipo | Default | Classificação proposta |
|---|---|---|---|---|
| Limiar de idade de senha | `ad.passwordAgeLimitDays` | number (dias) | `90` | `MOVE_TO_JOURNEY:ad_security` |
| Limiar de inatividade de usuário | `ad.inactiveUserLimitDays` | number (dias) | `180` | `MOVE_TO_JOURNEY:ad_security` |
| Máx. membros em grupo privilegiado | `ad.maxPrivilegedGroupMembers` | number | `5` | `MOVE_TO_JOURNEY:ad_security` |
| Dias de inatividade de computador | `ad.computerInactiveDays` | number (dias) | `90` | `MOVE_TO_JOURNEY:ad_security` |

> **Justificativa:** Esses quatro parâmetros são thresholds de validação usados pelo executor da jornada `ad_security` para classificar achados. Cada cliente pode ter ambientes com requisitos distintos. Migrar para os parâmetros da jornada AD Security (wizard "Parâmetros de Validação") permite configuração por jornada, não global. O default da jornada no momento da criação = valor atual em settings.

### 3.4 Aba "Notificações"

| Campo | Chave no DB | Tipo | Default | Classificação |
|---|---|---|---|---|
| Habilitar alertas por e-mail | `enableEmailAlerts` | boolean | `false` | `KEEP_GLOBAL` — infraestrutura de alerta |
| E-mail de alerta | `alertEmail` | string | `''` | `KEEP_GLOBAL` |
| Alertar em ameaça crítica | `criticalThreatAlert` | boolean | `true` | `KEEP_GLOBAL` |
| Alertar em falha de job | `jobFailureAlert` | boolean | `true` | `KEEP_GLOBAL` |

### 3.5 Aba "E-mail / SMTP" (tabela `email_settings`)

| Campo | Tipo | Sensível | Classificação |
|---|---|---|---|
| Provedor (Google/Microsoft/SMTP) | enum | — | `KEEP_GLOBAL` |
| SMTP host | string | — | `KEEP_GLOBAL` |
| SMTP port | number | — | `KEEP_GLOBAL` |
| SMTP secure (TLS) | boolean | — | `KEEP_GLOBAL` |
| Auth type | enum | — | `KEEP_GLOBAL` |
| Auth user | string | — | `KEEP_GLOBAL` |
| Auth password | string | **Sim** (DEK-KEK enc.) | `KEEP_GLOBAL` |
| OAuth2 client ID | string | — | `KEEP_GLOBAL` |
| OAuth2 client secret | string | **Sim** (DEK-KEK enc.) | `KEEP_GLOBAL` |
| OAuth2 refresh token | string | **Sim** (DEK-KEK enc.) | `KEEP_GLOBAL` |
| OAuth2 tenant ID | string | — | `KEEP_GLOBAL` |
| From e-mail | string | — | `KEEP_GLOBAL` |
| From name | string | — | `KEEP_GLOBAL` |

> **Nota de segurança:** Campos `authPassword`, `oauth2ClientSecret`, `oauth2RefreshToken` são criptografados com padrão DEK-KEK. A UI mostra campos de entrada mas **nunca exibe o valor descriptografado** — manter esse comportamento intocado.

### 3.6 Aba "Subscrição / Licenciamento" (`appliance_subscription`)

Toda a gestão de licença (ativação, heartbeat, status) está em `/subscription` (`AdminRoute`), **não** dentro de `/settings`. A aba "Subscrição" na sidebar aponta para `/subscription`. Classificação: `KEEP_GLOBAL`.

### 3.7 Resumo de classificações

| Classificação | Qtd. campos | Destino |
|---|---|---|
| `KEEP_GLOBAL` | 19 | Permanecem em `/settings`, agrupados e renomeados |
| `MOVE_TO_JOURNEY:ad_security` | 4 | Form da jornada AD Security — wizard "Parâmetros de Validação" |
| `MOVE_TO_JOURNEY:*` (outros) | 0 | Nenhum identificado nos demais tipos (journey params já estão nos forms) |
| `MOVE_TO_ENTITY` | 0 | Nenhum identificado |
| `DEPRECATE` | 0 | Nenhum identificado (todos os campos têm uso ativo) |

> **Importante:** Os parâmetros de jornada (nmapProfile, vulnScriptTimeout, domain, credentialId, enabledCategories, edrAvType, sampleRate, processTimeout, etc.) já estão **no form das respectivas jornadas**, não em `/settings`. A Fase 5 neste projeto se limita à migração dos 4 campos AD.

---

## 4. Inventário de Tokens de Tema

### 4.1 Sistema atual

O app é **dark-only permanente** — um único bloco `:root` em `client/src/index.css`. Não existe `prefers-color-scheme`, não existe `.dark`, não existe `ThemeProvider`, não existe toggle de tema, não existe persistência de preferência.

### 4.2 Variáveis CSS existentes (`:root`)

**Camada base (shadcn/ui compatível):**
| Variável | Valor atual (dark) | Valor a criar (light) |
|---|---|---|
| `--background` | `hsl(222, 18%, 8%)` — azul-cinza muito escuro | `hsl(0, 0%, 98%)` — quase branco |
| `--foreground` | `hsl(210, 20%, 93%)` — off-white | `hsl(222, 18%, 12%)` — quase preto |
| `--card` | `hsl(222, 16%, 13%)` | `hsl(0, 0%, 100%)` |
| `--card-foreground` | `hsl(210, 20%, 93%)` | `hsl(222, 18%, 12%)` |
| `--popover` | `hsl(222, 16%, 13%)` | `hsl(0, 0%, 100%)` |
| `--popover-foreground` | `hsl(210, 20%, 93%)` | `hsl(222, 18%, 12%)` |
| `--primary` | `hsl(197, 75%, 48%)` — ciano | `hsl(197, 75%, 40%)` — ciano mais escuro (contraste em fundo claro) |
| `--primary-foreground` | `hsl(222, 18%, 8%)` | `hsl(0, 0%, 100%)` |
| `--secondary` | `hsl(222, 16%, 17%)` | `hsl(210, 20%, 94%)` |
| `--secondary-foreground` | `hsl(210, 20%, 85%)` | `hsl(222, 18%, 20%)` |
| `--muted` | `hsl(222, 14%, 15%)` | `hsl(210, 20%, 96%)` |
| `--muted-foreground` | `hsl(210, 12%, 72%)` | `hsl(215, 14%, 42%)` |
| `--accent` | `hsl(45, 80%, 60%)` — dourado | `hsl(45, 80%, 45%)` |
| `--accent-foreground` | `hsl(222, 18%, 8%)` | `hsl(0, 0%, 100%)` |
| `--destructive` | `hsl(0, 75%, 55%)` | `hsl(0, 75%, 45%)` |
| `--destructive-foreground` | `hsl(210, 20%, 95%)` | `hsl(0, 0%, 100%)` |
| `--border` | `hsl(222, 14%, 22%)` | `hsl(214, 20%, 88%)` |
| `--input` | `hsl(222, 14%, 17%)` | `hsl(214, 20%, 92%)` |
| `--ring` | `hsl(197, 75%, 48%)` | `hsl(197, 75%, 40%)` |
| `--radius` | `8px` | idem |

**Sidebar:**
| Variável | Valor atual (dark) |
|---|---|
| `--sidebar` | `hsl(222, 18%, 10%)` |
| `--sidebar-foreground` | `hsl(210, 20%, 93%)` |
| `--sidebar-primary` | `hsl(197, 75%, 48%)` |
| `--sidebar-primary-foreground` | `hsl(222, 18%, 8%)` |
| `--sidebar-accent` | `hsl(222, 16%, 17%)` |
| `--sidebar-accent-foreground` | `hsl(210, 20%, 85%)` |
| `--sidebar-border` | `hsl(222, 14%, 18%)` |
| `--sidebar-ring` | `hsl(197, 75%, 48%)` |

**Cores semânticas de severidade (invariantes entre temas — só ajustar opacidades de bg/border):**
| Variável | Valor | Invariante? |
|---|---|---|
| `--severity-critical` | `hsl(0, 75%, 55%)` | Sim (vermelho) |
| `--severity-high` | `hsl(25, 85%, 50%)` | Sim (laranja) |
| `--severity-medium` | `hsl(45, 80%, 55%)` | Sim (amarelo) |
| `--severity-low` | `hsl(142, 60%, 40%)` | Sim (verde) |
| `--severity-info` | `hsl(210, 50%, 55%)` | Sim (azul) |
| `--status-open/investigating/mitigated/closed/hibernated/accepted` | vários | Sim |

> As cores de severidade/status devem **permanecer as mesmas** nos dois temas (são semânticas de segurança, não de interface). Apenas as variantes `*-bg` e `*-border` podem ter opacidade ajustada em tema claro para não sobrescrever o fundo branco.

**Sombras:**
- 8 níveis definidos com `hsl(0,0%,0%, alpha)` — funcionam bem em dark, mas em light precisam de `alpha` reduzido. Criar tokens separados por tema.

### 4.3 Classes `dark:` encontradas

> Resultado da busca: **ZERO usos de classes `dark:` Tailwind** em todo o codebase frontend. O app não usa o mecanismo `darkMode: 'class'` do Tailwind — toda a lógica de tema está nas CSS vars do `:root`. Isso significa que a implementação do light mode **não precisa adicionar prefixos `dark:` em componentes existentes** — basta criar o bloco `:root.dark { }` com os valores escuros atuais e reescrever o `:root` com valores claros.

### 4.4 Cores hardcoded a tokenizar

Cores literais encontradas fora das CSS vars (exemplos significativos):

| Local | Valor hardcoded | Token proposto |
|---|---|---|
| `relatorios.tsx` | `rgb(74, 222, 128)` | `var(--severity-low)` ou `--color-success` |
| `relatorios.tsx` | `rgb(248, 113, 113)` | `var(--severity-critical)` |
| `relatorios.tsx` | `rgb(250, 204, 21)` | `var(--severity-medium)` |
| `sidebar.tsx` (`.active`) | `hsl(197, 75%, 48%, 0.15)` | `var(--sidebar-primary) / 15%` |
| `index.css` (scrollbar thumb) | `hsl(222, 14%, 22%)` | `var(--border)` |
| `index.css` (scrollbar hover) | `hsl(222, 14%, 30%)` | novo `--border-strong` |
| `index.css` (.metric-card) | gradiente em linhas 130+ | `var(--card)` + `var(--primary)/5%` |
| `index.css` (.sidebar-item:hover) | `hsl(222, 16%, 17%)` | `var(--sidebar-accent)` |

### 4.5 Tailwind config

- Arquivo: `tailwind.config.ts`
- Usa `theme.extend.colors` com referências a CSS vars via `hsl(var(--...) / <alpha-value>)` para cores shadcn/ui
- `darkMode` não configurado explicitamente (default: `media`) — **deve ser alterado para `'class'`** na Fase 1 para controle programático

---

## 5. Inventário de Logos e Ícones

### 5.1 Arquivos de imagem existentes

| Arquivo | Localização | Dimensões (aprox.) | Uso atual |
|---|---|---|---|
| `logo.png` | `/opt/samureye/shared/logo.png` | — | **NÃO UTILIZADO** no frontend |
| `Logos_white.png` | `/opt/samureye/shared/Logos_white.png` | — | **NÃO UTILIZADO** no frontend |
| `Logon_bg.png` | `/opt/samureye/shared/Logon_bg.png` | — | **NÃO UTILIZADO** no frontend |

> **Atenção crítica:** Os três arquivos de imagem existem em `shared/` mas **nenhum é referenciado** no código frontend atual. Todo o branding usa o ícone `Shield` do `lucide-react`. A Fase 2 e Fase 3 deverão introduzir esses arquivos pela primeira vez.

### 5.2 Como os arquivos serão servidos

Os arquivos em `shared/` precisam ser copiados ou referenciados pela build do Vite. Estratégias:
- **Opção A:** Copiar para `client/public/` (sem import, referenciados por URL absoluta `/logo.png`)
- **Opção B:** Importar via `import logoUrl from '@/assets/logo.png'` com Vite asset handling
- **Recomendação:** Opção A para `Logon_bg.png` (background CSS), Opção B para logos condicionais por tema (melhor cache busting)

### 5.3 Ocorrências atuais do ícone `Shield` (a substituir por imagem)

| Arquivo | Linha aprox. | Contexto |
|---|---|---|
| `client/src/components/layout/sidebar.tsx` | 108–117 | Logo no topo da sidebar |
| `client/src/pages/login.tsx` | 80–84 | Logo no card de login |
| `client/src/pages/landing.tsx` | 18–22 | Logo na landing page pública |
| `client/src/App.tsx` | ~105 | Loading screen (pode manter Shield) |
| `client/src/App.tsx` | ~56 | ErrorBoundary (pode manter Shield) |
| `client/src/pages/mfa-challenge.tsx` | — | Tela de MFA (pode manter Shield) |

> **Regra de substituição (R3):**  
> - Tema **escuro** → usar `logo.png`  
> - Tema **claro** → usar `Logos_white.png` *(confirmar nome exato — o produto owner indica "Logos_white.png" mas o arquivo real é `/shared/Logos_white.png` — ✅ confirmado)*  
> - Aplicar em: sidebar, topo do card de login  
> - Loading screen, ErrorBoundary e MFA challenge podem manter o ícone Shield por serem telas temporárias/excepcionais

---

## 6. Matriz de Risco

### 6.1 Critérios de classificação

- **Baixo:** Mudança visual, sem impacto em lógica, auth, RBAC ou dados
- **Médio:** Afeta layout/componentes usados em múltiplas páginas, ou envolve migração de estado/dados
- **Alto:** Afeta autenticação, criptografia, RBAC, fluxo de dados sensíveis, ou é irreversível

### 6.2 Riscos por mudança proposta

| # | Mudança | Fase | Risco | Estratégia de rollback |
|---|---|---|---|---|
| 1 | Remover landing page pública (`/`) | 2 | **Baixo** | Reverter routing no App.tsx |
| 2 | Adicionar `Logon_bg.png` como background da tela de login | 2 | **Baixo** | Remover import e CSS |
| 3 | Substituir `Shield` icon por `logo.png`/`Logos_white.png` | 2/3 | **Baixo** | Reverter para Shield |
| 4 | Implementar `ThemeProvider` + toggle tema | 1 | **Médio** | CSS vars já estão em `:root`; reverter o Provider não afeta funcionalidade |
| 5 | Mudar `darkMode: 'media'` para `darkMode: 'class'` no Tailwind | 1 | **Médio** | Requer rebuild; em `class` mode sem `.dark` aplicada ao `<html>`, app aparece "claro" — risco de UX degradada se deploy parcial |
| 6 | Script anti-flash no `index.html` | 1 | **Médio** | Script minúsculo; falha silenciosa não bloqueia React |
| 7 | Adicionar `ui_preferences JSONB NULL` na tabela `users` | 1/R2 | **Baixo** | Coluna nullable com default `NULL` — zero impacto em registros existentes |
| 8 | Sidebar colapsável + estado persistido | 3 | **Baixo** | Estado em localStorage apenas; nenhum dado de negócio afetado |
| 9 | Reorganização dos grupos de menu | 4 | **Médio** | Nenhuma rota alterada; apenas labels/agrupamentos na sidebar. Risco: confusão de usuários acostumados. Mitigação: comunicar mudança |
| 10 | Migrar 4 parâmetros AD de `/settings` para form da jornada | 5 | **Alto** | **Requer migration aditiva + backfill idempotente.** Settings antigo mantido com banner de deprecação. Rollback: reverter UI + manter settings global como fonte de verdade durante 1 release |
| 11 | Breadcrumbs em todas as páginas | 4 | **Baixo** | Componente adicional; não afeta funcionalidade |
| 12 | Refatorar Tailwind config para usar `rgb(var(--...) / alpha)` | 1 | **Médio** | Afeta todas as classes Tailwind do projeto. Validar visualmente. Rebuild completo necessário |
| 13 | Persistência de tema no backend (campo `ui_preferences`) | 1 | **Baixo** | Tolerante a falhas por design (fallback para localStorage). Endpoint novo e aditivo |
| 14 | Substituir cores hardcoded em `relatorios.tsx` por tokens | 1 | **Baixo** | Mudança visual apenas; valores semanticamente equivalentes |

### 6.3 Dependências entre fases

```
Fase 1 (tema) → Fase 2 (login) → Fase 3 (shell) → Fase 4 (nav) → Fase 5 (settings migration)
                                                                  ↓
                                                           Fase 6 (QA)
```

Fase 1 é bloqueante para todas as demais — sem o `ThemeProvider` e os tokens, Fases 2-3 não podem implementar os logos condicionais.

---

## 7. Observações adicionais e perguntas abertas

### 7.1 Rota `/sessions` — ambiguidade RBAC

`/sessions` está acessível a todos os usuários autenticados (seção 1.3), mas também aparece no grupo "Administração" da sidebar (visível só a `global_administrator`). Precisa de clarificação:
- **Caso A:** Todo usuário pode ver suas próprias sessões; admin vê todas → deveria haver `/sessions` público + `/sessions/all` admin
- **Caso B:** Só admin acessa → remover da lista de rotas gerais e manter só no guard AdminRoute
- **Ação:** Perguntar ao product owner antes de alterar.

### 7.2 Rota `/journeys/api` — integração ou separação?

`API Discovery` aparece como item separado na sidebar ("Jornadas > API Discovery") mas também como sub-rota `/journeys/api`. Na nova navegação (R4), sugere-se unificar sob "Execução > Jornadas" com um tab ou filtro por tipo, em vez de item separado. Confirmar com PO.

### 7.3 `Logon_bg.png` — direitos de uso confirmados?

O arquivo existe em `shared/`. Confirmar que a imagem é própria (sem licença restrita) antes de usar como background.

### 7.4 Estratégia de migração dos thresholds AD

O `settingsService.ts` expõe `adPasswordAgeLimitDays` e `adInactiveUserLimitDays` como campos lidos pelo executor da jornada via `storage.getSetting(...)`. Na Fase 5, o executor precisará ser atualizado para ler de `journey.params` com fallback para o valor global — garantindo retrocompatibilidade com jornadas existentes que não têm o campo novo.

### 7.5 Ausência de `ui_preferences` na tabela `users`

Confirmado: a tabela `users` não tem coluna de preferências de UI. A migration Drizzle na Fase 1 adicionará:
```sql
ALTER TABLE users ADD COLUMN ui_preferences JSONB DEFAULT NULL;
```
Schema Drizzle: `uiPreferences: jsonb("ui_preferences").$type<{ theme?: 'light' | 'dark' | 'system'; sidebarCollapsed?: boolean }>().default(null)`

---

## 8. Checklist de pré-requisitos antes da Fase 1

- [ ] PO confirma rota `/sessions` (7.1)
- [ ] PO confirma destino de `API Discovery` na nova navegação (7.2)
- [ ] Direitos de uso de `Logon_bg.png` confirmados (7.3)
- [ ] PO aprova mapeamento de classificações da seção 3 (especialmente `MOVE_TO_JOURNEY:ad_security`)
- [ ] PO aprova nova estrutura de navegação (proposta na seção 2.1 alinhada com R4 — detalhamento em `docs/ui-revision-navigation.md` a criar antes da Fase 4)
- [ ] Equipe ciente de que Fase 5 exige migration de banco + backfill + atualização do executor `ad_security`

---

*Fim da auditoria. Aguardando aprovação para iniciar Fase 1.*
