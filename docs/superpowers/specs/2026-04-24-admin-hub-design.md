# Admin Hub — Design Spec

**Date:** 2026-04-24
**Status:** Approved
**Branch:** feat/api-security-journey

---

## Objetivo

Consolidar os 6 itens dispersos na seção "ADMINISTRAÇÃO" do sidebar em um único ponto de entrada (`/admin`) que exibe um hub com tiles organizados por grupo. Cada tile navega para uma rota dedicada sob `/admin/*`. Elimina duplicações existentes e reposiciona parâmetros de AD Security para o único lugar onde fazem sentido: o formulário da jornada.

---

## Arquitetura de Rotas

### Novas rotas

| Rota | Componente | Origem |
|---|---|---|
| `/admin` | `AdminHub` | novo |
| `/admin/usuarios` | `AdminUsuarios` | `/users` |
| `/admin/sessoes` | `AdminSessoes` | `/sessions` |
| `/admin/configuracoes` | `AdminConfiguracoes` | tab Geral de `/settings` |
| `/admin/seguranca` | `AdminSeguranca` | tab Segurança de `/settings` |
| `/admin/mensageria` | `AdminMensageria` | tab Mensageria de `/settings` |
| `/admin/notificacoes` | `AdminNotificacoes` | `/notification-policies` + tab Notificações de `/settings` |
| `/admin/subscricao` | `AdminSubscricao` | `/subscription` + tab Subscrição de `/settings` |
| `/admin/auditoria` | `AdminAuditoria` | `/audit` |

### Redirects (rotas antigas → novas)

| De | Para |
|---|---|
| `/users` | `/admin/usuarios` |
| `/sessions` | `/admin/sessoes` |
| `/notification-policies` | `/admin/notificacoes` |
| `/subscription` | `/admin/subscricao` |
| `/audit` | `/admin/auditoria` |
| `/settings` | `/admin/configuracoes` |

Todas as rotas novas são protegidas pelo `AdminRoute` guard existente (`role === "global_administrator"`).

---

## Hub Page — `/admin`

### Layout

- Cabeçalho: título "Administração" + subtítulo "Gerencie usuários, sistema, comunicação e plataforma"
- 4 grupos com label de seção (`text-xs font-semibold uppercase tracking-wider text-muted-foreground`)
- Grid de 2 colunas por grupo (desktop), 1 coluna (mobile)
- Sem busca ou filtro (8 tiles não justificam)

### Tile — anatomia

```
┌─────────────────────────────────────┐
│  [Ícone grande]                     │
│  Título em negrito                  │
│  Descrição de uma linha             │
│                              →      │
└─────────────────────────────────────┘
```

Hover: elevação de sombra + fundo levemente destacado. Click: navega para a rota.

### Grupos e tiles

#### Identidade & Acesso *(ícones azuis — blue-600)*
| Tile | Ícone | Descrição | Rota |
|---|---|---|---|
| Usuários | `Users` | Contas, roles e permissões | `/admin/usuarios` |
| Sessões | `Smartphone` | Dispositivos e acessos ativos | `/admin/sessoes` |

#### Sistema *(ícones slate — slate-600)*
| Tile | Ícone | Descrição | Rota |
|---|---|---|---|
| Configurações Gerais | `SlidersHorizontal` | Nome, timezone, localização e appliance | `/admin/configuracoes` |
| Segurança Operacional | `ShieldCheck` | Limites de jobs concorrentes e timeouts | `/admin/seguranca` |

#### Comunicação *(ícones violet — violet-600)*
| Tile | Ícone | Descrição | Rota |
|---|---|---|---|
| Mensageria | `Mail` | Provedor de email: Google Workspace, M365 ou SMTP | `/admin/mensageria` |
| Notificações | `Bell` | Políticas de alerta e destinatários | `/admin/notificacoes` |

#### Plataforma *(ícones amber — amber-600)*
| Tile | Ícone | Descrição | Rota |
|---|---|---|---|
| Subscrição | `CreditCard` | Licença, plano e ativação do appliance | `/admin/subscricao` |
| Auditoria | `History` | Histórico de ações administrativas | `/admin/auditoria` |

---

## Sub-páginas — Mudanças de Conteúdo

### `/admin/usuarios` e `/admin/sessoes`
Conteúdo idêntico ao atual. Apenas rota alterada.

### `/admin/auditoria`
Conteúdo idêntico ao atual. Apenas rota alterada.

### `/admin/configuracoes`
Extrai a tab **Geral** de `/settings`. Página standalone sem tabs.

Campos: `systemName`, `systemDescription`, `systemTimezone`, `sessionTimeout`, `applianceName`, `locationType`, `locationDetail`.

### `/admin/seguranca`
Extrai a tab **Segurança** de `/settings`. Página simples sem tabs.

Campos: `maxConcurrentJobs`, `jobTimeout`.

### `/admin/mensageria`
Extrai a tab **Mensageria** de `/settings`. Mantém o fluxo de seleção de provider com campos condicionais por tipo (SMTP / OAuth2 Google / OAuth2 Microsoft). Sem tabs.

### `/admin/notificacoes`
**Merge** de duas origens:

- **Seção "Alertas Globais"** (topo da página): campos `enableEmailAlerts`, `alertEmail`, `criticalThreatAlert`, `jobFailureAlert` — vindos da tab Notificações de `/settings`
- **Seção "Políticas"** (abaixo): CRUD de políticas de notificação — vindo de `/notification-policies`

Separação por heading, sem tabs.

### `/admin/subscricao`
Unifica a tab Subscrição de `/settings` com a rota `/subscription` (eram o mesmo conteúdo em dois lugares). Página única.

---

## Sidebar

### Antes
```
ADMINISTRAÇÃO
  Usuários
  Sessões
  Notificações
  Subscrição
  Configurações
  Auditoria
```

### Depois
```
  Administração  →  /admin
```

- Label "ADMINISTRAÇÃO" removido (único item torna o label redundante)
- Ícone: `LayoutDashboard`
- Item visível apenas para `role === "global_administrator"` (comportamento inalterado)
- Breadcrumb nas sub-páginas: `Administração > [Título da página]`

---

## Parâmetros de AD Security

### Decisão
A tab **AD Security** é **removida** do settings global. Os dois campos globais (`adPasswordAgeThreshold`, `adInactiveUserThreshold`) eram "defaults globais sobrescrevíveis por jornada" — uma abstração desnecessária dado que o formulário de jornada já exibe todos os 4 parâmetros com valores padrão embutidos.

### Parâmetros permanecem exclusivamente no formulário da jornada
`passwordAgeLimitDays` · `inactiveUserLimitDays` · `maxPrivilegedGroupMembers` · `computerInactiveDays`

### Impacto no banco
Os registros `adPasswordAgeThreshold` e `adInactiveUserThreshold` na tabela `settings` podem ser mantidos sem remoção imediata — o código apenas para de lê-los/escrevê-los. Limpeza de banco é opcional e pode ser feita posteriormente.

---

## Breadcrumbs

Todas as sub-páginas exibem breadcrumb no topo:

```
Administração  /  [Título da Sub-página]
```

"Administração" é clicável e retorna para `/admin`.

---

## Arquivos Afetados (estimativa)

| Arquivo | Mudança |
|---|---|
| `client/src/App.tsx` | Adicionar rotas `/admin/*`, adicionar redirects das rotas antigas |
| `client/src/components/layout/sidebar.tsx` | Substituir 6 itens por 1 item "Administração" |
| `client/src/pages/settings.tsx` | Desmontar — conteúdo distribuído para 4 novas pages |
| `client/src/pages/admin-hub.tsx` | Novo — hub com tiles |
| `client/src/pages/admin-configuracoes.tsx` | Novo — conteúdo da tab Geral |
| `client/src/pages/admin-seguranca.tsx` | Novo — conteúdo da tab Segurança |
| `client/src/pages/admin-mensageria.tsx` | Novo — conteúdo da tab Mensageria |
| `client/src/pages/admin-notificacoes.tsx` | Novo — merge Notificações + NotificationPolicies |
| `client/src/pages/admin-subscricao.tsx` | Novo — conteúdo unificado de subscription.tsx + tab Subscrição |
| `client/src/pages/users.tsx` | Sem rename — apenas nova rota no App.tsx aponta para este arquivo |
| `client/src/pages/sessions.tsx` | Sem rename — apenas nova rota no App.tsx aponta para este arquivo |
| `client/src/pages/audit.tsx` | Sem rename — apenas nova rota no App.tsx aponta para este arquivo |
| `client/src/components/forms/journey-form.tsx` | Sem mudança (parâmetros AD Security já estão aqui) |
| `server/routes/admin.ts` | Sem mudança estrutural (rotas de API não mudam) |
