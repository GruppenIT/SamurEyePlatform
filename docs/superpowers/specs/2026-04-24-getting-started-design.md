# Getting Started — Design Spec

**Date:** 2026-04-24  
**Status:** Approved  
**Branch:** feat/api-security-journey

---

## Objetivo

Guiar o administrador nas configurações essenciais para colocar o SamurEye em operação. Um checklist de 10 etapas com detecção automática de conclusão (derivada dos dados reais do banco), opção de ignorar etapas fora do escopo, e remoção progressiva do menu lateral conforme o sistema é configurado.

---

## Visibilidade e Acesso

- Visível exclusivamente para `role === "global_administrator"`
- Rota: `/getting-started`
- Acessível via sidebar (enquanto não dismissed) e via tile permanente em `/admin`

---

## Etapas

10 etapas em ordem lógica de implantação. A detecção de conclusão é **computada em tempo real** a partir dos dados do banco — não de flags manuais. Apenas o estado "ignorado" é persistido explicitamente.

| # | ID | Etapa | Critério de conclusão | Destino | Ignorável |
|---|---|---|---|---|---|
| 1 | `appliance_config` | Configurações do Appliance | `applianceName` não-vazio E `locationType` não-vazio em `settings` (timezone não entra no critério pois tem valor default) | `/admin/configuracoes` | Não |
| 2 | `mensageria` | Mensageria | `email_settings.smtpHost` não-vazio | `/admin/mensageria` | Não |
| 3 | `first_user` | Primeiro Usuário Nominal | ≥ 1 user com `role ≠ global_administrator` | `/admin/usuarios` | Não |
| 4 | `journey_attack_surface` | Jornada: Attack Surface | ≥ 1 journey com `type = attack_surface` | `/journeys` | Sim |
| 5 | `journey_ad_security` | Jornada: AD Security | ≥ 1 journey com `type = ad_security` | `/journeys` | Sim |
| 6 | `journey_edr_av` | Jornada: EDR/AV | ≥ 1 journey com `type = edr_av` | `/journeys` | Sim |
| 7 | `journey_web_application` | Jornada: Web Application | ≥ 1 journey com `type = web_application` | `/journeys` | Sim |
| 8 | `journey_api_security` | Jornada: API Security | ≥ 1 journey com `type = api_security` | `/journeys` | Sim |
| 9 | `notification_policy` | Política de Notificação | ≥ 1 registro em `notification_policies` | `/admin/notificacoes` | Sim |
| 10 | `action_plan` | Plano de Ação | ≥ 1 registro em `action_plans` | `/action-plan` | Não |

---

## Modelo de Dados

Nenhuma tabela nova. Dois registros na tabela `settings` existente:

### `gettingStarted.skipped`

Chave JSON com o estado de cada etapa ignorada:

```json
{
  "journey_ad_security": { "at": "2026-04-24T12:00:00Z", "reason": "Fora do escopo do contrato" },
  "journey_edr_av": { "at": "2026-04-24T12:05:00Z", "reason": "" }
}
```

- `reason` é opcional (string vazia se não informado)
- Ausência de chave = não ignorado
- Remover a chave = "retomar" etapa

### `gettingStarted.dismissed`

```json
{ "at": "2026-04-24T15:00:00Z" }
```

Setado quando o admin clica em "Fechar este guia" na tela de parabéns. Controla o desaparecimento do item do sidebar. Valor `null` ou ausência = não dismissed.

---

## API

Todas as rotas protegidas por `requireAdmin`.

### `GET /api/getting-started/status`

Retorna o estado de todas as etapas. Computa conclusão a partir do banco em tempo real.

**Response:**
```json
{
  "steps": [
    {
      "id": "appliance_config",
      "completed": true,
      "skippable": false,
      "skipped": false,
      "skipReason": null,
      "skippedAt": null
    },
    {
      "id": "journey_ad_security",
      "completed": false,
      "skippable": true,
      "skipped": true,
      "skipReason": "Fora do escopo do contrato",
      "skippedAt": "2026-04-24T12:00:00Z"
    }
  ],
  "totalSteps": 10,
  "completedCount": 6,
  "dismissed": false
}
```

### `POST /api/getting-started/skip`

**Body:** `{ "stepId": "journey_ad_security", "reason": "Fora do escopo" }`

Valida que `stepId` existe e é skippável. Salva em `gettingStarted.skipped`.

### `DELETE /api/getting-started/skip/:stepId`

Remove a chave do stepId em `gettingStarted.skipped` (retomar etapa).

### `POST /api/getting-started/dismiss`

Seta `gettingStarted.dismissed`. Só aceito quando `steps.every(s => s.completed || s.skipped)`.

---

## Página `/getting-started`

### Cabeçalho

- Título: "Primeiros Passos"
- Subtítulo: "Configure o SamurEye para começar a operar"
- Barra de progresso linear: `completedCount + skippedCount / totalSteps`
- Label: "N de 10 etapas concluídas"

### Grupos de seções

```
CONFIGURAÇÃO INICIAL    → etapas 1, 2, 3
JORNADAS                → etapas 4–8  (subtítulo: "Ignore etapas fora do escopo do seu contrato")
OPERAÇÃO                → etapas 9, 10
```

### Card de etapa — três estados

**Concluída**
- Borda `border-green-500/30`, fundo `bg-green-500/5`
- Ícone `CheckCircle` verde
- Badge "Concluída" (green)
- Botão outline discreto "Revisar →"

**Pendente**
- Borda padrão
- Ícone `Circle` muted
- Badge "Pendente" (secondary)
- Botão primário "Configurar →" (ou "Ir para →")
- Botão ghost "Ignorar" (apenas skippáveis)

**Ignorada**
- Borda `border-amber-500/30`, fundo `bg-amber-500/5`
- Ícone `MinusCircle` amber
- Badge "Ignorada" (amber) com tooltip mostrando justificativa + data formatada
- Botão ghost "Retomar" (chama DELETE skip)

### Modal de ignorar

`AlertDialog` com:
- Título: "Ignorar esta etapa?"
- Descrição: "Esta etapa ficará marcada como ignorada. Você pode retomá-la a qualquer momento."
- Campo de texto livre "Motivo (opcional)"
- Botões: [Cancelar] [Ignorar etapa]

### Banner de parabéns

Aparece quando `steps.every(s => s.completed || s.skipped)`, no topo da página acima dos cards:

- Ícone `PartyPopper`
- Título: "Configuração concluída!"
- Descrição: "O SamurEye está pronto para operar."
- Botão: "Fechar este guia" → chama `POST /api/getting-started/dismiss`

Após dismiss, os cards permanecem visíveis em modo somente-leitura (sem botões de ação).

---

## Sidebar

### Posicionamento

Entre "Postura" e o grupo "Inventário" — logo abaixo do primeiro item, antes da primeira divisória.

```
  Postura
  ─────────────────────
  Primeiros Passos  ●3      ← visível apenas para global_administrator
INVENTÁRIO
  Alvos
  ...
```

### Comportamento

- Ícone: `Rocket` (lucide-react)
- Badge numérico: contagem de etapas `!completed && !skipped`
- Sidebar colapsada: apenas ícone + ponto vermelho (padrão do badge existente)
- Desaparece após `dismissed = true` (leitura via mesma query do status)
- A rota `/getting-started` permanece acessível mesmo após dismissed (via tile do `/admin`)

---

## Tile no `/admin`

Adicionado ao grupo **Plataforma** (junto de Subscrição e Auditoria):

| Tile | Ícone | Descrição dinâmica | Rota |
|---|---|---|---|
| Primeiros Passos | `Rocket` | "N de 10 etapas concluídas" / "Configuração concluída" | `/getting-started` |

O tile exibe uma mini barra de progresso (`completedCount + skippedCount / totalSteps`) abaixo da descrição, usando os dados do `GET /api/getting-started/status`. Quando tudo concluído/ignorado, a barra fica verde e a descrição muda para "Configuração concluída". O tile é permanente — nunca desaparece do `/admin`.

---

## Arquivos Afetados

| Arquivo | Mudança |
|---|---|
| `server/routes/getting-started.ts` | Novo — endpoints GET status, POST skip, DELETE skip, POST dismiss |
| `server/routes/index.ts` | Registrar getting-started routes |
| `client/src/pages/getting-started.tsx` | Novo — página completa com cards, grupos, banner, modal de skip |
| `client/src/App.tsx` | Adicionar rota `/getting-started` com AdminRoute |
| `client/src/components/layout/sidebar.tsx` | Adicionar item "Primeiros Passos" entre Postura e Inventário |
| `client/src/pages/admin.tsx` | Adicionar tile "Primeiros Passos" no grupo Plataforma |
