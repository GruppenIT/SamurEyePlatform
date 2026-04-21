# Phase 16: UI & Final Integration - Context

**Gathered:** 2026-04-20 (via `/gsd:discuss-phase 16 --auto`)
**Status:** Ready for planning

<domain>
## Phase Boundary

Entregar a superfície de usuário final do milestone v2.0:
- Página `/journeys/api` com listagem de APIs descobertas e drill-down de endpoints.
- Filtro `source=api_security` na página de findings (threats) com OWASP category badges.
- Botão "Reproduzir" por finding que gera `curl` com placeholders de credenciais (nunca secrets reais).
- Marcação `false_positive` por finding registrada em `audit_log`.
- Wizard de 4 passos para criação de journey `api_security` (Alvos → Autenticação → Configuração → Confirmação) com authorization acknowledgment e preview de requests estimados.

**Fora de escopo:**
- Orquestração backend da jornada → Phase 15 (entregue).
- Scanners passivos/ativos → Phases 12/13 (entregues).
- Sanitização de evidence → Phase 14 (entregue).
- Dashboard executivo com métricas de api_security → backlog pós-v2.0.

</domain>

<decisions>
## Implementation Decisions

### Página API Discovery (`/journeys/api`) — UI-01

- **Layout**: Tabela (padrão consistente com todas as outras páginas — journeys.tsx, assets.tsx, threats.tsx). Colunas: baseUrl, tipo (REST/GraphQL/SOAP), método de discovery, contagem de endpoints, última execução.
- **Drill-down**: Sheet lateral (padrão do journeys.tsx com EDR deployments) — não uma nova página. Ao clicar em uma API, abre Sheet com endpoints agrupados por path.
- **Agrupamento de endpoints no drill-down**: Collapsible por path (padrão existente em threats.tsx com `Collapsible`). Dentro de cada path: method badges (GET=verde, POST=azul, PUT=amarelo, DELETE=vermelho, PATCH=laranja) + indicador de auth-required + parâmetros conhecidos.
- **Rota no router**: `/journeys/api` (nova rota em `client/src/App.tsx`) — página separada, não dentro de `journeys.tsx`.
- **Link na sidebar**: Grupo "Operações" — adicionar item "API Discovery" com ícone `Globe` ou `NetworkIcon` após "Jornadas".
- **Dados**: `GET /api/v1/apis` (Phase 11) para listagem; `GET /api/v1/apis/:id/endpoints` para drill-down.

### Wizard 4 passos — UI-06

- **Contentor**: Dialog (padrão existente para formulários complexos — Dialog com DialogContent). Não Sheet, não página full. Width: `max-w-3xl`.
- **Navegação entre passos**: Stepper horizontal com numeração (1-4) no topo do Dialog. Botões "Anterior" / "Próximo" no rodapé. "Criar Jornada" somente no passo 4.
- **Passo 1 — Alvos**: Nome da jornada + seleção de assets (reusa `TagSelector` e asset multi-select do `journey-form.tsx` existente). Campo de target URL base.
- **Passo 2 — Autenticação**: Seleção de credencial API existente (dropdown de `api_credentials`) + botão "Criar nova credencial" inline que abre Dialog aninhado (padrão existente). Toggle `authorizationAck` como Checkbox obrigatório com label em vermelho ("Confirmo que tenho autorização para testar estes alvos").
- **Passo 3 — Configuração**:
  - Discovery toggles: spec-first (ON por default), crawler (ON), kiterunner (OFF por default — mais ruidoso).
  - Testing toggles: misconfigs (ON), auth (ON), BOLA (OFF), BFLA (OFF), BOPLA (OFF), rate-limit (ON), SSRF (OFF).
  - Campo `rateLimit` (slider ou input numérico, 1-50 req/s, default 10).
  - Métodos destrutivos: `destructiveEnabled` como Checkbox separado com label vermelho — desativado por default.
  - Preview de requests estimados: cálculo client-side simples (endpoints descobertos × stages ativos) exibido como Badge cinza "~N requests estimados". Atualizado ao mudar toggles.
- **Passo 4 — Confirmação**: Resumo read-only de todos os campos (alvos, credencial, toggles ativos, rate limit, estimativa). Checkbox `dryRun` opcional. Botão "Criar Jornada" em destaque.
- **Schema Zod no frontend**: `authorizationAck: z.boolean().refine(v => v === true, 'Obrigatório')` — bloqueia avanço se não marcado.
- **Acessar o wizard**: Botão "Nova Jornada API" na página `/journeys/api` (não no `journeys.tsx` genérico). O `journeys.tsx` existente não é modificado — wizard fica isolado no contexto da página API.

### Filtro OWASP na página de findings — UI-03

- **Localização**: página `threats.tsx` existente — adicionar Select de `source` na toolbar de filtros (junto ao filtro de severidade/journey existente). Opção "API Security" filtra por `source=api_security`.
- **OWASP category badge**: coluna adicional na tabela de threats quando `source=api_security` está ativo — Badge com texto abreviado da categoria (ex: "API1:2023", "API3:2023"). Cor = severidade (vermelho=critical, laranja=high, amarelo=medium, azul=low).
- **Fallback**: se finding não tem categoria OWASP, badge "N/A" em cinza — não omitir a coluna.
- **Dados**: campo `owaspCategory` já presente em `api_findings` (Phase 9) + exposto via `GET /api/v1/findings?source=api_security` (Phase 14).

### Curl reproduction ("Reproduzir") — UI-04

- **Trigger**: botão "Reproduzir" (ícone `Terminal` ou `Code2`) no menu de ações de cada finding na tabela de threats quando `source=api_security`.
- **Output**: Dialog com `<pre>` code block mostrando o curl gerado. Botão "Copiar" com `navigator.clipboard`. Fechamento via "Fechar".
- **Formato do curl**: gerado client-side a partir dos campos do finding (method, url, headers, body schema). Credenciais substituídas por placeholders: `$API_KEY`, `$BEARER_TOKEN`, `$BASIC_AUTH` conforme o tipo. Nunca valores reais.
- **Fallback**: se finding não tem dados suficientes para curl, mostrar mensagem "Não foi possível gerar curl — dados de endpoint insuficientes".

### False-positive marking — UI-05

- **Trigger**: botão "Falso Positivo" (ícone `ShieldOff` ou `EyeOff`) no menu de ações de cada finding.
- **UX**: AlertDialog de confirmação ("Marcar como falso positivo? Esta ação é registrada no audit log.") com botões "Cancelar" / "Confirmar". Padrão existente de AlertDialog em `assets.tsx`.
- **Mutation**: `PATCH /api/v1/findings/:id` com `{ falsePositive: true }` (Phase 14 endpoint existente) — `useMutation` + `invalidateQueries`.
- **Feedback**: Toast "Finding marcado como falso positivo" após sucesso.
- **Estado visual**: linha do finding fica com opacidade reduzida e badge "Falso Positivo" na coluna de status após marcação.

### Claude's Discretion

- Ícone exato para API Discovery na sidebar.
- Animação de transição entre passos do wizard.
- Algoritmo exato de estimativa de requests no passo 3 (pode ser simples: `endpoints × stagesAtivos × 2`).
- Paginação vs scroll na tabela de endpoints no drill-down (depende de volume).
- Cor exata dos method badges (desde que diferenciáveis).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requisitos desta fase
- `.planning/REQUIREMENTS.md` §UI-01..06 — definição normativa de cada requisito

### Componentes e padrões existentes
- `client/src/pages/journeys.tsx` — padrão de tabela + Sheet lateral para drill-down (EDR deployments como referência)
- `client/src/pages/assets.tsx` — padrão AlertDialog para confirmações destrutivas
- `client/src/pages/threats.tsx` — padrão de filtros (Select), Badge por severidade, Collapsible por categoria, Dialog de detalhes
- `client/src/components/forms/journey-form.tsx` — asset multi-select, TagSelector, credencial linking — reutilizar no wizard
- `client/src/components/layout/sidebar.tsx` — onde adicionar entrada "API Discovery" no grupo Operações

### Router e navegação
- `client/src/App.tsx` — adicionar rota `/journeys/api` com import da nova página

### Backend endpoints que a UI consome
- `server/routes/apis.ts` — `GET /api/v1/apis`, `GET /api/v1/apis/:id/endpoints` (Phase 11)
- `server/routes/findings.ts` (ou equivalente Phase 14) — `GET /api/v1/findings?source=api_security`, `PATCH /api/v1/findings/:id`
- `server/routes/jobs.ts` — `POST /api/v1/jobs` (criar job api_security), `POST /api/v1/jobs/:id/abort` (Phase 15)

### Schema (tipos compartilhados)
- `shared/schema.ts` — `Api`, `ApiEndpoint`, `ApiCredential`, `ApiFinding` — tipos para props dos componentes

### Context Phase 15 (orquestração backend)
- `.planning/phases/15-journey-orchestration-safety/15-CONTEXT.md` — campos do body de criação de journey api_security (authorizationAck, toggles, rateLimit, destructiveEnabled, dryRun)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `Table`, `TableBody`, `TableCell`, `TableHead`, `TableHeader`, `TableRow` (Radix UI) — usados em todas as páginas de listagem; API Discovery segue o mesmo padrão.
- `Sheet`, `SheetContent`, `SheetHeader`, `SheetTitle` — drill-down de endpoints via Sheet (padrão EDR em `journeys.tsx:SheetContent`).
- `Dialog`, `DialogContent`, `DialogHeader`, `DialogTitle` — wizard e curl reproduction.
- `AlertDialog` — confirmação de false-positive (padrão de `assets.tsx`).
- `Collapsible`, `CollapsibleContent`, `CollapsibleTrigger` — agrupamento de endpoints por path (padrão em `threats.tsx`).
- `Badge` — OWASP category badges + method badges. Padrão de cor por severidade já existe em `threats.tsx`.
- `Select`, `SelectContent`, `SelectItem` — filtro de source na threats page.
- `Checkbox` — authorization acknowledgment + destructiveEnabled.
- `TagSelector` + asset multi-select de `journey-form.tsx` — reutilizar no passo 1 do wizard.
- `useQuery`, `useMutation`, `useQueryClient` de `@tanstack/react-query` — padrão de dados em todas as páginas.
- `useToast` — feedback de ações (padrão universal).
- `apiRequest` de `@/lib/queryClient` — helper para chamadas autenticadas.

### Established Patterns
- **Página com tabela**: `Sidebar + TopBar + Card + Table` — estrutura idêntica em todas as páginas principais.
- **Sheet drill-down**: abrir `SheetContent` ao clicar em linha da tabela — `selectedId` em useState, query habilitada com `enabled: !!selectedId`.
- **Filtros**: `Select` + `Input` de busca na toolbar acima da tabela — mesmo padrão em threats.tsx.
- **Mutations com confirmação**: `AlertDialog` → `useMutation` → `toast` → `queryClient.invalidateQueries`.
- **Multi-step form**: não existe ainda (wizard é novo) — implementar como Dialog com step state (`useState<1|2|3|4>`).

### Integration Points
- `client/src/App.tsx` — adicionar `import ApiDiscovery from "@/pages/api-discovery"` + `<Route path="/journeys/api" component={ApiDiscovery} />`.
- `client/src/components/layout/sidebar.tsx` — adicionar item no grupo "Operações" após "Jornadas".
- `client/src/pages/threats.tsx` — adicionar Select de `source` nos filtros + coluna OWASP conditional + botões "Reproduzir" e "Falso Positivo" no menu de ações.

</code_context>

<specifics>
## Specific Ideas

- O wizard deve usar o mesmo estilo visual das outras páginas — fundo dark, Tailwind classes padrão do projeto. Não introduzir estilos inline ou novas variáveis CSS.
- O drill-down de endpoints no Sheet deve mostrar os parâmetros conhecidos em chips/badges pequenos (path params em laranja, query params em azul, header params em roxo) para diferenciação visual rápida.
- O curl gerado deve ter linha de break (`\`) para legibilidade:
  ```
  curl -X POST "https://api.example.com/v1/users" \
    -H "Authorization: Bearer $BEARER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"key": "value"}'
  ```
- O passo 3 do wizard deve mostrar um resumo visual dos toggles ativos como lista de chips — não checkboxes puros — para reforçar o que está ativado antes de confirmar.
- OWASP category badges devem usar código abreviado (API1:2023, API2:2023, etc.) para economizar espaço na tabela, com tooltip mostrando o nome completo em pt-BR.

</specifics>

<deferred>
## Deferred Ideas

- Dashboard executivo com métricas de api_security journeys (endpoints testados, findings por severity, trend ao longo do tempo) — backlog pós-v2.0.
- Exportação de findings de api_security como PDF/CSV — backlog pós-v2.0.
- Visualização de grafo de endpoints descobertos (mapa de API surface) — alta complexidade, backlog futuro.

</deferred>

---

*Phase: 16-ui-final-integration*
*Context gathered: 2026-04-20*
