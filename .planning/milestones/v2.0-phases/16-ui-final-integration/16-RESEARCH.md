# Phase 16: UI & Final Integration - Research

**Researched:** 2026-04-20
**Domain:** React + TypeScript frontend — page scaffolding, multi-step wizard, OWASP badge rendering, curl generation, false-positive mutation
**Confidence:** HIGH (all findings verified directly in project source — no external research required)

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Página API Discovery (`/journeys/api`) — UI-01**
- Layout: Tabela (padrão consistente — journeys.tsx, assets.tsx, threats.tsx). Colunas: baseUrl, tipo (REST/GraphQL/SOAP), método de discovery, contagem de endpoints, última execução.
- Drill-down: Sheet lateral (padrão do journeys.tsx com EDR deployments). Clicar em API abre Sheet com endpoints agrupados por path.
- Agrupamento de endpoints: Collapsible por path. Dentro de cada path: method badges (GET=verde, POST=azul, PUT=amarelo, DELETE=vermelho, PATCH=laranja) + indicador de auth-required + parâmetros conhecidos.
- Rota no router: `/journeys/api` (nova rota em `client/src/App.tsx`) — página separada.
- Link na sidebar: Grupo "Operações" — item "API Discovery" com ícone `Globe` ou `NetworkIcon` após "Jornadas".
- Dados: `GET /api/v1/apis` para listagem; `GET /api/v1/apis/:id/endpoints` para drill-down.

**Wizard 4 passos — UI-06**
- Contentor: Dialog (max-w-3xl). Não Sheet, não página full.
- Navegação: Stepper horizontal 1-4 no topo. Botões "Anterior" / "Próximo" no rodapé. "Criar Jornada" somente no passo 4.
- Passo 1 — Alvos: Nome + assets (reusa TagSelector e asset multi-select de journey-form.tsx) + campo target URL base.
- Passo 2 — Autenticação: Seleção de credencial API existente + botão "Criar nova credencial" inline (Dialog aninhado). Toggle authorizationAck como Checkbox obrigatório com label vermelho.
- Passo 3 — Configuração: Discovery toggles (spec-first ON, crawler ON, kiterunner OFF). Testing toggles (misconfigs ON, auth ON, BOLA OFF, BFLA OFF, BOPLA OFF, rate-limit ON, SSRF OFF). Campo rateLimit (1-50 req/s, default 10). destructiveEnabled Checkbox vermelho. Preview de requests estimados como Badge cinza atualizado ao mudar toggles.
- Passo 4 — Confirmação: Resumo read-only. Checkbox dryRun opcional. Botão "Criar Jornada" em destaque.
- Schema Zod no frontend: `authorizationAck: z.boolean().refine(v => v === true, 'Obrigatório')` — bloqueia avanço.
- Acessar o wizard: Botão "Nova Jornada API" na página `/journeys/api`. journeys.tsx existente NÃO é modificado.

**Filtro OWASP na página de findings — UI-03**
- Localização: página threats.tsx existente — adicionar Select de `source` na toolbar de filtros.
- OWASP category badge: coluna adicional na tabela quando source=api_security ativo. Código abreviado (ex: "API1:2023"). Cor = severidade.
- Fallback: badge "N/A" em cinza se sem categoria OWASP.
- Dados: campo owaspCategory em api_findings + exposto via threats com source=api_security filter no backend.

**Curl reproduction ("Reproduzir") — UI-04**
- Trigger: botão "Reproduzir" (ícone Terminal ou Code2) no menu de ações por finding quando source=api_security.
- Output: Dialog com `<pre>` code block. Botão "Copiar" com navigator.clipboard. Fechamento via "Fechar".
- Formato: gerado client-side a partir de campos do finding. Credenciais substituídas por placeholders ($API_KEY, $BEARER_TOKEN, $BASIC_AUTH). Nunca valores reais.
- Fallback: mensagem "Não foi possível gerar curl — dados de endpoint insuficientes".

**False-positive marking — UI-05**
- Trigger: botão "Falso Positivo" (ícone ShieldOff ou EyeOff) no menu de ações por finding.
- UX: AlertDialog de confirmação. Padrão existente de AlertDialog em assets.tsx.
- Mutation: `PATCH /api/v1/findings/:id` com `{ falsePositive: true }` — useMutation + invalidateQueries.
- Feedback: Toast "Finding marcado como falso positivo" após sucesso.
- Estado visual: linha com opacidade reduzida e badge "Falso Positivo".

### Claude's Discretion
- Ícone exato para API Discovery na sidebar.
- Animação de transição entre passos do wizard.
- Algoritmo exato de estimativa de requests no passo 3 (pode ser simples: `endpoints × stagesAtivos × 2`).
- Paginação vs scroll na tabela de endpoints no drill-down.
- Cor exata dos method badges (desde que diferenciáveis).

### Deferred Ideas (OUT OF SCOPE)
- Dashboard executivo com métricas de api_security journeys — backlog pós-v2.0.
- Exportação de findings de api_security como PDF/CSV — backlog pós-v2.0.
- Visualização de grafo de endpoints descobertos — backlog futuro.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| UI-01 | New page `/journeys/api` lists discovered APIs with baseUrl, type, discovery method, endpoint count, last-execution metadata | GET /api/v1/apis route must be added (not yet present). Pattern: `useQuery + Table + Sheet` from journeys.tsx. |
| UI-02 | Drill-down view shows endpoints grouped by path with method badges, auth-required indicator, and known parameters | GET /api/v1/apis/:id/endpoints route must be added. Collapsible pattern exists in threats.tsx. Sheet pattern from journeys.tsx EDR block. |
| UI-03 | Findings page supports filtering by `source=api_security` and displays OWASP API Top 10 category badges | GET /api/threats already returns `source` field. Backend needs `source` filter param added. OWASP_API_CATEGORY_LABELS available from shared/owaspApiCategories.ts. |
| UI-04 | Each finding has a "Reproduzir" button that outputs a curl command with credential placeholders (never actual secret values) | Pure client-side generation from finding.evidence fields. Dialog pattern from threats.tsx. navigator.clipboard available. |
| UI-05 | User can mark a finding as false_positive, which is recorded in the audit log | PATCH /api/v1/findings/:id route must be created (currently the apiFindings route only has GET). AlertDialog pattern from assets.tsx. useMutation + invalidateQueries pattern from threats.tsx. |
| UI-06 | Journey creation wizard (4 steps) includes the authorization acknowledgment checkbox and an estimated-requests preview | Dialog multi-step form — new pattern. Reuses TagSelector, asset multi-select from journey-form.tsx. POST /api/v1/jobs from Phase 15. authorizationAck Zod refine on frontend. |
</phase_requirements>

---

## Summary

Phase 16 is a pure frontend phase with two required backend additions. All 6 UI requirements map to well-established patterns already present in the codebase — `Table + Sheet + Collapsible + Dialog + AlertDialog + useMutation`. The primary implementation effort is: (1) the new `ApiDiscovery` page (~400 lines), (2) the 4-step wizard Dialog (~350 lines), (3) targeted additions to `threats.tsx` for OWASP badge column + source filter + "Reproduzir" + "Falso Positivo" action buttons (~150 lines), and (4) two missing backend routes (`GET /api/v1/apis`, `GET /api/v1/apis/:id/endpoints`, `PATCH /api/v1/findings/:id`).

Two critical gaps exist in the backend that CONTEXT.md assumed were delivered but are not present in the code: `GET /api/v1/apis` (list), `GET /api/v1/apis/:id/endpoints` (drill-down), and `PATCH /api/v1/findings/:id` (false-positive). These must be created in Phase 16 Wave 1 before the UI can function. Additionally, `GET /api/threats` currently does not accept a `source` query filter — this must be added to both storage and route.

**Primary recommendation:** Build backend routes first (Wave 1), then page shell + table (Wave 2), then Sheet drill-down + filter additions + wizard (Wave 3), then curl + false-positive (Wave 4), using the existing page/component/mutation patterns throughout.

---

## Standard Stack

### Core (already installed — no new packages)

| Library | Version (in use) | Purpose | Why Standard |
|---------|-----------------|---------|--------------|
| React | 18.x | UI framework | Project baseline |
| @tanstack/react-query | 5.x | Server state + mutations | Universal project pattern |
| wouter | 3.x | Client routing | Used in App.tsx for all routes |
| @radix-ui/react-* | project version | Headless UI primitives (Dialog, Sheet, Collapsible, AlertDialog) | Already imported across all pages |
| Tailwind CSS | 3.x | Utility styling | Dark theme, project conventions |
| zod | 3.x | Runtime validation + form schemas | Used in all existing forms |
| react-hook-form | 7.x | Form state | Used in journey-form.tsx |
| @hookform/resolvers | 3.x | zodResolver bridge | Used in journey-form.tsx |
| lucide-react | project version | Icon set | Used universally in sidebar, pages |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| date-fns | project version | Date formatting | Already used in journeys.tsx (`format()`) |
| navigator.clipboard | Web API | Copy curl to clipboard | Curl reproduction Dialog |

**Installation:** No new packages needed — all dependencies already in `package.json`.

---

## Architecture Patterns

### Recommended Project Structure

New files to create:

```
client/src/pages/
└── api-discovery.tsx         # UI-01 + UI-02 + UI-06 (page + drill-down Sheet + wizard Dialog)

client/src/components/forms/
└── api-security-wizard.tsx   # UI-06 (4-step wizard, extracted as component)

server/routes/
└── apis.ts                   # ADD: GET /api/v1/apis, GET /api/v1/apis/:id/endpoints, PATCH /api/v1/findings/:id

server/storage/
└── apis.ts                   # ADD: listApis(), getApiEndpoints(apiId)
└── apiFindings.ts             # ADD: patchApiFinding(id, data) + audit log
```

Modifications to existing files:

```
client/src/App.tsx             # add Route path="/journeys/api"
client/src/components/layout/sidebar.tsx  # add "API Discovery" item in Operações group
client/src/pages/threats.tsx   # add source Select filter + owaspCategory column + Reproduzir + FalsoPositivo
server/routes/threats.ts       # add source to GET /api/threats query filter
server/storage/threats.ts      # add source filter to getThreatsWithHosts()
```

### Pattern 1: Page with Table + Sheet Drill-Down (from journeys.tsx)

**What:** Main page renders a full-width Card with Table. Clicking a row sets `selectedId` state, enabling a secondary `useQuery` with `enabled: !!selectedId`. Data renders inside a `SheetContent`.

**When to use:** API Discovery page (UI-01 + UI-02)

**Example (simplified from journeys.tsx):**
```typescript
// Source: client/src/pages/journeys.tsx lines 64-84, 525-615
const [selectedJourneyId, setSelectedJourneyId] = useState<string | null>(null);

const { data: edrDeployments = [] } = useQuery({
  queryKey: ["/api/edr-deployments", { journeyId: selectedJourneyId }],
  enabled: !!selectedJourneyId,
});

<Sheet open={!!selectedJourneyId} onOpenChange={(open) => !open && setSelectedJourneyId(null)}>
  <SheetContent side="right" className="w-[700px] sm:max-w-[700px] overflow-y-auto">
    ...
  </SheetContent>
</Sheet>
```

For `api-discovery.tsx`, adapt to: `selectedApiId` → query `GET /api/v1/apis/:id/endpoints`.

### Pattern 2: Collapsible Groups (from threats.tsx)

**What:** Renders a Collapsible wrapping TableRow(s). CollapsibleTrigger is a ChevronDown/ChevronRight button. CollapsibleContent renders child rows.

**When to use:** Endpoint grouping by path in the Sheet drill-down (UI-02)

**Example (from threats.tsx lines 968-1131):**
```typescript
// Source: client/src/pages/threats.tsx renderParentGroup()
<Collapsible open={isExpanded} onOpenChange={() => toggleGroup(parent.id)} asChild>
  <>
    <TableRow>
      <TableCell>
        <CollapsibleTrigger asChild>
          <button>
            {isExpanded ? <ChevronDown /> : <ChevronRight />}
          </button>
        </CollapsibleTrigger>
      </TableCell>
      ...
    </TableRow>
    <CollapsibleContent asChild>
      <>
        {children.map(child => renderChildRow(child))}
      </>
    </CollapsibleContent>
  </>
</Collapsible>
```

For endpoint drill-down, group `ApiEndpoint[]` by `path` client-side, render one Collapsible per path.

### Pattern 3: Mutation with AlertDialog Confirmation (from assets.tsx pattern)

**What:** Action button triggers AlertDialog state. "Confirmar" in AlertDialog fires `useMutation`. `onSuccess` calls `toast()` + `queryClient.invalidateQueries()`.

**When to use:** False-positive marking (UI-05)

```typescript
// Pattern verified in threats.tsx updateThreatMutation (lines 456-491) and statusChangeModal pattern
const falsePositiveMutation = useMutation({
  mutationFn: async (id: string) =>
    await apiRequest("PATCH", `/api/v1/findings/${id}`, { falsePositive: true }),
  onSuccess: () => {
    toast({ title: "Sucesso", description: "Finding marcado como falso positivo" });
    queryClient.invalidateQueries({ queryKey: ["/api/v1/findings"] });
  },
});
```

### Pattern 4: Multi-Step Dialog Wizard (new — no existing precedent)

**What:** Dialog with `useState<1|2|3|4>(step)`. Renders conditional step content based on step number. Footer has "Anterior" / "Próximo" / "Criar Jornada" buttons.

**When to use:** API Security journey creation wizard (UI-06)

```typescript
// New pattern — adapted from Dialog usage in journeys.tsx
const [step, setStep] = useState<1|2|3|4>(1);
const [wizardData, setWizardData] = useState<ApiSecurityWizardData>(defaults);

<Dialog open={wizardOpen} onOpenChange={setWizardOpen}>
  <DialogContent className="max-w-3xl">
    <DialogHeader>
      <DialogTitle>Nova Jornada API</DialogTitle>
      {/* Stepper horizontal */}
      <div className="flex items-center gap-2">
        {[1,2,3,4].map(n => (
          <div key={n} className={cn("w-8 h-8 rounded-full flex items-center justify-center text-sm",
            step >= n ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground"
          )}>{n}</div>
        ))}
      </div>
    </DialogHeader>
    {step === 1 && <Step1Alvos data={wizardData} onChange={setWizardData} />}
    {step === 2 && <Step2Auth data={wizardData} onChange={setWizardData} />}
    {step === 3 && <Step3Config data={wizardData} onChange={setWizardData} />}
    {step === 4 && <Step4Confirmation data={wizardData} />}
    <div className="flex justify-between pt-4">
      {step > 1 && <Button variant="outline" onClick={() => setStep(s => (s-1) as any)}>Anterior</Button>}
      {step < 4 && <Button onClick={handleNext} disabled={!isStepValid(step)}>Próximo</Button>}
      {step === 4 && <Button onClick={handleSubmit} disabled={createMutation.isPending}>Criar Jornada</Button>}
    </div>
  </DialogContent>
</Dialog>
```

### Pattern 5: Source Filter in threats.tsx

**What:** Add a `Select` component to the existing filter toolbar. The selected value is passed as a query param to `GET /api/threats?source=api_security`. Conditional rendering of the OWASP column depends on `sourceFilter === 'api_security'`.

**When to use:** UI-03

```typescript
// Add alongside existing Select components at threats.tsx line 1357-1404
const [sourceFilter, setSourceFilter] = useState<string>("all");

<Select value={sourceFilter} onValueChange={setSourceFilter}>
  <SelectTrigger className="w-48">
    <SelectValue placeholder="Filtrar por fonte" />
  </SelectTrigger>
  <SelectContent>
    <SelectItem value="all">Todas as Fontes</SelectItem>
    <SelectItem value="api_security">API Security</SelectItem>
  </SelectContent>
</Select>
```

The `useQuery` queryKey must include `sourceFilter` so React Query re-fetches when it changes.

### Anti-Patterns to Avoid

- **Modifying journeys.tsx:** The wizard is isolated to the `/journeys/api` page. journeys.tsx must not be touched.
- **Real secrets in curl output:** The `buildCurlCommand()` function must never read the actual credential value — only use the `authType` field to select the placeholder string. Evidence fields may contain partial auth info (masked in Phase 12) but placeholders are still safer.
- **Full-table scan on api_findings:** `GET /api/v1/api-findings` requires at least one of `apiId/endpointId/jobId`. Do not expose a parameterless list endpoint.
- **Importing from AGENTS.md or large context files:** All necessary types are in `shared/schema.ts` and `shared/owaspApiCategories.ts`.
- **Adding `source` filter client-side only:** The `threats.tsx` filter for `source=api_security` must be passed as a query param to the backend (the existing `getThreatsWithHosts` must be extended), not filtered client-side on the full threats array. Client-side filtering would break pagination and stats.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| OWASP category display | Custom label mapping | `OWASP_API_CATEGORY_LABELS` from `shared/owaspApiCategories.ts` | Already maps all 10 categories with `codigo`, `titulo`, `tituloIngles` |
| Credential placeholder selection | Custom auth type detection | `authType` field from finding evidence (already in schema) | Phase 12 stores `authType` in evidence |
| Date formatting | Custom date logic | `date-fns` `format()` already imported in journeys.tsx | Consistent locale formatting |
| Severity color mapping | New switch/case | `getSeverityColor()` pattern from threats.tsx (lines 660-674) | Already handles critical/high/medium/low |
| Clipboard copy | Custom copy mechanism | `navigator.clipboard.writeText()` | Web standard, no library needed |
| Zod form validation in wizard | Manual validation | `react-hook-form` + `zodResolver` (same pattern as journey-form.tsx) | Already wired, no new deps |
| `apiRequest` HTTP calls | `fetch()` directly | `apiRequest` from `@/lib/queryClient` | Handles auth headers, error normalization |

**Key insight:** Every UI primitive (Dialog, Sheet, Collapsible, AlertDialog, Badge, Select, Checkbox, Table) and every data access helper (`useQuery`, `useMutation`, `apiRequest`, `useToast`, `queryClient.invalidateQueries`) is already imported and used in existing pages. Phase 16 is assembly, not construction.

---

## Common Pitfalls

### Pitfall 1: Missing Backend Routes — GET /api/v1/apis and GET /api/v1/apis/:id/endpoints

**What goes wrong:** The CONTEXT.md mentions these as "Phase 11 routes" but inspecting `server/routes/apis.ts` confirms only `POST /api/v1/apis` and the scanner routes exist. There is no `GET /api/v1/apis` or `GET /api/v1/apis/:id/endpoints`.

**Why it happens:** Phase 11 built the storage facade (`listApis`, `listApisByParent`) but did not expose a GET list endpoint because the API was internal-only at that stage.

**How to avoid:** Phase 16 Wave 1 must add these GET routes to `server/routes/apis.ts` and register them in `registerApiRoutes()`. The storage functions `listApis()` and `getApiEndpoints(apiId)` are already in `server/storage/apis.ts`.

**Warning signs:** 404 errors when the ApiDiscovery page mounts and calls `GET /api/v1/apis`.

### Pitfall 2: Missing PATCH /api/v1/findings/:id

**What goes wrong:** The CONTEXT.md states `PATCH /api/v1/findings/:id` was delivered in Phase 14, but `server/routes/apiFindings.ts` only contains `GET /api/v1/api-findings`. There is no PATCH endpoint.

**Why it happens:** Phase 14 focused on sanitization and promotion; the false-positive mutation was left to the UI phase.

**How to avoid:** Add `PATCH /api/v1/api-findings/:id` to `server/routes/apiFindings.ts` in Wave 1. Must accept `{ falsePositive: true }` (maps to `status: 'false_positive'`), update the row, and write to `audit_log`.

**Warning signs:** 404 on mutation; `falsePositiveMutation.isError` fires immediately.

### Pitfall 3: source Filter Not in Backend GET /api/threats

**What goes wrong:** `getThreatsWithHosts()` in `server/storage/threats.ts` accepts `{ severity, status, assetId, hostId }` but NOT `source`. The frontend cannot filter by `source=api_security` unless the backend is extended.

**Why it happens:** The filter interface was defined before `api_security` source existed.

**How to avoid:** Add `source?: string` to the filter object in `getThreatsWithHosts()` and add `if (filters.source) conditions.push(eq(threats.source, filters.source))`. Extend `GET /api/threats` route handler to read `req.query.source`. Update `useQuery` key in threats.tsx to include `sourceFilter`.

**Warning signs:** Changing the source Select does not change the threats displayed.

### Pitfall 4: OWASP Badge Column Always Visible

**What goes wrong:** Adding the OWASP column unconditionally to the threats table breaks layout for non-api_security threats (which have no `owaspCategory` on `threats` rows).

**Why it happens:** The `threats` table stores `category` (used for grouping), not `owaspCategory`. The OWASP info lives in `api_findings` — threats promoted from api_findings carry the OWASP category in their `title` (per `threatPromotion.ts` line 156: `title` includes the owaspCategory).

**How to avoid:** The OWASP badge column should only render when `sourceFilter === 'api_security'`. The badge text is parsed from the threat `title` or the `category` field — both populated by `threatPromotion.ts`. Alternatively, store `owaspCategory` in `threats.evidence` during promotion. Verify the evidence payload shape from `threatPromotion.ts` before rendering.

**Warning signs:** Badge column appears with "N/A" on all existing threats; layout overflow on non-api rows.

### Pitfall 5: Curl Generation Without Sufficient Evidence Data

**What goes wrong:** The `ApiFindingEvidence` Zod schema stores method, url, headers, body schema — but evidence is sanitized (Phase 14 FIND-02). Auth headers are REDACTED. The curl generator must reconstruct the Authorization header from the `authType` placeholder, not from any stored header value.

**Why it happens:** Phase 12 stores headers as `Authorization: Bearer ***` (3-char prefix + `***`). The redacted value must not appear in the curl output.

**How to avoid:** In `buildCurlCommand(finding)`, read `finding.evidence.method`, `finding.evidence.url`, `finding.evidence.requestSchema` (body template). Determine auth placeholder from `finding.evidence.authType` (if present in evidence) using a switch:
```typescript
const authHeader = {
  api_key_header: '-H "X-API-Key: $API_KEY"',
  bearer_jwt: '-H "Authorization: Bearer $BEARER_TOKEN"',
  basic: '-H "Authorization: Basic $BASIC_AUTH"',
}[finding.evidence?.authType ?? ''] ?? '';
```

**Warning signs:** Curl output contains `***` or actual credential fragments; fallback "dados insuficientes" shown even when evidence exists.

### Pitfall 6: Wizard authorizationAck Blocks Form Submission But Not Step Navigation

**What goes wrong:** The Zod schema with `.refine(v => v === true, 'Obrigatório')` only runs on final submission. The wizard must also block "Próximo" in Step 2 until the checkbox is checked.

**Why it happens:** react-hook-form validation is triggered at submit time unless `mode: 'onChange'` is set or explicit `trigger()` is called per step.

**How to avoid:** In `handleNext()` for step 2, call `form.trigger('authorizationAck')` before advancing. Or manage `authorizationAck` as local state checked synchronously in the step validation guard.

**Warning signs:** User can advance from Step 2 to Step 3 without checking the authorization checkbox.

---

## Code Examples

Verified patterns from project source:

### OWASP Category Badge Rendering

```typescript
// Source: shared/owaspApiCategories.ts
import { OWASP_API_CATEGORY_LABELS, type OwaspApiCategory } from "@shared/owaspApiCategories";

function OwaspBadge({ category, severity }: { category: string | null; severity: string }) {
  if (!category || !(category in OWASP_API_CATEGORY_LABELS)) {
    return <Badge variant="secondary" className="bg-muted text-muted-foreground">N/A</Badge>;
  }
  const info = OWASP_API_CATEGORY_LABELS[category as OwaspApiCategory];
  return (
    <Badge
      className={getSeverityColor(severity)}
      title={info.titulo}
    >
      {info.codigo}
    </Badge>
  );
}
```

### Method Badge Color Mapping

```typescript
// Per CONTEXT.md: GET=verde, POST=azul, PUT=amarelo, DELETE=vermelho, PATCH=laranja
const METHOD_COLORS: Record<string, string> = {
  GET: "bg-green-600/20 text-green-500",
  POST: "bg-blue-600/20 text-blue-500",
  PUT: "bg-yellow-500/20 text-yellow-600",
  DELETE: "bg-destructive/20 text-destructive",
  PATCH: "bg-orange-500/20 text-orange-600",
};

function MethodBadge({ method }: { method: string }) {
  const color = METHOD_COLORS[method.toUpperCase()] ?? "bg-muted text-muted-foreground";
  return <Badge className={color}>{method.toUpperCase()}</Badge>;
}
```

### Curl Command Builder (client-side)

```typescript
// Source: CONTEXT.md §Specific Ideas curl format
function buildCurlCommand(finding: ApiFinding): string | null {
  const ev = finding.evidence as any;
  if (!ev?.url || !ev?.method) return null;

  const AUTH_PLACEHOLDER: Record<string, string> = {
    api_key_header: '-H "X-API-Key: $API_KEY"',
    api_key_query: '', // appended to URL as ?api_key=$API_KEY
    bearer_jwt: '-H "Authorization: Bearer $BEARER_TOKEN"',
    basic: '-H "Authorization: Basic $BASIC_AUTH"',
    oauth2_client_credentials: '-H "Authorization: Bearer $BEARER_TOKEN"',
  };

  const authFlag = ev.authType ? (AUTH_PLACEHOLDER[ev.authType] ?? '') : '';
  const contentType = ev.requestSchema ? '-H "Content-Type: application/json" \\' : '';
  const body = ev.requestSchema
    ? `  -d '${JSON.stringify(ev.requestSchema).slice(0, 500)}'`
    : '';

  return [
    `curl -X ${ev.method.toUpperCase()} "${ev.url}" \\`,
    authFlag ? `  ${authFlag} \\` : null,
    contentType || null,
    body || null,
  ].filter(Boolean).join('\n');
}
```

### Parameter Chips in Endpoint Drill-Down

```typescript
// Per CONTEXT.md §Specific Ideas: path=laranja, query=azul, header=roxo
const PARAM_COLORS = {
  path: "bg-orange-500/20 text-orange-600",
  query: "bg-blue-500/20 text-blue-500",
  header: "bg-purple-500/20 text-purple-500",
};

function ParamChip({ name, location }: { name: string; location: string }) {
  const color = PARAM_COLORS[location as keyof typeof PARAM_COLORS] ?? "bg-muted text-muted-foreground";
  return <Badge className={`text-xs ${color}`}>{name}</Badge>;
}
```

### Estimated Requests Preview

```typescript
// Per CONTEXT.md §Claude's Discretion: endpoints × stagesAtivos × 2
function estimateRequests(endpointCount: number, config: WizardStep3Config): number {
  const stages = [
    config.specFirst,
    config.crawler,
    config.kiterunner,
    config.misconfigs,
    config.auth,
    config.bola,
    config.bfla,
    config.bopla,
    config.rateLimitTest,
    config.ssrf,
  ].filter(Boolean).length;
  return endpointCount * stages * 2;
}

// In Step 3 JSX:
<Badge variant="secondary">
  ~{estimateRequests(endpointCount, config)} requests estimados
</Badge>
```

### Sidebar Entry Addition

```typescript
// Source: client/src/components/layout/sidebar.tsx lines 38-68
// Add to navGroups[2].items (Operações group) after Route item:
{ href: "/journeys/api", label: "API Discovery", icon: Globe }

// Import Globe from lucide-react (already available in the icon set)
```

### Route Registration in App.tsx

```typescript
// Source: client/src/App.tsx pattern (lines 147-178)
import ApiDiscovery from "@/pages/api-discovery";

// Inside Router's authenticated Switch:
<Route path="/journeys/api" component={ApiDiscovery} />
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Global threat list without source filter | Backend-filtered threats by source | Phase 16 adds this | Enables UI-03 without client-side filtering perf issues |
| No API list route (internal only) | GET /api/v1/apis public endpoint | Phase 16 adds this | Enables UI-01 page |
| No false-positive PATCH route | PATCH /api/v1/api-findings/:id | Phase 16 adds this | Enables UI-05 |

**Deprecated/outdated:**
- The assumption that `PATCH /api/v1/findings/:id` was delivered in Phase 14 — it was NOT. Phase 16 must create it in `apiFindings.ts`.

---

## Backend Gaps (Critical — Must be Created in Phase 16 Wave 1)

These routes are referenced in CONTEXT.md but do NOT exist in the codebase:

### 1. GET /api/v1/apis

Storage function `listApis()` exists at `server/storage/apis.ts:14`. Route must be added to `registerApiRoutes()` in `server/routes/apis.ts`.

Response shape per `Api` type from `shared/schema.ts`: `{ id, parentAssetId, baseUrl, apiType, name, description, specUrl, discoveryMethod, endpointCount (computed), lastExecutionAt, createdAt, updatedAt }`.

Note: `endpointCount` must be computed via a JOIN or subquery — it is NOT a column on `apis`. Use `db.select({ count: count() }).from(apiEndpoints).where(eq(apiEndpoints.apiId, api.id))` or a single query with aggregation.

### 2. GET /api/v1/apis/:id/endpoints

Storage function `getApiEndpointsByApiId()` should be verified or created. Response shape per `ApiEndpoint` from schema: `{ id, apiId, method, path, params (JSON), requestSchema, responseSchema, requiresAuth, discoverySources, httpx_* columns, createdAt, updatedAt }`.

### 3. PATCH /api/v1/api-findings/:id

Must accept `{ falsePositive: boolean }` body. Internally maps to `status: 'false_positive'`. Must write to `audit_log` with `actorId`, `action: 'update'`, `objectType: 'api_finding'`.

### 4. source filter in GET /api/threats

Extend `getThreatsWithHosts({ source?: string })` to add `if (filters.source) conditions.push(eq(threats.source, filters.source))`. Update the route handler to pass `req.query.source`.

---

## Open Questions

1. **endpointCount on apis — how to compute efficiently**
   - What we know: `apis` table has no `endpointCount` column. `api_endpoints` table has `apiId` FK.
   - What's unclear: Whether to use a subquery in the list query or a separate aggregation step.
   - Recommendation: Use a single query with LEFT JOIN + COUNT grouped by `apis.id`. Verified that drizzle ORM supports this pattern.

2. **owaspCategory on threats — where is it stored after promotion**
   - What we know: `threatPromotion.ts` stores `source: 'api_security'` and `category: apiId`. The `title` includes the `owaspCategory` string.
   - What's unclear: Whether `threats.evidence` is extended with `owaspCategory` during promotion.
   - Recommendation: Inspect `threatPromotion.ts` `buildTitle()` or `promoteFinding()` more carefully when implementing the badge. If not in evidence, parse from title using `OWASP_API_CATEGORY_LABELS` keys — or add `owaspCategory` to the `threats.evidence` JSON during promotion in Wave 1.

3. **Dialog nesting: wizard with inline credential creation**
   - What we know: Radix UI AlertDialog and Dialog can be nested, but z-index and focus trap require care.
   - What's unclear: Whether the existing Radix Dialog handles nested Dialog focus correctly in the current Radix version.
   - Recommendation: Use a separate state flag `credentialDialogOpen` independent of wizard step. Test focus trap manually. Pattern has precedent in other Radix UI apps.

---

## Validation Architecture

`nyquist_validation: true` — include test stubs.

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Vitest (project standard, `vitest.config.ts` present) |
| Config file | `vitest.config.ts` |
| Quick run command | `npx vitest run --reporter=verbose` |
| Full suite command | `npx vitest run` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| UI-01 | GET /api/v1/apis route returns list of apis with correct shape | integration (route test) | `npx vitest run server/__tests__/apiUi/listApis.test.ts -t "GET /api/v1/apis"` | ❌ Wave 0 |
| UI-02 | GET /api/v1/apis/:id/endpoints returns endpoints grouped-ready (flat list, correct apiId FK) | integration (route test) | `npx vitest run server/__tests__/apiUi/listEndpoints.test.ts -t "GET /api/v1/apis/:id/endpoints"` | ❌ Wave 0 |
| UI-03 | GET /api/threats?source=api_security filters to only api_security threats | integration (route test) | `npx vitest run server/__tests__/apiUi/threatSourceFilter.test.ts -t "source filter"` | ❌ Wave 0 |
| UI-04 | buildCurlCommand() returns correct curl with placeholder and no real secrets | unit | `npx vitest run client/src/__tests__/curlBuilder.test.ts` | ❌ Wave 0 |
| UI-05 | PATCH /api/v1/api-findings/:id with falsePositive:true sets status to false_positive + writes audit_log | integration (route test) | `npx vitest run server/__tests__/apiUi/patchFinding.test.ts -t "PATCH false_positive"` | ❌ Wave 0 |
| UI-06 | estimateRequests() returns endpointCount × activeStages × 2 | unit | `npx vitest run client/src/__tests__/estimateRequests.test.ts` | ❌ Wave 0 |

### Sampling Rate

- **Per task commit:** `npx vitest run server/__tests__/apiUi/ client/src/__tests__/`
- **Per wave merge:** `npx vitest run`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `server/__tests__/apiUi/listApis.test.ts` — covers UI-01
- [ ] `server/__tests__/apiUi/listEndpoints.test.ts` — covers UI-02
- [ ] `server/__tests__/apiUi/threatSourceFilter.test.ts` — covers UI-03
- [ ] `server/__tests__/apiUi/patchFinding.test.ts` — covers UI-05
- [ ] `client/src/__tests__/curlBuilder.test.ts` — covers UI-04
- [ ] `client/src/__tests__/estimateRequests.test.ts` — covers UI-06

---

## Sources

### Primary (HIGH confidence)
- `client/src/pages/threats.tsx` — filter pattern, Badge, Collapsible, Dialog, useMutation, toast patterns; verified by direct source read
- `client/src/pages/journeys.tsx` — Sheet drill-down, Table, Dialog pattern with JourneyForm; verified by direct source read
- `client/src/components/layout/sidebar.tsx` — navGroups structure for adding sidebar items; verified by direct source read
- `client/src/App.tsx` — Route registration pattern; verified by direct source read
- `shared/owaspApiCategories.ts` — OWASP_API_CATEGORY_LABELS constants, all 10 categories with `codigo` field; verified by direct source read
- `server/routes/apis.ts` — confirmed missing GET /api/v1/apis and GET /api/v1/apis/:id/endpoints; verified by direct source read
- `server/routes/apiFindings.ts` — confirmed only GET exists, no PATCH; verified by direct source read
- `server/storage/threats.ts` — confirmed `source` not in filter shape; verified by direct source read
- `server/services/threatPromotion.ts` — confirmed source='api_security' stored on promoted threats, category=apiId; verified by direct source read
- `client/src/components/forms/journey-form.tsx` — TagSelector, asset multi-select, react-hook-form + zodResolver patterns; verified by partial source read

### Secondary (MEDIUM confidence)
- `.planning/phases/16-ui-final-integration/16-CONTEXT.md` — canonical decisions on all 6 requirements; authoritative user choices
- `.planning/REQUIREMENTS.md` — normative requirement definitions for UI-01..06

### Tertiary (LOW confidence)
- None — all findings verified in project source

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all packages verified as already installed in project
- Architecture patterns: HIGH — all patterns verified in existing page source files
- Pitfalls: HIGH — all backend gaps verified by direct code inspection (not found = not found)
- Validation stubs: MEDIUM — test file paths are conventions following Phase 12 pattern; file structure not yet created

**Research date:** 2026-04-20
**Valid until:** 2026-05-20 (stable stack — React, Drizzle, Radix UI do not change rapidly)
