# SamurEye — Plano de 4 Revisões: Web App Journey, Hierarquia de Assets e UX

> **Status:** planejamento (pré-implementação). Nenhuma mudança de código ainda.
> **Base:** análise direta do código em `main @ 80f9d79`. Toda referência `file:line` aponta para esse SHA.
> **Alvo:** produção `app.samureye.com.br` (appliance). Toda mudança deve ser aditiva e não-quebrante.

---

## Sumário executivo

Quatro problemas interligados:

| # | Problema | Severidade | Complexidade |
|---|---|---|---|
| 1 | Jornada `web_application` não roda Nuclei de forma confiável | Média | Baixa |
| 2 | Attack Surface acopla descoberta e avaliação de web apps | Alta | Média |
| 3 | Lista de ativos é plana — web apps não agrupam sob seu host | Média | Média |
| 4 | Edição de jornada permite trocar `type` e não distingue imutável de editável | Baixa | Baixa |

**Ordem recomendada:** **3 → 2 → 1 → 4**. O Problema 3 (hierarquia) é pré-requisito dos Problemas 1 e 2 porque o schema precisa de `parentAssetId` antes que a Attack Surface possa criar `web_application` como filho de host e antes que a UI possa agrupar. O Problema 4 é ortogonal — pode sair em paralelo.

**Descobertas colaterais** (não eram parte dos 4 problemas, mas foram encontradas durante a análise):
- `createWebApplicationAssets` sempre inclui porta na URL (mesmo 80/443), enquanto `Phase 3C` usa `portSuffix` que omite portas default. Gera URLs divergentes entre descoberta e avaliação.
- Templates do Nuclei em `/tmp/nuclei/nuclei-templates` não têm pre-flight check. Se diretório não existir, Nuclei falha silencioso.

---

# Problema 1 — Jornada Web Application não executa Nuclei de forma confiável

## 1.1 Diagnóstico atual

O fluxo **existe** e está estruturalmente correto. A análise ponto a ponto:

1. **Disparo do job** — `server/routes/jobs.ts:23-48`
   - `POST /api/jobs/execute` recebe `journeyId`, chama `jobQueue.executeJobNow(journeyId)` na linha 32.

2. **Queue → execução** — `server/services/jobQueue.ts:98-125`
   - `executeJobNow()` cria registro `Job`, chama `enqueueJob()` → `processJob()`.

3. **Despacho por tipo** — `server/services/journeyExecutor.ts:77-100`
   - Switch em `journey.type` (linha 84). Para `web_application` chama `executeWebApplication()` (linha 95).

4. **Executor Web App** — `server/services/journeyExecutor.ts:483-577`
   - Resolve `assetIds` via params (linha 489).
   - Filtra assets com `type !== 'web_application'` (linhas 508-510).
   - Para cada app, chama `runNucleiWebScan([app.value], jobId, ...)` na linha 545.
   - Persiste resultados via `storage.createJobResult()` (linha 563).

5. **Invocação Nuclei** — `server/services/journeyExecutor.ts:1396-1478`
   - `child_process.spawn('nuclei', args)` na linha 1420.
   - Args (linhas 1404-1417): `-u <url> -jsonl -silent -duc -ni -nc -nm -s medium,high,critical -timeout 10 -retries 1 -c 5 -t /tmp/nuclei/nuclei-templates`.
   - Timeout com SIGTERM→SIGKILL (linhas 1435-1445).
   - Parsing delegado a `vulnScanner.parseNuclei(result)` na linha 1468.

6. **Geração de threats** — `server/services/threatEngine.ts:812-852`
   - `threatEngine.processJobResults(jobId)` chamado em `journeyExecutor.ts:110`.
   - Rota `analyzeWithLifecycle()` por tipo de jornada (linha 834).
   - Correlation key para `web_application` em `threatEngine.ts:859-886`.

**Conclusão:** o fluxo está ligado ponta a ponta. Se a jornada não produz resultado, as causas mais prováveis são:

## 1.2 Root cause (hipóteses ordenadas por probabilidade)

**A. Templates do Nuclei ausentes em `/tmp/nuclei/nuclei-templates`.**
Nenhum pre-flight check no código. `nuclei -t <dir-inexistente>` sai com 0 matches e exit code 0 — fluxo "termina com sucesso" mas sem findings.
**Evidência:** `journeyExecutor.ts:1416` referencia o diretório; grep mostra **zero** lugares onde o diretório é criado, `nuclei -update-templates` chamado, ou existência verificada.

**B. URL do asset em formato inesperado.**
`app.value` é passado direto a `-u`. `createWebApplicationAssets` (linha 1333) monta `${protocol}://${host}:${port}` e grava isso no `value`. Isso funciona para Nuclei, **mas**:
- Porta 80/443 sempre vai na URL (ex: `http://host:80`). Nuclei aceita, mas o host header/SNI pode vir estranho em alguns alvos.
- Se o asset foi criado manualmente (API direta) sem porta, `-u http://host` sem porta pode não resolver dependendo do DNS.
Sem validação antes do spawn.

**C. Binário `nuclei` ausente no PATH.**
`spawn('nuclei', ...)` falha silenciosamente sem pre-flight. O install.sh (linhas 280-334) instala nuclei em `/usr/local/bin`, mas se alguém fizer upgrade parcial, o binário pode desaparecer.

**D. Fluxo de dispatch da queue não está processando jobs em produção.**
`processJob()` é chamado dentro de `enqueueJob()` (linha 112 de `jobQueue.ts`). Não é um worker externo — é síncrono no mesmo processo. Verificar que o serviço `samureye-api` está realmente ativo ao criar a jornada.

## 1.3 Solução proposta

Três mudanças, cada uma como commit independente:

**1.3.1 Pre-flight check de templates e binário.**
Adicionar método privado `preflightNuclei()` em `journeyExecutor.ts` que executa **uma única vez por processo** (memoizado):
- Verifica `which nuclei` via `spawnSync` — se ausente, loga erro estruturado e lança exceção `NucleiNotAvailable`.
- Verifica `fs.existsSync('/tmp/nuclei/nuclei-templates')` — se ausente, tenta `nuclei -update-templates -silent` automaticamente com timeout de 5 min. Se falhar, loga warning e **continua com 0 findings** (fail-safe per pattern existente).
- Chamado no início de `runNucleiWebScan()`.

**1.3.2 Validação e normalização de URL.**
Antes do spawn:
```ts
function normalizeTarget(value: string): string | null {
  try {
    const u = new URL(value);
    if (!['http:', 'https:'].includes(u.protocol)) return null;
    // remove porta default
    const isDefault = (u.protocol === 'http:' && u.port === '80') || (u.protocol === 'https:' && u.port === '443');
    if (isDefault) u.port = '';
    return u.toString().replace(/\/$/, '');
  } catch { return null; }
}
```
Se `normalize` retorna `null`, log `warn` com o valor inválido e pula o asset (sem abortar a jornada inteira).

**1.3.3 Logging estruturado do resultado do Nuclei.**
Após cada spawn, log:
```
{ jobId, tool: "nuclei", target, exitCode, durationMs, stdoutBytes, stderrTail, findingsCount }
```
Isso dá diagnóstico rápido em produção sem precisar reproduzir.

## 1.4 Arquivos afetados

- Modificar: `server/services/journeyExecutor.ts` (método `runNucleiWebScan`, linhas 1396-1478)
- (Opcional) Criar: `server/services/journeys/nucleiPreflight.ts` — módulo dedicado se o método ficar grande
- Nenhuma mudança de schema

## 1.5 Ordem de implementação

1. Adicionar `preflightNuclei()` + integrar em `runNucleiWebScan` (commit 1)
2. Adicionar `normalizeTarget()` + aplicar (commit 2)
3. Logging estruturado (commit 3)

## 1.6 Riscos e cuidados

- **`nuclei -update-templates` em produção** pode demorar e consumir banda na primeira execução. Cercar com timeout de 5 min e rodar apenas se `-t <dir>` ausente.
- **Mudar URL normalizada** pode gerar dedup nos findings existentes (uma threat antiga em `http://host:80` vs nova em `http://host`). Estratégia: a normalização só afeta o TARGET passado ao Nuclei, não o `value` gravado em `assets`. Correlation key permanece baseada em `value` do asset + rule id do Nuclei. Sem colisão.
- **Falha do preflight não deve abortar a jornada** — deve produzir job com 0 findings e log claro de "templates ausentes".

## 1.7 Critérios de validação

1. **Smoke em prod:** criar asset `web_application` apontando para `https://httpbin.org`, criar jornada, executar, verificar no log: `nuclei exit=0 findings=N duration=Nms`.
2. **Falha graciosa:** renomear temporariamente `/tmp/nuclei/nuclei-templates` → rodar jornada → verificar log warning "templates missing" + jornada completa com status = `completed`, `jobResult.findings = []`.
3. **URL inválida:** criar asset com `value = "not-a-url"`, rodar jornada → log warn "invalid target", jornada segue para outros assets.

---

# Problema 2 — Separação entre Descoberta (Attack Surface) e Avaliação (Web Application)

## 2.1 Diagnóstico atual

**Attack Surface** (`server/services/journeyExecutor.ts:132-476`) tem quatro fases:

- **1A/1B** (linhas 184-279): descoberta de hosts + scan de portas via nmap.
- **3A/3B** (linhas 333-383): detecção opcional de CVEs via `nmap --script vuln` e lookup externo.
- **3C** (linhas 385-427): **scan web com Nuclei**, gated em `params.webScanEnabled === true`.
  - Monta `webUrls[]` a partir de port findings (linhas 388-404), com lógica correta de `portSuffix` (linha 402) que omite portas default.
  - Chama `this.runNucleiWebScan(webUrls, jobId, nucleiTimeoutMs)` (linha 416).
- **4** (linhas 442-456): **criação de assets `web_application`** via `createWebApplicationAssets(findings, createdBy, jobId)` (linha 454). **Sempre roda**, independente de webScanEnabled.

**`createWebApplicationAssets`** (linhas 1306-1355):
- Para cada port finding HTTP/HTTPS, monta `url = ${protocol}://${host}:${port}` (linha 1333).
- Cria asset via `storage.createAsset({ type: 'web_application', value: url, tags: [...], parentAssetId: parentHost?.id || null })` (linhas 1332-1344).
- **Atenção:** já tenta passar `parentAssetId`, mas a coluna **não existe** no schema atual (verificado em `shared/schema.ts:94-105`) — silenciosamente é ignorado pelo Drizzle/storage.

**Jornada Web Application** (`server/services/journeyExecutor.ts:483-577`):
- Espera `params.assetIds` contendo IDs de assets já criados.
- Filtra `asset.type === 'web_application'` (linha 508-510).
- Roda Nuclei em cada.

## 2.2 Root cause

1. **Acoplamento na Attack Surface:** Phase 3C avalia (Nuclei) e Phase 4 catalogza. Essas duas responsabilidades deveriam estar em jornadas distintas.
2. **Schema não suporta parent-child:** `createWebApplicationAssets` passa `parentAssetId` mas o campo não existe — perda silenciosa de dado.
3. **Sem normalização de URL entre descoberta e avaliação:** Phase 3C omite porta default, Phase 4 sempre inclui. Se o usuário executa só Attack Surface (sem webScanEnabled) e depois cria Web App Journey, a URL no asset (`http://host:80`) é passada ao Nuclei com porta, o que funciona mas difere do que Phase 3C faria.

## 2.3 Solução proposta

**2.3.1 Adicionar `parentAssetId` em `assets`** (necessário também pelo Problema 3 — consolidar aqui).
Migração aditiva:
```sql
ALTER TABLE assets ADD COLUMN parent_asset_id VARCHAR REFERENCES assets(id) ON DELETE CASCADE;
CREATE INDEX idx_assets_parent ON assets(parent_asset_id);
```
Drizzle:
```ts
parentAssetId: varchar("parent_asset_id").references(() => assets.id, { onDelete: 'cascade' }),
```
Atualizar `server/storage/assets.ts::createAsset()` para aceitar e persistir o campo (hoje ignora).

**2.3.2 Desacoplar Attack Surface.**
- Remover **Phase 3C inteira** (linhas 385-427) e o gate `webScanEnabled`.
- Manter **Phase 4** (`createWebApplicationAssets`), mas:
  - Unificar lógica de URL com a helper compartilhada (`buildWebAppUrl(host, port, scheme)` que aplica portSuffix).
  - Preencher `parentAssetId` corretamente (agora que a coluna existe).
  - Adicionar `promotionMetadata` (jsonb) com `{ source: 'attack_surface_job', port, service, jobId }` para auditoria.

**2.3.3 Atualizar formulário de Attack Surface.**
- Remover toggle `webScanEnabled` do formulário (`client/src/components/forms/journey-form.tsx`).
- Texto explicativo: "Esta jornada apenas descobre web applications. Para avaliá-las, crie uma jornada do tipo **Web Application** apontando para os ativos descobertos."

**2.3.4 Back-compat para jornadas existentes.**
- Jornadas salvas com `webScanEnabled=true` no JSON params continuam no banco. Novo código ignora o campo. Sem migração destrutiva.
- Jornadas **em execução** no momento do deploy continuam com o código velho até terminarem. Próximas execuções usam o novo.

## 2.4 Arquivos afetados

- Modificar: `shared/schema.ts` (adicionar `parentAssetId` em `assets`)
- Modificar: `server/storage/assets.ts` (persistir `parentAssetId`)
- Modificar: `server/services/journeyExecutor.ts` (remover Phase 3C, atualizar Phase 4, criar helper `buildWebAppUrl`)
- Modificar: `client/src/components/forms/journey-form.tsx` (remover toggle webScanEnabled)
- Criar (opcional): `server/services/journeys/urls.ts` (helper `buildWebAppUrl`)
- Nenhuma migração destrutiva

## 2.5 Ordem de implementação

1. **[bloqueia 3]** Schema: adicionar `parentAssetId` + migrar + atualizar storage
2. Helper `buildWebAppUrl` + teste unitário
3. Atualizar `createWebApplicationAssets` para usar helper + preencher `parentAssetId`
4. Remover Phase 3C
5. Atualizar formulário Attack Surface

## 2.6 Riscos e cuidados

- **`onDelete: 'cascade'` em parentAssetId:** se um host é deletado, seus web_applications são deletados junto. Verificar com o usuário se isso é o comportamento desejado vs `set null` (mantém órfãos). **Recomendação: cascade** — um web app sem host fonte não faz sentido e cria confusão visual.
- **Assets `web_application` órfãos existentes:** hoje há web apps no banco sem `parentAssetId`. O backfill (ver Problema 3) cuidará disso.
- **Remover Phase 3C quebra expectativa de usuários que usavam `webScanEnabled=true`:** comunicar via changelog e tooltip no formulário. Para continuar a avaliação, criar uma jornada Web Application dedicada.

## 2.7 Critérios de validação

1. Criar jornada Attack Surface contra um host web conhecido → verificar que aparece 1 asset `host` + N assets `web_application` em `assets`, todos com `parent_asset_id` preenchido.
2. Nenhuma threat criada pela jornada Attack Surface que tenha vindo do Nuclei (só threats de portas/CVE).
3. Criar jornada Web Application apontando para esses web apps → threats do Nuclei aparecem.
4. Deletar o host → web apps filhos também são deletados (cascade).
5. Formulário de Attack Surface não mostra mais `webScanEnabled`.

---

# Problema 3 — Agrupamento visual e lógico de Web Apps por Host

## 3.1 Diagnóstico atual

### Schema
`shared/schema.ts:94-101` — `assets` é uma tabela **plana**:
```ts
export const assets = pgTable("assets", {
  id: varchar("id").primaryKey(),
  type: assetTypeEnum("type").notNull(),  // 'host' | 'range' | 'web_application'
  value: text("value").notNull(),
  tags: jsonb("tags"),
  createdAt, createdBy
});
```
**Sem `parentAssetId`**. `assetsRelations` (linha 562-568) só define `createdBy` e `threats` — nenhuma relação parent/children.

### API
`server/routes/assets.ts`:
- `GET /api/assets` (linhas 11-18) → lista plana.
- `GET /api/assets/by-type/:type` (linhas 31-40) → filtra por tipo, ainda plana.

### Storage
`server/storage/assets.ts:14-77`:
- `getAssets()`, `getAssetsByType()` retornam linear.
- `createAsset()` **não aceita `parentAssetId`** (embora `createWebApplicationAssets` tente passar).

### UI
`client/src/pages/assets.tsx`:
- Fetch plano de `/api/assets` → tabela com colunas `type | value | tags | actions`.
- Sem agrupamento. Sem expansão. Ícone por tipo em `getTypeIcon()` (linha 174).

`client/src/components/forms/journey-form.tsx`:
- Seleção de alvos plana via checkbox (linhas 206-262 para attack_surface, 1013-1044 para web_application).
- Nenhum contexto de parent exibido.

## 3.2 Root cause

Gap de design: `assets` foi modelado como entidade plana. Hierarquia `host → web_application` nunca foi implementada. UI herdou a planície.

## 3.3 Solução proposta

### 3.3.1 Schema
Adicionar `parentAssetId` (mesma mudança da Solução 2.3.1 — um único commit cobre ambos).

Adicionar relação em `assetsRelations`:
```ts
export const assetsRelations = relations(assets, ({ one, many }) => ({
  createdBy: one(users, { fields: [assets.createdBy], references: [users.id] }),
  parent: one(assets, { fields: [assets.parentAssetId], references: [assets.id], relationName: "assetParent" }),
  children: many(assets, { relationName: "assetParent" }),
  threats: many(threats),
}));
```

### 3.3.2 API
- `GET /api/assets` retorna árvore (hosts no topo, children agrupados) — aceita query param `?flat=1` para compatibilidade.
- `GET /api/assets/:id/children` retorna só filhos de um asset.
- `GET /api/assets/by-type/:type` mantém comportamento, mas quando `type = web_application`, inclui `parentAsset` expandido no payload.

### 3.3.3 Storage
`server/storage/assets.ts`:
- `createAsset()` aceita `parentAssetId?`.
- Novo método `getAssetsTree()` que retorna `Array<Asset & { children: Asset[] }>` em uma query (join self ou duas queries com agrupamento em memória — para < 10k assets, memória é mais simples).
- Validação: não permitir ciclos (parent não pode ser descendente). Função pura `detectCycle(parentCandidate, children)` testa antes de `UPDATE`.

### 3.3.4 UI — Lista de Ativos
`client/src/pages/assets.tsx` — estrutura nova:
- **Toggle de visualização** no topbar: `[Árvore] [Plano]`. Padrão: árvore. Preferência persistida em `localStorage` (`samureye:assets:view`).
- **Modo árvore:**
  - Nível 0: `host`, `range` (renderizados como linhas expansíveis com chevron).
  - Nível 1: `web_application` sob o host correspondente (indentados, ícone diferente).
  - Contador: `Host X (3 web apps)`.
  - Busca filtra ambos os níveis; se um filho matcha, pai aparece aberto automaticamente.
- **Modo plano:** lista atual (preservada para compatibilidade de ferramentas de auditoria).

### 3.3.5 UI — Formulários de Jornada
`client/src/components/forms/journey-form.tsx`:
- Attack Surface: só seleciona `host`/`range`. Web apps filhos não aparecem na seleção.
- Web Application: só seleciona `web_application`. Em cada item, mostrar linha de contexto: `Parent: <host-value>` (ou "Sem host associado" para órfãos).

### 3.3.6 Backfill
Para `web_application` assets já existentes sem `parent_asset_id`:
- Script `server/scripts/backfillWebAppParent.ts` (com `--dry-run`).
- Algoritmo:
  1. Para cada web_application asset, parse `value` → extrai host.
  2. Query `assets` onde `type='host' AND value = <host>`.
  3. Se encontrou exatamente 1 match → set `parent_asset_id`.
  4. Se 0 ou >1 → deixa null, loga.
- Idempotente.

## 3.4 Arquivos afetados

**Schema/migração:**
- Modificar: `shared/schema.ts` (coluna + relations)

**Backend:**
- Modificar: `server/storage/assets.ts` (createAsset, novo `getAssetsTree`, validação de ciclo)
- Modificar: `server/routes/assets.ts` (endpoint árvore; filhos expandidos)
- Criar: `server/scripts/backfillWebAppParent.ts`
- Criar: `docs/operations/backfill-webapp-parent.md`

**Frontend:**
- Modificar: `client/src/pages/assets.tsx` (modo árvore, toggle, busca recursiva)
- Modificar: `client/src/components/forms/journey-form.tsx` (filtro por tipo, exibição de parent)

## 3.5 Ordem de implementação

1. **Schema:** coluna `parentAssetId` + migrar via `npm run db:push` + storage aceita o campo (commit único — coincide com a parte de schema do Problema 2)
2. Validação de ciclo em `createAsset`/`updateAsset`
3. Endpoint `/api/assets` árvore + `?flat=1` para compat
4. UI modo árvore com toggle
5. Formulários filtrados
6. Script de backfill + docs
7. Rodar backfill em prod (dry-run → live)

## 3.6 Riscos e cuidados

- **Queries de listagem ficam ~20% mais lentas por causa do join/agrupamento.** Para 1k assets, ainda é <100ms. Para 10k+, avaliar paginação server-side (fora do escopo deste plano).
- **Busca recursiva no modo árvore:** se muitos resultados filho, expandir todos os pais pode encher a tela. Limitar a 200 expansões automáticas.
- **Ciclos:** teoricamente um bug poderia criar ciclo via API direta. Validação no storage previne.
- **Web apps órfãos (parent=null)** continuam válidos — backfill resolve maioria, os restantes aparecem com "Sem host associado" na UI. Não bloqueia uso.
- **ON DELETE CASCADE:** deletar host apaga web apps filhos. Threats daqueles web apps ficam órfãs (assetId→null). O Threat Engine já tolera `assetId = null`, mas confirmar no `server/services/threatEngine.ts`.

## 3.7 Critérios de validação

1. **Schema:** `\d assets` em psql mostra coluna `parent_asset_id` + índice.
2. **API:** `GET /api/assets` retorna array com objetos que têm `children`.
3. **UI:** ativos renderizam em árvore; clicar no host expande web apps; busca por substring encontra match nos dois níveis.
4. **Backfill:** rodar contra DB de teste com 10 hosts + 30 web apps → 30 web apps ganham parent_asset_id; zero erros.
5. **Formulário attack_surface:** não mostra web apps na lista.
6. **Formulário web_application:** mostra web apps com "Parent: hostname" para cada.
7. **Delete cascade:** deletar um host remove seus web apps (verificar com `SELECT COUNT(*) WHERE parent_asset_id = <host_id>` antes e depois).

---

# Problema 4 — Edição de Jornadas: cabeçalho fixo + parâmetros editáveis

## 4.1 Diagnóstico atual

### Backend permite trocar `type`
`server/routes/middleware.ts:66-78` — `patchJourneySchema`:
```ts
export const patchJourneySchema = z.object({
  name: z.string().min(1).optional(),
  type: z.enum([...]).optional(),    // ← PROBLEMA: type é editável
  description: z.string().optional(),
  params: z.record(z.any()).optional(),
  targetSelectionMode: z.enum([...]).optional(),
  selectedTags: z.array(z.string()).optional(),
  credentials: z.array(...).optional(),
}).strict();
```

`server/routes/journeys.ts:79-112` — `PATCH /api/journeys/:id`:
```ts
const updates = patchJourneySchema.parse(req.body);   // ← type passa
const journey = await storage.updateJourney(id, journeyUpdates as any);
```

`server/storage/journeys.ts::updateJourney()` aplica qualquer campo diretamente via Drizzle.

### Frontend usa o mesmo form para create e edit
`client/src/components/forms/journey-form.tsx`:
- `journeySchema` (linhas 32-40) é único para ambos os casos.
- Dropdown de `type` (linha 1115: `<SelectItem value="web_application">`) é sempre interativo.
- `initialData` é usado para pré-preencher (sem lock em nenhum campo).

`client/src/pages/journeys.tsx:477-515` — dialog de edição renderiza `JourneyForm` com `initialData` sem distinção de modo.

`client/src/pages/journeys.tsx:230-233` — `handleEditJourney` passa `data` completo (incluindo type) ao PATCH.

## 4.2 Root cause

- Schema de validação do PATCH aceita `type` — negligência original.
- Form React não discrimina `create` vs `edit` — mesmo componente, mesmos campos.
- Sem auditoria em mudança de `type` (teórica).

## 4.3 Solução proposta

### 4.3.1 Backend: rejeitar `type` em PATCH
`server/routes/middleware.ts`:
```ts
export const patchJourneySchema = z.object({
  name: z.string().min(1).optional(),
  description: z.string().optional(),
  params: z.record(z.any()).optional(),
  targetSelectionMode: z.enum([...]).optional(),
  selectedTags: z.array(z.string()).optional(),
  credentials: z.array(...).optional(),
}).strict();  // .strict() rejeita campos não declarados — garante que `type` dá 400
```
Retira `type` inteiramente. Com `.strict()`, qualquer request com `type` retorna `400 Bad Request` com zod error claro.

### 4.3.2 Backend: auditoria defensiva
`server/routes/journeys.ts::PATCH`: se por algum motivo o payload contém `type` (via bypass), adicionar `if ('type' in req.body) log.warn({ journeyId, userId, attempted: req.body.type }, 'blocked attempt to change journey type');` antes do parse.

### 4.3.3 Frontend: `JourneyForm` distingue modo via prop `mode`
Adicionar prop obrigatória: `mode: 'create' | 'edit'`.

No modo `edit`:
- Dropdown de `type` substituído por `<Badge>` read-only exibindo o tipo.
- Header fixo no topo do formulário com:
  ```
  ┌─ Tipo: [Attack Surface]   Criada em: 2026-04-15 10:30   Por: admin@x ─┐
  ```
- Só os campos editáveis (nome, descrição, params específicos do tipo, targets, credenciais) aparecem abaixo.

### 4.3.4 Frontend: stripping defensivo antes do PATCH
`client/src/pages/journeys.tsx::updateJourneyMutation`:
```ts
mutationFn: async ({ id, data }) => {
  const { type, createdAt, createdBy, id: _, ...editablePayload } = data;
  return await apiRequest('PATCH', `/api/journeys/${id}`, editablePayload);
}
```
Protege contra regressões do form que sem querer reenvie campos imutáveis.

## 4.4 Arquivos afetados

- Modificar: `server/routes/middleware.ts` (remover `type` de `patchJourneySchema`)
- Modificar: `server/routes/journeys.ts` (log defensivo)
- Modificar: `client/src/components/forms/journey-form.tsx` (prop `mode`, header fixo, dropdown → badge)
- Modificar: `client/src/pages/journeys.tsx` (passar `mode="edit"`, strip defensivo)

## 4.5 Ordem de implementação

1. Backend: remover `type` do schema + log defensivo (commit)
2. Frontend: prop `mode` + header fixo + badge (commit)
3. Frontend: strip defensivo no mutation (commit)

Independente dos outros 3 problemas — pode sair em paralelo.

## 4.6 Riscos e cuidados

- **Jornadas existentes:** nenhuma mudança de dado — só validação mais restritiva. Jornadas já criadas continuam editáveis normalmente (nome, params, etc.).
- **Erro 400 inesperado:** se algum cliente antigo ainda envia `type`, recebe 400. Cliente web atualizado simultaneamente resolve. API externa (integração) teoricamente quebra — mas: nenhuma API externa documentada edita jornadas, risco baixo.
- **UX:** o badge de tipo deve ser visualmente distinto (cor diferenciada por tipo) para reforçar o significado.

## 4.7 Critérios de validação

1. `curl PATCH /api/journeys/:id -d '{"type":"web_application"}'` → retorna `400` com mensagem de Zod.
2. UI de edição mostra badge não-clicável com o tipo; dropdown antigo não aparece.
3. Editar nome + salvar → sucesso. Campos não-editáveis permanecem idênticos (comparar pre/post via SQL).
4. Header fixo exibe criador e data de criação corretamente.
5. Logs mostram warning defensivo se alguém tentar enviar `type` por bypass.

---

# Sequência global de implementação

```
FASE A — SCHEMA (bloqueia B e C)
  A.1  Adicionar parentAssetId em assets + relations + storage + migração (db:push)
       [resolve: parte de 2, base de 3]

FASE B — BACKEND (depende de A)
  B.1  Helper buildWebAppUrl + teste
  B.2  Atualizar createWebApplicationAssets (preenche parentAssetId, URL normalizada)
  B.3  Remover Phase 3C do Attack Surface executor
  B.4  Pre-flight Nuclei + normalização URL + logging (Problema 1)
  B.5  Validação de ciclo em createAsset/updateAsset
  B.6  Endpoint /api/assets árvore + compat ?flat=1
  B.7  Script de backfill + docs/operations

FASE C — FRONTEND (depende de B)
  C.1  Lista de ativos em árvore + toggle plano/árvore
  C.2  Formulário attack_surface: remover webScanEnabled + restringir seleção a host/range
  C.3  Formulário web_application: mostrar parent em cada item
  C.4  Edição de jornada: prop mode + header fixo + badge (Problema 4 front)
  C.5  Strip defensivo no updateJourneyMutation

FASE D — BACKEND PARALELO (Problema 4)
  D.1  Remover type de patchJourneySchema + log defensivo
       [pode sair antes ou depois das fases B/C, sem dependência]

FASE E — OPERAÇÃO (pós-deploy)
  E.1  Rodar backfill em dry-run contra prod
  E.2  Revisar e rodar live
  E.3  Smoke test: criar jornada attack_surface + web_application + verificar hierarquia
```

## Complexidade resumida

| Fase | Componente | Complexidade | Tempo estimado | Risco |
|---|---|---|---|---|
| A.1 | Schema parentAssetId | Baixa | 0.5 dia | Baixo |
| B.1-2 | Helper + createWebAppAssets | Baixa | 0.5 dia | Baixo |
| B.3 | Remover Phase 3C | Baixa | 0.5 dia | Médio (mudança de comportamento percebido) |
| B.4 | Pre-flight + URL + log | Baixa | 0.5 dia | Baixo |
| B.5 | Validação de ciclo | Baixa | 0.5 dia | Baixo |
| B.6 | API árvore | Média | 1 dia | Baixo |
| B.7 | Backfill | Baixa | 0.5 dia | Baixo |
| C.1 | UI árvore | Média | 1-2 dias | Médio (UX delicada) |
| C.2-3 | Form filters | Baixa | 0.5 dia | Baixo |
| C.4-5 | Edit journey | Baixa | 0.5 dia | Baixo |
| D.1 | PATCH schema strict | Muito Baixa | 0.25 dia | Muito Baixo |

**Total estimado:** ~7-9 dias de um dev full-time.

## Migrações necessárias consolidadas

Uma única migração aditiva:

```sql
ALTER TABLE assets
  ADD COLUMN parent_asset_id VARCHAR REFERENCES assets(id) ON DELETE CASCADE;
CREATE INDEX idx_assets_parent ON assets(parent_asset_id);
```

Aplicada via `npm run db:push` após merge do Fase A.

**Zero mudanças destrutivas.** Rollback: `ALTER TABLE assets DROP COLUMN parent_asset_id;` (web apps perdem link de parent, sem outra perda).

## Bugs colaterais encontrados (não são dos 4 problemas, mas vale corrigir junto)

### Bug 1 — `createWebApplicationAssets` sempre inclui porta
Local: `journeyExecutor.ts:1333`.
```ts
const url = `${protocol}://${host}:${port}`;  // Porta default incluída
```
Correto (padrão Phase 3C linha 402):
```ts
const portSuffix = (scheme === 'http' && cleanPort === '80') || 
                   (scheme === 'https' && cleanPort === '443') ? '' : `:${cleanPort}`;
const url = `${scheme}://${host}${portSuffix}`;
```
**Fix:** na mesma task B.2, quando extrair `buildWebAppUrl` para helper, aplicar a lógica correta.

### Bug 2 — Sem pre-flight check de templates do Nuclei
Local: `journeyExecutor.ts:1416`.
**Fix:** endereçado em B.4 (Problema 1).

## Push-first discipline

Antes de qualquer commit de código:
- Criar branch `feat/webapp-journey-revisions`
- Push imediato do branch vazio
- Cada commit → push imediato → verificar em `origin` antes de prosseguir
- Fim de cada Fase → abrir PR para visibilidade (não merge ainda)

## Pendências de decisão (aguardando aprovação antes de implementar)

1. **`ON DELETE CASCADE` em parentAssetId** — deletar host apaga web apps filhos. Alternativa: `SET NULL`. **Recomendação: CASCADE.**
2. **Preservar jornadas antigas com `webScanEnabled=true`** — após deploy, esse campo é ignorado. Jornadas continuam executando mas sem Nuclei. Aceitável?
3. **Toggle `árvore/plano` default** — árvore. Ok?
4. **Reorder:** se você quiser priorizar correção do Problema 1 (Nuclei não roda) como hotfix isolado, podemos fazer só B.4 primeiro, depois o resto. Quer?

Aguardando decisão nos 4 pontos acima antes de invocar `writing-plans` para gerar tasks detalhados de implementação.
