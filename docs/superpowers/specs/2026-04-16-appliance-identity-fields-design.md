# Design Spec — Campos de Identidade/Localização do Appliance

**Data:** 2026-04-16
**Branch:** `feat/webapp-journey-revisions`
**Autor:** Claude (brainstorming)

## 1. Problema

O console central (`www.samureye.com.br/cliente`) agora agrupa appliances por localização, mas o appliance não envia os campos `applianceName`, `locationType`, `locationDetail` no heartbeat — o console aceita esses dados e os persiste, mas como eles chegam sempre vazios, todos os appliances caem em "Sem localidade".

Esse spec adiciona UI na aba **Geral** de `/settings` para o cliente preencher os três campos e propaga os valores no próximo heartbeat.

## 2. Objetivo

1. Adicionar 3 campos editáveis na aba Geral de `/settings`: **Nome do Appliance**, **Tipo de Localização**, **Detalhes da Localização**.
2. Persistir os valores via o mesmo mecanismo key-value de settings já existente.
3. Incluir um bloco `identity` no payload do heartbeat quando qualquer um dos três campos tiver sido configurado.
4. Ao salvar, disparar um heartbeat out-of-band para o console refletir a mudança sem esperar o próximo ciclo de 5 minutos.

**Não-objetivos:**
- Trocar o header de autenticação do heartbeat (continua `Authorization: Bearer`; o prompt menciona `X-API-Key`, mas o header atual já funciona contra o console em produção).
- Reestruturar o payload para espelhar os blocos `inventory` / `loginLogs` descritos no prompt; o payload atual (`system / performance / threatStats / usage`) permanece.
- Migração de esquema de banco; settings continuam key-value.

## 3. Premissas verificadas no código

- `server/services/subscriptionService.ts:308` — método `sendHeartbeat()` POSTa `{consoleBaseUrl}/v1/appliance/heartbeat` com header `Authorization: Bearer ${apiKey}`. Intervalo ativo 5 min, standby 30 min.
- `server/services/telemetryService.ts:23` — método `collect(applianceId)` monta o payload atual; não conhece `identity`.
- `shared/schema.ts:1051` — `heartbeatRequestSchema` define `applianceId / version / timestamp / system / performance / threatStats / usage / commandResults`. Não tem `identity`.
- `client/src/pages/settings.tsx` — aba Geral usa `formData` local + `PUT /api/settings { key, value }` por campo; `handleSave()` itera os campos em paralelo.
- `server/routes/admin.ts` — expõe `PUT /api/settings` com auth de admin + password-check. Não expõe endpoint para forçar heartbeat.
- `server/services/settingsService.ts` — já conhece o padrão get/set por chave.

## 4. Contrato

### 4.1. Bloco `identity` no heartbeat

Adicionado a `heartbeatRequestSchema`:

```ts
identity: z.object({
  applianceName: z.string().max(100),
  locationType: z.string().max(50),
  locationDetail: z.string().max(200),
}).optional(),
```

Regras de emissão (no `telemetryService.collect`):

- Se **alguma** das três chaves (`appliance_name`, `location_type`, `location_detail`) existir no storage de settings, o bloco é incluído no payload com os três campos (ausentes viram string vazia).
- Se **nenhuma** existir, o bloco é omitido (preserva comportamento "não enviar = não altera no console").
- Valores explicitamente salvos como `""` são enviados como `""` (console converte em `NULL`).

### 4.2. Validação no cliente

- `applianceName`: texto livre, `maxLength=100`.
- `locationType`: select com 6 opções — `""` (Não definido), `matriz`, `filial`, `datacenter`, `nuvem`, `outro`. O valor enviado é literal, em minúsculas, sem acento.
- `locationDetail`: texto livre, `maxLength=200`.

### 4.3. Endpoint out-of-band

- Rota: `POST /api/appliance/heartbeat-now`.
- Auth: `isAuthenticatedWithPasswordCheck` + `requireAdmin` (mesmo padrão das outras rotas admin).
- Corpo: nenhum.
- Resposta: `202` imediato; chama `subscriptionService.sendHeartbeat()` em fire-and-forget (não bloqueia a resposta HTTP).
- Erros possíveis:
  - `400` se não houver subscription/API key configuradas.
  - O heartbeat em si pode falhar (console 4xx/5xx); isso não quebra a resposta desta rota — o erro aparece nos logs do serviço.

## 5. UI — aba Geral

Bloco novo inserido no fim do `CardContent` da aba Geral (depois de `Timeout de Sessão`), com separator:

```
[Separator]

Identificação e Localização
(info callout) "Estes campos são enviados ao console no próximo heartbeat e
 usados para organizar seus appliances por localização."

[Nome do Appliance]                        (text, maxLength=100)
 helper: "Um apelido amigável para identificar este appliance
          (ex.: sam-sp-dc01). Aparece no dashboard do cliente e
          na página de detalhe."

[Tipo de Localização]                      (select)
 opções:
   ""          "Não definido"
   "matriz"    "Matriz"
   "filial"    "Filial"
   "datacenter" "Datacenter"
   "nuvem"     "Nuvem"
   "outro"     "Outro"
 helper: "Escolha o tipo que melhor descreve onde este appliance
          está instalado. Appliances com o mesmo tipo e detalhe
          de localização serão agrupados juntos no painel do cliente."

[Detalhes da Localização]                  (text, maxLength=200)
 helper: "Complemento que torna a localização única
          (ex.: São Paulo - Av. Paulista 1000, Filial Curitiba,
          AWS us-east-1, DC Equinix SP4). Appliances que
          compartilham o mesmo tipo e o mesmo detalhe são
          exibidos no mesmo grupo no dashboard."
```

Data-testids novos:
- `input-appliance-name`
- `select-location-type`
- `input-location-detail`

## 6. Fluxo de salvar e out-of-band

1. Usuário edita um ou mais campos; estado local em `formData`.
2. Clica no botão global **Salvar Alterações** (já existe no `TopBar`). `handleSave()` itera `formData` e dispara `PUT /api/settings` por chave (comportamento atual, sem mudança).
3. Após todas as promessas resolverem com sucesso, se pelo menos uma das três chaves de identity estiver em `formData`, o cliente faz `POST /api/appliance/heartbeat-now` (fire-and-forget).
4. Toast de sucesso aparece imediatamente com o texto atual ("Configurações salvas com sucesso"). Uma segunda linha opcional ("Sincronizando com o console…") não é necessária — o tempo de resposta do endpoint é imediato.
5. Se o `heartbeat-now` falhar (ex.: console offline), o próximo heartbeat regular envia o bloco `identity` normalmente. O usuário não vê erro.

## 7. Chaves de settings

Os três campos viram chaves no storage `settings` (padrão kv já usado por `systemName`, `systemTimezone` etc.):

- `applianceName` → string
- `locationType` → string (dentre os 6 valores válidos)
- `locationDetail` → string

Tipo `SettingsForm` em `client/src/pages/settings.tsx` é estendido com esses 3 campos (strings). Defaults iniciais são `""`.

## 8. Estrutura de arquivos afetados

### Backend
- `shared/schema.ts` — adicionar `identity` opcional ao `heartbeatRequestSchema` (~7 linhas).
- `server/services/telemetryService.ts` — `collect()` lê settings e inclui `identity` quando aplicável (~15 linhas). Pequeno helper privado `collectIdentity()`.
- `server/routes/admin.ts` (ou um novo `server/routes/appliance.ts`) — endpoint `POST /api/appliance/heartbeat-now` (~15 linhas). Optar por colocar em `admin.ts` para consistência com as outras rotas de settings.

### Frontend
- `client/src/pages/settings.tsx` — 3 novos campos no `formData`, JSX adicional na aba Geral, chamada ao endpoint out-of-band após save bem-sucedido (~60 linhas).

### Sem mudança
- `server/services/subscriptionService.ts` — já tem `sendHeartbeat()` público; apenas é invocado.
- `server/services/settingsService.ts` — já conhece get/set por key.
- Banco de dados, migrations, criptografia.

## 9. Critérios de aceite

1. Aba Geral mostra os três campos novos no fim da seção, com os helper texts especificados e o info-callout.
2. Select de `locationType` oferece exatamente as 5 opções listadas + `""` (Não definido), com os valores literais (minúsculas, sem acento) enviados à API.
3. Salvar Alterações persiste as 3 chaves via `PUT /api/settings` sem erro; após o save, o cliente faz `POST /api/appliance/heartbeat-now` fire-and-forget.
4. Em uma nova chamada de `telemetryService.collect()`, se qualquer das 3 chaves existir em settings, o payload inclui `identity: { applianceName, locationType, locationDetail }` com strings (vazias ou preenchidas). Caso contrário, `identity` é omitido.
5. Limpar um campo preenchido na UI (texto vazio no input ou "Não definido" no select) resulta em `""` na chave salva e em `""` no payload de heartbeat — o console converte em `NULL`.
6. Limites de caracteres no cliente (`maxLength` no input e validação pré-save) evitam payloads > limite do servidor.
7. Nenhuma regressão nos demais campos da aba Geral (`systemName`, `systemDescription`, `systemTimezone`, `sessionTimeout` etc.).

## 10. Riscos e mitigações

- **Risco:** Se `sendHeartbeat()` bloquear em uma chamada lenta ao console, o handler do endpoint out-of-band pode demorar.
  - **Mitigação:** Handler retorna `202` imediato e dispara a promessa com `void` (fire-and-forget). O `sendHeartbeat` já tem `AbortSignal.timeout(15_000)`.
- **Risco:** Usuário preenche `locationType` com valor arbitrário (ex.: via devtools) e o console rejeita.
  - **Mitigação:** O servidor do console valida (conforme prompt). O cliente também valida no select. O appliance não valida (envia o que veio do settings); se o console rejeitar com 400, o log de heartbeat mostra e o estado atual do console não muda — baixo impacto.
- **Risco:** API key não configurada → `heartbeat-now` falha.
  - **Mitigação:** Endpoint retorna `400` com mensagem clara; UI tolera (não bloqueia o save). Próximo fluxo de onboarding da subscription reativa o heartbeat regular.

## 11. Fora de escopo

- Mostrar no appliance (fora de settings) o preview de como o agrupamento aparecerá no console.
- Cache local dos valores configurados separado do storage de settings (não necessário — settings já é source of truth).
- Controle de permissão diferente do admin global (alinha com os demais settings).
- I18n fora do pt-BR atual.
