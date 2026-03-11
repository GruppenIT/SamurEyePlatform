# Plano de Remediação de Segurança - SamurEye

> Baseado no **Relatório de Análise de Segurança de Código** elaborado por Rodrigo Urubatan Ferreira Jardim (08/03/2026)

---

## Resumo das Findings

| ID | Descrição | Severidade | Status |
|----|-----------|------------|--------|
| FND-001 | Man in the Middle (MITM) | **Crítica** | :red_circle: Pendente |
| FND-002 | Vulnerabilidades em dependências | **Alta** | :red_circle: Pendente |
| FND-003 | Configuração de CORS excessivamente permissiva | **Baixa** | :red_circle: Pendente |
| FND-004 | Risco de acesso ao AuthFile no EDR AV Scanner | **Média** | :red_circle: Pendente |
| FND-005 | Falta de testes automatizados | **Média** | :red_circle: Pendente |
| FND-006 | Falta de configuração para ferramentas de suporte a desenvolvedor | **Informativa** | :red_circle: Pendente |
| FND-007 | Arquivos fonte extensos (God Objects) | **Média** | :red_circle: Pendente |
| FND-008 | Falta de ferramenta configurável de logging | **Informativa** | :red_circle: Pendente |
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
- [ ] Executar `npm audit` para inventário completo
- [ ] Executar `npm audit fix` para correções não-breaking
- [ ] Avaliar `npm audit fix --force` para correções breaking (esbuild)
- [ ] Validar que a aplicação compila e funciona após atualização
- [ ] Documentar vulnerabilidades que não puderam ser resolvidas

---

#### 1.2 FND-001: Man in the Middle — MITM (Crítica)

**Justificativa:** Vulnerabilidade mais grave do relatório. Requer implementação cuidadosa em 3 frentes.

**Arquivos afetados:**
- `server/services/subscriptionService.ts` — Validação de certificado TLS
- `server/services/systemUpdateService.ts` — Validação de parâmetros de update

**Ações:**

**1.2a — Validação de Certificado TLS no SubscriptionService:**
- [ ] Verificar configuração atual de TLS/HTTPS no heartbeat
- [ ] Implementar certificate pinning ou validação estrita do certificado da GruppenIT
- [ ] Garantir que `rejectUnauthorized: true` é usado em todas as chamadas HTTP ao console
- [ ] Adicionar validação de hostname no certificado

**1.2b — Validação de Parâmetros no SystemUpdateService:**
- [ ] Mapear todos os parâmetros recebidos via comando de update do console
- [ ] Implementar whitelist de parâmetros aceitos (branch, token, skipBackup)
- [ ] Validar formato de cada parâmetro (regex para branch names, token format, etc.)
- [ ] Sanitizar valores antes de passá-los ao script `update.sh`
- [ ] Impedir injeção de comandos via valores de parâmetros

**1.2c — Assinatura criptográfica de comandos (opcional/recomendado):**
- [ ] Avaliar viabilidade de assinatura HMAC usando API key + salt
- [ ] Implementar verificação de assinatura nos comandos recebidos

---

### Fase 2 — Correções de Severidade Média

#### 2.1 FND-004: Risco de Acesso ao AuthFile no EDR AV Scanner (Média)

**Arquivos afetados:**
- `server/services/scanners/edrAvScanner.ts`

**Ações:**
- [ ] Revisar permissões do AuthFile (atualmente 0o600 — já adequado)
- [ ] Implementar limpeza imediata do AuthFile após uso (verificar finally blocks)
- [ ] Considerar uso de tmpfs/memfd para armazenamento temporário de credenciais
- [ ] Adicionar documentação de requisito de máquina dedicada

**Nota:** O código atual já implementa boas práticas (mode 0o600, cleanup em finally). Esta finding refere-se mais a uma recomendação operacional (máquina dedicada) do que a um bug no código.

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
- `server/index.ts` (linhas 16-35)

**Ações:**
- [ ] Implementar whitelist dinâmica baseada em variável de ambiente (ALLOWED_ORIGINS)
- [ ] Em produção, rejeitar origens não listadas (em vez de permitir todas por padrão)
- [ ] Manter permissividade em desenvolvimento (localhost)
- [ ] Documentar configuração de CORS no guia de instalação

---

### Fase 4 — Melhorias Informativas

#### 4.1 FND-008: Ferramenta configurável de logging (Informativa)

**Arquivos afetados:**
- Todos os arquivos do servidor (~691 ocorrências de console.log/warn/error)

**Ações:**
- [ ] Escolher biblioteca de logging (recomendado: **pino** — rápido, JSON estruturado)
- [ ] Criar módulo central de logger com níveis configuráveis (DEBUG, INFO, WARN, ERROR)
- [ ] Implementar sanitização de dados sensíveis (senhas, tokens, API keys)
- [ ] Substituir gradualmente console.log por chamadas ao logger
- [ ] Configurar nível de log por ambiente (development vs production)

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
Fase 1.1  →  FND-002  Dependências vulneráveis         [Rápido, alto impacto]
Fase 1.2  →  FND-001  Man in the Middle (MITM)          [Crítico, requer cuidado]
Fase 2.1  →  FND-004  AuthFile no EDR AV Scanner        [Verificação + hardening]
Fase 3.1  →  FND-003  CORS permissivo                   [Rápido]
Fase 4.1  →  FND-008  Logging estruturado               [Base para observabilidade]
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
