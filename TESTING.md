# Estratégia de Testes — SamurEye

> Documento vinculado ao [Plano de Remediação de Segurança](./SECURITY_REMEDIATION_PLAN.md) (FND-005)

---

## Filosofia

Os testes deste projeto seguem uma abordagem **security-first**:

1. **Testar o que protege** — Prioridade absoluta para funções que mitigam vulnerabilidades de segurança (FND-001, FND-003, FND-004, FND-008).
2. **Zero dependências externas** — Testes rodam sem banco de dados, sem rede, sem ferramentas externas (nmap, nuclei, smbclient). Módulos com dependências externas são mockados via `vi.mock()`.
3. **Rápido e determinístico** — Suite inteira roda em < 2 segundos. Sem flakiness, sem timeouts, sem estado compartilhado.
4. **Custo-benefício** — Cada teste adicionado deve justificar seu custo de manutenção. Não testamos o que o TypeScript ou o framework já garantem.

---

## Stack

| Ferramenta | Função |
|------------|--------|
| [Vitest](https://vitest.dev/) | Test runner (compatível com Vite, ESM nativo) |
| `vi.mock()` | Mock de módulos com dependências externas (DB, storage) |
| `pino` + `Writable` stream | Captura de output de log para testes de redação |

---

## Estrutura de diretórios

```
server/
├── __tests__/
│   ├── systemUpdateService.test.ts   ← FND-001: validação de params de update
│   ├── subscriptionService.test.ts   ← FND-001: HTTPS enforcement + command validation
│   ├── edrAvScanner.test.ts          ← FND-004: auth file handling (tmpfs, perms, cleanup)
│   ├── encryption.test.ts            ← DEK/KEK roundtrip, tamper detection, KEK isolation
│   ├── logger.test.ts                ← FND-008: redação automática de credenciais
│   └── cors.test.ts                  ← FND-003: CORS origin validation
├── services/
│   ├── systemUpdateService.ts        ← exports: validateUpdateParam, shellSingleQuoteEscape
│   ├── subscriptionService.ts        ← exports: validateConsoleUrl, validateCommand
│   ├── encryption.ts                 ← exports: EncryptionService class
│   └── scanners/
│       └── edrAvScanner.ts           ← exports: createSecureAuthFile, secureCleanup
└── lib/
    └── logger.ts                     ← createLogger (testado via stream capture)
```

---

## Comandos

```bash
# Rodar todos os testes (single run, para CI)
npm test

# Rodar em watch mode (desenvolvimento)
npm run test:watch

# Rodar um arquivo específico
npx vitest run server/__tests__/encryption.test.ts
```

---

## Padrões e convenções

### 1. Mocking de dependências com DB

Módulos que importam `storage` (que requer `DATABASE_URL`) devem ser mockados antes do import:

```typescript
import { vi } from 'vitest';

// ANTES de qualquer import do módulo sob teste
vi.mock('../storage', () => ({ storage: {} }));

import { myFunction } from '../services/myService';
```

### 2. Nomenclatura de testes

```typescript
describe('functionName', () => {
  describe('cenário', () => {
    it('comportamento esperado', () => { ... });
  });
});
```

Exemplos:
- `describe('validateUpdateParam')` → `describe('branch')` → `it('rejects branch names with shell metacharacters')`
- `describe('encrypt/decrypt roundtrip')` → `it('handles unicode content')`

### 3. O que testar vs. o que NÃO testar

#### Testar (obrigatório para código de segurança)

| Categoria | Exemplos |
|-----------|----------|
| **Input validation** | Regex de parâmetros, whitelist enforcement, rejeição de metacharacters |
| **Crypto roundtrip** | Encrypt → decrypt = original; tamper → throw; wrong key → throw |
| **Credential protection** | Auth file permissions (0o600), random filenames, secure cleanup |
| **Log redaction** | Campos sensíveis → `[REDACTED]`, campos normais → preservados |
| **Access control logic** | CORS origin checks, URL protocol enforcement |

#### NÃO testar (custo > benefício neste projeto)

| Categoria | Motivo |
|-----------|--------|
| **Rotas HTTP completas** | Requerem DB + auth + serviços = setup complexo, baixo ROI |
| **Queries SQL/Drizzle** | São type-safe pelo ORM; testar requer DB real |
| **Scanners (nmap, nuclei, etc.)** | Requerem binários instalados + alvos de rede |
| **Componentes React** | Frontend não processa dados sensíveis |
| **Integração end-to-end** | Requer infraestrutura completa (DB, rede, tools) |

### 4. Testes de segurança: checklist para novas features

Ao implementar uma nova feature de segurança, o teste deve cobrir:

- [ ] **Happy path**: input válido produz resultado esperado
- [ ] **Rejeição de input malicioso**: shell injection, SQL injection, XSS conforme aplicável
- [ ] **Edge cases**: string vazia, null, undefined, tipos incorretos
- [ ] **Boundary values**: limites de tamanho, caracteres limítrofes
- [ ] **Isolamento**: chave/credencial A não acessa dados de B

### 5. Exportação de funções para teste

Funções internas que precisam ser testadas devem ser exportadas com `export`:

```typescript
// Antes: function validateParam(...) — privada, não testável
// Depois: export function validateParam(...) — testável

export function validateUpdateParam(key: string, value: unknown): string | null {
  // ...
}
```

A classe principal continua exportando apenas a instância singleton. As funções de validação/sanitização são exportadas separadamente.

---

## Cobertura atual

| Suite | Tests | Finding | O que valida |
|-------|-------|---------|-------------|
| `systemUpdateService.test.ts` | 22 | FND-001 | Shell injection em params de update, whitelist, escape de single quotes |
| `subscriptionService.test.ts` | 33 | FND-001 | HTTPS enforcement, command type whitelist, ID validation |
| `edrAvScanner.test.ts` | 9 | FND-004 | Auth file permissions, crypto filenames, secure cleanup |
| `encryption.test.ts` | 16 | — | DEK/KEK roundtrip, tamper detection, cross-KEK isolation |
| `logger.test.ts` | 18 | FND-008 | Redação de 11+ campos sensíveis, nested, wildcard |
| `cors.test.ts` | 15 | FND-003 | Origin whitelist, localhost dev exception, bypass attempts |
| **Total** | **113** | | |

---

## Expandindo os testes no futuro

### Quando adicionar novos testes

1. **Nova validação de input externo** → Teste unitário obrigatório
2. **Nova integração com credenciais** → Testar que credenciais não vazam em logs/erros
3. **Novo tipo de comando do console** → Adicionar ao teste de `validateCommand`
4. **Novo campo sensível no schema** → Adicionar ao `REDACT_PATHS` do logger E ao teste
5. **Novo scanner** → Testar funções de sanitização/validação (não o scanner em si)

### Quando NÃO adicionar testes

1. Refatoração que não muda comportamento externamente observável
2. Mudanças puramente visuais no frontend
3. Adição de campos no schema sem implicação de segurança
4. CRUD simples via Drizzle (o ORM já garante type safety)

---

## Referências

- [Plano de Remediação](./SECURITY_REMEDIATION_PLAN.md) — Contexto completo das vulnerabilidades
- [Vitest Docs](https://vitest.dev/) — Documentação do framework de testes
- `vitest.config.ts` — Configuração do Vitest (root do projeto)
