# Plano de Ação v2 — Plano de Implementação

> **Para workers agênticos:** use `superpowers:subagent-driven-development` (recomendado) ou `superpowers:executing-plans` para executar o plano tarefa-a-tarefa. Steps seguem checkbox `- [ ]`.

**Goal:** Substituir a feature atual `/action-plan` (lista read-only de recomendações) pelo novo conceito "Plano de Ação" — organizador de trabalho de remediação com entidade própria, workflow de status, assignees, comentários rich-text com imagens, histórico e visualização lista/kanban.

**Arquitetura:** Novas tabelas em `shared/schema.ts` (5 tabelas + 2 enums). Novo módulo de rotas `server/routes/action-plans.ts` com sub-rotas (core, threats, comments, history, images). Serviço isolado `server/services/actionPlanService.ts` encapsula geração de código `PA-YYYY-NNNN`, transições de status e integridade referencial. Frontend reescreve `/action-plan` (lista+kanban), adiciona `/action-plan/:id` (abas) e estende `/threats` com bulk action "Associar a Plano de Ação" + coluna "prancheta".

**Tech Stack adicional:** `@dnd-kit/core` + `@dnd-kit/sortable` (kanban), `@tiptap/react` + starter-kit + extension-image + extension-link (rich text), `multer` + `sanitize-html` + `file-type` (upload seguro + sanitização).

---

## Premissas aprovadas (Fase 1)

Tratadas como aprovadas pelo "aprovado" do usuário. **Se alguma estiver errada, avise antes da Fase 3.**

1. **Hard-reset da feature atual:** `GET /api/action-plan` em `dashboard.ts:189-242` e `client/src/pages/action-plan.tsx` atuais são substituídos pelo novo conceito. Substituto para o consumidor atual (`client/src/components/dashboard/top-actions.tsx`) — novo endpoint `GET /api/recommendations/top` com a mesma shape usada hoje.
2. **Admin = `role === 'global_administrator'`**, não `email LIKE 'admin@%'`. Filtro de assignees: `role != 'global_administrator'`.
3. **Libs novas instaladas:** `@dnd-kit/core`, `@dnd-kit/sortable`, `@dnd-kit/utilities`, `@tiptap/react`, `@tiptap/pm`, `@tiptap/starter-kit`, `@tiptap/extension-image`, `@tiptap/extension-link`, `multer`, `sanitize-html`, `file-type`, `@types/multer`, `@types/sanitize-html`.
4. **Diretório de uploads:** `/var/lib/samureye/uploads/action-plans/`. Criado por `install.sh` + chmod para o usuário que roda o processo Node. Em dev, fallback para `./uploads/action-plans/` relativo ao cwd.
5. **URL `/action-plan`** passa a significar o novo conceito. Sem redirect de retrocompatibilidade (feature era nova, uso é interno).
6. **Fase GSD:** `04-04-action-plan-redesign` (esta pasta).

---

## Ordem de entrega (por sua solicitação §9)

```
Bloco A (DB):        schema + enums + push          — dependência zero
Bloco B (lib):       sanitize + upload + code-gen   — depende de A
Bloco C (API):       rotas action-plans v2          — depende de A, B
Bloco D (frontend-foundation):   RichTextEditor + KanbanBoard shell + hooks — depende de C (mock ok)
Bloco E (frontend-pages):        /action-plan (list+kanban) + /action-plan/:id (abas) — depende de D
Bloco F (threats integration):   bulk action + coluna prancheta em /threats — depende de C, E
Bloco G (cleanup):   substituir /api/action-plan legacy + rotas/sidebar + checklist final
```

Cada bloco **termina em commit verde** (type-check + testes que existem). Riscos marcados por bloco.

---

## Mapa de arquivos

### Criar
```
shared/schema.ts                                                    (modificar)
server/services/actionPlanService.ts                                (criar)
server/services/__tests__/actionPlanService.test.ts                 (criar)
server/lib/htmlSanitizer.ts                                         (criar)
server/lib/__tests__/htmlSanitizer.test.ts                          (criar)
server/lib/imageUpload.ts                                           (criar)
server/lib/__tests__/imageUpload.test.ts                            (criar)
server/routes/action-plans.ts                                       (criar)
server/storage/actionPlans.ts                                       (criar)

client/src/pages/action-plan.tsx                                    (reescrever)
client/src/pages/action-plan-detail.tsx                             (criar)
client/src/components/action-plan/KanbanBoard.tsx                   (criar)
client/src/components/action-plan/ActionPlanCard.tsx                (criar)
client/src/components/action-plan/ActionPlanListTable.tsx           (criar)
client/src/components/action-plan/StatusTransitionDialog.tsx        (criar)
client/src/components/action-plan/AssigneeSelector.tsx              (criar)
client/src/components/action-plan/ThreatPickerDialog.tsx            (criar)
client/src/components/action-plan/CommentComposer.tsx               (criar)
client/src/components/action-plan/CommentItem.tsx                   (criar)
client/src/components/action-plan/HistoryTimeline.tsx               (criar)
client/src/components/action-plan/AssociateToPlanDialog.tsx         (criar — usado em /threats)
client/src/components/rich-text/RichTextEditor.tsx                  (criar — TipTap)
client/src/components/rich-text/RichTextRenderer.tsx                (criar)
client/src/hooks/useActionPlans.ts                                  (criar — react-query hooks)

.planning/phases/04-user-facing-surfaces/04-04-action-plan-redesign/PLAN.md   (este arquivo)
```

### Modificar
```
server/routes/index.ts                         (registrar registerActionPlanRoutes)
server/routes/dashboard.ts:189-242             (remover GET /api/action-plan; mover para recommendations)
server/routes/recommendations.ts               (adicionar GET /api/recommendations/top)
client/src/App.tsx                             (adicionar rota /action-plan/:id)
client/src/components/layout/sidebar.tsx       (label permanece "Plano de Ação")
client/src/components/dashboard/top-actions.tsx (trocar endpoint para /api/recommendations/top)
client/src/pages/threats.tsx                   (bulk action + coluna prancheta + regra de checkbox grupo)
install.sh                                     (criar diretório de uploads)
package.json                                   (deps novas)
```

---

## BLOCO A — Fundação de dados

### Tarefa A1: Enums `action_plan_status` e `action_plan_priority`

**Files:**
- Modificar: `shared/schema.ts` (adicionar após os enums existentes em ~linha 60)

- [ ] **Passo 1:** Adicionar enums no Drizzle

```ts
// shared/schema.ts — após threatSeverityEnum
export const actionPlanStatusEnum = pgEnum('action_plan_status', [
  'pending',
  'in_progress',
  'blocked',
  'done',
  'cancelled',
]);

export const actionPlanPriorityEnum = pgEnum('action_plan_priority', [
  'low',
  'medium',
  'high',
  'critical',
]);
```

- [ ] **Passo 2:** `npm run check` — type-check passa.

- [ ] **Passo 3:** Commit

```
git add shared/schema.ts
git commit -m "feat(schema): add action_plan_status and action_plan_priority enums"
```

### Tarefa A2: Tabela `action_plans`

- [ ] **Passo 1:** Adicionar após a tabela `recommendations`.

```ts
export const actionPlans = pgTable('action_plans', {
  id: uuid('id').primaryKey().defaultRandom(),
  code: varchar('code', { length: 20 }).notNull().unique(),
  title: varchar('title', { length: 255 }).notNull(),
  description: text('description'),
  status: actionPlanStatusEnum('status').notNull().default('pending'),
  priority: actionPlanPriorityEnum('priority').notNull().default('medium'),
  createdBy: uuid('created_by').notNull().references(() => users.id, { onDelete: 'restrict' }),
  assigneeId: uuid('assignee_id').references(() => users.id, { onDelete: 'set null' }),
  blockReason: text('block_reason'),
  cancelReason: text('cancel_reason'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => ({
  codeIdx: uniqueIndex('action_plans_code_idx').on(t.code),
  statusIdx: index('action_plans_status_idx').on(t.status),
  assigneeIdx: index('action_plans_assignee_idx').on(t.assigneeId),
}));

export type ActionPlan = typeof actionPlans.$inferSelect;
export type NewActionPlan = typeof actionPlans.$inferInsert;
export const insertActionPlanSchema = createInsertSchema(actionPlans);
```

- [ ] **Passo 2:** `npm run check` — passa.
- [ ] **Passo 3:** Commit: `feat(schema): add action_plans table`

### Tarefa A3: Tabela `action_plan_threats`

- [ ] **Passo 1:**

```ts
export const actionPlanThreats = pgTable('action_plan_threats', {
  id: uuid('id').primaryKey().defaultRandom(),
  actionPlanId: uuid('action_plan_id').notNull().references(() => actionPlans.id, { onDelete: 'cascade' }),
  threatId: uuid('threat_id').notNull().references(() => threats.id, { onDelete: 'cascade' }),
  addedAt: timestamp('added_at', { withTimezone: true }).defaultNow().notNull(),
  addedBy: uuid('added_by').notNull().references(() => users.id, { onDelete: 'restrict' }),
}, (t) => ({
  uniqPlanThreat: uniqueIndex('action_plan_threats_plan_threat_idx').on(t.actionPlanId, t.threatId),
  threatIdx: index('action_plan_threats_threat_idx').on(t.threatId),
}));

export type ActionPlanThreat = typeof actionPlanThreats.$inferSelect;
```

- [ ] **Passo 2:** `npm run check`. Commit: `feat(schema): add action_plan_threats join table`

### Tarefa A4: Tabela `action_plan_comments`

- [ ] **Passo 1:**

```ts
export const actionPlanComments = pgTable('action_plan_comments', {
  id: uuid('id').primaryKey().defaultRandom(),
  actionPlanId: uuid('action_plan_id').notNull().references(() => actionPlans.id, { onDelete: 'cascade' }),
  authorId: uuid('author_id').notNull().references(() => users.id, { onDelete: 'restrict' }),
  content: text('content').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }),
}, (t) => ({
  planIdx: index('action_plan_comments_plan_idx').on(t.actionPlanId, t.createdAt),
}));

export type ActionPlanComment = typeof actionPlanComments.$inferSelect;
```

- [ ] **Passo 2:** `npm run check`. Commit: `feat(schema): add action_plan_comments table`

### Tarefa A5: Tabela `action_plan_comment_threats`

- [ ] **Passo 1:**

```ts
export const actionPlanCommentThreats = pgTable('action_plan_comment_threats', {
  id: uuid('id').primaryKey().defaultRandom(),
  commentId: uuid('comment_id').notNull().references(() => actionPlanComments.id, { onDelete: 'cascade' }),
  threatId: uuid('threat_id').notNull().references(() => threats.id, { onDelete: 'cascade' }),
}, (t) => ({
  uniqCommentThreat: uniqueIndex('ap_comment_threats_unique_idx').on(t.commentId, t.threatId),
  threatIdx: index('ap_comment_threats_threat_idx').on(t.threatId),
}));
```

> **Integridade de comentário-ameaça:** o spec §2.4 exige que remover uma ameaça do plano limpe as linhas em `action_plan_comment_threats`. Vamos implementar na **camada de serviço** (dentro da mesma transação de `DELETE FROM action_plan_threats`). Trigger de BD não é necessário porque `DELETE threat → CASCADE` já remove; o caso crítico é "remover threat do plano sem deletar threat global" — tratado no serviço.

- [ ] **Passo 2:** `npm run check`. Commit: `feat(schema): add action_plan_comment_threats join table`

### Tarefa A6: Tabela `action_plan_history`

- [ ] **Passo 1:**

```ts
export const actionPlanHistory = pgTable('action_plan_history', {
  id: uuid('id').primaryKey().defaultRandom(),
  actionPlanId: uuid('action_plan_id').notNull().references(() => actionPlans.id, { onDelete: 'cascade' }),
  actorId: uuid('actor_id').notNull().references(() => users.id, { onDelete: 'restrict' }),
  action: varchar('action', { length: 64 }).notNull(),
  detailsJson: jsonb('details_json'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => ({
  planIdx: index('action_plan_history_plan_idx').on(t.actionPlanId, t.createdAt),
}));

export type ActionPlanHistory = typeof actionPlanHistory.$inferSelect;
```

Ações válidas (enum TS, não pgEnum — decisão consistente com o resto do projeto):
```ts
export const ACTION_PLAN_HISTORY_ACTIONS = [
  'created',
  'status_changed',
  'assignee_changed',
  'title_changed',
  'description_changed',
  'priority_changed',
  'threat_added',
  'threat_removed',
  'comment_added',
  'comment_edited',
] as const;
export type ActionPlanHistoryAction = typeof ACTION_PLAN_HISTORY_ACTIONS[number];
```

- [ ] **Passo 2:** `npm run check`. Commit: `feat(schema): add action_plan_history table`

### Tarefa A7: Aplicar no banco (`db:push`)

- [ ] **Passo 1:** Ambiente local. Rodar `npm run db:push` e **revisar o SQL proposto** antes de confirmar. Não aplicar em produção nesta etapa.
- [ ] **Passo 2:** Verificar no psql local:

```sql
\d action_plans
\d action_plan_threats
\d action_plan_comments
\d action_plan_comment_threats
\d action_plan_history
\dT action_plan_status
\dT action_plan_priority
```

- [ ] **Passo 3:** Sem commit (não há arquivo alterado). Bloco A concluído.

### Riscos Bloco A
- `drizzle-kit push` pode sugerir drops se nome colidir com algo existente. Revisar cuidadosamente o SQL impresso.
- Se o projeto usa Postgres sem extensão `pgcrypto`, `defaultRandom()` falha. Validar no `server/db.ts` — o projeto já usa UUID nos threats, então está OK.

---

## BLOCO B — Fundação backend (bibliotecas e serviços)

### Tarefa B1: Instalar dependências

- [ ] **Passo 1:**

```bash
npm install @dnd-kit/core @dnd-kit/sortable @dnd-kit/utilities \
  @tiptap/react @tiptap/pm @tiptap/starter-kit @tiptap/extension-image @tiptap/extension-link \
  multer sanitize-html file-type
npm install -D @types/multer @types/sanitize-html
```

- [ ] **Passo 2:** `npm run check`. Commit: `chore(deps): add tiptap, dnd-kit, multer, sanitize-html`

### Tarefa B2: Sanitização de HTML (`server/lib/htmlSanitizer.ts`)

- [ ] **Passo 1:** Criar arquivo com allowlist conservadora.

```ts
import sanitizeHtml from 'sanitize-html';

const ALLOWED_TAGS = ['p','br','strong','em','u','s','ol','ul','li','pre','code','a','img','h1','h2','h3','blockquote'];
const ALLOWED_ATTRS: sanitizeHtml.IOptions['allowedAttributes'] = {
  a: ['href','title','target','rel'],
  img: ['src','alt','width','height'],
};

// src de img deve apontar para nosso endpoint /api/v1/action-plans/images/<uuid>.<ext>
const IMG_SRC_ALLOWLIST = /^\/api\/v1\/action-plans\/images\/[a-f0-9-]+\.(png|jpe?g|gif|webp)$/i;

export function sanitizeActionPlanHtml(input: string): string {
  return sanitizeHtml(input, {
    allowedTags: ALLOWED_TAGS,
    allowedAttributes: ALLOWED_ATTRS,
    allowedSchemes: ['http','https','mailto'],
    transformTags: {
      a: sanitizeHtml.simpleTransform('a', { rel: 'noopener noreferrer', target: '_blank' }),
    },
    exclusiveFilter: (frame) => {
      if (frame.tag === 'img' && !IMG_SRC_ALLOWLIST.test(frame.attribs.src ?? '')) return true;
      return false;
    },
  });
}
```

- [ ] **Passo 2:** Teste `server/lib/__tests__/htmlSanitizer.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { sanitizeActionPlanHtml } from '../htmlSanitizer';

describe('sanitizeActionPlanHtml', () => {
  it('keeps allowed tags', () => {
    expect(sanitizeActionPlanHtml('<p><strong>hi</strong></p>')).toBe('<p><strong>hi</strong></p>');
  });
  it('strips scripts', () => {
    expect(sanitizeActionPlanHtml('<p>x</p><script>alert(1)</script>')).toBe('<p>x</p>');
  });
  it('strips event handlers', () => {
    expect(sanitizeActionPlanHtml('<a href="#" onclick="x()">y</a>'))
      .toBe('<a href="#" target="_blank" rel="noopener noreferrer">y</a>');
  });
  it('rejects external images', () => {
    expect(sanitizeActionPlanHtml('<img src="https://evil/x.png">')).toBe('');
  });
  it('keeps internal images', () => {
    const url = '/api/v1/action-plans/images/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.png';
    expect(sanitizeActionPlanHtml(`<img src="${url}" alt="x">`)).toContain(url);
  });
});
```

- [ ] **Passo 3:** `npx vitest run server/lib/__tests__/htmlSanitizer.test.ts` — deve passar.
- [ ] **Passo 4:** Commit: `feat(lib): html sanitizer for action plan rich text`

### Tarefa B3: Upload de imagens (`server/lib/imageUpload.ts`)

- [ ] **Passo 1:** Criar handler com multer memory storage + validação magic bytes.

```ts
import multer from 'multer';
import { randomUUID } from 'crypto';
import { fileTypeFromBuffer } from 'file-type';
import { mkdir, writeFile } from 'fs/promises';
import path from 'path';

const MAX_BYTES = 5 * 1024 * 1024;
const ALLOWED_MIME = new Set(['image/png','image/jpeg','image/gif','image/webp']);
const MIME_TO_EXT: Record<string, string> = {
  'image/png':'png','image/jpeg':'jpg','image/gif':'gif','image/webp':'webp',
};

export const UPLOAD_DIR = process.env.SAMUREYE_UPLOAD_DIR
  ?? (process.env.NODE_ENV === 'production'
      ? '/var/lib/samureye/uploads/action-plans'
      : path.resolve(process.cwd(), 'uploads/action-plans'));

export const uploadMemory = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_BYTES, files: 1 },
});

export async function persistImage(buffer: Buffer): Promise<{ filename: string; url: string }> {
  const ft = await fileTypeFromBuffer(buffer);
  if (!ft || !ALLOWED_MIME.has(ft.mime)) {
    throw Object.assign(new Error('Formato de imagem inválido.'), { status: 415 });
  }
  const ext = MIME_TO_EXT[ft.mime];
  const filename = `${randomUUID()}.${ext}`;
  await mkdir(UPLOAD_DIR, { recursive: true });
  await writeFile(path.join(UPLOAD_DIR, filename), buffer);
  return { filename, url: `/api/v1/action-plans/images/${filename}` };
}

// Para GET: serializa path seguro bloqueando traversal.
export function resolveImagePath(filename: string): string {
  if (!/^[a-f0-9-]+\.(png|jpe?g|gif|webp)$/i.test(filename)) {
    throw Object.assign(new Error('Nome inválido'), { status: 400 });
  }
  const resolved = path.resolve(UPLOAD_DIR, filename);
  if (!resolved.startsWith(path.resolve(UPLOAD_DIR))) {
    throw Object.assign(new Error('Path traversal'), { status: 400 });
  }
  return resolved;
}
```

- [ ] **Passo 2:** Teste `server/lib/__tests__/imageUpload.test.ts` (unit — magic bytes e path resolution):

```ts
import { describe, it, expect } from 'vitest';
import { persistImage, resolveImagePath, UPLOAD_DIR } from '../imageUpload';
import { readFile } from 'fs/promises';
import path from 'path';

const pngMagic = Buffer.from([0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A]);
const pngMinimal = Buffer.concat([pngMagic, Buffer.alloc(32, 0)]);

describe('persistImage', () => {
  it('rejects non-image buffer', async () => {
    await expect(persistImage(Buffer.from('hello world'))).rejects.toThrow(/inválido/);
  });
  it('accepts valid PNG buffer', async () => {
    const { filename, url } = await persistImage(pngMinimal);
    expect(filename).toMatch(/\.png$/);
    expect(url).toBe(`/api/v1/action-plans/images/${filename}`);
    const onDisk = await readFile(path.join(UPLOAD_DIR, filename));
    expect(onDisk.length).toBeGreaterThan(0);
  });
});

describe('resolveImagePath', () => {
  it('blocks path traversal', () => {
    expect(() => resolveImagePath('../../etc/passwd')).toThrow();
  });
  it('resolves valid filename', () => {
    const p = resolveImagePath('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.png');
    expect(p).toContain(UPLOAD_DIR);
  });
});
```

- [ ] **Passo 3:** Rodar vitest. Deve passar.
- [ ] **Passo 4:** Commit: `feat(lib): secure image upload with magic-bytes validation`

### Tarefa B4: Serviço `actionPlanService.ts` — estrutura base + geração de código

- [ ] **Passo 1:** Esqueleto do serviço com geração atômica de `PA-YYYY-NNNN` via transaction.

```ts
// server/services/actionPlanService.ts
import { db } from '../db';
import { actionPlans } from '@shared/schema';
import { sql, and, like, desc } from 'drizzle-orm';

export async function generateNextActionPlanCode(tx = db): Promise<string> {
  const year = new Date().getFullYear();
  const prefix = `PA-${year}-`;
  // Lock a nível de advisory lock com hash do ano para evitar race.
  const lockKey = BigInt(`0xAC71${year}`); // pseudo-key determinístico
  await tx.execute(sql`SELECT pg_advisory_xact_lock(${lockKey})`);
  const rows = await tx
    .select({ code: actionPlans.code })
    .from(actionPlans)
    .where(like(actionPlans.code, `${prefix}%`))
    .orderBy(desc(actionPlans.code))
    .limit(1);
  const lastN = rows[0]?.code ? parseInt(rows[0].code.slice(prefix.length), 10) : 0;
  const next = String(lastN + 1).padStart(4, '0');
  return `${prefix}${next}`;
}
```

**Nota:** usa `pg_advisory_xact_lock` em vez de `SELECT ... FOR UPDATE` porque não há "linha sentinela". Lock é automaticamente liberado no final da transação.

- [ ] **Passo 2:** Teste com concorrência simulada em `server/services/__tests__/actionPlanService.test.ts`:

```ts
import { describe, it, expect, beforeAll } from 'vitest';
import { db } from '../../db';
import { actionPlans, users } from '@shared/schema';
import { generateNextActionPlanCode } from '../actionPlanService';
import { sql } from 'drizzle-orm';

describe('generateNextActionPlanCode', () => {
  let userId: string;
  beforeAll(async () => {
    await db.execute(sql`TRUNCATE action_plans CASCADE`);
    const [u] = await db.select().from(users).limit(1);
    userId = u.id;
  });

  it('generates PA-YYYY-0001 on empty table', async () => {
    const code = await db.transaction(async (tx) => generateNextActionPlanCode(tx));
    expect(code).toMatch(/^PA-\d{4}-0001$/);
  });

  it('generates unique codes under concurrent transactions', async () => {
    await db.execute(sql`TRUNCATE action_plans CASCADE`);
    const results = await Promise.all(
      Array.from({ length: 5 }).map(async () =>
        db.transaction(async (tx) => {
          const code = await generateNextActionPlanCode(tx);
          await tx.insert(actionPlans).values({
            code, title: 't', createdBy: userId,
          });
          return code;
        })
      )
    );
    expect(new Set(results).size).toBe(5);
  });
});
```

- [ ] **Passo 3:** Rodar. Deve passar (precisa DB local acessível). Se CI não tem DB, pular este teste via `describe.skipIf(!process.env.DATABASE_URL)`.
- [ ] **Passo 4:** Commit: `feat(service): action plan code generation with advisory lock`

### Tarefa B5: Serviço — transições de status

- [ ] **Passo 1:** Adicionar ao mesmo arquivo:

```ts
export type ActionPlanStatus = 'pending'|'in_progress'|'blocked'|'done'|'cancelled';

export interface StatusTransition {
  from: ActionPlanStatus;
  to: ActionPlanStatus;
  requiresReason: 'block'|'cancel'|'unblock'|null;
}

export const STATUS_TRANSITIONS: StatusTransition[] = [
  { from:'pending',     to:'in_progress', requiresReason:null },
  { from:'pending',     to:'blocked',     requiresReason:'block' },
  { from:'pending',     to:'cancelled',   requiresReason:'cancel' },
  { from:'in_progress', to:'blocked',     requiresReason:'block' },
  { from:'in_progress', to:'done',        requiresReason:null },
  { from:'in_progress', to:'cancelled',   requiresReason:'cancel' },
  { from:'blocked',     to:'pending',     requiresReason:'unblock' },
  { from:'blocked',     to:'in_progress', requiresReason:'unblock' },
  { from:'blocked',     to:'cancelled',   requiresReason:'cancel' },
];

export function getAllowedTransitions(from: ActionPlanStatus) {
  return STATUS_TRANSITIONS.filter(t => t.from === from);
}

export function validateStatusTransition(
  from: ActionPlanStatus,
  to: ActionPlanStatus,
  reason?: string
): { ok: true } | { ok: false; message: string; code: 'INVALID_TRANSITION'|'REASON_REQUIRED' } {
  const t = STATUS_TRANSITIONS.find(x => x.from === from && x.to === to);
  if (!t) return { ok:false, code:'INVALID_TRANSITION', message:`Transição ${from}→${to} não permitida.` };
  if (t.requiresReason && (!reason || reason.trim().length < 3)) {
    return { ok:false, code:'REASON_REQUIRED', message:`Justificativa obrigatória para esta transição.` };
  }
  return { ok:true };
}
```

- [ ] **Passo 2:** Testes:

```ts
import { validateStatusTransition } from '../actionPlanService';

describe('validateStatusTransition', () => {
  it('blocks done → anything', () => {
    const r = validateStatusTransition('done','pending');
    expect(r).toMatchObject({ ok:false, code:'INVALID_TRANSITION' });
  });
  it('blocks cancelled → anything', () => {
    expect(validateStatusTransition('cancelled','in_progress')).toMatchObject({ ok:false });
  });
  it('requires reason for pending → blocked', () => {
    expect(validateStatusTransition('pending','blocked')).toMatchObject({ ok:false, code:'REASON_REQUIRED' });
    expect(validateStatusTransition('pending','blocked','Aguardando firewall')).toEqual({ ok:true });
  });
  it('allows pending → in_progress without reason', () => {
    expect(validateStatusTransition('pending','in_progress')).toEqual({ ok:true });
  });
  it('requires unblock reason for blocked → pending', () => {
    expect(validateStatusTransition('blocked','pending')).toMatchObject({ ok:false, code:'REASON_REQUIRED' });
    expect(validateStatusTransition('blocked','pending','desbloqueado manualmente')).toEqual({ ok:true });
  });
});
```

- [ ] **Passo 3:** Rodar. Commit: `feat(service): status transition validation`

### Tarefa B6: Serviço — helpers de histórico e mutação

- [ ] **Passo 1:** Adicionar `recordHistory`, `applyStatusChange`, `removeThreatFromPlan` (este último com cleanup de `action_plan_comment_threats` dentro da transação).

```ts
import { actionPlanHistory, actionPlanThreats, actionPlanCommentThreats, actionPlanComments } from '@shared/schema';
import { eq, inArray } from 'drizzle-orm';

export async function recordHistory(tx: typeof db, params: {
  actionPlanId: string;
  actorId: string;
  action: ActionPlanHistoryAction;
  detailsJson?: unknown;
}) {
  await tx.insert(actionPlanHistory).values({
    actionPlanId: params.actionPlanId,
    actorId: params.actorId,
    action: params.action,
    detailsJson: params.detailsJson ?? null,
  });
}

export async function applyStatusChange(params: {
  planId: string;
  actorId: string;
  from: ActionPlanStatus;
  to: ActionPlanStatus;
  reason?: string;
}) {
  return db.transaction(async (tx) => {
    const v = validateStatusTransition(params.from, params.to, params.reason);
    if (!v.ok) throw Object.assign(new Error(v.message), { status:422, code: v.code });

    const patch: Partial<typeof actionPlans.$inferInsert> = {
      status: params.to,
      updatedAt: new Date(),
    };
    if (params.to === 'blocked') patch.blockReason = params.reason ?? null;
    else patch.blockReason = null;
    if (params.to === 'cancelled') patch.cancelReason = params.reason ?? null;

    await tx.update(actionPlans).set(patch).where(eq(actionPlans.id, params.planId));
    await recordHistory(tx, {
      actionPlanId: params.planId,
      actorId: params.actorId,
      action: 'status_changed',
      detailsJson: { from: params.from, to: params.to, reason: params.reason ?? null },
    });
  });
}

export async function removeThreatFromPlan(params: { planId: string; threatId: string; actorId: string; }) {
  return db.transaction(async (tx) => {
    // 1. commentIds deste plano
    const commentIds = (await tx.select({ id: actionPlanComments.id })
      .from(actionPlanComments).where(eq(actionPlanComments.actionPlanId, params.planId)))
      .map(r => r.id);

    // 2. limpa comment_threats dos comentários deste plano que apontam para a threat
    if (commentIds.length > 0) {
      await tx.delete(actionPlanCommentThreats)
        .where(and(
          inArray(actionPlanCommentThreats.commentId, commentIds),
          eq(actionPlanCommentThreats.threatId, params.threatId),
        ));
    }

    // 3. remove do join
    await tx.delete(actionPlanThreats).where(and(
      eq(actionPlanThreats.actionPlanId, params.planId),
      eq(actionPlanThreats.threatId, params.threatId),
    ));

    await recordHistory(tx, {
      actionPlanId: params.planId,
      actorId: params.actorId,
      action: 'threat_removed',
      detailsJson: { threatId: params.threatId },
    });
  });
}
```

- [ ] **Passo 2:** Teste de integração (precisa DB):

```ts
it('removeThreatFromPlan cleans comment_threats', async () => {
  // setup: criar plano, threat, associar, criar comentário ligado à threat
  // then call removeThreatFromPlan, assert threat+comment_threat rows gone, comment stays
});
```

- [ ] **Passo 3:** Commit: `feat(service): status change and threat removal with cascading cleanup`

### Riscos Bloco B
- `file-type` é ESM-only. Garantir `"type":"module"` (já é) e importar como ESM.
- `pg_advisory_xact_lock` exige que todos os writers de código passem pela função. Documentar isso no topo do serviço.
- Teste de concorrência requer DB real. Se CI não tiver, usar `describe.skipIf`.

---

## BLOCO C — API de planos de ação

### Tarefa C1: Storage `server/storage/actionPlans.ts` — leitura com joins nomeados

- [ ] **Passo 1:** Módulo que encapsula queries com resolução de nomes de usuário e ameaça.

```ts
// server/storage/actionPlans.ts
import { db } from '../db';
import { actionPlans, users, threats, actionPlanThreats, actionPlanComments, actionPlanCommentThreats, actionPlanHistory } from '@shared/schema';
import { and, eq, or, ilike, sql, inArray, desc } from 'drizzle-orm';

export async function listActionPlans(filters: {
  status?: string[]; priority?: string[]; assigneeId?: string; search?: string;
  limit: number; offset: number;
}) {
  const creator = alias(users, 'creator');
  const assignee = alias(users, 'assignee');
  const whereParts = [] as any[];
  if (filters.status?.length) whereParts.push(inArray(actionPlans.status, filters.status as any));
  if (filters.priority?.length) whereParts.push(inArray(actionPlans.priority, filters.priority as any));
  if (filters.assigneeId) whereParts.push(eq(actionPlans.assigneeId, filters.assigneeId));
  if (filters.search) whereParts.push(or(
    ilike(actionPlans.title, `%${filters.search}%`),
    ilike(actionPlans.code, `%${filters.search}%`),
  ));

  const rows = await db
    .select({
      id: actionPlans.id, code: actionPlans.code, title: actionPlans.title,
      status: actionPlans.status, priority: actionPlans.priority,
      createdAt: actionPlans.createdAt, updatedAt: actionPlans.updatedAt,
      blockReason: actionPlans.blockReason, cancelReason: actionPlans.cancelReason,
      createdBy: { id: creator.id, name: sql<string>`coalesce(${creator.firstName} || ' ' || ${creator.lastName}, ${creator.email})` },
      assignee: sql<any>`case when ${assignee.id} is null then null else json_build_object('id',${assignee.id},'name',coalesce(${assignee.firstName} || ' ' || ${assignee.lastName}, ${assignee.email})) end`,
      threatCount: sql<number>`(select count(*)::int from action_plan_threats apt where apt.action_plan_id = ${actionPlans.id})`,
    })
    .from(actionPlans)
    .leftJoin(creator, eq(creator.id, actionPlans.createdBy))
    .leftJoin(assignee, eq(assignee.id, actionPlans.assigneeId))
    .where(whereParts.length ? and(...whereParts) : undefined)
    .orderBy(desc(actionPlans.updatedAt))
    .limit(filters.limit)
    .offset(filters.offset);

  const [{ total }] = await db.select({ total: sql<number>`count(*)::int` })
    .from(actionPlans)
    .where(whereParts.length ? and(...whereParts) : undefined);

  return { rows, total };
}
```

- [ ] **Passo 2:** Adicionar `getActionPlanById`, `getPlanThreats`, `getPlanComments`, `getPlanHistory` seguindo mesmo padrão (queries com joins nomeados que retornam nome resolvido).
- [ ] **Passo 3:** `npm run check`. Commit: `feat(storage): action plans read layer with resolved names`

### Tarefa C2: Rotas — `registerActionPlanRoutes`

- [ ] **Passo 1:** Criar `server/routes/action-plans.ts` com estrutura:

```ts
import type { Express, Request, Response } from 'express';
import { isAuthenticatedWithPasswordCheck } from '../localAuth';
import { requireOperator } from './middleware';
import { z } from 'zod';
import { db } from '../db';
import { actionPlans, actionPlanThreats, actionPlanComments, actionPlanCommentThreats, users } from '@shared/schema';
import { eq, ne, inArray, and, sql } from 'drizzle-orm';
import { generateNextActionPlanCode, applyStatusChange, removeThreatFromPlan, recordHistory, validateStatusTransition } from '../services/actionPlanService';
import { sanitizeActionPlanHtml } from '../lib/htmlSanitizer';
import { uploadMemory, persistImage, resolveImagePath } from '../lib/imageUpload';
import { listActionPlans /* ... */ } from '../storage/actionPlans';
import { createLogger } from '../lib/logger';

const log = createLogger('routes:action-plans');

// Helper: checa se user é creator ou assignee
async function assertEditable(planId: string, userId: string) {
  const [row] = await db.select({ createdBy: actionPlans.createdBy, assigneeId: actionPlans.assigneeId })
    .from(actionPlans).where(eq(actionPlans.id, planId));
  if (!row) throw Object.assign(new Error('Plano não encontrado'), { status:404 });
  if (row.createdBy !== userId && row.assigneeId !== userId) {
    throw Object.assign(new Error('Apenas o criador ou responsável pode editar este plano.'), { status:403 });
  }
}

export function registerActionPlanRoutes(app: Express) {
  // ... endpoints abaixo
}
```

- [ ] **Passo 2:** Registrar em `server/routes/index.ts`:

```ts
import { registerActionPlanRoutes } from './action-plans';
// ...
registerActionPlanRoutes(app);
```

- [ ] **Passo 3:** Commit: `feat(routes): scaffold action plan routes module`

### Tarefa C3: Endpoint — `GET /api/v1/action-plans`

- [ ] **Passo 1:**

```ts
const listQuerySchema = z.object({
  status: z.string().optional().transform(s => s?.split(',').filter(Boolean)),
  priority: z.string().optional().transform(s => s?.split(',').filter(Boolean)),
  assigneeId: z.string().uuid().optional(),
  search: z.string().max(200).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(25),
  offset: z.coerce.number().int().min(0).default(0),
});

app.get('/api/v1/action-plans', isAuthenticatedWithPasswordCheck, async (req, res) => {
  try {
    const q = listQuerySchema.parse(req.query);
    const { rows, total } = await listActionPlans(q);
    res.json({ rows, total, limit: q.limit, offset: q.offset });
  } catch (err: any) {
    if (err instanceof z.ZodError) return res.status(400).json({ error: err.issues });
    log.error({ err }, 'list action plans failed');
    res.status(500).json({ error: 'Erro ao listar planos.' });
  }
});
```

- [ ] **Passo 2:** Smoke-test via curl após rodar dev server:

```bash
curl -s -b cookie.txt http://localhost:3000/api/v1/action-plans | jq .
```

- [ ] **Passo 3:** Commit: `feat(routes): GET /api/v1/action-plans list with filters`

### Tarefa C4: Endpoint — `POST /api/v1/action-plans`

- [ ] **Passo 1:**

```ts
const createSchema = z.object({
  title: z.string().min(1).max(255),
  description: z.string().max(100_000).optional(),
  priority: z.enum(['low','medium','high','critical']).default('medium'),
  assigneeId: z.string().uuid().nullable().optional(),
  threatIds: z.array(z.string().uuid()).optional(),
});

app.post('/api/v1/action-plans', isAuthenticatedWithPasswordCheck, requireOperator, async (req, res) => {
  try {
    const body = createSchema.parse(req.body);
    const userId = (req.user as any).id as string;
    const result = await db.transaction(async (tx) => {
      const code = await generateNextActionPlanCode(tx);
      const [plan] = await tx.insert(actionPlans).values({
        code,
        title: body.title,
        description: body.description ? sanitizeActionPlanHtml(body.description) : null,
        priority: body.priority,
        assigneeId: body.assigneeId ?? null,
        createdBy: userId,
      }).returning();
      if (body.threatIds?.length) {
        await tx.insert(actionPlanThreats).values(
          body.threatIds.map(tid => ({ actionPlanId: plan.id, threatId: tid, addedBy: userId })),
        );
      }
      await recordHistory(tx, { actionPlanId: plan.id, actorId: userId, action: 'created', detailsJson: { code } });
      return plan;
    });
    res.status(201).json(result);
  } catch (err: any) {
    if (err instanceof z.ZodError) return res.status(400).json({ error: err.issues });
    log.error({ err }, 'create plan failed');
    res.status(err.status ?? 500).json({ error: err.message ?? 'Erro ao criar plano.' });
  }
});
```

- [ ] **Passo 2:** Teste manual via curl (POST com body JSON). Validar que o código gerado é `PA-YYYY-0001`.
- [ ] **Passo 3:** Commit: `feat(routes): POST /api/v1/action-plans with code generation`

### Tarefa C5: Endpoint — `GET /api/v1/action-plans/:id` (com `?include=threats,comments,history`)

- [ ] **Passo 1:** Resolver o plano + opcionalmente incluir ameaças/comentários/histórico com nomes resolvidos.

```ts
const includeSchema = z.string().transform(s => new Set(s.split(',')));

app.get('/api/v1/action-plans/:id', isAuthenticatedWithPasswordCheck, async (req, res) => {
  try {
    const planId = z.string().uuid().parse(req.params.id);
    const include = req.query.include ? includeSchema.parse(req.query.include) : new Set<string>();
    const plan = await getActionPlanById(planId);
    if (!plan) return res.status(404).json({ error: 'Plano não encontrado.' });
    const out: any = { ...plan };
    if (include.has('threats')) out.threats = await getPlanThreats(planId);
    if (include.has('comments')) out.comments = await getPlanComments(planId);
    if (include.has('history')) out.history = await getPlanHistory(planId);
    res.json(out);
  } catch (err: any) {
    if (err instanceof z.ZodError) return res.status(400).json({ error: err.issues });
    res.status(err.status ?? 500).json({ error: err.message });
  }
});
```

- [ ] **Passo 2:** Commit: `feat(routes): GET /api/v1/action-plans/:id with includes`

### Tarefa C6: Endpoint — `PATCH /api/v1/action-plans/:id` (atributos)

- [ ] **Passo 1:**

```ts
const patchSchema = z.object({
  title: z.string().min(1).max(255).optional(),
  description: z.string().max(100_000).nullable().optional(),
  priority: z.enum(['low','medium','high','critical']).optional(),
  assigneeId: z.string().uuid().nullable().optional(),
}).refine(v => Object.keys(v).length > 0, 'Ao menos um campo.');

app.patch('/api/v1/action-plans/:id', isAuthenticatedWithPasswordCheck, requireOperator, async (req, res) => {
  try {
    const planId = z.string().uuid().parse(req.params.id);
    const body = patchSchema.parse(req.body);
    const userId = (req.user as any).id as string;
    await assertEditable(planId, userId);

    await db.transaction(async (tx) => {
      const [before] = await tx.select().from(actionPlans).where(eq(actionPlans.id, planId));
      const patch: any = { updatedAt: new Date() };
      if (body.title !== undefined) patch.title = body.title;
      if (body.description !== undefined) patch.description = body.description === null ? null : sanitizeActionPlanHtml(body.description);
      if (body.priority !== undefined) patch.priority = body.priority;
      if (body.assigneeId !== undefined) patch.assigneeId = body.assigneeId;

      await tx.update(actionPlans).set(patch).where(eq(actionPlans.id, planId));

      // histórico por campo alterado
      if (body.title !== undefined && body.title !== before.title)
        await recordHistory(tx, { actionPlanId: planId, actorId: userId, action: 'title_changed', detailsJson: { from: before.title, to: body.title } });
      if (body.description !== undefined)
        await recordHistory(tx, { actionPlanId: planId, actorId: userId, action: 'description_changed' });
      if (body.priority !== undefined && body.priority !== before.priority)
        await recordHistory(tx, { actionPlanId: planId, actorId: userId, action: 'priority_changed', detailsJson: { from: before.priority, to: body.priority } });
      if (body.assigneeId !== undefined && body.assigneeId !== before.assigneeId)
        await recordHistory(tx, { actionPlanId: planId, actorId: userId, action: 'assignee_changed', detailsJson: { from: before.assigneeId, to: body.assigneeId } });
    });
    res.json({ ok: true });
  } catch (err: any) {
    if (err instanceof z.ZodError) return res.status(400).json({ error: err.issues });
    res.status(err.status ?? 500).json({ error: err.message });
  }
});
```

- [ ] **Passo 2:** Commit: `feat(routes): PATCH /api/v1/action-plans/:id`

### Tarefa C7: Endpoint — `PATCH /api/v1/action-plans/:id/status`

- [ ] **Passo 1:**

```ts
const statusSchema = z.object({
  status: z.enum(['pending','in_progress','blocked','done','cancelled']),
  reason: z.string().min(3).max(2000).optional(),
});

app.patch('/api/v1/action-plans/:id/status', isAuthenticatedWithPasswordCheck, requireOperator, async (req, res) => {
  try {
    const planId = z.string().uuid().parse(req.params.id);
    const body = statusSchema.parse(req.body);
    const userId = (req.user as any).id as string;
    await assertEditable(planId, userId);
    const [before] = await db.select({ status: actionPlans.status }).from(actionPlans).where(eq(actionPlans.id, planId));
    await applyStatusChange({ planId, actorId: userId, from: before.status as any, to: body.status, reason: body.reason });
    res.json({ ok: true });
  } catch (err: any) {
    if (err instanceof z.ZodError) return res.status(400).json({ error: err.issues });
    res.status(err.status ?? 500).json({ error: err.message, code: err.code });
  }
});
```

- [ ] **Passo 2:** Smoke tests: tentar transição inválida (ex: `done→pending`) — deve retornar 422. Tentar `pending→blocked` sem reason — 422.
- [ ] **Passo 3:** Commit: `feat(routes): PATCH /api/v1/action-plans/:id/status`

### Tarefa C8: Endpoints — gestão de ameaças no plano

- [ ] **Passo 1:** `POST /api/v1/action-plans/:id/threats` (associar) — inserção em lote ignorando duplicatas (`ON CONFLICT DO NOTHING`) + histórico por ameaça.
- [ ] **Passo 2:** `DELETE /api/v1/action-plans/:id/threats/:threatId` — chama `removeThreatFromPlan` do serviço.
- [ ] **Passo 3:** `GET /api/v1/action-plans/:id/threats` — retorna lista com título, severidade, hosts e flag `hasComments`:

```ts
const rows = await db.select({
  threatId: threats.id,
  title: threats.title,
  severity: threats.severity,
  status: threats.status,
  // ...
  hasComments: sql<boolean>`exists (
    select 1 from action_plan_comment_threats apct
    join action_plan_comments apc on apc.id = apct.comment_id
    where apc.action_plan_id = ${planId} and apct.threat_id = ${threats.id}
  )`,
}).from(actionPlanThreats).innerJoin(threats, eq(threats.id, actionPlanThreats.threatId))
  .where(eq(actionPlanThreats.actionPlanId, planId));
```

- [ ] **Passo 4:** Commit: `feat(routes): action plan threats CRUD`

### Tarefa C9: Endpoints — comentários

- [ ] **Passo 1:** `POST /api/v1/action-plans/:id/comments`:
  - Body: `{ content, threatIds? }`.
  - Sanitizar HTML do content.
  - Validar que todas `threatIds` já estão em `action_plan_threats` deste plano (reject 400 se não).
  - Inserir comment + rows em comment_threats + history(`comment_added`).
- [ ] **Passo 2:** `GET /api/v1/action-plans/:id/comments?threatId=...` — filtro opcional por ameaça.
- [ ] **Passo 3:** `PATCH /api/v1/action-plans/:id/comments/:commentId` — apenas `author_id` pode editar. Atualizar `updatedAt`, histórico `comment_edited`.
- [ ] **Passo 4:** Commit: `feat(routes): action plan comments with threat associations`

### Tarefa C10: Endpoint — histórico

- [ ] **Passo 1:** `GET /api/v1/action-plans/:id/history` — retornar rows ordenadas `createdAt DESC` com `actor` resolvido em `{ id, name }` e `action`, `detailsJson`.
- [ ] **Passo 2:** Commit: `feat(routes): GET /api/v1/action-plans/:id/history`

### Tarefa C11: Endpoints — upload e serve de imagens

- [ ] **Passo 1:**

```ts
app.post('/api/v1/action-plans/upload-image',
  isAuthenticatedWithPasswordCheck, requireOperator,
  uploadMemory.single('image'),
  async (req: Request, res: Response) => {
    if (!req.file) return res.status(400).json({ error: 'Arquivo ausente (campo image).' });
    try {
      const { url } = await persistImage(req.file.buffer);
      res.status(201).json({ url });
    } catch (err: any) {
      res.status(err.status ?? 500).json({ error: err.message });
    }
  });

app.get('/api/v1/action-plans/images/:filename',
  isAuthenticatedWithPasswordCheck,
  async (req, res) => {
    try {
      const p = resolveImagePath(req.params.filename);
      res.sendFile(p, { headers: { 'Cache-Control': 'private, max-age=3600' } });
    } catch (err: any) {
      res.status(err.status ?? 404).end();
    }
  });
```

- [ ] **Passo 2:** Commit: `feat(routes): image upload and serve for action plans`

### Tarefa C12: Endpoint — assignees disponíveis

- [ ] **Passo 1:**

```ts
app.get('/api/v1/action-plans/assignees', isAuthenticatedWithPasswordCheck, async (_req, res) => {
  const rows = await db.select({
    id: users.id,
    name: sql<string>`coalesce(${users.firstName} || ' ' || ${users.lastName}, ${users.email})`,
    email: users.email,
  }).from(users).where(ne(users.role, 'global_administrator')).orderBy(users.email);
  res.json(rows);
});
```

- [ ] **Passo 2:** Commit: `feat(routes): GET /api/v1/action-plans/assignees`

### Tarefa C13: Substituir legacy `GET /api/action-plan`

- [ ] **Passo 1:** Em `server/routes/dashboard.ts`, remover bloco 189-242.
- [ ] **Passo 2:** Em `server/routes/recommendations.ts`, adicionar `GET /api/recommendations/top` com **mesma shape** do ActionPlanItem antigo (campos: `recommendationId, threatId, threatTitle, threatSeverity, threatCategory, contextualScore, projectedScoreAfterFix, whatIsWrong, fixPreview, effortTag, roleRequired, status`).
- [ ] **Passo 3:** Atualizar `client/src/components/dashboard/top-actions.tsx` para chamar `/api/recommendations/top`.
- [ ] **Passo 4:** Commit: `refactor: move legacy action-plan endpoint to /api/recommendations/top`

### Riscos Bloco C
- Mudança na shape `/api/action-plan`. Confirmar que somente `top-actions.tsx` + `pages/action-plan.tsx` consomem — grep duplo antes.
- `ON CONFLICT DO NOTHING` no Drizzle: usar `.onConflictDoNothing()` em `.insert()`.

---

## BLOCO D — Fundação frontend

### Tarefa D1: `client/src/hooks/useActionPlans.ts` — hooks react-query

- [ ] **Passo 1:** Criar hooks encapsulando fetch + invalidação. Chaves padronizadas: `['action-plans']`, `['action-plans', id]`, etc.

```ts
// Exemplo de um hook — repetir padrão para cada endpoint
export function useActionPlans(filters: Filters) {
  return useQuery({
    queryKey: ['action-plans', filters],
    queryFn: () => fetch(`/api/v1/action-plans?${qs.stringify(filters)}`, { credentials:'include' }).then(r => r.json()),
  });
}

export function useCreateActionPlan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreatePlanInput) => fetch('/api/v1/action-plans', { method:'POST', credentials:'include', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) }).then(...),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['action-plans'] }),
  });
}
// ...Plan detail, update, statusChange, threats CRUD, comments CRUD, history, upload, assignees
```

- [ ] **Passo 2:** Commit: `feat(client): react-query hooks for action plans`

### Tarefa D2: `RichTextEditor` (TipTap)

- [ ] **Passo 1:** `client/src/components/rich-text/RichTextEditor.tsx`:
  - `StarterKit` + `Image` + `Link`.
  - Interceptar `paste` para blobs de imagem: upload via `/api/v1/action-plans/upload-image`, inserir `<img>` no editor com URL retornada, mostrar spinner enquanto faz upload.
  - Toolbar mínima: Bold, Italic, Underline, List, OrderedList, Code, Link.
  - Prop `value: string` (HTML), `onChange: (html: string) => void`.
  - Prop `editable: boolean` (default true).
- [ ] **Passo 2:** `client/src/components/rich-text/RichTextRenderer.tsx` — componente read-only que renderiza HTML já sanitizado (vem do backend). Usar `dangerouslySetInnerHTML` ainda é necessário; como backend sanitiza no write, está OK. Encapsular para documentar.
- [ ] **Passo 3:** Smoke: criar página scratch que monta o editor, colar print do clipboard, validar upload.
- [ ] **Passo 4:** Commit: `feat(client): TipTap rich text editor with image paste`

### Tarefa D3: `KanbanBoard` shell com `@dnd-kit`

- [ ] **Passo 1:** `client/src/components/action-plan/KanbanBoard.tsx` com 5 colunas (status), cada uma um `useDroppable`. Cards `useDraggable`. Suporte a `onDropStart(plan, fromStatus, toStatus)` callback no pai para decidir abrir dialog ou confirmar direto.
- [ ] **Passo 2:** Se usuário não tem permissão (não é creator/assignee do plano), retornar card sem `useDraggable` (cursor default).
- [ ] **Passo 3:** Commit: `feat(client): action plan kanban board foundation`

### Tarefa D4: `StatusTransitionDialog`

- [ ] **Passo 1:** Modal com `select` de destino (preenchido pelas transições permitidas a partir de um status), campo textarea para motivo (visível só quando `requiresReason`), botões Confirmar/Cancelar.
- [ ] **Passo 2:** Usar no detail header (botão "Mudar Status") e também no kanban (ao tentar mover).
- [ ] **Passo 3:** Commit: `feat(client): status transition dialog`

### Tarefa D5: `AssigneeSelector` e `ThreatPickerDialog`

- [ ] **Passo 1:** `AssigneeSelector` — combobox com busca, consome `/api/v1/action-plans/assignees`.
- [ ] **Passo 2:** `ThreatPickerDialog` — consulta `/api/threats` com busca e severidade; permite selecionar N ameaças; retorna lista de IDs.
- [ ] **Passo 3:** Commit: `feat(client): assignee selector and threat picker`

---

## BLOCO E — Páginas `/action-plan` e `/action-plan/:id`

### Tarefa E1: Reescrever `client/src/pages/action-plan.tsx`

- [ ] **Passo 1:** Substituir conteúdo por shell que:
  - Header: título "Planos de Ação", botão "Novo plano" (abre `CreateActionPlanDialog`), toggle Lista/Kanban.
  - Filtros: busca textual, multi-select de status, multi-select de prioridade, select de responsável.
  - Rendera `<ActionPlanListTable>` ou `<KanbanBoard>` conforme toggle.
- [ ] **Passo 2:** `ActionPlanListTable` — tabela com colunas do §5.1.1 do spec, click em linha → `setLocation('/action-plan/:id')`.
- [ ] **Passo 3:** `KanbanBoard` conectado: drag inicia, aplica `validateStatusTransition` no cliente (usa mesma lista STATUS_TRANSITIONS duplicada em um módulo compartilhado `client/src/lib/actionPlanStatus.ts` — manter espelhado; único caminho backward-compat). Se transição inválida → toast + revert. Se exige reason → abre dialog → se cancel revert, se confirma chama `PATCH .../:id/status`.
- [ ] **Passo 4:** Commit: `feat(client): /action-plan list and kanban page`

### Tarefa E2: `/action-plan/:id` — shell e aba Sumário

- [ ] **Passo 1:** Registrar rota em `client/src/App.tsx`:

```ts
<Route path="/action-plan/:id" component={ActionPlanDetail} />
```

- [ ] **Passo 2:** `client/src/pages/action-plan-detail.tsx`:
  - Header com código, título, status badge, prioridade, responsável, datas.
  - Botões "Editar" (dialog) e "Mudar Status" (dialog) condicionados a permissão (creator || assignee).
  - Tabs: Sumário, Comentários, Ameaças, Histórico.
  - **Aba Sumário:** descrição renderizada (`RichTextRenderer`), cards de métricas (total ameaças + por severidade + total comentários), banner de `blockReason` ou `cancelReason` quando aplicável.
- [ ] **Passo 3:** Commit: `feat(client): action plan detail page — summary tab`

### Tarefa E3: Aba Comentários

- [ ] **Passo 1:** Lista de comentários (desc por data) — `CommentItem` renderiza autor, data, conteúdo HTML via `RichTextRenderer`, badges das ameaças associadas (título, clicável — abre popover com link pra ameaça em `/threats`).
- [ ] **Passo 2:** `CommentComposer` no topo: `RichTextEditor` + multi-select de ameaças do plano (não de todas ameaças). Botão enviar → `POST /comments`. Após sucesso: invalidar `['action-plans', id, 'comments']` + `['action-plans', id, 'history']`.
- [ ] **Passo 3:** Editar comentário: edit-inline para o autor, botão "Editar" que transforma item em composer com valor atual.
- [ ] **Passo 4:** Commit: `feat(client): action plan comments tab`

### Tarefa E4: Aba Ameaças

- [ ] **Passo 1:** Tabela com severity-badge, título, hosts, status, ícone prancheta.
- [ ] **Passo 2:** Prancheta:
  - Se `hasComments = true`: ícone colorido clicável → abre Drawer lateral listando comentários filtrados por esta threat (`GET /comments?threatId=...`).
  - Se falso: cinza/desabilitado.
- [ ] **Passo 3:** Botão "Associar Ameaças" (permissão) → abre `ThreatPickerDialog` → confirma → `POST /threats`.
- [ ] **Passo 4:** Botão de remover por linha com confirmação → `DELETE /threats/:threatId`.
- [ ] **Passo 5:** Commit: `feat(client): action plan threats tab`

### Tarefa E5: Aba Histórico

- [ ] **Passo 1:** Timeline vertical com ícone por `action`, descrição humanizada ("Status alterado de Pendente para Bloqueado"), autor e data. Motivos exibidos inline para `status_changed`.
- [ ] **Passo 2:** Commit: `feat(client): action plan history tab`

---

## BLOCO F — Integração em `/threats`

### Tarefa F1: Regra de checkbox do grupo

- [ ] **Passo 1:** Em `client/src/pages/threats.tsx`, localizar `selectedIds` (linha 267) e o render do parent group (linha 901). Ajustar `onCheckedChange` do parent:
  - Quando marca: marcar todos `children.map(c => c.id)` + o parent id.
  - Quando desmarca: desmarcar todos + parent.
- [ ] **Passo 2:** Ajustar render do checkbox do parent para ser `checked={allChildrenSelected}` (derivado). Estado `indeterminate` quando só alguns filhos selecionados:

```ts
const childIds = children.map(c => c.id);
const selectedCount = childIds.filter(id => selectedIds.has(id)).length;
const allSelected = childIds.length > 0 && selectedCount === childIds.length;
const someSelected = selectedCount > 0 && !allSelected;
```

Radix Checkbox aceita `checked={allSelected ? true : someSelected ? 'indeterminate' : false}`.

- [ ] **Passo 3:** Commit: `feat(threats): group checkbox follows children state`

### Tarefa F2: Botão "Associar a Plano de Ação" nas bulk actions

- [ ] **Passo 1:** Em `threats.tsx`, localizar barra de ações em massa (busca por `selectedIds.size > 0`). Adicionar botão "Associar a Plano de Ação".
- [ ] **Passo 2:** Criar `client/src/components/action-plan/AssociateToPlanDialog.tsx`:
  - Radio: "Plano existente" / "Novo plano".
  - Se existente: dropdown com `GET /api/v1/action-plans?status=pending,in_progress,blocked` (omitir done/cancelled) mostrando código + título. Confirmar → `POST /:id/threats`.
  - Se novo: abrir `CreateActionPlanDialog` com `threatIds` pré-preenchidos.
- [ ] **Passo 3:** Commit: `feat(threats): associate selected threats to action plan`

### Tarefa F3: Coluna "Plano de Ação" (prancheta)

- [ ] **Passo 1:** Adicionar ao `GET /api/threats` uma agregação opcional `planIds: string[]` por ameaça. **Preferível:** novo endpoint `GET /api/v1/threats/plan-links?threatIds=...` que recebe IDs e devolve map `{ threatId: [{id,code,title}, ...] }`. Mais simples que mexer no endpoint principal.
- [ ] **Passo 2:** No frontend, após carregar threats visíveis, fazer chamada batch para esse endpoint. Armazenar em `Map<string, PlanRef[]>`.
- [ ] **Passo 3:** Render da coluna:
  - **Linha ameaça:** se plans.length === 0, ícone cinza. Se 1, clickar navega para `/action-plan/:id`. Se >1, popover com lista.
  - **Linha grupo:** contar `children.filter(c => planMap.get(c.id)?.length).length` e mostrar `${planned}/${children.length}`. Apenas informativo.
- [ ] **Passo 4:** Commit: `feat(threats): action plan column with per-row and per-group counts`

### Riscos Bloco F
- `threats.tsx` tem 2056 linhas. Toda alteração exige leitura cuidadosa antes para não quebrar `selectedIds` bulk-status-modal existente.
- Endpoint `/plan-links` — manter shape pequena pra não explodir latência; limitar input a 500 IDs.

---

## BLOCO G — Cleanup, QA e checklist

### Tarefa G1: `install.sh` — preparar diretório de uploads

- [ ] **Passo 1:** Adicionar comandos idempotentes:

```bash
sudo mkdir -p /var/lib/samureye/uploads/action-plans
sudo chown -R samureye:samureye /var/lib/samureye/uploads
sudo chmod 750 /var/lib/samureye/uploads
```

- [ ] **Passo 2:** Commit: `chore(install): create action plan uploads directory`

### Tarefa G2: Sidebar label + ícone

- [ ] **Passo 1:** Já está "Plano de Ação" em `client/src/components/layout/sidebar.tsx`. Confirmar ícone (ClipboardList). Sem mudança se já ok.

### Tarefa G3: Type-check e smoke test geral

- [ ] `npm run check` — zero erros.
- [ ] `npm run test` — zero falhas.
- [ ] `npm run dev` — fluxo e2e manual:
  - Criar plano com 3 ameaças.
  - Verificar código `PA-2026-0001`.
  - Mudar status pending→in_progress (sem motivo).
  - Tentar done→in_progress (bloqueado, 422).
  - Adicionar comentário com print colado (Ctrl+V de screenshot).
  - Remover uma ameaça do plano → confirmar que o comment ainda existe mas o link ameaça-comentário sumiu.
  - Mover card no kanban com reason.
  - Associar ameaças via /threats.
  - Deslogar e logar com outro usuário (não creator/assignee) → confirmar que só vê, não edita.

### Tarefa G4: Checklist final do spec §10

Espelhar o §10 do spec original e marcar manualmente. Commit final: `chore(plan): complete action plan redesign per 04-04 spec`.

---

## Riscos globais e mitigação

| Risco | Probabilidade | Impacto | Mitigação |
|---|---|---|---|
| Quebra do dashboard (TopActions depende de /api/action-plan) | Alta | Alto | Tarefa C13 — substituição de endpoint na mesma PR antes de remover o antigo. |
| Upload dir sem permissão em prod | Média | Alto | Tarefa G1 + fallback para diretório relativo em dev. Validar no boot: `persistImage` falha explícita. |
| TipTap `Image.paste` não funcionar em Safari | Baixa | Médio | Implementar manual via `editorProps.handlePaste` custom em vez de confiar no extension default. |
| Grande volume de `threats` quebrar `/plan-links` | Baixa | Médio | Limitar a 500 IDs por request; paginar threats no front. |
| Sanitize-html quebrar markup legítimo do TipTap | Média | Baixo | Bateria de testes em htmlSanitizer (Tarefa B2). Ajustar allowlist quando necessário. |
| Race de `PA-YYYY-NNNN` | Baixa | Alto | `pg_advisory_xact_lock` + teste de concorrência em Tarefa B4. |
| Desalinhamento status list cliente↔servidor | Média | Médio | Definir `STATUS_TRANSITIONS` em arquivo compartilhado (ou em `shared/`) e importar em ambos. |

---

## Self-review

| Item do spec | Coberto por tarefa |
|---|---|
| Código PA-YYYY-NNNN (§2.1) | B4 |
| Assignees excluindo admin (§2.1) | C12 (usando `role`) |
| Constraint unique comment-threat (§2.4) | A5 |
| Cleanup comment_threats ao remover threat (§2.4) | B6 |
| action_plan_history com ações (§2.5) | A6 + B6 + cada endpoint mutável |
| Upload seguro de imagens (§2.6) | B3 + C11 |
| Todas as transições de status + reasons (§3) | B5 + B6 + C7 |
| Todos endpoints §4.1 | C3–C12 |
| Resolver nomes nas respostas (§4.2) | C1 (queries com joins nomeados) |
| Permissões (§4.3) | `assertEditable` + middlewares |
| Modo lista + kanban (§5.1) | E1 |
| Drag-and-drop com permissão + reason (§5.1.2) | D3 + E1 |
| Detalhe com abas (§5.2) | E2, E3, E4, E5 |
| Checkbox de grupo (§5.3.1) | F1 |
| "Associar a Plano" (§5.3.1) | F2 |
| Coluna prancheta (§5.3.2) | F3 |
| Editor rich text com paste (§6) | D2 |
| Sanitização (§8) | B2 + chamado em C4/C6/C9 |
| Migration Drizzle (§7) | A1–A7 |

---

## Handoff de execução

**Opção 1 (recomendada): Subagent-Driven** — dispatch de agente por tarefa, revisão entre cada. Bom para um plano extenso como este. Requer `superpowers:subagent-driven-development`.

**Opção 2: Inline** — executar sequencialmente nesta sessão, com checkpoints no final de cada Bloco. Requer `superpowers:executing-plans`.

**Qual você prefere?**

Sugiro iniciar executando o **Bloco A inteiro como unidade** (mudanças pequenas, pouca lógica, tudo em `shared/schema.ts`), revisar o SQL do `db:push` juntos, e só então seguir para B. Depois do Bloco C (backend completo + smoke-tested), pausamos novamente antes de frontend.
