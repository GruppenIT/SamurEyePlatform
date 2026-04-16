# Design Spec — Recuperação de senha via e-mail

**Data:** 2026-04-16
**Branch:** `feat/webapp-journey-revisions`
**Autor:** Claude (brainstorming)

## 1. Problema

Um usuário que esquece a senha hoje só consegue recuperar acesso pedindo a outro admin reset via SQL. Com a mensageria já integrada (Google, MS 365, SMTP), podemos oferecer auto-serviço seguro via e-mail.

## 2. Objetivo

Adicionar fluxo de recuperação de senha na tela de login:

1. Link "Esqueci minha senha" visível **apenas** quando a mensageria está configurada e testada (mesma condição usada pelo MFA por e-mail).
2. Usuário informa e-mail; servidor envia link com token de uso único (TTL 30 minutos).
3. Link abre tela onde usuário define nova senha.
4. Pós-reset: todas sessões ativas do usuário invalidadas; MFA continua exigido no próximo login.

Não-objetivos:
- Recuperação por SMS/WhatsApp/perguntas de segurança.
- Auto-login após reset (forçar relogin completo).
- Reset de MFA via esse fluxo (usuário que perdeu TOTP + senha continua dependendo de admin manual).
- Enforcement de política de senha complexa além do mínimo atual do sistema.

## 3. Premissas verificadas no código

- `email_settings.last_test_success_at` já existe e é setado por `POST /api/email-settings/test` em sucesso.
- `emailService.sendEmail(settings, options)` disponível e funcional.
- `users` tem `passwordHash`, `mustChangePassword`, `id`.
- `storage.getLoginAttempt(key)` / `storage.upsertLoginAttempt(key, true)` / `storage.resetLoginAttempts(key)` já reutilizáveis para qualquer prefixo de chave (hardcoded 5 tentativas → 15min bloqueio).
- `storage.invalidateAllSessionsOnStartup()` ou equivalente — a verificar se existe helper para invalidar sessões de um user específico; senão criar bump de `session_version` (já existe) ou adicionar `invalidateUserSessions(userId)`.
- `client/src/pages/login.tsx` usa wouter, react-hook-form, react-query.
- `App.tsx` tem um Switch não-autenticado que só lista `/` e `/login`; rotas novas precisam entrar ali.

## 4. Schema

Nova tabela `password_reset_tokens`:

```ts
export const passwordResetTokens = pgTable("password_reset_tokens", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").references(() => users.id, { onDelete: 'cascade' }).notNull(),
  tokenHash: text("token_hash").notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  consumedAt: timestamp("consumed_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
}, (table) => [
  index("idx_password_reset_tokens_user_active").on(table.userId, table.expiresAt),
]);
```

Sem coluna em `users`. Reset somente atualiza `users.passwordHash` e zera `users.mustChangePassword`.

## 5. Endpoints

### 5.1. `GET /api/auth/features` — público

Retorna `{ passwordRecoveryAvailable: boolean }`. Avaliação:

```
passwordRecoveryAvailable = emailSettings?.lastTestSuccessAt && lastTestSuccessAt > now - 30d
```

Sem rate limit (leve e idempotente; único dado exposto é "mensageria configurada" que um atacante descobre pedindo reset ou mandando login).

### 5.2. `POST /api/auth/password-reset/request` — público

Body: `{ email }`.

Pipeline:
1. Rate limits (nunca rejeitar — só deixar de enviar): `pwreset:ip:<ip>` 3/5min, `pwreset:email:<hash>` 3/15min.
2. Lookup `storage.getUserByEmail(email)`. Se não existir, ainda responde 202.
3. Se `passwordRecoveryAvailable` = false, ainda responde 202 (silencioso).
4. Gera `token = crypto.randomBytes(32).toString('base64url')`. Hash bcrypt 10. Insere em `password_reset_tokens` com `expiresAt = now + 30min`. Remove tokens do user com >24h de idade.
5. Envia e-mail: `to = user.email`, subject `Recuperação de senha SamurEye`, body html curto com link `{APP_BASE_URL}/reset-password?token={raw}`. Erros de envio são logados, não expostos.
6. `upsertLoginAttempt('pwreset:ip:<ip>', true)` + `upsertLoginAttempt('pwreset:email:<hash>', true)` (só para rate limit — nem bloqueia agora).
7. Retorna 202 `{ message: "Se o e-mail existir em nossa base, enviaremos um link em instantes." }`.

### 5.3. `GET /api/auth/password-reset/verify?token=...` — público

Valida existência + não-expirado + não-consumido. Não revela `userId`. Só retorna 200 `{ valid: true }` ou 410 `{ valid: false }`.

### 5.4. `POST /api/auth/password-reset/confirm` — público

Body: `{ token, newPassword }`.

Pipeline:
1. Rate limit `pwreset:confirm:ip:<ip>` (5/15min). Se bloqueado → 429.
2. Percorre tokens não-consumidos não-expirados, bcrypt.compare contra cada `token_hash`. Se nenhum bate → incrementa rate limit + 401.
3. Valida `newPassword` pela política unificada (§ 6.5): mínimo 12 caracteres, pelo menos 1 maiúscula, 1 minúscula, 1 dígito e 1 caractere especial. Cliente valida também localmente antes do submit.
4. `users.passwordHash = bcrypt.hash(newPassword, 12)` + `mustChangePassword = false`.
5. Marca o token `consumed_at = now`. Marca todos os outros tokens ativos do mesmo user como `consumed_at = now` (invalida duplicatas).
6. Invalida todas sessões ativas do user: bump do `session_version` global **apenas se não houver helper dedicado por-user** (checar no código). Se existir `storage.invalidateUserSessions(userId)`, usar. Caso contrário, adicionar essa função baseada no padrão de `active_sessions` (DELETE WHERE user_id = ?).
7. Audit log `user.password.reset`.
8. Retorna 200 `{ message: "Senha atualizada. Faça login." }`.

## 6. UI

### 6.1. Link na login page (`client/src/pages/login.tsx`)

Novo `useQuery(["/api/auth/features"])` no mount. Se `data?.passwordRecoveryAvailable` for true, renderiza abaixo do submit button:

```tsx
<Link href="/forgot-password" className="text-sm text-primary hover:underline">
  Esqueci minha senha
</Link>
```

### 6.2. Nova `/forgot-password`

Card simples:
- Input: e-mail.
- Botão "Enviar link".
- Submit → POST `/api/auth/password-reset/request`.
- Na resposta (sempre 202), troca conteúdo do card por mensagem "Se o e-mail existir na nossa base, você receberá um link em instantes. Verifique também a caixa de spam." + link "Voltar ao login".

### 6.3. Nova `/reset-password`

Lê `token` da query string.

- Mount: GET `/api/auth/password-reset/verify?token=`. 
- Se 410 → tela "Link inválido ou expirado" com botão "Solicitar novo link" (→ `/forgot-password`).
- Se 200 → form com "Nova senha" + "Confirmar nova senha" (com regras de mínimo local).
- Submit → POST `/api/auth/password-reset/confirm`. Sucesso → `setLocation("/login")` com toast "Senha atualizada. Faça login novamente."

### 6.5. Política de senha (reforçada)

Aplicada tanto em `/reset-password` quanto no `/change-password` existente (alinhar a política em um único ponto para evitar divergência):

- Mínimo 12 caracteres.
- Pelo menos 1 letra maiúscula.
- Pelo menos 1 letra minúscula.
- Pelo menos 1 dígito.
- Pelo menos 1 caractere especial (não alfanumérico).

Implementação:
- `shared/schema.ts` expõe `passwordComplexitySchema` (Zod) reutilizável — `z.string().min(12).regex(/[A-Z]/).regex(/[a-z]/).regex(/\d/).regex(/[^A-Za-z0-9]/)`.
- Backend `POST /password-reset/confirm` e a rota existente `POST /api/auth/change-password` passam a usar esse schema.
- Cliente `/reset-password` e `/change-password` exibem checklist visual (ícones ✓/✗ abaixo do campo "Nova senha" mostrando cada requisito) com feedback em tempo real.

Usuários existentes com senhas que não atendem à nova política **não são forçados a trocar** automaticamente — a validação só dispara em mudança (change-password ou reset).

### 6.4. `App.tsx`

No branch `!isAuthenticated`, adicionar antes do fallback:

```tsx
<Route path="/forgot-password" component={ForgotPassword} />
<Route path="/reset-password" component={ResetPassword} />
```

## 7. E-mail template (pt-BR)

```html
<p>Você solicitou a redefinição de senha para sua conta SamurEye.</p>
<p>Clique no link abaixo (válido por 30 minutos):</p>
<p><a href="{link}">{link}</a></p>
<p>Se você não fez essa solicitação, ignore este e-mail — sua senha permanece inalterada.</p>
```

## 8. Arquivos afetados

### Novos
- `server/storage/password-reset.ts` — CRUD (create, findActive, consume, consumeAllForUser, cleanupExpired).
- `server/services/passwordResetService.ts` — gera token, valida, envia e-mail.
- `server/routes/auth-password-reset.ts` — 4 endpoints.
- `client/src/pages/forgot-password.tsx`.
- `client/src/pages/reset-password.tsx`.

### Modificados
- `shared/schema.ts` — tabela + types + `passwordComplexitySchema` compartilhado.
- `server/storage/interface.ts` + `server/storage/index.ts` — wire novos helpers + `invalidateUserSessions` se não existir.
- `server/routes/index.ts` — registrar rotas.
- `server/localAuth.ts` — `POST /api/auth/change-password` passa a usar `passwordComplexitySchema`.
- `client/src/pages/login.tsx` — link condicional via `/api/auth/features`.
- `client/src/pages/change-password.tsx` — checklist visual da política reforçada.
- `client/src/App.tsx` — rotas novas no branch não-autenticado.

### Não alterados
- `server/services/emailService.ts` — reutilizado.
- Tabela `users` — sem novas colunas.
- `localAuth.ts` — o endpoint `/api/auth/login` não muda.

## 9. Critérios de aceite

1. `/login` mostra link "Esqueci minha senha" apenas quando a mensageria foi testada nos últimos 30 dias.
2. Sem mensageria testada: link sumido + `POST /password-reset/request` continua 202 sem enviar e-mail (com log).
3. `/forgot-password` sempre responde "Se o e-mail existir, enviaremos link" — não vaza existência.
4. E-mail de recuperação chega com link contendo token válido por 30 minutos.
5. Link inválido/expirado em `/reset-password` mostra "Link inválido" e CTA para solicitar novo.
6. Link válido aceita nova senha que atenda a política reforçada (§ 6.5) e após submit redireciona para `/login` com toast. Senha fraca → erro no submit e checklist visual mostrando critérios faltantes.
7. Após reset bem-sucedido: todas sessões ativas do usuário são invalidadas; próxima requisição autenticada dá 401.
8. Token usado fica com `consumed_at` preenchido e não pode ser reutilizado.
9. Se usuário tem MFA ativo, login pós-reset passa normalmente pela tela de `/mfa-challenge`.
10. Rate limit: 3 requests/5min por IP, 3/15min por e-mail, 5 tentativas de confirm/15min por IP.

## 10. Segurança

- **Enumeração de e-mail:** mitigada via 202 invariante.
- **Brute-force token:** 256 bits de entropia (`randomBytes(32)` base64url) + rate limit no confirm. Timing attack nos `bcrypt.compare` aceita — o atacante precisa adivinhar 256 bits antes de esgotar o rate limit.
- **Sequestro por e-mail comprometido:** aceito — MFA continua sendo exigido no próximo login.
- **Sessões órfãs:** invalidar todas sessões do user no reset evita que uma sessão de um possível atacante continue viva.
- **Logs:** nunca imprimir o token plaintext. Auditar request/confirm com metadata (userId se conhecido, timestamp, IP).

## 11. Fora de escopo

(A política reforçada, descrita na §6.5, passa a ser compartilhada com `/change-password`.)
- Histórico de senhas / "não pode repetir últimas N".
- Reset iniciado pelo admin (já existe via troca de senha do user em `/users`).
- Internacionalização além do pt-BR.
