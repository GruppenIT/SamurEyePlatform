# Design Spec — MFA (TOTP) + Menu de Conta + Banner do admin de setup

**Data:** 2026-04-16
**Branch:** `feat/webapp-journey-revisions`
**Autor:** Claude (brainstorming)

## 1. Problema

1. O SamurEye hoje autentica apenas com senha. Qualquer vazamento de credencial dá acesso pleno ao console.
2. O "user profile" está escondido no rodapé do sidebar — não há um lugar natural pra gerenciar a própria conta.
3. A conta de setup inicial (`admin@samureye.local`) é usada em produção por inércia porque nada sinaliza que ela deveria ficar só pro primeiro boot.

## 2. Objetivo

Ship em uma única sequência:

1. **Menu de conta no topbar** (canto superior direito) substitui o bloco do sidebar.
2. **MFA via TOTP** com 8 códigos de recuperação, modal de convite no primeiro login e opção "não lembrar mais".
3. **TOTP por e-mail** como alternativa no login, quando o usuário tem MFA e a mensageria foi testada com sucesso.
4. **Banner de aviso** quando logado como `admin@samureye.local`.

Não-objetivos:
- WebAuthn / chaves de hardware.
- SMS como fator.
- SSO / SAML / OIDC federado (fora do escopo).
- MFA opcional por role; todos têm a mesma experiência.
- Migrar usuários existentes pra MFA compulsório; MFA fica opcional.

## 3. Premissas verificadas no código

- `server/localAuth.ts` — Passport local strategy (email+password), rate limit por identificador, seed `admin@example.com`.
- DB tem três admins (`admin@samureye.local`, `admin@example.com`, `system@samureye.local`); `admin@samureye.local` é o efetivamente usado em prod.
- `shared/schema.ts:87` já tem `mustChangePassword` em `users`.
- Tabela `email_settings` não tem sinal persistido de "teste OK" — precisa de campo novo (§4.1).
- Não há biblioteca TOTP/QR instalada no `package.json`.
- `client/src/components/layout/sidebar.tsx:217-252` renderiza o bloco de user profile.
- `client/src/components/layout/topbar.tsx` tem espaço para ações no canto direito e já renderiza `SystemStatusPopup`.
- `EncryptionService` (padrão KEK/DEK) já é usado por `email_settings` para secrets.
- `client/src/pages/change-password.tsx` existe — será reaproveitado.

## 4. Schema & persistência

### 4.1. Alterações em tabelas existentes

**`users` (coluna nova)**:

| Coluna | Tipo | Default | Uso |
|---|---|---|---|
| `mfa_enabled` | `boolean` | `false` NOT NULL | Flag de ativação. |
| `mfa_secret_encrypted` | `text` | NULL | Segredo TOTP criptografado (KEK/DEK). |
| `mfa_secret_dek` | `text` | NULL | DEK que envelopa `mfa_secret_encrypted`. |
| `mfa_backup_codes` | `text[]` | NULL | Array de hashes bcrypt (custo 10) dos 8 recovery codes ainda não consumidos. |
| `mfa_enabled_at` | `timestamp` | NULL | Timestamp de ativação, para exibição em /account/mfa. |
| `mfa_invitation_dismissed` | `boolean` | `false` NOT NULL | "Não lembrar" do modal de convite. |

**`email_settings` (coluna nova)**:

| Coluna | Tipo | Default | Uso |
|---|---|---|---|
| `last_test_success_at` | `timestamp` | NULL | Setado em sucesso de `POST /api/email-settings/test`. Condição pra TOTP-por-email. |

### 4.2. Tabela nova

**`mfa_email_challenges`** — códigos enviados por e-mail:

| Coluna | Tipo | Constraints |
|---|---|---|
| `id` | `uuid` | PK, default `gen_random_uuid()` |
| `user_id` | `uuid` | FK `users.id`, NOT NULL |
| `code_hash` | `text` | NOT NULL (bcrypt do código de 6 dígitos) |
| `expires_at` | `timestamp` | NOT NULL (+5min) |
| `consumed_at` | `timestamp` | NULL até ser usado |
| `created_at` | `timestamp` | default `now()` |

Índice: `CREATE INDEX ON mfa_email_challenges (user_id, expires_at) WHERE consumed_at IS NULL;`

Cleanup lazy: toda criação de challenge para o `user_id` já remove expirados/consumidos com mais de 24h.

### 4.3. Sessão

`req.session` ganha um campo opcional `pendingMfa: boolean`. Sem migration — é só um field do express-session. Também `req.session.pendingMfaSecret` e `req.session.pendingMfaBackupHashes` são usados transitoriamente durante o setup (entre `/mfa/setup` e `/mfa/enable`); ficam só em memória, nunca no banco.

## 5. Fluxos

### 5.1. Login normal (MFA desativado)

Inalterado. POST `/api/auth/login` → 200 + user.

### 5.2. Login com MFA ativado

1. POST `/api/auth/login` `{ email, password }`.
2. Senha válida → marca `req.session.userId = user.id` + `req.session.pendingMfa = true`. Retorna:
   ```json
   { "pendingMfa": true, "emailDeliveryAvailable": true | false }
   ```
   `emailDeliveryAvailable` = `user.mfa_enabled && emailSettings.last_test_success_at < 30 dias atrás`.
3. Cliente navega para `/mfa-challenge`.
4. Middleware `isAuthenticated` bloqueia qualquer `/api/*` com 401 `{ mfaRequired: true }` enquanto `pendingMfa === true`, exceto: `/api/auth/mfa/verify`, `/api/auth/mfa/email`, `/api/auth/logout`, `/api/auth/user` (essa retorna um shape reduzido `{ pendingMfa: true }`).
5. POST `/api/auth/mfa/verify` `{ token: string }`:
   - Ordem de tentativa:
     1. Se existir `mfa_email_challenges` ativo (não consumido, não expirado) para esse user, tenta bcrypt-compare contra `code_hash`. Se bater → marca `consumed_at`, limpa os outros challenges ativos, promove sessão.
     2. Se `token.length === 6` e todos dígitos → TOTP: `authenticator.verify({ token, secret: decrypt(user.mfa_secret_encrypted), window: 1 })`. Passa → promove.
     3. Else → percorre `mfa_backup_codes` e tenta bcrypt-compare; quando bate, remove o hash consumido do array via UPDATE e promove.
   - Fail → 401 + incrementa rate limit MFA (5 tentativas / 15min por user_id). Esgotado → 423 Locked.
6. POST `/api/auth/mfa/email`:
   - Requer `pendingMfa` ou sessão plena + MFA ativado.
   - Requer `emailSettings.last_test_success_at` não-null e ≤30 dias.
   - Rate limit: 3 envios / 5min por user_id.
   - Gera código de 6 dígitos (crypto.randomInt), hasheia (bcrypt 10), insere em `mfa_email_challenges` com `expires_at = now + 5min`. Limpa expirados/consumidos antigos do mesmo user.
   - Envia via `emailService.sendEmail(settings, { to: user.email, subject: "Código de verificação SamurEye", html: "..." })`.
   - Retorna 202.

### 5.3. Setup de MFA (usuário autenticado, sessão plena)

1. Usuário abre `/account/mfa`.
2. Cliente POSTa `/api/auth/mfa/setup`:
   - Gera `secret = authenticator.generateSecret()`.
   - Gera 8 recovery codes de 10 chars alfanuméricos lowercase (ex.: `k3x7m9n1qp`), hashea cada um.
   - Stash em `req.session.pendingMfaSecret` (plaintext para validação no próximo passo) + `req.session.pendingMfaBackupHashes` (array).
   - Retorna `{ otpauthUrl, qrCodeSvg, backupCodes: [...plaintext] }` — plaintext **só vai na resposta**, nunca no DB.
3. Tela mostra QR + 8 códigos com botões "Copiar" e "Baixar .txt". Input de 6-dígitos + botão "Ativar".
4. POST `/api/auth/mfa/enable` `{ token }`:
   - Valida TOTP contra `session.pendingMfaSecret`.
   - Se OK: criptografa secret (KEK/DEK via `encryptionService`), grava em `users` junto com `mfa_backup_codes = session.pendingMfaBackupHashes`, `mfa_enabled = true`, `mfa_enabled_at = now`. Limpa a sessão.
   - Audit log da ativação.

### 5.4. Modal de convite (primeiro login)

- Condição: `user.mfa_enabled === false && user.mfa_invitation_dismissed === false`.
- `GET /api/auth/user` passa a retornar esses dois booleans.
- Cliente tem um componente `<MfaInvitationGate>` montado no `App.tsx` após o login; se a condição bater, exibe um `AlertDialog` (shadcn) modal blocking:
  - Título, texto, checkbox "Não lembrar novamente", dois botões:
    - **Configurar agora** → fecha modal, navega para `/account/mfa` (se checkbox marcada, PUT dismiss antes).
    - **Deixar pra depois** → fecha modal (se checkbox marcada, PUT dismiss antes).
- PUT `/api/auth/me/mfa-invitation-dismissed` `{}` → seta `mfa_invitation_dismissed = true`. Idempotente.

### 5.5. Gerenciar MFA (ativo)

`/account/mfa` com MFA ativo mostra:
- Status "MFA ativado desde {data}".
- Botão **Regenerar códigos de recuperação** → POST `/api/auth/mfa/recovery-codes/regenerate` `{ currentPassword }`. Valida senha; se OK, gera 8 novos, hashea, substitui o array. Retorna os plaintext. Exibe-os na tela com "Copiar/Baixar".
- Botão **Desativar MFA** → POST `/api/auth/mfa/disable` `{ currentPassword, token }`. Valida ambos. Se OK: zera `mfa_*` fields, audit log, redireciona para `/account` com toast.

### 5.6. Banner admin de setup

- Componente `<SetupAdminBanner>` montado em `App.tsx` logo acima do `<Sidebar>` quando `currentUser?.email === 'admin@samureye.local'` **e** sessão plena.
- Cor warning (amarelo), ícone `AlertTriangle`, não-dispensável.
- Conteúdo:
  > Você está usando a conta de setup inicial (`admin@samureye.local`). Esta conta serve apenas para instalação do appliance. Crie contas nomeadas em **Administração → Usuários** e evite continuar logado aqui.
- Link "Gerenciar usuários" → `/users`.

## 6. UI

### 6.1. Menu de conta no topbar

- Remove o bloco `{/* User Profile */}` de `sidebar.tsx` (linhas 217-252).
- Mantém a versão (`v{appVersion}`) no pé do sidebar, formatação discreta.
- Em `topbar.tsx`, adiciona, antes do `SystemStatusPopup`, um `<DropdownMenu>` (shadcn) com:
  - Trigger: `<Button variant="ghost" size="icon"><Avatar><AvatarFallback>XX</AvatarFallback></Avatar></Button>`. Fallback = iniciais do `firstName`/`email`.
  - `DropdownMenuContent` align="end":
    - `DropdownMenuLabel`: nome completo + `<span className="text-xs text-muted-foreground">{email}</span>` + role traduzido.
    - `DropdownMenuSeparator`.
    - `DropdownMenuItem` → `/account` ("Minha Conta").
    - `DropdownMenuItem` → `/change-password` ("Trocar senha").
    - `DropdownMenuItem` → `/account/mfa` ("Gerenciar MFA").
    - `DropdownMenuSeparator`.
    - `DropdownMenuItem` destructive → logout ("Sair").

### 6.2. Página `/account` (nova, container simples)

Cards de atalho com os mesmos 3 destinos (Minha Conta não é um hub complexo — essencialmente um index das ações). Opcional — se quiser pular, podemos linkar direto do dropdown; mantenho como página só pro dropdown não ser a única porta de entrada.

### 6.3. Página `/account/mfa`

Estados:
- **Desativado**: card com explicação curta + botão "Configurar MFA" → abre setup wizard inline.
- **Setup wizard**: QR (SVG inline renderizado pelo `qrcode.toString(url, { type: 'svg' })`) à esquerda, 8 códigos de recuperação em lista monospace à direita com "Copiar/Baixar". Input 6-dígitos + "Ativar".
- **Ativado**: linha "MFA ativado desde {data}", botões "Regenerar códigos" e "Desativar MFA" (ambos abrem diálogo de confirmação com os inputs requeridos).

### 6.4. Página `/mfa-challenge` (nova)

- Route pública (não exige sessão plena); exige `pendingMfa === true`.
- Input 6-dígitos grande + botão "Validar".
- Link "Usar código de recuperação" → troca o input para `maxLength=12` monospace.
- Se `emailDeliveryAvailable`, botão secundário "Enviar código por e-mail" → POST `/mfa/email`, toast "Código enviado".
- Link "Sair" → POST `/api/auth/logout`.
- Após sucesso, invalida query `/api/auth/user` e navega para `/`.

## 7. Segurança

- TOTP secret: `authenticator.generateSecret()` (32 chars base32 por padrão), criptografado KEK/DEK antes de persistir.
- Recovery codes: 10 chars alfanuméricos lowercase, gerados via `crypto.randomBytes(8).toString('hex').slice(0, 10)` (entropia suficiente, 10^10+ possibilidades); hash bcrypt custo 10; consumidos um a um e removidos do array.
- `otpauthUrl` usa `issuer="SamurEye"` + `label=${user.email}`.
- Rate limit MFA separado do password: 5 falhas / 15min por user_id → 423 Locked até janela expirar (reaproveita tabela `login_attempts` com prefixo de key, ex.: `mfa:${userId}`).
- Rate limit email MFA: 3 envios / 5min por user_id.
- Senha + TOTP exigidos tanto pra desativar MFA quanto pra regenerar códigos (defesa contra sequestro de sessão).
- Nenhum log deve imprimir secrets, códigos, tokens. Auditar: ativação, desativação, falha acima de threshold, regeneração de códigos.
- `/mfa-challenge` e POSTs de `/mfa/*` só aceitam POST (CSRF via sameSite=strict já existe no session cookie).
- Middleware rejeita `pendingMfa` em qualquer rota que não esteja na allowlist.

## 8. Componentes e arquivos afetados

### Novos
- Backend:
  - `server/services/mfaService.ts` — wrap de `otplib` + bcrypt para recovery codes + helpers de geração/verificação/limpeza de `mfa_email_challenges`. Testado com vitest.
  - `server/routes/mfa.ts` — rotas `/api/auth/mfa/*` (ou juntar em `localAuth.ts` se preferir mais enxuto; plano vai decidir).
- Cliente:
  - `client/src/pages/account.tsx` — hub Minha Conta.
  - `client/src/pages/account-mfa.tsx` — setup + gerenciar.
  - `client/src/pages/mfa-challenge.tsx` — tela de login fase 2.
  - `client/src/components/account/mfa-invitation-dialog.tsx` — modal de primeiro login.
  - `client/src/components/account/user-menu.tsx` — dropdown do topbar.
  - `client/src/components/layout/setup-admin-banner.tsx` — banner amarelo.

### Modificados
- Backend:
  - `shared/schema.ts` — colunas em `users` + `email_settings` + nova tabela `mfa_email_challenges` + tipos inferidos.
  - `server/localAuth.ts` — estende login para detectar `mfa_enabled`, middleware `isAuthenticated` checa `pendingMfa`, rota `/api/auth/user` retorna `{mfaEnabled, mfaInvitationDismissed}`.
  - `server/routes/admin.ts` — rota `email-settings/test` grava `last_test_success_at` em sucesso; rota `PUT /api/auth/me/mfa-invitation-dismissed`.
- Cliente:
  - `client/src/App.tsx` — roteia `/mfa-challenge`, `/account`, `/account/mfa`; monta `<SetupAdminBanner>` e `<MfaInvitationGate>`.
  - `client/src/components/layout/sidebar.tsx` — remove bloco user-profile.
  - `client/src/components/layout/topbar.tsx` — adiciona `<UserMenu>`.
  - `client/src/pages/login.tsx` — lida com resposta `{ pendingMfa: true }`, navega para `/mfa-challenge`.

### Não alterados
- `server/services/emailService.ts` — reaproveitado pra enviar códigos por e-mail.
- `EncryptionService` — reaproveitado pra criptografar MFA secret.

## 9. Dependências novas

- `otplib` — TOTP/HOTP (RFC 6238).
- `qrcode` — geração de SVG inline pro QR.
- Nenhuma dependência de tipo `@types/...` adicional (ambas têm types inclusos).

Instalar com `npm install otplib qrcode && npm install -D @types/qrcode`.

## 10. Critérios de aceite

1. Login como `admin@samureye.local` mostra banner warning no topo; link "Gerenciar usuários" leva para `/users`.
2. Menu de conta no topbar funciona: dropdown mostra nome/email/role + links pros 3 destinos + Sair.
3. Sidebar não tem mais o bloco de user profile; versão (`v{x}`) permanece discreta no pé.
4. Login com user sem MFA mantém comportamento atual.
5. Modal de convite aparece após login fresco para user com `mfa_enabled=false` e `mfa_invitation_dismissed=false`.
6. Modal com "Não lembrar" marcada não reaparece em novos logins; acesso via Minha Conta > Gerenciar MFA continua funcionando.
7. Setup: QR é escaneável por Google Authenticator/Authy; token válido ativa MFA; 8 recovery codes são mostrados e podem ser copiados/baixados.
8. Login com MFA: tela `/mfa-challenge` exibida; TOTP correto promove sessão; TOTP errado dá erro; 5 erros → 423 Locked.
9. Recovery codes: qualquer dos 8 funciona uma vez; não funciona na segunda; resta 7 na lista.
10. Com `email_settings.last_test_success_at` recente, a tela `/mfa-challenge` mostra botão "Enviar por e-mail"; e-mail chega com código de 6 dígitos; código entra no mesmo input e promove sessão.
11. Regenerar recovery codes: senha + exibição de 8 novos; antigos invalidados imediatamente.
12. Desativar MFA: senha + TOTP; próximo login vai direto sem `/mfa-challenge`.
13. Middleware bloqueia APIs com 401 `{ mfaRequired: true }` quando `pendingMfa === true`.
14. `npm run check` sem novos erros; `npx vite build` OK.

## 11. Riscos e mitigações

- **Risco:** Usuário perde o celular E os códigos de recuperação.
  - **Mitigação:** Outro admin pode limpar os campos `mfa_*` na tabela `users` via SQL direto. Documentar no guia. (Um endpoint de "reset MFA de outro user" é tentador, mas cria superfície de ataque — fora do escopo.)
- **Risco:** `pendingMfa` persiste indefinidamente se o usuário fecha o browser.
  - **Mitigação:** Sessão expira pela configuração atual (sessionTimeout = 3600s). Nada a fazer.
- **Risco:** `last_test_success_at` fica velho e o usuário não percebe que o e-mail pode estar quebrado quando precisa recuperar.
  - **Mitigação:** O botão só aparece se `last_test_success_at ≤ 30 dias`. Fora disso, o user precisa re-testar em `/settings` → Mensageria.
- **Risco:** Criptografia do secret usa a mesma KEK da mensageria; se a KEK vazar, os secrets MFA também vazam.
  - **Mitigação:** Aceito — o atacante com acesso à KEK já tem acesso root ao appliance; MFA protege contra credential-stuffing, não contra compromisso do host.
- **Risco:** Bcrypt (cost 10) em 8 códigos + 1 challenge ativo pode somar ~800ms em cada verificação no pior caso.
  - **Mitigação:** Cost 10 é padrão sane. A verificação só roda no login/challenge, não em rotas de API. Aceito.

## 12. Fora de escopo

- WebAuthn, SMS, hardware keys, push notifications.
- Enforcement de MFA por role / política ("admin deve ter MFA").
- Recovery via e-mail sem MFA já configurado.
- Reset de MFA de outro usuário pela UI (só via SQL manual).
- Branding do e-mail de código (template mínimo em pt-BR).
