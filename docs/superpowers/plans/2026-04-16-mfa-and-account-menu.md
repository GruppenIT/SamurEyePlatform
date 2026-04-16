# MFA + Menu de Conta + Banner Admin — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship TOTP-based MFA (with 8 recovery codes, email delivery as an alternative, first-login invitation, and "don't remind again"), move the user profile to a topbar dropdown with account actions, and show a warning banner when logged in as the setup-only admin (`admin@samureye.local`).

**Architecture:** Backend adds `otplib` + `qrcode`, extends `users` with MFA columns, adds `mfa_email_challenges` table and `email_settings.last_test_success_at`. Login flow is two-step when `mfa_enabled`: password sets `req.session.pendingMfa = true`; `isAuthenticated` blocks all `/api/*` except an allowlist until `POST /api/auth/mfa/verify` succeeds. Frontend replaces the sidebar user block with a topbar shadcn `DropdownMenu`, adds `/account`, `/account/mfa`, `/mfa-challenge` pages, an invitation modal, and a warning banner mounted globally in `App.tsx`.

**Tech Stack:** `otplib` (TOTP RFC 6238), `qrcode` (SVG), Drizzle (schema + push), bcrypt (recovery code hashing — already a dep), shadcn/ui primitives (Avatar, DropdownMenu, AlertDialog, Dialog, Input, Button).

**Spec:** `docs/superpowers/specs/2026-04-16-mfa-and-account-menu-design.md`.

**Verification approach:** `npm run check` (pre-existing `useAuth` errors baseline) + `npx vite build` + `vitest run` for the one new MfaService test. End-to-end QA runs against the production service after `deploy-samureye`.

---

## File Structure

| Path | Action | Responsibility |
| --- | --- | --- |
| `package.json` | Modify | Add `otplib`, `qrcode` + `@types/qrcode` (dev) |
| `shared/schema.ts` | Modify | Users MFA columns, `mfa_email_challenges` table, `email_settings.last_test_success_at`, types |
| `server/storage/users.ts` | Modify | Helpers: `getUserMfa`, `setUserMfa`, `consumeBackupCode`, `dismissMfaInvitation` |
| `server/storage/mfa.ts` | Create | CRUD for `mfa_email_challenges` |
| `server/storage/index.ts` | Modify | Wire new helpers |
| `server/storage/interface.ts` | Modify | Add interface methods |
| `server/services/mfaService.ts` | Create | `otplib` wrappers + recovery code gen + email code verification |
| `server/__tests__/mfaService.test.ts` | Create | Vitest for MfaService core paths |
| `server/localAuth.ts` | Modify | Login returns `pendingMfa`; `isAuthenticated` allowlist |
| `server/routes/auth-mfa.ts` | Create | All `/api/auth/mfa/*` routes |
| `server/routes/index.ts` | Modify | Register auth-mfa routes |
| `server/routes/admin.ts` | Modify | `/api/email-settings/test` persists `last_test_success_at`; `PUT /api/auth/me/mfa-invitation-dismissed` |
| `client/src/components/account/user-menu.tsx` | Create | Topbar dropdown |
| `client/src/components/account/mfa-invitation-dialog.tsx` | Create | First-login modal |
| `client/src/components/layout/setup-admin-banner.tsx` | Create | Warning banner |
| `client/src/components/layout/sidebar.tsx` | Modify | Remove user-profile block |
| `client/src/components/layout/topbar.tsx` | Modify | Mount `<UserMenu>` |
| `client/src/pages/account.tsx` | Create | Minha Conta index |
| `client/src/pages/account-mfa.tsx` | Create | MFA setup + manage |
| `client/src/pages/mfa-challenge.tsx` | Create | TOTP input after password |
| `client/src/pages/login.tsx` | Modify | Handle `{ pendingMfa: true }` response |
| `client/src/App.tsx` | Modify | Register new routes, mount banner + invitation dialog |

---

## Task 1: Install `otplib` and `qrcode`

**Files:** `package.json`, `package-lock.json`.

- [ ] **Step 1: Install**

```bash
cd /opt/samureye && npm install otplib qrcode && npm install -D @types/qrcode
```

- [ ] **Step 2: Verify**

```bash
grep -E '"otplib"|"qrcode"|"@types/qrcode"' package.json
```
Expected: three lines showing the installed versions.

- [ ] **Step 3: Commit**

```bash
git add package.json package-lock.json
git commit -m "chore(deps): add otplib and qrcode for MFA"
```

---

## Task 2: Schema changes

**Files:** `shared/schema.ts`.

- [ ] **Step 1: Extend `users` table**

Find `export const users = pgTable("users", {` (line ~79) and add five new columns before the closing `});`. The block becomes (only the additions are shown in order — keep existing fields intact above `lastLogin`):

```ts
  mustChangePassword: boolean("must_change_password").default(false).notNull(),
  // MFA (TOTP) fields
  mfaEnabled: boolean("mfa_enabled").default(false).notNull(),
  mfaSecretEncrypted: text("mfa_secret_encrypted"),
  mfaSecretDek: text("mfa_secret_dek"),
  mfaBackupCodes: text("mfa_backup_codes").array(),
  mfaEnabledAt: timestamp("mfa_enabled_at"),
  mfaInvitationDismissed: boolean("mfa_invitation_dismissed").default(false).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
```

(The `mfaEnabled`, `mfaSecretEncrypted`, `mfaSecretDek`, `mfaBackupCodes`, `mfaEnabledAt`, `mfaInvitationDismissed` are the five new rows. Leave `createdAt`, `updatedAt`, `lastLogin` where they are.)

- [ ] **Step 2: Extend `email_settings`**

Find `export const emailSettings = pgTable("email_settings", {` (line ~472) and add a new field right before the closing `});`:

```ts
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
  updatedBy: varchar("updated_by").references(() => users.id).notNull(),
  lastTestSuccessAt: timestamp("last_test_success_at"),
});
```

- [ ] **Step 3: Add `mfa_email_challenges` table**

At the end of the file, BEFORE the `// ═══════════════════════════════════════════════════════════\n// Schema exports / Zod schemas` block (or immediately after the last `pgTable(...)` declaration — scan for the last `export const X = pgTable`), insert:

```ts
export const mfaEmailChallenges = pgTable("mfa_email_challenges", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").references(() => users.id, { onDelete: 'cascade' }).notNull(),
  codeHash: text("code_hash").notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  consumedAt: timestamp("consumed_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
}, (table) => [
  index("idx_mfa_email_challenges_user_active").on(table.userId, table.expiresAt),
]);

export type MfaEmailChallenge = typeof mfaEmailChallenges.$inferSelect;
export type InsertMfaEmailChallenge = typeof mfaEmailChallenges.$inferInsert;
```

If `index` is not imported, add it to the existing `drizzle-orm/pg-core` import at the top of the file (search for `import { pgTable,`).

- [ ] **Step 4: Hide MFA secrets from selectable Zod schema**

Find the `createSelectSchema(users)` or `selectUserSchema` — specifically the `.omit({ passwordHash: true, mustChangePassword: true, ... })` call around line 695. Extend it:

```ts
  passwordHash: true,
  mustChangePassword: true,
  mfaSecretEncrypted: true,
  mfaSecretDek: true,
  mfaBackupCodes: true,
```

(Add the three new lines; keep existing omissions.)

- [ ] **Step 5: Push schema to database**

```bash
cd /opt/samureye && npm run db:push
```
Expected: drizzle-kit reports the ALTER TABLE and CREATE TABLE statements and applies them without errors.

- [ ] **Step 6: Verify DB state**

```bash
set -a && . ./.env && set +a && psql "$DATABASE_URL" -c "\d users" | grep -E "mfa|password"
psql "$DATABASE_URL" -c "\d email_settings" | grep last_test
psql "$DATABASE_URL" -c "\d mfa_email_challenges"
```
Expected: the columns exist and the new table is present.

- [ ] **Step 7: Type-check**

```bash
npm run check 2>&1 | grep "shared/schema" | head
```
Expected: no lines (pre-existing errors elsewhere remain untouched).

- [ ] **Step 8: Commit**

```bash
git add shared/schema.ts
git commit -m "feat(schema): add MFA columns, email_settings.last_test_success_at, mfa_email_challenges"
```

---

## Task 3: Storage helpers — users MFA

**Files:** `server/storage/users.ts`, `server/storage/interface.ts`, `server/storage/index.ts`.

- [ ] **Step 1: Add helpers to `server/storage/users.ts`**

Append at the end of the file (after the last existing export):

```ts
export async function getUserMfa(id: string): Promise<Pick<User, 'id' | 'email' | 'mfaEnabled' | 'mfaSecretEncrypted' | 'mfaSecretDek' | 'mfaBackupCodes' | 'mfaInvitationDismissed' | 'mfaEnabledAt'> | undefined> {
  const [row] = await db
    .select({
      id: users.id,
      email: users.email,
      mfaEnabled: users.mfaEnabled,
      mfaSecretEncrypted: users.mfaSecretEncrypted,
      mfaSecretDek: users.mfaSecretDek,
      mfaBackupCodes: users.mfaBackupCodes,
      mfaInvitationDismissed: users.mfaInvitationDismissed,
      mfaEnabledAt: users.mfaEnabledAt,
    })
    .from(users)
    .where(eq(users.id, id));
  return row;
}

export async function setUserMfa(
  id: string,
  data: {
    mfaEnabled: boolean;
    mfaSecretEncrypted: string | null;
    mfaSecretDek: string | null;
    mfaBackupCodes: string[] | null;
    mfaEnabledAt: Date | null;
  },
): Promise<void> {
  await db
    .update(users)
    .set({
      mfaEnabled: data.mfaEnabled,
      mfaSecretEncrypted: data.mfaSecretEncrypted,
      mfaSecretDek: data.mfaSecretDek,
      mfaBackupCodes: data.mfaBackupCodes,
      mfaEnabledAt: data.mfaEnabledAt,
      updatedAt: new Date(),
    })
    .where(eq(users.id, id));
}

export async function updateBackupCodes(id: string, codes: string[]): Promise<void> {
  await db
    .update(users)
    .set({ mfaBackupCodes: codes, updatedAt: new Date() })
    .where(eq(users.id, id));
}

export async function dismissMfaInvitation(id: string): Promise<void> {
  await db
    .update(users)
    .set({ mfaInvitationDismissed: true, updatedAt: new Date() })
    .where(eq(users.id, id));
}
```

- [ ] **Step 2: Extend interface**

In `server/storage/interface.ts`, search for the `// User operations` section and add to the interface:

```ts
  getUserMfa(id: string): Promise<Pick<User, 'id' | 'email' | 'mfaEnabled' | 'mfaSecretEncrypted' | 'mfaSecretDek' | 'mfaBackupCodes' | 'mfaInvitationDismissed' | 'mfaEnabledAt'> | undefined>;
  setUserMfa(id: string, data: { mfaEnabled: boolean; mfaSecretEncrypted: string | null; mfaSecretDek: string | null; mfaBackupCodes: string[] | null; mfaEnabledAt: Date | null }): Promise<void>;
  updateBackupCodes(id: string, codes: string[]): Promise<void>;
  dismissMfaInvitation(id: string): Promise<void>;
```

- [ ] **Step 3: Wire into storage index**

In `server/storage/index.ts`, add to the user-ops block:

```ts
  getUserMfa = userOps.getUserMfa;
  setUserMfa = userOps.setUserMfa;
  updateBackupCodes = userOps.updateBackupCodes;
  dismissMfaInvitation = userOps.dismissMfaInvitation;
```

- [ ] **Step 4: Type-check**

```bash
npm run check 2>&1 | grep "storage/users\|storage/index\|storage/interface" | head
```
Expected: no lines.

- [ ] **Step 5: Commit**

```bash
git add server/storage/users.ts server/storage/interface.ts server/storage/index.ts
git commit -m "feat(storage): add MFA helpers for users"
```

---

## Task 4: Storage helpers — mfa_email_challenges

**Files:** `server/storage/mfa.ts`, `server/storage/interface.ts`, `server/storage/index.ts`.

- [ ] **Step 1: Create `server/storage/mfa.ts`**

```ts
import { db } from "../db";
import { and, eq, gt, isNull, lt, or } from "drizzle-orm";
import { mfaEmailChallenges } from "@shared/schema";
import type { MfaEmailChallenge, InsertMfaEmailChallenge } from "@shared/schema";

export async function createMfaEmailChallenge(data: InsertMfaEmailChallenge): Promise<MfaEmailChallenge> {
  const [row] = await db.insert(mfaEmailChallenges).values(data).returning();
  return row;
}

export async function getActiveChallenges(userId: string): Promise<MfaEmailChallenge[]> {
  const now = new Date();
  return db
    .select()
    .from(mfaEmailChallenges)
    .where(and(
      eq(mfaEmailChallenges.userId, userId),
      isNull(mfaEmailChallenges.consumedAt),
      gt(mfaEmailChallenges.expiresAt, now),
    ));
}

export async function consumeChallenge(id: string): Promise<void> {
  await db
    .update(mfaEmailChallenges)
    .set({ consumedAt: new Date() })
    .where(eq(mfaEmailChallenges.id, id));
}

export async function countRecentChallenges(userId: string, sinceMs: number): Promise<number> {
  const since = new Date(Date.now() - sinceMs);
  const rows = await db
    .select({ id: mfaEmailChallenges.id })
    .from(mfaEmailChallenges)
    .where(and(
      eq(mfaEmailChallenges.userId, userId),
      gt(mfaEmailChallenges.createdAt, since),
    ));
  return rows.length;
}

export async function cleanupOldChallenges(userId: string): Promise<void> {
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24h
  await db
    .delete(mfaEmailChallenges)
    .where(and(
      eq(mfaEmailChallenges.userId, userId),
      or(
        lt(mfaEmailChallenges.expiresAt, cutoff),
        lt(mfaEmailChallenges.createdAt, cutoff),
      ),
    ));
}
```

- [ ] **Step 2: Extend interface**

In `server/storage/interface.ts`, add a new section:

```ts
  // MFA email challenges
  createMfaEmailChallenge(data: InsertMfaEmailChallenge): Promise<MfaEmailChallenge>;
  getActiveChallenges(userId: string): Promise<MfaEmailChallenge[]>;
  consumeChallenge(id: string): Promise<void>;
  countRecentChallenges(userId: string, sinceMs: number): Promise<number>;
  cleanupOldChallenges(userId: string): Promise<void>;
```

Ensure the `MfaEmailChallenge` and `InsertMfaEmailChallenge` types are imported at the top of `interface.ts` from `@shared/schema`.

- [ ] **Step 3: Wire into storage index**

In `server/storage/index.ts`, add a new import and block:

```ts
import * as mfaOps from "./mfa";
```

Inside the class:

```ts
  createMfaEmailChallenge = mfaOps.createMfaEmailChallenge;
  getActiveChallenges = mfaOps.getActiveChallenges;
  consumeChallenge = mfaOps.consumeChallenge;
  countRecentChallenges = mfaOps.countRecentChallenges;
  cleanupOldChallenges = mfaOps.cleanupOldChallenges;
```

- [ ] **Step 4: Type-check**

```bash
npm run check 2>&1 | grep "storage/mfa\|storage/index\|storage/interface" | head
```

- [ ] **Step 5: Commit**

```bash
git add server/storage/mfa.ts server/storage/interface.ts server/storage/index.ts
git commit -m "feat(storage): add helpers for mfa_email_challenges"
```

---

## Task 5: MfaService

**Files:** `server/services/mfaService.ts`.

- [ ] **Step 1: Create the service**

```ts
import { authenticator } from 'otplib';
import bcrypt from 'bcryptjs';
import QRCode from 'qrcode';
import crypto from 'crypto';
import { encryptionService } from './encryption';
import { storage } from '../storage';
import { createLogger } from '../lib/logger';

const log = createLogger('mfa');

const TOTP_WINDOW = 1; // accept tokens ±30s from now
const BACKUP_CODE_COUNT = 8;
const BACKUP_CODE_BYTES = 8; // 16 hex chars → trimmed to 10
const EMAIL_CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5min
const EMAIL_CHALLENGE_RATE_LIMIT_MS = 5 * 60 * 1000;
const EMAIL_CHALLENGE_RATE_LIMIT_MAX = 3;
const BCRYPT_COST = 10;

authenticator.options = { window: TOTP_WINDOW };

export interface SetupPayload {
  secret: string;
  otpauthUrl: string;
  qrCodeSvg: string;
  backupCodes: string[];        // plaintext, show once
  backupCodeHashes: string[];   // to stash in session
}

export class MfaService {
  async generateSetup(userEmail: string): Promise<SetupPayload> {
    const secret = authenticator.generateSecret();
    const otpauthUrl = authenticator.keyuri(userEmail, 'SamurEye', secret);
    const qrCodeSvg = await QRCode.toString(otpauthUrl, { type: 'svg', margin: 1, width: 240 });
    const backupCodes = Array.from({ length: BACKUP_CODE_COUNT }, () => this.generateBackupCode());
    const backupCodeHashes = await Promise.all(
      backupCodes.map((code) => bcrypt.hash(code, BCRYPT_COST)),
    );
    return { secret, otpauthUrl, qrCodeSvg, backupCodes, backupCodeHashes };
  }

  private generateBackupCode(): string {
    return crypto.randomBytes(BACKUP_CODE_BYTES).toString('hex').slice(0, 10);
  }

  verifyTotp(token: string, secret: string): boolean {
    if (!/^\d{6}$/.test(token)) return false;
    try {
      return authenticator.verify({ token, secret });
    } catch {
      return false;
    }
  }

  async verifyBackupCode(token: string, hashes: string[]): Promise<{ matchIndex: number }> {
    for (let i = 0; i < hashes.length; i++) {
      if (await bcrypt.compare(token, hashes[i])) {
        return { matchIndex: i };
      }
    }
    return { matchIndex: -1 };
  }

  encryptSecret(secret: string): { encrypted: string; dek: string } {
    const { secretEncrypted, dekEncrypted } = encryptionService.encryptCredential(secret);
    return { encrypted: secretEncrypted, dek: dekEncrypted };
  }

  decryptSecret(encrypted: string, dek: string): string {
    return encryptionService.decryptCredential(encrypted, dek);
  }

  // Email-delivered challenge
  async createEmailChallenge(userId: string): Promise<{ code: string }> {
    const recent = await storage.countRecentChallenges(userId, EMAIL_CHALLENGE_RATE_LIMIT_MS);
    if (recent >= EMAIL_CHALLENGE_RATE_LIMIT_MAX) {
      throw new Error('Limite de envios por e-mail atingido. Aguarde 5 minutos.');
    }
    await storage.cleanupOldChallenges(userId);
    const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
    const codeHash = await bcrypt.hash(code, BCRYPT_COST);
    const expiresAt = new Date(Date.now() + EMAIL_CHALLENGE_TTL_MS);
    await storage.createMfaEmailChallenge({ userId, codeHash, expiresAt });
    return { code };
  }

  async verifyEmailChallenge(userId: string, token: string): Promise<boolean> {
    const active = await storage.getActiveChallenges(userId);
    for (const ch of active) {
      if (await bcrypt.compare(token, ch.codeHash)) {
        await storage.consumeChallenge(ch.id);
        return true;
      }
    }
    return false;
  }
}

export const mfaService = new MfaService();
```

- [ ] **Step 2: Type-check**

```bash
npm run check 2>&1 | grep "mfaService" | head
```
Expected: no lines.

- [ ] **Step 3: Commit**

```bash
git add server/services/mfaService.ts
git commit -m "feat(mfa): add MfaService for TOTP/backup codes/email challenges"
```

---

## Task 6: Vitest for MfaService

**Files:** `server/__tests__/mfaService.test.ts`.

- [ ] **Step 1: Create the test file**

```ts
import { describe, it, expect } from 'vitest';
import { MfaService } from '../services/mfaService';
import { authenticator } from 'otplib';
import bcrypt from 'bcryptjs';

describe('MfaService', () => {
  const svc = new MfaService();

  describe('generateSetup', () => {
    it('produces a secret, otpauth URL, SVG QR and 8 backup codes', async () => {
      const out = await svc.generateSetup('user@example.com');
      expect(out.secret).toMatch(/^[A-Z2-7]+$/);
      expect(out.otpauthUrl).toContain('otpauth://totp/');
      expect(out.otpauthUrl).toContain('SamurEye');
      expect(out.otpauthUrl).toContain('user%40example.com');
      expect(out.qrCodeSvg).toContain('<svg');
      expect(out.backupCodes).toHaveLength(8);
      expect(out.backupCodeHashes).toHaveLength(8);
      for (const c of out.backupCodes) {
        expect(c).toMatch(/^[a-f0-9]{10}$/);
      }
    });
  });

  describe('verifyTotp', () => {
    it('accepts a valid token and rejects an invalid one', async () => {
      const { secret } = await svc.generateSetup('u@e.com');
      const valid = authenticator.generate(secret);
      expect(svc.verifyTotp(valid, secret)).toBe(true);
      expect(svc.verifyTotp('000000', secret)).toBe(false);
      expect(svc.verifyTotp('notadigit', secret)).toBe(false);
      expect(svc.verifyTotp('12345', secret)).toBe(false);
    });
  });

  describe('verifyBackupCode', () => {
    it('returns matching index for a known code and -1 otherwise', async () => {
      const codes = ['aaaaaaaaaa', 'bbbbbbbbbb', 'cccccccccc'];
      const hashes = await Promise.all(codes.map((c) => bcrypt.hash(c, 10)));
      const ok = await svc.verifyBackupCode('bbbbbbbbbb', hashes);
      expect(ok.matchIndex).toBe(1);
      const miss = await svc.verifyBackupCode('zzzzzzzzzz', hashes);
      expect(miss.matchIndex).toBe(-1);
    });
  });

  describe('encrypt/decrypt secret round trip', () => {
    it('restores the original secret', () => {
      const { secret } = authenticator.generateSecret ? { secret: authenticator.generateSecret() } : { secret: 'JBSWY3DPEHPK3PXP' };
      const { encrypted, dek } = svc.encryptSecret(secret);
      expect(encrypted).not.toBe(secret);
      expect(dek).toBeTruthy();
      expect(svc.decryptSecret(encrypted, dek)).toBe(secret);
    });
  });
});
```

- [ ] **Step 2: Run the tests**

```bash
cd /opt/samureye && npx vitest run server/__tests__/mfaService.test.ts
```
Expected: `4 passed`.

- [ ] **Step 3: Commit**

```bash
git add server/__tests__/mfaService.test.ts
git commit -m "test(mfa): cover MfaService core paths"
```

---

## Task 7: Login handler — detect mfa_enabled, set pendingMfa

**Files:** `server/localAuth.ts` (the passport callback, lines ~423-500).

- [ ] **Step 1: Modify the post-password success block**

In `server/localAuth.ts`, find `passport.authenticate('local', async (err: any, user: any, info: any) => {` around line 423. The block that executes after `req.session.regenerate` and `req.logIn` currently calls `res.json({ message: 'Login realizado com sucesso', user: {...} })`. Replace the `res.json(...)` call with a branch:

Locate (line ~486):

```ts
          res.json({ 
            message: 'Login realizado com sucesso',
            user: {
              id: user.id,
              email: user.email,
              firstName: user.firstName,
              lastName: user.lastName,
              role: user.role,
              mustChangePassword: user.mustChangePassword
            }
          });
```

Replace with:

```ts
          if (user.mfaEnabled) {
            (req.session as any).pendingMfa = true;
            (req.session as any).mfaUserId = user.id;
            const emailSettings = await storage.getEmailSettings();
            const emailDeliveryAvailable =
              !!emailSettings?.lastTestSuccessAt &&
              emailSettings.lastTestSuccessAt > new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
            return req.session.save(() => {
              res.json({ pendingMfa: true, emailDeliveryAvailable });
            });
          }
          res.json({
            message: 'Login realizado com sucesso',
            user: {
              id: user.id,
              email: user.email,
              firstName: user.firstName,
              lastName: user.lastName,
              role: user.role,
              mustChangePassword: user.mustChangePassword,
              mfaEnabled: user.mfaEnabled,
              mfaInvitationDismissed: user.mfaInvitationDismissed,
            }
          });
```

- [ ] **Step 2: Type-check**

```bash
npm run check 2>&1 | grep "localAuth" | grep -v "Property 'role'" | head
```

- [ ] **Step 3: Commit**

```bash
git add server/localAuth.ts
git commit -m "feat(auth): emit pendingMfa instead of user on password-ok when MFA enabled"
```

---

## Task 8: isAuthenticated middleware — allowlist for pendingMfa

**Files:** `server/localAuth.ts` (the `isAuthenticated` export at line ~684).

- [ ] **Step 1: Replace the middleware**

Replace:

```ts
export const isAuthenticated: RequestHandler = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ message: "Não autorizado" });
};
```

With:

```ts
const PENDING_MFA_ALLOWLIST = new Set<string>([
  '/api/auth/mfa/verify',
  '/api/auth/mfa/email',
  '/api/auth/logout',
  '/api/auth/user',
]);

export const isAuthenticated: RequestHandler = (req, res, next) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: "Não autorizado" });
  }
  const pendingMfa = (req.session as any).pendingMfa === true;
  if (pendingMfa && !PENDING_MFA_ALLOWLIST.has(req.path)) {
    return res.status(401).json({ message: "MFA requerido", mfaRequired: true });
  }
  return next();
};
```

- [ ] **Step 2: Update `/api/auth/user` to short-circuit when pendingMfa**

Find the handler around line 563 (`app.get('/api/auth/user', isAuthenticated, ...`). Before returning the full user object, add at the top of the handler:

```ts
    if ((req.session as any).pendingMfa === true) {
      return res.json({ pendingMfa: true });
    }
```

Also, when returning the user object, include MFA flags:

```ts
    res.json({
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      role: user.role,
      mustChangePassword: user.mustChangePassword,
      mfaEnabled: user.mfaEnabled,
      mfaInvitationDismissed: user.mfaInvitationDismissed,
      lastLogin: user.lastLogin,
    });
```

(Adapt to whatever shape the handler already returns — add the two new fields.)

- [ ] **Step 3: Type-check**

```bash
npm run check 2>&1 | grep "localAuth" | grep -v "Property 'role'" | head
```

- [ ] **Step 4: Commit**

```bash
git add server/localAuth.ts
git commit -m "feat(auth): allowlist MFA routes while pendingMfa; expose MFA flags on /auth/user"
```

---

## Task 9: Rate limit helper for MFA

**Files:** `server/localAuth.ts` (existing rate limit helpers around lines 60-90).

- [ ] **Step 1: No code change required**

The existing `isRateLimited` and `recordLoginAttempt` helpers are keyed by an arbitrary string. Task 10's routes will use `mfa:${userId}` as the key — no modification needed here.

- [ ] **Step 2: Mark complete (no commit)**

Skip commit; proceed to Task 10.

---

## Task 10: MFA routes

**Files:** `server/routes/auth-mfa.ts` (create), `server/routes/index.ts` (register).

- [ ] **Step 1: Create the routes file**

```ts
import type { Express } from "express";
import bcrypt from "bcryptjs";
import { storage } from "../storage";
import { isAuthenticated, verifyPassword } from "../localAuth";
import { mfaService } from "../services/mfaService";
import { emailService } from "../services/emailService";
import { createLogger } from "../lib/logger";

const log = createLogger('routes:auth-mfa');

const MFA_RATE_LIMIT_MAX = 5;
const MFA_RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;

async function isMfaRateLimited(userId: string): Promise<boolean> {
  const attempt = await storage.getLoginAttempt(`mfa:${userId}`);
  if (!attempt) return false;
  if (attempt.blockedUntil && new Date() < attempt.blockedUntil) return true;
  return false;
}

async function recordMfaAttempt(userId: string, success: boolean): Promise<void> {
  if (success) {
    await storage.resetLoginAttempts(`mfa:${userId}`);
    return;
  }
  const attempt = await storage.getLoginAttempt(`mfa:${userId}`);
  const count = (attempt?.count ?? 0) + 1;
  const blockedUntil = count >= MFA_RATE_LIMIT_MAX
    ? new Date(Date.now() + MFA_RATE_LIMIT_WINDOW_MS)
    : null;
  await storage.recordLoginAttempt(`mfa:${userId}`, { count, blockedUntil });
}

export function registerAuthMfaRoutes(app: Express) {
  // POST /api/auth/mfa/setup — generate secret + QR + 8 backup codes (stash in session)
  app.post('/api/auth/mfa/setup', isAuthenticated, async (req: any, res) => {
    try {
      const user = req.user;
      if (user.mfaEnabled) {
        return res.status(400).json({ message: "MFA já está ativado" });
      }
      const setup = await mfaService.generateSetup(user.email);
      req.session.pendingMfaSecret = setup.secret;
      req.session.pendingMfaBackupHashes = setup.backupCodeHashes;
      req.session.save(() => {
        res.json({
          otpauthUrl: setup.otpauthUrl,
          qrCodeSvg: setup.qrCodeSvg,
          backupCodes: setup.backupCodes,
        });
      });
    } catch (error) {
      log.error({ err: error }, 'mfa setup failed');
      res.status(500).json({ message: "Falha ao preparar MFA" });
    }
  });

  // POST /api/auth/mfa/enable — validate token against pending secret, persist
  app.post('/api/auth/mfa/enable', isAuthenticated, async (req: any, res) => {
    try {
      const user = req.user;
      const token = String(req.body?.token ?? '').trim();
      const pendingSecret = req.session.pendingMfaSecret;
      const pendingHashes = req.session.pendingMfaBackupHashes;
      if (!pendingSecret || !Array.isArray(pendingHashes) || pendingHashes.length !== 8) {
        return res.status(400).json({ message: "Setup de MFA não iniciado. Recarregue a página." });
      }
      if (!mfaService.verifyTotp(token, pendingSecret)) {
        return res.status(400).json({ message: "Código TOTP inválido" });
      }
      const { encrypted, dek } = mfaService.encryptSecret(pendingSecret);
      await storage.setUserMfa(user.id, {
        mfaEnabled: true,
        mfaSecretEncrypted: encrypted,
        mfaSecretDek: dek,
        mfaBackupCodes: pendingHashes,
        mfaEnabledAt: new Date(),
      });
      delete req.session.pendingMfaSecret;
      delete req.session.pendingMfaBackupHashes;
      await storage.logAudit({
        actorId: user.id,
        action: 'user.mfa.enable',
        objectType: 'user',
        objectId: user.id,
        before: null,
        after: { mfaEnabled: true },
      });
      req.session.save(() => res.json({ success: true }));
    } catch (error) {
      log.error({ err: error }, 'mfa enable failed');
      res.status(500).json({ message: "Falha ao ativar MFA" });
    }
  });

  // POST /api/auth/mfa/verify — promote pendingMfa session, or validate for disable/regen
  app.post('/api/auth/mfa/verify', async (req: any, res) => {
    try {
      const userId = (req.session as any).mfaUserId || req.user?.id;
      if (!userId) return res.status(401).json({ message: "Sessão inválida" });
      if (await isMfaRateLimited(userId)) {
        return res.status(423).json({ message: "Muitas tentativas. Aguarde 15 minutos." });
      }
      const token = String(req.body?.token ?? '').trim();
      if (!token) return res.status(400).json({ message: "Código obrigatório" });

      const mfa = await storage.getUserMfa(userId);
      if (!mfa || !mfa.mfaEnabled || !mfa.mfaSecretEncrypted || !mfa.mfaSecretDek) {
        return res.status(400).json({ message: "MFA não configurado" });
      }

      // 1) email challenge
      if (await mfaService.verifyEmailChallenge(userId, token)) {
        await recordMfaAttempt(userId, true);
        (req.session as any).pendingMfa = false;
        delete (req.session as any).mfaUserId;
        return req.session.save(() => res.json({ success: true }));
      }

      // 2) TOTP
      const secret = mfaService.decryptSecret(mfa.mfaSecretEncrypted, mfa.mfaSecretDek);
      if (mfaService.verifyTotp(token, secret)) {
        await recordMfaAttempt(userId, true);
        (req.session as any).pendingMfa = false;
        delete (req.session as any).mfaUserId;
        return req.session.save(() => res.json({ success: true }));
      }

      // 3) backup code
      const hashes = mfa.mfaBackupCodes ?? [];
      const { matchIndex } = await mfaService.verifyBackupCode(token, hashes);
      if (matchIndex >= 0) {
        const remaining = hashes.filter((_, i) => i !== matchIndex);
        await storage.updateBackupCodes(userId, remaining);
        await recordMfaAttempt(userId, true);
        (req.session as any).pendingMfa = false;
        delete (req.session as any).mfaUserId;
        return req.session.save(() => res.json({ success: true, backupCodeUsed: true, remaining: remaining.length }));
      }

      await recordMfaAttempt(userId, false);
      res.status(401).json({ message: "Código inválido" });
    } catch (error) {
      log.error({ err: error }, 'mfa verify failed');
      res.status(500).json({ message: "Falha ao validar código" });
    }
  });

  // POST /api/auth/mfa/email — send 6-digit code via email
  app.post('/api/auth/mfa/email', async (req: any, res) => {
    try {
      const userId = (req.session as any).mfaUserId || req.user?.id;
      if (!userId) return res.status(401).json({ message: "Sessão inválida" });
      const mfa = await storage.getUserMfa(userId);
      if (!mfa || !mfa.mfaEnabled) {
        return res.status(400).json({ message: "MFA não ativado" });
      }
      const emailSettings = await storage.getEmailSettings();
      const windowCutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      if (!emailSettings?.lastTestSuccessAt || emailSettings.lastTestSuccessAt < windowCutoff) {
        return res.status(400).json({ message: "Mensageria não foi testada recentemente" });
      }
      const { code } = await mfaService.createEmailChallenge(userId);
      await emailService.sendEmail(emailSettings, {
        to: mfa.email,
        subject: 'Código de verificação SamurEye',
        html: `
          <p>Seu código de verificação é:</p>
          <p style="font-size:24px;font-weight:bold;letter-spacing:4px">${code}</p>
          <p>Válido por 5 minutos. Se você não solicitou, ignore este e-mail.</p>
        `,
      });
      res.status(202).json({ message: "Código enviado" });
    } catch (error: any) {
      log.error({ err: error }, 'mfa email send failed');
      res.status(error?.message?.includes('Limite') ? 429 : 500).json({
        message: error?.message || "Falha ao enviar código",
      });
    }
  });

  // POST /api/auth/mfa/disable — requires password + current TOTP
  app.post('/api/auth/mfa/disable', isAuthenticated, async (req: any, res) => {
    try {
      const user = req.user;
      if (!user.mfaEnabled) return res.status(400).json({ message: "MFA não está ativado" });
      const { currentPassword, token } = req.body ?? {};
      if (!(await verifyPassword(String(currentPassword ?? ''), user.passwordHash))) {
        return res.status(401).json({ message: "Senha incorreta" });
      }
      const mfa = await storage.getUserMfa(user.id);
      if (!mfa?.mfaSecretEncrypted || !mfa?.mfaSecretDek) {
        return res.status(400).json({ message: "MFA em estado inválido" });
      }
      const secret = mfaService.decryptSecret(mfa.mfaSecretEncrypted, mfa.mfaSecretDek);
      if (!mfaService.verifyTotp(String(token ?? ''), secret)) {
        return res.status(401).json({ message: "TOTP inválido" });
      }
      await storage.setUserMfa(user.id, {
        mfaEnabled: false,
        mfaSecretEncrypted: null,
        mfaSecretDek: null,
        mfaBackupCodes: null,
        mfaEnabledAt: null,
      });
      await storage.logAudit({
        actorId: user.id,
        action: 'user.mfa.disable',
        objectType: 'user',
        objectId: user.id,
        before: { mfaEnabled: true },
        after: { mfaEnabled: false },
      });
      res.json({ success: true });
    } catch (error) {
      log.error({ err: error }, 'mfa disable failed');
      res.status(500).json({ message: "Falha ao desativar MFA" });
    }
  });

  // POST /api/auth/mfa/recovery-codes/regenerate — password + regen
  app.post('/api/auth/mfa/recovery-codes/regenerate', isAuthenticated, async (req: any, res) => {
    try {
      const user = req.user;
      if (!user.mfaEnabled) return res.status(400).json({ message: "MFA não está ativado" });
      const currentPassword = String(req.body?.currentPassword ?? '');
      if (!(await verifyPassword(currentPassword, user.passwordHash))) {
        return res.status(401).json({ message: "Senha incorreta" });
      }
      const setup = await mfaService.generateSetup(user.email); // only uses backup codes; secret discarded
      await storage.updateBackupCodes(user.id, setup.backupCodeHashes);
      await storage.logAudit({
        actorId: user.id,
        action: 'user.mfa.backupcodes.regenerate',
        objectType: 'user',
        objectId: user.id,
        before: null,
        after: { count: setup.backupCodes.length },
      });
      res.json({ backupCodes: setup.backupCodes });
    } catch (error) {
      log.error({ err: error }, 'mfa regenerate failed');
      res.status(500).json({ message: "Falha ao regenerar códigos" });
    }
  });

  // PUT /api/auth/me/mfa-invitation-dismissed
  app.put('/api/auth/me/mfa-invitation-dismissed', isAuthenticated, async (req: any, res) => {
    try {
      await storage.dismissMfaInvitation(req.user.id);
      res.json({ success: true });
    } catch (error) {
      log.error({ err: error }, 'dismiss mfa invitation failed');
      res.status(500).json({ message: "Falha ao salvar preferência" });
    }
  });
}
```

- [ ] **Step 2: Register in `server/routes/index.ts`**

Add import and call:

```ts
import { registerAuthMfaRoutes } from "./auth-mfa";
```

Inside `registerRoutes`, near the other `register*` calls:

```ts
  registerAuthMfaRoutes(app);
```

- [ ] **Step 3: Type-check**

```bash
npm run check 2>&1 | grep "auth-mfa\|routes/index" | head
```

- [ ] **Step 4: Commit**

```bash
git add server/routes/auth-mfa.ts server/routes/index.ts
git commit -m "feat(auth): add MFA routes (setup/enable/verify/email/disable/regenerate/dismiss)"
```

---

## Task 11: Persist `last_test_success_at` on email test success

**Files:** `server/routes/admin.ts` (the test endpoint around line 183).

- [ ] **Step 1: Update the test handler**

Find:

```ts
      await emailService.sendEmail(settings, {
        to: testEmail,
        subject: 'Teste de Configuração de E-mail',
        html: `...`,
      });

      res.json({ message: "E-mail de teste enviado com sucesso" });
```

Insert a storage update between the send and the res.json:

```ts
      await storage.setEmailSettings({
        ...settings,
        lastTestSuccessAt: new Date(),
      }, settings.updatedBy);
      res.json({ message: "E-mail de teste enviado com sucesso" });
```

If `storage.setEmailSettings` does not accept a full row directly (it might take a narrower shape), look at how `POST /api/email-settings` uses it earlier in this file and mimic — the goal is to write the timestamp without changing the other fields. If the storage doesn't have an "update only the timestamp" helper, add one in `server/storage/email.ts`:

```ts
export async function touchEmailSettingsTest(id: string, at: Date): Promise<void> {
  await db.update(emailSettings).set({ lastTestSuccessAt: at }).where(eq(emailSettings.id, id));
}
```

Then wire into `server/storage/index.ts` and `interface.ts`, and call `await storage.touchEmailSettingsTest(settings.id, new Date());` from the handler. (Use this path — it is cleaner than reusing `setEmailSettings`.)

- [ ] **Step 2: Type-check**

```bash
npm run check 2>&1 | grep "routes/admin\|storage/email" | grep -v "Property 'role'" | head
```

- [ ] **Step 3: Commit**

```bash
git add server/routes/admin.ts server/storage/email.ts server/storage/index.ts server/storage/interface.ts
git commit -m "feat(email): persist lastTestSuccessAt on successful test send"
```

---

## Task 12: Frontend — UserMenu component

**Files:** `client/src/components/account/user-menu.tsx`.

- [ ] **Step 1: Create the component**

```tsx
import { useLocation } from "wouter";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { useAuth } from "@/hooks/useAuth";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { LogOut, User, KeyRound, ShieldCheck } from "lucide-react";

function initials(user: { firstName?: string; lastName?: string; email?: string } | undefined): string {
  if (!user) return "?";
  const a = (user.firstName || user.email || "?").charAt(0);
  const b = (user.lastName || "").charAt(0);
  return (a + b).toUpperCase();
}

function translateRole(role: string | undefined): string {
  if (role === "global_administrator") return "Administrador Global";
  if (role === "operator") return "Operador";
  if (role === "read_only") return "Somente Leitura";
  return "";
}

export function UserMenu() {
  const { user } = useAuth();
  const [, setLocation] = useLocation();

  const logoutMutation = useMutation({
    mutationFn: async () => apiRequest("POST", "/api/auth/logout"),
    onSuccess: () => {
      window.location.href = "/login";
    },
  });

  const displayName = user?.firstName && user?.lastName
    ? `${user.firstName} ${user.lastName}`
    : user?.email || "Usuário";

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="rounded-full"
          data-testid="button-user-menu"
          aria-label="Menu da conta"
        >
          <Avatar className="h-8 w-8">
            <AvatarFallback className="text-xs font-medium">{initials(user as any)}</AvatarFallback>
          </Avatar>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-64">
        <DropdownMenuLabel className="font-normal">
          <div className="flex flex-col space-y-1">
            <p className="text-sm font-medium leading-none">{displayName}</p>
            {user?.email && (
              <p className="text-xs leading-none text-muted-foreground">{user.email}</p>
            )}
            {user?.role && (
              <p className="text-xs leading-none text-muted-foreground">{translateRole(user.role)}</p>
            )}
          </div>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem onClick={() => setLocation("/account")} data-testid="menu-account">
          <User className="mr-2 h-4 w-4" /> Minha Conta
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => setLocation("/change-password")} data-testid="menu-change-password">
          <KeyRound className="mr-2 h-4 w-4" /> Trocar senha
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => setLocation("/account/mfa")} data-testid="menu-mfa">
          <ShieldCheck className="mr-2 h-4 w-4" /> Gerenciar MFA
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          className="text-destructive focus:text-destructive"
          onClick={() => logoutMutation.mutate()}
          data-testid="menu-logout"
        >
          <LogOut className="mr-2 h-4 w-4" /> Sair
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
```

- [ ] **Step 2: Type-check**

```bash
npm run check 2>&1 | grep "user-menu" | head
```

- [ ] **Step 3: Commit**

```bash
git add client/src/components/account/user-menu.tsx
git commit -m "feat(account): add UserMenu dropdown for topbar"
```

---

## Task 13: Frontend — SetupAdminBanner component

**Files:** `client/src/components/layout/setup-admin-banner.tsx`.

- [ ] **Step 1: Create**

```tsx
import { useAuth } from "@/hooks/useAuth";
import { AlertTriangle } from "lucide-react";
import { Link } from "wouter";

const SETUP_ADMIN_EMAIL = "admin@samureye.local";

export function SetupAdminBanner() {
  const { user } = useAuth();
  if ((user as any)?.email !== SETUP_ADMIN_EMAIL) return null;
  return (
    <div
      role="alert"
      data-testid="banner-setup-admin"
      className="flex items-start gap-3 border-b border-yellow-500/40 bg-yellow-500/10 px-6 py-3 text-sm text-yellow-900 dark:text-yellow-100"
    >
      <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" aria-hidden="true" />
      <div className="flex-1">
        <p className="font-medium">Conta de setup inicial em uso</p>
        <p className="mt-0.5 text-xs leading-relaxed">
          Você está logado como <code className="font-mono">admin@samureye.local</code>. Esta conta serve apenas para a instalação do appliance.
          {" "}
          <Link href="/users" className="underline hover:no-underline" data-testid="link-manage-users">
            Crie contas nomeadas
          </Link>{" "}
          em Administração → Usuários e evite continuar logado aqui.
        </p>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Type-check**

```bash
npm run check 2>&1 | grep "setup-admin-banner" | head
```

- [ ] **Step 3: Commit**

```bash
git add client/src/components/layout/setup-admin-banner.tsx
git commit -m "feat(layout): add warning banner for setup-admin account"
```

---

## Task 14: Frontend — MfaInvitationDialog component

**Files:** `client/src/components/account/mfa-invitation-dialog.tsx`.

- [ ] **Step 1: Create**

```tsx
import { useEffect, useState } from "react";
import { useLocation } from "wouter";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useAuth } from "@/hooks/useAuth";

export function MfaInvitationDialog() {
  const { user, isLoading } = useAuth();
  const [, setLocation] = useLocation();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [doNotRemind, setDoNotRemind] = useState(false);

  useEffect(() => {
    if (isLoading) return;
    const u = user as any;
    if (!u) return;
    if (u.pendingMfa) return;
    if (u.mfaEnabled) return;
    if (u.mfaInvitationDismissed) return;
    setOpen(true);
  }, [user, isLoading]);

  const dismissMutation = useMutation({
    mutationFn: async () => apiRequest("PUT", "/api/auth/me/mfa-invitation-dismissed"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
    },
  });

  const handleLater = async () => {
    if (doNotRemind) await dismissMutation.mutateAsync();
    setOpen(false);
  };

  const handleConfigure = async () => {
    if (doNotRemind) await dismissMutation.mutateAsync();
    setOpen(false);
    setLocation("/account/mfa");
  };

  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogContent data-testid="dialog-mfa-invitation">
        <AlertDialogHeader>
          <AlertDialogTitle>Proteja sua conta com MFA</AlertDialogTitle>
          <AlertDialogDescription>
            A autenticação de dois fatores adiciona uma camada extra de segurança à sua conta.
            Basta instalar um app autenticador (Google Authenticator, Authy, 1Password) e escanear um QR code.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <div className="flex items-center gap-2">
          <Checkbox
            id="do-not-remind"
            checked={doNotRemind}
            onCheckedChange={(v) => setDoNotRemind(v === true)}
            data-testid="checkbox-do-not-remind"
          />
          <Label htmlFor="do-not-remind" className="text-sm">
            Não lembrar novamente
          </Label>
        </div>
        <AlertDialogFooter>
          <AlertDialogCancel onClick={handleLater} data-testid="button-mfa-later">Deixar pra depois</AlertDialogCancel>
          <AlertDialogAction onClick={handleConfigure} data-testid="button-mfa-configure">Configurar agora</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
```

- [ ] **Step 2: Type-check**

```bash
npm run check 2>&1 | grep "mfa-invitation-dialog" | head
```

- [ ] **Step 3: Commit**

```bash
git add client/src/components/account/mfa-invitation-dialog.tsx
git commit -m "feat(account): add first-login MFA invitation dialog"
```

---

## Task 15: Frontend — integrate topbar, sidebar, banner, dialog

**Files:** `client/src/components/layout/topbar.tsx`, `client/src/components/layout/sidebar.tsx`, `client/src/App.tsx`.

- [ ] **Step 1: Add `<UserMenu>` to topbar**

In `client/src/components/layout/topbar.tsx`, find `<SystemStatusPopup wsConnected={wsConnected} />` and wrap the neighbourhood:

```tsx
import { UserMenu } from "@/components/account/user-menu";
```

In the JSX, place the user menu to the right of all other action buttons, after the `actions` block:

```tsx
        <div className="flex items-center space-x-4">
          <SystemStatusPopup wsConnected={wsConnected} />
          {actions || (
            <>
              <Link href="/journeys">
                <Button className="bg-primary text-primary-foreground hover:bg-primary/90 transition-colors" data-testid="button-quick-scan">
                  <Search className="mr-2 h-4 w-4" />
                  Varredura Rápida
                </Button>
              </Link>
              <Link href="/journeys">
                <Button variant="secondary" data-testid="button-new-journey">
                  <Plus className="mr-2 h-4 w-4" />
                  Nova Jornada
                </Button>
              </Link>
            </>
          )}
          <UserMenu />
        </div>
```

- [ ] **Step 2: Remove user-profile block from sidebar**

In `client/src/components/layout/sidebar.tsx`, delete the block bounded by `{/* User Profile */}` comment and the closing `</div>` of the flex container, approximately lines 216-246 (the `p-4 border-t border-sidebar-border` wrapper). KEEP the subsequent version block:

```tsx
        {appVersion && (
          <p className="mt-2 text-[10px] text-muted-foreground/50 text-center select-all" title={`Build: ${appVersion}`}>
            v{appVersion}
          </p>
        )}
```

Wrap the version in its own small footer div:

```tsx
      <div className="p-4 border-t border-sidebar-border">
        {appVersion && (
          <p className="text-[10px] text-muted-foreground/50 text-center select-all" title={`Build: ${appVersion}`}>
            v{appVersion}
          </p>
        )}
      </div>
```

Also remove the unused `LogOut` and `handleLogout` / user-related imports that become dead code. (Run `npm run check` after; any remaining warnings point to leftovers.)

- [ ] **Step 3: Mount banner and invitation dialog in `App.tsx`**

In `client/src/App.tsx`, add imports:

```tsx
import { SetupAdminBanner } from "@/components/layout/setup-admin-banner";
import { MfaInvitationDialog } from "@/components/account/mfa-invitation-dialog";
```

Find the authenticated-root layout (inside `function Router()` or wherever the sidebar + routes are rendered after auth). Add `<SetupAdminBanner />` at the very top of the authenticated layout (above or as the first child of `<main>` so the banner sits above the topbar), and `<MfaInvitationDialog />` anywhere inside the authenticated tree (the dialog positions itself):

```tsx
      <SetupAdminBanner />
      {/* existing layout, sidebar, etc. */}
      <MfaInvitationDialog />
```

If the app currently has `<Router>` that mounts `Sidebar + main`, wrap both inside a fragment with the banner above:

```tsx
return (
  <>
    <SetupAdminBanner />
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <main className="flex-1 overflow-auto">
        {/* routes */}
      </main>
    </div>
    <MfaInvitationDialog />
  </>
);
```

- [ ] **Step 4: Type-check + build**

```bash
npm run check 2>&1 | grep -E "topbar|sidebar|App.tsx|setup-admin|mfa-invitation" | grep -v "Property 'role'" | head
npx vite build 2>&1 | tail -3
```
Expected: no new errors; build succeeds.

- [ ] **Step 5: Commit**

```bash
git add client/src/components/layout/topbar.tsx client/src/components/layout/sidebar.tsx client/src/App.tsx
git commit -m "feat(layout): move user profile to topbar dropdown, mount admin banner and MFA invitation"
```

---

## Task 16: Frontend — /account index page

**Files:** `client/src/pages/account.tsx`.

- [ ] **Step 1: Create**

```tsx
import { Link } from "wouter";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { KeyRound, ShieldCheck, User as UserIcon } from "lucide-react";
import { useWebSocket } from "@/lib/websocket";

export default function AccountPage() {
  const { connected } = useWebSocket();
  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <main className="flex-1 overflow-auto">
        <TopBar title="Minha Conta" subtitle="Gerencie sua conta e segurança" wsConnected={connected} />
        <div className="p-6 space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <Link href="/change-password">
              <Card className="cursor-pointer transition-colors hover:border-primary/50" data-testid="card-change-password">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <KeyRound className="h-5 w-5" />
                    Trocar senha
                  </CardTitle>
                  <CardDescription>Atualize a senha da sua conta.</CardDescription>
                </CardHeader>
              </Card>
            </Link>
            <Link href="/account/mfa">
              <Card className="cursor-pointer transition-colors hover:border-primary/50" data-testid="card-mfa">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <ShieldCheck className="h-5 w-5" />
                    MFA (autenticação em dois fatores)
                  </CardTitle>
                  <CardDescription>Configure ou gerencie seu segundo fator de autenticação.</CardDescription>
                </CardHeader>
              </Card>
            </Link>
          </div>
        </div>
      </main>
    </div>
  );
}
```

- [ ] **Step 2: Type-check**

```bash
npm run check 2>&1 | grep "pages/account.tsx" | head
```

- [ ] **Step 3: Commit**

```bash
git add client/src/pages/account.tsx
git commit -m "feat(account): add Minha Conta index page"
```

---

## Task 17: Frontend — /account/mfa page (setup + manage)

**Files:** `client/src/pages/account-mfa.tsx`.

- [ ] **Step 1: Create**

```tsx
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
import { useWebSocket } from "@/lib/websocket";
import { ShieldCheck, ShieldOff } from "lucide-react";

interface SetupData {
  otpauthUrl: string;
  qrCodeSvg: string;
  backupCodes: string[];
}

function CodesPanel({ codes }: { codes: string[] }) {
  const { toast } = useToast();
  const allText = codes.join("\n");
  return (
    <div className="rounded-md border border-border bg-muted/20 p-3">
      <ol className="space-y-1 font-mono text-sm">
        {codes.map((c, i) => <li key={i} data-testid={`backup-code-${i}`}>{c}</li>)}
      </ol>
      <div className="mt-3 flex gap-2">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => {
            navigator.clipboard.writeText(allText);
            toast({ title: "Copiado", description: "Códigos de recuperação copiados." });
          }}
          data-testid="button-copy-codes"
        >
          Copiar
        </Button>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => {
            const blob = new Blob([allText], { type: "text/plain" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = "samureye-mfa-backup-codes.txt";
            a.click();
            URL.revokeObjectURL(url);
          }}
          data-testid="button-download-codes"
        >
          Baixar .txt
        </Button>
      </div>
      <p className="mt-3 text-xs text-muted-foreground">
        Guarde esses códigos em um local seguro. Cada código só pode ser usado uma vez e não será mostrado novamente.
      </p>
    </div>
  );
}

export default function AccountMfaPage() {
  const { toast } = useToast();
  const { user } = useAuth();
  const { connected } = useWebSocket();
  const queryClient = useQueryClient();

  const [setup, setSetup] = useState<SetupData | null>(null);
  const [token, setToken] = useState("");
  const [disablePassword, setDisablePassword] = useState("");
  const [disableToken, setDisableToken] = useState("");
  const [regenPassword, setRegenPassword] = useState("");
  const [newCodes, setNewCodes] = useState<string[] | null>(null);

  const mfaEnabled = (user as any)?.mfaEnabled === true;

  const setupMutation = useMutation({
    mutationFn: async () => (await apiRequest("POST", "/api/auth/mfa/setup")) as any as SetupData,
    onSuccess: (data) => setSetup(data),
  });

  const enableMutation = useMutation({
    mutationFn: async () => apiRequest("POST", "/api/auth/mfa/enable", { token }),
    onSuccess: () => {
      toast({ title: "MFA ativado", description: "Próximos logins pedirão o código TOTP." });
      setSetup(null);
      setToken("");
      queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
    },
    onError: (err: any) => toast({ title: "Erro", description: err?.message || "Falha ao ativar", variant: "destructive" }),
  });

  const disableMutation = useMutation({
    mutationFn: async () => apiRequest("POST", "/api/auth/mfa/disable", { currentPassword: disablePassword, token: disableToken }),
    onSuccess: () => {
      toast({ title: "MFA desativado" });
      setDisablePassword("");
      setDisableToken("");
      queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
    },
    onError: (err: any) => toast({ title: "Erro", description: err?.message || "Falha ao desativar", variant: "destructive" }),
  });

  const regenMutation = useMutation({
    mutationFn: async () => (await apiRequest("POST", "/api/auth/mfa/recovery-codes/regenerate", { currentPassword: regenPassword })) as any as { backupCodes: string[] },
    onSuccess: (data) => {
      setNewCodes(data.backupCodes);
      setRegenPassword("");
      toast({ title: "Códigos regenerados" });
    },
    onError: (err: any) => toast({ title: "Erro", description: err?.message || "Falha ao regenerar", variant: "destructive" }),
  });

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <main className="flex-1 overflow-auto">
        <TopBar title="Gerenciar MFA" subtitle="Autenticação em dois fatores" wsConnected={connected} />
        <div className="p-6 space-y-6 max-w-3xl">

          {!mfaEnabled && !setup && (
            <Card>
              <CardHeader><CardTitle className="flex items-center gap-2"><ShieldCheck className="h-5 w-5" /> MFA desativado</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-muted-foreground">
                  Adicione uma camada extra de segurança. Você precisará de um aplicativo autenticador (Google Authenticator, Authy, 1Password, etc.).
                </p>
                <Button onClick={() => setupMutation.mutate()} disabled={setupMutation.isPending} data-testid="button-start-mfa-setup">
                  {setupMutation.isPending ? "Preparando..." : "Configurar MFA"}
                </Button>
              </CardContent>
            </Card>
          )}

          {!mfaEnabled && setup && (
            <Card>
              <CardHeader><CardTitle>Configure seu app autenticador</CardTitle></CardHeader>
              <CardContent className="space-y-6">
                <div className="grid gap-6 md:grid-cols-2">
                  <div>
                    <Label className="text-sm">1. Escaneie o QR code</Label>
                    <div
                      className="mt-2 inline-block rounded-md border border-border bg-white p-3"
                      dangerouslySetInnerHTML={{ __html: setup.qrCodeSvg }}
                    />
                    <p className="mt-2 text-xs text-muted-foreground break-all">
                      Ou copie manualmente: <code className="font-mono">{setup.otpauthUrl}</code>
                    </p>
                  </div>
                  <div>
                    <Label className="text-sm">2. Guarde os códigos de recuperação</Label>
                    <div className="mt-2">
                      <CodesPanel codes={setup.backupCodes} />
                    </div>
                  </div>
                </div>
                <Separator />
                <div>
                  <Label htmlFor="confirm-token">3. Digite o código de 6 dígitos gerado pelo app</Label>
                  <div className="flex gap-2 mt-2">
                    <Input
                      id="confirm-token"
                      value={token}
                      onChange={(e) => setToken(e.target.value.replace(/\D/g, "").slice(0, 6))}
                      maxLength={6}
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      placeholder="000000"
                      data-testid="input-confirm-token"
                    />
                    <Button
                      onClick={() => enableMutation.mutate()}
                      disabled={token.length !== 6 || enableMutation.isPending}
                      data-testid="button-enable-mfa"
                    >
                      {enableMutation.isPending ? "Ativando..." : "Ativar"}
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {mfaEnabled && (
            <>
              <Card>
                <CardHeader><CardTitle className="flex items-center gap-2"><ShieldCheck className="h-5 w-5 text-green-500" /> MFA ativado</CardTitle></CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <p>Próximos logins exigirão o código TOTP gerado pelo seu aplicativo autenticador.</p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader><CardTitle>Regenerar códigos de recuperação</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  {newCodes ? (
                    <CodesPanel codes={newCodes} />
                  ) : (
                    <>
                      <Label htmlFor="regen-password">Confirme sua senha atual</Label>
                      <Input id="regen-password" type="password" value={regenPassword} onChange={(e) => setRegenPassword(e.target.value)} data-testid="input-regen-password" />
                      <Button onClick={() => regenMutation.mutate()} disabled={!regenPassword || regenMutation.isPending} data-testid="button-regenerate-codes">
                        {regenMutation.isPending ? "Regenerando..." : "Gerar novos códigos"}
                      </Button>
                    </>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader><CardTitle className="flex items-center gap-2"><ShieldOff className="h-5 w-5" /> Desativar MFA</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  <Label htmlFor="disable-password">Senha atual</Label>
                  <Input id="disable-password" type="password" value={disablePassword} onChange={(e) => setDisablePassword(e.target.value)} data-testid="input-disable-password" />
                  <Label htmlFor="disable-token">Código TOTP atual</Label>
                  <Input
                    id="disable-token"
                    value={disableToken}
                    onChange={(e) => setDisableToken(e.target.value.replace(/\D/g, "").slice(0, 6))}
                    maxLength={6}
                    inputMode="numeric"
                    placeholder="000000"
                    data-testid="input-disable-token"
                  />
                  <Button variant="destructive" onClick={() => disableMutation.mutate()} disabled={!disablePassword || disableToken.length !== 6 || disableMutation.isPending} data-testid="button-disable-mfa">
                    {disableMutation.isPending ? "Desativando..." : "Desativar MFA"}
                  </Button>
                </CardContent>
              </Card>
            </>
          )}
        </div>
      </main>
    </div>
  );
}
```

- [ ] **Step 2: Type-check**

```bash
npm run check 2>&1 | grep "account-mfa" | head
```

- [ ] **Step 3: Commit**

```bash
git add client/src/pages/account-mfa.tsx
git commit -m "feat(account): add /account/mfa page (setup + manage)"
```

---

## Task 18: Frontend — /mfa-challenge page

**Files:** `client/src/pages/mfa-challenge.tsx`.

- [ ] **Step 1: Create**

```tsx
import { useEffect, useState } from "react";
import { useLocation } from "wouter";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";

interface ChallengeState {
  useRecoveryCode: boolean;
  emailDeliveryAvailable: boolean;
}

export default function MfaChallengePage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [, setLocation] = useLocation();
  const [token, setToken] = useState("");
  const [state, setState] = useState<ChallengeState>({ useRecoveryCode: false, emailDeliveryAvailable: false });

  useEffect(() => {
    const cached = sessionStorage.getItem("mfa-email-available");
    setState((s) => ({ ...s, emailDeliveryAvailable: cached === "true" }));
  }, []);

  const verifyMutation = useMutation({
    mutationFn: async () => apiRequest("POST", "/api/auth/mfa/verify", { token }),
    onSuccess: async () => {
      sessionStorage.removeItem("mfa-email-available");
      await queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
      setLocation("/");
    },
    onError: (err: any) => {
      toast({ title: "Código inválido", description: err?.message || "Tente novamente.", variant: "destructive" });
      setToken("");
    },
  });

  const emailMutation = useMutation({
    mutationFn: async () => apiRequest("POST", "/api/auth/mfa/email"),
    onSuccess: () => toast({ title: "Código enviado", description: "Verifique sua caixa de entrada." }),
    onError: (err: any) => toast({ title: "Erro", description: err?.message || "Falha ao enviar.", variant: "destructive" }),
  });

  const logoutMutation = useMutation({
    mutationFn: async () => apiRequest("POST", "/api/auth/logout"),
    onSuccess: () => window.location.href = "/login",
  });

  const sanitized = state.useRecoveryCode
    ? token.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 12)
    : token.replace(/\D/g, "").slice(0, 6);

  return (
    <div className="flex h-screen items-center justify-center bg-background">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Verificação em duas etapas</CardTitle>
          <CardDescription>
            {state.useRecoveryCode
              ? "Digite um dos seus códigos de recuperação."
              : "Digite o código de 6 dígitos do seu app autenticador."}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label htmlFor="mfa-token">Código</Label>
            <Input
              id="mfa-token"
              value={sanitized}
              onChange={(e) => setToken(e.target.value)}
              maxLength={state.useRecoveryCode ? 12 : 6}
              inputMode={state.useRecoveryCode ? "text" : "numeric"}
              autoComplete="one-time-code"
              className={state.useRecoveryCode ? "font-mono" : "font-mono text-center text-lg tracking-widest"}
              placeholder={state.useRecoveryCode ? "abc123def456" : "000000"}
              data-testid="input-mfa-token"
              autoFocus
            />
          </div>
          <Button
            onClick={() => verifyMutation.mutate()}
            disabled={!sanitized || verifyMutation.isPending}
            className="w-full"
            data-testid="button-verify-mfa"
          >
            {verifyMutation.isPending ? "Validando..." : "Validar"}
          </Button>

          <div className="flex flex-col gap-2 pt-2 text-sm">
            {state.emailDeliveryAvailable && !state.useRecoveryCode && (
              <button
                type="button"
                onClick={() => emailMutation.mutate()}
                disabled={emailMutation.isPending}
                className="text-primary hover:underline text-left"
                data-testid="button-send-email"
              >
                {emailMutation.isPending ? "Enviando..." : "Receber código por e-mail"}
              </button>
            )}
            <button
              type="button"
              onClick={() => { setState((s) => ({ ...s, useRecoveryCode: !s.useRecoveryCode })); setToken(""); }}
              className="text-primary hover:underline text-left"
              data-testid="button-toggle-recovery"
            >
              {state.useRecoveryCode ? "Voltar a usar código do app" : "Usar código de recuperação"}
            </button>
            <button
              type="button"
              onClick={() => logoutMutation.mutate()}
              className="text-muted-foreground hover:text-foreground text-left"
              data-testid="button-logout"
            >
              Sair
            </button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
```

- [ ] **Step 2: Type-check**

```bash
npm run check 2>&1 | grep "mfa-challenge" | head
```

- [ ] **Step 3: Commit**

```bash
git add client/src/pages/mfa-challenge.tsx
git commit -m "feat(auth): add /mfa-challenge page for post-password TOTP verification"
```

---

## Task 19: Frontend — login page handles pendingMfa

**Files:** `client/src/pages/login.tsx`.

- [ ] **Step 1: Find the login mutation success handler**

In `client/src/pages/login.tsx`, locate the `useMutation` whose `mutationFn` calls `apiRequest("POST", "/api/auth/login", ...)`. Its `onSuccess` currently navigates to `/` (or calls `invalidateQueries` and relies on auth guard).

- [ ] **Step 2: Update onSuccess to branch on response**

Change the success handler so that when the response contains `pendingMfa: true`, it stores the `emailDeliveryAvailable` flag in sessionStorage and navigates to `/mfa-challenge`:

```tsx
    onSuccess: async (data: any) => {
      if (data?.pendingMfa) {
        sessionStorage.setItem("mfa-email-available", data.emailDeliveryAvailable ? "true" : "false");
        setLocation("/mfa-challenge");
        return;
      }
      await queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
      setLocation("/");
    },
```

(Adapt to the handler's existing shape — the key is the `if (data?.pendingMfa)` branch. If the fetch wrapper doesn't return the parsed JSON, add a `.json()` call inside the `mutationFn`.)

- [ ] **Step 3: Type-check**

```bash
npm run check 2>&1 | grep "pages/login" | head
```

- [ ] **Step 4: Commit**

```bash
git add client/src/pages/login.tsx
git commit -m "feat(login): route to /mfa-challenge when backend returns pendingMfa"
```

---

## Task 20: Register routes in App.tsx

**Files:** `client/src/App.tsx`.

- [ ] **Step 1: Add route imports**

```tsx
import AccountPage from "@/pages/account";
import AccountMfaPage from "@/pages/account-mfa";
import MfaChallengePage from "@/pages/mfa-challenge";
```

- [ ] **Step 2: Register routes**

Find the `<Switch>` (or router component) that mounts existing authenticated pages. Add:

```tsx
<Route path="/mfa-challenge" component={MfaChallengePage} />
<Route path="/account" component={AccountPage} />
<Route path="/account/mfa" component={AccountMfaPage} />
```

Important: `/mfa-challenge` must be accessible to sessions where `pendingMfa === true`. The guard logic in App.tsx that redirects unauthenticated users to `/login` should treat `pendingMfa === true` as "authenticated enough to see /mfa-challenge". Look for the auth guard (probably using `useAuth`) — if the shape is `{ user, isLoading }`, the guard currently blocks when `!user`. Since `/api/auth/user` returns `{ pendingMfa: true }` in the pending state, treat that as a distinct branch:

```tsx
if (!isLoading && user && (user as any).pendingMfa) {
  // Redirect all paths except /mfa-challenge and /login to /mfa-challenge
  if (location !== "/mfa-challenge" && location !== "/login") {
    return <Redirect to="/mfa-challenge" />;
  }
}
```

(Exact syntax depends on the existing guard style. The invariant: `pendingMfa` users can only access `/mfa-challenge`.)

- [ ] **Step 3: Type-check + build**

```bash
npm run check 2>&1 | grep "App.tsx" | grep -v "Property 'role'" | head
npx vite build 2>&1 | tail -3
```

- [ ] **Step 4: Commit**

```bash
git add client/src/App.tsx
git commit -m "feat(app): register /account, /account/mfa and /mfa-challenge routes"
```

---

## Task 21: Deploy + runtime QA

- [ ] **Step 1: Final type-check + build**

```bash
cd /opt/samureye && npm run check 2>&1 | grep -vE "Property 'role'|threatEngine|cveService|storage/threats|sidebar\.tsx|audit\.tsx|useAuth\.ts|replitAuth\.ts|notification-policies\.tsx" | grep "error TS" | head
npx vite build 2>&1 | tail -3
npx vitest run server/__tests__/mfaService.test.ts
```
Expected: no new error lines; build succeeds; vitest passes.

- [ ] **Step 2: Deploy**

```bash
deploy-samureye
```
Expected: pull / build / restart / push all succeed.

- [ ] **Step 3: Runtime QA checklist**

Perform in browser as the DB admin (`admin@samureye.local`):

1. Topbar mostra avatar com iniciais no canto superior direito.
2. Clicar no avatar abre dropdown com nome/email/role, "Minha Conta", "Trocar senha", "Gerenciar MFA", "Sair".
3. Sidebar não tem mais o bloco de user profile no rodapé; a versão aparece pequena.
4. Banner amarelo aparece no topo ("Conta de setup inicial em uso") e somente para `admin@samureye.local`.
5. Modal de convite MFA aparece (primeiro login sem MFA, sem "não lembrar"); fechar com "Deixar pra depois" sem marcar checkbox → em novo login volta; marcar checkbox + qualquer botão → em novo login não volta.
6. `/account/mfa` mostra "MFA desativado" + botão "Configurar MFA" → clica → aparece QR + 8 códigos + input → app autenticador escaneia o QR e retorna 6 dígitos → "Ativar" persiste; toast "MFA ativado".
7. Logout + login novamente → após senha, vai para `/mfa-challenge`. TOTP correto → entra normal. TOTP errado → erro. 5 erros → 423.
8. Link "Usar código de recuperação" troca input; um dos 8 códigos funciona uma vez; repetir o mesmo código falha; na `/account/mfa` a lista de códigos ainda é 7.
9. Configurar mensageria em `/settings` → aba "Mensageria" → "Enviar teste" → toast OK → banco `email_settings.last_test_success_at` preenchido. Próximo login com MFA → tela de MFA mostra "Receber código por e-mail" → clica → e-mail chega em até 1min → código entra → login completa.
10. `/account/mfa` → "Regenerar códigos" → senha → 8 novos aparecem e antigos param de funcionar no próximo login.
11. `/account/mfa` → "Desativar MFA" → senha + TOTP → MFA desativa; próximo login não pede fator 2.
12. Banner some ao logar com outra conta que não seja `admin@samureye.local`.

- [ ] **Step 4: If any QA step fails, commit the fix**

```bash
git add -A
git commit -m "fix(mfa): QA follow-up"
deploy-samureye
```

---

## Self-Review (performed against spec)

- **Spec §4 schema**: Task 2 adds exactly the 5 users columns + 1 email_settings column + `mfa_email_challenges` table; push via `npm run db:push`.
- **Spec §5.1/§5.2 login flow**: Task 7 emits `pendingMfa`; Task 8 allowlist; Task 10 `mfa/verify` with email/TOTP/backup order.
- **Spec §5.3 setup**: Task 10 `mfa/setup` + `mfa/enable`; Task 17 UI renders QR + backup codes.
- **Spec §5.4 invitation modal**: Task 14 component + Task 15 mount.
- **Spec §5.5 manage MFA**: Task 10 `mfa/disable` + `mfa/recovery-codes/regenerate`; Task 17 UI.
- **Spec §5.6 admin banner**: Task 13 component + Task 15 mount.
- **Spec §6 UI menu**: Task 12 UserMenu + Task 15 integration.
- **Spec §7 security**: Task 5 MfaService encapsulates encryption + hashing; Task 10 rate-limit + audit logs.
- **Spec §8 file list**: all files accounted for in Tasks 1-20; plan file list matches.
- **Spec §9 deps**: Task 1.
- **Spec §10 acceptance criteria 1–14**: covered by Task 21 QA + automated check/build.
- **Spec §11 risks**: `pendingMfa` session expiry relies on existing session TTL; email-testing window is hard-coded to 30 days in Task 7 and Task 10; no UI-driven MFA reset (documented as out-of-scope).
