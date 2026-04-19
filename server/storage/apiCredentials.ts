// Phase 10 — CRED-01..04: facade de domínio para api_credentials.
// Padrão simétrico com server/storage/apis.ts (Phase 9).
// Reusa encryptionService (KEK/DEK existente) — zero nova crypto.

import { db } from "../db";
import {
  apiCredentials,
  type ApiCredentialSafe,
  type ApiCredentialWithSecret,
  type InsertApiCredential,
  type PatchApiCredential,
  type ApiAuthType,
} from "@shared/schema";
import { encryptionService } from "../services/encryption";
import { matchUrlPattern } from "../services/credentials/matchUrlPattern";
import { decodeJwtExp } from "../services/credentials/decodeJwtExp";
import { eq, asc, and, isNull, or } from "drizzle-orm";
import { createLogger } from "../lib/logger";

const log = createLogger("storage:api-credentials");

// SAFE_FIELDS: campos retornados por list/get/resolve — NUNCA inclui secret*/dek*.
// Padrão exato de getCredentials() em assets.ts:180.
const SAFE_FIELDS = {
  id: apiCredentials.id,
  name: apiCredentials.name,
  description: apiCredentials.description,
  authType: apiCredentials.authType,
  urlPattern: apiCredentials.urlPattern,
  priority: apiCredentials.priority,
  apiId: apiCredentials.apiId,
  apiKeyHeaderName: apiCredentials.apiKeyHeaderName,
  apiKeyQueryParam: apiCredentials.apiKeyQueryParam,
  basicUsername: apiCredentials.basicUsername,
  bearerExpiresAt: apiCredentials.bearerExpiresAt,
  oauth2ClientId: apiCredentials.oauth2ClientId,
  oauth2TokenUrl: apiCredentials.oauth2TokenUrl,
  oauth2Scope: apiCredentials.oauth2Scope,
  oauth2Audience: apiCredentials.oauth2Audience,
  hmacKeyId: apiCredentials.hmacKeyId,
  hmacAlgorithm: apiCredentials.hmacAlgorithm,
  hmacSignatureHeader: apiCredentials.hmacSignatureHeader,
  hmacSignedHeaders: apiCredentials.hmacSignedHeaders,
  hmacCanonicalTemplate: apiCredentials.hmacCanonicalTemplate,
  createdAt: apiCredentials.createdAt,
  updatedAt: apiCredentials.updatedAt,
  createdBy: apiCredentials.createdBy,
  updatedBy: apiCredentials.updatedBy,
};

export async function listApiCredentials(
  filter?: { apiId?: string; authType?: ApiAuthType },
): Promise<ApiCredentialSafe[]> {
  const conds = [];
  if (filter?.apiId) conds.push(eq(apiCredentials.apiId, filter.apiId));
  if (filter?.authType) conds.push(eq(apiCredentials.authType, filter.authType));

  const base = db.select(SAFE_FIELDS).from(apiCredentials);
  const withWhere = conds.length > 0 ? base.where(and(...conds)) : base;
  const rows = await withWhere.orderBy(
    asc(apiCredentials.priority),
    asc(apiCredentials.createdAt),
  );
  return rows as ApiCredentialSafe[];
}

export async function getApiCredential(
  id: string,
): Promise<ApiCredentialSafe | undefined> {
  const [row] = await db
    .select(SAFE_FIELDS)
    .from(apiCredentials)
    .where(eq(apiCredentials.id, id));
  return row as ApiCredentialSafe | undefined;
}

// INTERNO — uso exclusivo do executor (Phase 11+) que precisa do secret cifrado para decrypt.
export async function getApiCredentialWithSecret(
  id: string,
): Promise<ApiCredentialWithSecret | undefined> {
  const [row] = await db
    .select()
    .from(apiCredentials)
    .where(eq(apiCredentials.id, id));
  return row;
}

// Extrai o secret do input por auth type — função pura (sem I/O).
function extractSecret(input: InsertApiCredential): string {
  if (input.authType === "mtls") {
    return JSON.stringify({
      cert: input.mtlsCert,
      key: input.mtlsKey,
      ca: input.mtlsCa ?? null,
    });
  }
  // Demais tipos: campo `secret` direto
  return (input as { secret: string }).secret;
}

// Remove campos de "input wrapper" (secret, mtls*) para que `db.insert` receba só colunas válidas.
function stripSecretFields<T extends Record<string, unknown>>(
  input: T,
): Omit<T, "secret" | "mtlsCert" | "mtlsKey" | "mtlsCa"> {
  const {
    secret: _s,
    mtlsCert: _c,
    mtlsKey: _k,
    mtlsCa: _a,
    ...rest
  } = input as Record<string, unknown>;
  return rest as Omit<T, "secret" | "mtlsCert" | "mtlsKey" | "mtlsCa">;
}

export async function createApiCredential(
  input: InsertApiCredential,
  userId: string,
): Promise<ApiCredentialSafe> {
  const secretToEncrypt = extractSecret(input);
  const { secretEncrypted, dekEncrypted } =
    encryptionService.encryptCredential(secretToEncrypt);

  // Derivar bearerExpiresAt para bearer_jwt (CONTEXT.md: falha silenciosa)
  let bearerExpiresAt: Date | null = null;
  if (input.authType === "bearer_jwt") {
    bearerExpiresAt = decodeJwtExp((input as { secret: string }).secret);
  }

  const cleaned = stripSecretFields(input);
  const [created] = await db
    .insert(apiCredentials)
    .values({
      ...cleaned,
      secretEncrypted,
      dekEncrypted,
      bearerExpiresAt,
      createdBy: userId,
    })
    .returning(SAFE_FIELDS);

  log.info(
    {
      apiCredentialId: created.id,
      authType: created.authType,
      apiId: created.apiId,
    },
    "api credential created",
  );
  return created as ApiCredentialSafe;
}

export async function updateApiCredential(
  id: string,
  patch: PatchApiCredential,
  userId: string,
): Promise<ApiCredentialSafe> {
  // Se patch tem secret novo (ou cert/key/ca para mTLS), re-criptografa.
  const updates: Record<string, unknown> = stripSecretFields(patch);
  updates.updatedBy = userId;
  updates.updatedAt = new Date();

  const hasNewSecret =
    patch.secret || patch.mtlsCert || patch.mtlsKey || patch.mtlsCa;
  if (hasNewSecret) {
    // Para re-criptografar, precisamos saber o authType. Fetch row atual.
    const current = await getApiCredentialWithSecret(id);
    if (!current) {
      throw new Error("Credencial não encontrada");
    }
    let newSecret: string;
    if (current.authType === "mtls") {
      newSecret = JSON.stringify({
        cert: patch.mtlsCert ?? null,
        key: patch.mtlsKey ?? null,
        ca: patch.mtlsCa ?? null,
      });
    } else {
      newSecret = patch.secret as string;
    }
    const { secretEncrypted, dekEncrypted } =
      encryptionService.encryptCredential(newSecret);
    updates.secretEncrypted = secretEncrypted;
    updates.dekEncrypted = dekEncrypted;

    if (current.authType === "bearer_jwt" && patch.secret) {
      updates.bearerExpiresAt = decodeJwtExp(patch.secret);
    }
  }

  const [updated] = await db
    .update(apiCredentials)
    .set(updates)
    .where(eq(apiCredentials.id, id))
    .returning(SAFE_FIELDS);

  log.info(
    { apiCredentialId: id, reEncrypted: !!hasNewSecret },
    "api credential updated",
  );
  return updated as ApiCredentialSafe;
}

export async function deleteApiCredential(id: string): Promise<void> {
  await db.delete(apiCredentials).where(eq(apiCredentials.id, id));
  log.info({ apiCredentialId: id }, "api credential deleted");
}

// CRED-04 — resolução por priority + specificity + createdAt.
// Algoritmo (CONTEXT.md linhas 98-103):
//   1. Candidatos: apiId === apiId OR apiId IS NULL
//   2. Filtra por matchUrlPattern(c.urlPattern, endpointUrl)
//   3. Sort: priority ASC → specificity DESC (mais literais ganha) → createdAt ASC
//   4. Retorna top 1 ou null.
export async function resolveApiCredential(
  apiId: string,
  endpointUrl: string,
): Promise<ApiCredentialSafe | null> {
  const candidates = await db
    .select(SAFE_FIELDS)
    .from(apiCredentials)
    .where(or(eq(apiCredentials.apiId, apiId), isNull(apiCredentials.apiId)))
    .orderBy(asc(apiCredentials.priority), asc(apiCredentials.createdAt));

  const matching = (candidates as ApiCredentialSafe[]).filter((c) =>
    matchUrlPattern(c.urlPattern, endpointUrl),
  );
  if (matching.length === 0) return null;

  const countLiterals = (p: string) => p.replace(/\*/g, "").length;
  matching.sort((a, b) => {
    if (a.priority !== b.priority) return a.priority - b.priority;
    const specDiff = countLiterals(b.urlPattern) - countLiterals(a.urlPattern);
    if (specDiff !== 0) return specDiff;
    const aTime = a.createdAt ? new Date(a.createdAt).getTime() : 0;
    const bTime = b.createdAt ? new Date(b.createdAt).getTime() : 0;
    return aTime - bTime;
  });

  return matching[0];
}
