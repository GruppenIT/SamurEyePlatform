import { db } from "../db";
import {
  assets,
  credentials,
  type Asset,
  type InsertAsset,
  type Credential,
} from "@shared/schema";
import { eq, desc, and, sql } from "drizzle-orm";
import { createLogger } from '../lib/logger';

const log = createLogger('storage');

export async function getAssets(): Promise<Asset[]> {
  return await db.select().from(assets).orderBy(desc(assets.createdAt));
}

export async function getAsset(id: string): Promise<Asset | undefined> {
  const [asset] = await db.select().from(assets).where(eq(assets.id, id));
  return asset;
}

export async function getAssetsByTags(tags: string[]): Promise<Asset[]> {
  if (tags.length === 0) {
    return [];
  }

  // Busca assets que possuem QUALQUER uma das tags fornecidas
  // Usando o operador ?| do PostgreSQL para arrays JSONB
  const results = await db.select().from(assets).where(
    sql`${assets.tags}::jsonb ?| array[${sql.join(tags.map(tag => sql`${tag}`), sql`, `)}]::text[]`
  );
  return results;
}

export async function getAssetsByType(type: string): Promise<Asset[]> {
  return await db.select().from(assets).where(sql`${assets.type} = ${type}`).orderBy(desc(assets.createdAt));
}

export async function getUniqueTags(): Promise<string[]> {
  // Busca todas as TAGs únicas de todos os assets
  // Usando jsonb_array_elements_text para expandir o array JSONB em linhas
  const result = await db.execute<{ tag: string }>(
    sql`SELECT DISTINCT jsonb_array_elements_text(${assets.tags}) as tag FROM ${assets} WHERE ${assets.tags} IS NOT NULL AND jsonb_array_length(${assets.tags}) > 0 ORDER BY tag`
  );
  return result.rows.map(row => row.tag);
}

export async function createAsset(asset: InsertAsset, userId: string): Promise<Asset> {
  // Check for existing asset with same value and type
  const existing = await db
    .select()
    .from(assets)
    .where(and(
      eq(assets.value, asset.value),
      eq(assets.type, asset.type)
    ))
    .limit(1);

  if (existing.length > 0) {
    log.info({ value: asset.value, type: asset.type }, 'duplicate asset ignored');
    return existing[0];
  }

  const assetValues = {
    type: asset.type,
    value: asset.value,
    tags: asset.tags || [],
    parentAssetId: asset.parentAssetId ?? null,
    createdBy: userId,
  } as any;

  const [newAsset] = await db
    .insert(assets)
    .values(assetValues)
    .returning();
  return newAsset;
}

async function detectCycleIfSetParent(assetId: string, newParentId: string | null): Promise<boolean> {
  if (!newParentId) return false;
  if (newParentId === assetId) return true;
  // Walk up the chain from newParentId; if we ever reach assetId, it's a cycle
  let currentId: string | null = newParentId;
  const seen = new Set<string>();
  while (currentId) {
    if (seen.has(currentId)) return true; // already-broken cycle upstream; reject
    seen.add(currentId);
    if (currentId === assetId) return true;
    const [row] = await db.select({ parentAssetId: assets.parentAssetId }).from(assets).where(eq(assets.id, currentId)).limit(1);
    currentId = row?.parentAssetId ?? null;
  }
  return false;
}

export async function updateAsset(id: string, asset: Partial<InsertAsset>): Promise<Asset> {
  if ('parentAssetId' in asset) {
    const hasCycle = await detectCycleIfSetParent(id, asset.parentAssetId ?? null);
    if (hasCycle) {
      throw new Error("cycle detected: asset cannot be an ancestor of itself");
    }
  }

  const updates: any = {};
  if (asset.type !== undefined) updates.type = asset.type;
  if (asset.value !== undefined) updates.value = asset.value;
  if (asset.tags !== undefined) updates.tags = asset.tags;
  if ('parentAssetId' in asset) updates.parentAssetId = asset.parentAssetId ?? null;

  const [updatedAsset] = await db
    .update(assets)
    .set(updates)
    .where(eq(assets.id, id))
    .returning();
  return updatedAsset;
}

export async function deleteAsset(id: string): Promise<void> {
  await db.delete(assets).where(eq(assets.id, id));
}

// Credential operations
export async function getCredentials(): Promise<Omit<Credential, 'secretEncrypted' | 'dekEncrypted'>[]> {
  const results = await db
    .select({
      id: credentials.id,
      name: credentials.name,
      type: credentials.type,
      hostOverride: credentials.hostOverride,
      port: credentials.port,
      domain: credentials.domain,
      username: credentials.username,
      createdAt: credentials.createdAt,
      createdBy: credentials.createdBy,
    })
    .from(credentials)
    .orderBy(desc(credentials.createdAt));
  return results;
}

export async function getCredential(id: string): Promise<Credential | undefined> {
  const [credential] = await db.select().from(credentials).where(eq(credentials.id, id));
  return credential;
}

export async function createCredential(credential: Omit<Credential, 'id' | 'createdAt'>, userId: string): Promise<Credential> {
  const [newCredential] = await db
    .insert(credentials)
    .values({ ...credential, createdBy: userId })
    .returning();
  return newCredential;
}

export async function updateCredential(id: string, credential: Partial<Credential>): Promise<Credential> {
  const [updatedCredential] = await db
    .update(credentials)
    .set(credential)
    .where(eq(credentials.id, id))
    .returning();
  return updatedCredential;
}

export async function deleteCredential(id: string): Promise<void> {
  await db.delete(credentials).where(eq(credentials.id, id));
}
