import { db } from "../db";
import { users, threats, threatStatusHistory, postureSnapshots, recommendations } from "@shared/schema";
import { eq, sql, isNull } from "drizzle-orm";
import * as crypto from "crypto";
import { createLogger } from '../lib/logger';

const log = createLogger('storage');

export async function initializeDatabaseStructure(): Promise<void> {
  try {
    log.info('verifying database structure');

    // Step 0: Ensure system user exists
    await ensureSystemUserExists();

    // Check if unique index exists
    const indexCheck = await db.execute(sql`
      SELECT indexname
      FROM pg_indexes
      WHERE tablename = 'threats'
        AND indexname = 'UQ_threats_correlation_key'
    `);

    const hasUniqueIndex = (indexCheck.rowCount ?? 0) > 0;
    log.info({ hasUniqueIndex }, 'correlation_key unique index status');

    if (!hasUniqueIndex) {
      log.info('creating duplicate prevention structure');

      // Step 1: Consolidate existing duplicates
      log.info('consolidating existing duplicates');
      await consolidateDuplicateThreats();

      // Step 2: Create unique index
      log.info('creating unique index for correlation_key');
      await db.execute(sql`
        CREATE UNIQUE INDEX "UQ_threats_correlation_key"
        ON threats (correlation_key)
        WHERE (
          correlation_key IS NOT NULL
          AND (status != 'closed' OR closure_reason != 'duplicate')
        )
      `);

      log.info('unique index created successfully');
      log.info('duplicate prevention system active');
    } else {
      log.info('database structure already up to date');
    }

    // Phase 2: grouping_key partial unique index for parent threat upsert
    const groupingKeyCheck = await db.execute(sql`
      SELECT indexname
      FROM pg_indexes
      WHERE tablename = 'threats'
        AND indexname = 'UQ_threats_grouping_key'
    `);

    const hasGroupingKeyIndex = (groupingKeyCheck.rowCount ?? 0) > 0;
    log.info({ hasGroupingKeyIndex }, 'grouping_key unique index status');

    if (!hasGroupingKeyIndex) {
      log.info('creating unique index for grouping_key');
      await db.execute(sql`
        CREATE UNIQUE INDEX "UQ_threats_grouping_key"
        ON threats (grouping_key)
        WHERE grouping_key IS NOT NULL
      `);
      log.info('grouping_key unique index created successfully');
    }

    // Phase 3: recommendations threat_id unique index for upsert support
    const recommendationsUniqueCheck = await db.execute(sql`
      SELECT indexname
      FROM pg_indexes
      WHERE tablename = 'recommendations'
        AND indexname = 'UQ_recommendations_threat_id'
    `);

    const hasRecommendationsUniqueIndex = (recommendationsUniqueCheck.rowCount ?? 0) > 0;
    log.info({ hasRecommendationsUniqueIndex }, 'recommendations threat_id unique index status');

    if (!hasRecommendationsUniqueIndex) {
      log.info('creating unique index for recommendations threat_id');
      // First ensure status column exists (additive migration)
      await db.execute(sql`
        ALTER TABLE recommendations ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending'
      `);
      await db.execute(sql`
        CREATE UNIQUE INDEX "UQ_recommendations_threat_id"
        ON recommendations (threat_id)
      `);
      log.info('recommendations unique index created successfully');
    } else {
      // Ensure status column exists even if index was already present
      await db.execute(sql`
        ALTER TABLE recommendations ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending'
      `);
    }

  } catch (error) {
    log.error({ err: error }, 'database initialization error');
    // Don't throw - let the system continue with fallback mode
  }
}

export async function ensureSystemUserExists(): Promise<void> {
  try {
    // Check if system user exists
    const existingUsers = await db
      .select()
      .from(users)
      .where(eq(users.id, 'system'))
      .limit(1);

    if (existingUsers.length === 0) {
      log.info('creating system user');

      // Create system user with Drizzle insert for type safety
      await db.insert(users).values({
        id: 'system',
        email: 'system@samureye.local',
        firstName: 'Sistema',
        lastName: 'Automatizado',
        role: 'global_administrator',
        passwordHash: crypto.randomBytes(32).toString('hex'), // Unusable random password
        mustChangePassword: false,
      }).onConflictDoNothing();

      log.info('system user created successfully');
    } else {
      log.info('system user already exists');
    }

    // Verify system user exists after creation attempt
    const verifyUser = await db
      .select({ id: users.id })
      .from(users)
      .where(eq(users.id, 'system'))
      .limit(1);

    if (verifyUser.length === 0) {
      log.error('system user was not created correctly');
      throw new Error('Failed to create system user - this will cause FK violations');
    }

  } catch (error) {
    log.error({ err: error }, 'failed to verify/create system user');
    // This is critical for on-premise compatibility - throw to surface configuration issues
    throw error;
  }
}

export async function consolidateDuplicateThreats(): Promise<void> {
  try {
    // Find duplicates using direct query execution
    const duplicatesResult = await db.execute(sql`
      SELECT
        correlation_key,
        COUNT(*) as total,
        ARRAY_AGG(id ORDER BY created_at ASC) as ids
      FROM threats
      WHERE correlation_key IS NOT NULL
      GROUP BY correlation_key
      HAVING COUNT(*) > 1
    `);

    const duplicates = duplicatesResult.rows;

    if (duplicates.length === 0) {
      log.info('no duplicates found');
      return;
    }

    log.info({ count: duplicates?.length || 0 }, 'found keys with duplicates');

    // Consolidate each group of duplicates
    let totalRemoved = 0;

    if (!duplicates || duplicates.length === 0) {
      log.info('no duplicates found to consolidate');
      return;
    }

    for (const duplicate of duplicates) {
      const ids = (duplicate as any).ids as string[];
      const keepId = ids[0]; // Keep the oldest (first in the array)
      const removeIds = ids.slice(1); // Remove the rest

      if (removeIds.length > 0) {
        // Remove status history for duplicates
        await db.execute(sql`
          DELETE FROM threat_status_history
          WHERE threat_id = ANY(${removeIds})
        `);

        // Remove duplicate threats
        await db.execute(sql`
          DELETE FROM threats
          WHERE id = ANY(${removeIds})
        `);

        totalRemoved += removeIds.length;
        log.info({ count: removeIds.length, correlationKey: (duplicate as any).correlation_key }, 'removed duplicates');
      }
    }

    log.info({ totalRemoved }, 'duplicate consolidation completed');

  } catch (error) {
    log.error({ err: error }, 'duplicate consolidation error');
    throw error;
  }
}
