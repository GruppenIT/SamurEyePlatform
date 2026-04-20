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

    // Phase 3: rule_id column on threats for recommendation template lookup
    await db.execute(sql`
      ALTER TABLE threats ADD COLUMN IF NOT EXISTS rule_id TEXT
    `);
    log.info('threats.rule_id column ensured');

    // Phase 5: edr_deployments table for per-host EDR deployment metadata (PARS-10)
    const edrDeploymentsCheck = await db.execute(sql`
      SELECT tablename FROM pg_tables
      WHERE schemaname = 'public' AND tablename = 'edr_deployments'
    `);

    if ((edrDeploymentsCheck.rowCount ?? 0) === 0) {
      log.info('creating edr_deployments table');
      await db.execute(sql`
        CREATE TABLE IF NOT EXISTS edr_deployments (
          id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid(),
          host_id VARCHAR NOT NULL REFERENCES hosts(id),
          journey_id VARCHAR NOT NULL REFERENCES journeys(id),
          job_id VARCHAR NOT NULL REFERENCES jobs(id),
          deployment_timestamp TIMESTAMPTZ,
          detection_timestamp TIMESTAMPTZ,
          deployment_method TEXT NOT NULL,
          detected BOOLEAN,
          test_duration INTEGER NOT NULL,
          created_at TIMESTAMPTZ DEFAULT now() NOT NULL
        )
      `);
      await db.execute(sql`
        CREATE INDEX "IDX_edr_deployments_journey_id" ON edr_deployments (journey_id)
      `);
      await db.execute(sql`
        CREATE INDEX "IDX_edr_deployments_host_id" ON edr_deployments (host_id)
      `);
      log.info('edr_deployments table created');
    }

    // Phase 9: API Discovery tables (HIER-01, HIER-02, FIND-01)
    await ensureApiTables();

    // Phase 10: API Credentials table (CRED-01..04)
    await ensureApiCredentialTables();

    // Phase 11: httpx enrichment columns on api_endpoints (ENRH-01)
    await ensureApiEndpointHttpxColumns();  // Phase 11 ENRH-01

    // Phase 15: journey_type enum extension + authorizationAck column (JRNY-01, JRNY-02)
    await ensureJourneyApiSecurityColumns();

  } catch (error) {
    log.error({ err: error }, 'database initialization error');
    // Don't throw - let the system continue with fallback mode
  }
}

// Phase 9: API Discovery tables — HIER-01, HIER-02, FIND-01
// Runtime idempotent guard. Replicates edr_deployments pattern exactly (lines 107-136 above).
// Safe to re-run; safe to run after `db:push` has already created the objects.
// Identifiers are quoted in CREATE statements AND in pg_indexes lookups (Pitfall 1 avoidance).
export async function ensureApiTables(): Promise<void> {
  try {
    // ---- pgEnums ----
    // api_type_enum
    const apiTypeEnumCheck = await db.execute(sql`
      SELECT typname FROM pg_type WHERE typname = 'api_type_enum'
    `);
    if ((apiTypeEnumCheck.rowCount ?? 0) === 0) {
      log.info('creating api_type_enum');
      await db.execute(sql`CREATE TYPE api_type_enum AS ENUM ('rest', 'graphql', 'soap')`);
    } else {
      log.info({ hasApiTypeEnum: true }, 'api_type_enum status');
    }

    // owasp_api_category
    const owaspEnumCheck = await db.execute(sql`
      SELECT typname FROM pg_type WHERE typname = 'owasp_api_category'
    `);
    if ((owaspEnumCheck.rowCount ?? 0) === 0) {
      log.info('creating owasp_api_category enum');
      await db.execute(sql`
        CREATE TYPE owasp_api_category AS ENUM (
          'api1_bola_2023','api2_broken_auth_2023','api3_bopla_2023',
          'api4_rate_limit_2023','api5_bfla_2023','api6_business_flow_2023',
          'api7_ssrf_2023','api8_misconfiguration_2023','api9_inventory_2023',
          'api10_unsafe_consumption_2023'
        )
      `);
    } else {
      log.info({ hasOwaspEnum: true }, 'owasp_api_category status');
    }

    // api_finding_status
    const findingStatusEnumCheck = await db.execute(sql`
      SELECT typname FROM pg_type WHERE typname = 'api_finding_status'
    `);
    if ((findingStatusEnumCheck.rowCount ?? 0) === 0) {
      log.info('creating api_finding_status enum');
      await db.execute(sql`
        CREATE TYPE api_finding_status AS ENUM ('open','triaged','false_positive','closed')
      `);
    } else {
      log.info({ hasFindingStatusEnum: true }, 'api_finding_status status');
    }

    // ---- apis table ----
    const apisCheck = await db.execute(sql`
      SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = 'apis'
    `);
    if ((apisCheck.rowCount ?? 0) === 0) {
      log.info('creating apis table');
      await db.execute(sql`
        CREATE TABLE IF NOT EXISTS apis (
          id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid(),
          parent_asset_id VARCHAR NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
          base_url TEXT NOT NULL,
          api_type api_type_enum NOT NULL,
          name TEXT,
          description TEXT,
          spec_url TEXT,
          spec_hash TEXT,
          spec_version TEXT,
          spec_last_fetched_at TIMESTAMPTZ,
          created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
          created_by VARCHAR NOT NULL REFERENCES users(id),
          updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
        )
      `);
      log.info('apis table created');
    }

    // apis indexes (quoted identifiers — Pitfall 1)
    const apisUqCheck = await db.execute(sql`
      SELECT indexname FROM pg_indexes WHERE tablename = 'apis' AND indexname = 'UQ_apis_parent_base_url'
    `);
    if ((apisUqCheck.rowCount ?? 0) === 0) {
      await db.execute(sql`
        CREATE UNIQUE INDEX "UQ_apis_parent_base_url" ON apis (parent_asset_id, base_url)
      `);
      log.info('UQ_apis_parent_base_url created');
    }

    const apisIdxCheck = await db.execute(sql`
      SELECT indexname FROM pg_indexes WHERE tablename = 'apis' AND indexname = 'IDX_apis_parent_asset_id'
    `);
    if ((apisIdxCheck.rowCount ?? 0) === 0) {
      await db.execute(sql`
        CREATE INDEX "IDX_apis_parent_asset_id" ON apis (parent_asset_id)
      `);
      log.info('IDX_apis_parent_asset_id created');
    }

    // ---- api_endpoints table ----
    const endpointsCheck = await db.execute(sql`
      SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = 'api_endpoints'
    `);
    if ((endpointsCheck.rowCount ?? 0) === 0) {
      log.info('creating api_endpoints table');
      await db.execute(sql`
        CREATE TABLE IF NOT EXISTS api_endpoints (
          id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid(),
          api_id VARCHAR NOT NULL REFERENCES apis(id) ON DELETE CASCADE,
          method TEXT NOT NULL,
          path TEXT NOT NULL,
          path_params JSONB NOT NULL DEFAULT '[]'::jsonb,
          query_params JSONB NOT NULL DEFAULT '[]'::jsonb,
          header_params JSONB NOT NULL DEFAULT '[]'::jsonb,
          request_schema JSONB,
          response_schema JSONB,
          requires_auth BOOLEAN,
          discovery_sources TEXT[] NOT NULL DEFAULT ARRAY[]::text[],
          created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
          updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
          CONSTRAINT "CK_api_endpoints_method"
            CHECK (method IN ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'))
        )
      `);
      log.info('api_endpoints table created');
    }

    const endpointsUqCheck = await db.execute(sql`
      SELECT indexname FROM pg_indexes WHERE tablename = 'api_endpoints' AND indexname = 'UQ_api_endpoints_api_method_path'
    `);
    if ((endpointsUqCheck.rowCount ?? 0) === 0) {
      await db.execute(sql`
        CREATE UNIQUE INDEX "UQ_api_endpoints_api_method_path" ON api_endpoints (api_id, method, path)
      `);
      log.info('UQ_api_endpoints_api_method_path created');
    }

    const endpointsIdxCheck = await db.execute(sql`
      SELECT indexname FROM pg_indexes WHERE tablename = 'api_endpoints' AND indexname = 'IDX_api_endpoints_api_id'
    `);
    if ((endpointsIdxCheck.rowCount ?? 0) === 0) {
      await db.execute(sql`CREATE INDEX "IDX_api_endpoints_api_id" ON api_endpoints (api_id)`);
      log.info('IDX_api_endpoints_api_id created');
    }

    // ---- api_findings table ----
    const findingsCheck = await db.execute(sql`
      SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = 'api_findings'
    `);
    if ((findingsCheck.rowCount ?? 0) === 0) {
      log.info('creating api_findings table');
      await db.execute(sql`
        CREATE TABLE IF NOT EXISTS api_findings (
          id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid(),
          api_endpoint_id VARCHAR NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
          job_id VARCHAR REFERENCES jobs(id),
          owasp_category owasp_api_category NOT NULL,
          severity threat_severity NOT NULL,
          status api_finding_status NOT NULL DEFAULT 'open',
          title TEXT NOT NULL,
          description TEXT,
          remediation TEXT,
          risk_score REAL,
          evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
          promoted_threat_id VARCHAR REFERENCES threats(id) ON DELETE SET NULL,
          created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
          updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
        )
      `);
      log.info('api_findings table created');
    }

    // api_findings indexes (5 total)
    for (const [idxName, column] of [
      ['IDX_api_findings_endpoint_id', 'api_endpoint_id'],
      ['IDX_api_findings_job_id', 'job_id'],
      ['IDX_api_findings_owasp_category', 'owasp_category'],
      ['IDX_api_findings_severity', 'severity'],
      ['IDX_api_findings_status', 'status'],
    ] as const) {
      const idxCheck = await db.execute(sql`
        SELECT indexname FROM pg_indexes WHERE tablename = 'api_findings' AND indexname = ${idxName}
      `);
      if ((idxCheck.rowCount ?? 0) === 0) {
        // sql.raw is required here because the identifiers must NOT be parameterized as values.
        await db.execute(sql.raw(`CREATE INDEX "${idxName}" ON api_findings (${column})`));
        log.info(`${idxName} created`);
      }
    }

    log.info('ensureApiTables complete');
  } catch (error) {
    // Follow existing pattern: log but do not throw (app continues in fallback mode).
    log.error({ err: error }, 'ensureApiTables error');
  }
}

// Phase 10 — API Credentials table (CRED-01..04).
// Runtime idempotent guard. Replicates ensureApiTables pattern exactly.
// Safe to re-run; safe to run after `db:push` has already created the objects.
// Identifiers are quoted in CREATE statements AND in pg_indexes lookups.
export async function ensureApiCredentialTables(): Promise<void> {
  try {
    // ---- pgEnum api_auth_type ----
    const enumCheck = await db.execute(sql`
      SELECT typname FROM pg_type WHERE typname = 'api_auth_type'
    `);
    if ((enumCheck.rowCount ?? 0) === 0) {
      log.info('creating api_auth_type enum');
      await db.execute(sql`
        CREATE TYPE api_auth_type AS ENUM (
          'api_key_header',
          'api_key_query',
          'bearer_jwt',
          'basic',
          'oauth2_client_credentials',
          'hmac',
          'mtls'
        )
      `);
    }

    // ---- table api_credentials ----
    const tableCheck = await db.execute(sql`
      SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = 'api_credentials'
    `);
    if ((tableCheck.rowCount ?? 0) === 0) {
      log.info('creating api_credentials table');
      await db.execute(sql`
        CREATE TABLE IF NOT EXISTS api_credentials (
          id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid(),
          name TEXT NOT NULL,
          description TEXT,
          auth_type api_auth_type NOT NULL,
          url_pattern TEXT NOT NULL DEFAULT '*',
          priority INTEGER NOT NULL DEFAULT 100,
          api_id VARCHAR REFERENCES apis(id) ON DELETE SET NULL,
          secret_encrypted TEXT NOT NULL,
          dek_encrypted TEXT NOT NULL,
          api_key_header_name TEXT,
          api_key_query_param TEXT,
          basic_username TEXT,
          bearer_expires_at TIMESTAMP,
          oauth2_client_id TEXT,
          oauth2_token_url TEXT,
          oauth2_scope TEXT,
          oauth2_audience TEXT,
          hmac_key_id TEXT,
          hmac_algorithm TEXT,
          hmac_signature_header TEXT,
          hmac_signed_headers TEXT[],
          hmac_canonical_template TEXT,
          created_at TIMESTAMP NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
          created_by VARCHAR NOT NULL REFERENCES users(id),
          updated_by VARCHAR REFERENCES users(id)
        )
      `);
    }

    // ---- indexes ----
    const INDEXES: Array<[string, string]> = [
      [
        'IDX_api_credentials_api_id',
        `CREATE INDEX "IDX_api_credentials_api_id" ON api_credentials (api_id)`,
      ],
      [
        'IDX_api_credentials_priority',
        `CREATE INDEX "IDX_api_credentials_priority" ON api_credentials (priority)`,
      ],
      [
        'UQ_api_credentials_name_created_by',
        `CREATE UNIQUE INDEX "UQ_api_credentials_name_created_by" ON api_credentials (name, created_by)`,
      ],
    ];

    for (const [idxName, ddl] of INDEXES) {
      const idxCheck = await db.execute(sql`
        SELECT indexname FROM pg_indexes
        WHERE tablename = 'api_credentials' AND indexname = ${idxName}
      `);
      if ((idxCheck.rowCount ?? 0) === 0) {
        log.info({ idxName }, 'creating api_credentials index');
        await db.execute(sql.raw(ddl));
      }
    }

    log.info('ensureApiCredentialTables complete');
  } catch (error) {
    // Follow existing pattern: log but do not throw (app continues in fallback mode).
    log.error({ err: error }, 'ensureApiCredentialTables error');
  }
}

// Phase 11 ENRH-01 — runtime idempotent guard for httpx enrichment columns on api_endpoints.
// Replicates ensureApiTables pattern: ADD COLUMN IF NOT EXISTS against existing table.
// Failures are logged but swallowed so app boot continues (matches ensureApiTables catch).
export async function ensureApiEndpointHttpxColumns(): Promise<void> {
  try {
    await db.execute(sql`
      ALTER TABLE api_endpoints
        ADD COLUMN IF NOT EXISTS httpx_status INTEGER,
        ADD COLUMN IF NOT EXISTS httpx_content_type TEXT,
        ADD COLUMN IF NOT EXISTS httpx_tech TEXT[],
        ADD COLUMN IF NOT EXISTS httpx_tls JSONB,
        ADD COLUMN IF NOT EXISTS httpx_last_probed_at TIMESTAMP
    `);
    log.info('ensureApiEndpointHttpxColumns complete');
  } catch (error) {
    log.error({ err: error }, 'ensureApiEndpointHttpxColumns error');
  }
}

// Phase 15 JRNY-01, JRNY-02 — runtime idempotent guard for journey_type enum extension +
// journeys.authorization_ack column. Drizzle does NOT auto-generate ALTER TYPE ADD VALUE
// migrations (RESEARCH.md §Pitfall 1), so this guard handles it at boot.
// Pattern mirrors ensureApiEndpointHttpxColumns: try/catch with logged failure, no re-throw.
// Safe to re-run; idempotent via IF NOT EXISTS clauses.
export async function ensureJourneyApiSecurityColumns(): Promise<void> {
  try {
    // Extend journey_type enum with 'api_security' value (append-only per Postgres semantics).
    await db.execute(sql`
      ALTER TYPE journey_type ADD VALUE IF NOT EXISTS 'api_security'
    `);

    // Add authorization_ack boolean column with NOT NULL DEFAULT false.
    // Default false keeps existing journeys unaffected (attack_surface/ad_security/edr_av/web_application).
    await db.execute(sql`
      ALTER TABLE journeys
        ADD COLUMN IF NOT EXISTS authorization_ack boolean NOT NULL DEFAULT false
    `);

    log.info('ensureJourneyApiSecurityColumns complete');
  } catch (error) {
    log.error({ err: error }, 'ensureJourneyApiSecurityColumns error');
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
