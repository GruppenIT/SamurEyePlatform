#!/usr/bin/env tsx
/**
 * Phase 12 TEST-01/TEST-02 — Operator CLI for API Passive Tests.
 *
 * Usage:
 *   npx tsx --env-file=.env server/scripts/runApiPassiveTests.ts \
 *     --api=<id> [--no-nuclei] [--no-auth-failure] [--no-api9] [--dry-run] [--credential=<id>]
 *
 * Reads .env for DB + encryption config. Calls runApiPassiveTests() and
 * prints PassiveTestResult as JSON. Exit code 0 on success, 1 on error.
 *
 * Safety:
 *   - Always uses a synthetic UUID for jobId (operator-triggered, not a
 *     scheduled job). Phase 15 orchestration adds real enqueue.
 *   - dryRun forces fixtures — no real HTTP traffic.
 */
import { pathToFileURL } from 'url';
import { runApiPassiveTests } from '../services/journeys/apiPassiveTests';
import type { ApiPassiveTestOpts } from '@shared/schema';
import { randomUUID } from 'crypto';

function parseArgs(argv: string[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {};
  for (const arg of argv) {
    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=');
      if (eq > 0) {
        out[arg.slice(2, eq)] = arg.slice(eq + 1);
      } else {
        out[arg.slice(2)] = true;
      }
    }
  }
  return out;
}

function printUsage(): void {
  console.error(`
Usage:
  npx tsx --env-file=.env server/scripts/runApiPassiveTests.ts \\
    --api=<id> [--no-nuclei] [--no-auth-failure] [--no-api9] [--dry-run] [--credential=<id>]

Required:
  --api=<uuid>              API ID to test

Optional toggles (default: all stages ON):
  --no-nuclei               Skip Nuclei passive scan
  --no-auth-failure         Skip JWT/API key auth-failure tests
  --no-api9                 Skip API9 DB-derived inventory signals
  --dry-run                 Use local fixtures (no HTTP/spawn); findings titled [DRY-RUN]
  --credential=<uuid>       Force specific credential for auth-failure (overrides resolve)

Example:
  npx tsx --env-file=.env server/scripts/runApiPassiveTests.ts --api=abc-123 --dry-run
`);
}

export async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  if (args.help || args.h) {
    printUsage();
    process.exit(0);
  }

  const apiId = typeof args.api === 'string' ? args.api : undefined;
  if (!apiId) {
    console.error('Erro: flag obrigatória --api=<uuid> ausente.');
    printUsage();
    process.exit(1);
  }

  const opts: ApiPassiveTestOpts = {
    stages: {
      nucleiPassive: args['no-nuclei'] !== true,
      authFailure: args['no-auth-failure'] !== true,
      api9Inventory: args['no-api9'] !== true,
    },
    dryRun: args['dry-run'] === true,
  };
  if (typeof args.credential === 'string') {
    opts.credentialIdOverride = args.credential;
  }

  const jobId = randomUUID();

  console.error(
    `[runApiPassiveTests] apiId=${apiId} jobId=${jobId} dryRun=${opts.dryRun ?? false} ` +
      `nuclei=${opts.stages?.nucleiPassive} auth=${opts.stages?.authFailure} api9=${opts.stages?.api9Inventory}`,
  );

  try {
    const result = await runApiPassiveTests(apiId, opts, jobId);
    // Result on stdout (machine-readable); progress/log on stderr.
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.cancelled ? 2 : 0);
  } catch (err) {
    console.error('Erro executando testes passivos:', err instanceof Error ? err.message : err);
    process.exit(1);
  }
}

// Only run main() when invoked directly (not when imported from tests).
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error('Erro não tratado:', err);
    process.exit(1);
  });
}
