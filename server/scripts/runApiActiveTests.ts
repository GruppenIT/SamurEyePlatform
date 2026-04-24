#!/usr/bin/env tsx
/**
 * Phase 13 TEST-03..07 — Operator CLI for API Active Tests.
 *
 * Usage:
 *   npx tsx --env-file=.env server/scripts/runApiActiveTests.ts \
 *     --api=<id> [--no-bola] [--no-bfla] [--no-bopla] [--no-ssrf] \
 *     [--rate-limit] [--destructive] [--dry-run] [--credential=<id>...]
 *
 * Reads .env for DB + encryption config. Calls runApiActiveTests() and
 * prints ActiveTestResult as JSON to stdout. Exit code 0 on success,
 * 2 if cancelled, 1 on error.
 *
 * Safety gates:
 *   - BOPLA (--destructive): makes real PUT/PATCH requests — use only in dev/staging
 *     with explicit authorization from the system owner. NEVER in production without
 *     formal authorization.
 *   - Rate-Limit (--rate-limit): sends burst of 20 requests in parallel — may trigger
 *     WAF alerts or legitimate rate-limiting. Use only in dev/staging endpoints.
 *   - dryRun (--dry-run): safe in any environment — uses local fixtures, no real requests.
 */
import { pathToFileURL } from 'url';
import { runApiActiveTests } from '../services/journeys/apiActiveTests';
import type { ApiActiveTestOpts } from '@shared/schema';

function parseCliArgs(argv: string[]): Record<string, string | boolean | string[]> {
  const out: Record<string, string | boolean | string[]> = {};
  for (const arg of argv) {
    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=');
      if (eq > 0) {
        const key = arg.slice(2, eq);
        const val = arg.slice(eq + 1);
        // Handle repeatable flags (e.g. --credential=<uuid>)
        if (key in out) {
          const existing = out[key];
          if (Array.isArray(existing)) {
            existing.push(val);
          } else {
            out[key] = [existing as string, val];
          }
        } else {
          out[key] = val;
        }
      } else {
        out[arg.slice(2)] = true;
      }
    }
  }
  return out;
}

function printUsage(): void {
  console.error(`
Uso:
  npx tsx --env-file=.env server/scripts/runApiActiveTests.ts \\
    --api=<id> [opções]

Obrigatório:
  --api=<uuid>          ID da API a testar

Opções (default: BOLA + BFLA + SSRF ON; BOPLA + Rate-Limit OFF):
  --dry-run             Usa fixtures locais — sem requests reais; findings prefixadas [DRY-RUN]
  --no-bola             Desabilita BOLA (API1 cross-identity object access)
  --no-bfla             Desabilita BFLA (API5 privilege escalation)
  --no-bopla            Desabilita BOPLA (API3 mass assignment)
  --no-ssrf             Desabilita SSRF (API7 nuclei+interactsh)
  --rate-limit          Habilita Rate-Limit absence (API4) — opt-in; envia burst de 20 reqs
  --destructive         Habilita BOPLA (faz PUT/PATCH reais — use apenas com autorização explícita)
  --credential=<uuid>   Sobrescreve credenciais para os stages (pode repetir para múltiplas)
  --help                Mostra esta ajuda

Exemplos:
  # dryRun — seguro em qualquer ambiente
  npx tsx --env-file=.env server/scripts/runApiActiveTests.ts --api=<uuid> --dry-run

  # Execução real (BOLA + BFLA + SSRF apenas)
  npx tsx --env-file=.env server/scripts/runApiActiveTests.ts --api=<uuid>

  # Com Rate-Limit opt-in (dev/staging apenas)
  npx tsx --env-file=.env server/scripts/runApiActiveTests.ts --api=<uuid> --rate-limit

  # Com BOPLA destrutivo (requer autorização formal)
  npx tsx --env-file=.env server/scripts/runApiActiveTests.ts --api=<uuid> --destructive

  # Múltiplas credenciais
  npx tsx --env-file=.env server/scripts/runApiActiveTests.ts \\
    --api=<uuid> --credential=<uuid-a> --credential=<uuid-b>

Códigos de saída:
  0  Concluído com sucesso
  1  Erro de execução
  2  Execução cancelada (findings parciais persistidas)
`);
}

function toStringArray(val: string | boolean | string[] | undefined): string[] | undefined {
  if (val === undefined || val === false) return undefined;
  if (Array.isArray(val)) return val as string[];
  if (typeof val === 'string') return [val];
  return undefined;
}

export async function main(): Promise<void> {
  const args = parseCliArgs(process.argv.slice(2));

  if (args['help'] || args['h']) {
    printUsage();
    process.exit(0);
  }

  const apiId = typeof args['api'] === 'string' ? args['api'] : undefined;
  if (!apiId) {
    console.error('Erro: --api=<uuid> é obrigatório');
    printUsage();
    process.exit(1);
  }

  const isDryRun = args['dry-run'] === true;
  const isDestructive = args['destructive'] === true;
  const enableRateLimit = args['rate-limit'] === true;

  const opts: ApiActiveTestOpts = {
    stages: {
      bola: args['no-bola'] !== true,
      bfla: args['no-bfla'] !== true,
      bopla: args['no-bopla'] !== true,
      ssrf: args['no-ssrf'] !== true,
      rateLimit: enableRateLimit,
    },
    destructiveEnabled: isDestructive,
    dryRun: isDryRun,
  };

  const credentialIds = toStringArray(args['credential']);
  if (credentialIds?.length) {
    opts.credentialIds = credentialIds;
  }

  // Progress info on stderr (machine-readable JSON on stdout)
  console.error(`[runApiActiveTests] Iniciando testes ativos — apiId=${apiId} dryRun=${isDryRun}`);
  console.error(`[runApiActiveTests] Stages: bola=${opts.stages?.bola} bfla=${opts.stages?.bfla} bopla=${opts.stages?.bopla} ssrf=${opts.stages?.ssrf} rateLimit=${opts.stages?.rateLimit}`);
  if (!isDestructive) {
    console.error('[runApiActiveTests] BOPLA desabilitado (gate local) — use --destructive para habilitar (requer autorização)');
  }
  if (!enableRateLimit) {
    console.error('[runApiActiveTests] Rate-Limit test desabilitado — use --rate-limit para habilitar (dev/staging apenas)');
  }
  if (isDryRun) {
    console.error('[runApiActiveTests] Modo dryRun — sem requests reais; findings prefixadas [DRY-RUN]');
  }

  try {
    const result = await runApiActiveTests(apiId, opts);
    // Result on stdout (machine-readable); progress/log on stderr.
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.cancelled ? 2 : 0);
  } catch (err) {
    console.error('Erro executando testes ativos:', err instanceof Error ? err.message : err);
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
