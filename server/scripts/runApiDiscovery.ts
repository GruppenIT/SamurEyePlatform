/**
 * CLI operator tool for running API discovery against a registered API.
 *
 * Usage:
 *   npx tsx --env-file=.env server/scripts/runApiDiscovery.ts --api=<id>
 *   npx tsx --env-file=.env server/scripts/runApiDiscovery.ts --api=<id> --no-crawler --kiterunner
 *   npx tsx --env-file=.env server/scripts/runApiDiscovery.ts --api=<id> --arjun-endpoint=<eid1> --arjun-endpoint=<eid2>
 *   npx tsx --env-file=.env server/scripts/runApiDiscovery.ts --api=<id> --dry-run
 *
 * Flags:
 *   --api=<uuid>              Required — target API ID (apis.id)
 *   --no-spec                 Disable spec-first probing (default: enabled)
 *   --no-crawler              Disable Katana crawler (default: enabled)
 *   --kiterunner              Enable Kiterunner brute-force (default: disabled)
 *   --no-httpx                Disable httpx enrichment (default: enabled)
 *   --arjun-endpoint=<uuid>   Enable Arjun for specific GET endpoint ID (repeatable)
 *   --credential=<uuid>       Force specific credential ID (overrides resolveApiCredential)
 *   --dry-run                 Run only spec + httpx stages (disables crawler/kiterunner/arjun)
 *   --katana-depth=<n>        Override katana -d depth (default 3)
 *   --katana-headless         Enable -hl (requires Chrome)
 *   --kiterunner-rate=<n>     Override kiterunner -x (default 5)
 *   --help                    Show this message
 */
import { pathToFileURL } from 'url';
import { discoverApi } from '../services/journeys/apiDiscovery';
import type { DiscoverApiOpts } from '@shared/schema';

interface ParsedArgs {
  apiId?: string;
  noSpec?: boolean;
  noCrawler?: boolean;
  kiterunner?: boolean;
  noHttpx?: boolean;
  arjunEndpointIds: string[];
  credentialId?: string;
  dryRun?: boolean;
  katanaDepth?: number;
  katanaHeadless?: boolean;
  kiterunnerRate?: number;
  help?: boolean;
}

export function parseArgs(argv: string[]): ParsedArgs {
  const parsed: ParsedArgs = { arjunEndpointIds: [] };
  for (const arg of argv) {
    if (arg === '--help' || arg === '-h') parsed.help = true;
    else if (arg === '--no-spec') parsed.noSpec = true;
    else if (arg === '--no-crawler') parsed.noCrawler = true;
    else if (arg === '--kiterunner') parsed.kiterunner = true;
    else if (arg === '--no-httpx') parsed.noHttpx = true;
    else if (arg === '--dry-run') parsed.dryRun = true;
    else if (arg === '--katana-headless') parsed.katanaHeadless = true;
    else if (arg.startsWith('--api=')) parsed.apiId = arg.slice('--api='.length);
    else if (arg.startsWith('--arjun-endpoint=')) parsed.arjunEndpointIds.push(arg.slice('--arjun-endpoint='.length));
    else if (arg.startsWith('--credential=')) parsed.credentialId = arg.slice('--credential='.length);
    else if (arg.startsWith('--katana-depth=')) parsed.katanaDepth = parseInt(arg.slice('--katana-depth='.length), 10);
    else if (arg.startsWith('--kiterunner-rate=')) parsed.kiterunnerRate = parseInt(arg.slice('--kiterunner-rate='.length), 10);
  }
  return parsed;
}

export function argsToOpts(parsed: ParsedArgs): DiscoverApiOpts {
  return {
    stages: {
      spec: !parsed.noSpec,
      crawler: !parsed.noCrawler,
      kiterunner: parsed.kiterunner === true,
      httpx: !parsed.noHttpx,
      arjun: parsed.arjunEndpointIds.length > 0,
    },
    arjunEndpointIds: parsed.arjunEndpointIds.length > 0 ? parsed.arjunEndpointIds : undefined,
    credentialIdOverride: parsed.credentialId,
    dryRun: parsed.dryRun === true,
    katana: (parsed.katanaDepth || parsed.katanaHeadless) ? {
      depth: parsed.katanaDepth,
      headless: parsed.katanaHeadless,
    } : undefined,
    kiterunner: parsed.kiterunnerRate ? { rateLimit: parsed.kiterunnerRate } : undefined,
  };
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const parsed = parseArgs(argv);

  if (parsed.help || !parsed.apiId) {
    console.log(`\nUso: npx tsx --env-file=.env server/scripts/runApiDiscovery.ts --api=<uuid> [opções]\n`);
    console.log(`Flags disponíveis: --no-spec --no-crawler --kiterunner --no-httpx --arjun-endpoint=<id> --credential=<id> --dry-run --katana-depth=<n> --katana-headless --kiterunner-rate=<n> --help\n`);
    process.exit(parsed.apiId ? 0 : 1);
  }

  const opts = argsToOpts(parsed);
  console.log(`\nIniciando discovery para API ${parsed.apiId}`);
  console.log(`   stages: ${JSON.stringify(opts.stages)}`);
  if (opts.arjunEndpointIds) console.log(`   arjunEndpointIds: ${opts.arjunEndpointIds.length}`);
  if (opts.dryRun) console.log(`   dryRun=true — crawler/kiterunner/arjun serao ignorados\n`);

  try {
    const result = await discoverApi(parsed.apiId, opts);
    console.log(`\nDiscovery concluido em ${result.durationMs}ms`);
    console.log(`   stagesRun: ${result.stagesRun.join(', ') || '(none)'}`);
    console.log(`   stagesSkipped: ${result.stagesSkipped.map((s) => `${s.stage} (${s.reason})`).join(', ') || '(none)'}`);
    console.log(`   endpointsDiscovered: ${result.endpointsDiscovered}`);
    console.log(`   endpointsUpdated: ${result.endpointsUpdated}`);
    console.log(`   endpointsStale: ${result.endpointsStale.length}`);
    if (result.specFetched) {
      console.log(`   spec: ${result.specFetched.url} (${result.specFetched.version}) hash=${result.specFetched.hash.slice(0, 16)}...`);
      if (result.specFetched.driftDetected) console.log(`   AVISO: drift detectado!`);
    }
    process.exit(0);
  } catch (err) {
    console.error(`\nDiscovery falhou:`, err);
    process.exit(1);
  }
}

// Named export guard — allows test import without triggering main()
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  void main();
}
