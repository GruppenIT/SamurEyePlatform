# Phase 1: Parser Foundation - Research

**Researched:** 2026-03-16
**Domain:** TypeScript parser refactoring — nmap XML, nuclei JSONL, AD PowerShell, EDR/AV; Zod schemas; vitest snapshot tests
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- Discriminated union `NormalizedFinding`: each scanner gets its own interface (NmapFinding, NucleiFinding, AdFinding, EdrFinding) extending a common BaseFinding (type discriminator, target, severity, timestamp)
- Threat engine pattern-matches on the `type` discriminator field
- Types and Zod schemas live in `shared/schema.ts` alongside existing Drizzle schemas, imported via `@shared/*`
- Zod validation uses strict mode (`.strip()`) — only declared fields are kept; forces explicit modeling
- On validation failure: `safeParse()`, log warning with raw data, skip the line. One bad line does not abort the scan
- Full cut-over from text/regex to `-oX -` XML output parsed with `fast-xml-parser` — no text fallback
- All nmap spawning and XML parsing centralized in `networkScanner.ts` — journeyExecutor delegates instead of spawning nmap directly
- NSE script inclusion configurable per scan type: `scanPorts()` runs `-sV -O`, `scanVulns()` adds `--script=vuln`
- CIDR range scans naturally handled by XML `<host>` elements — current regex host-boundary detection code removed
- Synthetic fixtures (hand-crafted XML/JSONL/JSON) for all 4 scanner types, covering each of the 30+ threat rules
- Fixtures under `server/__tests__/fixtures/{nmap,nuclei,ad,edr}/`
- Tests: load fixture → run parser → feed NormalizedFindings to threat engine rule → snapshot resulting threat object
- Baseline snapshots written BEFORE parser refactor, updated after refactor with intentional diff review
- Snapshot files in co-located `__snapshots__/` directories (vitest default)
- NSE script output: `NseScript { id, output, cves?, exploitState?, tables? }` + raw text preserved
- OS detection: full OS detail string, CPE strings, accuracy percentage
- Service version: product, version, extrainfo, CPE
- Full nuclei `info` block preserved: name, severity, description, tags, classification, references, remediation
- PARS-06 fields: matcher-name, extracted-results, curl-command, template tags — all typed
- AD: full nested structures from `-Depth 10`, group membership chains as ordered string arrays, GPO links as structured objects, trust attributes as typed records, UAC flags decoded with risk descriptions, `rawData: Record<string, unknown>` fallback
- EDR: per-host event timeline array with granular events (deploy_attempt, deploy_success, detected, not_detected, timeout, cleanup); each event: timestamp, action, detail, share

### Claude's Discretion
- fast-xml-parser configuration options and parsing details
- Internal helper function decomposition within each parser
- Exact Zod schema field names and nesting (following the interface shapes above)
- How to handle the transition of journeyExecutor's direct nmap calls to networkScanner delegation
- Fixture file naming conventions and coverage per threat rule
- Test runner configuration and parallelization

### Deferred Ideas (OUT OF SCOPE)
None — discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| PARS-01 | nmap parser uses XML output (`-oX -`) via fast-xml-parser instead of regex text parsing | fast-xml-parser API and nmap XML schema documented below |
| PARS-02 | nmap parser captures full NSE script output blocks with CVE references and vuln details | NseScript interface and XML `<script>` element structure documented below |
| PARS-03 | nmap parser captures OS detection data (name, accuracy, CPE strings) | nmap XML `<os>` element structure documented below |
| PARS-04 | nmap parser captures service version details (product, version, extrainfo, CPE) | nmap XML `<service>` element structure documented below |
| PARS-05 | nuclei parser validates each JSONL line against a Zod schema at parse boundary | Zod `safeParse()` pattern documented; existing `parseNucleiOutput` in both `vulnScanner.ts` and `journeyExecutor.ts` already parse JSONL |
| PARS-06 | nuclei parser captures matcher-name, extracted-results, curl-command, and template tags | nuclei JSONL field names documented below |
| PARS-07 | AD PowerShell scripts use ConvertTo-Json -Depth 10 to preserve nested structures | PowerShell command locations in `adScanner.ts` documented; approach is a grep-and-replace on all `ConvertTo-Json` calls |
| PARS-08 | AD parser captures full group membership chains, GPO links, and trust attributes | Existing decoders (`decodeUacFlags`, `WELL_KNOWN_GROUPS`, `decodeKerberosEtypes`, `decodeTrustDirection`) are all reusable |
| PARS-09 | EDR/AV parser produces per-host timeline with deployment timestamp, detection status, and diagnostic detail | `testSingleHost` in `edrAvScanner.ts` returns a flat `finding` object; needs timeline event array added |
| PARS-10 | All 4 parsers output typed `NormalizedFinding` interfaces validated by Zod schemas | Interface design documented below; Zod already in `package.json` at `^3.24.2` |
| PARS-11 | Snapshot tests exist for all 30+ threat engine rules against known parser outputs before any refactor | vitest `toMatchSnapshot()` API documented; 26 threat rules counted in `threatEngine.ts` (some rules match multiple finding types, total coverage targets ~30 scenarios) |
</phase_requirements>

---

## Summary

Phase 1 replaces ad-hoc text parsing across four scanner files with explicit, typed, Zod-validated output contracts. The codebase already has the scaffolding: Zod is installed, `shared/schema.ts` is the central type file, pino logging is established, and partial evidence capture already exists in both `vulnScanner.ts` and `journeyExecutor.ts` (two overlapping nuclei parsers — both must be addressed).

The primary technical concern is the nmap migration: `networkScanner.ts` contains a 600-line text parser that will be replaced entirely with `fast-xml-parser` consuming `-oX -` XML output. `journeyExecutor.ts` has its own second nmap invocation at line 1277 (`parseNmapVulnOutput`) that must be deleted and delegated to `networkScanner.scanVulns()`. This dual-parser situation is the main code archaeology risk.

Snapshot test ordering is critical: baseline snapshots must be committed before any parser code changes so the diff during refactor is auditable. The 26 rules in `threatEngine.ts` correspond to roughly 30 distinct matching scenarios (some rules have multi-branch matchers). Fixtures need one scenario per matcher branch, not per rule ID.

**Primary recommendation:** Install `fast-xml-parser`, write baseline snapshots first (plan 01-01 first task), then refactor nmap → nuclei → AD → EDR in that order.

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| zod | ^3.24.2 | Runtime schema validation + TypeScript type inference | Already installed; used in `shared/schema.ts` with drizzle-zod |
| fast-xml-parser | ^4.x | Parse nmap `-oX -` XML output to JS objects | Decided in CONTEXT.md; fastest pure-JS XML parser, no DOM overhead |
| vitest | ^4.0.18 | Test runner with snapshot support | Already installed; configured in `vitest.config.ts` |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| pino (via createLogger) | project wrapper | Structured logging with redaction | All parsers — use `createLogger('parserName')` |
| drizzle-zod | ^0.7.0 | Generates Zod schemas from Drizzle tables | Already used; do NOT use for NormalizedFinding (those are not DB rows) |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| fast-xml-parser | xml2js, sax | fast-xml-parser is locked per CONTEXT.md; xml2js uses callback style, sax is streaming only |
| Zod `.strip()` | `.passthrough()` | `.passthrough()` would silently propagate unknown fields; `.strip()` forces explicit modeling per CONTEXT.md |

**Installation:**
```bash
npm install fast-xml-parser
```

---

## Architecture Patterns

### Recommended Project Structure
```
shared/
└── schema.ts            # ADD: BaseFinding, NmapFinding, NucleiFinding, AdFinding, EdrFinding interfaces + Zod schemas

server/
├── services/
│   └── scanners/
│       ├── networkScanner.ts    # REWRITE: parseNmapOutput → parseNmapXml; add scanVulns() method
│       ├── vulnScanner.ts       # EXTEND: replace parseNucleiOutput with Zod-validated version
│       ├── adScanner.ts         # EXTEND: -Depth 10, add AdFinding typed output, preserve all decoders
│       └── edrAvScanner.ts      # EXTEND: add timeline array to testSingleHost result
└── __tests__/
    ├── fixtures/
    │   ├── nmap/                # Hand-crafted XML files (one per nmap threat scenario)
    │   ├── nuclei/              # Hand-crafted JSONL files (one per nuclei threat scenario)
    │   ├── ad/                  # Hand-crafted JSON files (one per AD threat scenario)
    │   └── edr/                 # Hand-crafted JSON files (one per EDR threat scenario)
    ├── __snapshots__/           # Auto-generated by vitest
    ├── nmapParser.test.ts       # Snapshot tests: fixture → parser → threat engine rule → snapshot
    ├── nucleiParser.test.ts
    ├── adParser.test.ts
    └── edrParser.test.ts
```

### Pattern 1: Zod Discriminated Union for NormalizedFinding
**What:** Each scanner type has a dedicated interface extending a common base; Zod schemas mirror the interfaces; the `type` field is a literal that acts as a discriminator.
**When to use:** Whenever threat engine rules need to distinguish scanner source without `instanceof` checks.
**Example:**
```typescript
// shared/schema.ts (new additions — do not modify existing Drizzle tables)
import { z } from 'zod';

export const BaseFindingSchema = z.object({
  type: z.string(),
  target: z.string(),
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  timestamp: z.string().datetime().optional(),
});

export const NseScriptSchema = z.object({
  id: z.string(),
  output: z.string(),
  cves: z.array(z.string()).optional(),
  exploitState: z.string().optional(),
  tables: z.record(z.unknown()).optional(),
});

export const NmapFindingSchema = BaseFindingSchema.extend({
  type: z.literal('port'),
  ip: z.string().optional(),
  port: z.string(),
  state: z.enum(['open', 'closed', 'filtered']),
  service: z.string(),
  // New rich fields
  product: z.string().optional(),
  version: z.string().optional(),
  extrainfo: z.string().optional(),
  serviceCpe: z.string().optional(),
  osName: z.string().optional(),
  osAccuracy: z.number().optional(),
  osCpe: z.array(z.string()).optional(),
  nseScripts: z.array(NseScriptSchema).optional(),
  // Legacy compat (kept for existing threat rules)
  banner: z.string().optional(),
  osInfo: z.string().optional(),
}).strip();

export type NmapFinding = z.infer<typeof NmapFindingSchema>;
// ... NucleiFindingSchema, AdFindingSchema, EdrFindingSchema follow same pattern
```

### Pattern 2: Zod safeParse at Parse Boundary
**What:** Every line/record passes through `safeParse()` before being added to results. Failures are logged and skipped — they do not abort the scan.
**When to use:** All 4 parsers, applied at the point raw external data becomes structured output.
**Example:**
```typescript
// In any parser's line-processing loop
const result = NmapFindingSchema.safeParse(rawObject);
if (!result.success) {
  log.warn({ raw: rawObject, err: result.error.flatten() }, 'nmap finding validation failed — skipping');
  continue;
}
findings.push(result.data); // result.data is fully typed NmapFinding
```

### Pattern 3: fast-xml-parser for nmap XML
**What:** Replace `parseNmapOutput` (text regex) with `parseNmapXml` that processes `-oX -` XML output using `XMLParser`.
**When to use:** PARS-01 — all nmap scanning paths.
**Example:**
```typescript
import { XMLParser } from 'fast-xml-parser';

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  allowBooleanAttributes: true,
  parseAttributeValue: true,
  // Ensure arrays even when single child element present
  isArray: (name) => ['host', 'port', 'script', 'osmatch', 'osclass', 'cpe', 'elem'].includes(name),
});

const xmlDoc = parser.parse(xmlString);
const hosts: any[] = xmlDoc?.nmaprun?.host ?? [];
```

Key nmap XML structure to know:
```xml
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="dc01.corp.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds" product="Microsoft Windows Server 2019" version="..." extrainfo="..." cpe="cpe:/o:microsoft:windows_server_2019"/>
        <script id="smb-vuln-ms17-010" output="VULNERABLE">
          <table key="CVEs"><elem key="CVE number">CVE-2017-0144</elem></table>
        </script>
      </port>
    </ports>
    <os>
      <osmatch name="Windows Server 2019" accuracy="98">
        <osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="2019" accuracy="98">
          <cpe>cpe:/o:microsoft:windows_server_2019</cpe>
        </osclass>
      </osmatch>
    </os>
  </host>
</nmaprun>
```

**Critical `isArray` config:** Without `isArray`, fast-xml-parser returns a single object instead of an array when there is only one `<host>` or `<port>` or `<script>` child. The `isArray` predicate prevents this and makes single-host scan results consistent with multi-host results.

### Pattern 4: nmap Args Change for XML Output
**What:** Add `-oX -` to nmap args; remove text-specific args that are no longer needed; parse stdout as XML.
**When to use:** All `buildNmapArgs` paths in `networkScanner.ts`.
**Example:**
```typescript
// Add to args array (output XML to stdout)
args.push('-oX', '-');
// Remove legacy: no change needed to other args; XML output replaces text output
```

Note: `scanVulns()` is a new method on `NetworkScanner` that adds `--script=vuln --script-args vulns.showall` and delegates from `journeyExecutor.ts`. This replaces the direct nmap spawn at `journeyExecutor.ts:1277`.

### Pattern 5: Snapshot Tests with Vitest
**What:** Each test loads a synthetic fixture file, runs it through the parser, then passes the NormalizedFinding to the relevant threat rule, and snapshots the resulting `InsertThreat` object.
**When to use:** Every distinct threat rule matcher branch — one test per scenario.
**Example:**
```typescript
// server/__tests__/nmapParser.test.ts
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { NetworkScanner } from '../services/scanners/networkScanner';
import { threatEngine } from '../services/threatEngine';

describe('nmap parser → threat engine snapshots', () => {
  it('exposed-service rule: SMB port', async () => {
    const xml = readFileSync(
      join(__dirname, 'fixtures/nmap/smb-open-no-vuln.xml'), 'utf-8'
    );
    const scanner = new NetworkScanner();
    const findings = scanner.parseNmapXml(xml, '192.168.1.1'); // public for testing
    const threats = await threatEngine.analyzeFindings(findings);
    expect(threats).toMatchSnapshot();
  });
});
```

**Baseline snapshot strategy:**
1. Write the test files and fixtures BEFORE touching parser code
2. Run `vitest run` — snapshots are written from current (pre-refactor) behavior
3. Commit snapshots
4. Refactor parser
5. Run `vitest run` again — review any snapshot diffs; update intentionally with `vitest --update-snapshots`

### Anti-Patterns to Avoid
- **Two nuclei parsers:** `vulnScanner.ts:parseNucleiOutput` and `journeyExecutor.ts:parseNucleiOutput` are both active. After Phase 1, only `vulnScanner.ts` version should exist; `journeyExecutor.ts:1645` must be deleted.
- **Parsing in journeyExecutor:** `journeyExecutor.ts:1341 parseNmapVulnOutput` and `journeyExecutor.ts:1645 parseNucleiOutput` bypass the scanner classes. Both must be removed and replaced with delegation.
- **`isArray` omitted in fast-xml-parser:** Without the `isArray` predicate, single-`<host>` results are silently returned as objects instead of arrays, causing runtime crashes on single-host scans.
- **Zod `.passthrough()`:** Allows undeclared fields through; defeats the explicit-modeling goal. Use `.strip()` (strips unknowns) or `.strict()` (throws on unknowns) — CONTEXT.md says `.strip()`.
- **Snapshot tests without baseline commit:** Writing snapshots after refactoring captures the new behavior as "correct" with no reference to the old behavior. The diff is lost.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| XML parsing | Custom regex for nmap XML | fast-xml-parser | nmap XML has deeply nested `<table>` and `<elem>` structures in NSE output; regex cannot handle arbitrary nesting |
| Runtime type guards | Manual `if (typeof x.field === 'string')` chains | Zod `.safeParse()` | Zod generates the TypeScript type AND the runtime validator from one schema; separate guards go stale |
| Test snapshot serialization | Custom JSON serializer for threat objects | vitest built-in snapshot | vitest serializes to `.snap` files automatically with readable diff output |

**Key insight:** nmap NSE script output uses recursive `<table>/<elem>` structures for CVE data. Any regex approach will fail on multi-CVE scripts or nested vuln details.

---

## Common Pitfalls

### Pitfall 1: fast-xml-parser Single-Child Array Collapse
**What goes wrong:** `parser.parse(xml)` returns `host: { ... }` instead of `host: [{ ... }]` when only one `<host>` element exists. Code iterating `hosts.forEach(...)` crashes with "hosts.forEach is not a function".
**Why it happens:** fast-xml-parser collapses single-child arrays to objects by default for JSON-like output.
**How to avoid:** Always pass `isArray: (name) => ['host', 'port', 'script', 'osmatch', 'osclass', 'cpe', 'elem', 'hostname'].includes(name)` in parser options.
**Warning signs:** Tests pass on CIDR scans (multiple hosts) but fail on single-host scans.

### Pitfall 2: nmap `-oX -` Requires No Other Output Flags
**What goes wrong:** If `-oN -` (normal text) is also in args, nmap sends both text and XML to stdout interleaved, breaking XML parsing.
**Why it happens:** Multiple `-o` flags are additive for file targets but `-` means stdout for all of them.
**How to avoid:** Remove all `-oN` / `-oG` flags from `buildNmapArgs`; use only `-oX -`.
**Warning signs:** `XMLParser.parse()` throws "Invalid XML" because text output appears before `<?xml` declaration.

### Pitfall 3: nmap `-O` Requires Root/Privileged
**What goes wrong:** OS detection (`-O`) silently fails or causes nmap to abort with "You requested a scan type which requires root privileges" when the process has no `CAP_NET_RAW`.
**Why it happens:** nmap OS fingerprinting requires raw sockets.
**How to avoid:** The existing `buildNmapArgs` already has a `tcp-fallback` path without `-O`. Ensure that path is preserved in the XML-output refactor. OS data will be absent in the XML `<os>` block; handle gracefully (optional fields in `NmapFinding`).
**Warning signs:** OS fields are always `undefined` in production but populated in local root tests.

### Pitfall 4: journeyExecutor Dual Nuclei Parser Not Removed
**What goes wrong:** `journeyExecutor.ts` still calls its own `parseNucleiOutput` at line 1645, bypassing the Zod-validated `vulnScanner.parseNucleiOutput`. New fields like `curl-command` and `template tags` are captured in `vulnScanner.ts` but threat engine never sees them.
**Why it happens:** There are two independent nuclei parsers — one in `vulnScanner.ts` (class method) and one in `journeyExecutor.ts` (private method). Easy to patch one and forget the other.
**How to avoid:** In plan 01-02, explicitly delete `journeyExecutor.ts:1645-1679` (the private `parseNucleiOutput` method) and wire its call site at line 1630 to use `vulnScanner.parseNuclei(...)` instead.
**Warning signs:** `evidence.curl` is populated in unit tests but missing in end-to-end journey results.

### Pitfall 5: ConvertTo-Json -Depth Not Applied to All PS Commands
**What goes wrong:** Some AD PowerShell queries still use default depth (2), so nested group memberships are serialized as `"Microsoft.ActiveDirectory.Management.ADPropertyValueCollection"` strings instead of arrays.
**Why it happens:** `adScanner.ts` has many PowerShell command strings — easy to miss one.
**How to avoid:** Before writing plan 01-03, grep for all `ConvertTo-Json` occurrences in `adScanner.ts` and patch each one to `ConvertTo-Json -Depth 10`. Confirmed approach from STATE.md blocker note.
**Warning signs:** `evidence.groupMembership` appears as a type name string rather than an array.

### Pitfall 6: Zod Schema in shared/schema.ts Conflicts with Drizzle Code
**What goes wrong:** Adding `NormalizedFinding` Zod schemas to `shared/schema.ts` causes TypeScript errors if variable names clash with existing Drizzle schema exports or if the `z` import conflicts.
**Why it happens:** `shared/schema.ts` is 50KB+ and already imports `z` from `'zod'`. New schemas need to avoid name collisions with existing `insertThreatSchema`, `threatSchema`, etc.
**How to avoid:** Use `NmapFindingSchema`, `NucleiFindingSchema`, `AdFindingSchema`, `EdrFindingSchema` as names (not `threatSchema`, not `findingSchema`). Consider a separate `shared/findings.ts` if the file grows unwieldy — but CONTEXT.md says `shared/schema.ts`, so stay there unless a name collision actually occurs.
**Warning signs:** TypeScript reports "Duplicate identifier" or `tsc` fails with ambiguous type exports.

---

## Code Examples

### fast-xml-parser nmap XML Parse (complete minimal example)
```typescript
// Source: fast-xml-parser official API (verified behavior)
import { XMLParser } from 'fast-xml-parser';

const NMAP_ARRAY_ELEMENTS = new Set([
  'host', 'port', 'script', 'osmatch', 'osclass', 'cpe',
  'elem', 'table', 'hostname', 'address',
]);

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  parseAttributeValue: true,
  allowBooleanAttributes: true,
  isArray: (name) => NMAP_ARRAY_ELEMENTS.has(name),
});

function parseNmapXml(stdout: string, originalTarget: string): NmapFinding[] {
  const doc = xmlParser.parse(stdout);
  const hosts: any[] = doc?.nmaprun?.host ?? [];
  const findings: NmapFinding[] = [];

  for (const host of hosts) {
    const ip = host.address?.find((a: any) => a['@_addrtype'] === 'ipv4')?.['@_addr'] ?? '';
    const hostname = host.hostnames?.hostname?.[0]?.['@_name'] ?? originalTarget;
    const osBestMatch = host.os?.osmatch?.[0];

    for (const port of host.ports?.port ?? []) {
      const state = port.state?.['@_state'];
      if (state !== 'open') continue;

      const svc = port.service ?? {};
      const scripts: NseScript[] = (port.script ?? []).map((s: any) => ({
        id: s['@_id'],
        output: s['@_output'] ?? '',
        cves: extractCvesFromScript(s),
      }));

      const raw = {
        type: 'port' as const,
        target: hostname,
        ip,
        port: String(port['@_portid']),
        state: 'open' as const,
        service: svc['@_name'] ?? 'unknown',
        severity: 'medium' as const,
        product: svc['@_product'],
        version: svc['@_version'],
        extrainfo: svc['@_extrainfo'],
        serviceCpe: svc.cpe?.[0],
        osName: osBestMatch?.['@_name'],
        osAccuracy: osBestMatch ? Number(osBestMatch['@_accuracy']) : undefined,
        osCpe: osBestMatch?.osclass?.flatMap((c: any) => c.cpe ?? []),
        nseScripts: scripts.length ? scripts : undefined,
        // Legacy compat fields
        osInfo: osBestMatch?.['@_name'],
      };

      const result = NmapFindingSchema.safeParse(raw);
      if (!result.success) {
        log.warn({ raw, err: result.error.flatten() }, 'nmap XML finding validation failed');
        continue;
      }
      findings.push(result.data);
    }
  }
  return findings;
}
```

### Nuclei JSONL Field Names (confirmed from vulnScanner.ts existing code)
```typescript
// nuclei JSONL line structure (field names as emitted by nuclei -jsonl)
// NOTE: nuclei uses kebab-case field names in JSON output
interface NucleiRawLine {
  templateID: string;         // template identifier
  'matched-at': string;       // URL that matched
  'matcher-name'?: string;    // PARS-06: which matcher fired
  'extracted-results'?: string[];  // PARS-06: regex/xpath extracted values
  'curl-command'?: string;    // PARS-06: curl reproduction command
  info: {
    name: string;
    severity: string;
    description?: string;
    tags?: string[];           // PARS-06: template tags
    classification?: {
      'cve-id'?: string[];
      'cwe-id'?: string[];
    };
    reference?: string[];
    remediation?: string;
  };
  host: string;
  port?: string;
}
```

### EDR Timeline Event Shape
```typescript
// Per-host timeline event (to be added to EdrFinding)
interface EdrTimelineEvent {
  timestamp: string;          // ISO-8601
  action: 'deploy_attempt' | 'deploy_success' | 'detected' | 'not_detected' | 'timeout' | 'cleanup';
  detail: string;             // Human-readable description of what happened
  share?: string;             // SMB share used (e.g., \\host\C$)
}

interface EdrFinding {
  type: 'edr_test';
  target: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  timestamp: string;
  hostname: string;
  eicarRemoved: boolean | null;
  testDuration: number;
  deploymentMethod: string;
  filePath?: string;
  share?: string;
  error?: string;
  timeline: EdrTimelineEvent[];          // NEW (PARS-09)
  sampleRate?: number;                    // percentage
  detected: boolean | null;
}
```

### AD -Depth 10 Pattern
```typescript
// Pattern to apply: every ConvertTo-Json in adScanner.ts
// Before:
'... | ConvertTo-Json'
'... | ConvertTo-Json -Compress'
// After:
'... | ConvertTo-Json -Depth 10'
'... | ConvertTo-Json -Depth 10 -Compress'
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| nmap text output + regex | nmap `-oX -` XML + fast-xml-parser | Phase 1 | Structured NSE data, OS CPE, service CPE — no regex fragility |
| Implicit `any` finding shape | Discriminated union + Zod `.strip()` | Phase 1 | TypeScript catches contract violations at compile time; unknown fields stripped at runtime |
| Duplicate nuclei parsers in two files | Single Zod-validated parser in `vulnScanner.ts` | Phase 1 | One source of truth; `journeyExecutor.ts` private parser deleted |
| PowerShell `-Depth` default (2) | `-Depth 10` explicit | Phase 1 | Group chains and nested GPO objects survive serialization |

**Deprecated/outdated after Phase 1:**
- `networkScanner.ts:parseNmapOutput` — replaced by `parseNmapXml`
- `journeyExecutor.ts:parseNmapVulnOutput` (line 1341) — replaced by `networkScanner.scanVulns()` delegation
- `journeyExecutor.ts:parseNucleiOutput` (line 1645) — replaced by `vulnScanner.parseNuclei()` delegation
- Direct nmap spawn in `journeyExecutor.ts:1277` — replaced by `networkScanner.scanVulns(host, jobId)`

---

## Open Questions

1. **journeyExecutor scanVulns call site**
   - What we know: `journeyExecutor.ts:1277` spawns nmap `--script=vuln` directly. The surrounding context (lines 1240–1336) is a private method whose name and call site need to be identified.
   - What's unclear: Whether `networkScanner.scanVulns()` should return `NmapFinding[]` (same type as `scanPorts`) or a separate `NmapVulnFinding` type. The threat rule for `nmap_vuln` (finding type at line 150 of `threatEngine.ts`) expects `type === 'nmap_vuln'` not `type === 'port'`. This means `scanVulns()` may need to produce findings with `type: 'nmap_vuln'` rather than `type: 'port'`.
   - Recommendation: Plan 01-01 should clarify the `scanVulns()` return type before committing. A `NmapVulnFinding` extending `BaseFinding` with `type: 'nmap_vuln'` preserves the existing threat rule matcher.

2. **Fixture coverage count**
   - What we know: `threatEngine.ts` has 26 rule objects with `id:` fields. Some rules (e.g., `cve-detected`) match on `finding.type === 'nvd_cve' || finding.type === 'nmap_vuln'` — two scenarios. The AD rules have at least 15 distinct matchers.
   - What's unclear: Exact count of distinct fixture files needed. Rough estimate: ~8 nmap scenarios, ~3 nuclei scenarios, ~15 AD scenarios, ~3 EDR scenarios = ~29 fixtures.
   - Recommendation: Plan 01-03 should enumerate all rule matchers in `threatEngine.ts` and create a coverage table in the test file header comments.

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | vitest ^4.0.18 |
| Config file | `vitest.config.ts` (root) |
| Quick run command | `npx vitest run server/__tests__/nmapParser.test.ts` |
| Full suite command | `npx vitest run` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| PARS-01 | nmap XML parsed without regex | unit | `npx vitest run server/__tests__/nmapParser.test.ts` | ❌ Wave 0 |
| PARS-02 | NSE scripts with CVEs captured | unit (snapshot) | `npx vitest run server/__tests__/nmapParser.test.ts` | ❌ Wave 0 |
| PARS-03 | OS name/accuracy/CPE in NmapFinding | unit (snapshot) | `npx vitest run server/__tests__/nmapParser.test.ts` | ❌ Wave 0 |
| PARS-04 | Service product/version/extrainfo/CPE | unit (snapshot) | `npx vitest run server/__tests__/nmapParser.test.ts` | ❌ Wave 0 |
| PARS-05 | nuclei Zod validation rejects bad lines | unit | `npx vitest run server/__tests__/nucleiParser.test.ts` | ❌ Wave 0 |
| PARS-06 | matcher-name/extracted-results/curl/tags captured | unit (snapshot) | `npx vitest run server/__tests__/nucleiParser.test.ts` | ❌ Wave 0 |
| PARS-07 | PowerShell -Depth 10 produces nested output | unit (fixture-based) | `npx vitest run server/__tests__/adParser.test.ts` | ❌ Wave 0 |
| PARS-08 | Group chains/GPO/trusts in AdFinding | unit (snapshot) | `npx vitest run server/__tests__/adParser.test.ts` | ❌ Wave 0 |
| PARS-09 | Per-host EDR timeline with granular events | unit (snapshot) | `npx vitest run server/__tests__/edrParser.test.ts` | ❌ Wave 0 |
| PARS-10 | All 4 parsers produce NormalizedFinding validated by Zod | unit | `npx vitest run` | ❌ Wave 0 |
| PARS-11 | 30+ threat rule scenarios snapshot-tested before refactor | snapshot | `npx vitest run` | ❌ Wave 0 (MUST be first) |

### Sampling Rate
- **Per task commit:** `npx vitest run server/__tests__/<relevant-test-file>.test.ts`
- **Per wave merge:** `npx vitest run`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
All test files and fixtures are new — none exist yet.
- [ ] `server/__tests__/fixtures/nmap/` — directory + synthetic XML files
- [ ] `server/__tests__/fixtures/nuclei/` — directory + synthetic JSONL files
- [ ] `server/__tests__/fixtures/ad/` — directory + synthetic JSON files
- [ ] `server/__tests__/fixtures/edr/` — directory + synthetic JSON files
- [ ] `server/__tests__/nmapParser.test.ts` — baseline snapshots for PARS-11 (written BEFORE refactor)
- [ ] `server/__tests__/nucleiParser.test.ts`
- [ ] `server/__tests__/adParser.test.ts`
- [ ] `server/__tests__/edrParser.test.ts`
- [ ] `npm install fast-xml-parser` — not yet in package.json

---

## Sources

### Primary (HIGH confidence)
- Codebase direct inspection — `networkScanner.ts`, `vulnScanner.ts`, `adScanner.ts`, `edrAvScanner.ts`, `threatEngine.ts`, `journeyExecutor.ts` (all read in full)
- `shared/schema.ts` — confirmed Zod ^3.24.2 already installed and used
- `vitest.config.ts` — confirmed test configuration (node environment, `server/**/*.test.ts` glob, `@shared` alias)
- `package.json` — confirmed library versions: zod ^3.24.2, vitest ^4.0.18; confirmed fast-xml-parser NOT installed
- `server/__tests__/edrAvScanner.test.ts` — confirmed existing vitest test pattern (describe/it/expect, no mocking framework needed)

### Secondary (MEDIUM confidence)
- fast-xml-parser API: `isArray` option behavior — confirmed via known package behavior (v4.x stable API); installation command verified as `npm install fast-xml-parser`
- nmap XML output schema (`-oX -`): structure confirmed against nmap documentation knowledge (HIGH confidence for `<host>/<ports>/<port>/<service>/<script>/<os>` hierarchy)

### Tertiary (LOW confidence)
- Nuclei JSONL field naming (`matcher-name`, `extracted-results`, `curl-command`): inferred from existing `vulnScanner.ts` code which already accesses these fields (`finding['matcher-name']`, `finding['curl-command']`). The fields exist in nuclei output — LOW only because nuclei output format can vary by template type.

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — libraries either already installed or locked by CONTEXT.md decisions
- Architecture: HIGH — based on direct code reading of all 4 scanner files and threat engine
- Pitfalls: HIGH — all 6 pitfalls derived from observed code patterns in the codebase, not speculation
- Test map: HIGH — vitest snapshot API is stable; test file paths follow established project patterns

**Research date:** 2026-03-16
**Valid until:** 2026-04-16 (30 days — stable TypeScript/Zod/vitest ecosystem)
