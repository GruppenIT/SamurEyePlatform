# Phase 1: Parser Foundation - Context

**Gathered:** 2026-03-16
**Status:** Ready for planning

<domain>
## Phase Boundary

All 4 scanner parsers (nmap, nuclei, AD, EDR/AV) produce rich, typed, validated output that the threat engine can consume without data loss. Parsers output discriminated union `NormalizedFinding` types validated by Zod schemas and protected by snapshot tests. No new scanner types, no threat engine changes, no UI changes.

</domain>

<decisions>
## Implementation Decisions

### NormalizedFinding shape
- Discriminated union: each scanner gets its own interface (NmapFinding, NucleiFinding, AdFinding, EdrFinding) extending a common BaseFinding (type discriminator, target, severity, timestamp)
- Threat engine pattern-matches on the `type` discriminator field
- Types and Zod schemas live in `shared/schema.ts` alongside existing Drizzle schemas, imported via `@shared/*`
- Zod validation uses strict mode (`.strip()`) — only declared fields are kept; forces explicit modeling of needed data
- On validation failure: `safeParse()`, log warning with raw data, skip the line. One bad line does not abort the scan

### nmap XML migration
- Full cut-over from text/regex to `-oX -` XML output parsed with `fast-xml-parser` — no text fallback
- All nmap spawning and XML parsing centralized in `networkScanner.ts` — journeyExecutor delegates to networkScanner methods instead of spawning nmap directly
- NSE script inclusion configurable per scan type: `scanPorts()` runs basic detection (`-sV -O`), `scanVulns()` adds `--script=vuln`
- CIDR range scans naturally handled by XML `<host>` elements — current regex host-boundary detection code removed

### Snapshot test strategy
- Synthetic fixtures (hand-crafted XML/JSONL/JSON) for all 4 scanner types, covering each of the 30+ threat rules
- Fixtures stored under `server/__tests__/fixtures/{nmap,nuclei,ad,edr}/`
- Tests structured as full pipeline: load fixture → run parser → feed NormalizedFindings to threat engine rule → snapshot resulting threat object
- Baseline snapshots written BEFORE parser refactor (capturing current threat rule behavior), then updated after refactor with intentional diff review
- Snapshot files in co-located `__snapshots__/` directories (vitest default)

### Evidence preservation — nmap
- NSE script output: structured extraction (CVE IDs, exploit state, vuln name) + raw script text preserved as string
- NseScript interface: `{ id, output, cves?, exploitState?, tables? }`
- OS detection: full OS detail string, CPE strings, accuracy percentage
- Service version: product, version, extrainfo, CPE

### Evidence preservation — nuclei
- Full nuclei `info` block preserved: name, severity, description, tags, classification (cveId, cweId), references, remediation text
- PARS-06 fields: matcher-name, extracted-results, curl-command, template tags — all typed

### Evidence preservation — AD
- Full nested structures from `-Depth 10` PowerShell output
- Group membership chains as ordered string arrays (user → top-level group)
- GPO links as structured objects, trust attributes as typed records
- UAC flags decoded with risk descriptions (existing decoder preserved)
- `rawData: Record<string, unknown>` for full PS output as fallback

### Evidence preservation — EDR/AV
- Per-host event timeline array with granular events: deploy_attempt, deploy_success, detected, not_detected, timeout, cleanup
- Each event: timestamp, action, detail, share (SMB share used)
- Summary fields: detected boolean, sampleRate percentage

### Claude's Discretion
- fast-xml-parser configuration options and parsing details
- Internal helper function decomposition within each parser
- Exact Zod schema field names and nesting (following the interface shapes above)
- How to handle the transition of journeyExecutor's direct nmap calls to networkScanner delegation
- Fixture file naming conventions and coverage per threat rule
- Test runner configuration and parallelization

</decisions>

<specifics>
## Specific Ideas

- Baseline snapshots before refactor is critical — captures current data contract so we can see exactly what changes during migration
- AD scanner already has good UAC and group decoders (`decodeUacFlags`, `WELL_KNOWN_GROUPS`) — preserve and integrate into AdFinding type
- nuclei parser already captures matcher-name and extracted-results in evidence object — extend rather than rewrite
- networkScanner's `commonPorts` array and `AliveHostResult` interface are useful — keep alongside new NmapFinding type

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `networkScanner.ts`: NetworkScanner class with scanPorts, scanCIDR, host discovery — refactor internals, keep public API compatible
- `vulnScanner.ts`: VulnerabilityScanner with nuclei invocation and JSONL parsing — extend evidence capture
- `adScanner.ts`: UAC flag decoder, PrimaryGroupID decoder, PowerShell command builder — preserve all decoders
- `edrAvScanner.ts`: EICAR deployment, secure auth file handling — add timeline tracking to existing flow
- `shared/schema.ts`: Central type/schema location, already uses Zod, imported via `@shared/*`
- `server/lib/logger.ts`: createLogger utility with automatic redaction — use in all parsers

### Established Patterns
- Class-based singleton services (NetworkScanner, VulnerabilityScanner, EDRAVScanner)
- Process spawning via `child_process.spawn` with `processTracker` for cleanup
- Structured logging with pino: `log.warn({ raw, err }, 'message')`
- TypeScript strict mode with ES modules
- Error messages in Portuguese

### Integration Points
- `journeyExecutor.ts` (lines 1317, 1341, 1645): Currently spawns nmap directly and has its own `parseNmapVulnOutput` and `parseNucleiOutput` — must delegate to networkScanner/vulnScanner
- `threatEngine.ts`: Consumes parser output via `detectThreats()` — the 30+ rules define the implicit data contract that snapshot tests must capture
- `server/storage/`: Threat records persisted via Drizzle ORM — NormalizedFinding shape must be serializable to existing threat evidence columns

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 01-parser-foundation*
*Context gathered: 2026-03-16*
