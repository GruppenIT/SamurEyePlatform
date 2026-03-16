# Technology Stack

**Project:** SamurEye Platform Revision
**Researched:** 2026-03-16
**Scope:** Additive libraries for parsing, threat scoring, visualization, and recommendation engine. Existing stack (React 18 / Express 4 / PostgreSQL / Drizzle / Radix UI / Tailwind) is locked.

---

## What Exists Today

Inventoried from `package.json` and codebase source:

| What | Version | State |
|------|---------|-------|
| recharts | 2.15.2 | Installed. Used in `hosts.tsx` for area chart. A `ChartContainer` wrapper exists in `components/ui/chart.tsx`. Unused for threat/posture dashboards. |
| fast-xml-parser | 5.4.1 | **Transitive dependency only** (comes from another package). Not yet used by application code. |
| zod | 3.24.2 | Installed. Used for API/form validation. Not yet applied to parser output schemas. |
| nmap parser | custom | Plain-text `stdout.split('\n')` regex parser. No `-oX` XML mode. Loses script output, NSE results, structured vuln data. |
| nuclei parser | custom | Line-by-line `JSON.parse` on JSONL. Works but discards: `matcher-name`, `extracted-results`, `curl-command`, template metadata. |
| AD parser | custom | PowerShell JSON stdout fed through `JSON.parse`. No structured typing of UAC flags, group chain data, or trust attributes beyond what the PS script returns. |
| EDR/AV parser | custom | SMB result + sample rate. No per-host timeline, no diagnostic breakdown per host. |

---

## Recommended Additions

### 1. Parsing Layer — Server Side

#### fast-xml-parser 5.4.1 (already in lockfile — promote to direct dependency)

**Purpose:** Parse nmap `-oX` XML output instead of the current plain-text stdout parser.

**Why:** The current `parseNmapOutput` uses regex against text output (`stdout.split('\n')`). This loses structured data that nmap provides only in XML: full NSE/vuln script output per port, CPE strings, OS match accuracy percentages, script output blocks with multi-line content, and hop-by-hop traceroute data. Nmap's `-oX -` flag streams XML to stdout — fast-xml-parser handles it without temp files.

**Why fast-xml-parser over xml2js:** fast-xml-parser has no callback-style API debt, ships TypeScript types, produces plain JS objects with configurable attribute handling, and is already in the lockfile (zero install cost). xml2js is callback-era, has quirky array/object inconsistency, and is unmaintained.

**Confidence:** HIGH — verified present in lockfile at 5.4.1; official API matches use case.

```bash
# Promote to direct dependency (it's already installed):
npm install fast-xml-parser
```

**Usage pattern:**
```typescript
import { XMLParser } from 'fast-xml-parser';
// nmap args: [...existingArgs, '-oX', '-']
const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '$' });
const nmapXml = parser.parse(stdout);
```

---

#### zod (already installed — extend to parser output schemas)

**Purpose:** Define typed schemas for parsed nmap XML, nuclei JSONL, and AD PowerShell output. Validate at parse boundary so downstream threat engine receives well-typed data with known shape.

**Why:** The current parsers use `any` types and `JSON.parse(line)` with no validation. When nuclei output changes field names (which it has — `templateID` vs `template-id` naming inconsistency is already visible in the current code), silent failures occur. Zod parse-at-boundary catches malformed output, produces structured error logs, and gives the threat engine guaranteed typed input.

**Confidence:** HIGH — already installed, already used in API layer, extending to parsers is zero-dependency cost.

**Usage pattern:**
```typescript
const NucleiFindingSchema = z.object({
  'template-id': z.string().optional(),
  templateID: z.string().optional(),
  info: z.object({
    name: z.string(),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
    description: z.string().optional(),
    tags: z.array(z.string()).optional(),
  }),
  'matched-at': z.string().optional(),
  'matcher-name': z.string().optional(),
  'extracted-results': z.array(z.string()).optional(),
  'curl-command': z.string().optional(),
}).passthrough();
```

---

### 2. Threat Grouping and Scoring — Server Side

#### No new library needed. Pattern: pure TypeScript grouping functions with scoring weights table.

**Why no library:** The threat engine already has a `ThreatRule[]` pattern with service category classification. The missing capability is **grouping** (multiple open ports on the same host → one "exposed attack surface" threat with port list as evidence) and **contextual scoring** (CVSS score + asset criticality tier + compensating controls → final severity). Both are algorithmic transformations on existing data structures, not parsing or rendering problems. A library adds dependency surface for what is fundamentally a data mapping function.

**Pattern to adopt:** Scoring weight table as a typed constant, grouping as a reducer over findings keyed by `(host, category)`. No library dependency.

**Confidence:** HIGH — this is the correct architectural call for a stateless transformation function.

---

### 3. Visualization — Client Side

#### recharts 2.15.2 (already installed — extend usage)

**Purpose:** All new charts for executive dashboard, posture trend over time, per-journey severity distribution, and remediation impact projections.

**Why stay with recharts:** It is installed, version 2.15.2 is current (released Feb 2025), a `ChartContainer` wrapper already exists in `components/ui/chart.tsx` with Tailwind-aware CSS overrides. The existing `hosts.tsx` area chart demonstrates the pattern works. Switching to another library (tremor, visx, nivo) would require migrating the wrapper and existing usages for no functional gain. recharts supports all required chart types: AreaChart (trend over time), BarChart (severity distribution), RadialBarChart (exposure score gauge), PieChart (journey coverage).

**Why not visx:** visx (Airbnb) is a low-level D3 wrapper with no chart components — it's a building kit, not a charting library. Appropriate for highly custom visualizations; overkill for standard dashboard charts.

**Why not tremor:** Tremor is a full component library that conflicts with the existing Radix UI + Tailwind setup. It ships its own component primitives that would duplicate/conflict with the existing `components/ui/` layer.

**Why not nivo:** nivo is a viable alternative but introduces a 250KB bundle addition. recharts is already bundled.

**Confidence:** HIGH — verified installed, current version confirmed in lockfile.

**Chart types needed for the revision:**

| Chart | Component | Use Case |
|-------|-----------|----------|
| Posture trend | `AreaChart` | Score over last 30 days — already demonstrated in hosts.tsx |
| Severity distribution | `BarChart` | Threats by severity per journey type |
| Exposure score gauge | `RadialBarChart` | Single score 0-100 on executive dashboard |
| Journey coverage | `PieChart` | % scanned per journey category |
| Impact projection | `BarChart` (horizontal) | "Fix this → score improves by X" |
| Remediation burndown | `AreaChart` | Open vs. resolved threats over time |

---

#### lucide-react 0.453.0 (already installed — use for threat severity/status iconography)

**Purpose:** Consistent iconography for findings list: severity badges, remediation status, journey type indicators.

**Why:** Already installed and used throughout the codebase. No addition needed. Call out explicitly because the posture page and threats page currently mix severity coloring (CSS variables) with ad-hoc icon choices. A standardized icon-per-severity mapping should be codified as a shared constant.

**Confidence:** HIGH — verified installed.

---

### 4. Recommendation Engine — Server Side

#### No new library. Pattern: typed template registry with interpolation function.

**Why no library (and specifically: why not an LLM):** The PROJECT.md explicitly excludes AI/LLM-generated recommendations: "static contextual templates are sufficient for v1." A template engine library (handlebars, mustache, etc.) is heavier than needed for structured text interpolation over a known variable set. The recommendation templates follow a fixed schema: `{host}`, `{port}`, `{service}`, `{cve}`, `{command}` — these can be interpolated with a typed function using TypeScript template literals or a simple `String.prototype.replace` map. The complexity is in the template data (what commands to run for each finding type), not in the interpolation mechanism.

**Pattern to adopt:**

```typescript
interface RemediationTemplate {
  findingType: string;       // Matches threat rule id
  title: string;
  problem: string;
  impact: string;
  steps: RemediationStep[];
  estimatedEffort: 'low' | 'medium' | 'high';
  scoreImpact: number;       // Expected posture score delta after fix
}

interface RemediationStep {
  description: string;       // Template string with {{host}}, {{port}}, {{service}} placeholders
  command?: string;          // Shell/PS command template
  verification?: string;     // How to verify the fix worked
}
```

Store as a static TypeScript file (`server/lib/remediationTemplates.ts`). Interpolate with a `renderTemplate(template, context)` function. No library.

**Confidence:** HIGH — this is an architectural decision, not a library selection problem.

---

### 5. Testing Additions

#### vitest (already installed) — extend with parsing unit tests

**Purpose:** Unit tests for each new structured parser. nmap XML → `PortScanResult[]` round-trips, nuclei JSONL edge cases (field name variants, missing fields, malformed JSON lines), AD PowerShell schema validation.

**Why here:** The existing test suite has `server/__tests__/` but parsers are not unit-tested. The revision introduces structural changes to parsers — these need regression coverage. No new test library needed.

**Confidence:** HIGH — vitest 4.0.18 is installed.

---

## Alternatives Considered

| Category | Recommended | Alternative | Why Not |
|----------|-------------|-------------|---------|
| XML parsing | fast-xml-parser (existing) | xml2js | xml2js has callback-era API, inconsistent array vs object output, unmaintained |
| Charting | recharts (existing) | tremor | Tremor duplicates Radix UI components, conflicts with existing ui layer |
| Charting | recharts (existing) | nivo | Already have recharts installed, nivo adds ~250KB for equivalent functionality |
| Charting | recharts (existing) | visx | visx is a D3 primitive kit, not a chart library; too low-level for standard dashboard needs |
| Template rendering | plain TypeScript functions | handlebars | handlebars adds dependency for string interpolation that TypeScript handles natively |
| Template rendering | plain TypeScript functions | mustache | Same reason as handlebars; adds dependency for a solved problem |
| Threat scoring | typed scoring table | a scoring library | No scoring library exists with security-domain awareness; custom weights are the correct approach |

---

## Installation

**Promote existing transitive dependency to direct:**
```bash
npm install fast-xml-parser
```

**No other new npm packages are required.** All capabilities for the revision are achievable with the existing dependency set: recharts for charts, zod for schema validation at parse boundaries, fast-xml-parser for nmap XML, plain TypeScript for recommendation templates and threat scoring.

---

## Nmap Parser Migration Note

The current parser uses nmap text output. To switch to XML, the `buildNmapArgs` method needs `-oX -` appended to its args. The XML output includes all text output data plus structured extras. The migration is additive — the XML contains everything the text parser currently extracts, plus the fields that are currently lost.

Fields currently lost that XML recovers:
- `<script id="vuln-script" output="...">` blocks with full multi-line vuln evidence
- `<os><osmatch name="..." accuracy="95">` with accuracy percentage
- `<cpe>cpe:/o:microsoft:windows_server_2019</cpe>` structured CPE
- `<service conf="10" method="probed">` detection confidence
- `<state state="open" reason="syn-ack" reason_ttl="128">` — why port is considered open

---

## Sources

- Package versions verified from `/c/Temp/SamurEyePlatform/package-lock.json` (lockfile snapshot, HIGH confidence)
- Parser implementation gaps identified from source reading of `networkScanner.ts`, `vulnScanner.ts`, `adScanner.ts` (HIGH confidence — direct code analysis)
- fast-xml-parser transitive presence: `package-lock.json` line 779 (HIGH confidence)
- recharts current usage: `client/src/components/ui/chart.tsx`, `client/src/pages/hosts.tsx` (HIGH confidence)
- Nmap XML output format: Nmap official documentation (well-established, stable format since nmap 3.x)
- Architecture decisions (no LLM, additive schema changes): `.planning/PROJECT.md` Key Decisions table (HIGH confidence)
