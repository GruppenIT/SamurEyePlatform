# Feature Landscape

**Domain:** Adversarial Exposure Validation (AEV) / Exposure Management for medium businesses
**Researched:** 2026-03-16
**Confidence note:** Based on deep codebase analysis (existing SamurEye implementation) combined with domain knowledge of the AEV/BAS/VM category (Tenable, Qualys, Rapid7, Bishop Fox, Pentera, Cymulate, SafeBreach). Web search was unavailable; all confidence assessments reflect codebase-verified facts vs domain knowledge from training data (cutoff August 2025).

---

## Current State Baseline

SamurEye already ships these features (validated in codebase):
- 4 journey types: Attack Surface, AD Security, EDR/AV, Web Application
- Threat engine: 30+ rules, correlationKey deduplication, severity lifecycle
- Dashboard: posture score (0-100), delta cards, category distribution, activity feed
- Threat view: table with filters, status lifecycle, bulk operations, evidence JSON
- Reports: threat trend, journey summary, AD history, EDR coverage
- Host view: risk score, enrichments, linked threats

The revision targets what is structurally absent or broken: meaningful threat grouping, contextual scoring, actionable remediation, and the narrative flow from "what's wrong" to "how to fix it".

---

## Table Stakes

Features users expect in any AEV/exposure management product. Missing = product feels broken or incomplete. These are **must-have** for the revision.

| Feature | Why Expected | Complexity | Current State | Notes |
|---------|--------------|------------|---------------|-------|
| **Single-threat view with narrative structure** | Users need to understand what happened, why it matters, what to do — in that order | Med | Broken — threat detail shows raw evidence JSON, PowerShell rendered as table, no narrative | Problem → Impact → Fix hierarchy missing |
| **Threat grouping (consolidation)** | A host with 10 open ports should not appear as 10 separate threats; noise overwhelms remediation capacity | High | Broken — flat list, each finding is its own threat regardless of host/service relationship | correlationKey exists but grouping logic is too coarse |
| **Contextual severity scoring** | Score must reflect real exploitability, not just CVSS face value; a critical CVE on an internal host with no external access is less urgent than a high CVE on a public web server | High | Broken — score is CVSS-only, no asset criticality or exposure context factored in | rawScore and riskScore exist but are simple arithmetic on CVSS ranges |
| **Specific, host-referencing remediation** | Recommendations must name the actual host, port, service — not generic "patch OpenSSL" | High | Missing — no remediation content exists beyond generic threat descriptions | This is the core user pain: "I get findings but can't act" |
| **Prioritized action plan (ordered list)** | Post-journey view showing what to fix first with expected impact per fix | High | Missing entirely | Users freeze when confronted with 40 open threats of similar severity |
| **Posture score trend over time** | Users need to see if they're getting better or worse; a single score is not enough | Med | Partially present — sparkline in postura.tsx reads `posture.history` but the score history table exists and needs consistent population | Score history table exists in schema but not reliably written |
| **Remediation tracking (close the loop)** | Mark an action as done; re-scan confirms it; score reflects improvement | Med | Partial — threat status lifecycle exists (open/mitigated/closed) but no connection to "re-scan to verify" or projected score impact | Lifecycle is there; projection and verification loop missing |
| **Finding evidence that makes sense** | Evidence must be human-readable, not raw JSON or unparsed stdout | Med | Broken — evidence is raw JSON blob; PowerShell output is stdout string that needs special parsing in the UI | Parsers lose data; UI tries to salvage with tryParseStdoutObjects() |
| **Severity badges with consistent color semantics** | Users need instant visual triage: critical = red, high = orange, medium = yellow, low = gray | Low | Present and consistent via CSS variables (--severity-critical etc.) | This works; no change needed |
| **Journey execution feedback (real-time progress)** | During a scan, users need to see what's happening | Low | Present — WebSocket progress with task name and percentage | This works well |
| **Threat status lifecycle with audit** | open → investigating → mitigated/closed with justification | Low | Present and complete | This works; keep as-is |

---

## Differentiators

Features that set SamurEye apart from basic vulnerability scanners. Not universally expected in the category, but valued by the target buyer (sysadmin/junior analyst at 100-500 employee company).

| Feature | Value Proposition | Complexity | Current State | Notes |
|---------|-------------------|------------|---------------|-------|
| **Impact visualization: "fix this → score improves by X"** | Makes remediation prioritization tangible: not just "this is critical" but "fixing this raises your score from 42 to 58" | High | Missing | Requires projected score delta per threat; calculable from existing risk score logic |
| **Contextual remediation templates (host-specific commands)** | Instead of "disable SMBv1", produce `Set-SmbServerConfiguration -EnableSMB1Protocol $false` with a note that it applies to host `dc01.empresa.local` | High | Missing | Static templates parameterized with scan data; no LLM required; high signal-to-noise for target user |
| **Journey comparison across runs** | "AD Security improved: 3 new failures vs last week" or "Attack surface grew: 2 new open ports" | Med | Partial — AD history and EDR coverage tabs exist in reports, but no diff / delta view | delta_between_runs concept not implemented |
| **Remediation effort estimation** | Each recommended fix tagged with effort level (< 1 hour, 1 day, 1 week) and role (sysadmin, dev, vendor) | Med | Missing | Allows users to pick "quick wins" vs "long-term fixes" |
| **Threat grouping with rollup view** | Parent threat "Exposed Administration Services on host X" groups child findings (RDP open, WinRM open, SSH open) with individual detail accessible via expand | High | Missing — flat list only | The most visible differentiator for the target user; eliminates "wall of findings" problem |
| **Executive summary / one-page report** | CISO-friendly view: 3 metrics, top 3 risks, trend arrow, compliance posture — exportable | Med | Missing | Distinct from current detailed reports page; this is a summary for non-technical stakeholders |
| **Compensating control detection** | If a host has RDP open but all traffic is behind VPN and firewall rules, severity should be downgraded automatically | Very High | Missing | Requires network topology awareness; out of scope for revision; flag for future |
| **CVE patch intelligence (KB filtering)** | Showing only CVEs not already patched, with 74% false positive reduction | Med | Present and working — existing competitive advantage | Keep; document well for users |
| **Authenticated scan context** | Risk scores factor in what's actually installed (via WMI/SSH enrichment) vs. what nmap detects | Med | Present but scores don't yet fully leverage enrichment data | Enhancement of existing capability |

---

## Anti-Features

Features to explicitly NOT build in this revision. Each has a reason and an alternative.

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| **AI/LLM-generated remediation** | API cost, latency, hallucination risk, offline appliance constraints; out of scope by product decision | Static contextual templates parameterized with scan data — deterministic, fast, offline-capable |
| **New journey types** | Spreading effort thin across 4 working journey types that need depth improvement; out of scope | Make existing 4 journeys produce higher-quality, better-presented output |
| **Compliance report builder (ISO 27001 / PCI-DSS mapping)** | High complexity, low impact for revision milestone; becomes a distraction from core finding quality | Add compliance tags to existing threats (e.g., "relates to PCI DSS 6.3") as metadata only; full report builder is future milestone |
| **CVSS-only scoring display** | Raw CVSS numbers are meaningless to sysadmins who are not security specialists | Translate scores into plain language: "Critical: attacker can take over this server remotely without credentials" |
| **Infinite scrolling threat list** | Creates disorientation; users lose context scrolling through 200 threats | Paginated list + grouped view with expandable parents; max 20 items per page |
| **Per-finding false positive marking without resolution** | Users mark FPs but the threat reappears on the next scan, creating whack-a-mole frustration | Accepted Risk status with justification — already exists; surface it more prominently |
| **Real-time streaming scan output to UI** | Raw nmap/nuclei stdout is noise for the target user; high complexity for WebSocket streaming | Current task name + percentage progress is sufficient; full output available in job results for debugging |
| **Network topology graph visualization** | High complexity, requires graph rendering library, adds little actionable value for sysadmins | Host risk table with sortable columns is sufficient; topology is future enterprise tier feature |
| **Ticket system integration (Jira, ServiceNow)** | Complex auth flows, webhook maintenance, not needed for single-appliance model; adds surface area | Remediation tracking within SamurEye itself (existing status lifecycle) is sufficient |

---

## Feature Dependencies

```
Contextual severity scoring
    → requires: accurate parser output (full evidence data)
    → requires: asset criticality concept (at minimum: host type tag)
    → enables: meaningful prioritized action plan

Threat grouping (consolidation)
    → requires: accurate parser output (consistent host/port/service identifiers)
    → requires: updated correlationKey logic in ThreatEngine
    → enables: impact visualization (score delta per group, not per raw finding)
    → enables: parent/child threat view in UI

Contextual remediation templates
    → requires: specific evidence data per threat (host, port, service, version)
    → requires: static template library (one template per threat rule)
    → enables: prioritized action plan (templates have effort/impact metadata)

Prioritized action plan
    → requires: contextual severity scoring (to order by real risk)
    → requires: contextual remediation templates (to show what to do)
    → requires: threat grouping (to show actions at the right granularity)
    → enables: remediation tracking with verification

Impact visualization ("fix this → score X")
    → requires: contextual severity scoring (to calculate delta)
    → requires: threat grouping (delta per group, not per raw finding)
    → enables: executive summary score projection

Finding evidence redesign (human-readable)
    → requires: improved parsers (nmap, nuclei, AD, EDR — richer structured data)
    → enables: contextual remediation templates (templates can reference real data)
    → enables: contextual severity scoring (more data = better context signals)
```

**Critical path:**
Improved parsers → Threat grouping + Contextual scoring → Remediation templates → Action plan → Impact visualization

All UI improvements depend on the data quality improvements upstream.

---

## Dashboard Patterns (What Users Need vs. What Exists)

### Current Dashboard (postura.tsx)

The current dashboard has the right structure but lacks depth:
- Posture score: present, works, sparkline is small and not labeled
- Delta cards: 4 counters (new threats 24h, open total, critical hosts, running jobs) — useful but none answer "what should I do right now?"
- Top hosts by risk: present, links to /hosts but not to specific threats on that host
- Category distribution: horizontal progress bar, shows open/total per journey — no "click to see threats in this category"
- Activity feed: raw event log, mixes job completions with threat creations — low signal

### What the Dashboard Should Deliver

A sysadmin opening SamurEye after a journey completes needs to answer 3 questions in under 30 seconds:
1. "Is my posture better or worse than last week?" → Score + delta arrow (not just score)
2. "What are the 3 most important things I need to fix?" → Top 3 threats/groups with fix preview
3. "Did my recent changes work?" → Last journey result vs. previous run

### Target Dashboard Structure

| Zone | Content | Priority |
|------|---------|---------|
| **Posture hero** | Score + delta arrow (vs. last run) + trend sparkline labeled by date | Must have |
| **Action required** | Top 3 prioritized remediation actions with effort tag and projected score delta | Must have |
| **Journey coverage** | Grid: 4 journeys, last-run date, pass/fail indicator, click to see results | Must have |
| **Delta cards** | New threats (24h), critical open, hosts at risk, last journey delta | Nice to have |
| **Activity feed** | Keep but filter to threats only; job events to separate "System" panel | Nice to have |

---

## Threat Grouping Patterns

### The Problem

Current state: nmap finds RDP (3389), WinRM (5985), SSH (22) on host `dc01.empresa.local`. This generates 3 separate threats: "RDP Exposed", "WinRM Exposed", "SSH Exposed". Each has its own severity, status, evidence blob. User sees a list of 3 items and must mentally group them.

### Industry Pattern (from Tenable, Qualys, Rapid7)

All major platforms group at two levels:
1. **Finding** (raw scan output — one per service/CVE/test)
2. **Vulnerability** or **Threat** (grouped by type, potentially affecting multiple assets)

SamurEye should mirror this with:
1. **Threat group** (parent): "Exposed Administration Services" on host `dc01.empresa.local`
   - Severity: highest severity among children
   - Status: open if any child is open
   - Remediation: one action plan covering all child findings
2. **Finding** (child): individual port/service/CVE within the group
   - Expandable detail in UI
   - Individual evidence

### Grouping Keys by Journey Type

| Journey | Grouping Dimension | Example Group Name |
|---------|-------------------|--------------------|
| Attack Surface | (host + service_category) | "Exposed Database Services on 192.168.1.10" |
| Attack Surface | (CVE affecting multiple hosts) | "CVE-2021-44228 Log4Shell — 3 hosts affected" |
| AD Security | (test_category) | "Kerberos Delegation Misconfiguration" |
| EDR/AV | (host) | "Unprotected Endpoint: WORKSTATION-42" |
| Web Application | (web_category on URL) | "Authentication Issues on https://app.empresa.com" |

---

## Scoring Model Patterns

### Current Model

`riskScore` (0-100) = calculated from CVSS intervals. Simple bucketing: CVSS 9-10 → 90-100, CVSS 7-8.9 → 70-89, etc. `rawScore` = sum of weighted threat scores.

### What the Scoring Should Reflect

The Gartner CTEM framework and industry practice (HIGH confidence from domain knowledge) uses multi-factor scoring:

| Factor | Weight | Data Source | Current State |
|--------|--------|-------------|---------------|
| CVSS base score | 30% | NVD API | Present |
| Asset criticality | 25% | Host type (server/DC/desktop), tags | Partially present — host type exists in schema |
| Exploitability evidence | 20% | nmap vuln script confirmation, nuclei match confidence | Present but not factored into score |
| Exposure context | 15% | Internal vs external exposure, port accessibility | Missing — needs explicit tagging |
| Compensating controls | 10% | EDR coverage rate, authentication required | Partially present — EDR data exists |

**Practical recommendation for revision:** Don't implement full multi-factor model — that requires significant scoring engine rewrite. Instead:
- Apply multipliers based on existing data: host type (DC gets 1.5x), confirmed exploitability (vuln script hit gets 1.3x), service category (admin services get 1.2x)
- Document the formula explicitly so scores are explainable to users

---

## Remediation Guidance Patterns

### What Good Remediation Looks Like (Industry Standard)

Leading products (Qualys, Rapid7, Tenable) provide for each finding:
1. **What is wrong** (1 sentence)
2. **Why it matters** (business impact, attacker capability)
3. **How to fix it** (specific commands/steps referencing actual host/service data)
4. **References** (CVE link, vendor advisory, MITRE ATT&CK technique)
5. **Verification** (how to confirm the fix worked)

### What SamurEye Has Now

Nothing structured. Threats have a `description` field (free text) and an `evidence` JSON blob. No remediation content. The UI renders the evidence blob with best-effort parsing.

### Static Template Architecture for Revision

For each ThreatRule in `threatEngine.ts`, define a template object:

```typescript
interface RemediationTemplate {
  whatIsWrong: string;                    // static text
  businessImpact: string;                  // static text
  fixSteps: string[];                      // parameterized strings: "On host {{host}}, run: {{command}}"
  parameters: string[];                    // keys from evidence to inject
  effortLevel: 'minutes' | 'hours' | 'days' | 'weeks';
  requiredRole: 'sysadmin' | 'developer' | 'vendor' | 'security';
  verificationStep?: string;               // how to confirm fix
  references: string[];                    // CVE URLs, MITRE ATT&CK URLs
  projectedScoreImpact: number;            // estimated risk score reduction
}
```

Template selection: `ThreatEngine.createThreat()` already knows which rule fired. Templates live alongside rules (same file or adjacent). No new infrastructure needed.

### Remediation Template Coverage (30+ rules, effort estimate)

| Journey | Rule Category | Effort to Template | Example Fix |
|---------|--------------|-------------------|-------------|
| Attack Surface | Exposed admin services (RDP, SSH, WinRM) | Low — deterministic commands exist | Firewall rule, restrict IP range |
| Attack Surface | CVE detection | Med — need per-CVE fix descriptions | KB patch link, version upgrade |
| Attack Surface | Default credentials | Low — same 3-4 fix steps always | Change default password, disable account |
| AD Security | Password policy | Low — PowerShell commands known | Set-ADDefaultDomainPasswordPolicy |
| AD Security | Kerberos delegation | Med — complex, multi-step | Careful, needs AD expertise |
| AD Security | Privileged group membership | Low — remove account from group | Remove-ADGroupMember |
| EDR/AV | Unprotected endpoint | Low — install agent | Install EDR on host X |
| Web Application | Missing security headers | Low — config change | Add headers to web server config |
| Web Application | SSL/TLS issues | Low — reconfigure TLS version | Disable TLS 1.0/1.1 in IIS/nginx |

---

## MVP Recommendation for This Revision

### Prioritize (must ship, directly addresses the stated user pain)

1. **Improved parsers** — Foundation for everything else. Without richer evidence data, grouping and remediation templates are hollow.
2. **Threat grouping at engine level** — Eliminates the "wall of findings" problem. This is the single highest-impact UX improvement.
3. **Contextualized remediation templates** — The core value prop revision: users get "do this on this host" not "here is a generic suggestion".
4. **Prioritized action plan view** — Post-journey screen answering "what do I fix first and why".
5. **Findings redesign (problem → impact → fix hierarchy)** — Restructures the threat detail view to be narrative rather than data-dump.
6. **Contextual severity scoring** — Applies multipliers using existing data (host type, exploitability confirmation, service category).

### Defer (valuable but not critical path for user pain relief)

- **Impact visualization** (score delta per fix): Implement after scoring model is stable. The calculation is straightforward once grouping is in place.
- **Executive dashboard redesign**: Current dashboard is functional; the action plan view is more important for the target user than dashboard aesthetics.
- **Remediation tracking with re-scan verification**: The lifecycle is already there (mitigated/closed); the verification loop (re-scan confirms) is a nice enhancement, not core.
- **Journey comparison / delta between runs**: Good for power users, not the primary pain point.

---

## Feature Dependencies Summary

```
Phase 1 (Foundation)
  improved_parsers → [all subsequent features]

Phase 2 (Core Logic)
  threat_grouping → [action_plan, impact_viz, finding_redesign]
  contextual_scoring → [action_plan, impact_viz]
  remediation_templates → [action_plan, finding_redesign]

Phase 3 (UX Surface)
  action_plan = threat_grouping + contextual_scoring + remediation_templates
  finding_redesign = remediation_templates + improved_parsers
  impact_visualization = contextual_scoring + threat_grouping

Phase 4 (Dashboard & Reporting)
  executive_dashboard = action_plan + posture_trend
  remediation_tracking = existing_lifecycle + re_scan_hook
```

---

## Sources

- SamurEye codebase: `client/src/pages/threats.tsx`, `postura.tsx`, `relatorios.tsx` — direct analysis of current feature state
- SamurEye codebase: `server/services/threatEngine.ts` — threat rule structure and current scoring logic
- SamurEye codebase: `shared/schema.ts` — data model (threats table, riskScore, correlationKey, evidence JSONB)
- SamurEye product doc: `SAMUREYE_PRODUTO.md` — competitive analysis, target users, product decisions
- Project context: `.planning/PROJECT.md` — active requirements, stated weaknesses, out-of-scope items
- Domain knowledge (HIGH confidence, pre-August-2025): Gartner CTEM framework, Tenable/Qualys/Rapid7 feature sets, standard AEV product patterns
- NOTE: Web search unavailable during research; industry comparisons based on training data knowledge. Current product landscape may have evolved for specific vendors, but the category patterns documented here are stable and well-established.
