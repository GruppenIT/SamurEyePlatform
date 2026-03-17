# SamurEye Platform — Product Revision

## What This Is

SamurEye is an Adversarial Exposure Validation platform for medium businesses. It runs automated security journeys (network scanning, AD security assessment, EDR/AV validation, web application testing) using industry tools (nmap, nuclei, PowerShell, smbclient) and translates findings into prioritized, actionable remediation plans with contextual scoring, threat grouping, and executive dashboards. Targeted at sysadmins and junior security analysts who need clear guidance on what to fix first and how.

## Core Value

After running a security journey, the user must walk away with a prioritized, contextualized action plan — not a wall of raw findings.

## Current Milestone: v1.1 Close Known Gaps

**Goal:** Close all known gaps from v1.0 — parser depth, test coverage, scoring calibration

**Target features:**
- AD PowerShell -Depth 10 for full nested structures (PARS-07/08)
- EDR per-host timeline with deployment timestamp (PARS-09)
- Full snapshot test coverage for 30+ threat rules (PARS-11)
- Scoring weight calibration against real scan data (THRT-06/08/09)

## Current State

**Shipped:** v1.0 (2026-03-17)
**Stack:** TypeScript full-stack (React + Express + PostgreSQL), Drizzle ORM, Radix UI + Tailwind CSS
**Deployment:** Single-port appliance (Express serves API + Vite frontend)

### What v1.0 Delivered

- Typed, validated parsers for nmap (XML), nuclei (JSONL), AD (PowerShell), EDR (SMB)
- Threat grouping engine with parent/child clusters and journey-specific grouping keys
- Contextual scoring with weighted formula and projected posture delta per threat
- 25 remediation templates with host-specific commands, effort tags, and role requirements
- Redesigned threats page with expandable grouping, structured detail dialog, human-readable evidence
- Action plan page with prioritized cards, filters by effort/role/journey
- Executive dashboard with posture score hero, sparkline, journey coverage, top actions, WebSocket auto-refresh

## Requirements

### Validated

- Nmap XML parser with OS detection, service versions, NSE scripts, CVE refs — v1.0
- Nuclei JSONL parser with Zod validation, matcher-name, extracted-results — v1.0
- NormalizedFinding type system across all 4 parsers — v1.0
- Threat grouping with parent/child clusters and journey-specific keys — v1.0
- Contextual scoring with JSONB score breakdown persistence — v1.0
- Projected posture delta per threat — v1.0
- 25 remediation templates with host-specific data interpolation — v1.0
- Remediation lifecycle: mitigate, verify on re-scan, auto-close — v1.0
- Threat detail: problem/impact/fix hierarchy with human-readable evidence — v1.0
- Action plan: prioritized cards with effort/role filters — v1.0
- Executive dashboard: posture score, sparkline, coverage grid, top actions — v1.0
- WebSocket-triggered dashboard refresh on job completion — v1.0
- Journey comparison delta between snapshots — v1.0

### Active

- [ ] AD PowerShell -Depth 10 for full nested structures (PARS-07/08)
- [ ] EDR per-host timeline with deployment timestamp (PARS-09)
- [ ] Full snapshot test coverage for 30+ threat rules (PARS-11)
- [ ] Scoring weight calibration against real scan data (THRT-06/08/09)

### Out of Scope

- AI/LLM-generated recommendations — complexity and cost; static contextual templates are sufficient
- New journey types — focus on improving existing 4 journeys
- Mobile app — web-first, responsive improvements only
- Multi-tenant architecture — single-tenant appliance model stays
- Agent-based scanning — agentless architecture stays
- Network topology graph visualization — high complexity, low actionable value
- Microservices / message queues — monolith is correct architecture

## Constraints

- **Stack**: TypeScript full-stack (React/Express/PostgreSQL) — no framework migration
- **Binary tools**: nmap, nuclei, PowerShell, smbclient — no tool replacement
- **Deployment**: Single appliance, single port — no microservices
- **UI framework**: Radix UI + Tailwind CSS — no component library migration
- **Backward compatibility**: Existing journey definitions and credentials must continue working
- **Database**: Schema changes must be additive

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Contextual templates over AI/LLM | Cost, latency, reliability for offline appliance | Good — 25 templates cover all rules |
| Improve parsers, not rewrite | Preserve working functionality, reduce regression risk | Good — incremental improvement worked |
| Additive schema changes only | Protect existing data, allow rollback | Good — no data loss |
| Threat grouping at engine level | Single source of truth for count/severity | Good — consistent across all views |
| Self-referential parentThreatId with lambda | Drizzle circular init workaround | Good — clean FK relationship |
| Static TS templates over Handlebars | Type safety, compile-time validation | Good — easy to add new templates |
| Coverage endpoint: 2 queries per journey | Clarity over complex JOIN | Good — maintainable and fast |

---
*Last updated: 2026-03-17 after v1.1 milestone start*
