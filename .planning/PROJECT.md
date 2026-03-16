# SamurEye Platform — Product Revision

## What This Is

SamurEye is an Adversarial Exposure Validation platform for medium businesses. It runs automated security journeys (network scanning, AD security assessment, EDR/AV validation, web application testing) using industry tools (nmap, nuclei, PowerShell, smbclient) and translates findings into prioritized, actionable remediation plans. Targeted at sysadmins and junior security analysts who need clear guidance on what to fix first and how.

## Core Value

After running a security journey, the user must walk away with a prioritized, contextualized action plan — not a wall of raw findings.

## Requirements

### Validated

<!-- Shipped and confirmed valuable — existing capabilities from current codebase. -->

- ✓ 4 journey types operational: Attack Surface, AD Security, EDR/AV, Web Application — existing
- ✓ nmap integration: host discovery, port scanning, service detection, vuln scripts — existing
- ✓ nuclei integration: template-based web vulnerability detection (JSONL parsing) — existing
- ✓ PowerShell/WinRM AD security tests: 6 categories (critical config, account mgmt, kerberos, shares/GPOs, policies, inactive accounts) — existing
- ✓ EDR/AV testing via EICAR deployment over SMB with sample rate calculation — existing
- ✓ Threat engine with 30+ detection rules, correlation keys, deduplication — existing
- ✓ CVE enrichment via NVD API — existing
- ✓ Host enrichment via SSH/WMI (OS, services, patches) — existing
- ✓ Role-based access control (global_admin, operator, read_only) — existing
- ✓ Real-time job progress via WebSocket — existing
- ✓ Credential encryption (AES-256-GCM, DEK/KEK) — existing
- ✓ Scheduler for recurring journey execution — existing
- ✓ Email notifications (SMTP/OAuth2) — existing
- ✓ Subscription/license management with read-only mode — existing

### Active

<!-- Current scope — the product revision. -->

- [ ] Improved parsing: nmap output parser captures full script output, service details, and OS detection data
- [ ] Improved parsing: nuclei parser preserves template metadata, matcher details, extracted evidence
- [ ] Improved parsing: AD PowerShell parser retains full context (group membership chains, GPO links, trust attributes)
- [ ] Improved parsing: EDR/AV results include timeline and per-host diagnostic detail
- [ ] Threat grouping: related findings consolidated into single threat (e.g., multiple ports on same host = one "exposed service" threat with details)
- [ ] Contextual severity scoring: scores factor in asset criticality, exposure context, and compensating controls
- [ ] Contextualized remediation: each threat generates specific, actionable recommendations with commands/configs referencing actual hosts, ports, services found
- [ ] Prioritized action plan: post-journey view showing ordered remediation steps with estimated impact per fix
- [ ] Executive dashboard: security posture overview with exposure score, trend over time, top risks, journey coverage
- [ ] Findings redesign: threat detail view restructured to show problem → impact → fix in clear hierarchy
- [ ] Navigation improvement: streamlined flow from dashboard → journey results → specific threat → remediation action
- [ ] Impact visualization: "what improves if I fix this" — projected score change per remediation action
- [ ] Remediation tracking: mark actions as done, see posture improvement after re-scan

### Out of Scope

- AI/LLM-generated recommendations — complexity and cost; static contextual templates are sufficient for v1
- New journey types — focus on improving existing 4 journeys, not adding new ones
- Mobile app — web-first, responsive improvements only
- Multi-tenant architecture — single-tenant appliance model stays
- Agent-based scanning — agentless architecture stays (nmap, nuclei, WinRM, SMB)

## Context

- **Product category**: Adversarial Exposure Validation (AEV) — sits between vulnerability scanning and pentesting
- **Target user**: Mix of sysadmin generalist and junior cybersecurity analyst at medium businesses (50-500 employees)
- **User pain point**: "Não sabe por onde começar" — gets findings but can't prioritize or translate to action
- **Current weakness**: Findings are confusing — parsers lose data, grouping is wrong, scores don't reflect real risk, recommendations are generic
- **Stack**: TypeScript full-stack (React + Express + PostgreSQL), Drizzle ORM, Radix UI + Tailwind CSS
- **Deployment**: Single-port appliance (Express serves both API and static frontend on port 5000)
- **Binary tools**: nmap, nuclei, PowerShell/WinRM, smbclient — spawned as subprocesses

## Constraints

- **Stack**: Must remain TypeScript full-stack (React/Express/PostgreSQL) — no framework migration
- **Binary tools**: Must continue using nmap, nuclei, PowerShell, smbclient — no tool replacement
- **Deployment**: Single appliance model, single port — no microservices
- **UI framework**: Radix UI + Tailwind CSS — no component library migration
- **Backward compatibility**: Existing journey definitions and credentials must continue working after revision
- **Database**: Schema changes must be additive (migrations only, no destructive changes to existing data)

## Key Decisions

<!-- Decisions that constrain future work. Add throughout project lifecycle. -->

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Contextual templates over AI/LLM for recommendations | Cost, latency, reliability for medium business deployments without internet dependency | — Pending |
| Improve existing parsers rather than rewrite from scratch | Preserve working functionality, reduce risk of regression | — Pending |
| Additive schema changes only | Protect existing data, allow rollback | — Pending |
| Threat grouping at engine level, not UI level | Single source of truth for threat count/severity, consistent across dashboard and detail views | — Pending |

---
*Last updated: 2026-03-16 after initialization*
