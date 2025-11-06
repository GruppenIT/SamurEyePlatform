# SamurEye - Adversarial Exposure Validation Platform

## Overview
SamurEye is a comprehensive cybersecurity platform for continuous adversarial exposure validation. It automates security assessments through Attack Surface scanning, Active Directory analysis, and EDR/AV effectiveness testing. The platform is a full-stack web application designed to identify, track, and reactivate threats, providing real-time vulnerability detection and host management. Its core purpose is to enhance an organization's security posture by proactively discovering and managing cyber risks.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture

### UI/UX Decisions
The application features a dark, security-focused theme built with React, Radix UI, and shadcn/ui. Tailwind CSS and custom CSS properties ensure consistent styling. Key UI elements include interactive filtering tiles for threat intelligence, prominent risk score displays, and redesigned host detail dialogs with historical trend charts and compact threat badges. UI terminology has been updated (e.g., "Hosts" to "Ativos" for assets).

### Technical Implementations
The system is a full-stack application. The frontend uses React 18, TypeScript, TanStack Query for server state, and Wouter for routing. The backend is an Express.js application written in TypeScript, following a modular, service-oriented architecture.

**Key Backend Services:**
- **Job Queue & Journey Executor**: Manages and executes asynchronous security assessment journeys.
- **Threat Engine**: Processes scan results, generates threat intelligence, and supports cross-journey threat reactivation.
- **Encryption Service**: Securely stores credentials using Data Encryption Key (DEK) methodology.
- **CVE Detection Service**: Integrates with NIST NVD for real-time, intelligent CVE analysis with authoritative CPE-based filtering:
  - **CPE Matching (Primary)**: Validates CVEs against detected OS/service versions using NVD CPE configuration data with version range checks (versionStartIncluding/Excluding, versionEndIncluding/Excluding).
  - **Advanced Version Comparison**: Normalizes version comparisons to handle build numbers and trailing zeros correctly. For inclusive bounds, treats extra build segments as equal (e.g., 10.0.19045.452 ≤ 10.0.19045). For exclusive bounds, only non-zero trailing segments count as greater.
  - **Windows Version Extraction**: Extracts Windows versions from both CPE product names and English descriptions for accurate OS matching.
  - **Multi-Strategy Filtering**: Four-tier validation (CPE matching → Windows version extraction → version range parsing → fail-safe rejection) with confidence scoring (high/medium/low).
  - **Keyword Search Fallback**: Only uses keyword-based search when CPE data is unavailable, preventing false positives from cross-OS CVE leakage.

**Authentication & Authorization:**
Local authentication uses bcrypt for password hashing (12 rounds). Session management is handled by `express-session` with PostgreSQL storage, featuring:
- **Session Security**: Global versioning, active session tracking (IP, user agent, device), multi-device management, and immediate revocation.
- **Persistent Rate Limiting**: PostgreSQL-backed tracking of login attempts with lockouts.
- **RBAC System**: Role-based access control with `global_administrator`, `operator`, and `read_only` roles.

**Data Storage:**
PostgreSQL is the primary database, utilizing Drizzle ORM for type-safe operations. It stores users, assets, credentials, journeys, schedules, jobs, threats, audit logs, and hosts. Credentials are encrypted at rest using a KEK/DEK pattern.

**Real-time Communication:**
WebSocket integration provides live updates for job progress, threat notifications, and system status.

**Build System:**
Vite handles the frontend build, while esbuild bundles the backend.

**Core Features & Design Patterns:**
- **Host Management**: Automated discovery, intelligent deduplication, and automatic threat linkage.
- **Threat Lifecycle Management**: Cross-journey threat reactivation and duplicate prevention.
- **Risk Scoring System**: Dual-metric (Risk Score 0-100, Raw Score) assessment with historical tracking, automatic recalculation, and API access for historical data.
- **Asset Types**: Supports `host`, `range` (CIDR), and `web_application` assets.
- **Journey Types**: `attack_surface` (infrastructure discovery), `ad_security` (Active Directory assessment), `edr_av` (EDR/AV testing), and `web_application` (OWASP Top 10 scanning).
- **Attack Surface Journey**: Infrastructure discovery via nmap, smart CVE intelligence using the CVE Detection Service, active validation with nmap vuln scripts, and automatic `web_application` asset discovery.
- **Web Application Journey**: Dedicated OWASP Top 10 scanning using Nuclei for discovered `web_application` assets.
- **OS and Version Detection**: Enhanced nmap usage for accurate OS detection and service version normalization.
- **Email Notification System**: Supports Basic Password, OAuth2 for Google Workspace/Gmail, and OAuth2 for Microsoft 365, with encrypted credentials.
- **Tag-Based Target Selection**: Allows asset selection by individual assets or by tags, expanding tags into asset IDs at execution time.
- **AD Security Journey**: Rewritten using Python WinRM wrapper (`pywinrm`) for 28 PowerShell-based tests across 6 categories. Features DC failover, category toggles, Portuguese keyword enhancement for credential scanning, and comprehensive auditability with `adSecurityTestResults` table storing full execution evidence (PowerShell commands, stdout, stderr, exitCode).
- **Authenticated Scanning (Optional Credentials)**: Complete system for optional credential-based host enrichment in Attack Surface journeys (74% reduction in CVE false positives):
  - **Schema**: `journeyCredentials` junction table links journeys to credentials with priority ordering; `hostEnrichments` stores collected data (OS, apps, patches) plus complete audit trail (commands, stdout, stderr, exitCode).
  - **Collectors**: 
    - **WMICollector** (Windows): Uses pywinrm wrapper to execute PowerShell commands (Get-ComputerInfo for OS details, registry scan for installed apps up to 500, Get-HotFix for KB patches, Get-Service for running services). 30s timeout per attempt.
    - **SSHCollector** (Linux): SSH2-based execution (uname for OS/kernel, dpkg/rpm for package lists up to 1000, systemctl for running services). Auto-detects package manager. 30s timeout per attempt.
  - **Host Enricher Service**: 
    - Pluggable architecture via `IHostCollector` interface allowing easy addition of SNMP or custom protocols
    - **Priority ordering**: Credentials sorted ascending by priority field (0 = highest priority)
    - **Data validation**: Only marks enrichment successful when meaningful data is collected (OS version, apps, patches, or services)
    - **Retry logic**: Per-protocol grouping with exponential backoff (1s, 2s, 4s, 8s...) between failed attempts
    - **Stop-on-success**: First successful credential per protocol prevents unnecessary attempts and account lockouts
    - **Fail-safe**: Enrichment failures never block the scan pipeline; all attempts are logged for troubleshooting
  - **Journey Executor Phase 1.5**: 
    - Executes between Discovery (Phase 1) and CVE Detection (Phase 2)
    - Discovers/creates hosts in database before enrichment
    - Attempts enrichment on each discovered host using configured credentials
    - Persists all enrichment records (success and failure) with full audit trail
    - Detailed logging: protocol, credential used, data collected, success/failure reasons
  - **API Routes**: POST/PATCH /api/journeys accepts `credentials` array with credentialId, protocol, and priority; GET /api/journeys/:id/credentials returns linked credentials
  - **Security**: Credentials decrypted only at execution time using KEK/DEK pattern; passwords never logged or exposed in process lists

## External Dependencies

### Core Frameworks
- `pg` (PostgreSQL driver)
- `drizzle-orm` (Type-safe ORM)
- `express` (Web server framework)
- `@tanstack/react-query` (Server state management)

### UI and Styling
- `@radix-ui/*` (Headless UI components)
- `tailwindcss` (Utility-first CSS framework)
- `class-variance-authority` (Component variant management)
- `lucide-react` (Icon library)

### Authentication and Security
- `passport` (Authentication middleware)
- `bcryptjs` (Password hashing)
- `connect-pg-simple` (PostgreSQL session store)
- `express-session` (Session management)

### Utility Libraries
- `ws` (WebSocket implementation)
- `memoizee` (Function memoization)
- `zod` (Runtime type validation)
- `date-fns` (Date manipulation)