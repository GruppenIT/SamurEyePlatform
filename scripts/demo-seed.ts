/**
 * Demo seed: populates the database with realistic demo data for all 5 journey types.
 * Run: DATABASE_URL=... npx tsx scripts/demo-seed.ts
 *
 * This script is idempotent — it truncates demo-related data and re-inserts.
 * It does NOT remove users or system configuration.
 */
import { pool } from "../server/db";

async function demoSeed() {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // ── Resolve users ──────────────────────────────────────────────────────────
    const sysUser = await client.query(
      `SELECT id FROM users WHERE email = 'system@samureye.local' LIMIT 1`
    );
    const systemUserId = sysUser.rows[0]?.id ?? "system";

    const adminUser = await client.query(
      `SELECT id FROM users WHERE role = 'global_administrator' ORDER BY created_at LIMIT 1`
    );
    const adminId = adminUser.rows[0]?.id;
    if (!adminId) throw new Error("Admin user not found. Start the server once to bootstrap the admin.");

    // ── Clear existing demo data (order respects FK constraints) ──────────────
    // Ordem respeita FKs: tabelas filhas antes das pais
    await client.query(`DELETE FROM recommendations`);
    await client.query(`DELETE FROM posture_snapshots`);
    await client.query(`DELETE FROM threats`);
    await client.query(`DELETE FROM api_endpoints`);
    await client.query(`DELETE FROM jobs`);
    await client.query(`DELETE FROM schedules`);
    await client.query(`DELETE FROM journeys`);
    await client.query(`DELETE FROM apis`);
    await client.query(`DELETE FROM host_risk_history`);
    await client.query(`DELETE FROM hosts`);
    await client.query(`DELETE FROM assets`);

    console.log("Cleared existing demo data.");

    // ── Assets ────────────────────────────────────────────────────────────────
    const assetData = [
      { type: "host", value: "192.168.1.10", tags: ["producao", "web"] },
      { type: "host", value: "192.168.1.20", tags: ["producao", "db"] },
      { type: "host", value: "10.0.0.5", tags: ["staging", "app"] },
      { type: "host", value: "10.0.0.1", tags: ["producao", "dc"] },
      { type: "host", value: "10.0.0.254", tags: ["producao", "firewall"] },
      { type: "web_application", value: "https://app.empresa.local", tags: ["web", "producao"] },
      { type: "web_application", value: "https://api.empresa.local", tags: ["api", "producao"] },
      { type: "range", value: "192.168.1.0/24", tags: ["rede-interna"] },
      { type: "range", value: "10.0.0.0/24", tags: ["rede-interna", "servidores"] },
    ];
    const assetIds: string[] = [];
    for (const a of assetData) {
      const res = await client.query(
        `INSERT INTO assets (id, type, value, tags, created_by)
         VALUES (gen_random_uuid(), $1, $2, $3::jsonb, $4) RETURNING id`,
        [a.type, a.value, JSON.stringify(a.tags), adminId]
      );
      assetIds.push(res.rows[0].id);
    }

    // ── Hosts ─────────────────────────────────────────────────────────────────
    const hostData = [
      { name: "srv-web-01", os: "Ubuntu 22.04 LTS",      type: "server",   family: "linux",           ips: ["192.168.1.10"], risk: 78 },
      { name: "srv-db-01",  os: "Windows Server 2022",   type: "server",   family: "windows_server",  ips: ["192.168.1.20"], risk: 65 },
      { name: "srv-app-01", os: "Ubuntu 20.04 LTS",      type: "server",   family: "linux",           ips: ["10.0.0.5"],     risk: 55 },
      { name: "dc01.empresa.local", os: "Windows Server 2019", type: "domain", family: "windows_server", ips: ["10.0.0.1"], risk: 85 },
      { name: "fw-edge-01", os: "FortiOS 7.4.1",         type: "firewall", family: "fortios",         ips: ["10.0.0.254"],   risk: 42 },
      { name: "ws-dev-01",  os: "Windows 11 Pro",        type: "desktop",  family: "windows_desktop", ips: ["192.168.1.100"], risk: 30 },
      { name: "ws-rh-01",   os: "Windows 10 Pro",        type: "desktop",  family: "windows_desktop", ips: ["192.168.1.101"], risk: 22 },
      { name: "srv-bkp-01", os: "Ubuntu 20.04 LTS",      type: "server",   family: "linux",           ips: ["10.0.0.10"],    risk: 48 },
    ];
    const hostIds: string[] = [];
    for (const h of hostData) {
      const res = await client.query(
        `INSERT INTO hosts (id, name, description, operating_system, type, family, ips, risk_score, raw_score)
         VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6::jsonb, $7, $8) RETURNING id`,
        [h.name, `Servidor ${h.name}`, h.os, h.type, h.family, JSON.stringify(h.ips), h.risk, h.risk * 10]
      );
      hostIds.push(res.rows[0].id);
    }

    // ── Journeys (one per type) ────────────────────────────────────────────────
    const journeyDefs = [
      { name: "Varredura de Superfície de Ataque",  type: "attack_surface",  desc: "Mapeamento completo de superfície exposta e portas abertas" },
      { name: "Auditoria de Segurança AD",           type: "ad_security",     desc: "Verificação de políticas, contas e privilégios no Active Directory" },
      { name: "Verificação EDR/AV",                  type: "edr_av",          desc: "Detecção de agentes desatualizados e evasão de EDR" },
      { name: "Scan de Aplicação Web",               type: "web_application", desc: "Análise de vulnerabilidades em aplicações web e APIs" },
      { name: "Descoberta e Teste de APIs",           type: "api_security",    desc: "Inventário e testes de segurança em endpoints de API" },
    ];
    const journeyIds: string[] = [];
    for (const j of journeyDefs) {
      const res = await client.query(
        `INSERT INTO journeys (id, name, type, description, created_by)
         VALUES (gen_random_uuid(), $1, $2, $3, $4) RETURNING id`,
        [j.name, j.type, j.desc, adminId]
      );
      journeyIds.push(res.rows[0].id);
    }

    // ── API asset + endpoints (for api_security journey) ──────────────────────
    const apiAssetId = assetIds[6]; // https://api.empresa.local
    const apiRes = await client.query(
      `INSERT INTO apis (id, parent_asset_id, base_url, api_type, name, description, created_by)
       VALUES (gen_random_uuid(), $1, $2, 'rest', 'API Principal', 'API REST da aplicação principal', $3) RETURNING id`,
      [apiAssetId, "https://api.empresa.local", adminId]
    );
    const apiId = apiRes.rows[0].id;

    const endpointDefs = [
      { method: "GET",    path: "/api/v1/users",              requiresAuth: true,  httpxStatus: 200 },
      { method: "POST",   path: "/api/v1/users",              requiresAuth: true,  httpxStatus: 201 },
      { method: "GET",    path: "/api/v1/users/{id}",         requiresAuth: true,  httpxStatus: 200 },
      { method: "DELETE", path: "/api/v1/users/{id}",         requiresAuth: true,  httpxStatus: 204 },
      { method: "GET",    path: "/api/v1/products",           requiresAuth: false, httpxStatus: 200 },
      { method: "POST",   path: "/api/v1/products",           requiresAuth: true,  httpxStatus: 201 },
      { method: "GET",    path: "/api/v1/orders",             requiresAuth: true,  httpxStatus: 200 },
      { method: "POST",   path: "/api/v1/orders",             requiresAuth: true,  httpxStatus: 201 },
      { method: "GET",    path: "/api/v1/orders/{id}",        requiresAuth: true,  httpxStatus: 200 },
      { method: "GET",    path: "/api/v1/reports/sales",      requiresAuth: true,  httpxStatus: 200 },
      { method: "GET",    path: "/api/v1/health",             requiresAuth: false, httpxStatus: 200 },
      { method: "GET",    path: "/api/v1/admin/config",       requiresAuth: false, httpxStatus: 200 }, // misconfigured
      { method: "POST",   path: "/api/v1/auth/login",         requiresAuth: false, httpxStatus: 200 },
      { method: "POST",   path: "/api/v1/auth/reset-password",requiresAuth: false, httpxStatus: 200 },
      { method: "GET",    path: "/api/v2/users",              requiresAuth: true,  httpxStatus: 200 },
      { method: "GET",    path: "/api/v2/users/{id}/profile", requiresAuth: false, httpxStatus: 200 }, // bola
    ];
    const endpointIds: string[] = [];
    for (const ep of endpointDefs) {
      const res = await client.query(
        `INSERT INTO api_endpoints (id, api_id, method, path, requires_auth, httpx_status, discovery_sources)
         VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, ARRAY['kiterunner']::text[]) RETURNING id`,
        [apiId, ep.method, ep.path, ep.requiresAuth, ep.httpxStatus]
      );
      endpointIds.push(res.rows[0].id);
    }

    // ── Jobs (2 completed per journey, spaced 1 and 7 days ago) ──────────────
    const jobIds: string[] = [];
    for (let ji = 0; ji < journeyIds.length; ji++) {
      for (let run = 0; run < 2; run++) {
        const daysAgo = run === 0 ? 1 : 7;
        const res = await client.query(
          `INSERT INTO jobs (id, journey_id, status, progress, started_at, finished_at, created_at)
           VALUES (gen_random_uuid(), $1, 'completed', 100,
                   NOW() - interval '${daysAgo} days' - interval '12 minutes',
                   NOW() - interval '${daysAgo} days',
                   NOW() - interval '${daysAgo} days' - interval '15 minutes')
           RETURNING id`,
          [journeyIds[ji]]
        );
        jobIds.push(res.rows[0].id);
      }
    }

    // ── Posture snapshots ─────────────────────────────────────────────────────
    const snapshotScores = [
      [72, 65],  // attack_surface improved
      [58, 62],  // ad_security worsened
      [81, 78],  // edr_av improved
      [45, 45],  // web_application stable
      [63, 55],  // api_security improved
    ];
    for (let ji = 0; ji < journeyIds.length; ji++) {
      for (let run = 0; run < 2; run++) {
        const score = snapshotScores[ji][run];
        const openCount = Math.floor((100 - score) / 5);
        const critCount = Math.max(0, Math.floor(openCount * 0.2));
        const highCount = Math.max(0, Math.floor(openCount * 0.3));
        const medCount  = Math.max(0, Math.floor(openCount * 0.3));
        const lowCount  = Math.max(0, openCount - critCount - highCount - medCount);
        const daysAgo = run === 0 ? 1 : 7;
        await client.query(
          `INSERT INTO posture_snapshots (id, job_id, journey_id, score, open_threat_count, critical_count, high_count, medium_count, low_count, scored_at)
           VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, NOW() - interval '${daysAgo} days')`,
          [jobIds[ji * 2 + run], journeyIds[ji], score, openCount, critCount, highCount, medCount, lowCount]
        );
      }
    }

    // ── Host risk history (30-day trend) ──────────────────────────────────────
    for (const hId of hostIds) {
      const baseRisk = Math.floor(Math.random() * 40) + 30;
      for (let d = 30; d >= 0; d--) {
        const drift = Math.floor(Math.random() * 10) - 3;
        const risk = Math.min(100, Math.max(0, baseRisk + drift));
        await client.query(
          `INSERT INTO host_risk_history (id, host_id, risk_score, recorded_at)
           VALUES (gen_random_uuid(), $1, $2, NOW() - interval '${d} days')`,
          [hId, risk]
        );
      }
    }

    // ── Parent threats ────────────────────────────────────────────────────────
    const parentThreats = [
      // attack_surface (ji=0)
      {
        title: "Portas expostas em servidores de produção",
        desc: "Múltiplas portas de serviço expostas sem necessidade em servidores de produção.",
        severity: "critical", category: "attack_surface", hostIdx: 0, assetIdx: 0,
        groupingKey: "exposed-ports-producao",
        evidence: { ports: [22, 80, 443, 3306, 8080], protocol: "TCP", scanDate: "2026-03-15" },
        score: 92, projected: 35, ruleId: "exposed-service",
      },
      {
        title: "Certificados SSL expirados",
        desc: "Certificados SSL/TLS expirados ou próximos da expiração em domínios críticos.",
        severity: "medium", category: "attack_surface", hostIdx: 0, assetIdx: 5,
        groupingKey: "ssl-cert-expired",
        evidence: { domain: "app.empresa.local", expiresAt: "2026-02-28", issuer: "Let's Encrypt" },
        score: 55, projected: 10, ruleId: "ssl-expired",
      },
      {
        title: "Regra de firewall ANY-ANY ativa",
        desc: "Regra de firewall permissiva que permite todo tráfego sem restrição.",
        severity: "high", category: "attack_surface", hostIdx: 4, assetIdx: null,
        groupingKey: "firewall-any-any",
        evidence: { ruleId: "rule-15", action: "allow", source: "any", destination: "any", service: "any" },
        score: 68, projected: 25, ruleId: "firewall-permissive-rule",
      },
      // ad_security (ji=1)
      {
        title: "Contas AD com senha expirada",
        desc: "Contas de serviço com senhas que excedem a política de rotação.",
        severity: "high", category: "ad_security", hostIdx: 3, assetIdx: null,
        groupingKey: "ad-expired-passwords",
        evidence: { accountCount: 12, oldestPasswordAge: "450 dias", policyLimit: "90 dias" },
        score: 78, projected: 45, ruleId: "ad-password-age",
      },
      {
        title: "Usuários no grupo Domain Admins excessivos",
        desc: "O grupo Domain Admins possui mais membros do que o recomendado pela política de segurança.",
        severity: "high", category: "ad_security", hostIdx: 3, assetIdx: null,
        groupingKey: "ad-domain-admins-excess",
        evidence: { groupName: "Domain Admins", memberCount: 12, expectedMax: 5, members: ["admin1", "svc-backup", "jsilva", "mcarvalho", "admin2"] },
        score: 74, projected: 50, ruleId: "ad-privileged-group-excess",
      },
      // edr_av (ji=2)
      {
        title: "EDR desatualizado em endpoints",
        desc: "Agente EDR com versão desatualizada em múltiplos endpoints.",
        severity: "high", category: "edr_av", hostIdx: 5, assetIdx: null,
        groupingKey: "edr-outdated-agents",
        evidence: { currentVersion: "3.2.1", requiredVersion: "4.1.0", affectedCount: 8 },
        score: 71, projected: 55, ruleId: "edr-outdated",
      },
      // web_application (ji=3)
      {
        title: "Vulnerabilidades CVE em aplicação web",
        desc: "CVEs conhecidas com exploits públicos encontradas na aplicação web principal.",
        severity: "critical", category: "web_application", hostIdx: 2, assetIdx: 5,
        groupingKey: "web-cve-detected",
        evidence: { cves: ["CVE-2024-1234", "CVE-2024-5678", "CVE-2023-9012"], cvssMax: 9.8 },
        score: 95, projected: 30, ruleId: "cve-detected",
      },
      // api_security (ji=4)
      {
        title: "Endpoint administrativo exposto sem autenticação",
        desc: "Endpoint /api/v1/admin/config retorna dados sensíveis de configuração sem autenticação.",
        severity: "critical", category: "api_security", hostIdx: 2, assetIdx: 6,
        groupingKey: "api-admin-exposed",
        evidence: { endpoint: "/api/v1/admin/config", method: "GET", requiresAuth: false, httpxStatus: 200, responseContains: ["db_host", "secret_key"] },
        score: 97, projected: 10, ruleId: "api-unprotected-admin",
      },
      {
        title: "BOLA — Broken Object Level Authorization em /users/{id}",
        desc: "Endpoint de perfil de usuário acessível sem autenticação permite enumeração de dados.",
        severity: "high", category: "api_security", hostIdx: 2, assetIdx: 6,
        groupingKey: "api-bola-users",
        evidence: { endpoint: "/api/v2/users/{id}/profile", method: "GET", requiresAuth: false, owasp: "API1:2023", cvssEstimate: 8.1 },
        score: 83, projected: 20, ruleId: "api-bola",
      },
    ];

    const parentThreatIds: string[] = [];
    // Map category → ji index
    const catToJi: Record<string, number> = {
      attack_surface: 0, ad_security: 1, edr_av: 2, web_application: 3, api_security: 4,
    };

    for (const t of parentThreats) {
      const ji = catToJi[t.category];
      const res = await client.query(
        `INSERT INTO threats (id, title, description, severity, status, source, host_id, asset_id,
                              evidence, category, grouping_key, contextual_score, projected_score_after_fix,
                              rule_id, job_id, correlation_key, score_breakdown)
         VALUES (gen_random_uuid(),$1,$2,$3,'open','journey',$4,$5,$6::jsonb,$7,$8,$9,$10,$11,$12,$13,$14::jsonb)
         RETURNING id`,
        [
          t.title, t.desc, t.severity,
          hostIds[t.hostIdx],
          t.assetIdx !== null ? assetIds[t.assetIdx] : null,
          JSON.stringify(t.evidence),
          t.category, t.groupingKey, t.score, t.projected, t.ruleId,
          jobIds[ji * 2],
          `${t.ruleId}-${t.groupingKey}`,
          JSON.stringify({ baseSeverityWeight: 0.4, criticalityMultiplier: 1.2, exposureFactor: 0.8, controlsReductionFactor: 0.1, exploitabilityMultiplier: 1.0, rawScore: t.score, normalizedScore: t.score }),
        ]
      );
      parentThreatIds.push(res.rows[0].id);
    }

    // ── Child threats ─────────────────────────────────────────────────────────
    type ChildThreat = {
      title: string; severity: string; evidence: object; hostIdx: number;
    };
    const childGroups: ChildThreat[][] = [
      // 0: exposed-ports (parent 0)
      [
        { title: "Porta 3306 (MySQL) exposta em srv-web-01", severity: "critical", evidence: { port: 3306, service: "MySQL 8.0", state: "open" }, hostIdx: 0 },
        { title: "Porta 8080 (HTTP alternativa) exposta em srv-web-01", severity: "high", evidence: { port: 8080, service: "Apache Tomcat", state: "open" }, hostIdx: 0 },
        { title: "Porta 22 (SSH) com autenticação por senha", severity: "medium", evidence: { port: 22, service: "OpenSSH 8.9", authMethod: "password", state: "open" }, hostIdx: 0 },
      ],
      // 1: ssl-cert-expired (parent 1)
      [
        { title: "Certificado expirado em app.empresa.local:443", severity: "medium", evidence: { domain: "app.empresa.local", port: 443, expiresAt: "2026-02-28", daysExpired: 17 }, hostIdx: 0 },
      ],
      // 2: firewall-any-any (parent 2)
      [
        { title: "Tráfego de saída irrestrito no fw-edge-01", severity: "high", evidence: { ruleId: "rule-15", direction: "egress", protocol: "any" }, hostIdx: 4 },
        { title: "Tráfego lateral entre VLANs sem inspeção", severity: "medium", evidence: { ruleId: "rule-22", direction: "lateral", affectedVlans: ["vlan10", "vlan20"] }, hostIdx: 4 },
      ],
      // 3: ad-expired-passwords (parent 3)
      [
        { title: "Conta svc-backup com senha de 450 dias", severity: "high", evidence: { account: "svc-backup", passwordAge: "450 dias", lastLogon: "2026-01-10" }, hostIdx: 3 },
        { title: "Conta svc-sql com senha de 380 dias", severity: "high", evidence: { account: "svc-sql", passwordAge: "380 dias", lastLogon: "2026-03-01" }, hostIdx: 3 },
      ],
      // 4: ad-domain-admins-excess (parent 4)
      [
        { title: "Conta jsilva no grupo Domain Admins sem justificativa", severity: "high", evidence: { account: "jsilva", group: "Domain Admins", addedAt: "2025-11-20", justification: null }, hostIdx: 3 },
        { title: "Conta de serviço svc-backup com privilégios de DA", severity: "critical", evidence: { account: "svc-backup", group: "Domain Admins", risk: "service account should not be DA" }, hostIdx: 3 },
      ],
      // 5: edr-outdated (parent 5)
      [
        { title: "EDR v3.2.1 em ws-dev-01", severity: "medium", evidence: { hostname: "ws-dev-01", currentVersion: "3.2.1", expectedVersion: "4.1.0" }, hostIdx: 5 },
        { title: "EDR v3.0.0 em srv-app-01", severity: "high", evidence: { hostname: "srv-app-01", currentVersion: "3.0.0", expectedVersion: "4.1.0" }, hostIdx: 2 },
        { title: "EDR ausente em ws-rh-01", severity: "high", evidence: { hostname: "ws-rh-01", status: "not_installed" }, hostIdx: 6 },
      ],
      // 6: cve-detected (parent 6)
      [
        { title: "CVE-2024-1234: RCE em Spring Framework (CVSS 9.8)", severity: "critical", evidence: { cve: "CVE-2024-1234", cvss: 9.8, component: "Spring Framework", fixVersion: "6.1.5" }, hostIdx: 2 },
        { title: "CVE-2024-5678: SQL Injection em Hibernate (CVSS 8.1)", severity: "critical", evidence: { cve: "CVE-2024-5678", cvss: 8.1, component: "Hibernate ORM", fixVersion: "6.4.2" }, hostIdx: 2 },
        { title: "CVE-2023-9012: XSS em Thymeleaf (CVSS 6.5)", severity: "medium", evidence: { cve: "CVE-2023-9012", cvss: 6.5, component: "Thymeleaf", fixVersion: "3.1.3" }, hostIdx: 2 },
      ],
      // 7: api-admin-exposed (parent 7)
      [
        { title: "Resposta com db_host exposta em /admin/config", severity: "critical", evidence: { endpoint: "/api/v1/admin/config", field: "db_host", value: "192.168.1.20:5432" }, hostIdx: 2 },
        { title: "Secret key exposta em resposta JSON", severity: "critical", evidence: { endpoint: "/api/v1/admin/config", field: "secret_key", valueLength: 64 }, hostIdx: 2 },
      ],
      // 8: api-bola (parent 8)
      [
        { title: "Perfil de usuário admin acessível sem token", severity: "high", evidence: { endpoint: "/api/v2/users/1/profile", httpxStatus: 200, dataExposed: ["email", "phone", "address"] }, hostIdx: 2 },
      ],
    ];

    for (let pi = 0; pi < childGroups.length; pi++) {
      const parent = parentThreats[pi];
      const ji = catToJi[parent.category];
      for (const child of childGroups[pi]) {
        const childScore = Math.max(20, (parent.score) - Math.floor(Math.random() * 20 + 5));
        await client.query(
          `INSERT INTO threats (id, title, description, severity, status, source, host_id,
                                evidence, category, parent_threat_id, contextual_score,
                                projected_score_after_fix, rule_id, job_id, correlation_key, score_breakdown)
           VALUES (gen_random_uuid(),$1,$2,$3,'open','journey',$4,$5::jsonb,$6,$7,$8,$9,$10,$11,$12,$13::jsonb)`,
          [
            child.title, child.title, child.severity,
            hostIds[child.hostIdx],
            JSON.stringify(child.evidence),
            parent.category, parentThreatIds[pi],
            childScore, Math.max(10, childScore - 30),
            parent.ruleId, jobIds[ji * 2],
            `${parent.ruleId}-${child.title.slice(0, 40).replace(/\s/g, "-").toLowerCase()}`,
            JSON.stringify({ baseSeverityWeight: 0.3, criticalityMultiplier: 1.0, exposureFactor: 0.7, controlsReductionFactor: 0.1, exploitabilityMultiplier: 1.0, rawScore: childScore, normalizedScore: childScore }),
          ]
        );
      }
    }

    // ── Standalone threats ────────────────────────────────────────────────────
    const standaloneThreats = [
      {
        title: "Serviço FTP sem criptografia ativo",
        severity: "medium", category: "attack_surface", hostIdx: 1,
        evidence: { port: 21, service: "vsftpd 3.0.5", encryption: "none", state: "open" },
        score: 48, projected: 5, ruleId: "unencrypted-service",
      },
      {
        title: "SMB v1 habilitado em servidor de DB",
        severity: "high", category: "attack_surface", hostIdx: 1,
        evidence: { port: 445, protocol: "SMBv1", cve: "MS17-010", knownExploit: "EternalBlue" },
        score: 82, projected: 15, ruleId: "smb-v1-enabled",
      },
      {
        title: "Kerberoasting: SPN expostos em contas de serviço",
        severity: "high", category: "ad_security", hostIdx: 3,
        evidence: { spnCount: 4, crackableHashes: 4, accounts: ["svc-sql", "svc-backup", "svc-web", "svc-report"] },
        score: 79, projected: 30, ruleId: "ad-kerberoasting",
      },
      {
        title: "Rate limiting ausente em endpoint de autenticação",
        severity: "medium", category: "api_security", hostIdx: 2,
        evidence: { endpoint: "/api/v1/auth/login", rateLimitHeader: null, bruteForceRisk: "high", tested: "1000 req/min sem bloqueio" },
        score: 67, projected: 20, ruleId: "api-no-rate-limit",
      },
    ];

    for (const t of standaloneThreats) {
      const ji = catToJi[t.category];
      await client.query(
        `INSERT INTO threats (id, title, description, severity, status, source, host_id,
                              evidence, category, contextual_score, projected_score_after_fix,
                              rule_id, job_id, correlation_key, score_breakdown)
         VALUES (gen_random_uuid(),$1,$2,$3,'open','journey',$4,$5::jsonb,$6,$7,$8,$9,$10,$11,$12::jsonb)`,
        [
          t.title, t.title, t.severity,
          hostIds[t.hostIdx],
          JSON.stringify(t.evidence),
          t.category, t.score, t.projected, t.ruleId,
          jobIds[ji * 2],
          `${t.ruleId}-standalone-${t.hostIdx}`,
          JSON.stringify({ baseSeverityWeight: 0.3, criticalityMultiplier: 1.0, exposureFactor: 0.6, controlsReductionFactor: 0.1, exploitabilityMultiplier: 1.0, rawScore: t.score, normalizedScore: t.score }),
        ]
      );
    }

    // ── Recommendations ───────────────────────────────────────────────────────
    const recTemplates: Record<string, { whatIsWrong: string; impact: string; steps: string[]; verify: string; refs: string[]; effort: string; role: string }> = {
      "exposed-service": {
        whatIsWrong: "Portas de serviço desnecessárias estão expostas na rede, aumentando a superfície de ataque.",
        impact: "Atacantes podem explorar serviços vulneráveis para obter acesso inicial ao ambiente.",
        steps: ["Identificar serviços necessários vs. desnecessários em cada host", "Criar regras de firewall para bloquear portas não essenciais", "Implementar segmentação de rede para isolar serviços críticos", "Validar que serviços legítimos continuam acessíveis"],
        verify: "Executar nova varredura de portas e confirmar que apenas portas autorizadas estão abertas.",
        refs: ["https://www.cisecurity.org/controls/v8", "NIST SP 800-41"], effort: "hours", role: "Administrador de Rede",
      },
      "ssl-expired": {
        whatIsWrong: "Certificados SSL/TLS expirados comprometem a criptografia de dados em trânsito.",
        impact: "Usuários recebem avisos de segurança e dados podem ser interceptados por ataques MITM.",
        steps: ["Gerar novo CSR para o domínio afetado", "Solicitar renovação do certificado na CA", "Instalar o novo certificado no servidor web", "Configurar renovação automática (ex: certbot)"],
        verify: "Acessar o site via HTTPS e confirmar certificado válido sem avisos do navegador.",
        refs: ["https://letsencrypt.org/docs/", "Mozilla SSL Configuration Generator"], effort: "minutes", role: "Administrador de Sistemas",
      },
      "firewall-permissive-rule": {
        whatIsWrong: "Regra de firewall com ANY-ANY permite todo o tráfego sem restrição.",
        impact: "Qualquer comunicação é permitida, anulando o propósito do firewall como controle de acesso.",
        steps: ["Identificar tráfego legítimo que passa pela regra ANY-ANY", "Criar regras específicas para cada fluxo necessário", "Desativar a regra ANY-ANY", "Monitorar logs por 48h para detectar bloqueios incorretos"],
        verify: "Confirmar que regra ANY-ANY está desativada e serviços continuam funcionando.",
        refs: ["CIS Benchmark Firewalls", "NIST SP 800-41"], effort: "hours", role: "Administrador de Rede",
      },
      "ad-password-age": {
        whatIsWrong: "Contas de serviço com senhas que excedem o limite da política de rotação de credenciais.",
        impact: "Senhas antigas aumentam o risco de comprometimento via brute-force ou credenciais vazadas.",
        steps: ["Listar todas as contas de serviço com senha expirada", "Gerar novas senhas complexas para cada conta", "Atualizar credenciais nos serviços dependentes", "Configurar alerta automático para próximas expirações"],
        verify: "Verificar que todas as contas de serviço têm senha dentro do prazo da política.",
        refs: ["CIS Benchmark AD", "NIST SP 800-63B"], effort: "hours", role: "Administrador AD",
      },
      "ad-privileged-group-excess": {
        whatIsWrong: "O grupo Domain Admins possui mais membros que o recomendado pela política de segurança.",
        impact: "Excesso de administradores aumenta o risco de movimentação lateral e escalação de privilégios.",
        steps: ["Revisar cada membro do grupo Domain Admins", "Remover contas que não necessitam de privilégios administrativos completos", "Criar grupos delegados com privilégios mínimos necessários", "Implementar monitoramento de alterações no grupo"],
        verify: "Confirmar que Domain Admins tem no máximo 5 membros conforme política.",
        refs: ["CIS Benchmark AD", "Microsoft Tiered Admin Model"], effort: "hours", role: "Administrador AD",
      },
      "edr-outdated": {
        whatIsWrong: "Agentes EDR com versão desatualizada não recebem as últimas assinaturas de detecção.",
        impact: "Endpoints ficam vulneráveis a ameaças recentes que o EDR atualizado detectaria.",
        steps: ["Verificar console central do EDR para endpoints desatualizados", "Forçar atualização via política de grupo ou console do EDR", "Investigar endpoints que falharam na atualização"],
        verify: "Confirmar no console EDR que todos os agentes estão na versão 4.1.0 ou superior.",
        refs: ["Documentação do fornecedor EDR"], effort: "minutes", role: "Analista de Segurança",
      },
      "cve-detected": {
        whatIsWrong: "CVEs conhecidas com exploits públicos foram encontradas em componentes da aplicação web.",
        impact: "Exploits públicos permitem que atacantes comprometam a aplicação remotamente sem autenticação.",
        steps: ["Priorizar CVEs por CVSS score (críticas primeiro)", "Atualizar dependências afetadas para versões corrigidas", "Testar aplicação após atualizações em ambiente staging", "Aplicar patches em produção com janela de manutenção"],
        verify: "Executar novo scan de vulnerabilidades e confirmar que as CVEs foram remediadas.",
        refs: ["https://nvd.nist.gov", "OWASP Dependency Check"], effort: "days", role: "Desenvolvedor",
      },
      "api-unprotected-admin": {
        whatIsWrong: "Endpoint administrativo exposto sem controle de autenticação retorna configurações sensíveis.",
        impact: "Qualquer usuário não autenticado pode obter segredos de configuração, credenciais de banco e chaves privadas.",
        steps: ["Adicionar middleware de autenticação JWT no endpoint /admin/config", "Restringir acesso ao endpoint apenas para IPs internos via firewall", "Auditar todos os endpoints /admin/* para verificar autenticação", "Remover ou ofuscar campos sensíveis da resposta"],
        verify: "Confirmar que endpoint retorna 401 para requisições sem token válido.",
        refs: ["OWASP API Security Top 10 - API2:2023", "NIST SP 800-204"], effort: "hours", role: "Desenvolvedor",
      },
      "api-bola": {
        whatIsWrong: "Endpoint de perfil permite acesso a qualquer ID de usuário sem verificação de autorização.",
        impact: "Atacante pode enumerar dados de todos os usuários do sistema, incluindo informações PII.",
        steps: ["Implementar verificação de autorização: usuário autenticado só acessa próprio perfil", "Adicionar validação de ownership antes de retornar dados", "Revisar todos os endpoints com parâmetros de ID para BOLA similar"],
        verify: "Confirmar que /api/v2/users/{id}/profile retorna 403 para IDs de outros usuários.",
        refs: ["OWASP API Security - API1:2023 BOLA", "https://portswigger.net/web-security/access-control"], effort: "hours", role: "Desenvolvedor",
      },
      "smb-v1-enabled": {
        whatIsWrong: "SMB v1 está habilitado, protocolo com vulnerabilidade crítica EternalBlue (MS17-010).",
        impact: "Exploit público permite execução remota de código sem autenticação, base do ransomware WannaCry.",
        steps: ["Desabilitar SMBv1 via Group Policy ou PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false", "Verificar se alguma aplicação depende de SMBv1", "Habilitar SMBv2/v3 para substituir"],
        verify: "Confirmar desabilitação: Get-SmbServerConfiguration | Select EnableSMB1Protocol",
        refs: ["Microsoft Security Advisory 4023262", "CIS Benchmark Windows Server"], effort: "minutes", role: "Administrador de Sistemas",
      },
      "ad-kerberoasting": {
        whatIsWrong: "Contas de serviço com SPNs registrados são vulneráveis a ataques de Kerberoasting.",
        impact: "Atacante autenticado no domínio pode obter hashes Kerberos e quebrá-los offline.",
        steps: ["Fortalecer senhas das contas de serviço para 25+ caracteres aleatórios", "Migrar contas de serviço para Managed Service Accounts (gMSA)", "Monitorar TGS requests anômalos no Event ID 4769"],
        verify: "Confirmar que contas de serviço com SPN possuem senhas de alta entropia.",
        refs: ["MITRE ATT&CK T1558.003", "CIS Benchmark AD"], effort: "hours", role: "Administrador AD",
      },
      "api-no-rate-limit": {
        whatIsWrong: "Endpoint de autenticação aceita número ilimitado de requisições, permitindo brute-force.",
        impact: "Atacante pode testar credenciais em alta velocidade sem ser bloqueado.",
        steps: ["Implementar rate limiting: máximo 10 tentativas por IP em 10 minutos", "Adicionar CAPTCHA após 5 tentativas falhas", "Implementar bloqueio progressivo de conta após N falhas", "Monitorar padrões anômalos de login"],
        verify: "Confirmar que após 10 tentativas o endpoint retorna 429 Too Many Requests.",
        refs: ["OWASP API Security - API4:2023", "NIST SP 800-63B"], effort: "hours", role: "Desenvolvedor",
      },
      "unencrypted-service": {
        whatIsWrong: "Serviço FTP sem criptografia transmite credenciais e dados em texto plano.",
        impact: "Credenciais podem ser capturadas via sniffing de rede.",
        steps: ["Avaliar necessidade do serviço FTP", "Migrar para SFTP ou FTPS", "Desativar serviço FTP sem criptografia"],
        verify: "Confirmar que porta 21 (FTP) está fechada e transferências usam SFTP/FTPS.",
        refs: ["CIS Controls v8", "NIST SP 800-123"], effort: "minutes", role: "Administrador de Sistemas",
      },
    };

    const allThreats = await client.query(
      `SELECT id, title, rule_id, severity, contextual_score, projected_score_after_fix
       FROM threats
       WHERE parent_threat_id IS NULL AND status = 'open'
       ORDER BY contextual_score DESC NULLS LAST`
    );

    for (const threat of allThreats.rows) {
      const tpl = recTemplates[threat.rule_id as string];
      if (!tpl) continue;
      await client.query(
        `INSERT INTO recommendations (id, threat_id, template_id, title, what_is_wrong, business_impact,
                                      fix_steps, verification_step, "references", effort_tag, role_required, status)
         VALUES (gen_random_uuid(),$1,$2,$3,$4,$5,$6::jsonb,$7,$8::jsonb,$9,$10,'pending')`,
        [
          threat.id, threat.rule_id,
          `Remediação: ${threat.title}`,
          tpl.whatIsWrong, tpl.impact,
          JSON.stringify(tpl.steps),
          tpl.verify,
          JSON.stringify(tpl.refs),
          tpl.effort, tpl.role,
        ]
      );
    }

    // ── Schedules (one per journey) ───────────────────────────────────────────
    const schedDefs = [
      { ji: 0, name: "Varredura semanal de superfície",  recurrenceType: "weekly",  dayOfWeek: 1, hour: 2 },
      { ji: 1, name: "Auditoria AD mensal",               recurrenceType: "monthly", dayOfMonth: 1, hour: 3 },
      { ji: 2, name: "Verificação EDR diária",            recurrenceType: "daily",   hour: 6 },
      { ji: 3, name: "Scan web semanal",                  recurrenceType: "weekly",  dayOfWeek: 3, hour: 23 },
      { ji: 4, name: "Descoberta de APIs semanal",        recurrenceType: "weekly",  dayOfWeek: 5, hour: 1 },
    ];
    for (const s of schedDefs) {
      await client.query(
        `INSERT INTO schedules (id, journey_id, name, kind, recurrence_type, hour, minute, day_of_week, day_of_month, created_by)
         VALUES (gen_random_uuid(), $1, $2, 'recurring', $3, $4, 0, $5, $6, $7)`,
        [journeyIds[s.ji], s.name, s.recurrenceType, s.hour, s.dayOfWeek ?? null, s.dayOfMonth ?? null, adminId]
      );
    }

    await client.query("COMMIT");

    console.log("\nDemo seed concluído com sucesso!");
    console.log(`  ${assetData.length} ativos`);
    console.log(`  ${hostData.length} hosts`);
    console.log(`  ${journeyDefs.length} jornadas (uma de cada tipo)`);
    console.log(`  1 API com ${endpointDefs.length} endpoints`);
    console.log(`  ${journeyDefs.length * 2} jobs (2 por jornada)`);
    console.log(`  ${parentThreats.length} ameaças pai + filhas e standalone`);
    console.log(`  ${schedDefs.length} agendamentos`);
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Demo seed falhou:", err);
    process.exit(1);
  } finally {
    client.release();
    await pool.end();
  }
}

demoSeed();
