/**
 * Demo seed: populates the database with realistic demo data for all 5 journey types.
 * Run: DATABASE_URL=... npx tsx scripts/demo-seed.ts
 *
 * Idempotent — truncates demo data and re-inserts.
 * Does NOT remove the main demo admin (demo@samureye.com.br).
 */
import bcrypt from "bcryptjs";
import { pool } from "../server/db";

async function demoSeed() {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // ── Resolve main admin ─────────────────────────────────────────────────────
    const adminUser = await client.query(
      `SELECT id FROM users WHERE email = 'demo@samureye.com.br' LIMIT 1`
    );
    const adminId = adminUser.rows[0]?.id;
    if (!adminId) throw new Error("Admin user not found. Run create-demo-admin.ts first.");

    // ── Clear demo data (FK order: children before parents) ───────────────────
    await client.query(`DELETE FROM action_plan_comment_threats`);
    await client.query(`DELETE FROM action_plan_comments`);
    await client.query(`DELETE FROM action_plan_history`);
    await client.query(`DELETE FROM action_plan_threats`);
    await client.query(`DELETE FROM action_plans`);
    await client.query(`DELETE FROM notification_log`);
    await client.query(`DELETE FROM notification_policies`);
    await client.query(`DELETE FROM recommendations`);
    await client.query(`DELETE FROM posture_snapshots`);
    await client.query(`DELETE FROM ad_security_test_results`);
    await client.query(`DELETE FROM job_results`);
    await client.query(`DELETE FROM threats`);
    await client.query(`DELETE FROM api_endpoints`);
    await client.query(`DELETE FROM jobs`);
    await client.query(`DELETE FROM schedules`);
    await client.query(`DELETE FROM journeys`);
    await client.query(`DELETE FROM apis`);
    await client.query(`DELETE FROM host_risk_history`);
    await client.query(`DELETE FROM hosts`);
    await client.query(`DELETE FROM assets`);
    // Reassign FK references in settings to main admin before deleting demo users
    await client.query(
      `UPDATE settings SET updated_by = $1
       WHERE updated_by IN (
         SELECT id FROM users WHERE email = ANY($2::text[])
       )`,
      [adminId, ["admin2@empresa.local", "op.silva@empresa.local", "op.santos@empresa.local"]]
    );
    await client.query(
      `DELETE FROM users WHERE email = ANY($1::text[])`,
      [["admin2@empresa.local", "op.silva@empresa.local", "op.santos@empresa.local"]]
    );
    console.log("Cleared existing demo data.");

    // ── Demo users ─────────────────────────────────────────────────────────────
    const demoHash = await bcrypt.hash("Demo@2026!", 12);
    const userDefs = [
      { email: "admin2@empresa.local",    firstName: "Carlos", lastName: "Mendes", role: "global_administrator" },
      { email: "op.silva@empresa.local",  firstName: "João",   lastName: "Silva",  role: "operator" },
      { email: "op.santos@empresa.local", firstName: "Maria",  lastName: "Santos", role: "operator" },
    ];
    const userIdMap: Record<string, string> = {};
    for (const u of userDefs) {
      const r = await client.query(
        `INSERT INTO users (email, first_name, last_name, role, password_hash)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [u.email, u.firstName, u.lastName, u.role, demoHash]
      );
      userIdMap[u.email] = r.rows[0].id;
    }
    const adminId2 = userIdMap["admin2@empresa.local"];
    const opSilva  = userIdMap["op.silva@empresa.local"];
    const opSantos = userIdMap["op.santos@empresa.local"];

    // ── Assets (15) ───────────────────────────────────────────────────────────
    // Index: 0-6 = hosts, 7-10 = web_apps, 11-14 = ranges
    const assetData = [
      { type: "host",            value: "192.168.1.10",              tags: ["producao", "web"] },
      { type: "host",            value: "192.168.1.20",              tags: ["producao", "db"] },
      { type: "host",            value: "10.0.0.5",                  tags: ["staging", "app"] },
      { type: "host",            value: "10.0.0.1",                  tags: ["producao", "dc"] },
      { type: "host",            value: "10.0.0.254",                tags: ["producao", "firewall"] },
      { type: "host",            value: "192.168.1.15",              tags: ["producao", "mail"] },
      { type: "host",            value: "10.0.0.20",                 tags: ["producao", "vpn"] },
      { type: "web_application", value: "https://app.empresa.local", tags: ["web", "producao"] },
      { type: "web_application", value: "https://api.empresa.local", tags: ["api", "producao"] },
      { type: "web_application", value: "https://portal.empresa.local", tags: ["portal", "interno"] },
      { type: "web_application", value: "https://git.empresa.local", tags: ["devops", "interno"] },
      { type: "range",           value: "192.168.1.0/24",            tags: ["rede-interna"] },
      { type: "range",           value: "10.0.0.0/24",               tags: ["rede-interna", "servidores"] },
      { type: "range",           value: "172.16.0.0/16",             tags: ["rede-interna", "dmz"] },
      { type: "range",           value: "10.10.0.0/24",              tags: ["wireless", "convidados"] },
    ];
    const assetIds: string[] = [];
    for (const a of assetData) {
      const r = await client.query(
        `INSERT INTO assets (id, type, value, tags, created_by)
         VALUES (gen_random_uuid(), $1, $2, $3::jsonb, $4) RETURNING id`,
        [a.type, a.value, JSON.stringify(a.tags), adminId]
      );
      assetIds.push(r.rows[0].id);
    }

    // ── Hosts (12) ─────────────────────────────────────────────────────────────
    const hostData = [
      { name: "srv-web-01",         os: "Ubuntu 22.04 LTS",       type: "server",   family: "linux",           ips: ["192.168.1.10"],  risk: 78 },
      { name: "srv-db-01",          os: "Windows Server 2022",    type: "server",   family: "windows_server",  ips: ["192.168.1.20"],  risk: 65 },
      { name: "srv-app-01",         os: "Ubuntu 20.04 LTS",       type: "server",   family: "linux",           ips: ["10.0.0.5"],      risk: 55 },
      { name: "dc01.empresa.local", os: "Windows Server 2019",    type: "domain",   family: "windows_server",  ips: ["10.0.0.1"],      risk: 85 },
      { name: "fw-edge-01",         os: "FortiOS 7.4.1",          type: "firewall", family: "fortios",         ips: ["10.0.0.254"],    risk: 42 },
      { name: "ws-dev-01",          os: "Windows 11 Pro",         type: "desktop",  family: "windows_desktop", ips: ["192.168.1.100"], risk: 30 },
      { name: "ws-rh-01",           os: "Windows 10 Pro",         type: "desktop",  family: "windows_desktop", ips: ["192.168.1.101"], risk: 22 },
      { name: "srv-bkp-01",         os: "Ubuntu 20.04 LTS",       type: "server",   family: "linux",           ips: ["10.0.0.10"],     risk: 48 },
      { name: "srv-mail-01",        os: "Ubuntu 22.04 LTS",       type: "server",   family: "linux",           ips: ["192.168.1.15"],  risk: 60 },
      { name: "srv-vpn-01",         os: "Ubuntu 20.04 LTS",       type: "server",   family: "linux",           ips: ["10.0.0.20"],     risk: 52 },
      { name: "ws-financ-01",       os: "Windows 10 Pro",         type: "desktop",  family: "windows_desktop", ips: ["192.168.1.102"], risk: 35 },
      { name: "srv-git-01",         os: "Ubuntu 22.04 LTS",       type: "server",   family: "linux",           ips: ["10.0.0.30"],     risk: 45 },
    ];
    const hostIds: string[] = [];
    for (const h of hostData) {
      const r = await client.query(
        `INSERT INTO hosts (id, name, description, operating_system, type, family, ips, risk_score, raw_score)
         VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6::jsonb, $7, $8) RETURNING id`,
        [h.name, `Servidor ${h.name}`, h.os, h.type, h.family, JSON.stringify(h.ips), h.risk, h.risk * 10]
      );
      hostIds.push(r.rows[0].id);
    }

    // ── Journeys ──────────────────────────────────────────────────────────────
    const journeyDefs = [
      { name: "Varredura de Superfície de Ataque", type: "attack_surface",  desc: "Mapeamento completo de superfície exposta e portas abertas" },
      { name: "Auditoria de Segurança AD",          type: "ad_security",     desc: "Verificação de políticas, contas e privilégios no Active Directory" },
      { name: "Verificação EDR/AV",                 type: "edr_av",          desc: "Detecção de agentes desatualizados e evasão de EDR" },
      { name: "Scan de Aplicação Web",              type: "web_application", desc: "Análise de vulnerabilidades em aplicações web e APIs" },
      { name: "Descoberta e Teste de APIs",          type: "api_security",    desc: "Inventário e testes de segurança em endpoints de API" },
    ];
    const journeyIds: string[] = [];
    for (const j of journeyDefs) {
      const r = await client.query(
        `INSERT INTO journeys (id, name, type, description, created_by)
         VALUES (gen_random_uuid(), $1, $2, $3, $4) RETURNING id`,
        [j.name, j.type, j.desc, adminId]
      );
      journeyIds.push(r.rows[0].id);
    }

    // ── API asset + endpoints ─────────────────────────────────────────────────
    const apiAssetId = assetIds[8]; // https://api.empresa.local
    const apiRes = await client.query(
      `INSERT INTO apis (id, parent_asset_id, base_url, api_type, name, description, created_by)
       VALUES (gen_random_uuid(), $1, $2, 'rest', 'API Principal', 'API REST da aplicação principal', $3) RETURNING id`,
      [apiAssetId, "https://api.empresa.local", adminId]
    );
    const apiId = apiRes.rows[0].id;

    const endpointDefs = [
      { method: "GET",    path: "/api/v1/users",                requiresAuth: true,  httpxStatus: 200 },
      { method: "POST",   path: "/api/v1/users",                requiresAuth: true,  httpxStatus: 201 },
      { method: "GET",    path: "/api/v1/users/{id}",           requiresAuth: true,  httpxStatus: 200 },
      { method: "PUT",    path: "/api/v1/users/{id}",           requiresAuth: true,  httpxStatus: 200 },
      { method: "DELETE", path: "/api/v1/users/{id}",           requiresAuth: true,  httpxStatus: 204 },
      { method: "GET",    path: "/api/v1/products",             requiresAuth: false, httpxStatus: 200 },
      { method: "POST",   path: "/api/v1/products",             requiresAuth: true,  httpxStatus: 201 },
      { method: "GET",    path: "/api/v1/orders",               requiresAuth: true,  httpxStatus: 200 },
      { method: "POST",   path: "/api/v1/orders",               requiresAuth: true,  httpxStatus: 201 },
      { method: "GET",    path: "/api/v1/orders/{id}",          requiresAuth: true,  httpxStatus: 200 },
      { method: "GET",    path: "/api/v1/reports/sales",        requiresAuth: true,  httpxStatus: 200 },
      { method: "GET",    path: "/api/v1/health",               requiresAuth: false, httpxStatus: 200 },
      { method: "GET",    path: "/api/v1/admin/config",         requiresAuth: false, httpxStatus: 200 },
      { method: "POST",   path: "/api/v1/auth/login",           requiresAuth: false, httpxStatus: 200 },
      { method: "POST",   path: "/api/v1/auth/reset-password",  requiresAuth: false, httpxStatus: 200 },
      { method: "GET",    path: "/api/v2/users",                requiresAuth: true,  httpxStatus: 200 },
      { method: "GET",    path: "/api/v2/users/{id}/profile",   requiresAuth: false, httpxStatus: 200 },
      { method: "GET",    path: "/api/v2/products/search",      requiresAuth: false, httpxStatus: 200 },
      { method: "POST",   path: "/api/v2/upload",               requiresAuth: true,  httpxStatus: 200 },
      { method: "GET",    path: "/api/v1/internal/metrics",     requiresAuth: false, httpxStatus: 200 },
    ];
    for (const ep of endpointDefs) {
      await client.query(
        `INSERT INTO api_endpoints (id, api_id, method, path, requires_auth, httpx_status, discovery_sources)
         VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, ARRAY['kiterunner']::text[])`,
        [apiId, ep.method, ep.path, ep.requiresAuth, ep.httpxStatus]
      );
    }

    // ── Jobs (2 per journey: 3 and 14 days ago) ───────────────────────────────
    const jobDayOffsets = [3, 14];
    const jobIds: string[] = [];
    for (let ji = 0; ji < journeyIds.length; ji++) {
      for (let run = 0; run < 2; run++) {
        const da = jobDayOffsets[run];
        const r = await client.query(
          `INSERT INTO jobs (id, journey_id, status, progress, started_at, finished_at, created_at)
           VALUES (gen_random_uuid(), $1, 'completed', 100,
                   NOW() - interval '${da} days' - interval '12 minutes',
                   NOW() - interval '${da} days',
                   NOW() - interval '${da} days' - interval '15 minutes')
           RETURNING id`,
          [journeyIds[ji]]
        );
        jobIds.push(r.rows[0].id);
      }
    }
    // ji mapping: ji=0→jobs[0,1], ji=1→jobs[2,3], ji=2→jobs[4,5], ji=3→jobs[6,7], ji=4→jobs[8,9]

    // ── Job results for EDR (ji=2) ────────────────────────────────────────────
    const edrJobIdxes = [4, 5];
    const edrArtifacts = [
      { totalDiscovered: 12, successfulDeployments: 11, eicarRemovedCount: 9, eicarPersistedCount: 2, failedDeployments: 1 },
      { totalDiscovered: 12, successfulDeployments: 12, eicarRemovedCount: 8, eicarPersistedCount: 4, failedDeployments: 0 },
    ];
    for (let i = 0; i < 2; i++) {
      await client.query(
        `INSERT INTO job_results (id, job_id, stdout, artifacts)
         VALUES (gen_random_uuid(), $1, $2, $3::jsonb)`,
        [
          jobIds[edrJobIdxes[i]],
          `EDR scan concluído. ${edrArtifacts[i].eicarRemovedCount}/${edrArtifacts[i].successfulDeployments} endpoints protegidos.`,
          JSON.stringify({ statistics: edrArtifacts[i] }),
        ]
      );
    }

    // ── AD security test results (ji=1) ──────────────────────────────────────
    const adJobIdxes = [2, 3];
    const adDcHostId = hostIds[3]; // dc01.empresa.local
    const adTests = [
      { id: "test_001", name: "Contas admin com senha padrão",                   category: "configuracoes_criticas", severity: "critical", statuses: ["fail", "fail"] },
      { id: "test_002", name: "Política de senha atende complexidade mínima",    category: "politicas_senha",        severity: "medium",   statuses: ["pass", "pass"] },
      { id: "test_003", name: "Kerberoasting: SPNs em contas de usuário",        category: "ataques_credenciais",    severity: "high",     statuses: ["fail", "fail"] },
      { id: "test_004", name: "Contas com privilégio de replicação (DCSync)",    category: "privilegios",            severity: "critical", statuses: ["pass", "pass"] },
      { id: "test_005", name: "Domain Admins com mais de 5 membros",             category: "privilegios",            severity: "high",     statuses: ["fail", "fail"] },
      { id: "test_006", name: "Contas de serviço no grupo Domain Admins",        category: "privilegios",            severity: "critical", statuses: ["fail", "fail"] },
      { id: "test_007", name: "SMB signing habilitado em todos os DCs",          category: "configuracoes_criticas", severity: "high",     statuses: ["pass", "pass"] },
      { id: "test_008", name: "LDAP signing e channel binding",                  category: "configuracoes_criticas", severity: "medium",   statuses: ["pass", "fail"] },
      { id: "test_009", name: "Contas inativas há mais de 90 dias",              category: "higiene_contas",         severity: "medium",   statuses: ["fail", "pass"] },
      { id: "test_010", name: "Senha nunca expira em contas de usuário",         category: "politicas_senha",        severity: "medium",   statuses: ["fail", "fail"] },
      { id: "test_011", name: "Auditoria de logon habilitada",                   category: "auditoria",              severity: "low",      statuses: ["pass", "pass"] },
      { id: "test_012", name: "Protected Users group com membros sensíveis",     category: "privilegios",            severity: "medium",   statuses: ["pass", "pass"] },
      { id: "test_013", name: "AS-REP Roasting: pré-autenticação desabilitada", category: "ataques_credenciais",    severity: "high",     statuses: ["pass", "fail"] },
      { id: "test_014", name: "Histórico de senha: mínimo 10 senhas",           category: "politicas_senha",        severity: "low",      statuses: ["pass", "pass"] },
      { id: "test_015", name: "Fine-grained password policy configurada",        category: "politicas_senha",        severity: "low",      statuses: ["pass", "pass"] },
    ];
    for (let run = 0; run < 2; run++) {
      const jobId = jobIds[adJobIdxes[run]];
      const da = jobDayOffsets[run];
      for (const test of adTests) {
        await client.query(
          `INSERT INTO ad_security_test_results
             (id, job_id, host_id, test_id, test_name, category, severity_hint, status, evidence, executed_at)
           VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8::jsonb, NOW() - interval '${da} days')`,
          [jobId, adDcHostId, test.id, test.name, test.category, test.severity,
           test.statuses[run], JSON.stringify({ testId: test.id })]
        );
      }
    }

    // ── Posture snapshots ─────────────────────────────────────────────────────
    const snapshotScores = [
      [72, 65], [58, 62], [81, 78], [45, 45], [63, 55],
    ];
    for (let ji = 0; ji < journeyIds.length; ji++) {
      for (let run = 0; run < 2; run++) {
        const score = snapshotScores[ji][run];
        const open = Math.floor((100 - score) / 5);
        const crit = Math.max(0, Math.floor(open * 0.2));
        const high = Math.max(0, Math.floor(open * 0.3));
        const med  = Math.max(0, Math.floor(open * 0.3));
        const low  = Math.max(0, open - crit - high - med);
        const da   = jobDayOffsets[run];
        await client.query(
          `INSERT INTO posture_snapshots
             (id, job_id, journey_id, score, open_threat_count, critical_count, high_count, medium_count, low_count, scored_at)
           VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, NOW() - interval '${da} days')`,
          [jobIds[ji * 2 + run], journeyIds[ji], score, open, crit, high, med, low]
        );
      }
    }

    // ── Host risk history (30-day trend) ──────────────────────────────────────
    for (const hId of hostIds) {
      const base = Math.floor(Math.random() * 40) + 30;
      for (let d = 30; d >= 0; d--) {
        const drift = Math.floor(Math.random() * 10) - 3;
        const risk  = Math.min(100, Math.max(0, base + drift));
        await client.query(
          `INSERT INTO host_risk_history (id, host_id, risk_score, recorded_at)
           VALUES (gen_random_uuid(), $1, $2, NOW() - interval '${d} days')`,
          [hId, risk]
        );
      }
    }

    // ── Parent threats ────────────────────────────────────────────────────────
    // All have created_at set to historical dates for trend charts
    const catToJi: Record<string, number> = {
      attack_surface: 0, ad_security: 1, edr_av: 2, web_application: 3, api_security: 4,
    };

    type ParentThreat = {
      title: string; desc: string; severity: string; category: string;
      hostIdx: number; assetIdx: number | null; groupingKey: string;
      evidence: object; score: number; projected: number; ruleId: string; daysAgo: number;
    };

    const parentThreats: ParentThreat[] = [
      {
        title: "Portas expostas em servidores de produção",
        desc: "Múltiplas portas de serviço expostas sem necessidade em servidores de produção.",
        severity: "critical", category: "attack_surface", hostIdx: 0, assetIdx: 0,
        groupingKey: "exposed-ports-producao",
        evidence: { ports: [22, 80, 443, 3306, 8080], protocol: "TCP", scanDate: "2026-03-15" },
        score: 92, projected: 35, ruleId: "exposed-service", daysAgo: 28,
      },
      {
        title: "Certificados SSL expirados",
        desc: "Certificados SSL/TLS expirados ou próximos da expiração em domínios críticos.",
        severity: "medium", category: "attack_surface", hostIdx: 0, assetIdx: 7,
        groupingKey: "ssl-cert-expired",
        evidence: { domain: "app.empresa.local", expiresAt: "2026-02-28", issuer: "Let's Encrypt" },
        score: 55, projected: 10, ruleId: "ssl-expired", daysAgo: 21,
      },
      {
        title: "Regra de firewall ANY-ANY ativa",
        desc: "Regra de firewall permissiva que permite todo tráfego sem restrição.",
        severity: "high", category: "attack_surface", hostIdx: 4, assetIdx: null,
        groupingKey: "firewall-any-any",
        evidence: { ruleId: "rule-15", action: "allow", source: "any", destination: "any", service: "any" },
        score: 68, projected: 25, ruleId: "firewall-permissive-rule", daysAgo: 14,
      },
      {
        title: "Contas AD com senha expirada",
        desc: "Contas de serviço com senhas que excedem a política de rotação.",
        severity: "high", category: "ad_security", hostIdx: 3, assetIdx: null,
        groupingKey: "ad-expired-passwords",
        evidence: { accountCount: 12, oldestPasswordAge: "450 dias", policyLimit: "90 dias" },
        score: 78, projected: 45, ruleId: "ad-password-age", daysAgo: 25,
      },
      {
        title: "Usuários no grupo Domain Admins excessivos",
        desc: "O grupo Domain Admins possui mais membros do que o recomendado pela política de segurança.",
        severity: "high", category: "ad_security", hostIdx: 3, assetIdx: null,
        groupingKey: "ad-domain-admins-excess",
        evidence: { groupName: "Domain Admins", memberCount: 12, expectedMax: 5, members: ["admin1", "svc-backup", "jsilva", "mcarvalho", "admin2"] },
        score: 74, projected: 50, ruleId: "ad-privileged-group-excess", daysAgo: 18,
      },
      {
        title: "EDR desatualizado em endpoints",
        desc: "Agente EDR com versão desatualizada em múltiplos endpoints.",
        severity: "high", category: "edr_av", hostIdx: 5, assetIdx: null,
        groupingKey: "edr-outdated-agents",
        evidence: { currentVersion: "3.2.1", requiredVersion: "4.1.0", affectedCount: 8 },
        score: 71, projected: 55, ruleId: "edr-outdated", daysAgo: 10,
      },
      {
        title: "Vulnerabilidades CVE em aplicação web",
        desc: "CVEs conhecidas com exploits públicos encontradas na aplicação web principal.",
        severity: "critical", category: "web_application", hostIdx: 2, assetIdx: 7,
        groupingKey: "web-cve-detected",
        evidence: { cves: ["CVE-2024-1234", "CVE-2024-5678", "CVE-2023-9012"], cvssMax: 9.8 },
        score: 95, projected: 30, ruleId: "cve-detected", daysAgo: 20,
      },
      {
        title: "Endpoint administrativo exposto sem autenticação",
        desc: "Endpoint /api/v1/admin/config retorna dados sensíveis de configuração sem autenticação.",
        severity: "critical", category: "api_security", hostIdx: 2, assetIdx: 8,
        groupingKey: "api-admin-exposed",
        evidence: { endpoint: "/api/v1/admin/config", method: "GET", requiresAuth: false, httpxStatus: 200, responseContains: ["db_host", "secret_key"] },
        score: 97, projected: 10, ruleId: "api-unprotected-admin", daysAgo: 7,
      },
      {
        title: "BOLA — Broken Object Level Authorization em /users/{id}",
        desc: "Endpoint de perfil de usuário acessível sem autenticação permite enumeração de dados.",
        severity: "high", category: "api_security", hostIdx: 2, assetIdx: 8,
        groupingKey: "api-bola-users",
        evidence: { endpoint: "/api/v2/users/{id}/profile", method: "GET", requiresAuth: false, owasp: "API1:2023", cvssEstimate: 8.1 },
        score: 83, projected: 20, ruleId: "api-bola", daysAgo: 5,
      },
    ];

    const parentThreatIds: string[] = [];
    for (const t of parentThreats) {
      const ji = catToJi[t.category];
      const r = await client.query(
        `INSERT INTO threats
           (id, title, description, severity, status, source, host_id, asset_id,
            evidence, category, grouping_key, contextual_score, projected_score_after_fix,
            rule_id, job_id, correlation_key, score_breakdown, created_at, last_seen_at)
         VALUES
           (gen_random_uuid(),$1,$2,$3,'open','journey',$4,$5,$6::jsonb,$7,$8,$9,$10,
            $11,$12,$13,$14::jsonb,
            NOW() - interval '${t.daysAgo} days',
            NOW() - interval '${Math.max(1, t.daysAgo - 2)} days')
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
      parentThreatIds.push(r.rows[0].id);
    }

    // ── Child threats ─────────────────────────────────────────────────────────
    type ChildThreat = { title: string; severity: string; evidence: object; hostIdx: number };
    const childGroups: ChildThreat[][] = [
      // 0: exposed-ports
      [
        { title: "Porta 3306 (MySQL) exposta em srv-web-01", severity: "critical", evidence: { port: 3306, service: "MySQL 8.0", state: "open" }, hostIdx: 0 },
        { title: "Porta 8080 (Tomcat) exposta em srv-web-01", severity: "high", evidence: { port: 8080, service: "Apache Tomcat", state: "open" }, hostIdx: 0 },
        { title: "Porta 22 (SSH) com autenticação por senha em srv-web-01", severity: "medium", evidence: { port: 22, service: "OpenSSH 8.9", authMethod: "password", state: "open" }, hostIdx: 0 },
      ],
      // 1: ssl-cert-expired
      [
        { title: "Certificado expirado em app.empresa.local:443", severity: "medium", evidence: { domain: "app.empresa.local", port: 443, expiresAt: "2026-02-28", daysExpired: 17 }, hostIdx: 0 },
      ],
      // 2: firewall-any-any
      [
        { title: "Tráfego de saída irrestrito no fw-edge-01", severity: "high", evidence: { ruleId: "rule-15", direction: "egress", protocol: "any" }, hostIdx: 4 },
        { title: "Tráfego lateral entre VLANs sem inspeção", severity: "medium", evidence: { ruleId: "rule-22", direction: "lateral", affectedVlans: ["vlan10", "vlan20"] }, hostIdx: 4 },
      ],
      // 3: ad-expired-passwords
      [
        { title: "Conta svc-backup com senha de 450 dias", severity: "high", evidence: { account: "svc-backup", passwordAge: "450 dias", lastLogon: "2026-01-10" }, hostIdx: 3 },
        { title: "Conta svc-sql com senha de 380 dias", severity: "high", evidence: { account: "svc-sql", passwordAge: "380 dias", lastLogon: "2026-03-01" }, hostIdx: 3 },
      ],
      // 4: ad-domain-admins-excess
      [
        { title: "Conta jsilva no grupo Domain Admins sem justificativa", severity: "high", evidence: { account: "jsilva", group: "Domain Admins", addedAt: "2025-11-20", justification: null }, hostIdx: 3 },
        { title: "Conta svc-backup com privilégios de Domain Admin", severity: "critical", evidence: { account: "svc-backup", group: "Domain Admins", risk: "service account should not be DA" }, hostIdx: 3 },
      ],
      // 5: edr-outdated
      [
        { title: "EDR v3.2.1 desatualizado em ws-dev-01", severity: "medium", evidence: { hostname: "ws-dev-01", currentVersion: "3.2.1", expectedVersion: "4.1.0" }, hostIdx: 5 },
        { title: "EDR v3.0.0 desatualizado em srv-app-01", severity: "high", evidence: { hostname: "srv-app-01", currentVersion: "3.0.0", expectedVersion: "4.1.0" }, hostIdx: 2 },
        { title: "EDR ausente em ws-rh-01", severity: "high", evidence: { hostname: "ws-rh-01", status: "not_installed" }, hostIdx: 6 },
      ],
      // 6: cve-detected
      [
        { title: "CVE-2024-1234: RCE em Spring Framework (CVSS 9.8)", severity: "critical", evidence: { cve: "CVE-2024-1234", cvss: 9.8, component: "Spring Framework", fixVersion: "6.1.5" }, hostIdx: 2 },
        { title: "CVE-2024-5678: SQL Injection em Hibernate (CVSS 8.1)", severity: "critical", evidence: { cve: "CVE-2024-5678", cvss: 8.1, component: "Hibernate ORM", fixVersion: "6.4.2" }, hostIdx: 2 },
        { title: "CVE-2023-9012: XSS em Thymeleaf (CVSS 6.5)", severity: "medium", evidence: { cve: "CVE-2023-9012", cvss: 6.5, component: "Thymeleaf", fixVersion: "3.1.3" }, hostIdx: 2 },
      ],
      // 7: api-admin-exposed
      [
        { title: "Campo db_host exposto em /admin/config", severity: "critical", evidence: { endpoint: "/api/v1/admin/config", field: "db_host", value: "192.168.1.20:5432" }, hostIdx: 2 },
        { title: "Secret key exposta em resposta JSON de /admin/config", severity: "critical", evidence: { endpoint: "/api/v1/admin/config", field: "secret_key", valueLength: 64 }, hostIdx: 2 },
      ],
      // 8: api-bola
      [
        { title: "Perfil de usuário admin acessível sem token em /v2/users/1", severity: "high", evidence: { endpoint: "/api/v2/users/1/profile", httpxStatus: 200, dataExposed: ["email", "phone", "address"] }, hostIdx: 2 },
      ],
    ];

    for (let pi = 0; pi < childGroups.length; pi++) {
      const parent = parentThreats[pi];
      const ji = catToJi[parent.category];
      for (const child of childGroups[pi]) {
        const childScore = Math.max(20, parent.score - Math.floor(Math.random() * 20 + 5));
        const childDays  = Math.max(1, parent.daysAgo - Math.floor(Math.random() * 3));
        await client.query(
          `INSERT INTO threats
             (id, title, description, severity, status, source, host_id,
              evidence, category, parent_threat_id, contextual_score,
              projected_score_after_fix, rule_id, job_id, correlation_key, score_breakdown,
              created_at, last_seen_at)
           VALUES
             (gen_random_uuid(),$1,$2,$3,'open','journey',$4,$5::jsonb,$6,$7,$8,$9,
              $10,$11,$12,$13::jsonb,
              NOW() - interval '${childDays} days',
              NOW() - interval '${Math.max(1, childDays - 1)} days')`,
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

    // ── Standalone threats ─────────────────────────────────────────────────────
    const standaloneThreats = [
      { title: "Serviço FTP sem criptografia ativo em srv-db-01",    severity: "medium", category: "attack_surface", hostIdx: 1, evidence: { port: 21, service: "vsftpd 3.0.5", encryption: "none" }, score: 48, projected: 5,  ruleId: "unencrypted-service",     daysAgo: 17, correlKey: "unencrypted-service-ftp-1" },
      { title: "SMB v1 habilitado em srv-db-01",                     severity: "high",   category: "attack_surface", hostIdx: 1, evidence: { port: 445, protocol: "SMBv1", cve: "MS17-010", knownExploit: "EternalBlue" }, score: 82, projected: 15, ruleId: "smb-v1-enabled", daysAgo: 23, correlKey: "smb-v1-enabled-db-1" },
      { title: "Kerberoasting: SPN expostos em contas de serviço",    severity: "high",   category: "ad_security",   hostIdx: 3, evidence: { spnCount: 4, crackableHashes: 4, accounts: ["svc-sql", "svc-backup", "svc-web", "svc-report"] }, score: 79, projected: 30, ruleId: "ad-kerberoasting", daysAgo: 12, correlKey: "ad-kerberoasting-dc01" },
      { title: "Rate limiting ausente em endpoint de autenticação",   severity: "medium", category: "api_security",  hostIdx: 2, evidence: { endpoint: "/api/v1/auth/login", rateLimitHeader: null, bruteForceRisk: "high", tested: "1000 req/min sem bloqueio" }, score: 67, projected: 20, ruleId: "api-no-rate-limit", daysAgo: 6, correlKey: "api-no-rate-limit-login" },
      { title: "Servidor de email sem STARTTLS em srv-mail-01",       severity: "medium", category: "attack_surface", hostIdx: 8, evidence: { port: 25, service: "Postfix 3.6", tls: false }, score: 52, projected: 10, ruleId: "unencrypted-service", daysAgo: 9, correlKey: "unencrypted-service-smtp-8" },
      { title: "VPN com protocolo legado PPTP em srv-vpn-01",         severity: "high",   category: "attack_surface", hostIdx: 9, evidence: { port: 1723, protocol: "PPTP", vulnerabilities: ["MS-CHAPv2 breakable", "no PFS"] }, score: 75, projected: 15, ruleId: "legacy-vpn-protocol", daysAgo: 15, correlKey: "legacy-vpn-pptp-9" },
    ];

    for (const t of standaloneThreats) {
      const ji = catToJi[t.category];
      await client.query(
        `INSERT INTO threats
           (id, title, description, severity, status, source, host_id,
            evidence, category, contextual_score, projected_score_after_fix,
            rule_id, job_id, correlation_key, score_breakdown, created_at, last_seen_at)
         VALUES
           (gen_random_uuid(),$1,$2,$3,'open','journey',$4,$5::jsonb,$6,$7,$8,
            $9,$10,$11,$12::jsonb,
            NOW() - interval '${t.daysAgo} days',
            NOW() - interval '${Math.max(1, t.daysAgo - 1)} days')`,
        [
          t.title, t.title, t.severity,
          hostIds[t.hostIdx],
          JSON.stringify(t.evidence),
          t.category, t.score, t.projected, t.ruleId,
          jobIds[ji * 2],
          t.correlKey,
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
        steps: ["Desabilitar SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false", "Verificar se alguma aplicação depende de SMBv1", "Habilitar SMBv2/v3 para substituir"],
        verify: "Confirmar: Get-SmbServerConfiguration | Select EnableSMB1Protocol",
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
        steps: ["Implementar rate limiting: máximo 10 tentativas por IP em 10 minutos", "Adicionar CAPTCHA após 5 tentativas falhas", "Implementar bloqueio progressivo de conta após N falhas"],
        verify: "Confirmar que após 10 tentativas o endpoint retorna 429 Too Many Requests.",
        refs: ["OWASP API Security - API4:2023", "NIST SP 800-63B"], effort: "hours", role: "Desenvolvedor",
      },
      "unencrypted-service": {
        whatIsWrong: "Serviço de rede sem criptografia transmite credenciais e dados em texto plano.",
        impact: "Credenciais podem ser capturadas via sniffing de rede.",
        steps: ["Avaliar necessidade do serviço", "Migrar para versão criptografada (SFTP, FTPS, SMTPS)", "Desativar serviço sem criptografia"],
        verify: "Confirmar que porta do serviço legado está fechada.",
        refs: ["CIS Controls v8", "NIST SP 800-123"], effort: "minutes", role: "Administrador de Sistemas",
      },
      "legacy-vpn-protocol": {
        whatIsWrong: "Protocolo VPN legado PPTP usa MS-CHAPv2, quebrável offline, sem Perfect Forward Secrecy.",
        impact: "Sessões VPN podem ser descriptografadas retroativamente por atacante com capacidade suficiente.",
        steps: ["Migrar clientes VPN para IKEv2/IPSec ou WireGuard", "Desabilitar suporte a PPTP no servidor VPN", "Testar conectividade de todos os clientes com novo protocolo"],
        verify: "Confirmar que porta 1723 (PPTP) não responde mais.",
        refs: ["RFC 8247 - Protocols Recommended for IKEv2", "CIS Benchmark VPN"], effort: "hours", role: "Administrador de Rede",
      },
    };

    const allParentThreats = await client.query(
      `SELECT id, title, rule_id, severity, contextual_score, projected_score_after_fix
       FROM threats
       WHERE parent_threat_id IS NULL AND status = 'open'
       ORDER BY contextual_score DESC NULLS LAST`
    );
    for (const threat of allParentThreats.rows) {
      const tpl = recTemplates[threat.rule_id as string];
      if (!tpl) continue;
      await client.query(
        `INSERT INTO recommendations
           (id, threat_id, template_id, title, what_is_wrong, business_impact,
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

    // ── Schedules ─────────────────────────────────────────────────────────────
    const schedDefs = [
      { ji: 0, name: "Varredura semanal de superfície", recurrenceType: "weekly",  dayOfWeek: 1,    dayOfMonth: null, hour: 2  },
      { ji: 1, name: "Auditoria AD mensal",              recurrenceType: "monthly", dayOfWeek: null, dayOfMonth: 1,    hour: 3  },
      { ji: 2, name: "Verificação EDR diária",           recurrenceType: "daily",   dayOfWeek: null, dayOfMonth: null, hour: 6  },
      { ji: 3, name: "Scan web semanal",                 recurrenceType: "weekly",  dayOfWeek: 3,    dayOfMonth: null, hour: 23 },
      { ji: 4, name: "Descoberta de APIs semanal",       recurrenceType: "weekly",  dayOfWeek: 5,    dayOfMonth: null, hour: 1  },
    ];
    for (const s of schedDefs) {
      await client.query(
        `INSERT INTO schedules (id, journey_id, name, kind, recurrence_type, hour, minute, day_of_week, day_of_month, created_by)
         VALUES (gen_random_uuid(), $1, $2, 'recurring', $3, $4, 0, $5, $6, $7)`,
        [journeyIds[s.ji], s.name, s.recurrenceType, s.hour, s.dayOfWeek, s.dayOfMonth, adminId]
      );
    }

    // ── Notification policies ─────────────────────────────────────────────────
    await client.query(
      `INSERT INTO notification_policies (id, name, enabled, email_addresses, severities, statuses, created_by)
       VALUES (gen_random_uuid(), $1, true, $2::jsonb, $3::jsonb, $4::jsonb, $5)`,
      ["Alertas Críticos e High", JSON.stringify(["secops@empresa.local", "ciso@empresa.local"]),
       JSON.stringify(["critical", "high"]), JSON.stringify(["open", "investigating"]), adminId]
    );
    await client.query(
      `INSERT INTO notification_policies (id, name, enabled, email_addresses, severities, statuses, created_by)
       VALUES (gen_random_uuid(), $1, true, $2::jsonb, $3::jsonb, $4::jsonb, $5)`,
      ["Monitoramento Geral de Ameaças", JSON.stringify(["seguranca@empresa.local", "ti@empresa.local"]),
       JSON.stringify(["critical", "high", "medium", "low"]), JSON.stringify(["open"]), adminId]
    );

    // ── Action plans ──────────────────────────────────────────────────────────
    // Fetch top-level threat IDs by ruleId for linking
    const ruleToThreatIds: Record<string, string[]> = {};
    const topThreatsRes = await client.query(
      `SELECT id, rule_id FROM threats WHERE parent_threat_id IS NULL`
    );
    for (const row of topThreatsRes.rows) {
      if (!row.rule_id) continue;
      if (!ruleToThreatIds[row.rule_id]) ruleToThreatIds[row.rule_id] = [];
      ruleToThreatIds[row.rule_id].push(row.id);
    }

    const planDefs = [
      {
        code: "AP-0001", title: "Remediação de Portas Expostas em Produção",
        desc: "Fechar portas desnecessárias e implementar segmentação de rede nos servidores de produção.",
        status: "in_progress", priority: "high", createdBy: adminId, assigneeId: opSilva,
        threatRuleIds: ["exposed-service"],
        comment: "Iniciando levantamento das portas em uso. Janela de manutenção confirmada para sábado 02h.",
        commentAuthor: opSilva,
      },
      {
        code: "AP-0002", title: "Renovação e Automação de Certificados SSL",
        desc: "Renovar certificados SSL expirados e configurar renovação automática via certbot em todos os domínios.",
        status: "pending", priority: "medium", createdBy: adminId2, assigneeId: opSantos,
        threatRuleIds: ["ssl-expired"],
        comment: null, commentAuthor: null,
      },
      {
        code: "AP-0003", title: "Hardening de Active Directory",
        desc: "Remover privilégios excessivos, rotacionar senhas de contas de serviço e implementar gMSA para contas críticas.",
        status: "in_progress", priority: "critical", createdBy: adminId, assigneeId: opSilva,
        threatRuleIds: ["ad-password-age", "ad-privileged-group-excess", "ad-kerberoasting"],
        comment: "Mapeamento de contas de serviço concluído. Agendando rotação de senhas com equipe de aplicações.",
        commentAuthor: opSilva,
      },
      {
        code: "AP-0004", title: "Patching de CVEs Críticas em Aplicação Web",
        desc: "Atualizar dependências vulneráveis identificadas no scan de CVEs. Priorizar CVSS >= 9.0 primeiro.",
        status: "pending", priority: "critical", createdBy: adminId2, assigneeId: adminId2,
        threatRuleIds: ["cve-detected"],
        comment: null, commentAuthor: null,
      },
    ];

    for (const plan of planDefs) {
      const planRes = await client.query(
        `INSERT INTO action_plans (id, code, title, description, status, priority, created_by, assignee_id)
         VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7) RETURNING id`,
        [plan.code, plan.title, plan.desc, plan.status, plan.priority, plan.createdBy, plan.assigneeId]
      );
      const planId = planRes.rows[0].id;

      for (const ruleId of plan.threatRuleIds) {
        for (const tid of (ruleToThreatIds[ruleId] || [])) {
          await client.query(
            `INSERT INTO action_plan_threats (id, action_plan_id, threat_id, added_by)
             VALUES (gen_random_uuid(), $1, $2, $3)`,
            [planId, tid, plan.createdBy]
          );
        }
      }

      await client.query(
        `INSERT INTO action_plan_history (id, action_plan_id, actor_id, action, details_json)
         VALUES (gen_random_uuid(), $1, $2, 'created', $3::jsonb)`,
        [planId, plan.createdBy, JSON.stringify({ status: "pending", priority: plan.priority })]
      );

      if (plan.status === "in_progress") {
        await client.query(
          `INSERT INTO action_plan_history (id, action_plan_id, actor_id, action, details_json)
           VALUES (gen_random_uuid(), $1, $2, 'status_changed', $3::jsonb)`,
          [planId, plan.createdBy, JSON.stringify({ from: "pending", to: "in_progress" })]
        );
      }

      if (plan.comment && plan.commentAuthor) {
        await client.query(
          `INSERT INTO action_plan_comments (id, action_plan_id, author_id, content)
           VALUES (gen_random_uuid(), $1, $2, $3)`,
          [planId, plan.commentAuthor, plan.comment]
        );
      }
    }

    await client.query("COMMIT");

    const totalThreats = parentThreats.length
      + childGroups.reduce((s, g) => s + g.length, 0)
      + standaloneThreats.length;

    console.log("\nDemo seed concluído com sucesso!");
    console.log(`  ${assetData.length} ativos`);
    console.log(`  ${hostData.length} hosts`);
    console.log(`  3 usuários demo (1 admin, 2 operadores)`);
    console.log(`  ${journeyDefs.length} jornadas`);
    console.log(`  1 API com ${endpointDefs.length} endpoints`);
    console.log(`  ${journeyDefs.length * 2} jobs`);
    console.log(`  ${totalThreats} ameaças (${parentThreats.length} pai + filhas + ${standaloneThreats.length} standalone)`);
    console.log(`  ${adTests.length * 2} resultados AD security (2 execuções)`);
    console.log(`  ${schedDefs.length} agendamentos`);
    console.log(`  2 políticas de notificação`);
    console.log(`  ${planDefs.length} planos de ação`);
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
