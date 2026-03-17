/**
 * Seed script: populates the database with fake data for UAT testing.
 * Run: npx tsx scripts/seed.ts
 * Requires DATABASE_URL env var.
 */
import { pool } from "../server/db";

async function seed() {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // --- Get system user id ---
    const sysUser = await client.query(`SELECT id FROM users WHERE email = 'system@samureye.local' LIMIT 1`);
    const systemUserId = sysUser.rows[0]?.id ?? "system";

    // --- Get admin user id ---
    const adminUser = await client.query(`SELECT id FROM users WHERE email = 'admin@example.com' LIMIT 1`);
    const adminId = adminUser.rows[0]?.id;
    if (!adminId) throw new Error("Admin user not found. Start the server first to bootstrap dev admin.");

    // --- Assets ---
    const assetIds: string[] = [];
    const assetValues = [
      ["host", "192.168.1.10", '["producao","web"]'],
      ["host", "192.168.1.20", '["producao","db"]'],
      ["host", "10.0.0.5", '["staging","app"]'],
      ["web_application", "https://app.empresa.local", '["web","producao"]'],
      ["range", "172.16.0.0/24", '["rede-interna"]'],
    ];
    for (const [type, value, tags] of assetValues) {
      const res = await client.query(
        `INSERT INTO assets (id, type, value, tags, created_by) VALUES (gen_random_uuid(), $1, $2, $3::jsonb, $4) RETURNING id`,
        [type, value, tags, adminId]
      );
      assetIds.push(res.rows[0].id);
    }

    // --- Hosts ---
    const hostData = [
      { name: "srv-web-01", os: "Ubuntu 22.04 LTS", type: "server", family: "linux", ips: '["192.168.1.10"]', risk: 78 },
      { name: "srv-db-01", os: "Windows Server 2022", type: "server", family: "windows_server", ips: '["192.168.1.20"]', risk: 65 },
      { name: "dc01.empresa.local", os: "Windows Server 2019", type: "domain", family: "windows_server", ips: '["10.0.0.1"]', risk: 85 },
      { name: "fw-edge-01", os: "FortiOS 7.4.1", type: "firewall", family: "fortios", ips: '["10.0.0.254"]', risk: 42 },
      { name: "ws-dev-01", os: "Windows 11 Pro", type: "desktop", family: "windows_desktop", ips: '["192.168.1.100"]', risk: 30 },
      { name: "srv-app-01", os: "Ubuntu 20.04 LTS", type: "server", family: "linux", ips: '["10.0.0.5"]', risk: 55 },
    ];
    const hostIds: string[] = [];
    for (const h of hostData) {
      const res = await client.query(
        `INSERT INTO hosts (id, name, description, operating_system, type, family, ips, risk_score, raw_score)
         VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6::jsonb, $7, $8) RETURNING id`,
        [h.name, `Host ${h.name}`, h.os, h.type, h.family, h.ips, h.risk, h.risk * 10]
      );
      hostIds.push(res.rows[0].id);
    }

    // --- Journeys (one per type) ---
    const journeyTypes = [
      { name: "Varredura de Superficie", type: "attack_surface" },
      { name: "Auditoria AD", type: "ad_security" },
      { name: "Verificacao EDR/AV", type: "edr_av" },
      { name: "Scan Web", type: "web_application" },
    ];
    const journeyIds: string[] = [];
    for (const j of journeyTypes) {
      const res = await client.query(
        `INSERT INTO journeys (id, name, type, description, created_by)
         VALUES (gen_random_uuid(), $1, $2, $3, $4) RETURNING id`,
        [j.name, j.type, `Jornada de ${j.name}`, adminId]
      );
      journeyIds.push(res.rows[0].id);
    }

    // --- Jobs (2 completed per journey for posture comparison) ---
    const jobIds: string[] = [];
    for (let ji = 0; ji < journeyIds.length; ji++) {
      for (let run = 0; run < 2; run++) {
        const daysAgo = run === 0 ? 1 : 7;
        const res = await client.query(
          `INSERT INTO jobs (id, journey_id, status, progress, started_at, finished_at, created_at)
           VALUES (gen_random_uuid(), $1, 'completed', 100, NOW() - interval '${daysAgo} days' - interval '10 minutes', NOW() - interval '${daysAgo} days', NOW() - interval '${daysAgo} days' - interval '15 minutes')
           RETURNING id`,
          [journeyIds[ji]]
        );
        jobIds.push(res.rows[0].id);
      }
    }

    // --- Posture Snapshots (2 per journey for delta comparison) ---
    const snapshotScores = [
      // [recent_score, old_score] per journey
      [72, 65], // attack_surface improved
      [58, 62], // ad_security worsened
      [81, 78], // edr_av improved
      [45, 45], // web_application stable
    ];
    for (let ji = 0; ji < journeyIds.length; ji++) {
      for (let run = 0; run < 2; run++) {
        const score = run === 0 ? snapshotScores[ji][0] : snapshotScores[ji][1];
        const openCount = Math.floor((100 - score) / 5);
        const critCount = Math.max(0, Math.floor(openCount * 0.2));
        const highCount = Math.max(0, Math.floor(openCount * 0.3));
        const medCount = Math.max(0, Math.floor(openCount * 0.3));
        const lowCount = openCount - critCount - highCount - medCount;
        const jobIdx = ji * 2 + run;
        const daysAgo = run === 0 ? 1 : 7;
        await client.query(
          `INSERT INTO posture_snapshots (id, job_id, journey_id, score, open_threat_count, critical_count, high_count, medium_count, low_count, scored_at)
           VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, NOW() - interval '${daysAgo} days')`,
          [jobIds[jobIdx], journeyIds[ji], score, openCount, critCount, highCount, medCount, lowCount]
        );
      }
    }

    // --- Threats: Parent threats with groupingKey ---
    const parentThreats = [
      {
        title: "Portas expostas em servidores de producao",
        desc: "Multiplas portas de servico expostas sem necessidade em servidores de producao",
        severity: "critical", category: "attack_surface", hostIdx: 0, assetIdx: 0,
        groupingKey: "exposed-ports-producao",
        evidence: { ports: [22, 80, 443, 3306, 8080], protocol: "TCP", scanDate: "2026-03-15" },
        score: 92, projected: 35, ruleId: "exposed-service",
      },
      {
        title: "Contas AD com senha expirada",
        desc: "Contas de servico com senhas que excedem a politica de rotacao",
        severity: "high", category: "ad_security", hostIdx: 2, assetIdx: null,
        groupingKey: "ad-expired-passwords",
        evidence: { accountCount: 12, oldestPasswordAge: "450 dias", policyLimit: "90 dias" },
        score: 78, projected: 45, ruleId: "ad-password-age",
      },
      {
        title: "EDR desatualizado em endpoints",
        desc: "Agente EDR com versao desatualizada em multiplos endpoints",
        severity: "high", category: "edr_av", hostIdx: 4, assetIdx: null,
        groupingKey: "edr-outdated-agents",
        evidence: { currentVersion: "3.2.1", requiredVersion: "4.1.0", affectedCount: 8 },
        score: 71, projected: 55, ruleId: "edr-outdated",
      },
      {
        title: "Vulnerabilidades CVE em aplicacao web",
        desc: "CVEs conhecidas encontradas na aplicacao web principal",
        severity: "critical", category: "web_application", hostIdx: 5, assetIdx: 3,
        groupingKey: "web-cve-detected",
        evidence: { cves: ["CVE-2024-1234", "CVE-2024-5678", "CVE-2023-9012"], cvssMax: 9.8 },
        score: 95, projected: 30, ruleId: "cve-detected",
      },
      {
        title: "Certificados SSL expirados",
        desc: "Certificados SSL/TLS expirados ou proximos da expiracao",
        severity: "medium", category: "attack_surface", hostIdx: 0, assetIdx: 0,
        groupingKey: "ssl-cert-expired",
        evidence: { domain: "app.empresa.local", expiresAt: "2026-02-28", issuer: "Let's Encrypt" },
        score: 55, projected: 10, ruleId: "ssl-expired",
      },
    ];

    const parentThreatIds: string[] = [];
    for (const t of parentThreats) {
      const jIdx = journeyTypes.findIndex(j => j.type === t.category || (t.category === "ad_security" && j.type === "ad_security"));
      const res = await client.query(
        `INSERT INTO threats (id, title, description, severity, status, source, host_id, asset_id, evidence, category, grouping_key, contextual_score, projected_score_after_fix, rule_id, job_id, correlation_key, score_breakdown)
         VALUES (gen_random_uuid(), $1, $2, $3, 'open', 'journey', $4, $5, $6::jsonb, $7, $8, $9, $10, $11, $12, $13, $14::jsonb) RETURNING id`,
        [
          t.title, t.desc, t.severity,
          hostIds[t.hostIdx],
          t.assetIdx !== null ? assetIds[t.assetIdx] : null,
          JSON.stringify(t.evidence),
          t.category, t.groupingKey, t.score, t.projected, t.ruleId,
          jobIds[jIdx * 2], // most recent job
          `${t.ruleId}-${t.groupingKey}`,
          JSON.stringify({ baseSeverityWeight: 0.4, criticalityMultiplier: 1.2, exposureFactor: 0.8, controlsReductionFactor: 0.1, exploitabilityMultiplier: 1.0, rawScore: t.score, normalizedScore: t.score }),
        ]
      );
      parentThreatIds.push(res.rows[0].id);
    }

    // --- Child threats (2-3 per parent) ---
    const childThreatsData = [
      // Children of "Portas expostas" (parent 0)
      [
        { title: "Porta 3306 (MySQL) exposta em srv-web-01", severity: "critical", evidence: { port: 3306, service: "MySQL 8.0", state: "open" }, hostIdx: 0 },
        { title: "Porta 8080 (HTTP alternativa) exposta em srv-web-01", severity: "high", evidence: { port: 8080, service: "Apache Tomcat", state: "open" }, hostIdx: 0 },
        { title: "Porta 22 (SSH) com autenticacao por senha em srv-web-01", severity: "medium", evidence: { port: 22, service: "OpenSSH 8.9", authMethod: "password", state: "open" }, hostIdx: 0 },
      ],
      // Children of "Contas AD" (parent 1)
      [
        { title: "Conta svc-backup com senha de 450 dias", severity: "high", evidence: { account: "svc-backup", passwordAge: "450 dias", lastLogon: "2026-01-10" }, hostIdx: 2 },
        { title: "Conta svc-sql com senha de 380 dias", severity: "high", evidence: { account: "svc-sql", passwordAge: "380 dias", lastLogon: "2026-03-01" }, hostIdx: 2 },
      ],
      // Children of "EDR desatualizado" (parent 2)
      [
        { title: "EDR v3.2.1 em ws-dev-01", severity: "medium", evidence: { hostname: "ws-dev-01", currentVersion: "3.2.1", expectedVersion: "4.1.0" }, hostIdx: 4 },
        { title: "EDR v3.0.0 em srv-app-01", severity: "high", evidence: { hostname: "srv-app-01", currentVersion: "3.0.0", expectedVersion: "4.1.0" }, hostIdx: 5 },
      ],
      // Children of "CVEs web" (parent 3)
      [
        { title: "CVE-2024-1234: RCE em framework web (CVSS 9.8)", severity: "critical", evidence: { cve: "CVE-2024-1234", cvss: 9.8, component: "Spring Framework", fixVersion: "6.1.5" }, hostIdx: 5 },
        { title: "CVE-2024-5678: SQL Injection (CVSS 8.1)", severity: "critical", evidence: { cve: "CVE-2024-5678", cvss: 8.1, component: "Hibernate ORM", fixVersion: "6.4.2" }, hostIdx: 5 },
        { title: "CVE-2023-9012: XSS em template engine (CVSS 6.5)", severity: "medium", evidence: { cve: "CVE-2023-9012", cvss: 6.5, component: "Thymeleaf", fixVersion: "3.1.3" }, hostIdx: 5 },
      ],
      // Children of "SSL expirado" (parent 4)
      [
        { title: "Certificado expirado em app.empresa.local:443", severity: "medium", evidence: { domain: "app.empresa.local", port: 443, expiresAt: "2026-02-28", daysExpired: 17 }, hostIdx: 0 },
      ],
    ];

    for (let pi = 0; pi < childThreatsData.length; pi++) {
      const parent = parentThreats[pi];
      const jIdx = journeyTypes.findIndex(j => j.type === parent.category);
      for (const child of childThreatsData[pi]) {
        const childScore = Math.max(20, (parentThreats[pi].score ?? 50) - Math.floor(Math.random() * 20));
        await client.query(
          `INSERT INTO threats (id, title, description, severity, status, source, host_id, evidence, category, parent_threat_id, contextual_score, projected_score_after_fix, rule_id, job_id, correlation_key, score_breakdown)
           VALUES (gen_random_uuid(), $1, $2, $3, 'open', 'journey', $4, $5::jsonb, $6, $7, $8, $9, $10, $11, $12, $13::jsonb)`,
          [
            child.title, child.title, child.severity,
            hostIds[child.hostIdx],
            JSON.stringify(child.evidence),
            parent.category,
            parentThreatIds[pi],
            childScore, Math.max(10, childScore - 30),
            parent.ruleId,
            jobIds[jIdx * 2],
            `${parent.ruleId}-${child.title.slice(0, 40).replace(/\s/g, '-').toLowerCase()}`,
            JSON.stringify({ baseSeverityWeight: 0.3, criticalityMultiplier: 1.0, exposureFactor: 0.7, controlsReductionFactor: 0.1, exploitabilityMultiplier: 1.0, rawScore: childScore, normalizedScore: childScore }),
          ]
        );
      }
    }

    // --- Standalone threats (no parent/child) ---
    const standaloneThreats = [
      {
        title: "Firewall com regra ANY-ANY ativa",
        severity: "high", category: "attack_surface", hostIdx: 3,
        evidence: { ruleId: "rule-15", action: "allow", source: "any", destination: "any", service: "any" },
        score: 68, projected: 25, ruleId: "firewall-permissive-rule",
      },
      {
        title: "Usuarios no grupo Domain Admins excessivos",
        severity: "high", category: "ad_security", hostIdx: 2,
        evidence: { groupName: "Domain Admins", memberCount: 12, expectedMax: 5, members: ["admin1", "admin2", "svc-backup", "jsilva", "mcarvalho"] },
        score: 74, projected: 50, ruleId: "ad-privileged-group-excess",
      },
      {
        title: "Servico FTP ativo sem criptografia",
        severity: "medium", category: "attack_surface", hostIdx: 1,
        evidence: { port: 21, service: "vsftpd 3.0.5", encryption: "none", state: "open" },
        score: 48, projected: 5, ruleId: "unencrypted-service",
      },
    ];

    for (const t of standaloneThreats) {
      const jIdx = journeyTypes.findIndex(j => j.type === t.category);
      await client.query(
        `INSERT INTO threats (id, title, description, severity, status, source, host_id, evidence, category, contextual_score, projected_score_after_fix, rule_id, job_id, correlation_key, score_breakdown)
         VALUES (gen_random_uuid(), $1, $2, $3, 'open', 'journey', $4, $5::jsonb, $6, $7, $8, $9, $10, $11, $12::jsonb)`,
        [
          t.title, t.title, t.severity,
          hostIds[t.hostIdx],
          JSON.stringify(t.evidence),
          t.category, t.score, t.projected, t.ruleId,
          jobIds[jIdx * 2],
          `${t.ruleId}-standalone-${t.hostIdx}`,
          JSON.stringify({ baseSeverityWeight: 0.3, criticalityMultiplier: 1.0, exposureFactor: 0.6, controlsReductionFactor: 0.1, exploitabilityMultiplier: 1.0, rawScore: t.score, normalizedScore: t.score }),
        ]
      );
    }

    // --- Recommendations (one per parent + standalone) ---
    const allThreatsForRecs = await client.query(
      `SELECT id, title, rule_id, severity, contextual_score, projected_score_after_fix FROM threats WHERE parent_threat_id IS NULL AND status = 'open' ORDER BY contextual_score DESC NULLS LAST`
    );

    const recTemplates: Record<string, { whatIsWrong: string; impact: string; steps: string[]; verify: string; refs: string[]; effort: string; role: string }> = {
      "exposed-service": {
        whatIsWrong: "Portas de servico desnecessarias estao expostas na rede, aumentando a superficie de ataque.",
        impact: "Atacantes podem explorar servicos vulneraveis para obter acesso inicial ao ambiente.",
        steps: ["Identificar servicos necessarios vs. desnecessarios em cada host", "Criar regras de firewall para bloquear portas nao essenciais", "Implementar segmentacao de rede para isolar servicos criticos", "Validar que servicos legitimos continuam acessiveis"],
        verify: "Executar nova varredura de portas e confirmar que apenas portas autorizadas estao abertas.",
        refs: ["https://www.cisecurity.org/controls/v8", "NIST SP 800-41"],
        effort: "hours", role: "Administrador de Rede",
      },
      "ad-password-age": {
        whatIsWrong: "Contas de servico com senhas que excedem o limite da politica de rotacao de credenciais.",
        impact: "Senhas antigas aumentam o risco de comprometimento via brute-force ou credenciais vazadas.",
        steps: ["Listar todas as contas de servico com senha expirada", "Gerar novas senhas complexas para cada conta", "Atualizar credenciais nos servicos dependentes", "Configurar alerta automatico para proximas expiracoes"],
        verify: "Verificar que todas as contas de servico tem senha dentro do prazo da politica.",
        refs: ["CIS Benchmark AD", "NIST SP 800-63B"],
        effort: "hours", role: "Administrador AD",
      },
      "edr-outdated": {
        whatIsWrong: "Agentes EDR com versao desatualizada nao recebem as ultimas assinaturas de deteccao.",
        impact: "Endpoints ficam vulneraveis a ameacas recentes que o EDR atualizado detectaria.",
        steps: ["Verificar console central do EDR para endpoints desatualizados", "Forcar atualizacao via politica de grupo ou console do EDR", "Investigar endpoints que falharam na atualizacao"],
        verify: "Confirmar no console EDR que todos os agentes estao na versao 4.1.0 ou superior.",
        refs: ["Documentacao do fornecedor EDR"],
        effort: "minutes", role: "Analista de Seguranca",
      },
      "cve-detected": {
        whatIsWrong: "CVEs conhecidas com exploits publicos foram encontradas em componentes da aplicacao web.",
        impact: "Exploits publicos permitem que atacantes comprometam a aplicacao remotamente sem autenticacao.",
        steps: ["Priorizar CVEs por CVSS score (criticas primeiro)", "Atualizar dependencias afetadas para versoes corrigidas", "Testar aplicacao apos atualizacoes em ambiente staging", "Aplicar patches em producao com janela de manutencao"],
        verify: "Executar novo scan de vulnerabilidades e confirmar que as CVEs foram remediadas.",
        refs: ["https://nvd.nist.gov", "OWASP Dependency Check"],
        effort: "days", role: "Desenvolvedor",
      },
      "ssl-expired": {
        whatIsWrong: "Certificados SSL/TLS expirados comprometem a criptografia de dados em transito.",
        impact: "Usuarios recebem avisos de seguranca e dados podem ser interceptados por ataques MITM.",
        steps: ["Gerar novo CSR para o dominio afetado", "Solicitar renovacao do certificado na CA", "Instalar o novo certificado no servidor web", "Configurar renovacao automatica (ex: certbot)"],
        verify: "Acessar o site via HTTPS e confirmar certificado valido sem avisos do navegador.",
        refs: ["https://letsencrypt.org/docs/", "Mozilla SSL Configuration Generator"],
        effort: "minutes", role: "Administrador de Sistemas",
      },
      "firewall-permissive-rule": {
        whatIsWrong: "Regra de firewall com ANY-ANY permite todo o trafego sem restricao.",
        impact: "Qualquer comunicacao e permitida, anulando o proposito do firewall como controle de acesso.",
        steps: ["Identificar trafego legitimo que passa pela regra ANY-ANY", "Criar regras especificas para cada fluxo necessario", "Desativar a regra ANY-ANY", "Monitorar logs por 48h para detectar bloqueios incorretos"],
        verify: "Confirmar que regra ANY-ANY esta desativada e servicos continuam funcionando.",
        refs: ["CIS Benchmark Firewalls", "NIST SP 800-41"],
        effort: "hours", role: "Administrador de Rede",
      },
      "ad-privileged-group-excess": {
        whatIsWrong: "O grupo Domain Admins possui mais membros que o recomendado pela politica de seguranca.",
        impact: "Excesso de administradores aumenta o risco de movimentacao lateral e escalacao de privilegios.",
        steps: ["Revisar cada membro do grupo Domain Admins", "Remover contas que nao necessitam de privilegios administrativos completos", "Criar grupos delegados com privilegios minimos necessarios", "Implementar monitoramento de alteracoes no grupo"],
        verify: "Confirmar que Domain Admins tem no maximo 5 membros conforme politica.",
        refs: ["CIS Benchmark AD", "Microsoft Tiered Admin Model"],
        effort: "hours", role: "Administrador AD",
      },
      "unencrypted-service": {
        whatIsWrong: "Servico FTP sem criptografia transmite credenciais e dados em texto plano.",
        impact: "Credenciais podem ser capturadas via sniffing de rede.",
        steps: ["Avaliar necessidade do servico FTP", "Migrar para SFTP ou FTPS", "Desativar servico FTP sem criptografia"],
        verify: "Confirmar que porta 21 (FTP) esta fechada e transferencias usam SFTP/FTPS.",
        refs: ["CIS Controls v8", "NIST SP 800-123"],
        effort: "minutes", role: "Administrador de Sistemas",
      },
    };

    for (const threat of allThreatsForRecs.rows) {
      const tpl = recTemplates[threat.rule_id];
      if (!tpl) continue;
      await client.query(
        `INSERT INTO recommendations (id, threat_id, template_id, title, what_is_wrong, business_impact, fix_steps, verification_step, "references", effort_tag, role_required, status)
         VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6::jsonb, $7, $8::jsonb, $9, $10, 'pending')`,
        [
          threat.id, threat.rule_id,
          `Remediacao: ${threat.title}`,
          tpl.whatIsWrong, tpl.impact,
          JSON.stringify(tpl.steps),
          tpl.verify,
          JSON.stringify(tpl.refs),
          tpl.effort, tpl.role,
        ]
      );
    }

    await client.query("COMMIT");
    console.log("Seed completed successfully!");
    console.log("- 5 assets");
    console.log("- 6 hosts");
    console.log("- 4 journeys (one per type)");
    console.log("- 8 jobs (2 per journey)");
    console.log("- 8 posture snapshots");
    console.log("- 5 parent threats with children + 3 standalone threats");
    console.log("- 8 recommendations");
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Seed failed:", err);
    process.exit(1);
  } finally {
    client.release();
    await pool.end();
  }
}

seed();
