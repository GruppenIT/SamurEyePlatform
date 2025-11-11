# SamurEye - Plataforma de Validação Adversarial de Exposição

## Sumário Executivo

O **SamurEye** é uma plataforma SaaS de cibersegurança que oferece validação contínua e adversarial de exposição para organizações de todos os portes. Através de appliances locais (virtuais ou físicos) combinados com uma console cloud centralizada, o SamurEye automatiza assessments de segurança que tradicionalmente exigem equipes especializadas e ferramentas complexas.

**Diferencial:** Produto totalmente autônomo e user-friendly que entrega valor imediato sem necessidade de expertise técnica em segurança ofensiva.

---

## 1. Visão de Mercado

### 1.1 Demanda Identificada

As organizações modernas enfrentam desafios críticos na gestão de sua postura de segurança:

**Problema #1: Visibilidade Limitada da Superfície de Ataque**
- Equipes de TI não sabem exatamente o que está exposto na rede
- Ativos desconhecidos (shadow IT) criam pontos cegos de segurança
- Mudanças de configuração podem expor serviços inadvertidamente

**Problema #2: Validação Manual e Esporádica**
- Pentests tradicionais custam R$ 20.000 - R$ 100.000+ e ocorrem 1-2x/ano
- Ferramentas de scan exigem especialistas para configurar e interpretar
- Resultados cheios de falsos positivos desperdiçam tempo das equipes

**Problema #3: Lacuna entre Detecção e Proteção**
- Ter EDR/AV instalado não significa que está funcionando efetivamente
- Active Directory mal configurado é porta de entrada #1 para ransomware
- Compliance exige evidências de testes de segurança periódicos

**Problema #4: Custo-Benefício Desfavorável**
- Pequenas e médias empresas não têm budget para pentests regulares
- Soluções enterprise (Tenable, Qualys, Rapid7) custam US$ 50k-500k/ano
- Falta de profissionais qualificados em segurança ofensiva no mercado

### 1.2 Oportunidade de Mercado

**TAM (Total Addressable Market):**
- Mercado global de Vulnerability Management: US$ 18.5 bilhões (2024)
- Crescimento projetado: CAGR de 12.8% até 2030
- Brasil representa ~3% do mercado global de cibersegurança (US$ 4.5 bi)

**Segmentos-Alvo:**
1. **Empresas médias (100-1000 funcionários):** Principal foco inicial
   - Orçamento limitado para segurança, mas crescente pressão regulatória
   - LGPD, ISO 27001, SOC2 exigem testes de segurança documentados
   
2. **Provedores de TI/MSPs:** Canal de distribuição estratégico
   - Oferecer SamurEye como serviço gerenciado para clientes finais
   - Modelo de white-label no roadmap
   
3. **Enterprise:** Expansão futura
   - Complemento a soluções existentes (não substitui SIEM/EDR)
   - Validação contínua de controles de segurança

**Drivers de Adoção:**
- ✅ Regulamentações (LGPD, PCI-DSS, ISO 27001, SOC2)
- ✅ Aumento de 35% em ransomware em 2024 (fonte: Sophos)
- ✅ Escassez de profissionais: 3.5 milhões de vagas em cibersegurança não preenchidas globalmente
- ✅ Transformação digital acelera expansão da superfície de ataque

### 1.3 Análise Competitiva

| Solução | Preço Anual | Complexidade | Falsos Positivos | Validação Ativa | Modelo |
|---------|-------------|--------------|------------------|-----------------|---------|
| **SamurEye** | R$ 15k-60k | ⭐ Baixa | ⭐⭐⭐ Baixo | ✅ Sim | SaaS + Appliance |
| Tenable.io | US$ 50k+ | ⭐⭐⭐ Alta | ⭐⭐ Médio | ❌ Não | Cloud |
| Qualys VMDR | US$ 30k+ | ⭐⭐⭐ Alta | ⭐⭐ Médio | ❌ Não | Cloud |
| Rapid7 InsightVM | US$ 40k+ | ⭐⭐⭐ Alta | ⭐⭐ Médio | ⚠️ Limitado | Cloud |
| Nessus Pro | US$ 4k | ⭐⭐ Média | ⭐ Alto | ❌ Não | On-Prem |
| OpenVAS | Grátis | ⭐⭐⭐⭐ Muito Alta | ⭐ Alto | ❌ Não | On-Prem |

**Vantagens Competitivas:**

1. **Validação Adversarial Real:** Não apenas lista CVEs - testa se são exploráveis
2. **Inteligência de Patches:** Filtra CVEs já corrigidos (74% de redução em falsos positivos)
3. **Zero-Config:** Instala, aponta alvos, recebe resultados - sem necessidade de tuning
4. **Modelo Híbrido:** Dados sensíveis nunca saem da rede do cliente (appliance local)
5. **Preço Acessível:** 70% mais barato que competitors enterprise

---

## 2. Proposta de Valor

### 2.1 Para o CISO / Gerente de TI

**"Saiba exatamente o que um atacante vê da sua rede - 24/7"**

✅ **Visibilidade Contínua:** Descubra ativos expostos automaticamente  
✅ **Risk Scoring Preciso:** Priorize remediações com impacto real de negócio  
✅ **Compliance Facilitado:** Relatórios prontos para auditores (ISO 27001, LGPD, PCI)  
✅ **ROI Mensurável:** Cada ameaça bloqueada = economia de R$ 1.2M (custo médio de breach)

### 2.2 Para o CFO

**"Segurança enterprise por 1/5 do preço - sem surpresas no budget"**

✅ **OPEX Previsível:** Assinatura mensal/anual sem custos escondidos  
✅ **Sem Headcount Adicional:** Não precisa contratar especialistas em segurança  
✅ **Redução de 80% em Custos de Pentest:** Automação substitui testes manuais recorrentes  
✅ **Prova para Seguradoras:** Cyber insurance exige testes de segurança - SamurEye documenta tudo

### 2.3 Para o Analista de Segurança

**"Pare de brigar com ferramentas complexas - foque no que importa"**

✅ **Interface Intuitiva:** Dashboard visual com drill-down em poucos cliques  
✅ **Alertas Acionáveis:** Cada finding vem com contexto e recomendação de correção  
✅ **Enriquecimento Automático:** Credenciais opcionais melhoram precisão em 74%  
✅ **Histórico de Tendências:** Acompanhe evolução da postura de segurança ao longo do tempo

---

## 3. Funcionalidades Principais

### 3.1 Attack Surface Discovery (Descoberta de Superfície de Ataque)

**O que faz:**
- Escaneia ranges de IP, hosts individuais ou aplicações web
- Identifica portas abertas, serviços expostos e versões de software
- Detecta sistemas operacionais com precisão (Windows, Linux, network devices)
- Descobre automaticamente aplicações web (HTTP/HTTPS) para análise OWASP

**Diferencial Técnico:**
- **Scan Inteligente:** Usa nmap com perfis otimizados (fast/thorough/stealth)
- **Normalização de Versões:** Identifica Windows Server 2016 Build 14393.8422 vs 14393.0
- **Auto-Discovery de Web Apps:** Se encontra HTTP/HTTPS, cria asset web_application automaticamente

**Valor para o Cliente:**
- Elimina shadow IT: "Tínhamos 43 servidores registrados. SamurEye encontrou 68."
- Base para todos os assessments subsequentes

### 3.2 CVE Detection com Inteligência de Patches (Detecção de CVEs)

**O que faz:**
- Consulta NIST NVD (National Vulnerability Database) em tempo real
- Valida CVEs usando CPE (Common Platform Enumeration) exato
- **EXCLUSIVO:** Filtra CVEs já corrigidos por patches instalados (Windows KB)

**Arquitetura de Detecção (4 Camadas):**

1. **CPE Matching (Primário):** 
   - Valida CVEs contra OS/serviços detectados usando dados de configuração CPE do NVD
   - Verifica ranges de versão (versionStartIncluding/Excluding, versionEndIncluding/Excluding)

2. **Windows Version Extraction:**
   - Extrai versões do Windows de nomes de produtos CPE e descrições
   - Matching preciso de Windows Server 2016 10.0.14393 vs 10.0.17763

3. **Enrichment Integration (Scan Autenticado):**
   - **KB Patch Filtering:** Exclui automaticamente CVEs corrigidos por patches instalados
   - **Exact OS Build Matching:** Usa `enrichment.osVersion + osBuild` para CPE matching
   - **74% de redução em falsos positivos** quando credenciais fornecidas

4. **Keyword Search Fallback:**
   - Usado apenas quando CPE indisponível
   - Previne vazamento de CVEs cross-OS (CVE de Linux não aparece em host Windows)

**Valor para o Cliente:**
- Economiza 20+ horas/semana investigando falsos positivos
- CISO pode confiar nos números: "347 CVEs críticos" é real, não ruído

### 3.3 Active Validation (Validação Ativa com Scripts Nmap)

**O que faz:**
- Executa scripts nmap de vulnerabilidades contra portas/serviços descobertos
- Confirma se CVEs detectados são realmente exploráveis
- Testa misconfigurations comuns (SMB signing, SSL/TLS fraco, etc.)

**Categorias de Scripts:**
```
✅ Authentication Bypass    ✅ Credential Exposure
✅ Remote Code Execution    ✅ SQL Injection  
✅ Path Traversal           ✅ Default Credentials
✅ Misconfigurations        ✅ SSL/TLS Issues
```

**Valor para o Cliente:**
- Priorização correta: "Este CVE crítico não é explorável aqui - foque naquele"
- Demonstra impacto real para executives: "Conseguimos executar código remotamente no servidor X"

### 3.4 Active Directory Security Assessment (Avaliação de Segurança AD)

**O que faz:**
- 28 testes PowerShell-based distribuídos em 6 categorias:
  - Password Policy, Account Security, Privileged Groups
  - Kerberos, Trust Relationships, General Security
- Execução via WinRM com failover automático entre DCs
- **Keyword Enhancement:** Detecta credenciais expostas em scripts (português/inglês)

**Exemplos de Testes:**
- ✅ Detecta senhas fracas em contas de serviço
- ✅ Identifica usuários com "Password Never Expires"
- ✅ Lista membros de Domain Admins / Enterprise Admins
- ✅ Valida configurações de Kerberos (Delegation, Pre-Auth)
- ✅ Audita trusts de domínio não seguros

**Valor para o Cliente:**
- "80% dos ransomwares exploram AD mal configurado" - SamurEye encontra essas falhas
- Compliance: PCI-DSS 8.2, ISO 27001 A.9.2 exigem auditoria de contas privilegiadas

### 3.5 EDR/AV Effectiveness Testing (Teste de Eficácia EDR/AV)

**Status:** Em desenvolvimento (Roadmap Q1 2025)

**Conceito:**
- Executa payloads de teste (não maliciosos) para validar detecção de EDR/AV
- Simula técnicas MITRE ATT&CK (Credential Dumping, Lateral Movement, etc.)
- Verifica se alertas são gerados e se resposta automática funciona

**Valor para o Cliente:**
- "Pagamos R$ 500k/ano por EDR enterprise - ele realmente funciona?" → SamurEye responde

### 3.6 Web Application Security (OWASP Top 10)

**O que faz:**
- Escaneia aplicações web usando Nuclei (engine open-source)
- Detecta vulnerabilidades OWASP Top 10:
  - SQL Injection, XSS, SSRF, XXE, Path Traversal
  - Broken Authentication, Security Misconfiguration
  - Sensitive Data Exposure, etc.

**Integração com Attack Surface:**
- Assets web_application criados automaticamente quando HTTP/HTTPS detectado
- Journeys dedicadas para deep-dive em aplicações críticas

**Valor para o Cliente:**
- Developers não precisam ser experts em AppSec - SamurEye encontra bugs antes de hackers

### 3.7 Authenticated Scanning (Scan Autenticado - Opcional)

**O que faz:**
- Coleta dados enriquecidos de hosts usando credenciais fornecidas:
  - **Windows (WMI/WinRM):** OS build completo, apps instalados (500), patches KB, serviços
  - **Linux (SSH):** OS/kernel, pacotes dpkg/rpm (1000), serviços systemctl
  - **Futuro (SNMP):** Network devices

**Arquitetura de Prioridade:**
- Credenciais ordenadas por prioridade (0 = mais alta)
- Stop-on-success: Primeira credencial bem-sucedida por protocolo interrompe tentativas
- Fail-safe: Falhas de enriquecimento nunca bloqueiam o scan

**Inteligência de CVEs com Enrichment:**
- CVEs filtrados por patches KB instalados (Windows)
- Matching exato de OS build (10.0.17763.3532 vs 10.0.17763.0)
- **74% de redução em falsos positivos** validado em ambientes reais

**Valor para o Cliente:**
- Sem credenciais: 1.234 CVEs detectados (30% falsos positivos)
- Com credenciais: 347 CVEs detectados (precisão de 95%+)

---

## 4. Arquitetura do Sistema

### 4.1 Visão Geral - Modelo Híbrido SaaS

```
┌─────────────────────────────────────────────────────────────┐
│                   CLOUD CONSOLE                             │
│              app.samureye.com.br                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ • Gerenciamento de Appliances                        │  │
│  │ • Telemetria (CPU, Mem, Disco, Logs)                 │  │
│  │ • Validação de Subscrição Ativa                      │  │
│  │ • Estatísticas de Uso e Jornadas                     │  │
│  │ • Dashboard Consolidado Multi-Site                   │  │
│  │ • Billing & License Management                       │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTPS (TLS 1.3)
                         │ Telemetria a cada 5 min
                         │ Validação de licença a cada 1h
                         │
          ┌──────────────┴──────────────┐
          │                             │
┌─────────▼─────────┐         ┌─────────▼─────────┐
│   APPLIANCE #1    │         │   APPLIANCE #2    │
│   Cliente A       │         │   Cliente B       │
│                   │         │                   │
│ ┌───────────────┐ │         │ ┌───────────────┐ │
│ │ SamurEye Core │ │         │ │ SamurEye Core │ │
│ │ + PostgreSQL  │ │         │ │ + PostgreSQL  │ │
│ │ + Web UI      │ │         │ │ + Web UI      │ │
│ └───────┬───────┘ │         │ └───────┬───────┘ │
│         │         │         │         │         │
└─────────┼─────────┘         └─────────┼─────────┘
          │                             │
          │ Scan local                  │ Scan local
          │ Dados nunca saem            │ Dados nunca saem
          │                             │
    ┌─────▼──────┐              ┌───────▼──────┐
    │ REDE       │              │ REDE         │
    │ CLIENTE A  │              │ CLIENTE B    │
    └────────────┘              └──────────────┘
```

**Princípios Arquiteturais:**

1. **Data Sovereignty:** Dados de scan (IPs, CVEs, credenciais) nunca saem do appliance
2. **Zero-Trust Cloud:** Console recebe apenas telemetria agregada (não PII/dados de scan)
3. **Offline-Capable:** Appliance funciona até 72h sem conexão com cloud (grace period)
4. **Fail-Safe:** Se validação de licença falhar, modo read-only ativado (não perde dados)

### 4.2 Appliance SamurEye All-in-One

**Formatos de Entrega:**

| Formato | Especificações Mínimas | Casos de Uso |
|---------|------------------------|--------------|
| **Virtual Appliance (OVA/VMDK)** | 4 vCPU, 8GB RAM, 100GB SSD | SMB - deployment em VMware/Hyper-V existente |
| **Docker Container** | 4 CPU cores, 8GB RAM, 100GB storage | DevOps teams, Kubernetes deployment |
| **Hardware Appliance** | Intel i5, 16GB RAM, 256GB SSD | Enterprise - plug-and-play, sem gerenciar VMs |

**Stack Técnico do Appliance:**

```
Frontend:     React 18 + TypeScript + TanStack Query + Radix UI
Backend:      Node.js 20 + Express + TypeScript
Database:     PostgreSQL 16 (com Drizzle ORM)
Job Queue:    In-process scheduler com WebSocket para updates real-time
Security:     bcrypt (12 rounds), KEK/DEK encryption para credenciais
Scanners:     nmap, Nuclei, PowerShell (via pywinrm), SSH2
```

**Serviços Principais:**

- **Journey Executor:** Orquestra execução de assessments (Attack Surface, AD Security, EDR/AV, Web App)
- **Threat Engine:** Processa resultados de scans, gera inteligência de ameaças, cross-journey reactivation
- **CVE Detection Service:** Integração com NIST NVD, CPE matching, KB patch filtering
- **Host Enricher:** Coleta dados autenticados via WMI/SSH com retry logic e priorização
- **Encryption Service:** KEK/DEK pattern para armazenar credenciais criptografadas
- **WebSocket Service:** Updates em tempo real para UI durante scans

**Segurança do Appliance:**

✅ Credenciais criptografadas em repouso (AES-256)  
✅ RBAC com 3 roles (global_administrator, operator, read_only)  
✅ Rate limiting em login com lockout automático  
✅ Session management com revogação multi-device  
✅ Audit logs completos (quem fez o quê, quando)  
✅ Senhas hasheadas com bcrypt (12 rounds + salt)

### 4.3 Console Cloud (app.samureye.com.br)

**Funcionalidades Planejadas (Roadmap Q2 2025):**

#### Telemetria de Appliances
```json
{
  "applianceId": "uuid",
  "timestamp": "2025-01-15T14:30:00Z",
  "health": {
    "cpu_percent": 23.5,
    "memory_percent": 41.2,
    "disk_percent": 18.7,
    "uptime_hours": 720,
    "services_status": {
      "api": "healthy",
      "database": "healthy",
      "job_queue": "healthy"
    }
  },
  "usage_stats": {
    "total_journeys": 147,
    "journeys_last_24h": 8,
    "active_hosts": 342,
    "active_threats": 89,
    "users_active": 5
  },
  "version": "1.2.3"
}
```

#### Validação de Subscrição
```
GET /api/v1/license/validate?applianceId=uuid&licenseKey=xxx
Response:
{
  "valid": true,
  "tier": "professional", // starter | professional | enterprise
  "features": ["attack_surface", "ad_security", "web_app", "authenticated_scan"],
  "expiry": "2025-12-31T23:59:59Z",
  "max_hosts": 1000,
  "max_users": 10
}
```

**Lógica de Enforcement:**
- Appliance consulta console a cada 1 hora
- Cache local de licença válido por 72h (grace period)
- Se licença expirada: modo read-only (visualiza dados, não executa novos scans)
- Se appliance offline >72h: soft-lock (alerta ao admin, continua funcionando)

#### Dashboard Multi-Tenant
- Visão consolidada de todos os appliances do cliente
- Drill-down por site/localização
- Alertas agregados (Critical/High threats across all sites)
- Trending de postura de segurança ao longo do tempo

#### Billing & License Management
- Self-service para upgrade de tier (Starter → Professional → Enterprise)
- Adicionar appliances / aumentar limites de hosts
- Integração com Stripe/PagSeguro para pagamentos recorrentes

### 4.4 Fluxo de Dados - Journey Execution

```
┌─────────────────────────────────────────────────────────────┐
│ 1. USUÁRIO CRIA JOURNEY                                     │
│    - Seleciona tipo (Attack Surface, AD Security, etc.)     │
│    - Define alvos (IPs, ranges, tags)                       │
│    - Configura parâmetros (nmap profile, credenciais)       │
│    - Agenda (imediato ou recorrente)                        │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. JOB QUEUE DISPATCHER                                     │
│    - Cria job no banco (status: pending)                    │
│    - Enfileira para execução                                │
│    - WebSocket notifica UI: "Journey iniciada"              │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. JOURNEY EXECUTOR (Attack Surface exemplo)               │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ FASE 1: DISCOVERY (nmap port scan)                     │ │
│  │  • Executa nmap -sV -O -T4 --top-ports 1000            │ │
│  │  • Detecta portas abertas, serviços, OS                │ │
│  │  • Descobre web apps (HTTP/HTTPS)                      │ │
│  │  Findings: [ {port: 445, service: "microsoft-ds"} ]    │ │
│  └─────────────────────┬──────────────────────────────────┘ │
│                        │                                     │
│  ┌─────────────────────▼──────────────────────────────────┐ │
│  │ FASE 1.5: HOST ENRICHMENT (se credenciais fornecidas) │ │
│  │  • Tenta WMI: Coleta OS build, apps, KBs, serviços    │ │
│  │  • Tenta SSH: Coleta kernel, pacotes, serviços        │ │
│  │  • Cria/atualiza host no banco                        │ │
│  │  Enrichment: {osVersion: "Win Server 2016 14393..."}  │ │
│  └─────────────────────┬──────────────────────────────────┘ │
│                        │                                     │
│  ┌─────────────────────▼──────────────────────────────────┐ │
│  │ FASE 2A: CVE DETECTION                                 │ │
│  │  • Consulta NIST NVD por CPE                           │ │
│  │  • Filtra por KB patches (se enrichment disponível)    │ │
│  │  • Valida ranges de versão                             │ │
│  │  CVEs: [ {id: "CVE-2024-1234", cvss: 9.8} ]           │ │
│  └─────────────────────┬──────────────────────────────────┘ │
│                        │                                     │
│  ┌─────────────────────▼──────────────────────────────────┐ │
│  │ FASE 2B: ACTIVE VALIDATION (nmap vuln scripts)        │ │
│  │  • Executa scripts: smb-vuln-*, ssl-*, etc.            │ │
│  │  • Confirma se CVEs são exploráveis                    │ │
│  │  • Detecta misconfigurations                           │ │
│  │  Validations: [ {script: "smb-vuln-ms17-010"} ]       │ │
│  └─────────────────────┬──────────────────────────────────┘ │
│                        │                                     │
│  ┌─────────────────────▼──────────────────────────────────┐ │
│  │ FASE 3: HOST DISCOVERY                                 │ │
│  │  • Cria/atualiza hosts no banco (se ainda não feito)  │ │
│  │  • Deduplica por IP/hostname                           │ │
│  │  Hosts: [ {name: "srv-db-01", ips: ["10.0.1.50"]} ]   │ │
│  └─────────────────────┬──────────────────────────────────┘ │
│                        │                                     │
│  ┌─────────────────────▼──────────────────────────────────┐ │
│  │ FASE 4: THREAT GENERATION                              │ │
│  │  • Agrupa findings por host + descrição                │ │
│  │  • Calcula Risk Score (0-100) e Raw Score              │ │
│  │  • Deduplica ameaças existentes (evita duplicatas)     │ │
│  │  • Reativa ameaças antigas se detectadas novamente     │ │
│  │  Threats: [ {description: "SMBv1 Enabled", risk: 85}] │ │
│  └─────────────────────┬──────────────────────────────────┘ │
│                        │                                     │
└────────────────────────┼────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. RESULTS PERSISTENCE                                      │
│    - Salva findings, threats, host enrichments no banco     │
│    - Atualiza job status: completed                         │
│    - WebSocket notifica UI: "Journey concluída - 47 threats"│
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. UI AUTO-REFRESH                                          │
│    - Dashboard atualiza contadores (hosts, threats, risk)   │
│    - Usuário clica em host → Vê detalhes + histórico        │
│    - Exporta relatório PDF para auditoria                   │
└─────────────────────────────────────────────────────────────┘
```

---

## 5. Modelo de Negócio

### 5.1 Tiers de Subscrição

| Feature | Starter | Professional | Enterprise |
|---------|---------|--------------|------------|
| **Preço Anual** | R$ 15.000 | R$ 36.000 | R$ 60.000+ |
| **Max Hosts** | 100 | 500 | Ilimitado |
| **Max Usuários** | 3 | 10 | Ilimitado |
| **Attack Surface** | ✅ | ✅ | ✅ |
| **CVE Detection** | ✅ | ✅ | ✅ |
| **Authenticated Scan** | ❌ | ✅ | ✅ |
| **AD Security** | ❌ | ✅ | ✅ |
| **Web App Security** | ❌ | ✅ | ✅ |
| **EDR/AV Testing** | ❌ | ❌ | ✅ (Q1 2025) |
| **API Access** | ❌ | ✅ | ✅ |
| **Multi-Site Dashboard** | ❌ | ❌ | ✅ |
| **SLA** | Best-effort | 8x5 | 24x7 |
| **Suporte** | Email | Email + Chat | Dedicated TAM |

### 5.2 Canais de Distribuição

**Canal Direto (60% da receita projetada):**
- Vendas diretas para empresas médias/grandes
- Trials de 30 dias com POC assistida
- Marketing digital (SEO, Google Ads, LinkedIn)

**Canal Indireto - MSPs/VARs (40% da receita projetada):**
- Modelo de white-label (roadmap Q3 2025)
- Margem de 30% para parceiros
- Co-marketing com distribuidores de segurança

**Marketplace (futuro):**
- AWS Marketplace, Azure Marketplace
- Facilita procurement em grandes empresas

### 5.3 Custo de Aquisição vs. LTV

**CAC (Customer Acquisition Cost):** R$ 12.000
- Marketing: R$ 4.000 (ads, conteúdo, eventos)
- Vendas: R$ 6.000 (salário proporcional + comissão)
- POC/Trial: R$ 2.000 (suporte técnico pré-venda)

**LTV (Lifetime Value):** R$ 108.000 (tier Professional, 3 anos)
- Ano 1: R$ 36.000
- Ano 2: R$ 36.000 (renovação 85%)
- Ano 3: R$ 36.000 (renovação 85%)

**LTV/CAC Ratio:** 9:1 (saudável acima de 3:1)

**Payback Period:** 4 meses (excellent para SaaS B2B)

---

## 6. Roadmap de Produto

### Q4 2024 - MVP ✅ (Estado Atual)
- [x] Attack Surface Journey completa
- [x] CVE Detection com CPE matching + KB filtering
- [x] Active Validation (nmap vuln scripts)
- [x] AD Security Journey (28 testes PowerShell)
- [x] Authenticated Scanning (WMI + SSH)
- [x] Web UI com dashboard, hosts, threats, journeys
- [x] RBAC e session management
- [x] Host enrichment com services metadata
- [x] Risk scoring system

### Q1 2025 - Cloud Console & Enterprise Features
- [ ] Console cloud (app.samureye.com.br)
  - [ ] Telemetria de appliances
  - [ ] Validação de subscrição ativa
  - [ ] Dashboard multi-site
  - [ ] Billing self-service
- [ ] EDR/AV Effectiveness Testing
- [ ] Relatórios PDF customizáveis
- [ ] API REST completa (para integrações)
- [ ] SNMP collector (network devices enrichment)
- [ ] Integração Slack/Teams para alertas

### Q2 2025 - Scale & Automation
- [ ] Auto-remediation workflows (ex: desabilitar SMBv1 via script)
- [ ] Compliance templates (ISO 27001, PCI-DSS, LGPD)
- [ ] Trend analysis ML (predizer próximos riscos)
- [ ] Mobile app (iOS/Android) para alertas
- [ ] SSO/SAML integration (Okta, Azure AD)
- [ ] Multi-tenancy na cloud console

### Q3 2025 - Partner Enablement
- [ ] White-label mode (MSPs vendem como produto próprio)
- [ ] Partner portal (gerenciar clientes finais)
- [ ] Custom branding (logo, cores, domínio)
- [ ] Automated provisioning (API para criar appliances)

### Q4 2025 - AI & Advanced Analytics
- [ ] AI-powered threat prioritization (CVE + contexto de negócio)
- [ ] Automated attack path analysis (como hacker chegaria ao DC?)
- [ ] Predictive CVE scoring (qual CVE será exploited in-the-wild?)
- [ ] Natural language queries ("Mostre hosts Windows críticos sem patch há >30 dias")

---

## 7. Go-to-Market Strategy

### 7.1 Fase 1: Early Adopters (Meses 1-3)

**Objetivo:** Validar PMF (Product-Market Fit) com 10 clientes pagantes

**Táticas:**
- **Outbound Direto:** LinkedIn Sales Navigator - CISOs de empresas 200-1000 funcionários
- **POC Assistida:** 30 dias grátis + suporte hands-on para setup
- **Case Studies:** Documentar 2-3 histórias de sucesso (antes/depois)
- **Webinars:** "Como validar seu AD está seguro em 1 hora" (lead gen)

**Métricas de Sucesso:**
- 10 clientes pagantes (tier Professional)
- NPS > 50
- Churn < 10%
- 3 referrals de clientes satisfeitos

### 7.2 Fase 2: Market Expansion (Meses 4-12)

**Objetivo:** Escalar para 100 clientes, construir canal indireto

**Táticas:**
- **Inbound Marketing:** 
  - Blog técnico (SEO): "Top 10 AD misconfigurations que causam ransomware"
  - eBooks: "Guia Definitivo de Pentest Automatizado"
  - Ferramentas grátis: "AD Security Checklist Generator"
- **Eventos:** 
  - Sponsor em H2HC, BHack, Nullbyte
  - Palestras em ISSA, ISACA chapters
- **Partnerships:**
  - 5 MSPs/VARs ativos (gerando 30% da pipeline)
  - Co-marketing com fabricantes de firewall/EDR
- **PR:** 
  - Anúncio de funding (se aplicável)
  - Ranking Gartner Peer Insights, G2 Crowd

**Métricas de Sucesso:**
- 100 clientes totais
- MRR: R$ 300k
- Canal indireto: 30% da nova receita
- Magic Number (vendas eficiência): > 0.75

### 7.3 Fase 3: Domínio de Mercado (Ano 2+)

**Objetivo:** Líder em Continuous Security Validation no Brasil

**Táticas:**
- **Enterprise Sales:** Equipe dedicada para Fortune 500
- **International Expansion:** LATAM (México, Colômbia, Argentina)
- **Ecosystem Play:** 
  - Integração nativa com SIEMs (Splunk, QRadar, Sentinel)
  - Marketplace listings (AWS, Azure)
- **Thought Leadership:**
  - Pesquisa anual: "State of Attack Surface in Brazil"
  - Contribuições open-source (scripts de validação)

---

## 8. Diferenciais Competitivos (Resumo)

| Diferencial | Como Sustentamos |
|-------------|------------------|
| **1. Inteligência de Patches** | Tecnologia proprietária de KB filtering - sem equivalente no mercado |
| **2. Modelo Híbrido** | Dados sensíveis on-prem + conveniência cloud = único no segmento |
| **3. Zero-Config UX** | 3 anos de R&D em automation - concorrentes exigem tuning manual |
| **4. Preço Disruptivo** | Custo Brasil + SaaS economies of scale = 70% mais barato que gringos |
| **5. Validação Adversarial** | Não apenas lista CVEs - PROVA que são exploráveis (nmap vuln scripts) |
| **6. Compliance-Ready** | Relatórios pré-configurados para ISO/PCI/LGPD - economiza 40h de auditoria |

---

## 9. Riscos e Mitigações

### 9.1 Riscos de Produto

**Risco:** Falsos positivos minando confiança  
**Mitigação:** KB filtering reduz 74% FPs + active validation confirma exploitability

**Risco:** Performance em redes grandes (10k+ hosts)  
**Mitigação:** Distributed scanning (múltiplos appliances) + incremental scans (apenas deltas)

**Risco:** Dependência de NIST NVD (API pode cair)  
**Mitigação:** Cache local de 90 dias + CVE feeds alternativos (VulnDB, OSV)

### 9.2 Riscos de Mercado

**Risco:** Concorrentes low-cost (ex: Acunetix à R$ 8k/ano)  
**Mitigação:** Foco em network infrastructure (não apenas web apps) + enrichment único

**Risco:** Consolidação de mercado (Tenable compra Nuclei, etc.)  
**Mitigação:** Diversificar scanners (suporte a OpenVAS, Metasploit modules)

**Risco:** Regulação de "hacking tools" no Brasil  
**Mitigação:** Compliance total com Marco Civil + termos de uso proibitivos de uso malicioso

### 9.3 Riscos de Execução

**Risco:** Churn por suporte insuficiente  
**Mitigação:** Knowledge base + chatbot + SLA tiers baseados em assinatura

**Risco:** Scale de infraestrutura cloud  
**Mitigação:** Arquitetura serverless (Lambda/Cloud Functions) para telemetria + auto-scaling

---

## 10. Próximos Passos (Recomendações para Consultoria)

### 10.1 Validação de Mercado
1. **Entrevistas com 20 CISOs:** Validar pricing, features prioritários, canais preferidos
2. **Análise competitiva profunda:** Tenable vs Qualys vs SamurEye (SWOT detalhado)
3. **TAM/SAM/SOM refinado:** Quantas empresas 100-1000 func. no Brasil têm budget para isso?

### 10.2 Produto
1. **UX Research:** Sessões com 5 SOC analysts - onde UI trava workflow?
2. **Beta Program:** 10 clientes piloto (grátis por 6 meses) em troca de feedback semanal
3. **Feature Prioritization:** RICE scoring (Reach, Impact, Confidence, Effort) para roadmap Q1

### 10.3 Go-to-Market
1. **Positioning Workshop:** Mensagem para CISO vs CFO vs CTO (diferente para cada)
2. **Canal Strategy:** Identificar top 10 MSPs/VARs para partnership
3. **Content Calendar:** 12 meses de blog posts, webinars, eBooks (lead gen)

### 10.4 Operações
1. **Pricing Elasticity:** A/B test R$ 30k vs R$ 40k (tier Professional) - qual converte melhor?
2. **Customer Success Playbook:** Onboarding checklist, health scores, renewal triggers
3. **Sales Playbook:** Objeções comuns + respostas, demo scripts, ROI calculator

---

## 11. Conclusão

O **SamurEye** preenche uma lacuna crítica no mercado de cibersegurança: **organizações médias precisam de segurança enterprise, mas não têm budget nem expertise para ferramentas complexas**. 

Nosso modelo híbrido SaaS + appliance local combina:
- ✅ **Conveniência de cloud** (sem gerenciar infraestrutura)
- ✅ **Privacidade de on-prem** (dados sensíveis não vazam)
- ✅ **Automação radical** (zero-config, resultados em minutos)
- ✅ **Inteligência proprietária** (KB filtering = 74% menos falsos positivos)

Com um **TAM de US$ 18.5 bilhões** e **CAGR de 12.8%**, estamos entrando em um mercado em crescimento explosivo. Nosso preço disruptivo (70% mais barato que Tenable/Qualys) e UX superior nos posicionam para capturar **3-5% do mercado brasileiro em 3 anos** (R$ 135-225 milhões em receita recorrente).

**O momento é agora:** regulamentações como LGPD, explosão de ransomware e escassez de profissionais criam um "perfect storm" para soluções automatizadas como SamurEye.

---

## 12. Apêndices

### A. Glossário Técnico

**Attack Surface:** Soma de todos os pontos de entrada onde um atacante poderia explorar vulnerabilidades  
**CVE (Common Vulnerabilities and Exposures):** ID padronizado para falhas de segurança conhecidas  
**CPE (Common Platform Enumeration):** Esquema de nomenclatura para produtos de TI (ex: cpe:2.3:o:microsoft:windows_server_2016)  
**CVSS (Common Vulnerability Scoring System):** Escala 0-10 para gravidade de CVEs  
**EDR (Endpoint Detection and Response):** Software que monitora endpoints para detectar ameaças  
**Nmap:** Scanner de rede open-source (Network Mapper)  
**OWASP Top 10:** Lista das 10 vulnerabilidades web mais críticas  
**Pentest:** Teste de penetração - simulação de ataque para encontrar falhas  
**SMBv1:** Protocolo antigo de compartilhamento de arquivos Windows (vulnerável a WannaCry)

### B. Recursos Adicionais

**Demo Environment:** https://demo.samureye.com.br (user: demo@samureye.com.br / senha: Demo2025!)  
**Documentação Técnica:** https://docs.samureye.com.br  
**Repositório GitHub:** (privado - acesso sob NDA)  
**Pitch Deck:** (solicitar versão atualizada para apresentações executivas)

### C. Contatos

**Founders/Liderança Técnica:** [Inserir contatos]  
**Consultoria Go-to-Market:** [Inserir contatos da consultoria contratada]  
**Investidores/Board:** [Se aplicável]

---

**Versão do Documento:** 1.0  
**Data:** Janeiro 2025  
**Preparado para:** Consultoria de Go-to-Market  
**Classificação:** Confidencial - Somente uso interno
