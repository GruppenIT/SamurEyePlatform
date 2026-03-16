# SamurEye - Plataforma de Validacao Adversarial de Exposicao

**Versao do Documento:** 2.0
**Data:** Marco 2026
**Classificacao:** Confidencial - Somente uso interno

---

## Sumario Executivo

O **SamurEye** e uma plataforma SaaS de ciberseguranca que oferece validacao continua e adversarial de exposicao para organizacoes de todos os portes. Atraves de appliances locais (virtuais ou fisicos) combinados com uma console cloud centralizada, o SamurEye automatiza assessments de seguranca que tradicionalmente exigem equipes especializadas e ferramentas complexas.

**Diferencial:** Produto totalmente autonomo e user-friendly que entrega valor imediato sem necessidade de expertise tecnica em seguranca ofensiva.

---

## 1. Proposito e Visao

### 1.1 Missao

Democratizar a seguranca ofensiva, permitindo que organizacoes de qualquer porte validem continuamente sua postura de seguranca com a mesma profundidade de um pentest profissional -- sem depender de especialistas escassos ou ferramentas complexas.

### 1.2 Problemas que Resolve

**Problema #1: Visibilidade Limitada da Superficie de Ataque**
- Equipes de TI nao sabem exatamente o que esta exposto na rede
- Ativos desconhecidos (shadow IT) criam pontos cegos de seguranca
- Mudancas de configuracao podem expor servicos inadvertidamente

**Problema #2: Validacao Manual e Esporadica**
- Pentests tradicionais custam R$ 20.000 - R$ 100.000+ e ocorrem 1-2x/ano
- Ferramentas de scan exigem especialistas para configurar e interpretar
- Resultados cheios de falsos positivos desperdicam tempo das equipes

**Problema #3: Lacuna entre Deteccao e Protecao**
- Ter EDR/AV instalado nao significa que esta funcionando efetivamente
- Active Directory mal configurado e porta de entrada #1 para ransomware
- Compliance exige evidencias de testes de seguranca periodicos

**Problema #4: Custo-Beneficio Desfavoravel**
- Pequenas e medias empresas nao tem budget para pentests regulares
- Solucoes enterprise (Tenable, Qualys, Rapid7) custam US$ 50k-500k/ano
- Falta de profissionais qualificados em seguranca ofensiva no mercado

### 1.3 Proposta de Valor

| Persona | Proposta |
|---------|----------|
| **CISO / Gerente de TI** | Visibilidade continua da superficie de ataque, risk scoring preciso, relatorios de compliance prontos (ISO 27001, LGPD, PCI-DSS) |
| **CFO** | OPEX previsivel (assinatura), sem headcount adicional, reducao de 80% em custos de pentest, documentacao para cyber insurance |
| **Analista de Seguranca** | Interface intuitiva, alertas acionaveis com recomendacao de correcao, enriquecimento automatico com credenciais, historico de tendencias |

---

## 2. Publico-Alvo

### 2.1 Segmento Primario: Empresas Medias (100-1.000 funcionarios)

- Orcamento limitado para seguranca, mas crescente pressao regulatoria
- LGPD, ISO 27001, SOC2 exigem testes de seguranca documentados
- Equipes de TI generalistas que precisam de ferramentas autonomas
- Tipicamente possuem infraestrutura Windows/AD que requer auditoria

### 2.2 Segmento Estrategico: Provedores de TI / MSPs

- Canal de distribuicao para clientes finais
- Oferecem SamurEye como servico gerenciado
- Modelo de white-label no roadmap para branding proprio
- Margem de 30% para parceiros

### 2.3 Segmento Futuro: Enterprise

- Complemento a solucoes existentes (nao substitui SIEM/EDR)
- Validacao continua de controles de seguranca
- Multi-site com dashboard consolidado na console cloud

### 2.4 Drivers de Adocao

- Regulamentacoes crescentes (LGPD, PCI-DSS, ISO 27001, SOC2)
- Aumento de ransomware e ameacas ciberneticas
- Escassez global de profissionais de ciberseguranca (3.5 milhoes de vagas nao preenchidas)
- Transformacao digital acelerando expansao da superficie de ataque

---

## 3. Arquitetura do Sistema

### 3.1 Visao Geral - Modelo Hibrido SaaS

O SamurEye adota uma arquitetura hibrida onde dados sensiveis de scan permanecem no appliance local do cliente, enquanto a console cloud centraliza telemetria, licenciamento e gestao multi-site.

```
+-------------------------------------------------------------+
|                   CLOUD CONSOLE                              |
|              app.samureye.com.br                             |
|  +--------------------------------------------------------+ |
|  | - Gerenciamento de Appliances                           | |
|  | - Telemetria (CPU, Mem, Disco, Rede, Servicos)          | |
|  | - Validacao de Subscricao Ativa                         | |
|  | - Estatisticas de Uso e Jornadas                        | |
|  | - Dashboard Consolidado Multi-Site                      | |
|  | - Billing & License Management                          | |
|  | - Despacho de Comandos (update, restart)                | |
|  +--------------------------------------------------------+ |
+-----------------------------+-------------------------------+
                              | HTTPS (TLS 1.3)
                              | Heartbeat a cada 5 min (ativo)
                              | Heartbeat a cada 30 min (standby)
                              | Validacao de licenca via API key
                              |
           +------------------+------------------+
           |                                     |
+----------v----------+            +-------------v---------+
|   APPLIANCE #1      |            |   APPLIANCE #2        |
|   Cliente A         |            |   Cliente B           |
|                     |            |                       |
| +-----------------+ |            | +-----------------+   |
| | SamurEye Core   | |            | | SamurEye Core   |   |
| | + PostgreSQL 16 | |            | | + PostgreSQL 16 |   |
| | + Web UI (React)| |            | | + Web UI (React)|   |
| | + WebSocket     | |            | | + WebSocket     |   |
| +--------+--------+ |            | +--------+--------+   |
|          |           |            |          |            |
+----------+-----------+            +----------+------------+
           |                                   |
           | Scan local                        | Scan local
           | Dados nunca saem                  | Dados nunca saem
           |                                   |
     +-----v------+                     +------v------+
     | REDE       |                     | REDE        |
     | CLIENTE A  |                     | CLIENTE B   |
     +------------+                     +-------------+
```

**Principios Arquiteturais:**

1. **Data Sovereignty:** Dados de scan (IPs, CVEs, credenciais) nunca saem do appliance
2. **Zero-Trust Cloud:** Console recebe apenas telemetria agregada (contadores, metricas de performance -- nenhum PII ou dado de scan)
3. **Offline-Capable:** Appliance funciona ate 72h sem conexao com cloud (grace period)
4. **Fail-Safe:** Se validacao de licenca falhar, modo read-only ativado (dados preservados, novos scans bloqueados)
5. **Graceful Shutdown:** Handlers para SIGTERM/SIGINT com timeout de 10s, fechamento ordenado de HTTP, WebSocket, scheduler e pool PostgreSQL

### 3.2 Stack Tecnologico do Appliance

```
Frontend:     React 18 + TypeScript + TanStack Query v5 + Radix UI + shadcn/ui
Estilizacao:  Tailwind CSS 3 + tailwindcss-animate + Framer Motion
Roteamento:   Wouter (client-side routing leve)
Backend:      Node.js 20 + Express 4 + TypeScript
Database:     PostgreSQL 16 (Drizzle ORM + drizzle-zod para validacao)
Sessoes:      express-session + connect-pg-simple (store PostgreSQL)
Job Queue:    In-process scheduler (60s polling) + WebSocket real-time
Logging:      Pino (structured JSON logging com modulos nomeados)
Security:     bcryptjs (12 rounds), AES-256-GCM (KEK/DEK), Passport.js
Scanners:     nmap (port scan + vuln scripts), Nuclei (web app scan)
Collectors:   WMI/WinRM (Windows), SSH2 (Linux), PowerShell (AD)
Integracao:   NIST NVD API v2.0 (CVE detection), LDAP (AD discovery)
Email:        Nodemailer + OAuth2 (Gmail/Microsoft 365)
Build:        Vite 6 (frontend) + esbuild (backend bundle)
Testes:       Vitest 4
```

### 3.3 Modelo de Dados (PostgreSQL)

O banco de dados e composto por **24 tabelas** organizadas em dominios funcionais, todas gerenciadas via Drizzle ORM com migracao automatica (`drizzle-kit push`).

#### Dominio: Identidade e Acesso
| Tabela | Descricao |
|--------|-----------|
| `users` | Usuarios com roles (global_administrator, operator, read_only), hash bcrypt, flag mustChangePassword |
| `sessions` | Sessoes express-session persistidas em PostgreSQL (connect-pg-simple) |
| `active_sessions` | Rastreamento de sessoes ativas por dispositivo com versionamento global para revogacao em massa |
| `login_attempts` | Rate limiting persistente com bloqueio temporario apos tentativas falhas |
| `session_version` | Controle de versao global para invalidacao de todas as sessoes |

#### Dominio: Superficie de Ataque
| Tabela | Descricao |
|--------|-----------|
| `assets` | Alvos de scan: hosts individuais (FQDN/IP), ranges CIDR, web applications. Suportam tags para agrupamento |
| `credentials` | Credenciais criptografadas (AES-256-GCM KEK/DEK) para scan autenticado: SSH, WMI, OMI, AD |
| `hosts` | Hosts descobertos com IPs, aliases, OS, tipo (server/desktop/firewall/switch/router), familia (linux/windows_server/windows_desktop/fortios/network_os), risk score (0-100) e raw score |
| `host_enrichments` | Dados coletados via scan autenticado: OS build exato, apps instalados, patches KB, servicos com status e tipo de startup |

#### Dominio: Operacoes de Scan
| Tabela | Descricao |
|--------|-----------|
| `journeys` | Configuracoes de assessment: tipo (attack_surface, ad_security, edr_av, web_application), alvos (individual ou por tag), parametros, credenciais associadas |
| `journey_credentials` | Tabela de juncao que vincula credenciais a journeys com prioridade de tentativa |
| `schedules` | Agendamentos flexiveis: on_demand, once, recurring (daily/weekly/monthly) com hora/minuto/dia, ou intervalo customizado (a cada X horas/dias) |
| `jobs` | Execucoes de journeys com status (pending/running/completed/failed/timeout), progresso (0-100), task atual |
| `job_results` | Artefatos de execucao: stdout, stderr, findings serializados em JSON |

#### Dominio: Inteligencia de Ameacas
| Tabela | Descricao |
|--------|-----------|
| `threats` | Ameacas com lifecycle completo: severity (low/medium/high/critical), status (open/investigating/mitigated/closed/hibernated/accepted_risk), correlationKey para deduplicacao, lastSeenAt, atribuicao a usuario |
| `threat_status_history` | Auditoria completa de mudancas de status com justificativa, usuario e timestamp |
| `ad_security_test_results` | Resultados granulares de testes AD: 28 testes com status (pass/fail/error/skipped), evidencia, comando executado |

#### Dominio: Configuracao e Auditoria
| Tabela | Descricao |
|--------|-----------|
| `settings` | Configuracoes chave-valor: timeout de nmap, fuso horario, perfil de scan, configuracoes de email (com OAuth2) |
| `audit_log` | Log completo de acoes: ator, acao, objeto, estado before/after em JSON |
| `notification_policies` | Regras de notificacao por email baseadas em severidade e status de ameaca |
| `notification_log` | Historico de notificacoes enviadas/falhas |

#### Dominio: Subscricao e Telemetria
| Tabela | Descricao |
|--------|-----------|
| `appliance_subscription` | Estado da subscricao: API key (criptografada), console URL, tier, status (not_configured/active/expired/grace_period/unreachable), ultimo heartbeat |

### 3.4 Servicos Backend (server/services/)

O backend e composto por **18 servicos** especializados que orquestram toda a logica de negocio:

#### Orquestracao
| Servico | Arquivo | Funcao |
|---------|---------|--------|
| **JourneyExecutor** | `journeyExecutor.ts` | Orquestra execucao completa de assessments. Resolve alvos (individual ou por tag via LDAP), coordena fases de scan (discovery -> enrichment -> CVE -> validation -> threats), gerencia progresso via callback |
| **JobQueue** | `jobQueue.ts` | Fila de execucao com EventEmitter para broadcasts WebSocket. Gerencia ciclo de vida de jobs (pending -> running -> completed/failed) |
| **Scheduler** | `scheduler.ts` | Polling a cada 60s para agendamentos ativos. Suporta recorrencia daily/weekly/monthly e intervalos customizados (a cada X horas/dias). Timezone configuravel (padrao: America/Sao_Paulo) |

#### Scanners
| Servico | Arquivo | Funcao |
|---------|---------|--------|
| **NetworkScanner** | `scanners/networkScanner.ts` | Wrapper de nmap com perfis (fast/thorough/stealth). Detecta portas abertas, servicos, versoes, OS. Cria processos rastreados com timeout configuravel. Suporta host discovery (ping sweep) para ranges |
| **VulnScanner** | `scanners/vulnScanner.ts` | Scanner de vulnerabilidades com nmap vuln scripts e Nuclei (templates OWASP). Verifica headers HTTP, directory listing, SSL/TLS, credenciais default |
| **ADScanner** | `scanners/adScanner.ts` | 28+ testes PowerShell via WinRM contra Active Directory: password policy, account security, privileged groups, Kerberos delegation, trust relationships. Decodifica flags UAC (UserAccountControl) com descricoes de risco. Failover automatico entre DCs |
| **EDR/AV Scanner** | `scanners/edrAvScanner.ts` | Testes de eficacia de EDR/AV via SMB shares. Credenciais temporarias em tmpfs (/dev/shm) com cleanup seguro (overwrite antes de delete). Usa smbclient para deploy de payloads de teste |

#### Inteligencia
| Servico | Arquivo | Funcao |
|---------|---------|--------|
| **ThreatEngine** | `threatEngine.ts` | Motor de regras para classificacao de ameacas. Categoriza servicos (admin/database/sharing/web/email/infrastructure) com severidade baseada em categoria. Deduplicacao por correlationKey, reativacao de ameacas hibernadas, monitor de hibernacao |
| **CVEService** | `cveService.ts` | Integracao com NIST NVD API v2.0. CPE matching com ranges de versao (versionStart/End Including/Excluding). Rate limiting de 6s entre requests. Filtragem de CVEs por patches KB instalados. Traducao de descricoes para PT-BR |
| **HostService** | `hostService.ts` | CRUD de hosts com calculo de risk score (0-100 baseado em intervalos CVSS), deduplicacao por IP/hostname, merge de aliases |
| **HostEnricher** | `hostEnricher.ts` | Orquestra coleta autenticada com collectors registrados (WMI, SSH). Prioridade configuravel, stop-on-success por protocolo, fail-safe (falhas nunca bloqueiam scan) |

#### Collectors
| Servico | Arquivo | Funcao |
|---------|---------|--------|
| **WMICollector** | `collectors/wmiCollector.ts` | Coleta de dados Windows via WinRM/WMI: OS build completo, aplicacoes instaladas, patches KB, servicos com status e startup type |
| **SSHCollector** | `collectors/sshCollector.ts` | Coleta de dados Linux via SSH2: OS/kernel, pacotes dpkg/rpm, servicos systemctl. Validacao TOFU de fingerprint SSH (FND-009) |

#### Infraestrutura
| Servico | Arquivo | Funcao |
|---------|---------|--------|
| **EncryptionService** | `encryption.ts` | Criptografia KEK/DEK com AES-256-GCM. KEK via variavel de ambiente (ENCRYPTION_KEK). IV de 96 bits, auth tag de 128 bits, AAD (Additional Authenticated Data) para contexto |
| **SubscriptionService** | `subscriptionService.ts` | Heartbeat para console cloud: telemetria a cada 5min (ativo) ou 30min (standby). Validacao HTTPS obrigatoria (anti-MITM). Whitelist de comandos remotos (system_update, restart_service). Grace period de 72h. Retry com backoff exponencial (10s, 20s, 40s, 80s) |
| **TelemetryService** | `telemetryService.ts` | Coleta metricas do appliance: CPU, memoria, disco, rede, uptime, servicos. Agrega contadores do banco (threats, hosts, jobs, usuarios). Nunca envia dados sensiveis |
| **NotificationService** | `notificationService.ts` | Notificacoes por email baseadas em politicas. Match de severidade e status contra policies configuradas. Suporta OAuth2 (Gmail/Microsoft 365) |
| **SettingsService** | `settingsService.ts` | Gerenciamento de configuracoes com valores padrao: timeout de nmap, perfil de scan, fuso horario do sistema |
| **ProcessTracker** | `processTracker.ts` | Rastreamento de processos filhos (nmap, nuclei) com timeout e cleanup em caso de kill do job |

### 3.5 API REST (server/routes/)

A API e organizada em **12 modulos de rotas** com autenticacao obrigatoria (exceto login/health):

| Modulo | Prefixo | Operacoes Principais |
|--------|---------|---------------------|
| **Dashboard** | `/api/dashboard/*` | Metricas agregadas, threats recentes, posture score, activity feed, stats por categoria |
| **Assets** | `/api/assets` | CRUD de alvos (host/range/web_application) com tags, validacao Zod |
| **Hosts** | `/api/hosts` | Listagem com filtros, detalhes com enrichments e threats vinculadas |
| **Credentials** | `/api/credentials` | CRUD com criptografia automatica KEK/DEK, validacao de tipo (ssh/wmi/omi/ad) |
| **Journeys** | `/api/journeys` | CRUD com credenciais associadas, execucao sob demanda |
| **Schedules** | `/api/schedules` | Agendamentos com recorrencia flexivel |
| **Jobs** | `/api/jobs` | Execucao, listagem, cancelamento, resultados com artefatos |
| **Threats** | `/api/threats` | Listagem com filtros, mudanca de status com justificativa e auditoria, bulk operations |
| **Users** | `/api/users` | CRUD de usuarios (admin only), reset de senha com flag mustChangePassword |
| **Reports** | `/api/reports/*` | Trend de ameacas, resumo por journey, historico AD, export CSV |
| **Admin** | `/api/admin/*` | Configuracoes do sistema, email settings (SMTP/OAuth2), audit log, gestao de sessoes |
| **Subscription** | `/api/subscription/*` | Ativacao/desativacao de API key, status da subscricao |

**Middlewares globais:**
- `requireActiveSubscription`: Bloqueia operacoes de escrita quando subscricao expirada (GET/HEAD/OPTIONS sempre permitidos)
- `requireAdmin`: Restringe rotas administrativas a `global_administrator`
- `requireOperator`: Bloqueia `read_only` em operacoes de escrita
- `isAuthenticatedWithPasswordCheck`: Valida sessao ativa + flag mustChangePassword

### 3.6 WebSocket (Tempo Real)

O servidor WebSocket (path `/ws`) fornece updates em tempo real para a UI:

- **Autenticacao:** Verifica cookie `connect.sid` e valida sessao ativa em `active_sessions`
- **Eventos emitidos:**
  - `connected` - Confirmacao de conexao
  - `jobUpdate` - Progresso de jobs (status, porcentagem, task atual)
  - `threatCreated` - Nova ameaca detectada
- **Broadcast:** Todos os clientes autenticados recebem todos os eventos
- **Cleanup:** Desconexao automatica em erro, remocao do set de clientes

### 3.7 Fluxo de Dados - Execucao de Journey (Attack Surface)

```
+--------------------------------------------------------------+
| 1. USUARIO CRIA JOURNEY                                       |
|    - Seleciona tipo (Attack Surface, AD Security, etc.)       |
|    - Define alvos (IPs, ranges, tags)                         |
|    - Configura parametros (nmap profile, credenciais)          |
|    - Agenda (imediato ou recorrente)                           |
+----------------------------+---------------------------------+
                             |
                             v
+--------------------------------------------------------------+
| 2. JOB QUEUE DISPATCHER                                       |
|    - Cria job no banco (status: pending)                      |
|    - Enfileira para execucao                                  |
|    - WebSocket notifica UI: "Journey iniciada"                |
+----------------------------+---------------------------------+
                             |
                             v
+--------------------------------------------------------------+
| 3. JOURNEY EXECUTOR                                           |
|                                                               |
|  +----------------------------------------------------------+|
|  | FASE 1: DISCOVERY (nmap port scan)                        ||
|  |  - Executa nmap -sV -O com perfil configurado             ||
|  |  - Detecta portas abertas, servicos, OS                   ||
|  |  - Descobre web apps (HTTP/HTTPS)                         ||
|  +-------------------------+--------------------------------+|
|                            |                                  |
|  +-------------------------v--------------------------------+|
|  | FASE 1.5: HOST ENRICHMENT (se credenciais fornecidas)    ||
|  |  - WMI: OS build, apps instalados, KBs, servicos         ||
|  |  - SSH: kernel, pacotes dpkg/rpm, servicos systemctl      ||
|  |  - Prioridade configuravel, stop-on-success               ||
|  +-------------------------+--------------------------------+|
|                            |                                  |
|  +-------------------------v--------------------------------+|
|  | FASE 2A: CVE DETECTION (NIST NVD API)                    ||
|  |  - CPE matching com ranges de versao                      ||
|  |  - Filtragem por KB patches instalados                    ||
|  |  - 74% reducao de falsos positivos com enrichment         ||
|  +-------------------------+--------------------------------+|
|                            |                                  |
|  +-------------------------v--------------------------------+|
|  | FASE 2B: ACTIVE VALIDATION (nmap vuln scripts)           ||
|  |  - Scripts: smb-vuln-*, ssl-*, http-vuln-*                ||
|  |  - Confirma exploitabilidade de CVEs                      ||
|  |  - Detecta misconfigurations                              ||
|  +-------------------------+--------------------------------+|
|                            |                                  |
|  +-------------------------v--------------------------------+|
|  | FASE 3: HOST DISCOVERY                                    ||
|  |  - Cria/atualiza hosts no banco                           ||
|  |  - Deduplicacao por IP/hostname                           ||
|  |  - Classifica tipo e familia do host                      ||
|  +-------------------------+--------------------------------+|
|                            |                                  |
|  +-------------------------v--------------------------------+|
|  | FASE 4: THREAT GENERATION (ThreatEngine)                  ||
|  |  - Categoriza por tipo de servico                         ||
|  |  - Calcula Risk Score (0-100) e Raw Score                 ||
|  |  - Deduplicacao por correlationKey                        ||
|  |  - Reativacao de ameacas hibernadas                       ||
|  +----------------------------------------------------------+|
+----------------------------+---------------------------------+
                             |
                             v
+--------------------------------------------------------------+
| 4. RESULTS PERSISTENCE                                        |
|    - Salva findings, threats, enrichments no banco            |
|    - Atualiza job status: completed                           |
|    - WebSocket notifica UI: "Journey concluida - N threats"   |
|    - Notificacoes por email (se politicas configuradas)       |
+--------------------------------------------------------------+
```

---

## 4. Interface do Usuario (UI)

### 4.1 Arquitetura Frontend

A interface e construida como uma **Single-Page Application (SPA)** com React 18 e TypeScript, utilizando o design system **shadcn/ui** baseado em Radix UI primitives para componentes acessiveis e consistentes.

**Stack de UI:**
- **Componentes:** shadcn/ui (50+ componentes Radix UI wrappers) - Accordion, Dialog, DropdownMenu, Table, Tabs, Toast, Tooltip, etc.
- **Estilizacao:** Tailwind CSS 3 com class-variance-authority (CVA) para variantes de componentes
- **Icones:** Lucide React (Shield, AlertTriangle, Server, Monitor, Key, Route, etc.)
- **Animacoes:** Framer Motion + tailwindcss-animate
- **Graficos:** Recharts para visualizacoes de dados (trends, distribuicao de ameacas)
- **Formularios:** React Hook Form + Zod (validacao compartilhada com backend via drizzle-zod)
- **Estado servidor:** TanStack Query v5 com refetch automatico (polling intervals de 10s-60s)
- **Roteamento:** Wouter (client-side routing leve, sem dependencia de React Router)
- **Tempo real:** WebSocket nativo com hook customizado `useWebSocket`

### 4.2 Layout e Navegacao

A aplicacao usa um layout com **sidebar fixa lateral** + **topbar** para todas as paginas autenticadas:

**Sidebar - Grupos de Navegacao:**

| Grupo | Itens | Acesso |
|-------|-------|--------|
| **Principal** | Postura (dashboard de seguranca) | Todos |
| **Superficie** | Alvos, Hosts, Credenciais | Todos (escrita: operator+) |
| **Operacoes** | Jornadas, Agendamentos, Jobs | Todos (escrita: operator+) |
| **Inteligencia** | Ameacas, Relatorios | Todos |
| **Administracao** | Usuarios, Sessoes, Notificacoes, Subscricao, Configuracoes, Auditoria | Apenas global_administrator |

### 4.3 Paginas da Aplicacao

#### 4.3.1 Postura de Seguranca (`/postura` - pagina inicial)

Dashboard principal que apresenta a visao consolidada da postura de seguranca:

- **Posture Score (0-100):** Metrica agregada baseada nos risk scores de todos os hosts
- **Hosts em Risco:** Contagem de hosts com ameacas abertas criticas/altas
- **Stats por Categoria:** Distribuicao de ameacas por tipo de journey (Attack Surface, AD Security, EDR/AV, Web Application)
- **Atencao Necessaria:** Alertas de acoes imediatas requeridas
- **Activity Feed:** Timeline de ameacas e jobs recentes com atualizacao a cada 30s
- **Ameacas Recentes:** Lista das ameacas mais recentes com severidade e status

#### 4.3.2 Alvos (`/assets`)

Gerenciamento de alvos de scan com suporte a:
- **Tipos:** Host individual (FQDN/IP), Range CIDR, Web Application (URL)
- **Tags:** Sistema de agrupamento flexivel para selecao por tag em journeys
- **Formulario:** Criacao e edicao com validacao Zod em tempo real

#### 4.3.3 Hosts (`/hosts` ou `/ativos`)

Visualizacao dos hosts descobertos pelos scans:
- **Detalhes:** Nome, IPs, aliases, OS detectado, tipo, familia
- **Risk Score:** Indicador visual (0-100) com codigo de cores
- **Enrichments:** Dados de scan autenticado (OS build, apps, patches, servicos)
- **Ameacas Vinculadas:** Threats associadas ao host com severidade

#### 4.3.4 Credenciais (`/credentials`)

Gestao segura de credenciais para scan autenticado:
- **Tipos suportados:** SSH (chave/senha), WMI (Windows), OMI, AD (LDAP)
- **Criptografia:** Senhas nunca exibidas apos salvas, armazenadas com AES-256-GCM
- **Host Override:** Opcao de restringir credencial a host especifico
- **Porta customizada:** Sobrescrever porta padrao do protocolo

#### 4.3.5 Jornadas (`/journeys`)

Configuracao de assessments de seguranca:
- **Attack Surface:** Scan de portas + CVE detection + validacao ativa
- **AD Security:** 28 testes PowerShell contra Active Directory
- **EDR/AV:** Testes de eficacia de endpoint protection
- **Web Application:** Scan OWASP Top 10 com Nuclei
- **Selecao de alvos:** Individual (selecao direta) ou por Tag (dinamica)
- **Credenciais:** Associacao com prioridade para scan autenticado

#### 4.3.6 Agendamentos (`/schedules`)

Sistema de agendamento flexivel:
- **On Demand:** Execucao manual unica
- **Once:** Execucao agendada para data/hora especifica
- **Recurring:** Daily, Weekly (dia da semana), Monthly (dia do mes)
- **Intervalo customizado:** A cada X horas ou X dias
- **Controle:** Habilitar/desabilitar sem deletar

#### 4.3.7 Jobs (`/jobs`)

Monitoramento de execucoes em andamento e historicas:
- **Status em tempo real:** Via WebSocket (pending -> running -> completed/failed/timeout)
- **Progresso:** Barra de progresso com porcentagem e tarefa atual
- **Resultados:** Stdout, stderr, artefatos JSON com findings

#### 4.3.8 Ameacas (`/threats`)

Central de gestao de ameacas detectadas:
- **Filtros:** Por severidade, status, categoria, host, busca textual
- **Status lifecycle:** open -> investigating -> mitigated/closed/hibernated/accepted_risk
- **Mudanca de status:** Requer justificativa obrigatoria (auditada)
- **Detalhes:** Evidencia tecnica, CVEs associados, dados de scan PowerShell renderizados como tabela
- **Bulk operations:** Selecao multipla para acoes em lote
- **Export:** Download de dados para analise externa

#### 4.3.9 Relatorios (`/relatorios`)

Dashboards analiticos com abas:
- **Trend de Ameacas:** Grafico temporal por severidade (critical/high/medium/low)
- **Resumo por Journey:** Estatisticas por categoria com MTTR (Mean Time to Resolution)
- **Historico AD:** Timeline de resultados de testes AD com pass/fail rates
- **Distribuicao:** Graficos de pizza e barra com ameacas por status, severidade, categoria

#### 4.3.10 Paginas Administrativas (global_administrator)

- **Usuarios (`/users`):** CRUD completo com roles (global_administrator, operator, read_only), reset de senha, flag mustChangePassword
- **Sessoes (`/sessions`):** Visualizacao de sessoes ativas por dispositivo, revogacao individual ou em massa
- **Notificacoes (`/notification-policies`):** Politicas de email baseadas em severidade/status de ameacas
- **Subscricao (`/subscription`):** Ativacao com API key, status da console cloud, tier da licenca
- **Configuracoes (`/settings`):** Timeout de nmap, perfil de scan, fuso horario, configuracoes de email (SMTP, OAuth2 Gmail/Microsoft)
- **Auditoria (`/audit`):** Log completo de acoes com ator, acao, objeto, estado before/after

#### 4.3.11 Outras Paginas

- **Login (`/login`):** Autenticacao local com email/senha
- **Landing (`/`):** Pagina de apresentacao para usuarios nao autenticados
- **Change Password (`/change-password`):** Forcada quando flag mustChangePassword esta ativa
- **Not Found:** Pagina 404 customizada

### 4.4 Experiencia do Usuario

- **Idioma:** Interface completamente em Portugues Brasileiro (PT-BR)
- **Tema:** Dark mode por padrao com design system consistente
- **Responsividade:** Hook `use-mobile` para adaptacao a telas menores
- **Error Boundary:** Componente React ErrorBoundary global previne tela branca em erros de renderizacao
- **Toasts:** Sistema de notificacoes via Radix UI Toast para feedback de acoes
- **Loading States:** Skeleton components durante carregamento de dados
- **Validacao:** Feedback em tempo real nos formularios via React Hook Form + Zod
- **WebSocket Indicator:** Indicador visual de conexao WebSocket ativa
- **Subscription Banner:** Banner global quando subscricao esta expirada ou em grace period
- **Auto-refresh:** Dados atualizados via polling (10s-60s) e WebSocket push

---

## 5. Seguranca

### 5.1 Autenticacao

| Mecanismo | Implementacao |
|-----------|---------------|
| **Hash de senha** | bcryptjs com 12 rounds + salt automatico |
| **Sessoes** | express-session + connect-pg-simple (store PostgreSQL), cookie httpOnly + secure (auto-detect HTTPS) + sameSite=lax |
| **Duracao de sessao** | 8 horas (TTL no cookie e na store), limpeza automatica a cada 10 minutos |
| **Versionamento de sessao** | Incremento global ao reiniciar servidor invalida todas as sessoes anteriores |
| **Rastreamento multi-dispositivo** | Tabela `active_sessions` com device info (browser + OS parseados do User-Agent) |
| **Revogacao** | Revogacao individual ou em massa via tabela `active_sessions`; sessoes nao rastreadas sao bloqueadas |
| **Primeiro acesso** | Flag `mustChangePassword` forca troca de senha antes de qualquer acesso |
| **Bootstrap dev** | Admin padrao criado automaticamente em desenvolvimento (desabilitavel) |

### 5.2 Autorizacao (RBAC)

O sistema implementa 3 roles com permissoes hierarquicas:

| Role | Permissoes |
|------|-----------|
| **global_administrator** | Acesso total: CRUD de usuarios, configuracoes do sistema, email settings, audit log, gestao de sessoes, subscricao, notification policies |
| **operator** | Operacoes de scan: CRUD de assets/credentials/journeys/schedules, execucao de jobs, gestao de threats (mudanca de status) |
| **read_only** | Somente leitura: visualizacao de dashboards, hosts, threats, jobs, relatorios. Bloqueado para qualquer operacao de escrita |

**Middlewares de autorizacao:**
- `requireAdmin` - Retorna 403 para non-admin em rotas `/users`, `/settings`, `/audit`, etc.
- `requireOperator` - Retorna 403 para `read_only` em operacoes POST/PUT/PATCH/DELETE
- `requireActiveSubscription` - Retorna 403 com codigo `SUBSCRIPTION_EXPIRED` para escrita quando licenca expirada
- `AdminRoute` (frontend) - Componente React que redireciona non-admin para `/`

### 5.3 Rate Limiting e Protecao contra Brute Force

- **Rate limiting persistente** em PostgreSQL (tabela `login_attempts`)
- Bloqueio temporario apos N tentativas falhas consecutivas (`blockedUntil` com timestamp)
- Reset automatico do contador apos login bem-sucedido
- Limpeza periodica de tentativas antigas

### 5.4 Criptografia de Credenciais

O sistema usa o padrao **KEK/DEK (Key Encryption Key / Data Encryption Key)** para proteger credenciais armazenadas:

```
Fluxo de Criptografia:
1. Gera DEK aleatorio (32 bytes) para cada credencial
2. Criptografa segredo com DEK usando AES-256-GCM
   - IV: 96 bits (aleatorio)
   - Auth Tag: 128 bits
   - AAD: "samureye-credential"
3. Criptografa DEK com KEK usando AES-256-GCM
   - AAD: "samureye-dek"
4. Armazena secretEncrypted + dekEncrypted no banco

Fluxo de Descriptografia:
1. Descriptografa DEK com KEK
2. Descriptografa segredo com DEK
```

- **KEK em producao:** Variavel de ambiente `ENCRYPTION_KEK` (64 hex chars = 256 bits). Ausencia causa erro fatal
- **KEK em desenvolvimento:** Derivada via `crypto.scryptSync` (warning no log)
- **Rotacao de KEK:** Suportada (re-criptografar DEKs existentes com nova KEK)

### 5.5 Seguranca de Comunicacao

| Componente | Protecao |
|-----------|----------|
| **CORS** | Configuravel via `ALLOWED_ORIGINS`. Em producao, rejeita origens desconhecidas. Appliance single-host permite qualquer origem quando nao configurado |
| **Console URL** | Validacao obrigatoria de HTTPS (anti-MITM). HTTP aceito apenas para localhost |
| **Cookies de sessao** | `httpOnly: true`, `secure: auto` (detecta HTTPS), `sameSite: lax` (CSRF protection) |
| **WebSocket** | Autenticacao via cookie de sessao, verificacao contra `active_sessions` |
| **Heartbeat** | Whitelist de comandos remotos (`system_update`, `restart_service`). Validacao rigorosa de estrutura de comandos |

### 5.6 Protecao de Dados Sensiveis

| Dado | Protecao |
|------|----------|
| **Senhas de usuario** | bcrypt 12 rounds (nunca armazenadas em texto claro) |
| **Credenciais de scan** | AES-256-GCM com KEK/DEK (nunca retornadas em API responses) |
| **Arquivos temporarios de auth** | Criados em tmpfs (/dev/shm), nomes imprevisíveis (crypto.randomBytes), permissao 0o600, overwrite com zeros antes de delete |
| **Dados de scan** | Permanecem no appliance (nunca enviados para cloud) |
| **Telemetria** | Apenas contadores agregados (nao PII): total de threats, hosts, jobs, metricas de performance |
| **SSH host keys** | Fingerprint SHA-256 armazenado para validacao TOFU (Trust On First Use) |

### 5.7 Audit Trail

- **Tabela `audit_log`:** Registra todas as acoes de escrita com:
  - `actorId` - Usuario que executou a acao
  - `action` - Tipo de acao (create, update, delete, login, logout, status_change, etc.)
  - `objectType` - Tipo de objeto afetado (user, asset, credential, journey, threat, setting, etc.)
  - `objectId` - ID do objeto afetado
  - `before` / `after` - Estado JSON antes/depois da mudanca
  - `createdAt` - Timestamp da acao
- **Threat status history:** Tabela dedicada com justificativa obrigatoria para cada mudanca de status
- **Notification log:** Historico de todas as notificacoes enviadas (sucesso/falha)

### 5.8 Seguranca do Processo de Scan

- **Timeout configuravel:** Timeout de nmap e nuclei configuravel via settings (padrao: 5 minutos por host)
- **Process tracking:** Todos os processos filhos (nmap, nuclei, PowerShell) sao rastreados e podem ser cancelados
- **Isolamento:** Scans executados localmente no appliance, sem transmissao de dados para cloud
- **Credenciais em memoria:** Descriptografadas apenas no momento do uso, nunca persistidas em texto claro
- **Validacao de input:** Schemas Zod para todos os endpoints de API, prevencao de injecao de comandos em alvos de scan
- **HTML sanitization:** Funcao `escapeHtml` para conteudo de email (prevencao de XSS)

---

## 6. Funcionalidades Principais

### 6.1 Attack Surface Discovery

- Scan de portas com nmap usando perfis otimizados (fast/thorough/stealth)
- Deteccao de servicos e versoes com precisao (alta/media/baixa)
- Identificacao de OS (Windows, Linux, network devices, FortiOS)
- Auto-discovery de web applications quando HTTP/HTTPS detectado
- Host discovery via ping sweep para ranges CIDR

### 6.2 CVE Detection com Inteligencia de Patches

Deteccao em 4 camadas:
1. **CPE Matching:** Validacao contra configuracoes CPE do NVD com ranges de versao
2. **Windows Version Extraction:** Matching preciso de builds (10.0.14393 vs 10.0.17763)
3. **Enrichment Integration:** KB patch filtering (74% reducao de falsos positivos)
4. **Keyword Search Fallback:** Quando CPE indisponivel, com protecao cross-OS

### 6.3 Active Validation (nmap vuln scripts)

Scripts de verificacao em categorias: Authentication Bypass, Credential Exposure, Remote Code Execution, SQL Injection, Path Traversal, Default Credentials, Misconfigurations, SSL/TLS Issues.

### 6.4 AD Security Assessment

28+ testes PowerShell distribuidos em categorias:
- Password Policy, Account Security, Privileged Groups
- Kerberos (Delegation, Pre-Auth), Trust Relationships, General Security
- Decodificacao UAC flags com descricoes de risco em PT-BR
- Keyword Enhancement para deteccao de credenciais em scripts
- Failover automatico entre Domain Controllers via DNS

### 6.5 EDR/AV Effectiveness Testing

- Deploy de payloads de teste via SMB para validar deteccao
- Credenciais temporarias em tmpfs com cleanup seguro
- Simulacao de tecnicas MITRE ATT&CK

### 6.6 Web Application Security (OWASP Top 10)

- Scan com engine Nuclei (templates open-source)
- Verificacao de headers HTTP, directory listing, SSL/TLS, credenciais default
- Assets web_application criados automaticamente quando HTTP/HTTPS detectado

### 6.7 Authenticated Scanning

- **Windows (WMI/WinRM):** OS build completo, apps instalados, patches KB, servicos
- **Linux (SSH):** OS/kernel, pacotes dpkg/rpm, servicos systemctl
- Prioridade configuravel, stop-on-success, fail-safe

### 6.8 Sistema de Notificacoes

- Politicas de notificacao por email baseadas em severidade e status
- Suporte a SMTP, OAuth2 Gmail, OAuth2 Microsoft 365
- Templates HTML para notificacoes de ameacas (criacao e mudanca de status)
- Log de todas as notificacoes enviadas/falhas

### 6.9 Agendamento de Scans

- Recorrencia flexivel: diario, semanal, mensal, ou intervalo customizado
- Timezone configuravel (padrao: America/Sao_Paulo)
- Execucao automatica com polling a cada 60s
- Rastreamento de ultima execucao para evitar execucoes duplicadas

### 6.10 Sistema de Subscricao

- Ativacao por API key criptografada
- Heartbeat periodico para console central
- Grace period de 72h para desconexao
- Modo read-only quando expirado (preserva dados)
- Atualizacao remota via comandos whitelisted

---

## 7. Modelo de Negocio

### 7.1 Tiers de Subscricao

| Feature | Starter | Professional | Enterprise |
|---------|---------|--------------|------------|
| **Preco Anual** | R$ 15.000 | R$ 36.000 | R$ 60.000+ |
| **Max Hosts** | 100 | 500 | Ilimitado |
| **Max Usuarios** | 3 | 10 | Ilimitado |
| **Attack Surface** | Sim | Sim | Sim |
| **CVE Detection** | Sim | Sim | Sim |
| **Authenticated Scan** | Nao | Sim | Sim |
| **AD Security** | Nao | Sim | Sim |
| **Web App Security** | Nao | Sim | Sim |
| **EDR/AV Testing** | Nao | Nao | Sim |
| **API Access** | Nao | Sim | Sim |
| **Multi-Site Dashboard** | Nao | Nao | Sim |
| **SLA** | Best-effort | 8x5 | 24x7 |
| **Suporte** | Email | Email + Chat | Dedicated TAM |

### 7.2 Analise Competitiva

| Solucao | Preco Anual | Complexidade | Falsos Positivos | Validacao Ativa | Modelo |
|---------|-------------|--------------|------------------|-----------------|---------|
| **SamurEye** | R$ 15k-60k | Baixa | Baixo | Sim | SaaS + Appliance |
| Tenable.io | US$ 50k+ | Alta | Medio | Nao | Cloud |
| Qualys VMDR | US$ 30k+ | Alta | Medio | Nao | Cloud |
| Rapid7 InsightVM | US$ 40k+ | Alta | Medio | Limitado | Cloud |
| Nessus Pro | US$ 4k | Media | Alto | Nao | On-Prem |
| OpenVAS | Gratis | Muito Alta | Alto | Nao | On-Prem |

**Vantagens Competitivas:**
1. Inteligencia de Patches: KB filtering com 74% reducao de falsos positivos
2. Modelo Hibrido: Dados sensiveis on-prem + conveniencia cloud
3. Zero-Config: Instala, aponta alvos, recebe resultados
4. Preco Disruptivo: 70% mais barato que competitors enterprise
5. Validacao Adversarial: Prova que CVEs sao exploraveis (nao apenas lista)
6. Compliance-Ready: Relatorios para ISO/PCI/LGPD

---

## 8. Formatos de Deploy

| Formato | Especificacoes Minimas | Casos de Uso |
|---------|------------------------|--------------|
| **Virtual Appliance (OVA/VMDK)** | 4 vCPU, 8GB RAM, 100GB SSD | SMB - deployment em VMware/Hyper-V |
| **Docker Container** | 4 CPU cores, 8GB RAM, 100GB storage | DevOps teams, Kubernetes |
| **Hardware Appliance** | Intel i5, 16GB RAM, 256GB SSD | Enterprise plug-and-play |

**Instalacao automatizada:** Script `install.sh` (45KB) com provisionamento completo: PostgreSQL, Node.js, nmap, Nuclei, PowerShell, dependencias, systemd service, SSL, UFW firewall.

---

## 9. Glossario Tecnico

| Termo | Descricao |
|-------|-----------|
| **Attack Surface** | Soma de todos os pontos de entrada exploraveis |
| **CVE** | Common Vulnerabilities and Exposures - ID padronizado para falhas |
| **CPE** | Common Platform Enumeration - nomenclatura de produtos IT |
| **CVSS** | Common Vulnerability Scoring System - escala 0-10 de gravidade |
| **EDR** | Endpoint Detection and Response |
| **Journey** | Configuracao de assessment de seguranca no SamurEye |
| **KEK/DEK** | Key Encryption Key / Data Encryption Key - padrao de criptografia em camadas |
| **Nmap** | Network Mapper - scanner de rede open-source |
| **Nuclei** | Engine de scan de vulnerabilidades web open-source |
| **OWASP Top 10** | Lista das 10 vulnerabilidades web mais criticas |
| **Pentest** | Teste de penetracao - simulacao de ataque |
| **RBAC** | Role-Based Access Control |
| **SMBv1** | Protocolo antigo de compartilhamento Windows (vulneravel a WannaCry) |
| **TOFU** | Trust On First Use - validacao de fingerprint SSH |
| **UAC** | User Account Control flags do Active Directory |
| **WinRM/WMI** | Windows Remote Management / Windows Management Instrumentation |

---

**Versao do Documento:** 2.0
**Ultima Atualizacao:** Marco 2026
**Preparado para:** Consultoria de Go-to-Market e Referencia Interna
**Classificacao:** Confidencial - Somente uso interno
