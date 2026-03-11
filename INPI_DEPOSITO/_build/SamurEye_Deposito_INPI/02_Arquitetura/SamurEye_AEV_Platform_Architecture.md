# SamurEye — Adversarial Exposure Validation Platform (All‑in‑One)

> **Versão do documento:** 1.0  
> **Objetivo:** Especificação **arquitetural** e **funcional** completa para construir o SamurEye como uma aplicação _all‑in‑one_ instalada em Ubuntu, com UI web para gestão de ativos, credenciais, jornadas e agendamentos; dashboards e **Threat Intelligence**.

---

## 1) Visão Geral

O **SamurEye – Adversarial Exposure Validation Platform** é uma solução _all‑in‑one_ de validação contínua de exposição, projetada para ser instalada em **uma única VM Ubuntu**. Fornece:

- **UI Web** moderna (administração, operação e visualização em TVs/visores);
- **Cadastro de ativos** (host único ou ranges);
- **Cadastro seguro de credenciais** (SSH e WMI/OMI);
- **Jornadas** de verificação:
  - **Attack Surface:** _nmap_ + _nuclei_ sobre ativos selecionados;
  - **Higiene AD/LDAP:** análise de políticas, usuários e grupos no AD;
  - **EDR/AV Testing:** amostragem de _computers_ do AD e simulação com **EICAR**;
- **Agendamentos** (sob demanda, único ou recorrente);
- **Threat Intelligence**: correlaciona achados e gera “ameaças” operacionais;
- **APIs REST** com autenticação e RBAC;
- **Scripts de deployment:** `install.sh` (instalação/zerar) e `update.sh` (atualização/migrações).

### 1.1 Metas
- Operação simples (_single host_), com _observability_ básica e logs;
- Segurança por padrão (TLS, _hardening_, armazenamento seguro de segredos);
- Extensível: novas jornadas e integrações futuras.

### 1.2 Não‑Metas
- Não é uma plataforma de varredura distribuída multi‑agente (nesta fase);
- Não orquestra _malware_ real (usa **EICAR** e simulações seguras).

---

## 2) Perfis de Usuário e RBAC

- **Admin padrão (primeiro acesso):** `admin@samureye.local`  
  - No primeiro _login_, será forçado a definir senha forte.
- **Papéis:**
  1. **Global Administrator** – gerencia tudo (usuários, configurações, jornadas, agendamentos, etc.);
  2. **Operator** – cria/edita jornadas, agenda execuções, acompanha jobs e ameaças;
  3. **Read‑only** – acesso somente leitura, pensado para TVs/dashboards.

**Boas práticas:**
- Autenticação por **email + senha** (Argon2id) e opção futura de SSO;
- Sessões JWT **assinado** + _rotating refresh tokens_;
- Auditoria de ações administrativas (audit trail).

---

## 3) Modelo de Dados (Resumo)

> Banco: **PostgreSQL** (prod) | **SQLite** (dev/Replit).

Entidades principais:

- `users(id, email, name, role, password_hash, created_at, last_login)`  
- `api_keys(id, user_id, name, hash, created_at, last_used)` *(futuro)*  
- `assets(id, type[host|range], value, created_at, tags[])`  
  - **host**: FQDN ou IP único (v4/v6)  
  - **range**: `CIDR` (ex.: `10.0.0.0/24`) ou intervalo por hífen (ex.: `10.0.0.10-10.0.0.50`)
- `credentials(id, type[ssh|wmi|omi], host_override?, port, username, secret_enc, created_at)`  
  - `secret_enc`: **AES‑256‑GCM** com **DEK** cifrada por **KEK** (ver §6)
- `journeys(id, type[attack_surface|ad_hygiene|edr_av], name, params_json, created_by, created_at)`  
- `schedules(id, journey_id, kind[on_demand|once|recurring], cron?, once_at?, enabled, created_at)`  
- `jobs(id, journey_id, schedule_id?, status[pending|running|ok|error|timeout], created_at, started_at?, finished_at?)`  
- `job_results(id, job_id, stdout, stderr, artifacts_json, created_at)`  
- `threats(id, source[journey], title, severity[low|med|high|crit], asset_id?, evidence_json, status[open|investigating|mitigated|closed], created_at, updated_at)`  
- `settings(id, key, value_json, updated_at)` – ex.: thresholds AD, EICAR timeout, etc.  
- `audit_log(id, actor_id, action, object, before_json?, after_json?, at)`

Índices em colunas de pesquisa (e.g., `assets.value`, `threats.status`, `jobs.status`).

---

## 4) Jornadas (Funcional)

### 4.1 Attack Surface
- **Seleção de ativos** (multi‑escolha) a partir de `assets`.
- **Parâmetros**:
  - _nmap_: perfis (rápido, completo, top‑ports, com scripts seguros NSE); _rate limit_;
  - _nuclei_: _templates_ selecionáveis, severidade mínima a coletar.
- **Saída**: normaliza achados (aberta/fechada, porta, serviço, CVE), gera _Threats_ conforme _severity_.

### 4.2 Higiene AD/LDAP
- **Entrada**: `domain_fqdn` (ex.: `corp.local`), descobre DC via DNS `SRV _ldap._tcp.dc._msdcs.<domain>`;  
  Credencial do tipo **WMI/OMI** ou LDAP com privilégios de leitura.
- **Validações** (exemplos):
  - Usuários **inativos** (sem _lastLogonTimestamp_ > _N_ dias);
  - **Domain Admins** com **senha > 90 dias**;
  - Contas com **PasswordNeverExpires**;
  - Policies: complexidade de senha, mínimo, histórico, lockout;
  - **Computers**: últimos _logons_, objetos órfãos.
- **Saída**: Threats com evidências (contas, datas, grupos, políticas).

### 4.3 EDR/AV Testing
- **Amostragem**: sobre `computers` do AD (ex.: `X%` por execução).
- **Ação**: cria arquivo **EICAR** em `\\<host>\C$\Windows\Temp\samureye_eicar.txt` via SMB (credencial **WMI/OMI** com admin local).
- **Validação**: aguarda **T** segundos/minutos; se arquivo **for removido** pelo AV/EDR → **OK**; se **persistir**, cria **Threat** “EDR/AV falhou em remover EICAR” para aquele host.
- **Segurança**: **somente EICAR**, _dry‑run_ disponível, _rate limit_ e _kill‑switch_.

---

## 5) Agendamentos

- **Sob demanda** (executa agora);
- **Único** (data/hora específica);
- **Recorrente** (CRON: `m h dom mon dow`), com _timezone_ & _window_ de execução;
- Limite de concorrência e tempo máximo por job;
- Reagendamento automático em falha opcional.

---

## 6) Segurança & Armazenamento de Segredos

- **Senhas de usuários:** `Argon2id` (sal único, parâmetros ajustáveis).  
- **Credenciais (SSH/WMI/OMI):**  
  - Gerar **DEK** aleatória por credencial (AES‑256‑GCM) → cifra `secret`;  
  - **KEK** mantida no `.env`/secret (ou **Vault** opcional) → cifra DEKs;  
  - Estrutura: `secret_enc = base64(aes_gcm_encrypt(DEK, secret)); dek_enc = base64(aes_gcm_encrypt(KEK, DEK))`;  
  - Em memória: decifra sob demanda, limpa após uso.
- **TLS**: `nginx` terminando **HTTPS** (Let’s Encrypt, ver §9).  
- **Headers de segurança** (HSTS, XFO, XCTO, RP).  
- **RBAC** estrito em APIs, _scopes_ por rota.  
- **Auditoria** de ações administrativas.  
- **Backups**: base + `/var/lib/samureye` (artefatos).

---

## 7) Arquitetura Lógica

```
┌────────────────────────────────────────────────────────────────────┐
│                            NGINX (443)                             │
│            TLS / Certbot | Static / Reverse Proxy / CORS           │
└──────────────┬───────────────────────────────┬──────────────────────┘
               │                               │
   / (UI)      │                       /api (REST/WebSocket) 
               ▼                               ▼
        Frontend (React + Vite)        FastAPI (Auth, RBAC, CRUD, Jobs)
               │                               │
               │                               │ Schedules (APScheduler)
               │                               ├───────────────┐
               │                               │               │
               ▼                               ▼               ▼
          Browser/TV                     Workers (RQ/Celery)   Threat Engine
                                      (nmap, nuclei, LDAP, SMB/EICAR)
                                              │
                                              ▼
                                       PostgreSQL / Redis
```

### Componentes
- **Frontend:** React + Vite + Tailwind + shadcn/ui;
- **API:** **FastAPI** (Python 3.11+), SQLAlchemy, Alembic;
- **Workers:** **RQ** (Redis) ou Celery (com Redis) p/ jobs;
- **DB:** PostgreSQL 14+ (prod) | SQLite (dev);
- **Cache/Queue:** Redis 7+;
- **Proxy/TLS:** nginx + certbot;
- **Scanner libs:** `nmap`, `nuclei`, `ldap3`/`impacket`, `smbprotocol`/`pypsexec` (somente EICAR).

---

## 8) API (Esboço)

Prefácio: todas as rotas sob `/api/v1`, **JWT** (Bearer).

- **Auth**  
  - `POST /auth/login` → tokens; `POST /auth/refresh`; `POST /auth/logout`  
- **Users**  
  - `GET /users`, `POST /users`, `PATCH /users/{id}`, `DELETE /users/{id}`  
- **Assets**  
  - `GET /assets`, `POST /assets`, `PATCH /assets/{id}`, `DELETE /assets/{id}`  
- **Credentials**  
  - `GET /credentials`, `POST /credentials`, `GET /credentials/{id}` (sem revelar segredos), `DELETE /credentials/{id}`  
- **Journeys**  
  - `GET /journeys`, `POST /journeys`, `GET /journeys/{id}`, `PATCH /journeys/{id}`, `DELETE /journeys/{id}`  
- **Schedules**  
  - `GET /schedules`, `POST /schedules`, `PATCH /schedules/{id}`, `DELETE /schedules/{id}`  
- **Jobs**  
  - `POST /jobs/run` (on‑demand), `GET /jobs`, `GET /jobs/{id}`, `GET /jobs/{id}/result`  
- **Threats**  
  - `GET /threats`, `PATCH /threats/{id}` (status), `GET /threats/stats`  
- **Events/WS**  
  - `GET /events` (SSE) ou `GET /ws` (WebSocket) para atualizações em tempo real.

---

## 9) Deploy (All‑in‑One em Ubuntu)

### 9.1 Requisitos
- **Ubuntu 22.04 / 24.04 LTS** (VM “samureye-core”);
- IP fixo (ex.: `10.10.10.10`) e **hostname** (ex.: `samureye-core`);
- Domínio público (opcional) p/ **Let’s Encrypt** (ex.: `samureye.example.com`);
- Portas liberadas: **80/443** (externo), **22** (SSH administrativo).

### 9.2 Hostnames sugeridos
- **Único host:** `app.samureye.local` (UI/API no mesmo);
- Se houver DNS público: `samureye.example.com` (UI+API).

### 9.3 Let’s Encrypt
- **HTTP‑01** (porta 80 aberta) com `certbot` + `nginx`;
- Alternativa **DNS‑01** (provedor DNS) se 80 não estiver disponível;
- **Fallback**: _self‑signed_ para ambientes isolados.

### 9.4 Hardening
- `ufw allow 80,443/tcp` e regras mínimas;
- SSH: `PasswordAuthentication no`, `PermitRootLogin no`, chaves somente;
- Autoupdate de segurança (`unattended-upgrades`);
- _Non‑root_ containers/processos, _read‑only_ FS quando possível;
- `nginx` com TLS 1.2/1.3, ciphers seguras, HSTS.

---

## 10) Scripts de Deployment

> Ambos os scripts ficam no diretório raiz do projeto.  
> **Observação:** em **Replit**, usar modo **dev** (SQLite, sem `nginx/certbot`).

### 10.1 `install.sh` (esqueleto)

```bash
#!/usr/bin/env bash
set -euo pipefail

echo "==> SamurEye Installer (all-in-one)"
if [ -f .env ] || [ -d /var/lib/samureye ]; then
  read -rp "Instalação já detectada. Fazer HARD RESET (apaga banco e dados)? [yes/NO] " ans
  if [[ "${ans,,}" == "yes" ]]; then
    echo "Apagando dados..."
    sudo systemctl stop samureye-* || true
    sudo rm -rf /var/lib/samureye
    sudo -u postgres dropdb --if-exists samureye || true
    sudo -u postgres dropuser --if-exists samureye || true
  else
    echo "Abortado."; exit 1
  fi
fi

echo "==> Pacotes base"
sudo apt-get update -y
sudo apt-get install -y nginx postgresql redis-server python3.11 python3.11-venv \
  certbot python3-certbot-nginx build-essential git curl

echo "==> Usuário e diretórios"
sudo useradd -m -r -s /usr/sbin/nologin samureye || true
sudo install -d -o samureye -g samureye -m 0750 /var/lib/samureye

echo "==> Banco de dados"
sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='samureye'" | grep -q 1 || \
  sudo -u postgres createuser samureye
sudo -u postgres createdb -O samureye samureye || true

echo "==> .env"
cat > .env <<'ENV'
APP_ENV=prod
APP_SECRET=$(openssl rand -hex 32)
DB_URL=postgresql+psycopg2://samureye:@localhost/samureye
REDIS_URL=redis://localhost:6379/0
# TLS: configurar hostname público se usar LE
PUBLIC_HOST=samureye.example.com
ENV

echo "==> Backend venv, dependências e migrações"
python3.11 -m venv .venv
source .venv/bin/activate
pip install -U pip wheel
pip install -r backend/requirements.txt
alembic upgrade head

echo "==> Systemd services"
sudo cp deploy/systemd/samureye-api.service /etc/systemd/system/
sudo cp deploy/systemd/samureye-worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now samureye-api samureye-worker

echo "==> NGINX + Certbot (opcional)"
sudo cp deploy/nginx/samureye.conf /etc/nginx/sites-available/samureye.conf
sudo ln -sf /etc/nginx/sites-available/samureye.conf /etc/nginx/sites-enabled/samureye.conf
sudo nginx -t && sudo systemctl reload nginx
# certbot --nginx -d "$PUBLIC_HOST"  # habilite se tiver DNS público

echo "==> Pronto. Acesse: https://$PUBLIC_HOST/"
```

### 10.2 `update.sh` (esqueleto)

```bash
#!/usr/bin/env bash
set -euo pipefail

echo "==> SamurEye Updater"
git pull --rebase || true

echo "==> Backend deps & migrations"
source .venv/bin/activate
pip install -r backend/requirements.txt
alembic upgrade head

echo "==> Reload services"
sudo systemctl restart samureye-api samureye-worker
sudo nginx -t && sudo systemctl reload nginx

echo "==> OK"
```

---

## 11) Frontend (UI)

- **Tecnologias:** React + Vite + TypeScript + Tailwind + shadcn/ui;
- **Design:** minimalista, alto contraste, responsivo; tabelas com filtros; _dark mode_;
- **Páginas:**
  - **Login** (primeiro acesso força troca de senha);
  - **Dashboard** (contagem de ameaças por severidade, jobs recentes);
  - **Ativos** (lista, criação em massa, validação e _tags_);
  - **Credenciais** (tipo, porta, usuário; indica “guardado com segurança”);
  - **Jornadas** (criar/editar cada tipo, parâmetros por _wizard_);
  - **Agendamentos** (sob demanda/único/recorrente, CRON helper);
  - **Jobs** (últimas execuções, status _live_);
  - **Threat Intelligence** (filtros, estados, evidências, export);
  - **Admin** (usuários, papéis, parâmetros globais).

**Realtime:** WebSocket ou SSE para jobs/ameaças ao vivo.  
**Acessibilidade:** foco visível, labels, teclado, _aria_.

---

## 12) Execução de Jornadas (Técnico)

- **Attack Surface**  
  - _nmap_ executado via wrapper; saída XML → parser;  
  - _nuclei_ via CLI com _templates_ selecionados (whitelist); sanitizar caminhos;  
  - _Rate‑limit_ e _concurrency_ configuráveis.
- **AD/LDAP**  
  - `ldap3` para _bind_; _search_ de usuários, grupos, computers;  
  - Validadores parametrizáveis (dias, grupos críticos, etc.).
- **EDR/AV (EICAR)**  
  - `smbprotocol` ou `pypsexec` para copiar o arquivo EICAR;  
  - _Timeout_ para remoção; remove manualmente no fim se necessário;  
  - Registro completo de evidências (hash do arquivo, timestamps).

---

## 13) Observabilidade & Logs

- **API & Workers**: `structlog`/`loguru` JSON‑lines;
- **Acesso**: `/var/log/samureye/*.log` e `journalctl -u samureye-*`;
- **Métricas** (futuro): `/metrics` Prometheus, _exporters_ básicos;
- **Alertas** (futuro): webhook/email para novas **Threats criticas**.

---

## 14) Replit (modo Dev)

- Banco **SQLite** em `./dev.db`;  
- Executar apenas **API** e **Frontend** (sem nginx/certbot/systemd);
- Scripts `npm run dev` (UI) e `uvicorn api.main:app --reload` (API);
- _Mock_ de scanner (nmap/nuclei/AD/SMB) para desenvolvimento.

---

## 15) Testes Rápidos (pós‑deploy)

```bash
# Saúde
curl -sS http://127.0.0.1:8000/healthz | jq .

# Cria asset (host)
curl -sS -H "Authorization: Bearer <TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{"type":"host","value":"1.2.3.4"}' \
     http://127.0.0.1:8000/api/v1/assets | jq .

# Lista jobs recentes
curl -sS -H "Authorization: Bearer <TOKEN>" \
     http://127.0.0.1:8000/api/v1/jobs | jq .
```

---

## 16) Roadmap (curto prazo)

- UI: assistente de CRON, _bulk import_ de ativos, export CSV;
- Threats: _dedup_, _watchlists_, integrações (Jira/Teams/Slack);
- SSO (OIDC), 2FA TOTP;
- Modo “Distribuído” com “collectors” externos (mTLS).

---

## 17) Licenciamento e Compliance

- Componentes de terceiros com licenças permissivas (MIT/BSD/Apache);
- Armazenamento de segredos conforme LGPD/segurança da informação;
- Logs sem dados sensíveis; _PII_ minimizada.

---

## 18) Anexos

### 18.1 Estrutura de pastas (sugerida)

```
samureye/
├─ backend/
│  ├─ api/            # FastAPI (routers, schemas, services)
│  ├─ core/           # auth, security, settings
│  ├─ jobs/           # workers, tasks para jornadas
│  ├─ models/         # SQLAlchemy
│  ├─ migrations/     # Alembic
│  ├─ requirements.txt
│  └─ main.py
├─ frontend/
│  ├─ src/ (React/Vite/Tailwind/shadcn)
│  └─ package.json
├─ deploy/
│  ├─ systemd/*.service
│  └─ nginx/samureye.conf
├─ scripts/
│  ├─ install.sh
│  └─ update.sh
├─ .env.example
└─ README.md
```

---

**FIM** — Este documento serve como _blueprint_ para geração do projeto no Replit e implantação em VM Ubuntu _all‑in‑one_.

