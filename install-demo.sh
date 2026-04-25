#!/usr/bin/env bash
# install-demo.sh — SamurEye Demo Installer
#
# Instala uma instância de demonstração do SamurEye em /opt/samureye-demo
# servida na porta 5005 e acessível via nginx em /demo/.
#
# Uso:
#   ./install-demo.sh --install    # instala/reinstala a instância demo
#   ./install-demo.sh --seed       # (re)popula o banco com dados de demonstração
#   ./install-demo.sh --update     # atualiza código da branch main e reconstrói
#   ./install-demo.sh --status     # exibe status do serviço
#
# Requisitos:
#   - Debian/Ubuntu 20.04+
#   - PostgreSQL já instalado (ou será instalado automaticamente)
#   - nginx já instalado (snippet de configuração será gerado)
#   - Executar como root ou com sudo

set -euo pipefail

# ── Configuração ──────────────────────────────────────────────────────────────
REPO_URL="https://github.com/GruppenIT/SamurEyePlatform.git"
BRANCH="main"
INSTALL_DIR="/opt/samureye-demo"
SERVICE_NAME="samureye-demo"
APP_PORT="5005"
BASE_PATH="/demo"
APP_USER="samureye-demo"
DB_NAME="samureye_demo"
DB_USER="samureye_demo"
LOG_DIR="/var/log/samureye-demo"
NGINX_SNIPPET="/etc/nginx/snippets/samureye-demo.conf"

# ── Cores ─────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*" >&2; }
success() { echo -e "${GREEN}[OK]${NC}    $*" >&2; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()     { error "$*"; exit 1; }

# ── Pré-condições ─────────────────────────────────────────────────────────────
require_root() {
  [[ $EUID -eq 0 ]] || die "Execute como root: sudo $0 $*"
}

require_command() {
  command -v "$1" &>/dev/null || die "Comando não encontrado: $1"
}

# ── Detecção de distro ────────────────────────────────────────────────────────
detect_distro() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_VERSION="${VERSION_ID:-0}"
  else
    die "Não foi possível detectar distribuição Linux."
  fi
  info "Distribuição: ${DISTRO_ID} ${DISTRO_VERSION}"
}

# ── Node.js ───────────────────────────────────────────────────────────────────
install_nodejs() {
  if command -v node &>/dev/null; then
    NODE_VER=$(node --version | sed 's/v//' | cut -d. -f1)
    if [[ $NODE_VER -ge 20 ]]; then
      success "Node.js $(node --version) já instalado."
      return
    fi
    warn "Node.js muito antigo (v${NODE_VER}). Atualizando para v22..."
  fi
  info "Instalando Node.js 22 LTS..."
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y nodejs
  success "Node.js $(node --version) instalado."
}

# ── PostgreSQL ────────────────────────────────────────────────────────────────
setup_postgresql() {
  # Verifica se PostgreSQL está disponível
  if pg_isready -q 2>/dev/null; then
    success "PostgreSQL em execução — reutilizando instância existente."
  elif command -v pg_isready &>/dev/null; then
    info "PostgreSQL instalado mas não rodando — iniciando..."
    systemctl start postgresql || service postgresql start
    sleep 2
    pg_isready -q || die "PostgreSQL não respondeu após inicialização."
    success "PostgreSQL iniciado."
  else
    info "PostgreSQL não encontrado. Instalando..."
    apt-get install -y postgresql postgresql-contrib
    systemctl enable postgresql
    systemctl start postgresql
    sleep 3
    pg_isready -q || die "PostgreSQL não respondeu após instalação."
    success "PostgreSQL instalado e iniciado."
  fi

  # Cria banco e usuário se não existirem
  info "Configurando banco de dados '${DB_NAME}'..."

  # Gera sempre uma senha nova no --install para garantir consistência
  # (evita reutilizar senha corrompida de .env de runs anteriores)
  DB_PASS=$(openssl rand -base64 24 | tr -d '=/+' | head -c 32)

  sudo -u postgres psql -c "
    DO \$\$
    BEGIN
      IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${DB_USER}') THEN
        CREATE ROLE ${DB_USER} WITH LOGIN PASSWORD '${DB_PASS}';
      ELSE
        ALTER ROLE ${DB_USER} WITH PASSWORD '${DB_PASS}';
      END IF;
    END
    \$\$;
  " || die "Falha ao criar usuário do banco."

  sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname = '${DB_NAME}'" | grep -q 1 || \
    sudo -u postgres createdb -O "${DB_USER}" "${DB_NAME}"

  # Extensão uuid-ossp
  sudo -u postgres psql -d "${DB_NAME}" -c "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";" &>/dev/null || true

  success "Banco '${DB_NAME}' configurado."
  echo "$DB_PASS"
}

# ── Sistema de arquivos e usuário ─────────────────────────────────────────────
setup_user_and_dirs() {
  if ! id "${APP_USER}" &>/dev/null; then
    info "Criando usuário de sistema '${APP_USER}'..."
    useradd -r -s /bin/false -d "${INSTALL_DIR}" "${APP_USER}"
  fi
  mkdir -p "${INSTALL_DIR}" "${LOG_DIR}"
  chown -R "${APP_USER}:${APP_USER}" "${LOG_DIR}"
}

# ── Clone / atualização do repositório ───────────────────────────────────────
fetch_code() {
  if [[ -d "${INSTALL_DIR}/.git" ]]; then
    info "Repositório existente encontrado. Atualizando para branch '${BRANCH}'..."
    git -C "${INSTALL_DIR}" fetch origin
    git -C "${INSTALL_DIR}" checkout "${BRANCH}"
    git -C "${INSTALL_DIR}" reset --hard "origin/${BRANCH}"
    success "Código atualizado."
  else
    info "Clonando repositório (branch ${BRANCH})..."
    git clone --depth 1 --branch "${BRANCH}" "${REPO_URL}" "${INSTALL_DIR}"
    success "Repositório clonado."
  fi
}

# ── Arquivo .env ──────────────────────────────────────────────────────────────
write_env() {
  local db_pass="$1"
  cat > "${INSTALL_DIR}/.env" <<EOF
# SamurEye Demo — gerado por install-demo.sh
NODE_ENV=production
PORT=${APP_PORT}
DATABASE_URL=postgresql://${DB_USER}:${db_pass}@localhost:5432/${DB_NAME}
DB_PASS=${db_pass}

# Modo demo: desabilita fila de jobs e e-mail
DEMO_MODE=true

# Segredo de sessão (regenerado a cada reinstalação)
SESSION_SECRET=$(openssl rand -hex 32)

# Criptografia de credenciais (não usada no demo, mas obrigatória)
ENCRYPTION_KEY=$(openssl rand -hex 32)
MASTER_KEY=$(openssl rand -hex 32)

# Base path do nginx
BASE_PATH=${BASE_PATH}
EOF
  chmod 640 "${INSTALL_DIR}/.env"
  chown "${APP_USER}:${APP_USER}" "${INSTALL_DIR}/.env"
  success "Arquivo .env criado."
}

# ── Dependências npm ──────────────────────────────────────────────────────────
install_deps() {
  info "Instalando dependências npm..."
  cd "${INSTALL_DIR}"
  npm ci --omit=dev --ignore-scripts 2>&1 | tail -5 || \
    npm install --omit=dev --ignore-scripts 2>&1 | tail -5
  # tsx e drizzle-kit necessários para migrations e seed
  npm install --save-dev tsx drizzle-kit 2>&1 | tail -3 || true
  success "Dependências instaladas."
}

# ── Build do frontend ─────────────────────────────────────────────────────────
build_frontend() {
  info "Compilando frontend (base: ${BASE_PATH}/)..."
  cd "${INSTALL_DIR}"
  VITE_BASE_PATH="${BASE_PATH}/" \
  VITE_API_PREFIX="${BASE_PATH}" \
  VITE_ROUTER_BASE="${BASE_PATH}" \
  VITE_DEMO_MODE="true" \
    npx vite build 2>&1 | tail -10
  success "Frontend compilado em dist/public."
}

# ── Migrations ────────────────────────────────────────────────────────────────
run_migrations() {
  info "Executando drizzle-kit push (cria/atualiza schema)..."
  cd "${INSTALL_DIR}"
  DATABASE_URL=$(grep -E '^DATABASE_URL=' .env | head -1 | cut -d= -f2-)
  export DATABASE_URL

  # Testa conectividade antes de rodar drizzle-kit (diagnóstico precoce)
  node --input-type=module <<'PGTEST' || die "Falha na conexão ao banco — verifique DATABASE_URL no .env"
import pg from 'pg';
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, connectionTimeoutMillis: 5000 });
const client = await pool.connect();
client.release();
await pool.end();
PGTEST

  # Usa 'push' — o projeto não tem migration files, usa push direto
  npx drizzle-kit push --force 2>&1 || \
    die "Falha no drizzle-kit push — verifique a DATABASE_URL no .env"
  success "Schema criado/atualizado."
}

# ── Admin inicial ─────────────────────────────────────────────────────────────
create_admin() {
  info "Criando usuário admin de demonstração..."
  cd "${INSTALL_DIR}"
  DATABASE_URL=$(grep -E '^DATABASE_URL=' .env | head -1 | cut -d= -f2-)
  export DATABASE_URL
  ADMIN_EMAIL="demo@samureye.com.br" \
  ADMIN_PASSWORD="Demo@2026!" \
    npx tsx scripts/create-demo-admin.ts 2>&1 | tail -5 || \
    warn "Falha ao criar admin — verifique manualmente."
  success "Usuário admin: demo@samureye.com.br / Demo@2026!"
}

# ── Seed de dados de demonstração ────────────────────────────────────────────
run_demo_seed() {
  info "Populando banco com dados de demonstração..."
  cd "${INSTALL_DIR}"
  DATABASE_URL=$(grep -E '^DATABASE_URL=' .env | head -1 | cut -d= -f2-)
  export DATABASE_URL
  npx tsx scripts/demo-seed.ts
  success "Dados de demonstração inseridos."
}

# ── Systemd service ───────────────────────────────────────────────────────────
install_systemd() {
  info "Configurando serviço systemd '${SERVICE_NAME}'..."
  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=SamurEye Demo Instance
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=${APP_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=$(which node) dist/index.js
Restart=always
RestartSec=5
StandardOutput=append:${LOG_DIR}/app.log
StandardError=append:${LOG_DIR}/error.log
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}"
  success "Serviço systemd configurado."
}

# ── Build do backend ──────────────────────────────────────────────────────────
build_backend() {
  info "Compilando backend TypeScript..."
  cd "${INSTALL_DIR}"
  npx esbuild server/index.ts \
    --platform=node \
    --packages=external \
    --bundle \
    --format=esm \
    --outdir=dist \
    2>&1 | tail -5
  bash generate-version.sh 2>/dev/null || true
  success "Backend compilado em dist/."
}

# ── Snippet nginx ─────────────────────────────────────────────────────────────
write_nginx_snippet() {
  info "Gerando snippet nginx em ${NGINX_SNIPPET}..."
  mkdir -p "$(dirname "${NGINX_SNIPPET}")"
  cat > "${NGINX_SNIPPET}" <<'NGINX'
# SamurEye Demo — inclua este snippet no bloco server{} do seu nginx:
#   include snippets/samureye-demo.conf;

# API do demo — proxy sem strip de prefixo (Express recebe /api/...)
location /demo/api/ {
    proxy_pass         http://127.0.0.1:5005/api/;
    proxy_http_version 1.1;
    proxy_set_header   Upgrade $http_upgrade;
    proxy_set_header   Connection "upgrade";
    proxy_set_header   Host $host;
    proxy_set_header   X-Real-IP $remote_addr;
    proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header   X-Forwarded-Proto $scheme;
    proxy_read_timeout 300s;
}

# WebSocket do demo
location /demo/ws {
    proxy_pass         http://127.0.0.1:5005/ws;
    proxy_http_version 1.1;
    proxy_set_header   Upgrade $http_upgrade;
    proxy_set_header   Connection "upgrade";
    proxy_set_header   Host $host;
    proxy_read_timeout 86400s;
}

# Frontend do demo (SPA) — strip do prefixo /demo/
location /demo/ {
    proxy_pass         http://127.0.0.1:5005/;
    proxy_http_version 1.1;
    proxy_set_header   Host $host;
    proxy_set_header   X-Real-IP $remote_addr;
    proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header   X-Forwarded-Proto $scheme;
    # Cache de assets estáticos
    location ~* \.(js|css|png|jpg|ico|woff2?)$ {
        proxy_pass http://127.0.0.1:5005;
        proxy_cache_valid 200 1d;
        add_header Cache-Control "public, max-age=86400";
    }
}

# Redireciona /demo para /demo/
location = /demo {
    return 301 /demo/;
}
NGINX
  success "Snippet nginx criado em ${NGINX_SNIPPET}."
  echo ""
  echo -e "${YELLOW}Adicione no bloco server{} do nginx:${NC}"
  echo "    include snippets/samureye-demo.conf;"
  echo "E então: nginx -t && systemctl reload nginx"
}

# ── Permissões finais ─────────────────────────────────────────────────────────
set_permissions() {
  chown -R "${APP_USER}:${APP_USER}" "${INSTALL_DIR}"
  # .env apenas para o dono
  chmod 640 "${INSTALL_DIR}/.env" 2>/dev/null || true
}

# ── Status ────────────────────────────────────────────────────────────────────
show_status() {
  echo ""
  echo -e "${BLUE}═══════════════════════════════════════${NC}"
  echo -e "${BLUE}  SamurEye Demo — Status${NC}"
  echo -e "${BLUE}═══════════════════════════════════════${NC}"
  systemctl status "${SERVICE_NAME}" --no-pager -l 2>/dev/null || \
    echo "  Serviço não encontrado."
  echo ""
  if curl -sf "http://localhost:${APP_PORT}/api/health" &>/dev/null; then
    success "App respondendo em http://localhost:${APP_PORT}"
  else
    warn "App não está respondendo em http://localhost:${APP_PORT}"
  fi
}

# ── Fluxo principal ───────────────────────────────────────────────────────────
main_install() {
  require_root
  detect_distro

  echo ""
  echo -e "${BLUE}╔══════════════════════════════════════════╗${NC}"
  echo -e "${BLUE}║   SamurEye Demo — Instalação             ║${NC}"
  echo -e "${BLUE}╚══════════════════════════════════════════╝${NC}"
  echo ""

  install_nodejs
  setup_user_and_dirs
  DB_PASS=$(setup_postgresql)
  fetch_code

  # .env deve existir antes do build (variáveis de ambiente)
  write_env "${DB_PASS}"

  install_deps
  build_frontend
  build_backend
  run_migrations
  create_admin
  run_demo_seed
  install_systemd
  set_permissions
  write_nginx_snippet

  info "Iniciando serviço..."
  systemctl restart "${SERVICE_NAME}"
  sleep 3
  show_status

  echo ""
  echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}║  Instalação concluída!                           ║${NC}"
  echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
  echo -e "${GREEN}║  URL:    http://localhost:${APP_PORT}                   ║${NC}"
  echo -e "${GREEN}║  Admin:  demo@samureye.com.br                    ║${NC}"
  echo -e "${GREEN}║  Senha:  Demo@2026!                              ║${NC}"
  echo -e "${GREEN}║                                                  ║${NC}"
  echo -e "${GREEN}║  Após configurar nginx:                          ║${NC}"
  echo -e "${GREEN}║  https://www.samureye.com.br/demo                ║${NC}"
  echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
  echo ""
}

main_update() {
  require_root
  info "Atualizando SamurEye Demo..."

  systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
  fetch_code

  # Recarrega variáveis do .env existente (sem xargs — evita split em espaços)
  DATABASE_URL=$(grep -E '^DATABASE_URL=' "${INSTALL_DIR}/.env" | head -1 | cut -d= -f2-)
  DB_PASS=$(grep -E '^DB_PASS=' "${INSTALL_DIR}/.env" | head -1 | cut -d= -f2-)
  export DATABASE_URL DB_PASS
  DB_PASS="${DB_PASS:-}"

  install_deps
  build_frontend
  build_backend
  run_migrations
  set_permissions

  systemctl start "${SERVICE_NAME}"
  sleep 3
  show_status
  success "Atualização concluída."
}

main_seed() {
  require_root
  [[ -f "${INSTALL_DIR}/.env" ]] || die "Instância não encontrada em ${INSTALL_DIR}. Execute --install primeiro."
  run_demo_seed
}

# ── Ponto de entrada ──────────────────────────────────────────────────────────
case "${1:-}" in
  --install)  main_install ;;
  --update)   main_update  ;;
  --seed)     main_seed    ;;
  --status)   show_status  ;;
  *)
    echo "Uso: $0 {--install|--update|--seed|--status}"
    echo ""
    echo "  --install   Instala a instância demo completa"
    echo "  --update    Atualiza código e reconstrói (preserva banco)"
    echo "  --seed      (Re)popula o banco com dados de demonstração"
    echo "  --status    Exibe status do serviço"
    exit 1
    ;;
esac
