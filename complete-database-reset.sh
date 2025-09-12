#!/bin/bash

# SamurEye - Reset Completo de Banco de Dados
# Solução definitiva para problemas de autenticação PostgreSQL

set -Eeuo pipefail

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Variáveis de configuração
INSTALL_DIR="${INSTALL_DIR:-/opt/samureye}"
DB_NAME="${DB_NAME:-samureye_db}"
DB_USER="${DB_USER:-samureye}"
SERVICE_USER="${SERVICE_USER:-samureye}"

# Função para logging
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Verifica se está rodando como root
if [[ $EUID -ne 0 ]]; then
   error "Este script deve ser executado como root (sudo)"
   exit 1
fi

log "==========================================
  SamurEye - Reset Completo de Banco DB
=========================================="

# Para completamente o serviço
log "🛑 Parando todos os processos relacionados ao SamurEye..."
systemctl stop samureye-api 2>/dev/null || true
pkill -f "node.*samureye" 2>/dev/null || true
pkill -f "npm.*samureye" 2>/dev/null || true
pkill -f "tsx.*samureye" 2>/dev/null || true

# Aguarda processos finalizarem
sleep 3

# Força término de todas as conexões ativas do banco
log "🔌 Terminando TODAS as conexões ativas do banco..."
sudo -u postgres psql -c "
    SELECT pg_terminate_backend(pg_stat_activity.pid) 
    FROM pg_stat_activity 
    WHERE pg_stat_activity.datname = '$DB_NAME' 
      AND pid <> pg_backend_pid();
" 2>/dev/null || true

# Aguarda conexões terminarem
sleep 2

# Remove completamente banco e usuário
log "🗑️ Removendo banco de dados existente..."
sudo -u postgres psql -c "DROP DATABASE IF EXISTS $DB_NAME;" 2>/dev/null || true

log "🗑️ Removendo usuário do banco existente..."
sudo -u postgres psql -c "DROP USER IF EXISTS $DB_USER;" 2>/dev/null || true

# Gera nova senha APENAS com caracteres hex (0-9, a-f)
log "🔑 Gerando nova senha segura (apenas caracteres alfanuméricos)..."
DB_PASSWORD=$(openssl rand -hex 32)

# Verifica se a senha foi gerada
if [[ -z "$DB_PASSWORD" ]] || [[ ${#DB_PASSWORD} -lt 32 ]]; then
    error "Falha ao gerar senha do banco"
    exit 1
fi

log "👤 Criando novo usuário do banco: $DB_USER"
sudo -u postgres psql -c "CREATE USER $DB_USER WITH LOGIN CREATEDB;"
sudo -u postgres psql -c "ALTER USER $DB_USER WITH ENCRYPTED PASSWORD '$DB_PASSWORD';"

log "🏗️ Criando novo banco de dados: $DB_NAME"
sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"
sudo -u postgres psql -c "ALTER USER $DB_USER NOCREATEDB;"

# Instala extensão pgcrypto
log "🔧 Instalando extensão pgcrypto..."
sudo -u postgres psql -d "$DB_NAME" -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;" || true

# Força reload do PostgreSQL
log "🔄 Recarregando configuração PostgreSQL..."
sudo -u postgres psql -c "SELECT pg_reload_conf();" || true
systemctl reload postgresql || true

# Aguarda estabilizar
sleep 3

# Testa conexão múltiplas vezes
log "🧪 Testando conexão com novas credenciais..."
for i in {1..3}; do
    if PGPASSWORD="$DB_PASSWORD" psql -h localhost -U "$DB_USER" -d "$DB_NAME" -c "SELECT version();" > /dev/null 2>&1; then
        log "✅ Teste de conexão $i/3 - SUCESSO"
        break
    else
        warn "❌ Teste de conexão $i/3 - FALHOU"
        if [[ $i -eq 3 ]]; then
            error "Falha crítica na conexão após 3 tentativas"
            exit 1
        fi
        sleep 2
    fi
done

# Atualiza arquivo .env
if [[ -f "$INSTALL_DIR/.env" ]]; then
    log "📝 Fazendo backup do .env..."
    cp "$INSTALL_DIR/.env" "$INSTALL_DIR/.env.backup.$(date +%Y%m%d_%H%M%S)"
fi

# Preserva configurações existentes
ENCRYPTION_KEK=""
SESSION_SECRET=""
if [[ -f "$INSTALL_DIR/.env" ]]; then
    ENCRYPTION_KEK=$(grep "^ENCRYPTION_KEK=" "$INSTALL_DIR/.env" | cut -d'=' -f2- || echo "")
    SESSION_SECRET=$(grep "^SESSION_SECRET=" "$INSTALL_DIR/.env" | cut -d'=' -f2- || echo "")
fi

# Gera novas chaves se necessário
if [[ -z "$ENCRYPTION_KEK" ]]; then
    ENCRYPTION_KEK=$(openssl rand -hex 32)
fi

if [[ -z "$SESSION_SECRET" ]]; then
    SESSION_SECRET=$(openssl rand -base64 64 | tr -d '\n')
fi

log "📝 Criando novo arquivo .env..."
cat > "$INSTALL_DIR/.env" << EOF
# Configuração do Banco de Dados - Reset $(date)
DATABASE_URL=postgresql://$DB_USER:$DB_PASSWORD@localhost:5432/$DB_NAME
PGHOST=localhost
PGPORT=5432
PGUSER=$DB_USER
PGPASSWORD=$DB_PASSWORD
PGDATABASE=$DB_NAME

# Configuração da Aplicação
NODE_ENV=production
PORT=5000

# Chave de Criptografia
ENCRYPTION_KEK=$ENCRYPTION_KEK

# Configuração de Sessão  
SESSION_SECRET="$SESSION_SECRET"

# Configuração de Logs
LOG_LEVEL=info
EOF

# Define permissões
chown $SERVICE_USER:$SERVICE_USER "$INSTALL_DIR/.env"
chmod 600 "$INSTALL_DIR/.env"

# Executa migrações
log "📋 Executando migrações do banco..."
cd "$INSTALL_DIR"

if sudo -u $SERVICE_USER \
    DATABASE_URL="postgresql://$DB_USER:$DB_PASSWORD@localhost:5432/$DB_NAME" \
    npm run db:push; then
    log "✅ Migrações executadas com sucesso"
else
    warn "Tentando migrações com --force..."
    if sudo -u $SERVICE_USER \
        DATABASE_URL="postgresql://$DB_USER:$DB_PASSWORD@localhost:5432/$DB_NAME" \
        npx drizzle-kit push --force; then
        log "✅ Migrações forçadas executadas"
    else
        error "❌ Falha nas migrações"
        exit 1
    fi
fi

# Verifica tabelas criadas
log "🔍 Verificando tabelas criadas..."
TABLES_COUNT=$(PGPASSWORD="$DB_PASSWORD" psql -h localhost -U "$DB_USER" -d "$DB_NAME" \
    -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';" | tr -d ' ')

log "📋 Tabelas no banco ($TABLES_COUNT encontradas):"
PGPASSWORD="$DB_PASSWORD" psql -h localhost -U "$DB_USER" -d "$DB_NAME" -c "\dt"

# Cria usuário admin
log "👤 Criando usuário administrador..."
ADMIN_PASSWORD=$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c16)
ADMIN_HASH=$(node -e "
    const bcrypt = require('bcryptjs');
    console.log(bcrypt.hashSync('$ADMIN_PASSWORD', 12));
")

PGPASSWORD="$DB_PASSWORD" psql -h localhost -U "$DB_USER" -d "$DB_NAME" -c "
    INSERT INTO users (id, email, password_hash, role, must_change_password) 
    VALUES (gen_random_uuid(), 'admin@samureye.com.br', '$ADMIN_HASH', 'global_administrator', true)
    ON CONFLICT DO NOTHING;
"

# Salva credenciais
cat > "$INSTALL_DIR/ADMIN_CREDENTIALS" << EOF
=======================================
   SamurEye - Credenciais de Acesso
=======================================

URL: http://$(hostname -I | awk '{print $1}'):5000
Email: admin@samureye.com.br  
Senha: $ADMIN_PASSWORD

IMPORTANTE: Altere a senha no primeiro login!
=======================================
EOF

chmod 600 "$INSTALL_DIR/ADMIN_CREDENTIALS"
chown $SERVICE_USER:$SERVICE_USER "$INSTALL_DIR/ADMIN_CREDENTIALS"

# Reinicia serviço
log "🚀 Reiniciando serviço SamurEye..."
systemctl start samureye-api

sleep 5

if systemctl is-active --quiet samureye-api; then
    log "✅ Reset completo do banco CONCLUÍDO COM SUCESSO!"
    log "🌐 Acesso: http://$(hostname -I | awk '{print $1}'):5000"
    log "🔑 Credenciais: cat $INSTALL_DIR/ADMIN_CREDENTIALS"
    log "🔍 Logs: journalctl -u samureye-api -f"
else
    error "❌ Serviço com problemas. Verifique logs: journalctl -u samureye-api -n 50"
fi

log "=========================================="