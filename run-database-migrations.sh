#!/bin/bash

# SamurEye - Script para Executar Migrações do Banco de Dados
# Cria tabelas necessárias na instalação existente

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
    SamurEye - Execução de Migrações DB
=========================================="

# Verifica se o diretório de instalação existe
if [[ ! -d "$INSTALL_DIR" ]]; then
    error "Diretório de instalação $INSTALL_DIR não encontrado"
    exit 1
fi

# Verifica se arquivo .env existe
if [[ ! -f "$INSTALL_DIR/.env" ]]; then
    error "Arquivo .env não encontrado em $INSTALL_DIR"
    exit 1
fi

# Para o serviço se estiver rodando
if systemctl is-active --quiet samureye-api; then
    log "Parando serviço SamurEye..."
    systemctl stop samureye-api
fi

# Extrai credenciais do .env
log "Carregando configurações do banco..."
DB_PASSWORD=$(grep "^PGPASSWORD=" "$INSTALL_DIR/.env" | cut -d'=' -f2-)

if [[ -z "$DB_PASSWORD" ]]; then
    error "Senha do banco não encontrada no arquivo .env"
    exit 1
fi

# Verifica conexão com o banco
log "Testando conexão com PostgreSQL..."
cd "$INSTALL_DIR"

if ! sudo -u samureye DATABASE_URL="postgresql://$DB_USER:$DB_PASSWORD@localhost:5432/$DB_NAME" node -e "
const { Pool } = require('pg');
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
pool.query('SELECT version()').then(() => {
    console.log('✅ Conexão com banco OK');
    process.exit(0);
}).catch(err => {
    console.error('❌ Erro conexão:', err.message);
    process.exit(1);
});
" 2>/dev/null; then
    error "❌ Falha na conexão com PostgreSQL"
    exit 1
fi

# Verifica se drizzle-kit está disponível
log "Verificando se drizzle-kit está instalado..."
if ! npm list drizzle-kit > /dev/null 2>&1; then
    error "drizzle-kit não encontrado. Instalando dependências..."
    sudo -u samureye npm install
fi

# Lista tabelas existentes antes das migrações
log "📋 Tabelas existentes antes das migrações:"
PGPASSWORD="$DB_PASSWORD" psql -h localhost -U "$DB_USER" -d "$DB_NAME" \
    -c "\dt" 2>/dev/null || echo "Nenhuma tabela encontrada"

# Executa migrações
log "📋 Executando migrações Drizzle..."
if sudo -u samureye \
    DATABASE_URL="postgresql://$DB_USER:$DB_PASSWORD@localhost:5432/$DB_NAME" \
    npm run db:push; then
    log "✅ Migrações executadas com sucesso"
else
    warn "❌ Migrações falharam, tentando com --force..."
    if sudo -u samureye \
        DATABASE_URL="postgresql://$DB_USER:$DB_PASSWORD@localhost:5432/$DB_NAME" \
        npx drizzle-kit push --force; then
        log "✅ Migrações forçadas executadas com sucesso"
    else
        error "❌ Falha crítica nas migrações do banco"
        exit 1
    fi
fi

# Verifica se as tabelas principais foram criadas
log "🔍 Verificando se tabelas foram criadas..."
TABLES_CHECK=$(PGPASSWORD="$DB_PASSWORD" psql -h localhost -U "$DB_USER" -d "$DB_NAME" \
    -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('users', 'assets', 'jobs', 'journeys', 'audit_log');" 2>/dev/null | tr -d ' ' || echo "0")

log "📋 Tabelas criadas no banco:"
PGPASSWORD="$DB_PASSWORD" psql -h localhost -U "$DB_USER" -d "$DB_NAME" \
    -c "\dt" 2>/dev/null || echo "Erro ao listar tabelas"

if [[ "$TABLES_CHECK" -ge 5 ]]; then
    log "✅ Tabelas principais criadas com sucesso ($TABLES_CHECK/5)"
else
    warn "⚠️ Algumas tabelas podem estar faltando (encontradas: $TABLES_CHECK/5)"
fi

# Cria usuário administrador se não existir
log "🔍 Verificando usuário administrador..."
ADMIN_COUNT=$(PGPASSWORD="$DB_PASSWORD" psql -h localhost -U "$DB_USER" -d "$DB_NAME" \
    -t -c "SELECT COUNT(*) FROM users WHERE role = 'global_administrator';" 2>/dev/null | tr -d ' ' || echo "0")

if [[ "$ADMIN_COUNT" -eq 0 ]]; then
    log "👤 Criando usuário administrador inicial..."
    
    # Gera senha temporária
    ADMIN_TEMP_PASSWORD=$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c16)
    
    # Cria hash da senha
    ADMIN_PASSWORD_HASH=$(node -e "
        const bcrypt = require('bcryptjs');
        const password = '$ADMIN_TEMP_PASSWORD';
        const hash = bcrypt.hashSync(password, 12);
        console.log(hash);
    ")
    
    # Insere usuário admin no banco
    PGPASSWORD="$DB_PASSWORD" psql -h localhost -U "$DB_USER" -d "$DB_NAME" \
        -c "INSERT INTO users (id, email, password_hash, role, must_change_password) 
            VALUES (gen_random_uuid(), 'admin@samureye.com.br', '$ADMIN_PASSWORD_HASH', 'global_administrator', true);" || true
    
    # Salva credenciais
    cat > "$INSTALL_DIR/ADMIN_CREDENTIALS" << EOF
=======================================
   SamurEye - Credenciais de Acesso
=======================================

URL de Acesso: http://$(hostname -I | awk '{print $1}'):5000
Email: admin@samureye.com.br
Senha Temporária: $ADMIN_TEMP_PASSWORD

IMPORTANTE: Altere a senha no primeiro login!

=======================================
EOF
    
    chmod 600 "$INSTALL_DIR/ADMIN_CREDENTIALS"
    chown samureye:samureye "$INSTALL_DIR/ADMIN_CREDENTIALS"
    
    log "✅ Usuário administrador criado"
    log "📋 Credenciais salvas em: $INSTALL_DIR/ADMIN_CREDENTIALS"
else
    log "✅ Usuário administrador já existe ($ADMIN_COUNT encontrado)"
fi

# Reinicia o serviço
log "Reiniciando serviço SamurEye..."
systemctl start samureye-api

# Aguarda alguns segundos e verifica status
sleep 5
if systemctl is-active --quiet samureye-api; then
    log "✅ Serviço SamurEye iniciado com sucesso"
    log "✅ Migrações do banco concluídas!"
    log ""
    log "🔍 Para verificar logs: journalctl -u samureye-api -f"
    log "🌐 Para acessar: http://$(hostname -I | awk '{print $1}'):5000"
    
    if [[ -f "$INSTALL_DIR/ADMIN_CREDENTIALS" ]]; then
        log "🔑 Credenciais de admin: cat $INSTALL_DIR/ADMIN_CREDENTIALS"
    fi
else
    warn "⚠️  Serviço pode ter problemas. Verifique os logs:"
    warn "   journalctl -u samureye-api -n 50"
fi

log "==========================================
    Execução de Migrações DB Finalizada
=========================================="