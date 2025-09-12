#!/bin/bash

# SamurEye - Script de Correção de Autenticação PostgreSQL
# Corrige problemas de caracteres especiais na senha do banco

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
       SamurEye - Correção de Auth DB
=========================================="

# Verifica se o diretório de instalação existe
if [[ ! -d "$INSTALL_DIR" ]]; then
    error "Diretório de instalação $INSTALL_DIR não encontrado"
    exit 1
fi

# Para o serviço se estiver rodando
if systemctl is-active --quiet samureye-api; then
    log "Parando serviço SamurEye..."
    systemctl stop samureye-api
fi

# Backup do arquivo .env atual
if [[ -f "$INSTALL_DIR/.env" ]]; then
    log "Fazendo backup do .env atual..."
    cp "$INSTALL_DIR/.env" "$INSTALL_DIR/.env.backup.$(date +%Y%m%d_%H%M%S)"
fi

# Gera nova senha usando apenas caracteres alfanuméricos (hex)
log "Gerando nova senha do banco (apenas caracteres seguros)..."
NEW_DB_PASSWORD=$(openssl rand -hex 32)

# Reseta a senha do usuário no PostgreSQL
log "Atualizando senha do usuário $DB_USER no PostgreSQL..."
sudo -u postgres psql -c "ALTER USER $DB_USER WITH ENCRYPTED PASSWORD '$NEW_DB_PASSWORD';"

if [[ $? -eq 0 ]]; then
    log "✅ Senha do usuário $DB_USER atualizada com sucesso"
else
    error "❌ Falha ao atualizar senha do usuário $DB_USER"
    exit 1
fi

# Recria arquivo .env com nova senha
log "Atualizando arquivo .env..."

# Preserva as chaves existentes se houver
ENCRYPTION_KEK=""
SESSION_SECRET=""
if [[ -f "$INSTALL_DIR/.env" ]]; then
    ENCRYPTION_KEK=$(grep "^ENCRYPTION_KEK=" "$INSTALL_DIR/.env" | cut -d'=' -f2- || echo "")
    SESSION_SECRET=$(grep "^SESSION_SECRET=" "$INSTALL_DIR/.env" | cut -d'=' -f2- || echo "")
fi

# Gera novas chaves se não existirem
if [[ -z "$ENCRYPTION_KEK" ]]; then
    ENCRYPTION_KEK=$(openssl rand -hex 32)
fi

if [[ -z "$SESSION_SECRET" ]]; then
    SESSION_SECRET=$(openssl rand -base64 64 | tr -d '\n')
fi

# Cria novo arquivo .env
cat > "$INSTALL_DIR/.env" << EOF
# Configuração do Banco de Dados
DATABASE_URL=postgresql://$DB_USER:$NEW_DB_PASSWORD@localhost:5432/$DB_NAME
PGHOST=localhost
PGPORT=5432
PGUSER=$DB_USER
PGPASSWORD=$NEW_DB_PASSWORD
PGDATABASE=$DB_NAME

# Configuração da Aplicação
NODE_ENV=production
PORT=5000

# Chave de Criptografia (CRÍTICO - Mantenha segura)
ENCRYPTION_KEK=$ENCRYPTION_KEK

# Configuração de Sessão
SESSION_SECRET="$SESSION_SECRET"

# Configuração de Logs
LOG_LEVEL=info
EOF

# Define permissões seguras
chown samureye:samureye "$INSTALL_DIR/.env"
chmod 600 "$INSTALL_DIR/.env"

log "✅ Arquivo .env atualizado com nova senha"

# Testa a conexão
log "Testando conexão com o banco..."
cd "$INSTALL_DIR"

# Testa usando as novas credenciais
if sudo -u samureye DATABASE_URL="postgresql://$DB_USER:$NEW_DB_PASSWORD@localhost:5432/$DB_NAME" node -e "
const { Pool } = require('pg');
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
pool.query('SELECT version()')
  .then(() => { console.log('✅ Conexão PostgreSQL OK'); process.exit(0); })
  .catch(err => { console.error('❌ Erro de conexão:', err.message); process.exit(1); });
"; then
    log "✅ Conexão com PostgreSQL funcionando"
else
    error "❌ Ainda há problemas na conexão com PostgreSQL"
    exit 1
fi

# Reinicia o serviço
log "Reiniciando serviço SamurEye..."
systemctl start samureye-api

# Aguarda alguns segundos e verifica status
sleep 3
if systemctl is-active --quiet samureye-api; then
    log "✅ Serviço SamurEye iniciado com sucesso"
    log "✅ Correção da autenticação PostgreSQL concluída!"
    log ""
    log "🔍 Para verificar logs: journalctl -u samureye-api -f"
    log "🌐 Para acessar: http://$(hostname -I | awk '{print $1}'):5000"
else
    warn "⚠️  Serviço pode ter problemas. Verifique os logs:"
    warn "   journalctl -u samureye-api -n 50"
fi

log "==========================================
       Correção de Auth DB Finalizada
=========================================="