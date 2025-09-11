#!/bin/bash

# SamurEye - Adversarial Exposure Validation Platform
# Script de Upgrade Automático
# Versão: 1.0.0

set -euo pipefail

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variáveis de configuração
INSTALL_DIR="/opt/samureye"
SERVICE_USER="www-data"
BACKUP_DIR="$INSTALL_DIR/backups"
TEMP_DIR="$INSTALL_DIR/temp"
SERVICE_NAME="samureye"

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

# Função para verificar se o usuário é root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Este script deve ser executado como root (use sudo)"
        exit 1
    fi
}

# Função para verificar se a aplicação está instalada
check_installation() {
    if [[ ! -d "$INSTALL_DIR" ]]; then
        error "SamurEye não está instalado em $INSTALL_DIR"
        exit 1
    fi
    
    if [[ ! -f "$INSTALL_DIR/.env" ]]; then
        error "Arquivo de configuração não encontrado: $INSTALL_DIR/.env"
        exit 1
    fi
    
    log "Instalação verificada em $INSTALL_DIR"
}

# Função para verificar atualizações
check_updates() {
    log "Verificando atualizações..."
    cd "$INSTALL_DIR"
    
    # Configura upstream se não estiver configurado
    if ! git rev-parse --abbrev-ref @{u} &>/dev/null; then
        git branch --set-upstream-to=origin/main main || git branch --set-upstream-to=origin/main
    fi
    
    git fetch origin main
    
    LOCAL=$(git rev-parse @)
    REMOTE=$(git rev-parse origin/main)
    
    if [[ $LOCAL == $REMOTE ]]; then
        log "Sistema já na versão mais recente"
        read -p "Continuar com upgrade? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 0
        fi
    else
        log "Atualizações disponíveis"
        log "Local: $(git rev-parse --short $LOCAL)"
        log "Remoto: $(git rev-parse --short $REMOTE)"
    fi
}

# Função para backup pré-upgrade
create_backup() {
    log "Criando backup..."
    local DATE=$(date +%Y%m%d_%H%M%S)
    local DB_BACKUP="$BACKUP_DIR/pre_upgrade_db_$DATE.sql"
    
    mkdir -p "$BACKUP_DIR" "$TEMP_DIR"
    
    # Carrega variáveis de ambiente
    set -a
    source "$INSTALL_DIR/.env"
    set +a
    
    # Backup do banco
    log "Backup do banco de dados..."
    PGPASSWORD="$PGPASSWORD" pg_dump -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" > "$DB_BACKUP"
    
    # Salva informações para rollback
    echo "DB_BACKUP_FILE=\"$DB_BACKUP\"" > "$TEMP_DIR/upgrade_info"
    echo "PREVIOUS_COMMIT=\"$(git rev-parse HEAD)\"" >> "$TEMP_DIR/upgrade_info"
    
    log "Backup criado: $DB_BACKUP"
}

# Função para parar serviços
stop_services() {
    log "Parando serviços..."
    systemctl stop "$SERVICE_NAME" || true
    sleep 2
}

# Função para atualizar código
update_code() {
    log "Atualizando código..."
    cd "$INSTALL_DIR"
    
    # Salva mudanças locais se houver
    if ! git diff --quiet; then
        git stash push -m "Auto-stash upgrade $(date)"
    fi
    
    git pull origin main
    log "Código atualizado para: $(git rev-parse --short HEAD)"
}

# Função para atualizar dependências
update_dependencies() {
    log "Atualizando dependências..."
    cd "$INSTALL_DIR"
    npm ci --production=false
}

# Função para compilar aplicação
build_application() {
    log "Compilando aplicação..."
    cd "$INSTALL_DIR"
    rm -rf dist/
    npm run build
}

# Função para executar migrações
run_migrations() {
    log "Executando migrações..."
    cd "$INSTALL_DIR"
    
    # Lê variáveis de ambiente do arquivo
    source "$INSTALL_DIR/.env"
    
    # Executa migrações com variáveis inline para evitar problemas com sudo -E
    sudo -u "$SERVICE_USER" \
        DATABASE_URL="$DATABASE_URL" \
        PGHOST="$PGHOST" \
        PGPORT="$PGPORT" \
        PGUSER="$PGUSER" \
        PGPASSWORD="$PGPASSWORD" \
        PGDATABASE="$PGDATABASE" \
        npm run db:push
}

# Função para iniciar serviços
start_services() {
    log "Iniciando serviços..."
    systemctl start "$SERVICE_NAME"
    sleep 5
    
    if ! systemctl is-active --quiet "$SERVICE_NAME"; then
        error "Falha ao iniciar serviço"
        return 1
    fi
    
    # Testa aplicação
    for i in {1..30}; do
        if curl -f http://localhost:5000/api/health &>/dev/null; then
            log "Aplicação respondendo"
            return 0
        fi
        sleep 2
    done
    
    error "Aplicação não responde"
    return 1
}

# Função para rollback
rollback() {
    error "Executando rollback..."
    
    if [[ -f "$TEMP_DIR/upgrade_info" ]]; then
        source "$TEMP_DIR/upgrade_info"
        
        cd "$INSTALL_DIR"
        
        # Restaura código
        git reset --hard "$PREVIOUS_COMMIT"
        npm ci --production=false
        npm run build
        
        # Restaura banco
        if [[ -f "$DB_BACKUP_FILE" ]]; then
            set -a
            source "$INSTALL_DIR/.env"
            set +a
            PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" < "$DB_BACKUP_FILE"
        fi
        
        # Reinicia serviços
        systemctl start "$SERVICE_NAME"
        
        log "Rollback concluído"
    fi
}

# Função para verificar integridade
verify_upgrade() {
    log "Verificando integridade..."
    
    # Verifica serviços
    if ! systemctl is-active --quiet "$SERVICE_NAME"; then
        return 1
    fi
    
    # Testa aplicação
    if ! curl -f http://localhost:5000/api/health &>/dev/null; then
        return 1
    fi
    
    # Testa banco
    set -a
    source "$INSTALL_DIR/.env"
    set +a
    if ! PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" -c "SELECT 1;" &>/dev/null; then
        return 1
    fi
    
    return 0
}

# Função principal
main() {
    echo
    log "SamurEye - Upgrade Automático v1.0"
    log "=================================="
    
    check_root
    check_installation
    check_updates
    
    read -p "Continuar com upgrade? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
    
    # Executa upgrade com fallback para rollback
    if ! (
        create_backup
        stop_services
        update_code
        update_dependencies
        build_application
        run_migrations
        start_services
        verify_upgrade
    ); then
        rollback
        error "Upgrade falhou - rollback executado"
        exit 1
    fi
    
    # Limpeza
    rm -f "$TEMP_DIR/upgrade_info"
    
    log "Upgrade concluído com sucesso!"
    log "Nova versão: $(cd $INSTALL_DIR && git rev-parse --short HEAD)"
}

# Executa upgrade
main "$@"