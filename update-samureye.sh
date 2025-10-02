#!/bin/bash

# SamurEye - Adversarial Exposure Validation Platform
# Script de Atualização Segura (Sem Reset do Banco de Dados)
# Versão: 1.0.0
#
# USAGE:
#   sudo ./update-samureye.sh              # Atualização padrão do repositório GitHub
#   sudo SKIP_BACKUP=true ./update-samureye.sh  # Pula backup (use com cautela)

set -euo pipefail

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variáveis de configuração (baseadas no install.sh)
INSTALL_DIR="${INSTALL_DIR:-/opt/samureye}"
SERVICE_USER="${SERVICE_USER:-samureye}"
SERVICE_GROUP="${SERVICE_GROUP:-samureye}"
SERVICE_NAME="${SERVICE_NAME:-samureye-api}"
BACKUP_DIR="$INSTALL_DIR/backups"
TEMP_DIR="$INSTALL_DIR/temp"
SKIP_BACKUP="${SKIP_BACKUP:-false}"
REPO_URL="${REPO_URL:-https://github.com/GruppenIT/SamurEyePlatform.git}"
BRANCH="${BRANCH:-main}"

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

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
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
    log "Verificando instalação existente..."
    
    if [[ ! -d "$INSTALL_DIR" ]]; then
        error "SamurEye não está instalado em $INSTALL_DIR"
        error "Execute o install.sh primeiro"
        exit 1
    fi
    
    if [[ ! -f "$INSTALL_DIR/.env" ]]; then
        error "Arquivo de configuração não encontrado: $INSTALL_DIR/.env"
        exit 1
    fi
    
    if [[ ! -d "$INSTALL_DIR/.git" ]]; then
        error "Repositório Git não encontrado em $INSTALL_DIR"
        error "A instalação pode estar corrompida"
        exit 1
    fi
    
    success "Instalação verificada em $INSTALL_DIR"
}

# Função para verificar atualizações disponíveis
check_updates() {
    log "Verificando atualizações disponíveis no GitHub..."
    cd "$INSTALL_DIR"
    
    # Configura upstream se não estiver configurado
    if ! git rev-parse --abbrev-ref @{u} &>/dev/null; then
        log "Configurando upstream..."
        git remote set-url origin "$REPO_URL" 2>/dev/null || true
        git branch --set-upstream-to=origin/$BRANCH $BRANCH 2>/dev/null || \
        git branch --set-upstream-to=origin/$BRANCH 2>/dev/null || true
    fi
    
    # Fetch do repositório remoto
    git fetch origin $BRANCH
    
    LOCAL=$(git rev-parse @)
    REMOTE=$(git rev-parse origin/$BRANCH)
    
    log "Versão local:  $(git rev-parse --short $LOCAL) - $(git log -1 --format=%s $LOCAL)"
    log "Versão remota: $(git rev-parse --short $REMOTE) - $(git log -1 --format=%s $REMOTE)"
    
    if [[ $LOCAL == $REMOTE ]]; then
        success "Sistema já está na versão mais recente!"
        echo
        read -p "Deseja forçar atualização mesmo assim? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log "Atualização cancelada pelo usuário"
            exit 0
        fi
    else
        warn "Novas atualizações disponíveis:"
        echo
        git log --oneline --decorate --graph $LOCAL..$REMOTE | head -n 10
        echo
    fi
}

# Função para criar backup completo pré-atualização
create_backup() {
    if [[ "$SKIP_BACKUP" == "true" ]]; then
        warn "⚠️  BACKUP DESABILITADO - Pulando backup (não recomendado)"
        return 0
    fi
    
    log "Criando backup de segurança..."
    local TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    local DB_BACKUP="$BACKUP_DIR/pre_update_db_$TIMESTAMP.sql"
    local CODE_BACKUP="$BACKUP_DIR/pre_update_code_$TIMESTAMP.tar.gz"
    
    # Cria diretórios se não existirem
    mkdir -p "$BACKUP_DIR" "$TEMP_DIR"
    
    # Carrega variáveis de ambiente
    if [[ -f "$INSTALL_DIR/.env" ]]; then
        set -a
        source "$INSTALL_DIR/.env"
        set +a
    else
        error "Arquivo .env não encontrado"
        exit 1
    fi
    
    # 1. Backup do banco de dados
    log "📦 Fazendo backup do banco de dados PostgreSQL..."
    if PGPASSWORD="$PGPASSWORD" pg_dump -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" > "$DB_BACKUP" 2>/dev/null; then
        success "Backup do banco: $DB_BACKUP ($(du -h "$DB_BACKUP" | cut -f1))"
    else
        error "Falha ao criar backup do banco de dados"
        exit 1
    fi
    
    # 2. Backup do código fonte (excluindo node_modules e dist)
    log "📦 Fazendo backup do código fonte..."
    cd "$INSTALL_DIR"
    if tar --exclude='node_modules' --exclude='dist' --exclude='logs' --exclude='temp' \
        -czf "$CODE_BACKUP" . 2>/dev/null; then
        success "Backup do código: $CODE_BACKUP ($(du -h "$CODE_BACKUP" | cut -f1))"
    else
        warn "Falha ao criar backup do código (não crítico)"
    fi
    
    # 3. Salva informações para rollback
    cat > "$TEMP_DIR/update_info_$TIMESTAMP" <<EOF
DB_BACKUP_FILE="$DB_BACKUP"
CODE_BACKUP_FILE="$CODE_BACKUP"
PREVIOUS_COMMIT="$(git rev-parse HEAD)"
UPDATE_TIMESTAMP="$TIMESTAMP"
UPDATE_DATE="$(date)"
EOF
    
    success "✅ Backup completo criado com sucesso!"
    echo "   📁 Banco de dados: $DB_BACKUP"
    echo "   📁 Código fonte: $CODE_BACKUP"
    echo "   📝 Info de rollback: $TEMP_DIR/update_info_$TIMESTAMP"
    echo
}

# Função para parar serviços
stop_services() {
    log "Parando serviço $SERVICE_NAME..."
    
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl stop "$SERVICE_NAME"
        sleep 3
        
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            error "Falha ao parar o serviço $SERVICE_NAME"
            return 1
        fi
        success "Serviço parado com sucesso"
    else
        warn "Serviço $SERVICE_NAME não estava rodando"
    fi
}

# Função para atualizar código do GitHub
update_code() {
    log "Atualizando código do repositório GitHub..."
    cd "$INSTALL_DIR"
    
    # Salva mudanças locais se houver (stash)
    if ! git diff --quiet || ! git diff --cached --quiet; then
        warn "Existem alterações locais não commitadas"
        log "Salvando alterações locais em stash..."
        git stash push -m "Auto-stash antes de update em $(date +%Y-%m-%d_%H:%M:%S)"
    fi
    
    # Pull do repositório remoto
    log "Baixando atualizações do branch $BRANCH..."
    if git pull origin $BRANCH; then
        local NEW_VERSION=$(git rev-parse --short HEAD)
        success "Código atualizado para versão: $NEW_VERSION"
        log "Último commit: $(git log -1 --format=%s)"
    else
        error "Falha ao atualizar código do repositório"
        exit 1
    fi
}

# Função para atualizar dependências Node.js
update_dependencies() {
    log "Atualizando dependências Node.js..."
    cd "$INSTALL_DIR"
    
    # Remove node_modules antigos para instalação limpa
    log "Limpando instalação anterior..."
    rm -rf node_modules package-lock.json
    
    # Instala dependências
    log "Instalando dependências (isso pode demorar alguns minutos)..."
    if npm install --production=false 2>&1 | tee /tmp/npm_install.log; then
        success "Dependências instaladas com sucesso"
    else
        error "Falha ao instalar dependências"
        cat /tmp/npm_install.log
        exit 1
    fi
    
    # Verifica driver PostgreSQL correto
    if npm list pg > /dev/null 2>&1; then
        success "Driver PostgreSQL (pg) verificado"
    else
        warn "Driver PostgreSQL pode estar incorreto"
        log "Instalando driver PostgreSQL correto..."
        npm uninstall @neondatabase/serverless 2>/dev/null || true
        npm install pg @types/pg
    fi
}

# Função para compilar aplicação
build_application() {
    log "Compilando aplicação TypeScript..."
    cd "$INSTALL_DIR"
    
    # Remove build anterior
    rm -rf dist/
    
    # Compila aplicação
    if npm run build 2>&1 | tee /tmp/npm_build.log; then
        if [[ -f "dist/index.js" ]]; then
            success "Build concluído com sucesso"
            log "Arquivo principal: dist/index.js ($(du -h dist/index.js | cut -f1))"
        else
            error "Build falhou - arquivo dist/index.js não foi criado"
            cat /tmp/npm_build.log
            exit 1
        fi
    else
        error "Falha na compilação da aplicação"
        cat /tmp/npm_build.log
        exit 1
    fi
}

# Função para executar migrações do banco de dados
run_migrations() {
    log "Executando migrações do banco de dados..."
    cd "$INSTALL_DIR"
    
    # Carrega variáveis de ambiente
    set -a
    source "$INSTALL_DIR/.env"
    set +a
    
    # Executa migrações com usuário correto
    log "Aplicando schema changes (npm run db:push)..."
    
    if sudo -u "$SERVICE_USER" \
        DATABASE_URL="$DATABASE_URL" \
        PGHOST="$PGHOST" \
        PGPORT="$PGPORT" \
        PGUSER="$PGUSER" \
        PGPASSWORD="$PGPASSWORD" \
        PGDATABASE="$PGDATABASE" \
        npm run db:push 2>&1 | tee /tmp/db_push.log; then
        success "Migrações aplicadas com sucesso"
    else
        warn "db:push apresentou avisos ou erros"
        
        # Se falhar, tenta com --force (somente se necessário)
        read -p "Forçar aplicação das migrações? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log "Forçando migrações com --force..."
            sudo -u "$SERVICE_USER" \
                DATABASE_URL="$DATABASE_URL" \
                npm run db:push -- --force 2>&1 | tee /tmp/db_push_force.log
        else
            error "Migrações não foram aplicadas"
            exit 1
        fi
    fi
}

# Função para iniciar serviços
start_services() {
    log "Iniciando serviço $SERVICE_NAME..."
    
    systemctl start "$SERVICE_NAME"
    sleep 5
    
    # Verifica se o serviço iniciou
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        success "Serviço iniciado com sucesso"
    else
        error "Falha ao iniciar o serviço"
        log "Exibindo logs do serviço:"
        journalctl -u "$SERVICE_NAME" -n 50 --no-pager
        return 1
    fi
    
    # Aguarda aplicação responder
    log "Aguardando aplicação responder (timeout: 60s)..."
    for i in {1..30}; do
        if curl -f http://localhost:5000/api/health &>/dev/null; then
            success "Aplicação respondendo corretamente em http://localhost:5000"
            return 0
        fi
        echo -n "."
        sleep 2
    done
    
    echo
    error "Aplicação não está respondendo após 60 segundos"
    log "Verificando logs:"
    journalctl -u "$SERVICE_NAME" -n 30 --no-pager
    return 1
}

# Função para verificar integridade pós-atualização
verify_update() {
    log "Verificando integridade da atualização..."
    
    local ERRORS=0
    
    # 1. Verifica serviço systemd
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        success "✅ Serviço $SERVICE_NAME está ativo"
    else
        error "❌ Serviço $SERVICE_NAME não está ativo"
        ((ERRORS++))
    fi
    
    # 2. Verifica API HTTP
    if curl -f http://localhost:5000/api/health &>/dev/null; then
        success "✅ API respondendo em http://localhost:5000/api/health"
    else
        error "❌ API não está respondendo"
        ((ERRORS++))
    fi
    
    # 3. Verifica conexão com banco de dados
    set -a
    source "$INSTALL_DIR/.env"
    set +a
    
    if PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" -c "SELECT 1;" &>/dev/null; then
        success "✅ Conexão com banco de dados OK"
    else
        error "❌ Falha na conexão com banco de dados"
        ((ERRORS++))
    fi
    
    # 4. Verifica arquivos essenciais
    if [[ -f "$INSTALL_DIR/dist/index.js" ]] && [[ -f "$INSTALL_DIR/.env" ]]; then
        success "✅ Arquivos essenciais presentes"
    else
        error "❌ Arquivos essenciais faltando"
        ((ERRORS++))
    fi
    
    if [[ $ERRORS -eq 0 ]]; then
        success "✅ Todos os testes de integridade passaram!"
        return 0
    else
        error "❌ $ERRORS teste(s) falharam"
        return 1
    fi
}

# Função para rollback em caso de falha
rollback() {
    error "⚠️  EXECUTANDO ROLLBACK..."
    
    # Procura arquivo de info mais recente
    local INFO_FILE=$(ls -t $TEMP_DIR/update_info_* 2>/dev/null | head -1)
    
    if [[ -z "$INFO_FILE" || ! -f "$INFO_FILE" ]]; then
        error "Arquivo de informações de rollback não encontrado"
        error "Rollback manual necessário"
        return 1
    fi
    
    log "Carregando informações de rollback: $INFO_FILE"
    source "$INFO_FILE"
    
    cd "$INSTALL_DIR"
    
    # 1. Restaura código anterior
    if [[ -n "$PREVIOUS_COMMIT" ]]; then
        log "Restaurando código para commit: $PREVIOUS_COMMIT"
        git reset --hard "$PREVIOUS_COMMIT"
        npm install --production=false
        npm run build
    fi
    
    # 2. Restaura banco de dados
    if [[ -f "$DB_BACKUP_FILE" ]]; then
        log "Restaurando banco de dados: $DB_BACKUP_FILE"
        set -a
        source "$INSTALL_DIR/.env"
        set +a
        
        PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" < "$DB_BACKUP_FILE"
    fi
    
    # 3. Reinicia serviços
    log "Reiniciando serviços..."
    systemctl start "$SERVICE_NAME"
    sleep 5
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        success "Rollback concluído - serviço restaurado"
    else
        error "Rollback concluído mas serviço não iniciou"
        error "Verificação manual necessária"
    fi
}

# Função para exibir resumo final
show_summary() {
    echo
    echo "=========================================="
    log "📊 RESUMO DA ATUALIZAÇÃO"
    echo "=========================================="
    echo
    
    cd "$INSTALL_DIR"
    
    log "🔹 Versão instalada: $(git rev-parse --short HEAD)"
    log "🔹 Branch: $(git rev-parse --abbrev-ref HEAD)"
    log "🔹 Último commit: $(git log -1 --format=%s)"
    log "🔹 Data do commit: $(git log -1 --format=%cd --date=format:'%d/%m/%Y %H:%M')"
    
    echo
    log "🔹 Diretório: $INSTALL_DIR"
    log "🔹 Serviço: $SERVICE_NAME"
    log "🔹 Status: $(systemctl is-active $SERVICE_NAME 2>/dev/null || echo 'desconhecido')"
    
    echo
    log "📁 Backups salvos em: $BACKUP_DIR"
    
    if [[ -d "$BACKUP_DIR" ]]; then
        log "   $(ls -lh $BACKUP_DIR/pre_update_* 2>/dev/null | tail -2 | awk '{print $9" ("$5")"}')"
    fi
    
    echo
    success "✅ Atualização concluída com sucesso!"
    echo
    log "🔍 Para verificar logs: journalctl -u $SERVICE_NAME -f"
    log "🔍 Para acessar: http://localhost:5000"
    echo "=========================================="
    echo
}

# Função principal
main() {
    echo
    echo "=========================================="
    log "🛡️  SamurEye - Atualização Segura v1.0"
    echo "=========================================="
    log "⚠️  Esta atualização NÃO reseta o banco de dados"
    log "⚠️  Todos os dados serão preservados"
    echo "=========================================="
    echo
    
    # Verificações iniciais
    check_root
    check_installation
    check_updates
    
    # Confirmação do usuário
    echo
    warn "⚠️  O serviço será parado temporariamente durante a atualização"
    read -p "Continuar com a atualização? (y/N): " -n 1 -r
    echo
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "Atualização cancelada pelo usuário"
        exit 0
    fi
    
    # Executa atualização com proteção de rollback
    if ! (
        create_backup &&
        stop_services &&
        update_code &&
        update_dependencies &&
        build_application &&
        run_migrations &&
        start_services &&
        verify_update
    ); then
        error "❌ Atualização falhou!"
        echo
        read -p "Executar rollback automático? (Y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            rollback
        fi
        error "Atualização não foi concluída"
        exit 1
    fi
    
    # Limpeza e resumo
    log "Limpando arquivos temporários..."
    rm -f /tmp/npm_install.log /tmp/npm_build.log /tmp/db_push.log /tmp/db_push_force.log 2>/dev/null || true
    
    show_summary
}

# Tratamento de sinais (Ctrl+C)
trap 'error "Atualização interrompida pelo usuário"; exit 130' INT TERM

# Executa atualização
main "$@"
    