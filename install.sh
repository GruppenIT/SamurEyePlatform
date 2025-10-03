#!/bin/bash

# SamurEye - Adversarial Exposure Validation Platform
# Script de Instalação Automática para Ubuntu 20.04+
# Versão: 1.0.0
#
# USAGE:
#   sudo ./install.sh                    # Instalação padrão não-interativa
#   sudo NONINTERACTIVE=false ./install.sh   # Instalação interativa (deprecated)
#   sudo INSTALL_DIR=/custom/path ./install.sh # Diretório customizado
#
# VARIABLES:
#   INSTALL_DIR     - Diretório de instalação (padrão: /opt/samureye)
#   SERVICE_USER    - Usuário do serviço (padrão: samureye)
#   SERVICE_GROUP   - Grupo do serviço (padrão: samureye)
#   DB_NAME         - Nome do banco (padrão: samureye_db)
#   DB_USER         - Usuário do banco (padrão: samureye)
#   REPO_URL        - URL do repositório (padrão: https://github.com/GruppenIT/SamurEyePlatform.git)
#   NODE_VERSION    - Versão Node.js (padrão: 20)
#   NONINTERACTIVE  - Modo não-interativo (padrão: true)

set -Eeuo pipefail

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variáveis de configuração
INSTALL_DIR="${INSTALL_DIR:-/opt/samureye}"
SERVICE_USER="${SERVICE_USER:-samureye}"
SERVICE_GROUP="${SERVICE_GROUP:-samureye}"
SERVICE_NAME="${SERVICE_NAME:-samureye-api}"
DB_NAME="${DB_NAME:-samureye_db}"
DB_USER="${DB_USER:-samureye}"
REPO_URL="${REPO_URL:-https://github.com/GruppenIT/SamurEyePlatform.git}"
BRANCH="${BRANCH:-main}"
NODE_VERSION="${NODE_VERSION:-20}"
NONINTERACTIVE="${NONINTERACTIVE:-true}"

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

# Função para detectar distribuição
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    else
        error "Não foi possível detectar a distribuição do sistema"
        exit 1
    fi
    
    if [[ "$DISTRO" != "ubuntu" ]]; then
        error "Este script foi projetado para Ubuntu. Distribuição detectada: $DISTRO"
        exit 1
    fi
    
    log "Distribuição detectada: $DISTRO $VERSION"
}

# Função para instalar dependências do sistema
install_system_deps() {
    log "Atualizando repositórios do sistema..."
    apt update && apt upgrade -y

    log "Instalando dependências básicas do sistema..."
    apt install -y \
        curl \
        wget \
        git \
        unzip \
        build-essential \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        gnupg \
        lsb-release \
        ufw \
        htop \
        tree \
        jq \
        openssl \
        net-tools \
        python3

    log "Dependências básicas instaladas com sucesso"
}

# Função para instalar Node.js
install_nodejs() {
    log "Instalando Node.js $NODE_VERSION..."
    
    # Remove instalações antigas do Node.js
    apt remove -y nodejs npm || true
    
    # Instala Node.js via NodeSource
    curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash -
    apt install -y nodejs
    
    # Verifica instalação
    node_version=$(node --version)
    npm_version=$(npm --version)
    log "Node.js $node_version e npm $npm_version instalados com sucesso"
}

# Função para instalar PostgreSQL
install_postgresql() {
    log "Instalando PostgreSQL..."
    
    # Instala PostgreSQL
    apt install -y postgresql postgresql-contrib postgresql-client
    
    # Inicia e habilita PostgreSQL
    systemctl start postgresql
    systemctl enable postgresql
    
    log "PostgreSQL instalado e iniciado com sucesso"
}

# Função para configurar banco de dados (HARD RESET - sempre recria)
setup_database() {
    log "🔄 HARD RESET: Recriando banco de dados PostgreSQL..."
    
    # ⚠️ HARD RESET: Remove completamente banco e usuário existentes
    log "☢️ HARD RESET RADICAL: Removendo banco e usuário com método direto..."
    
    # Para PostgreSQL temporariamente para limpeza total
    systemctl stop postgresql 2>/dev/null || true
    sleep 2
    systemctl start postgresql 2>/dev/null || true
    sleep 3
    
    # Termina conexões ativas primeiro
    sudo -u postgres psql -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '$DB_USER' AND pid <> pg_backend_pid();" 2>/dev/null || true
    
    # Remove banco e usuário (comandos separados - método correto)
    sudo -u postgres psql -c "DROP DATABASE IF EXISTS $DB_NAME;" 2>/dev/null || true
    sudo -u postgres psql -c "DROP ROLE IF EXISTS $DB_USER;" 2>/dev/null || true
    
    
    # Verificação final simples
    USER_CHECK=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER';" 2>/dev/null || echo "")
    if [[ -z "$USER_CHECK" ]]; then
        log "✅ Usuário $DB_USER removido com sucesso"
    else
        log "⚠️ Usuário ainda existe, mas prosseguindo (será recriado)"
    fi
    
    # Gera nova senha aleatória para o usuário do banco
    DB_PASSWORD=$(openssl rand -base64 32)
    
    log "👤 Criando novo usuário do banco de dados..."
    # Cria role/usuário com privilégios mínimos necessários
    sudo -u postgres psql -c "CREATE ROLE $DB_USER WITH LOGIN CREATEDB ENCRYPTED PASSWORD '$DB_PASSWORD';"
    
    log "🏗️ Criando novo banco de dados..."
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"
    
    # Remove privilégio CREATEDB após criação do banco (least privilege) 
    log "🔒 Removendo privilégio CREATEDB desnecessário..."
    sudo -u postgres psql -c "ALTER ROLE $DB_USER NOCREATEDB;" 2>/dev/null || true
    
    # Instala extensão pgcrypto necessária para gen_random_uuid()
    log "🔧 Instalando extensões necessárias..."
    sudo -u postgres psql -d "$DB_NAME" -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;" || true
    
    # Testa conexão e verifica estrutura final
    log "🔍 Verificando estrutura final do banco..."
    if sudo -u postgres psql -d $DB_NAME -c "SELECT version();" > /dev/null 2>&1; then
        # Verifica se usuário foi criado corretamente
        USER_FINAL_CHECK=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER' AND rolcanlogin=true;" 2>/dev/null || echo "")
        if [[ -z "$USER_FINAL_CHECK" ]]; then
            error "❌ Usuário $DB_USER não foi criado corretamente"
            exit 1
        fi
        
        # Verifica se banco foi criado corretamente  
        DB_FINAL_CHECK=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME';" 2>/dev/null || echo "")
        if [[ -z "$DB_FINAL_CHECK" ]]; then
            error "❌ Banco $DB_NAME não foi criado corretamente"
            exit 1
        fi
        
        log "✅ HARD RESET concluído com sucesso"
        log "✅ Banco de dados: $DB_NAME criado"
        log "✅ Usuário do banco: $DB_USER criado"
        log "🔑 Nova senha do banco gerada"
        log "🔧 Extensão pgcrypto instalada"
    else
        error "❌ Falha ao recriar o banco de dados"
        error "❌ Não foi possível conectar ao banco $DB_NAME"
        exit 1
    fi
}

# Função para instalar Nginx
install_nginx() {
    log "Instalando Nginx..."
    
    apt install -y nginx
    
    # Inicia e habilita Nginx
    systemctl start nginx
    systemctl enable nginx
    
    # Remove configuração padrão
    rm -f /etc/nginx/sites-enabled/default
    
    log "Nginx instalado com sucesso"
}

# Função para instalar ferramentas de segurança
install_security_tools() {
    log "Instalando ferramentas de segurança..."
    
    # Instala nmap
    apt install -y nmap
    
    # Instala nuclei via Go (mais seguro que download direto)
    if ! command -v nuclei &> /dev/null; then
        log "Instalando nuclei..."
        
        # Verifica se Go está disponível ou instala
        if ! command -v go &> /dev/null; then
            # Tenta instalar via snap primeiro
            if command -v snap &> /dev/null; then
                snap install go --classic
            else
                # Fallback para apt se snap não estiver disponível
                log "Snapd não disponível, instalando Go via apt..."
                apt install -y golang-go
            fi
        fi
        
        # Verifica se Go foi instalado corretamente
        if ! command -v go &> /dev/null; then
            warn "Não foi possível instalar Go. Nuclei será ignorado."
            warn "Instale manualmente: https://github.com/projectdiscovery/nuclei"
        else
            # Instala nuclei via Go
            GOPATH="/tmp/go" go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
            if [[ -f "/tmp/go/bin/nuclei" ]]; then
                mv /tmp/go/bin/nuclei /usr/local/bin/
                chmod +x /usr/local/bin/nuclei
                log "Nuclei instalado com sucesso"
                
                # Atualiza templates do nuclei
                nuclei -update-templates -silent
            else
                warn "Falha na instalação do nuclei via Go"
            fi
            rm -rf /tmp/go
        fi
    fi
    
    # Instala smbclient e ferramentas LDAP
    apt install -y smbclient ldap-utils
    
    # Instala PowerShell Core (necessário para AD Security via WinRM)
    log "Configurando PowerShell Core com suporte WSMan..."
    
    # Remove PowerShell via snap se existir (snap não inclui WSMan)
    if snap list 2>/dev/null | grep -q powershell; then
        warn "Removendo PowerShell instalado via snap (sem suporte WSMan)..."
        snap remove powershell --purge || true
        rm -f /usr/bin/pwsh 2>/dev/null || true
    fi
    
    # Detecta versão do Ubuntu
    UBUNTU_VERSION=$(lsb_release -rs)
    UBUNTU_CODENAME=$(lsb_release -cs)
    
    # Instala PowerShell via repositório oficial da Microsoft (com WSMan)
    if ! command -v pwsh &> /dev/null; then
        log "Instalando PowerShell via repositório Microsoft..."
        
        # Instala dependências necessárias para WSMan
        log "Instalando dependências WSMan..."
        apt install -y libssl-dev libpam0g-dev
        
        # Download e instalação do pacote Microsoft
        wget -q "https://packages.microsoft.com/config/ubuntu/${UBUNTU_VERSION}/packages-microsoft-prod.deb" -O /tmp/packages-microsoft-prod.deb
        dpkg -i /tmp/packages-microsoft-prod.deb
        rm -f /tmp/packages-microsoft-prod.deb
        
        # Atualiza repositórios e instala PowerShell
        apt update
        apt install -y powershell
        
        # Verifica se PowerShell foi instalado corretamente
        if command -v pwsh &> /dev/null; then
            PWSH_VERSION=$(pwsh --version)
            log "✅ PowerShell instalado com sucesso: $PWSH_VERSION"
            
            # Testa suporte WSMan
            log "Verificando suporte WSMan..."
            WSMAN_TEST=$(pwsh -NoProfile -Command "Get-Command New-PSSession -ErrorAction SilentlyContinue" 2>&1 || echo "FAIL")
            if [[ "$WSMAN_TEST" != "FAIL" ]]; then
                log "✅ Suporte WSMan verificado com sucesso"
            else
                warn "⚠️ WSMan pode não estar disponível, mas prosseguindo..."
            fi
        else
            error "❌ Falha ao instalar PowerShell Core"
            error "❌ A jornada AD Security não funcionará sem PowerShell"
            error "❌ Instale manualmente: https://learn.microsoft.com/powershell/scripting/install/install-ubuntu"
            exit 1
        fi
    else
        # PowerShell já instalado - verifica se é via snap
        PWSH_PATH=$(which pwsh)
        if [[ "$PWSH_PATH" == *"/snap/"* ]]; then
            warn "PowerShell instalado via snap detectado - removendo para instalar versão com WSMan..."
            snap remove powershell --purge || true
            rm -f /usr/bin/pwsh 2>/dev/null || true
            
            # Reinstala via repositório Microsoft
            log "Instalando dependências WSMan..."
            apt install -y libssl-dev libpam0g-dev
            
            wget -q "https://packages.microsoft.com/config/ubuntu/${UBUNTU_VERSION}/packages-microsoft-prod.deb" -O /tmp/packages-microsoft-prod.deb
            dpkg -i /tmp/packages-microsoft-prod.deb
            rm -f /tmp/packages-microsoft-prod.deb
            
            apt update
            apt install -y powershell
            
            PWSH_VERSION=$(pwsh --version)
            log "✅ PowerShell reinstalado com sucesso: $PWSH_VERSION"
        else
            PWSH_VERSION=$(pwsh --version)
            log "PowerShell já instalado (repositório Microsoft): $PWSH_VERSION"
        fi
    fi
    
    log "Ferramentas de segurança instaladas com sucesso"
}

# Função para criar usuário do sistema
create_system_user() {
    log "Configurando usuário do sistema..."
    
    # Criar grupo se não existir
    if ! getent group "$SERVICE_GROUP" &>/dev/null; then
        log "Criando grupo $SERVICE_GROUP..."
        groupadd -r "$SERVICE_GROUP"
    fi
    
    # Criar usuário se não existir
    if ! id "$SERVICE_USER" &>/dev/null; then
        log "Criando usuário $SERVICE_USER..."
        useradd -r -s /bin/false -d "$INSTALL_DIR" -g "$SERVICE_GROUP" "$SERVICE_USER"
    else
        log "Usuário $SERVICE_USER já existe"
    fi
    
    # Criar diretório de instalação
    mkdir -p "$INSTALL_DIR"
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
}

# Função para configurar firewall
setup_firewall() {
    log "Configurando firewall UFW..."
    
    # Detecta porta SSH atual com fallback para porta padrão
    SSH_PORT=$(ss -tlnp | grep sshd | awk '{print $4}' | cut -d: -f2 | head -1)
    if [[ -z "$SSH_PORT" ]]; then
        SSH_PORT="22"
        warn "Não foi possível detectar porta SSH, usando padrão: 22"
    else
        log "Porta SSH detectada: $SSH_PORT"
    fi
    
    # Configurar de forma não-interativa se NONINTERACTIVE=true
    if [[ "$NONINTERACTIVE" == "true" ]]; then
        log "Configurando firewall automaticamente (modo não-interativo):"
        log "- SSH permitido na porta $SSH_PORT"
        log "- HTTP (80) e HTTPS (443) permitidos"  
        log "- Aplicação (5000) bloqueada externamente"
    else
        # Confirmação antes de habilitar firewall
        warn "O firewall será configurado com as seguintes regras:"
        warn "- SSH permitido na porta $SSH_PORT"
        warn "- HTTP (80) e HTTPS (443) permitidos"
        warn "- Aplicação (5000) bloqueada externamente"
        
        read -p "Continuar com configuração do firewall? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            warn "Configuração do firewall ignorada"
            return 0
        fi
    fi
    
    # Configura UFW
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow $SSH_PORT/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw deny 5000/tcp
    ufw --force enable
    
    log "Firewall configurado com sucesso"
}

# Função para baixar e instalar aplicação
install_application() {
    log "Baixando e instalando aplicação SamurEye..."
    
    # Hard reset - remove diretório existente se houver
    if [[ -d "$INSTALL_DIR" ]]; then
        # Verificações de segurança antes do rm -rf
        if [[ -z "$INSTALL_DIR" || "$INSTALL_DIR" == "/" || "$INSTALL_DIR" == "/opt" ]]; then
            error "INSTALL_DIR inválido ou perigoso: $INSTALL_DIR"
            exit 1
        fi
        
        # Verifica se é um caminho seguro do SamurEye
        if [[ ! "$INSTALL_DIR" =~ ^/opt/samureye ]]; then
            error "INSTALL_DIR deve estar em /opt/samureye: $INSTALL_DIR"
            exit 1
        fi
        
        # Para o serviço se estiver rodando
        log "Parando serviços existentes..."
        systemctl stop ${SERVICE_NAME} || true
        systemctl disable ${SERVICE_NAME} || true
        
        # Preserva backups existentes se houverem
        local temp_backup_dir=""
        if [[ -d "$INSTALL_DIR/backups" ]]; then
            temp_backup_dir="/tmp/samureye_backups_$(date +%s)"
            log "Preservando backups existentes..."
            mv "$INSTALL_DIR/backups" "$temp_backup_dir" || true
        fi
        
        log "Removendo instalação anterior..."
        rm -rf "$INSTALL_DIR"
    fi
    
    # Cria diretório de instalação limpo
    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    
    # Clone limpo do repositório sempre
    log "Clonando repositório..."
    git clone -b "$BRANCH" "$REPO_URL" .
    
    # Restaura backups preservados se houverem
    if [[ -n "$temp_backup_dir" && -d "$temp_backup_dir" ]]; then
        log "Restaurando backups preservados..."
        rm -rf "$INSTALL_DIR/backups" 2>/dev/null || true
        mv "$temp_backup_dir" "$INSTALL_DIR/backups" || true
    fi
    
    # Instala dependências Node.js
    log "Instalando dependências da aplicação..."
    npm install --production=false
    
    # Aplicar correções críticas do WebSocket (PostgreSQL driver)
    log "Aplicando correções do driver de banco de dados..."
    npm uninstall @neondatabase/serverless || true
    npm install pg @types/pg
    npm dedupe && npm prune
    
    # Verificar se a correção foi aplicada
    if npm list pg > /dev/null 2>&1; then
        log "✅ Driver PostgreSQL (pg) instalado com sucesso"
    else
        error "❌ Falha ao instalar driver PostgreSQL correto"
        exit 1
    fi
    
    # Compila aplicação
    log "Compilando aplicação..."
    npm run build
    
    # Verificar se build foi bem-sucedido
    if [[ -f "dist/index.js" ]]; then
        log "✅ Build da aplicação finalizado com sucesso"
        
        # Verificar se package.json contém os scripts necessários
        if grep -q '"start".*"node.*dist/index.js"' package.json; then
            log "✅ Script de produção configurado corretamente"
        else
            warn "⚠️  Script de produção pode não estar configurado corretamente"
        fi
        
        # Verificar se as dependências corretas estão instaladas
        if [[ -d "node_modules/pg" ]]; then
            log "✅ Driver PostgreSQL (pg) disponível no node_modules"
        else
            error "❌ Driver PostgreSQL não encontrado após instalação"
            exit 1
        fi
    else
        error "❌ Falha no build da aplicação - arquivo dist/index.js não foi criado"
        exit 1
    fi
    
    # Cria diretórios necessários
    mkdir -p logs backups temp
    
    # Define permissões
    chown -R $SERVICE_USER:$SERVICE_GROUP $INSTALL_DIR
    chmod +x install.sh upgrade.sh
    
    log "Aplicação instalada com sucesso"
}

# Função para configurar variáveis de ambiente
setup_environment() {
    log "Configurando variáveis de ambiente..."
    
    # Gera chaves de criptografia
    ENCRYPTION_KEK=$(openssl rand -hex 32)
    SESSION_SECRET=$(openssl rand -base64 64 | tr -d '\n')
    
    # Cria arquivo .env
    cat > $INSTALL_DIR/.env << EOF
# Configuração do Banco de Dados
DATABASE_URL=postgresql://$DB_USER:$(echo -n "$DB_PASSWORD" | python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip(), safe=''))")@localhost:5432/$DB_NAME
PGHOST=localhost
PGPORT=5432
PGUSER=$DB_USER
PGPASSWORD=$DB_PASSWORD
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

# Configuração de Autenticação OIDC (Configure conforme necessário)
# ISSUER_URL=https://auth.replit.com
# CLIENT_ID=seu_client_id
# CLIENT_SECRET=seu_client_secret
# REDIRECT_URI=https://seu-dominio.com/auth/callback
EOF

    # Define permissões seguras
    chown $SERVICE_USER:$SERVICE_GROUP $INSTALL_DIR/.env
    chmod 600 $INSTALL_DIR/.env
    
    log "Variáveis de ambiente configuradas"
}

# Função para executar migrações do banco
run_migrations() {
    log "Executando migrações do banco de dados..."
    
    cd $INSTALL_DIR
    
    # Executa migrações usando o arquivo .env diretamente (sem source)
    # O systemd e npm lerão o arquivo automaticamente
    sudo -u $SERVICE_USER \
        DATABASE_URL="postgresql://$DB_USER:$(echo -n "$DB_PASSWORD" | python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip(), safe=''))")@localhost:5432/$DB_NAME" \
        npm run db:push
    
    log "Migrações executadas com sucesso"
}

# Função para criar usuário administrador inicial (HARD RESET - sempre recria)
create_admin_user() {
    log "🔄 HARD RESET: Criando novo usuário administrador..."
    
    cd $INSTALL_DIR
    
    # Configurações de email (pode ser personalizada via variável de ambiente)
    ADMIN_EMAIL="${ADMIN_EMAIL:-admin@samureye.com.br}"
    
    # Arquivo de credenciais (sempre recriado)
    CREDENTIALS_FILE="$INSTALL_DIR/ADMIN_CREDENTIALS"
    
    # ⚠️ HARD RESET: Remove qualquer usuário administrador existente
    log "🗑️ Removendo usuários administradores existentes..."
    PGPASSWORD="$DB_PASSWORD" psql -h localhost -U "$DB_USER" -d "$DB_NAME" \
        -c "DELETE FROM users WHERE role = 'global_administrator' OR email = '$ADMIN_EMAIL';" 2>/dev/null || true
    
    log "🆕 Criando novo usuário administrador: $ADMIN_EMAIL"
    
    # Gera senha aleatória forte (apenas alfanuméricos para evitar problemas)
    ADMIN_TEMP_PASSWORD=$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c16)
    
    # Verifica se a senha foi gerada corretamente
    if [[ -z "$ADMIN_TEMP_PASSWORD" ]] || [[ ${#ADMIN_TEMP_PASSWORD} -lt 16 ]]; then
        error "Falha ao gerar senha temporária"
        exit 1
    fi
    
    log "Senha temporária gerada: ${#ADMIN_TEMP_PASSWORD} caracteres"
    
    # Verifica se bcryptjs está disponível
    if ! node -e "require('bcryptjs')" 2>/dev/null; then
        error "Biblioteca bcryptjs não encontrada. Execute: npm install"
        exit 1
    fi
    
    # Cria hash da senha usando Node.js com mesma biblioteca da aplicação
    log "Gerando hash seguro da senha..."
    ADMIN_PASSWORD_HASH=$(node -e "
        const bcrypt = require('bcryptjs');
        const password = '$ADMIN_TEMP_PASSWORD';
        const hash = bcrypt.hashSync(password, 12);
        
        // Testa se o hash foi gerado corretamente
        const isValid = bcrypt.compareSync(password, hash);
        if (!isValid) {
            console.error('ERRO: Hash gerado não confere com a senha!');
            process.exit(1);
        }
        
        console.log(hash);
    " 2>/dev/null)
    
    if [[ -z "$ADMIN_PASSWORD_HASH" ]]; then
        error "Falha ao gerar hash da senha"
        exit 1
    fi
    
    log "Hash gerado com ${#ADMIN_PASSWORD_HASH} caracteres"
    
    # Insere novo usuário administrador (simples INSERT após limpeza)
    log "👤 Inserindo novo usuário administrador no banco..."
    
    # Debug: mostra informações antes da inserção
    log "🔍 Email: $ADMIN_EMAIL"
    log "🔍 Hash length: ${#ADMIN_PASSWORD_HASH}"
    
    INSERT_RESULT=$(PGPASSWORD="$DB_PASSWORD" psql -h localhost -U "$DB_USER" -d "$DB_NAME" -c "
        INSERT INTO users (email, password_hash, first_name, last_name, role, must_change_password)
        VALUES (\$\$${ADMIN_EMAIL}\$\$, \$\$${ADMIN_PASSWORD_HASH}\$\$, 'Administrador', 'SamurEye', 'global_administrator'::user_role, true)
        ON CONFLICT (email) DO UPDATE SET
            password_hash = EXCLUDED.password_hash,
            first_name = EXCLUDED.first_name,
            last_name = EXCLUDED.last_name,
            role = 'global_administrator'::user_role,
            must_change_password = true;
        " 2>&1)
    
    if [[ $? -ne 0 ]]; then
        error "Falha ao inserir usuário administrador"
        error "Erro SQL: $INSERT_RESULT"
        
        # Debug adicional: verifica se tabela existe
        log "🔍 Verificando estrutura da tabela users..."
        PGPASSWORD="$DB_PASSWORD" psql -h localhost -U "$DB_USER" -d "$DB_NAME" \
            -c "\d users" 2>&1 || true
        
        exit 1
    fi
    
    log "✅ Usuário administrador inserido no banco"
    
    # CRÍTICO: Busca o hash REAL do banco para validação
    log "🔍 Verificando credenciais contra o banco de dados..."
    
    # Debug: verificar se usuário foi realmente inserido
    USER_COUNT=$(PGPASSWORD="$DB_PASSWORD" psql -h localhost -U "$DB_USER" -d "$DB_NAME" \
        -t -A \
        -c "SELECT COUNT(*) FROM users WHERE email = \$\$${ADMIN_EMAIL}\$\$;" 2>&1)
    
    log "🔍 DEBUG: Usuários encontrados: $USER_COUNT"
    
    if [[ "$USER_COUNT" != "1" ]]; then
        error "PROBLEMA: Usuário não foi inserido corretamente (count: $USER_COUNT)"
        # Debug: mostrar todos os usuários
        log "🔍 DEBUG: Listando todos os usuários:"
        PGPASSWORD="$DB_PASSWORD" psql -h localhost -U "$DB_USER" -d "$DB_NAME" \
            -c "SELECT email, role, created_at FROM users;" 2>&1 || true
        exit 1
    fi
    
    # Buscar hash usando dollar-quoted (mesma sintaxe do INSERT)
    STORED_HASH_RESULT=$(PGPASSWORD="$DB_PASSWORD" psql -h localhost -U "$DB_USER" -d "$DB_NAME" \
        -t -A \
        -c "SELECT password_hash FROM users WHERE email = \$\$${ADMIN_EMAIL}\$\$ LIMIT 1;" 2>&1)
    
    log "🔍 DEBUG: Resultado da query hash: ${#STORED_HASH_RESULT} caracteres"
    
    # Extrair apenas o hash (remover espaços/quebras)
    STORED_HASH=$(echo "$STORED_HASH_RESULT" | tr -d ' \n\r\t')
    
    log "🔍 DEBUG: Hash limpo: ${#STORED_HASH} caracteres"
    
    if [[ -z "$STORED_HASH" ]] || [[ ${#STORED_HASH} -lt 50 ]]; then
        error "Não foi possível recuperar hash válido do usuário do banco"
        error "Hash resultado: '$STORED_HASH_RESULT'"
        error "Hash limpo: '$STORED_HASH'"
        exit 1
    fi
    
    # Testa a senha contra o hash REAL armazenado no banco
    log "🧪 Validando senha contra hash do banco de dados..."
    
    log "🔍 DEBUG: Senha para testar: '$ADMIN_TEMP_PASSWORD' (${#ADMIN_TEMP_PASSWORD} chars)"
    log "🔍 DEBUG: Hash para testar: ${#STORED_HASH} chars (${STORED_HASH:0:10}...)"
    
    DB_TEST_RESULT=$(node -e "
        try {
            const bcrypt = require('bcryptjs');
            const password = '$ADMIN_TEMP_PASSWORD';
            const storedHash = '$STORED_HASH';
            
            console.log('Password:', password);
            console.log('Hash length:', storedHash.length);
            console.log('Hash start:', storedHash.substring(0, 10));
            
            const isValid = bcrypt.compareSync(password, storedHash);
            console.log(isValid ? 'SUCESSO' : 'ERRO');
        } catch (err) {
            console.log('ERRO_NODE:', err.message);
        }
    " 2>&1)
    
    log "🔍 DEBUG: Resultado do teste bcrypt: $DB_TEST_RESULT"
    
    if [[ "$DB_TEST_RESULT" != *"SUCESSO"* ]]; then
        error "CRÍTICO: Senha não confere com hash armazenado no banco!"
        error "Resultado do teste: $DB_TEST_RESULT"
        exit 1
    fi
    
    log "✅ Validação contra banco de dados PASSOU"
    
    # Remove arquivo antigo se existir
    [[ -f "$CREDENTIALS_FILE" ]] && rm -f "$CREDENTIALS_FILE"
    
    # Cria novo arquivo com credenciais válidas
    cat > "$CREDENTIALS_FILE" << EOF
===============================================
    CREDENCIAIS DO ADMINISTRADOR (HARD RESET)
===============================================

📧 Email: $ADMIN_EMAIL
🔑 Senha temporária: $ADMIN_TEMP_PASSWORD

🚨 IMPORTANTE: 
- Faça login imediatamente e altere a senha
- Remova este arquivo após o primeiro login
- Não compartilhe essas credenciais

✅ VERIFICADO: Credenciais testadas contra banco real
🔄 HARD RESET: Nova senha gerada a cada instalação  
💡 Gerado em: $(date '+%d/%m/%Y às %H:%M:%S')
===============================================
EOF
    
    # Define permissões seguras
    chown $SERVICE_USER:$SERVICE_GROUP "$CREDENTIALS_FILE"
    chmod 600 "$CREDENTIALS_FILE"
    
    log "✅ Usuário administrador CRIADO com sucesso (HARD RESET)"
    log "🆕 Novo administrador configurado no sistema"
    log "📧 Email: $ADMIN_EMAIL"
    log "📄 Credenciais salvas em: $CREDENTIALS_FILE"
    log ""
    log "🚨 IMPORTANTE: Leia o arquivo de credenciais e faça login imediatamente!"
    log ""
    log "🔒 SEGURANÇA: Execute 'rm $CREDENTIALS_FILE' após primeiro login"
}

# Função para configurar serviços systemd
setup_systemd_services() {
    log "Configurando serviços systemd..."
    
    # Serviço principal da API (inclui toda a aplicação) com graceful shutdown
    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=SamurEye API Server
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/npm run start
Restart=always
RestartSec=10

# Graceful shutdown configuration
KillSignal=SIGTERM
TimeoutStopSec=30
ExecStop=/bin/kill -s SIGTERM \$MAINPID

# Environment configuration
Environment=NODE_ENV=production
EnvironmentFile=$INSTALL_DIR/.env
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$INSTALL_DIR/logs $INSTALL_DIR/backups $INSTALL_DIR/temp /tmp
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictRealtime=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF

    # Recarrega systemd e habilita serviços
    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME}
    
    log "Serviços systemd configurados"
}

# Função para configurar Nginx reverse proxy
setup_nginx_proxy() {
    log "Configurando proxy reverso Nginx..."
    
    cat > /etc/nginx/sites-available/samureye << EOF
server {
    listen 80 default_server;
    server_name _;
    
    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    
    # Proxy Settings
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        
        # WebSocket Support
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }

    # Static files with caching
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)\$ {
        proxy_pass http://127.0.0.1:5000;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Health check endpoint
    location /health {
        proxy_pass http://127.0.0.1:5000/api/health;
        access_log off;
    }
}
EOF

    # Ativa site
    ln -sf /etc/nginx/sites-available/samureye /etc/nginx/sites-enabled/
    
    # Testa configuração
    nginx -t
    systemctl reload nginx
    
    log "Proxy reverso Nginx configurado"
}

# Função para criar scripts de backup
setup_backup_scripts() {
    log "Criando scripts de backup..."
    
    mkdir -p $INSTALL_DIR/scripts
    
    cat > $INSTALL_DIR/scripts/backup.sh << 'EOF'
#!/bin/bash
# SamurEye Backup Script

BACKUP_DIR="/opt/samureye/backups"
DATE=$(date +%Y%m%d_%H%M%S)
DB_BACKUP="$BACKUP_DIR/db_backup_$DATE.sql"
APP_BACKUP="$BACKUP_DIR/app_backup_$DATE.tar.gz"

# Carrega variáveis de ambiente
source /opt/samureye/.env

# Cria diretório de backup
mkdir -p "$BACKUP_DIR"

echo "Iniciando backup em $DATE..."

# Backup do banco de dados
echo "Fazendo backup do banco de dados..."
PGPASSWORD="$PGPASSWORD" pg_dump -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" > "$DB_BACKUP"

if [[ $? -eq 0 ]]; then
    echo "Backup do banco concluído: $DB_BACKUP"
else
    echo "ERRO: Falha no backup do banco de dados"
    exit 1
fi

# Backup dos arquivos da aplicação
echo "Fazendo backup dos arquivos da aplicação..."
tar -czf "$APP_BACKUP" --exclude=node_modules --exclude=dist --exclude=backups --exclude=.git /opt/samureye

if [[ $? -eq 0 ]]; then
    echo "Backup da aplicação concluído: $APP_BACKUP"
else
    echo "ERRO: Falha no backup da aplicação"
    exit 1
fi

# Limpeza de backups antigos (mantém últimos 7 dias)
echo "Limpando backups antigos..."
find "$BACKUP_DIR" -name "*.sql" -mtime +7 -delete
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +7 -delete

echo "Backup concluído com sucesso!"
echo "Banco: $DB_BACKUP"
echo "Aplicação: $APP_BACKUP"
EOF

    chmod +x $INSTALL_DIR/scripts/backup.sh
    chown $SERVICE_USER:$SERVICE_GROUP $INSTALL_DIR/scripts/backup.sh
    
    # Adiciona backup ao cron (diário às 2h da manhã)
    (crontab -l 2>/dev/null; echo "0 2 * * * $INSTALL_DIR/scripts/backup.sh") | crontab -
    
    log "Scripts de backup configurados"
}

# Função para iniciar serviços
start_services() {
    log "Iniciando serviços..."
    
    # Inicia serviços PostgreSQL e Nginx primeiro
    systemctl start postgresql nginx
    
    # Inicia serviços SamurEye
    systemctl start ${SERVICE_NAME}
    
    # Verifica status dos serviços
    sleep 5
    local services_ok=true
    
    for service in "${SERVICE_NAME}" "postgresql" "nginx"; do
        if systemctl is-active --quiet "$service"; then
            log "✓ Serviço $service iniciado com sucesso"
        else
            error "✗ Falha ao iniciar serviço $service"
            systemctl status "$service"
            journalctl -u "$service" --no-pager -n 20
            services_ok=false
        fi
    done
    
    if [[ "$services_ok" != "true" ]]; then
        error "Um ou mais serviços falharam ao iniciar"
        exit 1
    fi
    
    # Testa aplicação
    log "Testando resposta da aplicação..."
    for i in {1..30}; do
        if curl -f http://localhost:5000/api/health &>/dev/null; then
            log "✓ Aplicação respondendo corretamente"
            break
        fi
        if [[ $i -eq 30 ]]; then
            error "✗ Aplicação não está respondendo após 30 tentativas"
            systemctl status ${SERVICE_NAME}
            journalctl -u ${SERVICE_NAME} --no-pager -n 50
            exit 1
        fi
        sleep 2
    done
    
    # Testa Nginx
    if curl -f http://localhost/ &>/dev/null; then
        log "✓ Proxy reverso Nginx funcionando"
    else
        warn "⚠ Nginx pode não estar configurado corretamente"
    fi
}

# Função para verificar se as correções do WebSocket funcionaram
verify_websocket_fix() {
    log "Verificando se as correções do WebSocket foram aplicadas..."
    
    # Aguarda o serviço estabilizar
    sleep 10
    
    # Verifica se o serviço está ativo
    if ! systemctl is-active --quiet ${SERVICE_NAME}; then
        error "❌ Serviço ${SERVICE_NAME} não está ativo"
        return 1
    fi
    
    # Verifica logs recentes por erros de WebSocket do NeonDB
    log "Verificando logs recentes por erros de WebSocket..."
    local websocket_errors=$(journalctl -u ${SERVICE_NAME} --since "5 minutes ago" --no-pager -q | grep -c "wss://localhost/v2\|connect ECONNREFUSED.*:443\|@neondatabase/serverless.*WebSocket" || echo "0")
    
    if [[ "$websocket_errors" -gt 0 ]]; then
        error "❌ Detectados $websocket_errors erro(s) de WebSocket nos logs recentes!"
        log "Últimos erros encontrados:"
        journalctl -u ${SERVICE_NAME} --since "5 minutes ago" --no-pager -n 20 | grep -A5 -B5 "wss://localhost/v2\|connect ECONNREFUSED.*:443\|@neondatabase/serverless.*WebSocket"
        return 1
    fi
    
    # Verifica se aplicação está rodando corretamente
    local startup_success=$(journalctl -u ${SERVICE_NAME} --since "5 minutes ago" --no-pager -q | grep -c "serving on port\|express.*serving" || echo "0")
    
    if [[ "$startup_success" -eq 0 ]]; then
        warn "⚠️  Não foi encontrada mensagem de startup bem-sucedido nos logs recentes"
        log "Logs recentes do serviço:"
        journalctl -u ${SERVICE_NAME} --since "5 minutes ago" --no-pager -n 20
    else
        log "✅ Aplicação iniciou corretamente (mensagens de startup encontradas)"
    fi
    
    # Teste final de saúde da API
    local health_check_attempts=0
    local health_check_success=false
    
    while [[ $health_check_attempts -lt 10 ]]; do
        if curl -f -s http://localhost:5000/api/health &>/dev/null; then
            health_check_success=true
            break
        fi
        sleep 2
        ((health_check_attempts++))
    done
    
    if [[ "$health_check_success" == "true" ]]; then
        log "✅ API Health check passou - aplicação totalmente funcional"
    else
        error "❌ API Health check falhou - aplicação pode ter problemas"
        return 1
    fi
    
    log "✅ Verificação das correções de WebSocket PASSOU - problema resolvido!"
    return 0
}

# Função para exibir informações finais
show_final_info() {
    local server_ip=$(curl -s http://ipv4.icanhazip.com/ 2>/dev/null || echo "IP_EXTERNO_NAO_DETECTADO")
    
    echo
    log "=========================================="
    log "    INSTALAÇÃO CONCLUÍDA COM SUCESSO!"
    log "=========================================="
    echo
    log "🌐 Acesso à aplicação:"
    log "   Local: http://localhost"
    log "   Externo: http://$server_ip"
    echo
    log "📊 Status dos serviços:"
    log "   SamurEye: $(systemctl is-active ${SERVICE_NAME})"
    log "   PostgreSQL: $(systemctl is-active postgresql)"
    log "   Nginx: $(systemctl is-active nginx)"
    echo
    log "📁 Diretórios importantes:"
    log "   Aplicação: $INSTALL_DIR"
    log "   Logs: $INSTALL_DIR/logs"
    log "   Backups: $INSTALL_DIR/backups"
    log "   Configuração: $INSTALL_DIR/.env"
    echo
    log "🔧 Comandos úteis:"
    log "   Status: systemctl status ${SERVICE_NAME}"
    log "   Logs: journalctl -u ${SERVICE_NAME} -f"
    log "   Restart: systemctl restart ${SERVICE_NAME}"
    log "   Backup: $INSTALL_DIR/scripts/backup.sh"
    log "   Upgrade: cd $INSTALL_DIR && ./upgrade.sh"
    echo
    log "👤 Primeiro Acesso:"
    log "   1. Acesse a aplicação no navegador"
    log "   2. Use o usuário administrador padrão criado na instalação"
    log "   3. IMPORTANTE: Altere a senha padrão no primeiro login"
    echo
    warn "⚠️  AÇÕES NECESSÁRIAS:"
    warn "1. Configure SSL/HTTPS para produção:"
    warn "   sudo apt install certbot python3-certbot-nginx"
    warn "   sudo certbot --nginx -d seu-dominio.com"
    echo
    warn "2. Configure autenticação OIDC no arquivo:"
    warn "   $INSTALL_DIR/.env"
    echo
    warn "3. Revise configurações de firewall:"
    warn "   sudo ufw status"
    echo
    log "📖 Documentação completa: README.md"
    log "🆘 Suporte: https://github.com/GruppenIT/SamurEyePlatform/issues"
    echo
}

# Função CRÍTICA para validar e corrigir credenciais PostgreSQL
validate_and_fix_credentials() {
    log "🔍 CRÍTICO: Validando credenciais do PostgreSQL..."
    
    # Testa conexão atual usando credenciais do .env
    if ! PGPASSWORD="$DB_PASSWORD" psql -h localhost -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" > /dev/null 2>&1; then
        error "❌ FALHA: Credenciais PostgreSQL inválidas - regenerando..."
        
        # Para o serviço se estiver rodando
        systemctl stop ${SERVICE_NAME} 2>/dev/null || true
        
        # Regenera senha do usuário PostgreSQL
        NEW_DB_PASSWORD=$(openssl rand -base64 32)
        log "🔑 Regenerando senha do usuário PostgreSQL..."
        
        # Atualiza senha no PostgreSQL
        sudo -u postgres psql -c "ALTER USER $DB_USER WITH ENCRYPTED PASSWORD '$NEW_DB_PASSWORD';" || {
            error "Falha ao alterar senha do PostgreSQL"
            exit 1
        }
        
        # Atualiza variável local
        DB_PASSWORD="$NEW_DB_PASSWORD"
        
        # Regenera chaves de criptografia
        ENCRYPTION_KEK=$(openssl rand -hex 32)
        SESSION_SECRET=$(openssl rand -base64 64 | tr -d '\n')
        
        # Recria arquivo .env com credenciais corretas
        log "📝 Atualizando arquivo .env..."
        cat > $INSTALL_DIR/.env << EOF
# Configuração do Banco de Dados (CORRIGIDO)
DATABASE_URL=postgresql://$DB_USER:$(echo -n "$DB_PASSWORD" | python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip(), safe=''))")@localhost:5432/$DB_NAME
PGHOST=localhost
PGPORT=5432
PGUSER=$DB_USER
PGPASSWORD=$DB_PASSWORD
PGDATABASE=$DB_NAME

# Configuração da Aplicação
NODE_ENV=production
PORT=5000

# Chave de Criptografia (REGENERADA)
ENCRYPTION_KEK=$ENCRYPTION_KEK

# Configuração de Sessão (REGENERADA)  
SESSION_SECRET="$SESSION_SECRET"

# Configuração de Logs
LOG_LEVEL=info
EOF
        
        # Define permissões seguras
        chown $SERVICE_USER:$SERVICE_GROUP $INSTALL_DIR/.env
        chmod 600 $INSTALL_DIR/.env
        
        # Testa nova conexão
        if ! PGPASSWORD="$DB_PASSWORD" psql -h localhost -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" > /dev/null 2>&1; then
            error "❌ CRÍTICO: Credenciais ainda inválidas após correção!"
            exit 1
        fi
        
        log "✅ Credenciais PostgreSQL corrigidas com sucesso"
        
        # Força reload do systemd para ler novo .env
        log "🔄 Forçando reload do systemd para novas credenciais..."
        systemctl daemon-reload
        
    else
        log "✅ Credenciais PostgreSQL válidas"
    fi
    
    # Debug: mostra credenciais (sem senha) para verificação
    log "🔍 Configuração PostgreSQL:"
    log "   Host: localhost:5432"
    log "   Banco: $DB_NAME"
    log "   Usuário: $DB_USER"
    log "   Senha: [OCULTA - ${#DB_PASSWORD} caracteres]"
    
    # Testa DATABASE_URL específicamente
    TEST_URL="postgresql://$DB_USER:$(echo -n "$DB_PASSWORD" | python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip(), safe=''))")@localhost:5432/$DB_NAME"
    
    # Teste final com timeout
    log "🧪 Teste final de conectividade..."
    if timeout 10 node -e "
        const { Pool } = require('pg');
        const pool = new Pool({ connectionString: '$TEST_URL' });
        pool.query('SELECT version()')
            .then((result) => { 
                console.log('✅ DATABASE_URL OK - PostgreSQL conectado');
                process.exit(0); 
            })
            .catch(err => { 
                console.error('❌ DATABASE_URL ERRO:', err.message); 
                process.exit(1); 
            });
    "; then
        log "✅ DATABASE_URL validado com sucesso"
    else
        error "❌ CRÍTICO: DATABASE_URL inválido mesmo após correção"
        error "Verifique manualmente: PGPASSWORD='$DB_PASSWORD' psql -h localhost -U '$DB_USER' -d '$DB_NAME'"
        exit 1
    fi
}

# Função principal
main() {
    echo
    log "=========================================="
    log "  SamurEye - Instalação Automática v1.0"
    log "=========================================="
    echo
    
    check_root
    detect_distro
    
    log "Iniciando instalação em $(date)"
    
    # Executa etapas da instalação
    install_system_deps
    install_nodejs
    install_postgresql
    setup_database
    install_nginx
    install_security_tools
    create_system_user
    setup_firewall
    install_application
    setup_environment
    run_migrations
    create_admin_user
    setup_systemd_services
    setup_nginx_proxy
    setup_backup_scripts
    
    # ⚠️ CRÍTICO: Valida e corrige credenciais antes de iniciar serviços
    validate_and_fix_credentials
    
    start_services
    verify_websocket_fix
    
    show_final_info
    
    log "Instalação concluída em $(date)"
}

# Captura erros e limpa arquivos temporários (sem mensagem duplicada)
trap 'rm -f /tmp/db_credentials; exit 1' ERR

# Executa instalação
main "$@"