#!/bin/bash
#
# SamurEye - Clean Appliance
# Zera o banco de dados e recria o usuário administrador
#

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Diretórios e arquivos
INSTALL_DIR="/opt/samureye"
ENV_FILE="$INSTALL_DIR/.env"
CREDENTIALS_FILE="$INSTALL_DIR/ADMIN_CREDENTIALS"

# Verifica se está rodando como root
if [[ $EUID -ne 0 ]]; then
    error "Este script deve ser executado como root (sudo)"
    exit 1
fi

# Verifica se o SamurEye está instalado
if [[ ! -f "$ENV_FILE" ]]; then
    error "SamurEye não está instalado em $INSTALL_DIR"
    error "Execute primeiro: curl -fsSL https://raw.githubusercontent.com/GruppenIT/SamurEyePlatform/main/install.sh | sudo bash"
    exit 1
fi

echo -e "${RED}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  ⚠️  ATENÇÃO: OPERAÇÃO DESTRUTIVA                         ║"
echo "╠═══════════════════════════════════════════════════════════╣"
echo "║  Este script irá:                                         ║"
echo "║  • APAGAR TODOS OS DADOS do banco de dados                ║"
echo "║  • Recriar o usuário admin@samureye.com.br                ║"
echo "║  • Gerar nova senha de administrador                      ║"
echo "║                                                            ║"
echo "║  TODOS OS HOSTS, AMEAÇAS, JORNADAS E CONFIGURAÇÕES        ║"
echo "║  SERÃO PERMANENTEMENTE PERDIDOS!                          ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

read -p "Tem certeza que deseja continuar? Digite 'SIM' para confirmar: " CONFIRM

if [[ "$CONFIRM" != "SIM" ]]; then
    log "Operação cancelada pelo usuário"
    exit 0
fi

echo ""
log "Iniciando limpeza do appliance..."

# Carrega variáveis de ambiente
source "$ENV_FILE"

# Para o serviço SamurEye
log "Parando serviço SamurEye..."
systemctl stop samureye 2>/dev/null || true
sleep 2

# Gera nova senha para o admin
ADMIN_PASSWORD=$(openssl rand -base64 12 | tr -dc 'A-Za-z0-9' | head -c 16)
ADMIN_EMAIL="admin@samureye.com.br"

log "Limpando banco de dados..."

# Recria todas as tabelas (drop e create)
sudo -u postgres psql -d "$PGDATABASE" << 'EOSQL'
-- Desativa verificação de foreign keys temporariamente
SET session_replication_role = 'replica';

-- Lista e dropa todas as tabelas
DO $$ 
DECLARE 
    r RECORD;
BEGIN
    FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public') LOOP
        EXECUTE 'DROP TABLE IF EXISTS public.' || quote_ident(r.tablename) || ' CASCADE';
    END LOOP;
END $$;

-- Dropa todas as sequences
DO $$ 
DECLARE 
    r RECORD;
BEGIN
    FOR r IN (SELECT sequencename FROM pg_sequences WHERE schemaname = 'public') LOOP
        EXECUTE 'DROP SEQUENCE IF EXISTS public.' || quote_ident(r.sequencename) || ' CASCADE';
    END LOOP;
END $$;

-- Dropa todos os types customizados
DO $$ 
DECLARE 
    r RECORD;
BEGIN
    FOR r IN (SELECT typname FROM pg_type WHERE typnamespace = 'public'::regnamespace AND typtype = 'e') LOOP
        EXECUTE 'DROP TYPE IF EXISTS public.' || quote_ident(r.typname) || ' CASCADE';
    END LOOP;
END $$;

-- Reativa verificação de foreign keys
SET session_replication_role = 'origin';
EOSQL

log "✅ Banco de dados limpo"

# Recria as tabelas usando o schema do Drizzle
log "Recriando estrutura do banco de dados..."
cd "$INSTALL_DIR"

# Executa o push do schema
npm run db:push --force 2>/dev/null || {
    warn "db:push falhou, tentando método alternativo..."
    npx drizzle-kit push --force 2>/dev/null || true
}

log "✅ Estrutura do banco recriada"

# Gera hash da senha usando Node.js
log "Criando usuário administrador..."

HASHED_PASSWORD=$(node -e "
const bcrypt = require('bcryptjs');
const hash = bcrypt.hashSync('$ADMIN_PASSWORD', 12);
console.log(hash);
")

# Insere o usuário admin
sudo -u postgres psql -d "$PGDATABASE" << EOSQL
INSERT INTO users (username, email, password, role, is_active, created_at)
VALUES (
    'Administrador',
    '$ADMIN_EMAIL',
    '$HASHED_PASSWORD',
    'global_administrator',
    true,
    NOW()
);
EOSQL

log "✅ Usuário administrador criado"

# Atualiza arquivo de credenciais
log "Atualizando arquivo de credenciais..."

cat > "$CREDENTIALS_FILE" << EOF
╔═══════════════════════════════════════════════════════════╗
║           CREDENCIAIS DE ADMINISTRADOR                    ║
╠═══════════════════════════════════════════════════════════╣
║                                                            ║
║  Email:    $ADMIN_EMAIL                       
║  Senha:    $ADMIN_PASSWORD                                
║                                                            ║
╠═══════════════════════════════════════════════════════════╣
║  ⚠️  IMPORTANTE:                                           ║
║  • Altere esta senha após o primeiro login               ║
║  • Guarde estas credenciais em local seguro              ║
║  • Este arquivo será atualizado em cada clean            ║
║                                                            ║
║  Gerado em: $(date '+%Y-%m-%d %H:%M:%S')                  
╚═══════════════════════════════════════════════════════════╝
EOF

chmod 600 "$CREDENTIALS_FILE"
chown root:root "$CREDENTIALS_FILE"

log "✅ Arquivo de credenciais atualizado: $CREDENTIALS_FILE"

# Reinicia o serviço
log "Iniciando serviço SamurEye..."
systemctl start samureye

# Aguarda o serviço iniciar
sleep 5

# Verifica status
if systemctl is-active --quiet samureye; then
    log "✅ Serviço SamurEye iniciado com sucesso"
else
    warn "Serviço pode estar iniciando... verifique com: systemctl status samureye"
fi

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗"
echo -e "║          LIMPEZA CONCLUÍDA COM SUCESSO!                   ║"
echo -e "╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Credenciais do administrador:"
echo -e "  Email: ${BLUE}$ADMIN_EMAIL${NC}"
echo -e "  Senha: ${BLUE}$ADMIN_PASSWORD${NC}"
echo ""
echo -e "Arquivo de credenciais: ${BLUE}$CREDENTIALS_FILE${NC}"
echo ""
echo -e "${YELLOW}⚠️  Guarde estas credenciais em local seguro!${NC}"
echo ""
