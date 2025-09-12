#!/bin/bash

# SamurEye - Reset Total do Banco (Comando Único)
# Execute: curl -s https://raw.githubusercontent.com/seu-repo/fix-db-single-command.sh | sudo bash

set -e

echo "🔄 Iniciando reset completo do SamurEye..."

# Para o serviço
systemctl stop samureye-api 2>/dev/null || true
pkill -f samureye 2>/dev/null || true
sleep 3

# Mata conexões ativas
sudo -u postgres psql -c "SELECT pg_terminate_backend(pg_stat_activity.pid) FROM pg_stat_activity WHERE pg_stat_activity.datname = 'samureye_db' AND pid <> pg_backend_pid();" 2>/dev/null || true

# Remove banco e usuário
sudo -u postgres psql -c "DROP DATABASE IF EXISTS samureye_db;" 2>/dev/null || true
sudo -u postgres psql -c "DROP USER IF EXISTS samureye;" 2>/dev/null || true

# Gera nova senha (apenas hex)
NEW_DB_PASSWORD=$(openssl rand -hex 32)
echo "🔑 Nova senha gerada: ${#NEW_DB_PASSWORD} caracteres"

# Cria usuário e banco
sudo -u postgres psql -c "CREATE USER samureye WITH LOGIN;"
sudo -u postgres psql -c "ALTER USER samureye WITH ENCRYPTED PASSWORD '$NEW_DB_PASSWORD';"
sudo -u postgres psql -c "CREATE DATABASE samureye_db OWNER samureye;"
sudo -u postgres psql -d samureye_db -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;"

# Testa conexão
echo "🧪 Testando conexão..."
if PGPASSWORD="$NEW_DB_PASSWORD" psql -h localhost -U samureye -d samureye_db -c "SELECT version();" > /dev/null 2>&1; then
    echo "✅ Conexão PostgreSQL OK"
else
    echo "❌ Falha na conexão"
    exit 1
fi

# Atualiza .env
cd /opt/samureye
cp .env .env.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true

# Preserva configurações existentes e atualiza apenas o banco
ENCRYPTION_KEK=$(grep "^ENCRYPTION_KEK=" .env 2>/dev/null | cut -d'=' -f2- || openssl rand -hex 32)
SESSION_SECRET=$(grep "^SESSION_SECRET=" .env 2>/dev/null | cut -d'=' -f2- || openssl rand -base64 64 | tr -d '\n')

# Cria novo .env limpo
cat > .env << EOF
DATABASE_URL=postgresql://samureye:$NEW_DB_PASSWORD@localhost:5432/samureye_db
PGHOST=localhost
PGPORT=5432
PGUSER=samureye
PGPASSWORD=$NEW_DB_PASSWORD
PGDATABASE=samureye_db
NODE_ENV=production
PORT=5000
ENCRYPTION_KEK=$ENCRYPTION_KEK
SESSION_SECRET="$SESSION_SECRET"
LOG_LEVEL=info
EOF

chown samureye:samureye .env
chmod 600 .env

# Executa migrações
echo "📋 Executando migrações..."
if sudo -u samureye DATABASE_URL="postgresql://samureye:$NEW_DB_PASSWORD@localhost:5432/samureye_db" npm run db:push; then
    echo "✅ Migrações OK"
else
    echo "🔄 Tentando com --force..."
    sudo -u samureye DATABASE_URL="postgresql://samureye:$NEW_DB_PASSWORD@localhost:5432/samureye_db" npx drizzle-kit push --force
fi

# Cria admin
echo "👤 Criando usuário administrador..."
ADMIN_PASS=$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c16)
ADMIN_HASH=$(node -e "console.log(require('bcryptjs').hashSync('$ADMIN_PASS', 12))")

PGPASSWORD="$NEW_DB_PASSWORD" psql -h localhost -U samureye -d samureye_db -c "
    INSERT INTO users (id, email, password_hash, role, must_change_password) 
    VALUES (gen_random_uuid(), 'admin@samureye.com.br', '$ADMIN_HASH', 'global_administrator', true);"

# Salva credenciais
cat > ADMIN_CREDENTIALS << EOF
=========================================
     SamurEye - Credenciais de Acesso
=========================================

URL: http://$(hostname -I | awk '{print $1}'):5000
Email: admin@samureye.com.br
Senha: $ADMIN_PASS

IMPORTANTE: Altere a senha no primeiro login!
=========================================
EOF

chmod 600 ADMIN_CREDENTIALS
chown samureye:samureye ADMIN_CREDENTIALS

# Reinicia serviço
echo "🚀 Reiniciando serviço..."
systemctl start samureye-api
sleep 5

if systemctl is-active --quiet samureye-api; then
    echo "🎯 SUCESSO! SamurEye funcionando"
    echo "🌐 Acesso: http://$(hostname -I | awk '{print $1}'):5000"
    echo "🔑 Credenciais:"
    cat ADMIN_CREDENTIALS
else
    echo "❌ Problema no serviço. Logs:"
    journalctl -u samureye-api -n 10 --no-pager
fi