#!/bin/bash

# SamurEye - Script de Atualização para Correção do WebSocket
# Este script aplica as correções necessárias no servidor on-premise
# para resolver os crashes causados pelo @neondatabase/serverless

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

INSTALL_DIR="/opt/samureye"
SERVICE_NAME="samureye-api.service"

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Verificar se é root
if [[ $EUID -ne 0 ]]; then
    error "Este script deve ser executado como root (use sudo)"
    exit 1
fi

log "=== SamurEye - Atualização de Correção do WebSocket ==="

# Parar o serviço
log "Parando o serviço SamurEye..."
systemctl stop $SERVICE_NAME || true

# Fazer backup do código atual
log "Criando backup do código atual..."
BACKUP_DIR="/opt/samureye_backup_$(date +%Y%m%d_%H%M%S)"
cp -r $INSTALL_DIR $BACKUP_DIR
log "Backup criado em: $BACKUP_DIR"

# Navegar para o diretório de instalação
cd $INSTALL_DIR

# Atualizar o código do repositório
log "Atualizando código do repositório..."
git stash || true
git pull origin main

# Instalar/atualizar dependências corretas
log "Removendo dependência problemática @neondatabase/serverless..."
npm uninstall @neondatabase/serverless 2>/dev/null || true

log "Instalando driver PostgreSQL correto..."
npm install pg @types/pg

# Rebuild da aplicação
log "Reconstruindo aplicação..."
npm run build

# Verificar se os arquivos críticos foram atualizados
if grep -q "from 'pg'" $INSTALL_DIR/dist/index.js; then
    log "✅ Correção aplicada com sucesso - usando driver PostgreSQL correto"
else
    warn "⚠️  Não foi possível verificar se a correção foi aplicada"
fi

# Reiniciar o serviço
log "Reiniciando serviço SamurEye..."
systemctl start $SERVICE_NAME

# Aguardar um momento e verificar status
sleep 5
if systemctl is-active --quiet $SERVICE_NAME; then
    log "✅ Serviço reiniciado com sucesso"
    
    # Verificar logs para confirmar que não há mais erros de WebSocket
    log "Verificando logs recentes..."
    sleep 10
    
    if journalctl -u $SERVICE_NAME --since "1 minute ago" | grep -q "wss://localhost/v2\|connect ECONNREFUSED.*:443"; then
        error "❌ Ainda há erros de WebSocket nos logs. Verificar configuração."
        log "Exibindo logs recentes:"
        journalctl -u $SERVICE_NAME --since "1 minute ago" --no-pager -n 20
        exit 1
    else
        log "✅ Nenhum erro de WebSocket detectado nos logs"
        log "🎉 Atualização concluída com sucesso!"
        log ""
        log "Para verificar o status do serviço:"
        log "  sudo systemctl status $SERVICE_NAME"
        log ""
        log "Para ver os logs em tempo real:"
        log "  sudo journalctl -u $SERVICE_NAME -f"
    fi
else
    error "❌ Falha ao reiniciar o serviço"
    log "Status do serviço:"
    systemctl status $SERVICE_NAME --no-pager -n 10
    exit 1
fi