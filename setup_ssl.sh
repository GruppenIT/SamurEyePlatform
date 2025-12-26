#!/bin/bash
#
# SamurEye - Configuração SSL/HTTPS
# Este script configura certificado SSL self-signed e HTTPS no Nginx
# Válido por 60 meses (5 anos)
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

# Verifica se está rodando como root
if [[ $EUID -ne 0 ]]; then
    error "Este script deve ser executado como root (sudo)"
    exit 1
fi

echo -e "${BLUE}"
echo "=========================================="
echo "  SamurEye - Configuração SSL/HTTPS"
echo "=========================================="
echo -e "${NC}"

# Solicita o FQDN
read -p "Digite o FQDN do servidor (ex: samureye.empresa.com.br): " FQDN

if [[ -z "$FQDN" ]]; then
    error "FQDN não pode ser vazio"
    exit 1
fi

log "Configurando SSL para: $FQDN"

# Diretórios
SSL_DIR="/etc/ssl/samureye"
NGINX_CONF="/etc/nginx/sites-available/samureye-ssl"
NGINX_ENABLED="/etc/nginx/sites-enabled/samureye-ssl"
MARKER_FILE="/etc/samureye/.ssl_configured"

# Cria diretório para certificados
mkdir -p "$SSL_DIR"
mkdir -p /etc/samureye

# Gera certificado SSL self-signed válido por 60 meses (1825 dias)
log "Gerando certificado SSL self-signed válido por 60 meses..."

openssl req -x509 -nodes -days 1825 \
    -newkey rsa:4096 \
    -keyout "$SSL_DIR/samureye.key" \
    -out "$SSL_DIR/samureye.crt" \
    -subj "/C=BR/ST=SP/L=SaoPaulo/O=SamurEye/OU=Security/CN=$FQDN" \
    -addext "subjectAltName=DNS:$FQDN,DNS:localhost,IP:127.0.0.1"

# Ajusta permissões
chmod 600 "$SSL_DIR/samureye.key"
chmod 644 "$SSL_DIR/samureye.crt"
chown -R root:root "$SSL_DIR"

log "Certificado gerado em: $SSL_DIR/"

# Remove configurações antigas do Nginx
rm -f /etc/nginx/sites-enabled/samureye 2>/dev/null || true
rm -f /etc/nginx/sites-enabled/samureye-ssl 2>/dev/null || true
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

# Cria configuração do Nginx com HTTPS
log "Configurando Nginx para HTTPS..."

cat > "$NGINX_CONF" << 'NGINX_EOF'
# SamurEye - Configuração SSL/HTTPS
# Gerado por setup_ssl.sh - NÃO EDITAR MANUALMENTE
# Este arquivo é preservado durante reinstalações

# Servidor HTTP - Apenas localhost (bloqueia acesso externo)
server {
    listen 127.0.0.1:80;
    server_name localhost;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}

# Servidor HTTPS - Acesso externo
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name FQDN_PLACEHOLDER;

    # Certificados SSL
    ssl_certificate /etc/ssl/samureye/samureye.crt;
    ssl_certificate_key /etc/ssl/samureye/samureye.key;

    # Configurações SSL modernas
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    # Headers de segurança
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Tamanho máximo de upload
    client_max_body_size 100M;

    # Proxy para o backend SamurEye
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_cache_bypass $http_upgrade;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }

    # WebSocket support
    location /ws {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}

# Bloqueia porta 80 externa - redireciona para HTTPS
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    
    # Redireciona tudo para HTTPS
    return 301 https://$host$request_uri;
}
NGINX_EOF

# Substitui o placeholder do FQDN
sed -i "s/FQDN_PLACEHOLDER/$FQDN/g" "$NGINX_CONF"

# Ativa a configuração
ln -sf "$NGINX_CONF" "$NGINX_ENABLED"

# Testa configuração do Nginx
log "Testando configuração do Nginx..."
if nginx -t; then
    log "Configuração do Nginx válida"
else
    error "Erro na configuração do Nginx"
    exit 1
fi

# Reinicia Nginx
log "Reiniciando Nginx..."
systemctl reload nginx

# Configura UFW para permitir apenas HTTPS externo
log "Configurando firewall (UFW)..."

# Bloqueia porta 80 externa (permite apenas localhost)
ufw delete allow 80/tcp 2>/dev/null || true
ufw delete allow "Nginx HTTP" 2>/dev/null || true

# Permite porta 443
ufw allow 443/tcp comment 'SamurEye HTTPS'
ufw allow "Nginx HTTPS" 2>/dev/null || true

# Recarrega UFW
ufw reload 2>/dev/null || true

# Cria arquivo marcador para indicar que SSL foi configurado
echo "FQDN=$FQDN" > "$MARKER_FILE"
echo "CONFIGURED_AT=$(date -Iseconds)" >> "$MARKER_FILE"
echo "CERT_EXPIRES=$(date -d '+1825 days' -Iseconds)" >> "$MARKER_FILE"
chmod 600 "$MARKER_FILE"

echo ""
echo -e "${GREEN}=========================================="
echo "  SSL/HTTPS Configurado com Sucesso!"
echo "==========================================${NC}"
echo ""
echo -e "FQDN:              ${BLUE}$FQDN${NC}"
echo -e "Certificado:       ${BLUE}$SSL_DIR/samureye.crt${NC}"
echo -e "Chave Privada:     ${BLUE}$SSL_DIR/samureye.key${NC}"
echo -e "Validade:          ${BLUE}60 meses (5 anos)${NC}"
echo -e "Porta HTTPS:       ${GREEN}443 (aberta)${NC}"
echo -e "Porta HTTP:        ${YELLOW}80 (somente localhost)${NC}"
echo ""
echo -e "${YELLOW}NOTA: Como o certificado é self-signed, navegadores"
echo -e "mostrarão um aviso de segurança. Isso é normal.${NC}"
echo ""
echo -e "Acesse: ${BLUE}https://$FQDN${NC}"
echo ""
