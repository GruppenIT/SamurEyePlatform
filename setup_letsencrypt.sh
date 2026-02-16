#!/bin/bash
#
# SamurEye - Configuração de Certificados Let's Encrypt via DNS-01
#
# Este script configura certificados SSL válidos emitidos pelo Let's Encrypt
# usando validação DNS (não requer exposição pública do servidor).
#
# Uso: sudo bash setup_letsencrypt.sh
#
# O script vai:
#   1. Instalar certbot
#   2. Solicitar os domínios desejados
#   3. Orientar quais registros DNS TXT criar
#   4. Emitir o certificado após validação
#   5. Configurar Nginx para usar o certificado
#   6. Configurar renovação automática
#
# IMPORTANTE: Os certificados Let's Encrypt são válidos por 90 dias.
# A renovação automática é configurada via systemd timer.
#

set -euo pipefail

# ─── Cores ──────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()     { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERRO]${NC} $1"; }
step()    { echo -e "\n${CYAN}━━━ $1 ━━━${NC}"; }
highlight() { echo -e "${BOLD}${BLUE}$1${NC}"; }

# ─── Verificações iniciais ──────────────────────────────
if [[ $EUID -ne 0 ]]; then
    error "Este script deve ser executado como root (sudo)"
    exit 1
fi

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║  SamurEye - Certificados Let's Encrypt (DNS-01)     ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ─── Variáveis ──────────────────────────────────────────
NGINX_CONF="/etc/nginx/sites-available/samureye-ssl"
NGINX_ENABLED="/etc/nginx/sites-enabled/samureye-ssl"
MARKER_FILE="/etc/samureye/.ssl_configured"
LETSENCRYPT_MARKER="/etc/samureye/.letsencrypt_configured"
RENEW_HOOK="/etc/letsencrypt/renewal-hooks/deploy/samureye-reload-nginx.sh"

# ─── Step 1: Instalar certbot ──────────────────────────
step "1/6 — Instalando certbot"

if command -v certbot &>/dev/null; then
    log "certbot já instalado: $(certbot --version 2>&1)"
else
    log "Instalando certbot..."
    apt update -qq
    apt install -y certbot
    log "certbot instalado: $(certbot --version 2>&1)"
fi

# ─── Step 2: Solicitar domínios ─────────────────────────
step "2/6 — Configuração dos domínios"

echo ""
echo -e "O certificado será emitido para os domínios que você informar."
echo -e "Para um ${BOLD}wildcard${NC} (ex: *.samureye.com.br), informe o domínio base."
echo ""

read -p "Domínio base (ex: samureye.com.br): " BASE_DOMAIN

if [[ -z "$BASE_DOMAIN" ]]; then
    error "Domínio não pode ser vazio"
    exit 1
fi

# Remove possíveis prefixos
BASE_DOMAIN=$(echo "$BASE_DOMAIN" | sed 's|^https\?://||' | sed 's|/.*||' | sed 's|^\*\.||')

echo ""
echo -e "Domínios que serão incluídos no certificado:"
echo -e "  ${GREEN}✓${NC} ${BOLD}${BASE_DOMAIN}${NC} (domínio raiz)"
echo -e "  ${GREEN}✓${NC} ${BOLD}*.${BASE_DOMAIN}${NC} (wildcard — cobre api., www., app., etc.)"
echo ""

read -p "Confirma esses domínios? [S/n]: " CONFIRM
CONFIRM=${CONFIRM:-S}
if [[ ! "$CONFIRM" =~ ^[Ss]$ ]]; then
    error "Operação cancelada."
    exit 0
fi

# E-mail para notificações de renovação
echo ""
read -p "E-mail para notificações de renovação Let's Encrypt: " LE_EMAIL

if [[ -z "$LE_EMAIL" ]]; then
    error "E-mail é obrigatório para Let's Encrypt"
    exit 1
fi

# FQDN principal para o Nginx server_name
echo ""
read -p "FQDN principal do servidor (ex: api.${BASE_DOMAIN} ou www.${BASE_DOMAIN}): " SERVER_FQDN

if [[ -z "$SERVER_FQDN" ]]; then
    SERVER_FQDN="$BASE_DOMAIN"
    warn "Usando domínio base como FQDN: $SERVER_FQDN"
fi

# ─── Step 3: Orientar registros DNS ────────────────────
step "3/6 — Emitindo certificado via DNS-01"

echo ""
echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║  ATENÇÃO: O certbot vai pedir que você crie registros DNS   ║${NC}"
echo -e "${YELLOW}║  do tipo TXT. Siga as instruções abaixo com cuidado.        ║${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "O que vai acontecer:"
echo -e ""
echo -e "  1. O certbot vai exibir ${BOLD}UM ou DOIS valores${NC} de validação"
echo -e "  2. Para cada valor, você precisa criar um registro DNS:"
echo -e ""
echo -e "     ${BOLD}Tipo:${NC}  TXT"
echo -e "     ${BOLD}Nome:${NC}  _acme-challenge.${BASE_DOMAIN}"
echo -e "     ${BOLD}Valor:${NC} (será exibido pelo certbot)"
echo -e "     ${BOLD}TTL:${NC}   60 (ou o menor possível)"
echo -e ""
echo -e "  3. ${YELLOW}IMPORTANTE:${NC} Como estamos pedindo wildcard + raiz,"
echo -e "     o certbot pedirá ${BOLD}DOIS registros TXT${NC} com o ${BOLD}MESMO nome${NC}"
echo -e "     mas ${BOLD}valores diferentes${NC}. Crie os dois no DNS!"
echo -e ""
echo -e "  4. Após criar cada registro, aguarde ~30s para propagação"
echo -e "     e pressione ENTER quando o certbot solicitar."
echo -e ""
echo -e "  ${CYAN}Dica: Use https://toolbox.googleapps.com/apps/dig/#TXT/_acme-challenge.${BASE_DOMAIN}${NC}"
echo -e "  ${CYAN}para verificar se o registro propagou antes de confirmar.${NC}"
echo ""

read -p "Pronto para iniciar? O certbot será executado agora. [S/n]: " READY
READY=${READY:-S}
if [[ ! "$READY" =~ ^[Ss]$ ]]; then
    error "Operação cancelada."
    exit 0
fi

# Executa certbot com DNS-01 manual
echo ""
log "Executando certbot..."
echo ""

certbot certonly \
    --manual \
    --preferred-challenges dns \
    -d "${BASE_DOMAIN}" \
    -d "*.${BASE_DOMAIN}" \
    --email "$LE_EMAIL" \
    --agree-tos \
    --no-eff-email \
    --manual-public-ip-logging-ok \
    --cert-name "$BASE_DOMAIN"

# Verifica se o certificado foi emitido
CERT_PATH="/etc/letsencrypt/live/${BASE_DOMAIN}"
if [[ ! -f "${CERT_PATH}/fullchain.pem" ]]; then
    error "Certificado não encontrado em ${CERT_PATH}/"
    error "O certbot pode ter falhado. Verifique os logs: journalctl -u certbot"
    exit 1
fi

log "Certificado emitido com sucesso!"
echo -e "  Certificado: ${BLUE}${CERT_PATH}/fullchain.pem${NC}"
echo -e "  Chave:       ${BLUE}${CERT_PATH}/privkey.pem${NC}"

# ─── Step 4: Configurar Nginx ──────────────────────────
step "4/6 — Configurando Nginx com certificado Let's Encrypt"

# Remove configs antigas
rm -f /etc/nginx/sites-enabled/samureye 2>/dev/null || true
rm -f /etc/nginx/sites-enabled/samureye-ssl 2>/dev/null || true
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

cat > "$NGINX_CONF" << NGINX_EOF
# SamurEye - HTTPS com Let's Encrypt
# Gerado por setup_letsencrypt.sh em $(date -Iseconds)
# NÃO EDITAR MANUALMENTE — Este arquivo é preservado durante atualizações
# Certificado: Let's Encrypt (DNS-01) para ${BASE_DOMAIN} + *.${BASE_DOMAIN}

# Servidor HTTP - Apenas localhost (health checks internos)
server {
    listen 127.0.0.1:80;
    server_name localhost;

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
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}

# Servidor HTTPS - Let's Encrypt
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${SERVER_FQDN};

    # Certificados Let's Encrypt
    ssl_certificate     ${CERT_PATH}/fullchain.pem;
    ssl_certificate_key ${CERT_PATH}/privkey.pem;

    # OCSP Stapling (melhora performance TLS)
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate ${CERT_PATH}/chain.pem;
    resolver 8.8.8.8 1.1.1.1 valid=300s;
    resolver_timeout 5s;

    # Configurações TLS modernas
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    # Headers de segurança
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Tamanho máximo de upload
    client_max_body_size 100M;

    # Proxy para o backend SamurEye
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_cache_bypass \$http_upgrade;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }

    # WebSocket support
    location /ws {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}

# Redireciona HTTP externo para HTTPS
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 301 https://\$host\$request_uri;
}
NGINX_EOF

# Ativa configuração
ln -sf "$NGINX_CONF" "$NGINX_ENABLED"

# Testa configuração
log "Testando configuração Nginx..."
if nginx -t 2>&1; then
    log "Configuração Nginx válida"
else
    error "Configuração Nginx inválida! Verifique manualmente."
    error "Restaure com: ln -sf /etc/nginx/sites-available/samureye /etc/nginx/sites-enabled/"
    exit 1
fi

# Recarrega Nginx
systemctl reload nginx
log "Nginx recarregado com certificado Let's Encrypt"

# ─── Step 5: Configurar renovação automática ───────────
step "5/6 — Configurando renovação automática"

# Hook de deploy para recarregar Nginx após renovação
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > "$RENEW_HOOK" << 'HOOK_EOF'
#!/bin/bash
# Recarrega Nginx após renovação do certificado Let's Encrypt
# Instalado por setup_letsencrypt.sh — NÃO REMOVER
systemctl reload nginx
echo "[$(date -Iseconds)] Nginx recarregado após renovação Let's Encrypt" >> /var/log/letsencrypt-renew.log
HOOK_EOF
chmod +x "$RENEW_HOOK"

# Configura systemd timer para renovação (se não existir via certbot)
if systemctl list-timers | grep -q certbot; then
    log "Timer de renovação certbot já ativo"
else
    # Cria timer e service de renovação
    cat > /etc/systemd/system/certbot-renew.timer << 'TIMER_EOF'
[Unit]
Description=Renovação automática de certificados Let's Encrypt

[Timer]
OnCalendar=*-*-* 02:30:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
TIMER_EOF

    cat > /etc/systemd/system/certbot-renew.service << 'SERVICE_EOF'
[Unit]
Description=Renovação de certificados Let's Encrypt
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/certbot renew --quiet --deploy-hook "/etc/letsencrypt/renewal-hooks/deploy/samureye-reload-nginx.sh"
SERVICE_EOF

    systemctl daemon-reload
    systemctl enable --now certbot-renew.timer
    log "Timer de renovação criado e ativado (executa diariamente às 02:30)"
fi

# Testa renovação (dry-run)
log "Testando renovação (dry-run)..."
if certbot renew --dry-run 2>&1 | tail -3; then
    log "Teste de renovação OK"
else
    warn "Dry-run falhou — a renovação automática pode precisar de intervenção manual"
    warn "Para renovar manualmente: sudo certbot renew --manual --preferred-challenges dns"
fi

# ─── Step 6: Marcadores e firewall ─────────────────────
step "6/6 — Finalizando configuração"

# Configura firewall
log "Configurando firewall..."
ufw delete allow 80/tcp 2>/dev/null || true
ufw delete allow "Nginx HTTP" 2>/dev/null || true
ufw allow 443/tcp comment 'SamurEye HTTPS (Let'\''s Encrypt)' 2>/dev/null || true
ufw reload 2>/dev/null || true

# Cria marcadores (preservados durante update.sh)
mkdir -p /etc/samureye
cat > "$MARKER_FILE" << EOF
FQDN=${SERVER_FQDN}
CONFIGURED_AT=$(date -Iseconds)
SSL_TYPE=letsencrypt
CERT_PATH=${CERT_PATH}
BASE_DOMAIN=${BASE_DOMAIN}
EOF
chmod 600 "$MARKER_FILE"

cat > "$LETSENCRYPT_MARKER" << EOF
BASE_DOMAIN=${BASE_DOMAIN}
SERVER_FQDN=${SERVER_FQDN}
LE_EMAIL=${LE_EMAIL}
CERT_PATH=${CERT_PATH}
CONFIGURED_AT=$(date -Iseconds)
CERT_EXPIRES=$(openssl x509 -enddate -noout -in "${CERT_PATH}/fullchain.pem" 2>/dev/null | cut -d= -f2)
RENEW_HOOK=${RENEW_HOOK}
EOF
chmod 600 "$LETSENCRYPT_MARKER"

# ─── Resumo final ──────────────────────────────────────
CERT_EXPIRY=$(openssl x509 -enddate -noout -in "${CERT_PATH}/fullchain.pem" 2>/dev/null | cut -d= -f2)
CERT_ISSUER=$(openssl x509 -issuer -noout -in "${CERT_PATH}/fullchain.pem" 2>/dev/null | sed 's/issuer=//')

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Let's Encrypt configurado com sucesso!                     ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Domínios:${NC}          ${BASE_DOMAIN}, *.${BASE_DOMAIN}"
echo -e "  ${BOLD}FQDN (Nginx):${NC}      ${SERVER_FQDN}"
echo -e "  ${BOLD}Certificado:${NC}       ${CERT_PATH}/fullchain.pem"
echo -e "  ${BOLD}Chave Privada:${NC}     ${CERT_PATH}/privkey.pem"
echo -e "  ${BOLD}Emissor:${NC}           ${CERT_ISSUER}"
echo -e "  ${BOLD}Validade até:${NC}      ${CERT_EXPIRY}"
echo -e "  ${BOLD}Renovação:${NC}         Automática (systemd timer, diariamente)"
echo -e "  ${BOLD}Porta HTTPS:${NC}       ${GREEN}443 (aberta)${NC}"
echo -e "  ${BOLD}Porta HTTP:${NC}        ${YELLOW}80 → redireciona para HTTPS${NC}"
echo ""
echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║  IMPORTANTE — Renovação a cada 90 dias                      ║${NC}"
echo -e "${YELLOW}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${YELLOW}║                                                              ║${NC}"
echo -e "${YELLOW}║  Como usamos validação DNS manual, a renovação automática    ║${NC}"
echo -e "${YELLOW}║  pode falhar (não consegue criar o registro TXT sozinha).    ║${NC}"
echo -e "${YELLOW}║                                                              ║${NC}"
echo -e "${YELLOW}║  Opções para renovação:                                      ║${NC}"
echo -e "${YELLOW}║                                                              ║${NC}"
echo -e "${YELLOW}║  1. MANUAL (a cada ~80 dias):                                ║${NC}"
echo -e "${YELLOW}║     sudo certbot renew --manual --preferred-challenges dns   ║${NC}"
echo -e "${YELLOW}║                                                              ║${NC}"
echo -e "${YELLOW}║  2. AUTOMÁTICA (recomendado): Se seu provedor DNS tem API,   ║${NC}"
echo -e "${YELLOW}║     instale o plugin certbot correspondente:                 ║${NC}"
echo -e "${YELLOW}║     • Cloudflare: pip install certbot-dns-cloudflare         ║${NC}"
echo -e "${YELLOW}║     • Route53:    pip install certbot-dns-route53            ║${NC}"
echo -e "${YELLOW}║     • Google DNS: pip install certbot-dns-google             ║${NC}"
echo -e "${YELLOW}║     • DigitalOcean: pip install certbot-dns-digitalocean     ║${NC}"
echo -e "${YELLOW}║                                                              ║${NC}"
echo -e "${YELLOW}║  Verifique a data de expiração:                              ║${NC}"
echo -e "${YELLOW}║     sudo certbot certificates                                ║${NC}"
echo -e "${YELLOW}║                                                              ║${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Acesse: https://${SERVER_FQDN}${NC}"
echo ""

# Registra no log do sistema
logger -t samureye "Let's Encrypt configurado para ${BASE_DOMAIN} (*.${BASE_DOMAIN}) - expira ${CERT_EXPIRY}"
