
# SamurEye - Adversarial Exposure Validation Platform

![SamurEye Logo](
)
![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)

SamurEye é uma plataforma empresarial de cibersegurança projetada para validação contínua de exposição adversarial. A plataforma oferece avaliações automatizadas de segurança através de três tipos principais de jornadas: escaneamento de superfície de ataque (usando nmap e nuclei), análise de higiene do Active Directory e teste de eficácia EDR/AV.

## 🎯 Funcionalidades Principais

- **Escaneamento de Superfície de Ataque**: Descoberta de portas com nmap e detecção de vulnerabilidades web com nuclei
- **Análise de Higiene AD/LDAP**: Descoberta de controladores de domínio e consultas LDAP em tempo real
- **Teste EDR/AV Real**: Deployment de arquivo EICAR via protocolos SMB para testar eficácia de soluções de segurança
- **Inteligência de Ameaças**: Engine de correlação com fontes de dados reais
- **Dashboard em Tempo Real**: Interface moderna com atualizações WebSocket
- **Auditoria Completa**: Logs detalhados de todas as operações de segurança

## 🏗️ Arquitetura do Sistema

### Frontend
- **React 18** com TypeScript
- **Radix UI** + **shadcn/ui** para componentes
- **TanStack Query** para gerenciamento de estado do servidor
- **Wouter** para roteamento
- **Tailwind CSS** com tema escuro de segurança

### Backend
- **Express.js** com TypeScript
- **PostgreSQL** com **Drizzle ORM**
- **Autenticação OIDC** via Replit
- **WebSocket** para atualizações em tempo real
- **Sistema de criptografia** com DEK/KEK para credenciais

### Serviços de Segurança
- **Scanner de Rede**: nmap para descoberta de portas
- **Scanner de Vulnerabilidade**: nuclei para detecção web
- **Scanner AD/LDAP**: ldapts para análise de diretório
- **Scanner EDR/AV**: smbclient para teste de detecção

## 📋 Pré-requisitos

### Sistema Operacional
- Ubuntu 20.04 LTS ou superior
- Acesso root ou sudo

### Dependências do Sistema
- Node.js 18.x ou superior
- PostgreSQL 14.x ou superior
- Git
- Nginx (para proxy reverso)
- SSL/TLS certificates (recomendado Let's Encrypt)

### Ferramentas de Segurança
- nmap (escaneamento de portas e vulnerabilidades)
- nuclei (detecção de vulnerabilidades web)
- smbclient (testes EDR/AV)
- ldap-utils (análise de Active Directory)
- **PowerShell Core (pwsh)** - **OBRIGATÓRIO** para jornada AD Security via WinRM

## 🚀 Instalação Rápida

### Método 1: Script de Instalação Automática

```bash
# Clone o repositório
git clone https://github.com/GruppenIT/SamurEyePlatform.git
cd SamurEyePlatform

# Execute o script de instalação
sudo ./install.sh

# Ou execute remotamente
curl -fsSL https://raw.githubusercontent.com/GruppenIT/SamurEyePlatform/main/install.sh | sudo bash
```

### Método 2: Instalação Manual

1. **Clone o repositório**
   ```bash
   git clone https://github.com/GruppenIT/SamurEyePlatform.git
   cd SamurEyePlatform
   ```

2. **Instale dependências do sistema**
   ```bash
   sudo apt update && sudo apt upgrade -y
   sudo apt install -y nodejs npm postgresql postgresql-contrib nginx git
   sudo apt install -y nmap smbclient ldap-utils
   
   # Instalar PowerShell Core (OBRIGATÓRIO para AD Security)
   sudo snap install powershell --classic
   sudo ln -sf /snap/bin/pwsh /usr/bin/pwsh
   
   # Instalar nuclei via Go
   sudo apt install -y golang-go
   go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
   sudo mv ~/go/bin/nuclei /usr/local/bin/
   ```

3. **Configure o Node.js**
   ```bash
   curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
   sudo apt-get install -y nodejs
   ```

4. **Configure o PostgreSQL**
   ```bash
   sudo systemctl start postgresql
   sudo systemctl enable postgresql
   
   # Crie usuário e banco de dados
   sudo -u postgres createuser --superuser samureye
   sudo -u postgres createdb samureye_db
   sudo -u postgres psql -c "ALTER USER samureye PASSWORD 'senha_forte_aqui';"
   ```

5. **Instale dependências da aplicação**
   ```bash
   npm install
   ```

6. **Configure variáveis de ambiente**
   ```bash
   cp .env.example .env
   # Edite o arquivo .env com suas configurações
   ```

7. **Execute migrações do banco**
   ```bash
   npm run db:push
   ```

8. **Compile e inicie a aplicação**
   ```bash
   npm run build
   npm start
   ```

## ⚙️ Configuração

### Variáveis de Ambiente

Crie um arquivo `.env` na raiz do projeto:

```env
# Configuração do Banco de Dados
DATABASE_URL=postgresql://samureye:sua_senha@localhost:5432/samureye_db
PGHOST=localhost
PGPORT=5432
PGUSER=samureye
PGPASSWORD=sua_senha
PGDATABASE=samureye_db

# Configuração da Aplicação
NODE_ENV=production
PORT=5000

# Chave de Criptografia (CRÍTICO - Use uma chave forte)
ENCRYPTION_KEK=sua_chave_kek_256bits_base64

# Configuração de Autenticação OIDC (Replit)
ISSUER_URL=https://auth.replit.com
CLIENT_ID=seu_client_id
CLIENT_SECRET=seu_client_secret
REDIRECT_URI=https://seu-dominio.com/auth/callback

# Configuração de Sessão
SESSION_SECRET=sua_session_secret_forte

# Configuração de Logs
LOG_LEVEL=info
```

### Configuração do Nginx

Crie `/etc/nginx/sites-available/samureye`:

```nginx
server {
    listen 80;
    server_name seu-dominio.com www.seu-dominio.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name seu-dominio.com www.seu-dominio.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/seu-dominio.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/seu-dominio.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' wss: ws:;";

    # Proxy Settings
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
        
        # WebSocket Support
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }

    # Static files with caching
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        proxy_pass http://127.0.0.1:5000;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

Ative o site:
```bash
sudo ln -s /etc/nginx/sites-available/samureye /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Configuração de SSL com Let's Encrypt

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d seu-dominio.com -d www.seu-dominio.com
sudo systemctl enable certbot.timer
```

## 🔧 Gerenciamento de Serviços

### Systemd Service

Crie `/etc/systemd/system/samureye.service`:

```ini
[Unit]
Description=SamurEye Adversarial Exposure Validation Platform
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/opt/samureye
ExecStart=/usr/bin/node dist/index.js
Restart=always
RestartSec=10
Environment=NODE_ENV=production
EnvironmentFile=/opt/samureye/.env

# Security
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/samureye/logs /tmp
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictRealtime=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
```

Gerencie o serviço:
```bash
sudo systemctl daemon-reload
sudo systemctl enable samureye
sudo systemctl start samureye
sudo systemctl status samureye
```

## 📊 Monitoramento e Logs

### Logs da Aplicação
```bash
# Logs do systemd
sudo journalctl -u samureye -f

# Logs da aplicação
tail -f /opt/samureye/logs/app.log

# Logs de auditoria
tail -f /opt/samureye/logs/audit.log
```

### Health Check
```bash
curl -f http://localhost:5000/api/health || echo "Serviço indisponível"
```

## 🔄 Atualizações

### Método 1: Script de Upgrade Automático

```bash
cd /opt/samureye
sudo ./upgrade.sh
```

### Método 2: Upgrade Manual

```bash
# Faça backup do banco de dados
sudo -u postgres pg_dump samureye_db > backup_$(date +%Y%m%d_%H%M%S).sql

# Pare o serviço
sudo systemctl stop samureye

# Atualize o código
cd /opt/samureye
sudo git pull origin main
sudo npm install
sudo npm run build

# Execute migrações se necessário
sudo -u www-data npm run db:push

# Reinicie o serviço
sudo systemctl start samureye
sudo systemctl status samureye
```

## 🛡️ Segurança

### Configurações de Firewall

```bash
# UFW (Ubuntu Firewall)
sudo ufw enable
sudo ufw allow 22/tcp      # SSH
sudo ufw allow 80/tcp      # HTTP
sudo ufw allow 443/tcp     # HTTPS
sudo ufw deny 5000/tcp     # Bloquear acesso direto à aplicação
```

### Backup e Restore

#### Backup Automático

Crie `/opt/samureye/scripts/backup.sh`:

```bash
#!/bin/bash
BACKUP_DIR="/opt/samureye/backups"
DATE=$(date +%Y%m%d_%H%M%S)
DB_BACKUP="$BACKUP_DIR/db_backup_$DATE.sql"
APP_BACKUP="$BACKUP_DIR/app_backup_$DATE.tar.gz"

# Criar diretório de backup
mkdir -p "$BACKUP_DIR"

# Backup do banco de dados
sudo -u postgres pg_dump samureye_db > "$DB_BACKUP"

# Backup dos arquivos da aplicação
tar -czf "$APP_BACKUP" --exclude=node_modules --exclude=dist --exclude=backups /opt/samureye

# Manter apenas os últimos 7 backups
find "$BACKUP_DIR" -name "*.sql" -mtime +7 -delete
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +7 -delete

echo "Backup concluído: $DB_BACKUP, $APP_BACKUP"
```

#### Agendar backup com cron

```bash
sudo crontab -e
# Adicionar linha: 0 2 * * * /opt/samureye/scripts/backup.sh
```

#### Restore

```bash
# Restaurar banco de dados
sudo systemctl stop samureye
sudo -u postgres psql -c "DROP DATABASE IF EXISTS samureye_db;"
sudo -u postgres psql -c "CREATE DATABASE samureye_db;"
sudo -u postgres psql samureye_db < backup_YYYYMMDD_HHMMSS.sql
sudo systemctl start samureye
```

## 🧰 Troubleshooting

### Problemas Comuns

1. **Erro de conexão com o banco**
   ```bash
   sudo systemctl status postgresql
   sudo -u postgres psql -c "SELECT version();"
   ```

2. **Aplicação não inicia**
   ```bash
   sudo journalctl -u samureye --no-pager
   cd /opt/samureye && sudo -u www-data npm run check
   ```

3. **Erro de permissões**
   ```bash
   sudo chown -R www-data:www-data /opt/samureye
   sudo chmod +x /opt/samureye/install.sh
   sudo chmod +x /opt/samureye/upgrade.sh
   ```

4. **SSL/HTTPS não funciona**
   ```bash
   sudo nginx -t
   sudo certbot certificates
   sudo systemctl reload nginx
   ```

5. **WebSocket connection failed**
   ```bash
   # Verificar se proxy reverso está configurado corretamente para WebSocket
   curl -I -H "Upgrade: websocket" -H "Connection: upgrade" http://localhost:5000
   ```

### Comandos de Diagnóstico

```bash
# Status dos serviços
sudo systemctl status samureye postgresql nginx

# Uso de recursos
sudo htop
sudo df -h
sudo free -h

# Conexões de rede
sudo netstat -tulpn | grep -E ':5000|:5432|:80|:443'

# Logs em tempo real
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
sudo journalctl -u samureye -f
```

## 🤝 Contribuição

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📄 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 📧 Suporte

- **Documentação**: [Wiki do Projeto](https://github.com/GruppenIT/SamurEyePlatform/wiki)
- **Issues**: [GitHub Issues](https://github.com/GruppenIT/SamurEyePlatform/issues)
- **Discussões**: [GitHub Discussions](https://github.com/GruppenIT/SamurEyePlatform/discussions)

## 🚨 Avisos Importantes

- ⚠️ **Esta plataforma executa ferramentas de segurança reais** (nmap, nuclei, etc.). Use apenas em ambientes autorizados
- 🔒 **Mantenha as credenciais seguras** - Use senhas fortes e rotacione regularmente
- 📋 **Monitore os logs de auditoria** - Todas as ações são registradas para compliance
- 🛡️ **Mantenha o sistema atualizado** - Execute `sudo ./upgrade.sh` regularmente

---

**Desenvolvido com ❤️ pela equipe GruppenIT**