#!/bin/bash

# SamurEye - Adversarial Exposure Validation Platform
# Script de Instalação para Ambiente Replit/NixOS
# Versão: 2.0.0 - Compatível com Replit
#
# USAGE:
#   ./install-replit.sh                    # Instalação automática
#   SKIP_TOOLS=true ./install-replit.sh    # Pular instalação de ferramentas
#
# VARIABLES:
#   SKIP_TOOLS      - Pular instalação de ferramentas (padrão: false)
#   NUCLEI_VERSION  - Versão do nuclei (padrão: latest)

set -Eeuo pipefail

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variáveis de configuração
SKIP_TOOLS="${SKIP_TOOLS:-false}"
NUCLEI_VERSION="${NUCLEI_VERSION:-latest}"

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

# Função para detectar ambiente
detect_environment() {
    log "Detectando ambiente de execução..."
    
    if [[ -n "${REPL_ID:-}" ]] || command -v nix &>/dev/null; then
        ENV_TYPE="replit"
        log "Ambiente detectado: Replit/NixOS"
    elif [[ -f /etc/os-release ]]; then
        . /etc/os-release
        ENV_TYPE="linux"
        log "Ambiente detectado: $ID $VERSION_ID"
    else
        error "Ambiente não suportado"
        exit 1
    fi
}

# Função para instalar ferramentas via Nix (Replit)
install_tools_nix() {
    log "🔧 Instalando ferramentas de segurança via Nix..."
    
    # Verifica se as ferramentas já estão instaladas
    local tools_missing=false
    
    if ! command -v nmap &>/dev/null; then
        log "📦 Instalando nmap..."
        nix-env -iA nixpkgs.nmap || {
            error "Falha ao instalar nmap via nix-env"
            tools_missing=true
        }
    else
        success "✅ nmap já instalado: $(which nmap)"
    fi
    
    if ! command -v nuclei &>/dev/null; then
        log "📦 Instalando nuclei..."
        nix-env -iA nixpkgs.nuclei || {
            error "Falha ao instalar nuclei via nix-env"
            tools_missing=true
        }
    else
        success "✅ nuclei já instalado: $(which nuclei)"
    fi
    
    if ! command -v smbclient &>/dev/null; then
        log "📦 Instalando samba (smbclient)..."
        nix-env -iA nixpkgs.samba || {
            error "Falha ao instalar samba via nix-env"
            tools_missing=true
        }
    else
        success "✅ smbclient já instalado: $(which smbclient)"
    fi
    
    if [[ "$tools_missing" == "true" ]]; then
        warn "Algumas ferramentas falharam na instalação via nix-env"
        warn "Tentando instalação via shell.nix..."
        
        # Cria shell.nix para development environment
        cat > shell.nix << 'EOF'
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    nmap
    nuclei
    samba
    openssl
    curl
    wget
    git
  ];
  
  shellHook = ''
    echo "SamurEye Security Tools Environment"
    echo "Available tools:"
    echo "  - nmap: $(which nmap 2>/dev/null || echo 'not found')"
    echo "  - nuclei: $(which nuclei 2>/dev/null || echo 'not found')"
    echo "  - smbclient: $(which smbclient 2>/dev/null || echo 'not found')"
  '';
}
EOF
        log "📝 shell.nix criado. Execute 'nix-shell' para carregar ferramentas"
    fi
}

# Função para instalar ferramentas via apt (Linux tradicional)
install_tools_apt() {
    log "🔧 Instalando ferramentas de segurança via apt..."
    
    # Atualiza repositórios
    apt update
    
    # Instala nmap
    if ! command -v nmap &>/dev/null; then
        log "📦 Instalando nmap..."
        apt install -y nmap
    fi
    
    # Instala nuclei
    if ! command -v nuclei &>/dev/null; then
        log "📦 Instalando nuclei..."
        
        # Tenta instalar via Go primeiro
        if command -v go &>/dev/null; then
            GOPATH="/tmp/go" go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
            if [[ -f "/tmp/go/bin/nuclei" ]]; then
                mv /tmp/go/bin/nuclei /usr/local/bin/
                chmod +x /usr/local/bin/nuclei
            fi
            rm -rf /tmp/go
        else
            warn "Go não disponível, nuclei pode não estar instalado"
        fi
    fi
    
    # Instala samba/smbclient
    if ! command -v smbclient &>/dev/null; then
        log "📦 Instalando samba..."
        apt install -y samba smbclient
    fi
}

# Função principal de instalação de ferramentas
install_security_tools() {
    if [[ "$SKIP_TOOLS" == "true" ]]; then
        warn "Pulando instalação de ferramentas (SKIP_TOOLS=true)"
        return 0
    fi
    
    log "🛡️ Instalando ferramentas de segurança..."
    
    case "$ENV_TYPE" in
        "replit")
            install_tools_nix
            ;;
        "linux")
            install_tools_apt
            ;;
        *)
            error "Ambiente não suportado para instalação de ferramentas"
            exit 1
            ;;
    esac
}

# Função para verificar ferramentas instaladas
verify_tools() {
    log "🔍 Verificando ferramentas instaladas..."
    
    local all_good=true
    
    # Verifica nmap
    if command -v nmap &>/dev/null; then
        local nmap_version=$(nmap --version 2>/dev/null | head -1 | grep -o 'version [0-9.]*' | cut -d' ' -f2)
        success "✅ nmap $nmap_version: $(which nmap)"
    else
        error "❌ nmap não encontrado"
        all_good=false
    fi
    
    # Verifica nuclei
    if command -v nuclei &>/dev/null; then
        local nuclei_version=$(nuclei -version 2>/dev/null | grep -o 'v[0-9.]*' || echo "desconhecida")
        success "✅ nuclei $nuclei_version: $(which nuclei)"
    else
        error "❌ nuclei não encontrado"
        all_good=false
    fi
    
    # Verifica smbclient
    if command -v smbclient &>/dev/null; then
        local samba_version=$(smbclient --version 2>/dev/null | grep -o 'Version [0-9.]*' | cut -d' ' -f2 || echo "desconhecida")
        success "✅ smbclient $samba_version: $(which smbclient)"
    else
        error "❌ smbclient não encontrado"
        all_good=false
    fi
    
    if [[ "$all_good" == "true" ]]; then
        success "🎉 Todas as ferramentas estão instaladas e funcionais!"
    else
        warn "⚠️ Algumas ferramentas não estão disponíveis"
        warn "Isso pode afetar a funcionalidade dos scanners"
    fi
}

# Função para configurar nuclei
configure_nuclei() {
    if ! command -v nuclei &>/dev/null; then
        warn "Nuclei não disponível, pulando configuração"
        return 0
    fi
    
    log "⚙️ Configurando nuclei..."
    
    # Cria diretórios necessários
    mkdir -p /tmp/nuclei/.config
    mkdir -p /tmp/nuclei/.cache
    
    # Define variáveis de ambiente para nuclei
    export HOME="/tmp/nuclei"
    export NUCLEI_CONFIG_DIR="/tmp/nuclei/.config"
    export XDG_CONFIG_HOME="/tmp/nuclei/.config"
    export XDG_CACHE_HOME="/tmp/nuclei/.cache"
    
    # Tenta atualizar templates (sem falhar se não conseguir)
    log "📚 Atualizando templates do nuclei..."
    nuclei -update-templates -silent 2>/dev/null || {
        warn "Não foi possível atualizar templates do nuclei"
        warn "Funcionalidade pode ser limitada"
    }
    
    # Testa nuclei básico
    log "🧪 Testando nuclei..."
    if echo "httpbin.org" | nuclei -silent -nc -timeout 2 -retries 1 >/dev/null 2>&1; then
        success "✅ Nuclei configurado e funcionando"
    else
        warn "⚠️ Nuclei pode não estar funcionando corretamente"
    fi
}

# Função para testar ferramentas
test_tools() {
    log "🧪 Testando funcionalidade das ferramentas..."
    
    local test_target="httpbin.org"
    
    # Testa nmap
    if command -v nmap &>/dev/null; then
        log "🔍 Testando nmap..."
        if timeout 10 nmap -p 80,443 --max-retries 1 "$test_target" >/dev/null 2>&1; then
            success "✅ nmap funcionando"
        else
            warn "⚠️ nmap pode ter problemas de conectividade"
        fi
    fi
    
    # Testa nuclei (teste muito básico)
    if command -v nuclei &>/dev/null; then
        log "🔍 Testando nuclei..."
        if timeout 10 nuclei -target "$test_target" -silent -nc -timeout 2 -retries 1 >/dev/null 2>&1; then
            success "✅ nuclei funcionando"
        else
            warn "⚠️ nuclei pode ter problemas"
        fi
    fi
    
    # Testa smbclient (teste básico de sintaxe)
    if command -v smbclient &>/dev/null; then
        log "🔍 Testando smbclient..."
        if smbclient --help >/dev/null 2>&1; then
            success "✅ smbclient funcionando"
        else
            warn "⚠️ smbclient pode ter problemas"
        fi
    fi
}

# Função principal
main() {
    log "🚀 Iniciando instalação SamurEye Security Tools..."
    
    detect_environment
    install_security_tools
    verify_tools
    configure_nuclei
    test_tools
    
    success "🎯 Instalação concluída!"
    log ""
    log "📋 Próximos passos:"
    log "1. Execute a aplicação SamurEye"
    log "2. Teste a criação de jornadas Attack Surface"
    log "3. Verifique se os scanners detectam ameaças corretamente"
    
    if [[ "$ENV_TYPE" == "replit" ]] && [[ -f "shell.nix" ]]; then
        log ""
        log "💡 Dica: Se as ferramentas não estiverem disponíveis,"
        log "   execute 'nix-shell' para carregar o ambiente com todas as dependências"
    fi
}

# Executa função principal
main "$@"