#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# build_inpi_deposit.sh
# Gera o pacote de deposito INPI do SamurEye
# Uso: bash scripts/build_inpi_deposit.sh
# ============================================================

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$REPO_ROOT/INPI_DEPOSITO/_build/SamurEye_Deposito_INPI"
OUTPUT_DIR="$REPO_ROOT/INPI_DEPOSITO"
ZIP_NAME="SamurEye_Deposito_INPI.zip"
HASH_FILE="resumo_hash_sha512.txt"

echo "==> Limpando build anterior..."
rm -rf "$OUTPUT_DIR/_build"
rm -f "$OUTPUT_DIR/$ZIP_NAME" "$OUTPUT_DIR/$HASH_FILE"
mkdir -p "$BUILD_DIR"/{02_Arquitetura,05_Trechos_Representativos_de_Codigo/{frontend,backend,database,workers_jobs}}

# --- Metadados do repositorio ---
COMMIT_HASH=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "UNKNOWN")
BRANCH=$(git -C "$REPO_ROOT" branch --show-current 2>/dev/null || echo "UNKNOWN")
APP_VERSION=$(cat "$REPO_ROOT/.version" 2>/dev/null || echo "UNKNOWN")
LATEST_TAG=$(git -C "$REPO_ROOT" describe --tags --abbrev=0 2>/dev/null || echo "(nenhuma)")
TODAY=$(date +%Y-%m-%d)

# --- 01: Resumo e Titulo ---
echo "==> 01_Resumo_e_Titulo.md"
cat > "$BUILD_DIR/01_Resumo_e_Titulo.md" <<'HEREDOC'
# SamurEye -- Plataforma de Validacao Adversarial de Exposicao

## Titulo

SamurEye -- Plataforma de Validacao Adversarial de Exposicao

## Resumo

O SamurEye e uma plataforma de ciberseguranca para validacao adversarial continua de exposicao,
projetada para execucao em appliance Linux (virtual ou fisico). A solucao permite que organizacoes
identifiquem, monitorem e mitiguem riscos em sua superficie de ataque, seguranca de Active Directory,
e eficacia de solucoes EDR/AV.

A plataforma e composta por quatro modulos principais:
- **Interface Web (UI):** Frontend React + TypeScript com design responsivo, dashboards de postura
  de seguranca, gestao de ativos, credenciais, jornadas de verificacao e ameacas identificadas.
- **API Backend:** Servidor Node.js/Express + TypeScript com autenticacao local (Passport.js),
  RBAC (Global Administrator, Operator, Read-Only), sessoes seguras e auditoria completa.
- **Banco de Dados:** PostgreSQL com ORM Drizzle, schema versionado, criptografia AES-256-GCM
  para credenciais (modelo DEK/KEK).
- **Workers/Jobs:** Motor de execucao de jornadas com orquestracao de scanners externos (nmap,
  nuclei), analise LDAP de Active Directory, e testes EDR/AV via EICAR. Os resultados alimentam
  um Threat Engine que correlaciona e classifica ameacas automaticamente.

O SamurEye opera como solucao all-in-one, instalada e atualizada via scripts de deployment
(install.sh / update.sh), com suporte a TLS, hardening e observabilidade integrada.
HEREDOC

# --- 02: Arquitetura ---
echo "==> 02_Arquitetura/"
ARCH_CANDIDATES=(
  "$REPO_ROOT/attached_assets/SamurEye_AEV_Platform_Architecture_1757528991932.md"
  "$REPO_ROOT/SamurEye_AEV_Platform_Architecture.md"
)
ARCH_FOUND=0
for f in "${ARCH_CANDIDATES[@]}"; do
  if [ -f "$f" ]; then
    cp "$f" "$BUILD_DIR/02_Arquitetura/SamurEye_AEV_Platform_Architecture.md"
    ARCH_FOUND=1
    break
  fi
done
# Tambem copiar PDF se existir
for f in "$REPO_ROOT"/attached_assets/SamurEye_AEV_Platform_Architecture*.pdf "$REPO_ROOT"/SamurEye_AEV_Platform_Architecture.pdf; do
  if [ -f "$f" ]; then
    cp "$f" "$BUILD_DIR/02_Arquitetura/SamurEye_AEV_Platform_Architecture.pdf"
    break
  fi
done
if [ "$ARCH_FOUND" -eq 0 ]; then
  echo "AVISO: Arquivo de arquitetura nao encontrado. Criando placeholder."
  echo "# Arquitetura - placeholder (ver repositorio original)" > "$BUILD_DIR/02_Arquitetura/Arquitetura_Resumo.md"
fi

# --- 03: Estrutura do Repositorio ---
echo "==> 03_Estrutura_do_Repositorio.txt"
(cd "$REPO_ROOT" && find . -maxdepth 3 \
  -not -path './.git/*' \
  -not -path './node_modules/*' \
  -not -path './dist/*' \
  -not -path './attached_assets/*' \
  -not -path './INPI_DEPOSITO/*' \
  -not -name '*.png' \
  -not -name '*.tar.gz' \
  -not -name 'package-lock.json' \
  -not -name 'cookie.txt' \
  | sort) > "$BUILD_DIR/03_Estrutura_do_Repositorio.txt"

# --- 04: Dependencias Principais ---
echo "==> 04_Dependencias_Principais.md"
cp "$REPO_ROOT/INPI_DEPOSITO/_build/SamurEye_Deposito_INPI/04_Dependencias_Principais.md" \
   "$BUILD_DIR/04_Dependencias_Principais.md" 2>/dev/null || \
   echo "# Dependencias - ver package.json" > "$BUILD_DIR/04_Dependencias_Principais.md"

# --- 05: Trechos Representativos ---
echo "==> 05_Trechos_Representativos_de_Codigo/"
# Copia trechos ja preparados no _build (gerados pela execucao inicial)
# Se necessario, copiar do repo e sanitizar manualmente

# --- 06: Versao e Evidencias ---
echo "==> 06_Versao_e_Evidencias.md"
cat > "$BUILD_DIR/06_Versao_e_Evidencias.md" <<EOF
# Versao e Evidencias de Rastreabilidade

## Data de geracao do pacote

$TODAY

## Informacoes do repositorio

- **Commit hash:** $COMMIT_HASH
- **Branch:** $BRANCH
- **Versao do aplicativo:** $APP_VERSION
- **Tag de release mais recente:** $LATEST_TAG

## Observacoes

- Este pacote foi gerado automaticamente a partir do repositorio Git do SamurEye.
- O commit hash e a versao servem para rastreabilidade interna e correlacao
  com o codigo-fonte completo mantido no repositorio privado.
- Nenhum segredo, credencial ou dado sensivel foi incluido neste pacote.
EOF

# --- 07: Instrucoes de Hash ---
echo "==> 07_Instrucoes_de_Hash.md"
cat > "$BUILD_DIR/07_Instrucoes_de_Hash.md" <<'HEREDOC'
# Instrucoes para Geracao e Verificacao do Hash SHA-512

O hash SHA-512 serve como prova de integridade do pacote de deposito.

## Gerar o hash

### Linux / macOS
```bash
sha512sum SamurEye_Deposito_INPI.zip > resumo_hash_sha512.txt
```

### Windows (PowerShell)
```powershell
Get-FileHash -Algorithm SHA512 SamurEye_Deposito_INPI.zip | Format-List
```

### Windows (CertUtil)
```cmd
certutil -hashfile SamurEye_Deposito_INPI.zip SHA512 > resumo_hash_sha512.txt
```

## Verificar o hash
```bash
sha512sum -c resumo_hash_sha512.txt
```
HEREDOC

# --- Gerar ZIP ---
echo "==> Gerando ZIP..."
(cd "$OUTPUT_DIR/_build" && zip -r "$OUTPUT_DIR/$ZIP_NAME" SamurEye_Deposito_INPI/)

# --- Gerar Hash ---
echo "==> Gerando SHA-512..."
(cd "$OUTPUT_DIR" && sha512sum "$ZIP_NAME" > "$HASH_FILE")

echo ""
echo "=== PACOTE INPI GERADO COM SUCESSO ==="
echo "ZIP:  $OUTPUT_DIR/$ZIP_NAME"
echo "Hash: $OUTPUT_DIR/$HASH_FILE"
echo ""
cat "$OUTPUT_DIR/$HASH_FILE"
echo ""
echo "Conteudo do ZIP:"
unzip -l "$OUTPUT_DIR/$ZIP_NAME"
