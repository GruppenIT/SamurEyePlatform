#!/bin/bash
#
# SamurEye - Limpar Ameaças (Ferramenta de Desenvolvimento)
# Remove ameaças do banco de dados por tipo de jornada
# As ameaças só voltarão a aparecer na próxima execução da jornada correspondente
#

set -euo pipefail

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log()     { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }

# Diretórios
INSTALL_DIR="/opt/samureye"
ENV_FILE="$INSTALL_DIR/.env"

# Verifica se está rodando como root
if [[ $EUID -ne 0 ]]; then
    error "Este script deve ser executado como root (sudo)"
    exit 1
fi

# Verifica se o SamurEye está instalado
if [[ ! -f "$ENV_FILE" ]]; then
    error "SamurEye não está instalado em $INSTALL_DIR"
    exit 1
fi

# Carrega variáveis de ambiente
set -a
source "$ENV_FILE"
set +a

echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗"
echo -e "║       SamurEye - Limpar Ameaças (DEV Tool)                ║"
echo -e "╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Mostra contagem atual por categoria
echo -e "${BLUE}Ameaças atuais no banco de dados:${NC}"
echo ""

COUNTS=$(PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" -t -A -F'|' <<'EOSQL'
SELECT
    COALESCE(category, 'sem_categoria') AS cat,
    COUNT(*) AS total,
    COUNT(*) FILTER (WHERE status = 'open') AS abertas,
    COUNT(*) FILTER (WHERE status = 'closed') AS fechadas,
    COUNT(*) FILTER (WHERE status NOT IN ('open', 'closed')) AS outras
FROM threats
GROUP BY category
ORDER BY category;
EOSQL
)

if [[ -z "$COUNTS" ]]; then
    success "Nenhuma ameaça encontrada no banco. Nada a limpar."
    exit 0
fi

TOTAL_ALL=0
declare -A CATEGORY_MAP
IDX=1

while IFS='|' read -r cat total abertas fechadas outras; do
    label="$cat"
    case "$cat" in
        attack_surface)   label="Attack Surface (Infraestrutura)" ;;
        ad_security)      label="AD Security (Active Directory)" ;;
        edr_av)           label="EDR/AV (Endpoint Detection)" ;;
        web_application)  label="Web Application (OWASP)" ;;
        sem_categoria)    label="Sem categoria" ;;
    esac

    printf "  ${YELLOW}%d)${NC} %-42s Total: ${RED}%s${NC}  (abertas: %s, fechadas: %s, outras: %s)\n" \
        "$IDX" "$label" "$total" "$abertas" "$fechadas" "$outras"

    CATEGORY_MAP[$IDX]="$cat"
    TOTAL_ALL=$((TOTAL_ALL + total))
    IDX=$((IDX + 1))
done <<< "$COUNTS"

echo ""
printf "  ${YELLOW}%d)${NC} %-42s Total: ${RED}%s${NC}\n" "$IDX" "TODAS as categorias" "$TOTAL_ALL"
CATEGORY_MAP[$IDX]="__ALL__"

echo ""
echo -e "${YELLOW}Qual tipo de jornada deseja limpar?${NC}"
read -p "Escolha o número (1-$IDX): " CHOICE

# Valida escolha
if ! [[ "$CHOICE" =~ ^[0-9]+$ ]] || [[ "$CHOICE" -lt 1 ]] || [[ "$CHOICE" -gt "$IDX" ]]; then
    error "Opção inválida: $CHOICE"
    exit 1
fi

SELECTED="${CATEGORY_MAP[$CHOICE]}"

if [[ "$SELECTED" == "__ALL__" ]]; then
    LABEL="TODAS as ameaças"
    WHERE_CLAUSE=""
else
    LABEL="ameaças da categoria '$SELECTED'"
    WHERE_CLAUSE="WHERE category = '$SELECTED'"
fi

echo ""
warn "Você vai apagar: $LABEL"
warn "As ameaças só voltarão após nova execução da jornada correspondente."
echo ""
read -p "Confirma? (y/N): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log "Operação cancelada."
    exit 0
fi

echo ""
log "Removendo $LABEL..."

# Também limpa o histórico de risco dos hosts afetados
if [[ -z "$WHERE_CLAUSE" ]]; then
    # Limpar tudo
    DELETED=$(PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" -t -A <<'EOSQL'
    BEGIN;

    -- Salva contagem antes de deletar
    SELECT COUNT(*) FROM threats;
EOSQL
    )

    PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" <<'EOSQL'
    -- Remove histórico de status das ameaças
    DELETE FROM threat_status_history
    WHERE threat_id IN (SELECT id FROM threats);

    -- Remove todas as ameaças
    DELETE FROM threats;

    -- Recalcula risk score dos hosts (zera todos)
    UPDATE hosts SET risk_score = 0, raw_score = 0;

    COMMIT;
EOSQL
else
    DELETED=$(PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" -t -A <<EOSQL
    SELECT COUNT(*) FROM threats $WHERE_CLAUSE;
EOSQL
    )

    PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" <<EOSQL
    BEGIN;

    -- Remove histórico de status das ameaças desta categoria
    DELETE FROM threat_status_history
    WHERE threat_id IN (SELECT id FROM threats $WHERE_CLAUSE);

    -- Remove ameaças da categoria
    DELETE FROM threats $WHERE_CLAUSE;

    -- Recalcula risk score dos hosts que tinham ameaças desta categoria
    -- Zera hosts que não têm mais nenhuma ameaça aberta
    UPDATE hosts SET risk_score = 0, raw_score = 0
    WHERE id NOT IN (
        SELECT DISTINCT host_id FROM threats
        WHERE host_id IS NOT NULL AND status IN ('open', 'investigating')
    );

    COMMIT;
EOSQL
fi

success "$DELETED ameaça(s) removida(s) com sucesso!"
echo ""

# Mostra contagem final
REMAINING=$(PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" -t -A <<'EOSQL'
SELECT COUNT(*) FROM threats;
EOSQL
)

log "Ameaças restantes no banco: $REMAINING"
echo ""
echo -e "${GREEN}As ameaças limpas só voltarão a aparecer na próxima execução da jornada.${NC}"
echo ""
