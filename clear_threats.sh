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

# ─── Função SQL para recalcular risk score de TODOS os hosts ───
# Replica a lógica CVSS do threatEngine.ts:
#   - critical present → riskScore = min(100, 90 + critical*2)
#   - high present     → riskScore = min(89,  70 + high*3)
#   - medium present   → riskScore = min(69,  40 + medium*5)
#   - low present      → riskScore = min(39,  10 + low*5)
#   - no threats       → riskScore = 0
#   - rawScore = critical*10 + high*8.5 + medium*5.5 + low*2.5
RECALC_RISK_SQL=$(cat <<'RISKSQL'

-- ═══════════════════════════════════════════════════════════════════
-- Recalcula risk_score e raw_score de TODOS os hosts
-- Lógica CVSS idêntica ao threatEngine.ts:calculateHostRiskScore()
--   CVSS weights: critical=10, high=8.5, medium=5.5, low=2.5
--   Risk bands:   critical→90-100, high→70-89, medium→40-69, low→10-39
-- ═══════════════════════════════════════════════════════════════════
WITH risk_calc AS (
    SELECT
        h.id AS host_id,
        COUNT(*) FILTER (WHERE t.severity = 'critical' AND t.status IN ('open','investigating')) AS cnt_critical,
        COUNT(*) FILTER (WHERE t.severity = 'high'     AND t.status IN ('open','investigating')) AS cnt_high,
        COUNT(*) FILTER (WHERE t.severity = 'medium'   AND t.status IN ('open','investigating')) AS cnt_medium,
        COUNT(*) FILTER (WHERE t.severity = 'low'      AND t.status IN ('open','investigating')) AS cnt_low,
        -- raw_score: soma ponderada CVSS
        ROUND(
            COUNT(*) FILTER (WHERE t.severity = 'critical' AND t.status IN ('open','investigating')) * 10.0 +
            COUNT(*) FILTER (WHERE t.severity = 'high'     AND t.status IN ('open','investigating')) * 8.5  +
            COUNT(*) FILTER (WHERE t.severity = 'medium'   AND t.status IN ('open','investigating')) * 5.5  +
            COUNT(*) FILTER (WHERE t.severity = 'low'      AND t.status IN ('open','investigating')) * 2.5
        )::int AS new_raw_score,
        -- risk_score: faixas CVSS
        CASE
            WHEN COUNT(*) FILTER (WHERE t.severity = 'critical' AND t.status IN ('open','investigating')) > 0
                THEN LEAST(100, 90 + COUNT(*) FILTER (WHERE t.severity = 'critical' AND t.status IN ('open','investigating'))::int * 2)
            WHEN COUNT(*) FILTER (WHERE t.severity = 'high' AND t.status IN ('open','investigating')) > 0
                THEN LEAST(89,  70 + COUNT(*) FILTER (WHERE t.severity = 'high' AND t.status IN ('open','investigating'))::int * 3)
            WHEN COUNT(*) FILTER (WHERE t.severity = 'medium' AND t.status IN ('open','investigating')) > 0
                THEN LEAST(69,  40 + COUNT(*) FILTER (WHERE t.severity = 'medium' AND t.status IN ('open','investigating'))::int * 5)
            WHEN COUNT(*) FILTER (WHERE t.severity = 'low' AND t.status IN ('open','investigating')) > 0
                THEN LEAST(39,  10 + COUNT(*) FILTER (WHERE t.severity = 'low' AND t.status IN ('open','investigating'))::int * 5)
            ELSE 0
        END AS new_risk_score
    FROM hosts h
    LEFT JOIN threats t ON t.host_id = h.id
    GROUP BY h.id
),
-- Step 1: Atualiza hosts
do_update AS (
    UPDATE hosts
    SET risk_score = rc.new_risk_score,
        raw_score  = rc.new_raw_score
    FROM risk_calc rc
    WHERE hosts.id = rc.host_id
    RETURNING hosts.id
)
-- Step 2: Registra snapshot no histórico de risco para trend analysis
INSERT INTO host_risk_history (id, host_id, risk_score, raw_score, critical_count, high_count, medium_count, low_count, recorded_at)
SELECT
    gen_random_uuid(),
    rc.host_id,
    rc.new_risk_score,
    rc.new_raw_score,
    rc.cnt_critical,
    rc.cnt_high,
    rc.cnt_medium,
    rc.cnt_low,
    NOW()
FROM risk_calc rc;

RISKSQL
)

if [[ -z "$WHERE_CLAUSE" ]]; then
    # Limpar TODAS as ameaças
    DELETED=$(PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" -t -A <<'EOSQL'
SELECT COUNT(*) FROM threats;
EOSQL
    )

    PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" <<EOSQL
BEGIN;

-- Remove histórico de status das ameaças
DELETE FROM threat_status_history
WHERE threat_id IN (SELECT id FROM threats);

-- Remove todas as ameaças
DELETE FROM threats;

-- Recalcula risk scores (vai zerar todos pois não há mais ameaças)
$RECALC_RISK_SQL

COMMIT;
EOSQL
else
    # Limpar ameaças de uma categoria específica
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

-- Recalcula risk scores (baseado nas ameaças restantes de outras categorias)
$RECALC_RISK_SQL

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

# Mostra risk scores atualizados dos hosts
echo ""
log "Risk scores recalculados:"
echo ""
PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" -t <<'EOSQL'
SELECT
    '  ' || name ||
    ' → risk_score=' || risk_score ||
    ', raw_score=' || raw_score
FROM hosts
ORDER BY risk_score DESC
LIMIT 20;
EOSQL

echo ""
echo -e "${GREEN}As ameaças limpas só voltarão a aparecer na próxima execução da jornada.${NC}"
echo ""
