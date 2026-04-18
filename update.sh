#!/bin/bash
# SamurEye - update.sh [DEPRECATED em v2.0 — Phase 8 / INFRA-05]
#
# Este script agora é um WRAPPER DE DEPRECATION que delega para install.sh --update.
# A cadeia de update remoto do console continua funcionando porque:
#   - /etc/sudoers.d/samureye-update aponta para este arquivo
#   - samureye-update.path + samureye-update.service apontam para este arquivo
#   - systemUpdateService.ts (server/services/) escreve temp/.update-trigger
# Este wrapper preserva todos os env vars passados por systemUpdateService
# (AUTO_CONFIRM, SKIP_BACKUP, GIT_TOKEN, BRANCH, INSTALL_DIR) — o `exec`
# substitui o processo atual, mantendo o env herdado do sudo -E intacto.
#
# SERA REMOVIDO na milestone AUTOUP (auto-update service futuro).

set -Eeuo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/samureye}"

cat <<'BANNER' >&2
================================================================================
  DEPRECATED: update.sh sera substituido por servico auto-update em milestone
  futura (AUTOUP-01, AUTOUP-02). Esta invocacao esta delegando para
  install.sh --update — use install.sh diretamente em scripts novos.
================================================================================
BANNER

# `exec` substitui o processo atual — o exit code do install.sh se torna o do
# wrapper, o que e critico para systemUpdateService.ts que le ExecMainStatus
# via systemctl. Todos os env vars ja exportados pelo sudo -E sao preservados
# automaticamente pelo exec.
exec "$INSTALL_DIR/install.sh" --update
