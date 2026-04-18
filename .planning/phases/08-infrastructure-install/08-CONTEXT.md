# Phase 8: Infrastructure & Install - Context

**Gathered:** 2026-04-18
**Status:** Ready for planning

<domain>
## Phase Boundary

Fluxo reprodutível de install/update do appliance + binários auxiliares pinados (Katana, Kiterunner, httpx, Arjun) + wordlists (`routes-large.kite`, `arjun-extended-pt-en.txt`), com artefatos de usuário (`.planning/`, `docs/`, `backups/`, `uploads/`, `.env`, cloud-synced skills dirs) preservados entre execuções. Todos os artefatos verificados por SHA-256 sem downloads em runtime.

**Fora de escopo deste phase (em outros phases ou futuro):**
- Substituição do `update.sh` por serviço auto-update (AUTOUP-*, futura milestone)
- Publicação de manifests assinados (AUTOUP-02, futura milestone)
- Schema de APIs e credenciais (Phases 9-10)
- Executor da journey API security (Phases 11-15)

</domain>

<decisions>
## Implementation Decisions

### Safe hard-reset semantics (INFRA-01)
- **Abort trigger**: commits locais ahead de `origin/main` **OU** working tree suja (`git status --porcelain` não-vazio, incluindo untracked/modificado/staged). Qualquer um dispara abort antes de tocar na árvore.
- **Reference branch**: fixo em `origin/main` (após `git fetch origin main`). A env var `BRANCH` ainda existe mas default permanece `main`.
- **Recovery**: abort imprime os commits ahead e/ou arquivos modificados, sugere `git push` / `git stash` / `git status`, retorna `exit 1`. Zero side-effects na árvore.
- **Modo de invocação**: flag explícita `--install` (primeira instalação, comportamento atual de clone) vs `--update` (safe hard-reset contra appliance existente). **Sem auto-detecção** via presença de `.git`.

### Preserve list & path handling (INFRA-02)
- **Maintained as**: array `PRESERVE_PATHS=(...)` hardcoded no topo do `install.sh`. Auditável via `git blame`, mudança exige PR.
- **Paths incluídos** (minimum set):
  - `.planning/`, `docs/`, `backups/`, `uploads/`, `.env`
  - Cloud-synced skills dirs detectados via glob: `.claude/skills/**` e `.gsd/skills/**` (qualquer subdir presente)
- **Mecanismo**: move paths preservados para `/tmp/samureye-preserve-<pid>/`, executa `git reset --hard origin/main` + `git clean -fdx`, move de volta. Mesmo padrão que o `install.sh` atual já usa para `backups/`.
- **Ownership**: preservar ownership original via `cp -a` / `mv` (uid/gid intactos). **Não** forçar `samureye:samureye`.
- **Falha no restore**: se `mv` de volta falhar, deixa arquivos em `/tmp/samureye-preserve-<pid>/` e imprime caminho explícito na mensagem de erro — nunca apaga o staging.

### Pinned binaries on disk (INFRA-03)
- **Install location**: `$INSTALL_DIR/bin/` (ex: `/opt/samureye/bin/katana`). Chamados por caminho absoluto do código Node (não dependem de PATH).
- **Checksum source of truth**: manifest JSON versionado em `scripts/install/binaries.json` com `{name, version, url, sha256}` por binário. `install.sh` parseia com `jq` (já instalado).
- **Download source**: GitHub Releases oficiais dos quatro projetos upstream (projectdiscovery/katana, assetnote/kiterunner, projectdiscovery/httpx, s0md3v/Arjun). URL específica do release asset vai no manifest.
- **Checksum mismatch**: abort imediato — log com `expected=X actual=Y`, remove o arquivo baixado, `exit 1`. Zero tolerância.
- **Versões específicas**: a serem decididas pelo researcher/planner durante Phase 8 (researcher verifica releases atuais compatíveis, planner pina no PLAN.md). Usuário revisa antes da execução.

### Wordlists on disk (INFRA-04)
- **routes-large.kite**: baixado como asset do GitHub Release do Kiterunner, entrada própria no mesmo `scripts/install/binaries.json` (com sha256).
- **arjun-extended-pt-en.txt**: custom da SamurEye (extensão pt-BR do wordlist Arjun) — **commitado no repo** em `scripts/install/wordlists/arjun-extended-pt-en.txt`. Poucos MBs, justifica version control.
- **Install path**: `$INSTALL_DIR/wordlists/` (paralelo a `bin/`). Imutável por release — reinstalado a cada update; **não** está na preserve-list.

### Release tarball & distribution (INFRA-05)
- **Layout interno (flat)**:
  ```
  samureye-v2.0.0.tar.gz
  ├── app/                      # conteúdo do repo (código)
  ├── bin/                      # binários pré-baixados, prontos para copiar
  ├── wordlists/                # routes-large.kite + arjun-extended-pt-en.txt
  ├── install.sh                # mesma lógica do install.sh do repo, consome arquivos locais
  └── MANIFEST.json             # versions + sha256 de todos os assets
  ```
- **Publishing**: GitHub Releases do repositório SamurEye; tarball anexado como asset de cada tag.
- **install.sh mode switch**: flag explícita `--from-tarball <path>`. Default é git-clone (com `--install` ou `--update`). Com `--from-tarball`, o MANIFEST.json do tarball vira fonte de verdade de SHAs/versions (zero download, zero `git clone`).
- **Todas as três invocações coexistem**: `--install` (fresh git clone), `--update` (safe hard-reset git), `--from-tarball` (offline).

### update.sh deprecation (INFRA-05)
- **Estratégia**: **wrapper com aviso + delegação** — `update.sh` passa a:
  1. Imprimir banner `DEPRECATED: update.sh será substituído por serviço auto-update em milestone futura`
  2. Executar `install.sh --update` com os mesmos args/env vars relevantes
  3. Retornar o exit code do `install.sh`
- **Motivo**: preserva a cadeia `systemUpdateService` → `temp/.update-trigger` → `samureye-update.path` → `samureye-update.service` → `update.sh`. Zero quebra do botão de remote update na console do cliente durante v2.0.
- **Sudoers + systemd units**: **mantidos intactos**. Phase 8 não toca em `/etc/sudoers.d/samureye-update`, `samureye-update.service`, `samureye-update.path` — esses recursos continuam apontando para `update.sh`, que agora delega.
- **Logica de backup/rollback do update.sh atual**: a lógica de backup pre-update (linha 215 de `update.sh`) e rollback (linha 524) **é descartada** — o novo `install.sh --update` confia no preserve-list para proteção de dados; auto-update service no futuro retomará backups formais.

### Claude's Discretion
- Versões específicas pinadas de cada binário (decidido no research/plan, revisado pelo usuário antes da execução)
- Formato exato de mensagens de log/erro em pt-BR (mantém convenção do `install.sh` atual)
- Estrutura interna do `scripts/install/binaries.json` (schema JSON)
- Script/pipeline de build do tarball (Makefile target, shell script, ou GitHub Action) — desde que gere o layout flat acordado
- Se `MANIFEST.json` é assinado ou não — não está na INFRA-05, trata como discretion (recomendação: não assinar em v2.0, deixa para AUTOUP-02)
- Política exata de retry em falha de `curl`/`wget` ao baixar binários (1 retry padrão aceitável)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Milestone spec
- `.planning/ROADMAP.md` §"Phase 8: Infrastructure & Install" — goal, 5 success criteria, dependency em Phase 7
- `.planning/REQUIREMENTS.md` §"Infrastructure (INFRA)" — INFRA-01..INFRA-05 com acceptance criteria completos
- `.planning/PROJECT.md` §"Key Decisions" — decisão "Include auxiliary binaries via release tarball; deprecate update.sh as legacy Replit-era tool" (linha 122)

### Existing install/update infrastructure (reference para research)
- `install.sh` — script atual (1327 linhas). Seções relevantes:
  - Linhas 31-41: variáveis de configuração (INSTALL_DIR, REPO_URL, BRANCH)
  - Linhas 440-464: padrão atual de preservar `backups/` via `/tmp` staging (template para a nova preserve-list)
  - Linhas 513, 531-573: criação de `.env`, diretórios de runtime, execução de migrações
- `update.sh` — script atual (686 linhas). Seções relevantes:
  - Linhas 102-156: instalação de sudoers + systemd units (`samureye-update.path`, `samureye-update.service`) que devem continuar funcionando após a deprecação
  - Linhas 160-213: `check_updates` — lógica de `git fetch` / ahead-detection que informa a nova safe-reset semantics
  - Linhas 214-295: `create_backup` + lógica de rollback (será descartada na v2.0)
  - Linhas 297-331: `update_code` — padrão de `git stash` + `git pull` (substituído pela nova lógica)

### Code que depende do update.sh (não pode ser quebrado)
- `server/services/systemUpdateService.ts` — cria trigger file em `temp/.update-trigger`
- `server/services/subscriptionService.ts` — aciona systemUpdateService em comando remoto da console
- `server/__tests__/systemUpdateService.test.ts` — testes devem continuar passando
- `server/__tests__/subscriptionService.test.ts` — idem

### Upstream projects (para research de versões e release URLs)
- https://github.com/projectdiscovery/katana/releases — Katana
- https://github.com/assetnote/kiterunner/releases — Kiterunner (inclui `routes-large.kite` asset)
- https://github.com/projectdiscovery/httpx/releases — httpx
- https://github.com/s0md3v/Arjun/releases — Arjun

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`install.sh` existing preserve pattern** (linhas 440-464): move para `/tmp` staging antes de `git clone`, restaura depois. Mesma técnica vira o core do safe hard-reset, expandida de `backups/` para a preserve-list completa.
- **`jq` já está instalado** pelo `install_system_deps()` (linha 103) — pode parsear `scripts/install/binaries.json` sem nova dependência.
- **`sha256sum` disponível** em qualquer Ubuntu base — nenhuma dependência extra para checksum.
- **Logging helpers** (`log`, `warn`, `error` em install.sh linhas 44-54) — reusar para mensagens em pt-BR consistentes.
- **`set -Eeuo pipefail`** já está no topo do install.sh (linha 22) — fail-fast está estabelecido.

### Established Patterns
- **Hardcoded config no topo do script**: `INSTALL_DIR`, `REPO_URL`, `BRANCH` (linhas 31-41). `PRESERVE_PATHS=(...)` segue o mesmo padrão.
- **NONINTERACTIVE=true como default**: appliance não deve pedir input (linha 41). Novo modo `--update` deve assumir o mesmo default.
- **Env vars sobrepõem defaults**: padrão `${VAR:-default}`. Mantido.
- **pt-BR em mensagens de usuário**: todo log interativo do install.sh é em pt-BR (ex: "Preservando backups existentes..."). Convenção preservada.
- **systemd units geradas via heredoc** (update.sh linhas 128-156): reusável se precisarmos de novos units — mas Phase 8 não cria nenhum.

### Integration Points
- **`/etc/sudoers.d/samureye-update`** — rule `samureye ALL=(root) NOPASSWD:SETENV: /bin/bash $INSTALL_DIR/update.sh`. Continua apontando para `update.sh` (que vira wrapper). Não mexer.
- **`samureye-update.path` / `samureye-update.service`** systemd units — observam `INSTALL_DIR/temp/.update-trigger` e disparam `update.sh`. Continuam funcionando.
- **`server/services/systemUpdateService.ts`** — escreve o trigger file. Nenhuma mudança.
- **`scripts/install/`** — nova subdir a ser criada para `binaries.json` e `wordlists/arjun-extended-pt-en.txt`.
- **`$INSTALL_DIR/bin/`** e **`$INSTALL_DIR/wordlists/`** — novos diretórios criados pelo install.sh; código Node referencia por caminho absoluto (via env ou config).

</code_context>

<specifics>
## Specific Ideas

- Quando safe-reset aborta, a mensagem deve incluir o comando exato para remediar. Ex: "`git push origin main`" ou "`git stash -u`" — não só descrever o problema.
- Manifest JSON deve permitir comentários de contexto? **Não** — JSON estrito (consumido por `jq`). Racional vai no PR que adiciona/altera pinos.
- `routes-large.kite` e `arjun-extended-pt-en.txt` são **imutáveis por release** (não estão na preserve-list). Se o cliente customizar, deve via PR ao repo SamurEye, não edição in-place.
- `update.sh` wrapper deve preservar **todos** os env vars (`SKIP_BACKUP`, `AUTO_CONFIRM`, etc.) ao delegar, mesmo que o novo `install.sh --update` ignore alguns — retrocompatibilidade de invocação remota.
- Binary presence check na startup do server deixado como discretion do researcher (pode virar um helper em `server/lib/` ou check lazy no primeiro uso).

</specifics>

<deferred>
## Deferred Ideas

- **Serviço de auto-update** (AUTOUP-01, AUTOUP-02) — substitui `update.sh` por mecanismo service-based + manifests assinados. Future milestone dedicada.
- **Symlinks de binários em `/usr/local/bin`** — discutido e descartado para v2.0; se ficar útil no futuro, adicionar depois sem impacto no app (app usa caminho absoluto).
- **Monitor periódico de checksums pós-install** (re-verificação em background) — nice-to-have de segurança, não em INFRA-*.
- **Rollback formal pós-update** — descartado em v2.0 junto com a remoção do backup pre-update do `update.sh`. Retomado quando AUTOUP for planejado.
- **Modo interativo com `git stash` automático** — considerado na Área 1, descartado (appliance é NONINTERACTIVE-first).
- **Manifest JSON assinado** (chave pública embutida, verificação GPG) — deixado para AUTOUP-02.

</deferred>

---

*Phase: 08-infrastructure-install*
*Context gathered: 2026-04-18*
