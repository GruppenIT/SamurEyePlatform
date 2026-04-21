# Phase 8: Infrastructure & Install - Research

**Researched:** 2026-04-18
**Domain:** Bash install/update scripting, binary distribution with SHA-256 verification, reproducible appliance packaging
**Confidence:** HIGH (all upstream versions, URLs, and checksums verified against authoritative sources on 2026-04-18)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Safe hard-reset semantics (INFRA-01)**
- Abort trigger: commits locais ahead de `origin/main` OR working tree suja (`git status --porcelain` não-vazio, incluindo untracked/modificado/staged). Qualquer um dispara abort antes de tocar na árvore.
- Reference branch: fixo em `origin/main` (após `git fetch origin main`). Env var `BRANCH` existe mas default é `main`.
- Recovery: abort imprime commits ahead e/ou arquivos modificados, sugere `git push` / `git stash` / `git status`, retorna `exit 1`. Zero side-effects na árvore.
- Modo de invocação: flag explícita `--install` (primeira instalação, comportamento atual de clone) vs `--update` (safe hard-reset contra appliance existente). **Sem auto-detecção** via presença de `.git`.

**Preserve list & path handling (INFRA-02)**
- Maintained as: array `PRESERVE_PATHS=(...)` hardcoded no topo do `install.sh`. Auditável via `git blame`, mudança exige PR.
- Paths incluídos (minimum set): `.planning/`, `docs/`, `backups/`, `uploads/`, `.env`, cloud-synced skills dirs detectados via glob `.claude/skills/**` e `.gsd/skills/**`.
- Mecanismo: move paths preservados para `/tmp/samureye-preserve-<pid>/`, executa `git reset --hard origin/main` + `git clean -fdx`, move de volta.
- Ownership: preservar via `cp -a` / `mv` (uid/gid intactos). **Não** forçar `samureye:samureye`.
- Falha no restore: se `mv` de volta falhar, deixa arquivos em `/tmp/samureye-preserve-<pid>/` e imprime caminho explícito. Nunca apaga o staging.

**Pinned binaries on disk (INFRA-03)**
- Install location: `$INSTALL_DIR/bin/` (ex: `/opt/samureye/bin/katana`). Chamados por caminho absoluto do código Node.
- Checksum source of truth: manifest JSON `scripts/install/binaries.json` com `{name, version, url, sha256}` por binário. Parseado com `jq`.
- Download source: GitHub Releases oficiais dos quatro projetos upstream (projectdiscovery/katana, assetnote/kiterunner, projectdiscovery/httpx, s0md3v/Arjun).
- Checksum mismatch: abort imediato — log `expected=X actual=Y`, remove arquivo, `exit 1`. Zero tolerância.
- Versões específicas: decididas no research/plan, revisadas pelo usuário antes da execução.

**Wordlists on disk (INFRA-04)**
- `routes-large.kite`: baixado como asset de release externo, entrada no mesmo `scripts/install/binaries.json` (com sha256).
- `arjun-extended-pt-en.txt`: custom SamurEye — **commitado no repo** em `scripts/install/wordlists/arjun-extended-pt-en.txt`.
- Install path: `$INSTALL_DIR/wordlists/` (paralelo a `bin/`). Imutável por release — reinstalado a cada update; **não** está na preserve-list.

**Release tarball & distribution (INFRA-05)**
- Layout interno (flat): `app/`, `bin/`, `wordlists/`, `install.sh`, `MANIFEST.json`.
- Publishing: GitHub Releases do repositório SamurEye; tarball anexado como asset de cada tag.
- install.sh mode switch: flag explícita `--from-tarball <path>`. Default é git-clone (com `--install` ou `--update`). Com `--from-tarball`, o MANIFEST.json do tarball vira fonte de verdade.
- Três invocações coexistem: `--install`, `--update`, `--from-tarball`.

**update.sh deprecation (INFRA-05)**
- Estratégia: **wrapper com aviso + delegação** — `update.sh` passa a imprimir banner de deprecation, executar `install.sh --update` com os mesmos args/env vars, retornar exit code.
- Preserva cadeia `systemUpdateService` → `temp/.update-trigger` → `samureye-update.path` → `samureye-update.service` → `update.sh`.
- Sudoers + systemd units: **mantidos intactos**. Phase 8 não toca em `/etc/sudoers.d/samureye-update`, `samureye-update.service`, `samureye-update.path`.
- Lógica de backup/rollback do `update.sh` atual: **descartada** — novo `install.sh --update` confia no preserve-list para proteção de dados.

### Claude's Discretion

- Versões específicas pinadas de cada binário (decidido no research/plan, revisado pelo usuário antes da execução).
- Formato exato de mensagens de log/erro em pt-BR (mantém convenção do `install.sh` atual).
- Estrutura interna do `scripts/install/binaries.json` (schema JSON).
- Script/pipeline de build do tarball (Makefile target, shell script, ou GitHub Action).
- Se `MANIFEST.json` é assinado ou não — recomendação: não assinar em v2.0, deixa para AUTOUP-02.
- Política exata de retry em falha de `curl`/`wget` ao baixar binários (1 retry padrão aceitável).

### Deferred Ideas (OUT OF SCOPE)

- **Serviço de auto-update** (AUTOUP-01, AUTOUP-02) — substitui `update.sh` por mecanismo service-based + manifests assinados. Future milestone dedicada.
- **Symlinks de binários em `/usr/local/bin`** — discutido e descartado para v2.0; se ficar útil no futuro, adicionar depois sem impacto no app.
- **Monitor periódico de checksums pós-install** (re-verificação em background) — nice-to-have de segurança, não em INFRA-*.
- **Rollback formal pós-update** — descartado em v2.0 junto com a remoção do backup pre-update do `update.sh`.
- **Modo interativo com `git stash` automático** — descartado (appliance é NONINTERACTIVE-first).
- **Manifest JSON assinado** (chave pública embutida, verificação GPG) — deixado para AUTOUP-02.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| INFRA-01 | `install.sh` é revisado em safe hard-reset updater — aborta limpo se branch local tem commits não-pushados ahead de origin | Ahead/dirty detection via `git rev-list --count origin/main..HEAD` + `git status --porcelain` (authoritative pattern, Brandon Rozek/git-scm); padrão atual de `git fetch origin main` em `update.sh` linhas 160-181 reutilizado |
| INFRA-02 | `install.sh` preserva artefatos do usuário (`.planning/`, `docs/`, `backups/`, `uploads/`, `.env`, cloud-synced skills) | Padrão existente em `install.sh` linhas 440-464 (backup staging em `/tmp`) estendido para array `PRESERVE_PATHS`; `cp -a` / `mv` preservam ownership/permissions |
| INFRA-03 | `install.sh` instala versões pinadas de Katana, Kiterunner, httpx, Arjun com verificação SHA-256 | 4 versões + 4 SHA-256s verificados contra checksum files oficiais em 2026-04-18 (katana v1.5.0, httpx v1.9.0, kiterunner v1.0.2, arjun 2.2.7); manifest `scripts/install/binaries.json` + `sha256sum -c` pattern |
| INFRA-04 | `routes-large.kite` e `arjun-extended-pt-en.txt` distribuídos com release e verificados por checksum (sem download runtime) | `routes-large.kite.tar.gz` SHA-256 computado (não publicado upstream), URL CDN do assetnote ativa; custom wordlist pt-BR commitado no repo |
| INFRA-05 | Release tarball (app + binaries + wordlists) — fluxo bootstrapped; `update.sh` marcado legacy/deprecated | Tarball layout flat + `MANIFEST.json` + flag `--from-tarball`; `update.sh` wrapper com banner + delegação a `install.sh --update` preservando systemd/sudoers chain |
</phase_requirements>

## Summary

Este phase estabelece a infraestrutura de install/update reprodutível para o appliance SamurEye. A complexidade NÃO está em novas tecnologias — é no rigor de um shell script com semântica de hard-reset seguro, preservação de artefatos do usuário, download de binários externos com verificação SHA-256, e um formato de distribuição offline (tarball) — tudo sem quebrar a cadeia `systemUpdateService` → `update.sh` que o console remoto usa hoje.

As quatro versões pinadas foram verificadas contra os checksum files oficiais de cada release GitHub em 2026-04-18: **Katana v1.5.0** (publicado 2026-03-10), **httpx v1.9.0** (publicado 2026-03-09), **Kiterunner v1.0.2** (publicado 2021-04-11 — único release estável desde então), **Arjun 2.2.7** (publicado 2024-11-03 — source-only distribution via PyPI tarball). Os dois wordlists têm SHA-256s computados localmente — `routes-large.kite.tar.gz` (36 MB) disponível no CDN da Assetnote, `arjun-extended-pt-en.txt` é custom SamurEye e vai commitado no repo.

**Primary recommendation:** Reestruture `install.sh` em torno de três flags mutuamente exclusivas (`--install`, `--update`, `--from-tarball`). Extraia a lógica de preserve-staging/restore para uma função reutilizada. Adicione um novo módulo `install_binaries()` dirigido por `scripts/install/binaries.json` (parseado com `jq`). Converta `update.sh` em wrapper de 30 linhas. Use `bats-core` + `shellcheck` para garantir não-regressão; use vitest (já instalado) para o MANIFEST.json parser e um eventual helper Node que resolve paths de binários.

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| **bash** | ≥ 4.0 (Ubuntu 20.04+) | Orquestração install/update | Já é a base — `set -Eeuo pipefail` estabelecido em `install.sh` linha 22 |
| **jq** | (apt-latest) | Parsing `binaries.json` + `MANIFEST.json` | **Já instalado** em `install_system_deps()` linha 103 — zero nova dep |
| **sha256sum** | coreutils (pre-installed Ubuntu) | Verificação de checksums | Universal, sem instalação; suporta formato `<hash>  <filename>` compatível com arquivos de release GitHub |
| **curl** | apt-latest | Download de binários + checksum files | **Já instalado** (linha 90); `-fsSL` pattern já usado em `install.sh` linha 158, 313 |
| **unzip** | apt-latest | Extração de `.zip` (katana, httpx) | **Já instalado** (linha 93); pattern em linha 314 |
| **tar** | pre-installed | Extração de `.tar.gz` (kiterunner, routes-large.kite, release tarball) | Universal |
| **git** | ≥ 2.25 | Clone, fetch, rev-list, status --porcelain | **Já instalado** (linha 92) |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| **shellcheck** | 0.10+ | Static analysis de shell scripts | CI lint step — detecta quoting bugs, bashisms, variáveis não citadas; padrão de facto em 2026 |
| **bats-core** | 1.11+ | Teste automatizado de install.sh | Opt-in para cobertura dos success criteria; não obrigatório mas forte para Nyquist validation |
| **Python 3** | pre-installed | Runtime do Arjun (source install) | **Já configurado** em `setup_python_winrm()` via virtualenv `$INSTALL_DIR/venv`; Arjun instalado no mesmo venv |
| **pip** | via python3-pip | Instalação offline do Arjun wheel-less | Requer `pip install arjun-2.2.7.tar.gz` (source build) — `--no-index` quando instalando do tarball local |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `curl -fsSL` + `sha256sum` | `wget --checksum` | `wget` não tem flag nativa de checksum; curl + sha256sum é o padrão dominante |
| `jq` | `awk`/`sed` manual parsing | jq é infinitamente mais robusto e já instalado; nada a ganhar |
| `bats-core` tests | smoke tests em `shell + assert` | bats-core tem `setup()` / `teardown()` e assertions legíveis; vale os 5 MB |
| Arjun via `pipx` | `pip install` em venv dedicado | pipx é mais limpo para CLI tools, mas adiciona dep; reuso do `$INSTALL_DIR/venv` é mais coeso |
| Release tarball com `app/`, `bin/`, `wordlists/` | Imagem Docker / OVA | Tarball é leve, alinha com modelo appliance atual; Docker é futura milestone |

**Installation (novo) — adicionar ao `install_system_deps()`:**
```bash
# shellcheck (CI only, opcional em runtime)
apt install -y shellcheck

# bats-core (CI only, opcional em runtime)
apt install -y bats
```

**Verificação de versões (executado 2026-04-18):**
```bash
# katana v1.5.0 — publicado 2026-03-10
curl -sL https://api.github.com/repos/projectdiscovery/katana/releases/latest | jq -r .tag_name

# httpx v1.9.0 — publicado 2026-03-09
curl -sL https://api.github.com/repos/projectdiscovery/httpx/releases/latest | jq -r .tag_name

# kiterunner v1.0.2 — publicado 2021-04-11 (único release stable)
curl -sL https://api.github.com/repos/assetnote/kiterunner/releases/latest | jq -r .tag_name

# Arjun 2.2.7 — publicado 2024-11-03 (source-only, sem wheel)
curl -sL https://pypi.org/pypi/arjun/json | jq -r .info.version
```

## Binary Pinning Table (verified 2026-04-18)

Fonte de verdade a ser escrita em `scripts/install/binaries.json`:

| Tool | Version | Asset URL | SHA-256 (linux/amd64) | Published |
|------|---------|-----------|----------------------|-----------|
| **katana** | 1.5.0 | `https://github.com/projectdiscovery/katana/releases/download/v1.5.0/katana_1.5.0_linux_amd64.zip` | `592890e5febaf5706d0a962d96299512418d6eccce6388cf1600e1f078ed359d` | 2026-03-10 |
| **httpx** | 1.9.0 | `https://github.com/projectdiscovery/httpx/releases/download/v1.9.0/httpx_1.9.0_linux_amd64.zip` | `54c6c91d61d3b82ba79f93633df04bb547f0c954d9d9b0fb8bcedf158f85ff2f` | 2026-03-09 |
| **kiterunner** | 1.0.2 | `https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_amd64.tar.gz` | `6f0b70aabf747de592445a690281897eebbc45927e9264185d34ffb11637613b` | 2021-04-11 |
| **arjun** | 2.2.7 | `https://files.pythonhosted.org/packages/04/22/c5b969720d2802de2248c2aac0414ee5ae234887cfe150564d591c73fb23/arjun-2.2.7.tar.gz` | `b193cdaf97bf7b0e8cd91a41da778639e01fd9738d5f666a8161377f475ce72e` | 2024-11-03 |

**Wordlists:**

| File | Source | SHA-256 | Size | Published / Committed |
|------|--------|---------|------|-----------------------|
| **routes-large.kite.tar.gz** | `https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz` | `e6f4d78f6e607d0352527dee0123ce1ff7ab18fe845ea898b7ca38e0c6a321f2` | 34.7 MB (36355123 B) | Upstream: 2023-04-28 last-modified |
| **routes-small.kite.tar.gz** | `https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz` | `6f7249887cd66fdbb1220caa2281ee6290111ca444d49d4eafabfee2549e40d9` | 430 KB (440239 B) | Upstream: 2023-04-28 last-modified |
| **arjun-extended-pt-en.txt** | `scripts/install/wordlists/arjun-extended-pt-en.txt` (commitado) | TBD (a computar quando arquivo for adicionado) | A definir pelo usuário | Novo arquivo — Phase 8 |

**HIGH confidence** — todos SHA-256 computados/lidos diretamente dos checksum files oficiais ou do CDN em 2026-04-18.

**Atenção (MEDIUM confidence):** Arjun só publica source tarball no PyPI (nenhum wheel para 2.2.7). O appliance precisa de Python+pip para construir. Alternativa robusta: congelar Arjun como uma "cópia fat" (tarball + todas as deps transitive) via `pip download arjun==2.2.7 -d vendor/arjun` durante o build do release tarball, e `pip install --no-index --find-links vendor/arjun arjun` durante install. O `venv` do WinRM (linha 119) pode ser reutilizado ou um venv dedicado para ferramentas de segurança pode ser criado (`$INSTALL_DIR/venv-security`) — recomendação: **venv dedicado** para evitar conflitos de versão com `pywinrm`.

## Architecture Patterns

### Recommended Project Structure (adições em Phase 8)

```
/opt/samureye/
├── install.sh                 # REESCRITO — suporta --install | --update | --from-tarball
├── update.sh                  # WRAPPER DEPRECADO — banner + delega para install.sh --update
├── scripts/
│   └── install/
│       ├── binaries.json      # NOVO — manifest pinado (versions + SHA-256 + URLs)
│       ├── build-release.sh   # NOVO — constrói tarball (app + bin + wordlists)
│       └── wordlists/
│           └── arjun-extended-pt-en.txt  # NOVO — custom wordlist pt-BR, commitado
├── bin/                       # NOVO — pós-install: binários pinados
│   ├── katana
│   ├── httpx
│   ├── kiterunner
│   └── arjun                  # shell wrapper calling $INSTALL_DIR/venv-security/bin/arjun
├── wordlists/                 # NOVO — pós-install: wordlists imutáveis
│   ├── routes-large.kite
│   └── arjun-extended-pt-en.txt
├── venv-security/             # NOVO — venv dedicado com arjun + deps
│   └── bin/arjun
└── tests/
    └── install/               # NOVO — bats-core tests para install.sh
        ├── test_safe_reset.bats
        ├── test_preserve_paths.bats
        ├── test_binaries_install.bats
        └── test_tarball_install.bats
```

### Pattern 1: Three-Mode Entry Point (Flag-Driven)

**What:** Substitute a detecção implícita (presença de `.git`) por flags explícitas.

**When to use:** Sempre — elimina ambiguidade para o console remoto e para operadores humanos.

**Example:**
```bash
# Source: adaptação de install.sh atual + decisão explícita do CONTEXT.md
usage() {
  cat <<EOF
Usage: $0 [MODE] [OPTIONS]
  --install          Primeira instalação (clone limpo do repo)
  --update           Atualização de appliance existente (safe hard-reset)
  --from-tarball P   Instalação offline a partir de tarball em P
EOF
  exit 1
}

MODE=""
TARBALL=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --install)       MODE="install"; shift ;;
    --update)        MODE="update"; shift ;;
    --from-tarball)  MODE="tarball"; TARBALL="$2"; shift 2 ;;
    -h|--help)       usage ;;
    *)               error "Flag desconhecida: $1"; usage ;;
  esac
done

[[ -z "$MODE" ]] && { error "Escolha um modo: --install | --update | --from-tarball"; exit 1; }

case "$MODE" in
  install) run_install ;;
  update)  run_safe_update ;;
  tarball) run_from_tarball "$TARBALL" ;;
esac
```

### Pattern 2: Safe Hard-Reset Gate (Pre-Mutation Check)

**What:** Ahead-of-origin + working-tree-dirty detection antes de QUALQUER mutação.

**When to use:** `--update` path. Único local onde a árvore existente é potencialmente destruída.

**Example:**
```bash
# Source: https://brandonrozek.com/blog/ahead-behind-git/ + git-scm.com/docs/git-status
# Pattern: safe-reset gate
safe_reset_gate() {
  cd "$INSTALL_DIR"

  # 1. Fetch sem tocar na árvore
  log "Buscando atualizações de origin/$BRANCH..."
  git fetch origin "$BRANCH" 2>&1 | grep -v '^$' || true

  # 2. Detecta commits ahead
  local ahead
  ahead=$(git rev-list --count "origin/$BRANCH..HEAD" 2>/dev/null || echo "0")
  if [[ "$ahead" -gt 0 ]]; then
    error "Abort: $ahead commit(s) local(is) não-pushados ahead de origin/$BRANCH:"
    git log --oneline "origin/$BRANCH..HEAD" >&2
    error "Resolva com: git push origin $BRANCH  (ou git reset --hard origin/$BRANCH se descartar)"
    exit 1
  fi

  # 3. Detecta working tree suja (inclui untracked)
  if [[ -n "$(git status --porcelain)" ]]; then
    error "Abort: working tree suja (arquivos modificados/staged/untracked):"
    git status --porcelain >&2
    error "Resolva com: git stash -u  (ou git clean -fd  /  git checkout -- .)"
    exit 1
  fi

  log "Safe-reset gate OK — árvore limpa e sincronizada com origin/$BRANCH"
}
```

### Pattern 3: Preserve-Staging Restore (Idempotent, Ownership-Aware)

**What:** Move paths preservados para `/tmp`, reset/clean, restaura com ownership intacto.

**When to use:** Toda execução de `--update`. Código compartilhado com `--install` se o diretório já existe.

**Example:**
```bash
# Source: install.sh linhas 440-464 existente + expansão para array PRESERVE_PATHS
readonly PRESERVE_PATHS=(
  ".planning"
  "docs"
  "backups"
  "uploads"
  ".env"
  # Cloud-synced skills dirs — glob via eval
  ".claude/skills"
  ".gsd/skills"
)

preserve_and_reset() {
  local staging
  staging="/tmp/samureye-preserve-$$"
  mkdir -p "$staging"

  # 1. Move paths preservados (se existirem) para staging
  local moved=()
  for p in "${PRESERVE_PATHS[@]}"; do
    if [[ -e "$INSTALL_DIR/$p" ]]; then
      local dest_parent
      dest_parent="$staging/$(dirname "$p")"
      mkdir -p "$dest_parent"
      # -a preserva uid/gid/modes/symlinks/xattrs
      if mv "$INSTALL_DIR/$p" "$dest_parent/"; then
        moved+=("$p")
        log "Preservado: $p → $staging/$p"
      else
        error "Falha ao mover $p para staging; abortando"
        exit 1
      fi
    fi
  done

  # 2. Hard reset contra origin/main + limpeza total
  cd "$INSTALL_DIR"
  git reset --hard "origin/$BRANCH"
  git clean -fdx

  # 3. Restaura paths preservados (ownership intacto via mv)
  for p in "${moved[@]}"; do
    local src="$staging/$p"
    local dest_parent
    dest_parent="$INSTALL_DIR/$(dirname "$p")"
    mkdir -p "$dest_parent"
    if ! mv "$src" "$dest_parent/"; then
      error "Falha ao restaurar $p"
      error "Artefato preservado em: $staging/$p  — NÃO APAGUE"
      exit 1
    fi
  done

  # 4. Cleanup staging somente se tudo foi restaurado
  rm -rf "$staging"
  log "Todos os paths preservados foram restaurados com ownership original"
}
```

**Nota sobre globbing:** `.claude/skills` só casa se o subdir existir. Para múltiplos subdirs (ex: `.claude/skills/cloud-a/`, `.claude/skills/cloud-b/`), o `mv` de `.claude/skills` move o pai todo — preserva tudo abaixo dele. Não é necessário expandir glob.

### Pattern 4: Manifest-Driven Binary Install with SHA-256 Gate

**What:** `binaries.json` é single-source-of-truth; script lê o manifest e valida cada download.

**When to use:** `--install`, `--update`, e (lendo `MANIFEST.json` em vez de `binaries.json`) `--from-tarball`.

**Example:**
```bash
# Source: padrão curl + sha256sum -c (hak5.org, baeldung + install.sh linhas 300-326)
install_binary() {
  local name="$1"
  local url expected_sha temp

  url=$(jq -r ".binaries.${name}.url" "$MANIFEST")
  expected_sha=$(jq -r ".binaries.${name}.sha256" "$MANIFEST")

  temp=$(mktemp --suffix=".${name}")
  log "Baixando $name de $url..."

  if ! curl -fsSL --retry 1 -o "$temp" "$url"; then
    error "Falha ao baixar $name"
    rm -f "$temp"
    exit 1
  fi

  # sha256sum -c lê "<hash>  <file>" do stdin
  local actual_sha
  actual_sha=$(sha256sum "$temp" | awk '{print $1}')
  if [[ "$actual_sha" != "$expected_sha" ]]; then
    error "Checksum mismatch para $name:"
    error "  expected=$expected_sha"
    error "  actual=$actual_sha"
    rm -f "$temp"
    exit 1
  fi

  log "SHA-256 de $name verificado: $actual_sha"

  # Extração por tipo (zip vs tar.gz)
  mkdir -p "$INSTALL_DIR/bin"
  case "$url" in
    *.zip)    unzip -oj "$temp" "$name" -d "$INSTALL_DIR/bin/" ;;
    *.tar.gz) tar -xzf "$temp" -C "$INSTALL_DIR/bin/" --strip-components=0 --wildcards "*/$name" ;;
    *)        error "Formato desconhecido: $url"; exit 1 ;;
  esac

  chmod +x "$INSTALL_DIR/bin/$name"
  rm -f "$temp"
  log "$name instalado em $INSTALL_DIR/bin/$name"
}
```

**Arjun é um caso especial** — não é um binário Go, é um Python package source-only:
```bash
install_arjun() {
  local url expected_sha temp venv
  venv="$INSTALL_DIR/venv-security"
  url=$(jq -r ".binaries.arjun.url" "$MANIFEST")
  expected_sha=$(jq -r ".binaries.arjun.sha256" "$MANIFEST")

  temp=$(mktemp --suffix=".tar.gz")
  curl -fsSL -o "$temp" "$url" || { error "Download arjun falhou"; exit 1; }

  local actual_sha
  actual_sha=$(sha256sum "$temp" | awk '{print $1}')
  [[ "$actual_sha" == "$expected_sha" ]] || { error "arjun SHA mismatch"; rm -f "$temp"; exit 1; }

  # venv dedicado (não reutiliza pywinrm venv — isolamento)
  python3 -m venv "$venv"
  "$venv/bin/pip" install --quiet "$temp"
  rm -f "$temp"

  # shell wrapper em bin/ com PATH absoluto
  cat > "$INSTALL_DIR/bin/arjun" <<WRAP
#!/bin/bash
exec $venv/bin/arjun "\$@"
WRAP
  chmod +x "$INSTALL_DIR/bin/arjun"
  log "arjun instalado em $venv (wrapper em bin/arjun)"
}
```

### Pattern 5: Release Tarball Layout + `--from-tarball` Install

**What:** Tarball flat que contém tudo necessário para instalação offline.

**When to use:** Customer sites air-gapped; distribuição de appliance binária; CI/CD release.

**Example layout:**
```
samureye-v2.0.0.tar.gz
├── app/                      # git archive do repo na tag
├── bin/                      # binários pré-baixados (os 4 + wordlists)
├── wordlists/                # routes-large.kite + arjun-extended-pt-en.txt
├── install.sh                # mesmo install.sh do repo, consome arquivos locais
└── MANIFEST.json             # schema igual a binaries.json, mas com caminhos locais
```

**Build script (scripts/install/build-release.sh):**
```bash
#!/bin/bash
set -Eeuo pipefail

TAG="${1:?Usage: $0 <tag>}"
WORKDIR="$(mktemp -d)/samureye-${TAG}"
MANIFEST="$(pwd)/scripts/install/binaries.json"

mkdir -p "$WORKDIR/app" "$WORKDIR/bin" "$WORKDIR/wordlists"

# 1. App source (git archive da tag)
git archive --format=tar "$TAG" | tar -xC "$WORKDIR/app"

# 2. Baixa + verifica cada binário usando o mesmo código do install.sh
for name in $(jq -r '.binaries | keys[]' "$MANIFEST"); do
  bash "$(pwd)/scripts/install/fetch-binary.sh" "$name" "$WORKDIR/bin/"
done

# 3. Wordlists
cp "scripts/install/wordlists/arjun-extended-pt-en.txt" "$WORKDIR/wordlists/"
bash "$(pwd)/scripts/install/fetch-wordlist.sh" "routes-large.kite" "$WORKDIR/wordlists/"

# 4. Install.sh + MANIFEST local
cp "$WORKDIR/app/install.sh" "$WORKDIR/"
# MANIFEST.json = binaries.json com URLs substituídos por paths locais
jq '.binaries |= with_entries(.value.url = ("./bin/" + .key))' "$MANIFEST" > "$WORKDIR/MANIFEST.json"

# 5. Tarball
tar -czf "samureye-${TAG}.tar.gz" -C "$(dirname "$WORKDIR")" "$(basename "$WORKDIR")"
echo "Release: samureye-${TAG}.tar.gz"
```

### Pattern 6: update.sh Deprecation Wrapper

**What:** `update.sh` vira um wrapper finíssimo que preserva a cadeia systemd.

**Example (substitui todo o update.sh atual):**
```bash
#!/bin/bash
# SamurEye - update.sh [DEPRECATED em v2.0 — será removido quando AUTOUP service existir]
#
# Este script agora é um wrapper que delega para install.sh --update.
# Os systemd units (samureye-update.path, samureye-update.service) e a regra sudoers
# (/etc/sudoers.d/samureye-update) permanecem apontando para este arquivo — este
# wrapper garante que a cadeia de update remoto do console continue funcionando.
#
# SERÁ REMOVIDO QUANDO: milestone AUTOUP (auto-update service) substituir a cadeia.

set -Eeuo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/samureye}"

cat <<'BANNER' >&2
================================================================================
  DEPRECATED: update.sh será substituído por serviço auto-update em milestone
  futura (AUTOUP-01, AUTOUP-02). Esta invocação está delegando para
  install.sh --update — use install.sh diretamente em scripts novos.
================================================================================
BANNER

# Delega com TODOS os env vars relevantes preservados (AUTO_CONFIRM, SKIP_BACKUP,
# GIT_TOKEN, BRANCH, INSTALL_DIR, etc.) — install.sh --update pode ignorar alguns
# mas manter retrocompatibilidade de invocação é crítico.
exec "$INSTALL_DIR/install.sh" --update
```

**Por que `exec`:** substitui o processo atual — exit code do install.sh se torna o exit code do update.sh. `systemUpdateService.ts` lê `ExecMainStatus` do systemd unit e essa propagação precisa funcionar.

### Anti-Patterns to Avoid

- **Auto-detectar `.git` para decidir entre install/update:** ambíguo quando `.git` existe mas a árvore está corrompida. Flags explícitas são mais defensivas. (Decidido no CONTEXT.md.)
- **Usar `cp -r` em vez de `mv`/`cp -a` para preserve staging:** perde ownership, perde xattrs, perde symlinks. `cp -a` ou `mv` mantém tudo.
- **Baixar checksum file + arquivo e chamar `sha256sum -c`:** funciona, mas requer que o checksum file tenha formato compatível. Mais simples e previsível: extrair o SHA-256 do manifest JSON e comparar strings diretamente.
- **`chown -R samureye:samureye` após restaurar preserved paths:** o CONTEXT.md veta explicitamente. Cada artefato tem owner próprio (ex: `.env` pode ter mode 600 com owner específico).
- **Assumir `routes-large.kite.tar.gz` estará sempre disponível no CDN da Assetnote:** o arquivo está lá há 3 anos, mas se desaparecer, o `--install`/`--update` quebra. Mitigação: o release tarball mode (`--from-tarball`) é a rota de fallback — sempre tem o arquivo dentro.
- **Executar `apt install` sem `DEBIAN_FRONTEND=noninteractive`:** `install.sh` atual depende do default não-interativo do Ubuntu — manter, mas documentar em comentário no header.
- **Esquecer `set -E`:** sem `-E`, traps ERR não propagam em funções. `install.sh` já usa `-Eeuo pipefail` (linha 22). Mantenha em todo código novo.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Parsing checksum files | awk/sed pipeline custom | Comparar string direto do JSON manifest (jq extraído) | Manifest é a fonte de verdade; checksum files upstream já têm SHA-256 em plaintext — use apenas para referência cruzada, não para parsing runtime |
| JSON parsing | grep/sed em JSON | `jq` | jq já está instalado (linha 103); regex em JSON é frágil |
| Git ahead detection | `git log` + awk em `...` linhas | `git rev-list --count origin/BRANCH..HEAD` | Primitivo nativo, zero parsing, funciona em qualquer versão do git |
| Working tree dirty detection | `git diff --quiet` (não vê untracked!) | `git status --porcelain` (vê tudo) | `git diff --quiet` retorna 0 se só há untracked files — falso negativo perigoso para safe-reset |
| Lock file / mutex para evitar instâncias paralelas | flock em `/var/lock/` | Não fazer — o serviço systemd-update já serializa (Type=oneshot), e `--install` é idempotente após preserve-staging | Complexidade desnecessária; o único caller concorrente real é o console remoto, que já é serializado pelo path unit |
| Retry exponencial custom para curl | loop bash com sleep | `curl --retry 1 --retry-delay 3` | Flags nativas do curl cobrem o caso 1-retry decidido no CONTEXT.md |
| Preservar ownership/xattrs ao copiar | `cp -r` + `chown`/`setfacl` manual | `cp -a` ou `mv` | `-a` implica `-dR --preserve=all` — uid/gid/mode/symlinks/xattrs preservados |
| Detectar binário já instalado + versão | `katana --version | grep ...` + lógica de comparação | Sempre reinstalar durante `--install`/`--update` | Simpler; manifest é a source of truth e reinstall é idempotente. |
| Verificar que systemd path unit está habilitado após install | Parsing custom de `systemctl status` | `systemctl is-enabled samureye-update.path` (pattern em systemUpdateService.ts linha 201) | Comando nativo retorna "enabled"/"disabled"/"masked"; já é o padrão usado |
| Build de tarball multi-arch com cross-compile | GitHub Action com matrix de arch | Single-arch (linux/amd64) neste milestone | Appliance é Ubuntu amd64 conforme `install.sh` linha 75; ARM não é target |

**Key insight:** A tentação em shell scripts longos é reinventar utilitários. Neste phase, todas as primitivas necessárias (download, hash, parse, git state) têm comandos nativos de 1-2 flags. Manifesto-driven + primitivas nativas + funções pequenas é o padrão saudável.

## Common Pitfalls

### Pitfall 1: `git diff --quiet` ignora untracked files
**What goes wrong:** Alguém adiciona um arquivo em `.planning/phases/` sem commitar, corre `install.sh --update`, e o novo arquivo é obliterado pelo `git clean -fdx`.
**Why it happens:** `git diff --quiet` só olha para tracked files modificados. Untracked = invisível.
**How to avoid:** Sempre use `git status --porcelain` para safe-reset gates. `--porcelain` mostra 3 tipos de estado: staged (`A`, `M`), unstaged (` M`, ` D`), untracked (`??`).
**Warning signs:** Qualquer uso de `git diff` em contexto de "verificar se árvore está limpa" é suspeito.

### Pitfall 2: Preserve-staging falha no meio da restauração, deixa usuário sem dados
**What goes wrong:** `mv /tmp/samureye-preserve-1234/.env /opt/samureye/.env` falha (disk full, permission denied), script sai com `set -e`, staging é apagado no `trap EXIT` antigo, `.env` desaparece.
**Why it happens:** `trap EXIT` que limpa staging assume sucesso.
**How to avoid:** **Nunca** apague staging em `trap EXIT`. Só remova via `rm -rf "$staging"` na última linha da função, após loop de restauração bem-sucedido. Em caso de falha, imprima o caminho do staging explicitamente para o usuário.
**Warning signs:** `trap cleanup EXIT` em função de preserve-restore é red flag.

### Pitfall 3: `sha256sum -c` falha silenciosamente em formatos diferentes
**What goes wrong:** GitHub Releases de diferentes projetos usam formatos ligeiramente diferentes para checksum files (espaços duplos, tabs, prefixo de filename). `sha256sum -c checksum.txt` pode dizer "OK" mesmo com nome errado.
**Why it happens:** `sha256sum -c` é tolerante; compara apenas arquivos que reconhece.
**How to avoid:** Extraia o SHA-256 do manifest JSON (fonte única) e compare string contra `sha256sum arquivo | awk '{print $1}'`. Nunca rely no `-c` lendo arquivos externos.
**Warning signs:** Código que baixa `checksums.txt` do upstream para uso runtime.

### Pitfall 4: `curl -fsSL` retorna 0 em 404 se GitHub Releases muda URL
**What goes wrong:** URL do asset muda (ex: `v1.5.0` → `V1.5.0`), curl baixa página HTML de erro, sha256sum do HTML falha.
**Why it happens:** `-f` (fail on HTTP errors) + `-L` (follow redirects) geralmente pega isso, mas CDNs podem servir 200 com conteúdo inesperado.
**How to avoid:** O checksum gate pega isso — HTML não vai ter o SHA esperado. Adicionalmente, logar o `Content-Length` do download e comparar com valor esperado no manifest (opcional, mas aumenta clareza do erro).
**Warning signs:** Downloads sem verificação de checksum.

### Pitfall 5: `routes-large.kite.tar.gz` do CDN externo é SPOF para `--install`
**What goes wrong:** Assetnote descontinua o CDN, `install.sh --install` em instância nova quebra (sem rollback graceful).
**Why it happens:** O CDN `wordlists-cdn.assetnote.io` é third-party, não é GitHub Releases.
**How to avoid:** (a) Vendorar dentro do release tarball — resolvido pelo `--from-tarball`. (b) Documentar no README que fresh `--install` sem tarball requer conectividade com `wordlists-cdn.assetnote.io`. (c) Adicionar (futuro, não em Phase 8) um mirror do arquivo nos Releases do próprio SamurEye.
**Warning signs:** Dependência de CDN externo em fluxo crítico.

### Pitfall 6: `python3 -m venv` pode falhar em Ubuntu 22.04+ sem `python3-venv`
**What goes wrong:** `install.sh` atual já instala `python3-venv` em `setup_python_winrm()` linha 116, mas essa função é específica do WinRM. Se a ordem de execução mudar, venv para Arjun pode falhar.
**Why it happens:** Ubuntu separou `python3` e `python3-venv` em pacotes diferentes.
**How to avoid:** Garantir que `apt install python3-venv` seja chamado ANTES de qualquer `python3 -m venv`. Mover essa dep para `install_system_deps()` (topo), ou chamar novo `setup_python_security_tools()` antes de `install_binaries()`.
**Warning signs:** `python3 -m venv` em função nova sem verificar a ordem.

### Pitfall 7: systemd units de update continuam apontando para `update.sh` após deprecation
**What goes wrong:** `update.sh` é removido ou renomeado por engano, o path unit dispara, `ExecStart=/bin/bash update.sh` retorna 127, console mostra falha misteriosa.
**Why it happens:** Mudar o ponto de entrada sem atualizar as unit files.
**How to avoid:** `update.sh` NÃO é removido em Phase 8 — vira wrapper. Os systemd units e sudoers continuam apontando para ele. A remoção física do wrapper só acontece quando AUTOUP (future milestone) reescreve os units.
**Warning signs:** PR que toca em `/etc/sudoers.d/samureye-update` ou `samureye-update.service` em Phase 8.

### Pitfall 8: Preserve-staging race condition com múltiplas invocações
**What goes wrong:** Dois `install.sh --update` em paralelo (improvável mas possível se admin está debugando), ambos criam `/tmp/samureye-preserve-1234` e `/tmp/samureye-preserve-1235`, um move `.env` antes do outro, estado corrompido.
**Why it happens:** `$$` é único por processo mas staging não é reclaimado atomicamente.
**How to avoid:** Usar `mktemp -d` em vez de `/tmp/samureye-preserve-$$` — `mktemp` garante unicidade atomica. Opcional: `flock` em `/var/lock/samureye-install.lock` para serialização explícita (over-engineering para a v2.0; não fazer).
**Warning signs:** `/tmp/samureye-preserve-$PID` hardcoded em vez de `mktemp -d`.

### Pitfall 9: `git clean -fdx` apaga `.env` que está no `.gitignore`
**What goes wrong:** `.env` está no `.gitignore` (linha 14). Após preserve-and-move, o arquivo foi movido para staging — `git clean -fdx` é inofensivo. Mas se alguém adicionar um path à preserve-list e ESQUECER de movê-lo primeiro, `git clean -fdx` obliterará.
**Why it happens:** `-x` força cleanup de arquivos ignorados também, que é o comportamento desejado para hard-reset mas perigoso sem preserve-staging.
**How to avoid:** Ordem estrita: (1) `preserve_paths_to_staging`, (2) `git reset --hard`, (3) `git clean -fdx`, (4) `restore_paths_from_staging`. Nunca reverter a ordem. Test de regressão em `bats` garante isso.
**Warning signs:** `git clean` chamado antes de preserve-staging.

### Pitfall 10: Arjun source-only install sem pinar `pip` version
**What goes wrong:** `pip install arjun-2.2.7.tar.gz` puxa deps transitive (requests, etc.) com versões latest. Em 2 meses, uma dep sub-transitive tem breaking change. Arjun quebra.
**Why it happens:** Source install sem lock file.
**How to avoid:** Durante build do release tarball, executar `pip download arjun==2.2.7 -d vendor/arjun` para congelar árvore transitive. Em `--install`/`--from-tarball`, usar `pip install --no-index --find-links vendor/arjun arjun`. Isso torna o Arjun install offline e reproduzível.
**Warning signs:** `pip install arjun` sem `--no-index` em install.sh.

## Code Examples

### Binaries manifest schema (`scripts/install/binaries.json`)

```json
{
  "$schema": "./binaries.schema.json",
  "version": 1,
  "binaries": {
    "katana": {
      "version": "1.5.0",
      "url": "https://github.com/projectdiscovery/katana/releases/download/v1.5.0/katana_1.5.0_linux_amd64.zip",
      "sha256": "592890e5febaf5706d0a962d96299512418d6eccce6388cf1600e1f078ed359d",
      "format": "zip",
      "binary_in_archive": "katana"
    },
    "httpx": {
      "version": "1.9.0",
      "url": "https://github.com/projectdiscovery/httpx/releases/download/v1.9.0/httpx_1.9.0_linux_amd64.zip",
      "sha256": "54c6c91d61d3b82ba79f93633df04bb547f0c954d9d9b0fb8bcedf158f85ff2f",
      "format": "zip",
      "binary_in_archive": "httpx"
    },
    "kiterunner": {
      "version": "1.0.2",
      "url": "https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_amd64.tar.gz",
      "sha256": "6f0b70aabf747de592445a690281897eebbc45927e9264185d34ffb11637613b",
      "format": "tar.gz",
      "binary_in_archive": "kr"
    },
    "arjun": {
      "version": "2.2.7",
      "url": "https://files.pythonhosted.org/packages/04/22/c5b969720d2802de2248c2aac0414ee5ae234887cfe150564d591c73fb23/arjun-2.2.7.tar.gz",
      "sha256": "b193cdaf97bf7b0e8cd91a41da778639e01fd9738d5f666a8161377f475ce72e",
      "format": "pip_source",
      "install_into_venv": "venv-security"
    }
  },
  "wordlists": {
    "routes-large.kite": {
      "url": "https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz",
      "sha256": "e6f4d78f6e607d0352527dee0123ce1ff7ab18fe845ea898b7ca38e0c6a321f2",
      "format": "tar.gz",
      "extract_to": "wordlists/"
    },
    "arjun-extended-pt-en.txt": {
      "source": "local",
      "path": "scripts/install/wordlists/arjun-extended-pt-en.txt",
      "sha256": "TBD-computar-quando-arquivo-existir",
      "install_to": "wordlists/arjun-extended-pt-en.txt"
    }
  }
}
```

**Nota:** a entry `binary_in_archive` resolve a diferença entre `katana` (nome = filename), `httpx` (nome = filename), `kiterunner` (binário é `kr` dentro do tarball), e Arjun (pip install, não binary extract).

### MANIFEST.json schema (dentro do tarball) — diffs vs. binaries.json

```json
{
  "version": 1,
  "release_tag": "v2.0.0",
  "release_date": "2026-XX-XX",
  "binaries": {
    "katana": {
      "version": "1.5.0",
      "url": "./bin/katana_1.5.0_linux_amd64.zip",
      "sha256": "592890e5febaf5706d0a962d96299512418d6eccce6388cf1600e1f078ed359d",
      "format": "zip",
      "binary_in_archive": "katana"
    }
  },
  "wordlists": {
    "routes-large.kite": {
      "url": "./bin/routes-large.kite.tar.gz",
      "sha256": "e6f4d78f6e607d0352527dee0123ce1ff7ab18fe845ea898b7ca38e0c6a321f2"
    }
  }
}
```

**Regra de substituição:** URLs remotas → paths relativos `./bin/` e `./wordlists/`. Checksums permanecem iguais (valida integridade do tarball).

### Ordering diagram (`install.sh --update` flow)

```
1. Parse args → MODE=update
2. check_root
3. detect_distro (existing)
4. safe_reset_gate                  ← NOVO — aborta se dirty/ahead
5. configure_git (existing, para safe.directory)
6. preserve_paths_to_staging        ← NOVO — move para /tmp
7. systemctl stop samureye-api
8. git reset --hard origin/main
9. git clean -fdx
10. restore_paths_from_staging      ← NOVO — restaura com ownership
11. install_binaries (from binaries.json)   ← NOVO
12. install_wordlists                       ← NOVO
13. npm install + build + db:push (existing)
14. systemctl start samureye-api
15. verify (existing-style health check)
```

### bats-core test skeleton (`tests/install/test_safe_reset.bats`)

```bash
#!/usr/bin/env bats

setup() {
  export TMPDIR="$(mktemp -d)"
  export INSTALL_DIR="$TMPDIR/opt-samureye"
  git init --quiet --bare "$TMPDIR/remote.git"
  git clone --quiet "$TMPDIR/remote.git" "$INSTALL_DIR"
  cd "$INSTALL_DIR"
  echo "v1" > README.md && git add . && git commit -qm "init" && git push -q origin master
}

teardown() {
  rm -rf "$TMPDIR"
}

@test "safe_reset_gate aborts when working tree has untracked files" {
  cd "$INSTALL_DIR"
  echo "local-change" > untracked-file
  run bash -c "source /opt/samureye/install.sh && safe_reset_gate"
  [ "$status" -eq 1 ]
  [[ "$output" =~ "working tree suja" ]]
  # Crítico: untracked file ainda está presente (árvore não foi tocada)
  [ -f "$INSTALL_DIR/untracked-file" ]
}

@test "safe_reset_gate aborts when ahead of origin" {
  cd "$INSTALL_DIR"
  echo "ahead" >> README.md && git add . && git commit -qm "unpushed"
  run bash -c "source /opt/samureye/install.sh && safe_reset_gate"
  [ "$status" -eq 1 ]
  [[ "$output" =~ "ahead" ]]
}

@test "safe_reset_gate passes when clean and synced" {
  cd "$INSTALL_DIR"
  run bash -c "source /opt/samureye/install.sh && safe_reset_gate"
  [ "$status" -eq 0 ]
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Baixar nuclei com "latest" pattern (linhas 300-326 install.sh) | Manifest JSON pinado + SHA-256 hardcoded | Phase 8 | Reprodutibilidade + supply-chain defense |
| `git stash` + `git pull` (update.sh linhas 301-328) | `git reset --hard origin/main` após safe-gate + preserve-staging | Phase 8 | Elimina ambiguidade de stash; preserve-list é explícita |
| Backup pre-update + rollback pós-falha (update.sh linhas 214-295, 519-566) | Preserve-list (limitado a user artifacts) — sem rollback formal | Phase 8 | Simpler; AUTOUP (futuro) retoma backups formais |
| `update.sh` como entrada principal + `install.sh` como fresh install | `install.sh` como entrada única com 3 flags; `update.sh` = wrapper deprecado | Phase 8 | Um único fluxo para testar |
| `nuclei` versão latest via curl GitHub API | (mantido por ora — fora do escopo de INFRA-03, continua em Phase 8 não-alterado) | - | nuclei não está na lista INFRA-03, mas seria bom incluí-lo no manifest futuramente |

**Deprecated/outdated:**
- `update.sh` como script primário (vira wrapper em Phase 8, será removido em AUTOUP future milestone)
- Rollback via backup-restore (eliminado em Phase 8)
- Modo interativo com prompt (já deprecado em `install.sh` comentário linha 9)

## Open Questions

1. **Arjun deps transitive precisam ser vendoradas?**
   - What we know: Arjun é source-only no PyPI; `pip install arjun-2.2.7.tar.gz` puxa `requests`, `rich`, etc.
   - What's unclear: Deps transitive mudam com o tempo; sem `requirements.lock`, a árvore não é reprodutível entre instalações.
   - Recommendation: No `scripts/install/build-release.sh`, rode `pip download arjun==2.2.7 -d vendor/arjun/` e inclua o diretório `vendor/arjun/` no tarball. Em `install_arjun()`, use `pip install --no-index --find-links vendor/arjun arjun`. Para `--install` modo online, mantém comportamento online (sem vendor). **Planner deve decidir se isto é bloqueante ou não** — minha recomendação é sim, porque sem isso `--from-tarball` não é genuinamente offline para Arjun.

2. **Onde computar o SHA-256 de `arjun-extended-pt-en.txt`?**
   - What we know: O arquivo é commitado no repo; o SHA deve estar no `binaries.json`.
   - What's unclear: Se o arquivo é editado, o SHA muda — precisa de re-compute manual.
   - Recommendation: Adicione um `make update-manifest` / `scripts/install/update-manifest.sh` que recomputa SHAs de todos os arquivos locais (wordlists custom). Se `binaries.json` estiver inconsistente com o arquivo em disco, install.sh aborta no checksum gate — falha visível, não silenciosa.

3. **`routes-large.kite.tar.gz` deve ser mirrored nos Releases do SamurEye?**
   - What we know: O CDN assetnote tem o arquivo desde 2023-04-28; 36 MB.
   - What's unclear: Longevidade do CDN third-party.
   - Recommendation: **Não em Phase 8** (cada milestone tem escopo limitado). Quando construir o release tarball pela primeira vez, incluir o arquivo dentro do tarball é a mitigação principal. Adicionar entry `mirror_url` no manifest como preparação futura é opcional.

4. **O venv Python do Arjun deve reutilizar `$INSTALL_DIR/venv` (WinRM) ou ter venv próprio?**
   - What we know: O venv WinRM tem `pywinrm` + `requests-ntlm`. Arjun tem `requests` + outras deps.
   - What's unclear: Conflito de versões entre `requests` (pywinrm) e `requests` (arjun).
   - Recommendation: **Venv dedicado** (`$INSTALL_DIR/venv-security`) para isolamento. Nenhuma economia real em compartilhar, e isolamento evita heisenbugs quando Arjun muda deps.

5. **O `MANIFEST.json` no tarball deve estar assinado (GPG/cosign)?**
   - What we know: CONTEXT.md marca como discretion; recomendação era "não assinar em v2.0".
   - What's unclear: Se o cliente air-gapped já confia no processo de release manual, assinatura é overkill para v2.0.
   - Recommendation: Não assinar. Deixar para AUTOUP-02 (signed manifests) no future milestone. Documentar no `build-release.sh` que a decisão foi consciente.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | **bats-core** (novo — bash scripts) + **vitest 4.0.18** (já instalado — TypeScript/Node helpers) |
| Config file | `vitest.config.ts` (existente) + NOVO `tests/install/` dir para bats |
| Quick run command | `vitest run server/__tests__/systemUpdateService.test.ts` (testes afetados) + `bats tests/install/test_safe_reset.bats` |
| Full suite command | `npm test` (vitest full) + `bats tests/install/` (todos os .bats) |

**Instalação de bats-core (uma vez):**
```bash
apt install -y bats shellcheck
```

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| INFRA-01 | `safe_reset_gate` aborta em working tree suja (incluindo untracked) | integration (bats) | `bats tests/install/test_safe_reset.bats -f "untracked"` | ❌ Wave 0 |
| INFRA-01 | `safe_reset_gate` aborta em commits ahead de origin | integration (bats) | `bats tests/install/test_safe_reset.bats -f "ahead"` | ❌ Wave 0 |
| INFRA-01 | `safe_reset_gate` passa em árvore limpa e sincronizada | integration (bats) | `bats tests/install/test_safe_reset.bats -f "passes"` | ❌ Wave 0 |
| INFRA-01 | Mensagem de abort sugere `git push` / `git stash` com comando exato | integration (bats) | `bats tests/install/test_safe_reset.bats -f "recovery hint"` | ❌ Wave 0 |
| INFRA-02 | Array `PRESERVE_PATHS` cobre todos paths minimum-set do CONTEXT.md | unit (bats) | `bats tests/install/test_preserve_paths.bats -f "paths list"` | ❌ Wave 0 |
| INFRA-02 | `.planning/`, `.env`, `backups/` são preservados após --update simulado | integration (bats, temp fixture) | `bats tests/install/test_preserve_paths.bats -f "preserves after reset"` | ❌ Wave 0 |
| INFRA-02 | Ownership original (uid/gid) preservado após restauração | integration (bats) | `bats tests/install/test_preserve_paths.bats -f "ownership"` | ❌ Wave 0 |
| INFRA-02 | Falha no `mv` de restauração deixa staging intacto + imprime caminho | integration (bats) | `bats tests/install/test_preserve_paths.bats -f "restore failure"` | ❌ Wave 0 |
| INFRA-03 | `install_binary katana` baixa e instala em `bin/katana` com SHA-256 correto | integration (bats, offline fixture) | `bats tests/install/test_binaries_install.bats -f "katana"` | ❌ Wave 0 |
| INFRA-03 | `install_binary` aborta com exit 1 em SHA-256 mismatch | integration (bats, mocked curl) | `bats tests/install/test_binaries_install.bats -f "checksum mismatch aborts"` | ❌ Wave 0 |
| INFRA-03 | `install_binary` remove arquivo temp após mismatch (no garbage) | integration (bats) | `bats tests/install/test_binaries_install.bats -f "cleanup on mismatch"` | ❌ Wave 0 |
| INFRA-03 | Manifest `binaries.json` é JSON válido e tem schema esperado | unit (vitest) | `vitest run tests/unit/binaries-manifest.test.ts` | ❌ Wave 0 |
| INFRA-03 | Arjun instalado via pip em venv-security com SHA verificado | integration (bats + venv real, slower) | `bats tests/install/test_binaries_install.bats -f "arjun venv"` | ❌ Wave 0 |
| INFRA-04 | `routes-large.kite` existe em `wordlists/` após install com SHA correto | integration (bats) | `bats tests/install/test_wordlists.bats -f "routes-large"` | ❌ Wave 0 |
| INFRA-04 | `arjun-extended-pt-en.txt` presente em `scripts/install/wordlists/` e copiado para `wordlists/` | integration (bats) | `bats tests/install/test_wordlists.bats -f "arjun wordlist"` | ❌ Wave 0 |
| INFRA-04 | Nenhum `curl` / `wget` é executado em runtime do appliance (post-install) | manual-only | Execução real + `strace -e openat,execve` no server + grep por URLs externas | N/A (manual) |
| INFRA-05 | `build-release.sh v2.0.0` gera tarball com layout flat correto | integration (bats) | `bats tests/install/test_tarball_build.bats -f "layout"` | ❌ Wave 0 |
| INFRA-05 | `install.sh --from-tarball /path/to/tarball` instala end-to-end sem acesso de rede | integration (bats, simulado com `unshare -n`) | `bats tests/install/test_tarball_install.bats -f "offline install"` | ❌ Wave 0 |
| INFRA-05 | `update.sh` (wrapper) imprime banner DEPRECATED em stderr | unit (bats) | `bats tests/install/test_update_wrapper.bats -f "banner"` | ❌ Wave 0 |
| INFRA-05 | `update.sh` delega para `install.sh --update` com exit code propagado | integration (bats + mock install.sh) | `bats tests/install/test_update_wrapper.bats -f "delegates"` | ❌ Wave 0 |
| INFRA-05 | systemd units (samureye-update.path/.service) não são modificados em Phase 8 | regression (bats + diff contra snapshot) | `bats tests/install/test_systemd_untouched.bats` | ❌ Wave 0 |
| INFRA-05 | systemUpdateService.test.ts / subscriptionService.test.ts continuam verdes | unit (vitest existente) | `vitest run server/__tests__/systemUpdateService.test.ts server/__tests__/subscriptionService.test.ts` | ✅ existente |

### Sampling Rate

- **Per task commit:** `bats tests/install/test_<affected>.bats` (tempo esperado: < 10s por arquivo bats)
- **Per wave merge:** `npm test && bats tests/install/` (full vitest + full bats — tempo esperado: < 60s)
- **Phase gate:** Execução real em VM Ubuntu limpa: `install.sh --install` + `install.sh --update` + `install.sh --from-tarball` com binários reais e verificação de SHA-256 contra checksum files do GitHub (tempo: 10-15 min, manual-ish — pode ser automatizado num GitHub Action matrix)

### Wave 0 Gaps

- [ ] `tests/install/` diretório — criar
- [ ] `tests/install/helpers.bash` — setup git remote em tmpdir, fixtures de manifest mockado, mock de curl
- [ ] `tests/install/test_safe_reset.bats` — INFRA-01 coverage
- [ ] `tests/install/test_preserve_paths.bats` — INFRA-02 coverage
- [ ] `tests/install/test_binaries_install.bats` — INFRA-03 coverage
- [ ] `tests/install/test_wordlists.bats` — INFRA-04 coverage
- [ ] `tests/install/test_tarball_build.bats` — INFRA-05 (build side)
- [ ] `tests/install/test_tarball_install.bats` — INFRA-05 (install side)
- [ ] `tests/install/test_update_wrapper.bats` — INFRA-05 (deprecation)
- [ ] `tests/install/test_systemd_untouched.bats` — INFRA-05 (regression)
- [ ] `tests/unit/binaries-manifest.test.ts` — vitest para validação de schema JSON
- [ ] Framework install: `apt install -y bats shellcheck` (uma vez, docs em README)
- [ ] GitHub Action `.github/workflows/release.yml` — builda tarball e anexa em releases (INFRA-05) — opcional para Phase 8 se build-release.sh rodar manualmente

## Sources

### Primary (HIGH confidence)

- **katana v1.5.0 release manifest** — https://github.com/projectdiscovery/katana/releases/tag/v1.5.0 (verificado 2026-04-18, published 2026-03-10)
- **katana checksums file** — `curl -sL https://github.com/projectdiscovery/katana/releases/download/v1.5.0/katana-linux-checksums.txt` (SHA-256 extraído diretamente 2026-04-18)
- **httpx v1.9.0 release manifest** — https://github.com/projectdiscovery/httpx/releases/tag/v1.9.0 (verificado 2026-04-18, published 2026-03-09)
- **httpx checksums file** — `curl -sL https://github.com/projectdiscovery/httpx/releases/download/v1.9.0/httpx_1.9.0_checksums.txt` (SHA-256 extraído 2026-04-18)
- **kiterunner v1.0.2 release** — https://github.com/assetnote/kiterunner/releases/tag/v1.0.2 (último release stable, published 2021-04-11)
- **kiterunner checksums** — `curl -sL https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_checksums.txt` (SHA-256 extraído 2026-04-18)
- **Arjun PyPI 2.2.7** — https://pypi.org/pypi/arjun/json — `.urls[0].digests.sha256` (verificado 2026-04-18)
- **routes-large.kite.tar.gz** — `curl -sL https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz | sha256sum` (computado localmente 2026-04-18)
- **routes-small.kite.tar.gz** — idem (computado localmente 2026-04-18, incluído como reference/fallback)
- **install.sh atual** — `/opt/samureye/install.sh` linhas 22, 31-41, 103, 158-165, 300-326, 440-464, 513
- **update.sh atual** — `/opt/samureye/update.sh` linhas 102-156, 160-213, 297-329, 519-566
- **systemUpdateService.ts** — `/opt/samureye/server/services/systemUpdateService.ts` (integration constraints)
- **git-scm git-status docs** — https://git-scm.com/docs/git-status (porcelain format spec)
- **CONTEXT.md (Phase 8)** — decisões do usuário sobre safe-reset, preserve-list, pinning strategy

### Secondary (MEDIUM confidence)

- **Brandon Rozek — Git ahead/behind detection pattern** — https://brandonrozek.com/blog/ahead-behind-git/ (verificado com git-scm.com official)
- **Baeldung — Shell script git status parsing** — https://www.baeldung.com/linux/git-script-check-clean-directory (confirma `git status --porcelain` para scripting)
- **Hak5 — SHA-256 verification in bash** — https://docs.hak5.org/general/how-to-verify-the-sha256-checksum-of-a-downloaded-file/ (pattern `sha256sum | awk '{print $1}'`)
- **bats-core documentation** — https://bats-core.readthedocs.io/en/stable/writing-tests.html (setup/teardown patterns)
- **ShellCheck** — https://www.shellcheck.net/ (static analysis tool for scripts)
- **Kiterunner README** — https://github.com/assetnote/kiterunner (confirmação das URLs de wordlist e nome do binário = `kr`)

### Tertiary (LOW confidence)

- **PyPI arjun install recommendation via pipx** — https://pypi.org/project/arjun/ — menciona pipx; o CONTEXT.md e esta research recomendam venv dedicado, divergindo da sugestão oficial. Justificativa: isolamento + alinhamento com estrutura existente do WinRM venv.
- **Assetnote CDN longevity** — não há SLA público. Risco documentado no Pitfall 5 e endereçado via tarball bundling.

## Metadata

**Confidence breakdown:**
- Standard stack: **HIGH** — bash/jq/curl/sha256sum são primitivos universais; todos já instalados ou triviais
- Architecture: **HIGH** — padrão de preserve-staging já existe em `install.sh` 440-464, safe-reset gate é well-established; `--from-tarball` é pattern comum em releases self-hosted
- Pitfalls: **HIGH** — 10 pitfalls cobrem os modos de falha principais; `git diff --quiet` vs `git status --porcelain` é o maior risco silencioso
- Binary pinning (versions + SHA-256): **HIGH** — todos 4 checksums lidos/computados em 2026-04-18 a partir de fontes autoritativas (GitHub Release checksums.txt + PyPI JSON + CDN compute local)
- Wordlist availability: **MEDIUM** — CDN Assetnote vivo, mas third-party; `arjun-extended-pt-en.txt` ainda não existe (usuário deve criar/commitar)
- Validation architecture (bats-core approach): **MEDIUM** — bats-core é standard para testes de bash, mas requer instalar novo toolkit no CI

**Research date:** 2026-04-18
**Valid until:** 2026-05-18 (30 dias para binary versions — Katana/httpx têm release cadence ~mensal; re-verificar SHAs antes de implementar se > 30 dias passaram)
