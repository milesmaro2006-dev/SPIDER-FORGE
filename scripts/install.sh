#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  SpiderForge — POSIX installer (Linux / macOS / WSL)
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

APP_NAME="spiderforge"
MIN_PY="3.10"

log()  { printf '\033[36m[%s]\033[0m %s\n' "$APP_NAME" "$*"; }
ok()   { printf '\033[32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[X]\033[0m %s\n' "$*" >&2; exit 1; }

banner() {
cat <<'EOF'

   ███████╗██████╗ ██╗██████╗ ███████╗██████╗
   ██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔══██╗
   ███████╗██████╔╝██║██║  ██║█████╗  ██████╔╝
   ╚════██║██╔═══╝ ██║██║  ██║██╔══╝  ██╔══██╗
   ███████║██║     ██║██████╔╝███████╗██║  ██║
   ╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝
             SpiderForge — installer
EOF
}

# ─── 1. Python check ──────────────────────────────────────────
check_python() {
    local py
    py="$(command -v python3 || true)"
    [ -z "$py" ] && die "python3 not found. Install Python ${MIN_PY}+."

    if ! "$py" -c "import sys; sys.exit(0 if sys.version_info[:2] >= (3,10) else 1)"; then
        die "Python ${MIN_PY}+ required. Found: $("$py" --version 2>&1)"
    fi
    ok "Python: $("$py" --version 2>&1)"
}

# ─── 2. pipx ──────────────────────────────────────────────────
ensure_pipx() {
    if command -v pipx >/dev/null 2>&1; then
        ok "pipx: $(pipx --version)"
        return
    fi
    warn "pipx not found — installing..."
    python3 -m pip install --user --upgrade pipx
    python3 -m pipx ensurepath || true
    export PATH="$HOME/.local/bin:$PATH"
    command -v pipx >/dev/null 2>&1 || die "pipx install failed"
    ok "pipx installed"
}

# ─── 3. Locate project ────────────────────────────────────────
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

# ─── 4. Install core ──────────────────────────────────────────
install_core() {
    log "Installing ${APP_NAME} from $REPO_DIR..."
    pipx install --force . 2>&1 | tail -5
    ok "${APP_NAME} installed"
}

# ─── 5. Optional: web ─────────────────────────────────────────
install_web() {
    printf '\n[?] Install Web Dashboard (fastapi + uvicorn)? [y/N] '
    read -r answer
    case "$answer" in
        [yY]|[yY][eE][sS])
            pipx inject "$APP_NAME" fastapi 'uvicorn[standard]' 2>&1 | tail -3
            ok "Web Dashboard ready"
            ;;
        *) log "Skipped web dashboard" ;;
    esac
}

# ─── 6. Optional: PDF ─────────────────────────────────────────
install_pdf() {
    printf '\n[?] Install PDF export (weasyprint)? [y/N] '
    read -r answer
    case "$answer" in
        [yY]|[yY][eE][sS])
            warn "WeasyPrint needs system libs (pango, cairo). See README."
            pipx inject "$APP_NAME" weasyprint 2>&1 | tail -3
            ok "PDF export installed"
            ;;
        *) log "Skipped PDF" ;;
    esac
}

# ─── 7. Data dirs ─────────────────────────────────────────────
create_dirs() {
    mkdir -p "$HOME/.spiderforge/workspaces"
    mkdir -p "$HOME/.spiderforge/logs"
    mkdir -p "$HOME/.config/spiderforge"
    ok "Created ~/.spiderforge and ~/.config/spiderforge"
}

# ─── 8. Health check ──────────────────────────────────────────
health_check() {
    export PATH="$HOME/.local/bin:$PATH"
    if command -v "$APP_NAME" >/dev/null 2>&1; then
        log "Running doctor..."
        "$APP_NAME" doctor || true
    else
        warn "${APP_NAME} not on PATH yet. Restart your shell or run:"
        echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
}

# ─── Main ─────────────────────────────────────────────────────
banner
check_python
ensure_pipx
install_core
install_web
install_pdf
create_dirs
health_check

echo
ok "Installation complete!"
echo "Run: spiderforge"
