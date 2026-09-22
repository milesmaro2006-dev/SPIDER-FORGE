#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  SpiderForge — POSIX installer (Linux / macOS / WSL)
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

APP_NAME="spiderforge"
MIN_PY_MAJOR=3
MIN_PY_MINOR=11

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

# ─── 1. Locate project ────────────────────────────────────────
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

# ─── 2. Python check ──────────────────────────────────────────
check_python() {
    local py

    py="$(command -v python3 || true)"

    [ -z "$py" ] && die "python3 not found. Install Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+."

    if ! "$py" -c "
import sys
sys.exit(
    0 if sys.version_info[:2] >= (${MIN_PY_MAJOR}, ${MIN_PY_MINOR}) else 1
)
"; then
        die "Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+ required. Found: $("$py" --version 2>&1)"
    fi

    ok "Python: $("$py" --version 2>&1)"
}

# ─── 3. Linux system dependencies ────────────────────────────
install_linux_dependencies() {
    [ "$(uname -s)" != "Linux" ] && return 0

    if ! command -v apt-get >/dev/null 2>&1; then
        warn "apt-get not found. Skipping automatic Linux system dependency installation."
        warn "Make sure Python venv/build tools and WeasyPrint system libraries are installed."
        return 0
    fi

    log "Installing required Linux system dependencies..."

    sudo apt-get update

    sudo apt-get install -y \
        python3-venv \
        python3-dev \
        build-essential \
        pipx \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libharfbuzz0b \
        libharfbuzz-subset0 \
        libffi-dev \
        libjpeg-dev \
        libopenjp2-7-dev

    ok "Linux system dependencies ready"
}

# ─── 4. pipx ──────────────────────────────────────────────────
ensure_pipx() {
    if command -v pipx >/dev/null 2>&1; then
        ok "pipx: $(pipx --version)"
        return
    fi

    die "pipx installation failed or is unavailable."
}

# ─── 5. Install SpiderForge ──────────────────────────────────
install_spiderforge() {
    log "Installing ${APP_NAME} with full feature set..."

    pipx install --force \
        ".[web,pdf,browser]"

    ok "${APP_NAME} installed"
}

# ─── 6. Browser setup ─────────────────────────────────────────
install_browser() {
    export PATH="$HOME/.local/bin:$PATH"

    if ! command -v spiderforge >/dev/null 2>&1; then
        die "SpiderForge command not found after installation."
    fi

    log "Installing Playwright browser..."

    if spiderforge --help >/dev/null 2>&1; then
        if command -v playwright >/dev/null 2>&1; then
            playwright install chromium
            ok "Playwright Chromium ready"
        else
            warn "Playwright command not exposed by pipx environment."
            warn "Browser support may require manual Playwright setup."
        fi
    fi
}

# ─── 7. Data directories ─────────────────────────────────────
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

        if "$APP_NAME" doctor; then
            ok "SpiderForge doctor passed"
        else
            die "SpiderForge doctor reported errors."
        fi
    else
        die "${APP_NAME} command not found."
    fi
}

# ─── Main ─────────────────────────────────────────────────────
banner

check_python
install_linux_dependencies
ensure_pipx
install_spiderforge
create_dirs
install_browser
health_check

echo
ok "Installation complete!"
echo
echo "Run:"
echo "  spiderforge"
echo
