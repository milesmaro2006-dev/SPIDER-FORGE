#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  SpiderForge — Installer
#  Linux / macOS / WSL
#
#  Does NOT modify system packages or run apt upgrade/update.
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

[ -f "pyproject.toml" ] || die "pyproject.toml not found. Invalid SpiderForge directory."

# ─── 2. Python check ──────────────────────────────────────────

check_python() {
    local py

    py="$(command -v python3 || true)"

    [ -z "$py" ] && die \
        "Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+ is required. python3 was not found."

    if ! "$py" -c "
import sys
sys.exit(
    0 if sys.version_info[:2] >= (${MIN_PY_MAJOR}, ${MIN_PY_MINOR}) else 1
)
"; then
        die \
            "Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+ is required. Found: $("$py" --version 2>&1)"
    fi

    ok "Python: $("$py" --version 2>&1)"
}

# ─── 3. pipx check ────────────────────────────────────────────

ensure_pipx() {
    export PATH="$HOME/.local/bin:$PATH"

    if command -v pipx >/dev/null 2>&1; then
        ok "pipx: $(pipx --version)"
        return 0
    fi

    die "pipx is required but was not found.

Install pipx using your operating system package manager,
then run this installer again.

No system package changes were made by SpiderForge."
}

# ─── 4. Install SpiderForge ──────────────────────────────────

install_spiderforge() {
    log "Installing ${APP_NAME} with full feature set..."

    # Core + Web Dashboard + PDF + Browser
    pipx install --force \
        ".[web,pdf,browser]"

    ok "${APP_NAME} installed"
}

# ─── 5. Browser setup ─────────────────────────────────────────

install_browser() {
    export PATH="$HOME/.local/bin:$PATH"

    if ! command -v spiderforge >/dev/null 2>&1; then
        die "SpiderForge command was not found after installation."
    fi

    if ! command -v playwright >/dev/null 2>&1; then
        warn "Playwright command was not found."
        warn "Browser support may require manual Playwright setup."
        return 0
    fi

    log "Installing Chromium for Playwright..."

    if playwright install chromium; then
        ok "Playwright Chromium ready"
    else
        warn "Chromium installation failed."
        warn "SpiderForge core features remain installed."
        warn "Browser-based features may require manual Playwright setup."
    fi
}

# ─── 6. Create SpiderForge directories ───────────────────────

create_dirs() {
    mkdir -p "$HOME/.spiderforge/workspaces"
    mkdir -p "$HOME/.spiderforge/logs"
    mkdir -p "$HOME/.config/spiderforge"

    ok "SpiderForge directories ready"
}

# ─── 7. Verify installation ──────────────────────────────────

health_check() {
    export PATH="$HOME/.local/bin:$PATH"

    command -v "$APP_NAME" >/dev/null 2>&1 || \
        die "${APP_NAME} command is not available on PATH."

    log "Running SpiderForge doctor..."

    if "$APP_NAME" doctor; then
        ok "SpiderForge doctor completed successfully"
    else
        die "SpiderForge doctor reported errors."
    fi
}

# ─── Main ─────────────────────────────────────────────────────

banner

check_python
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
