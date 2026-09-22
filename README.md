<h1 align="center">🕷️ SpiderForge 🕷️</h1>

<p align="center">
  <b>Automated Web Reconnaissance, Crawling & Security Assessment Framework</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-3.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.11%2B-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows%20(WSL)-orange.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen.svg" alt="Status">
  <img src="https://img.shields.io/badge/Tests-304%20passing-success.svg" alt="Tests">
</p>

<p align="center">
  A modular security assessment framework for penetration testers, bug bounty hunters, and red teamers.<br>
  Scope-aware scanning. Real findings. Professional reports. Standalone web UI. Built-in anonymity layer.
</p>

---

## ⚡ Quick Start (one command)

```bash
git clone https://github.com/milesmaro2006-dev/spider-forge.git
cd spider-forge/scripts
bash install.sh
```

That's it. The installer is fully automated — no questions, no system package changes, no apt calls.

Then launch:

```bash
spiderforge
```

Pick `[1] Run Full Assessment` or `[2] Launch Web Dashboard` from the interactive menu.

---

## 🖼️ Showcase

<details open>
<summary><b>1. Interactive Control Center</b></summary>
<br>
<img src="docs/images/1-interactive-cli.png" alt="Interactive CLI" width="900" />
</details>

<details>
<summary><b>2. Persistent Web Dashboard (FastAPI GUI)</b></summary>
<br>
<img src="docs/images/2-web-dashboard.png" alt="Web Dashboard" width="1100" />
</details>

<details>
<summary><b>3. Scans & Assessment History</b></summary>
<br>
<img src="docs/images/3-scans-page.png" alt="Scans Page" width="1100" />
</details>

<details>
<summary><b>4. System Diagnostics (Pre-flight Doctor)</b></summary>
<br>
<img src="docs/images/4-doctor.png" alt="Doctor" width="900" />
</details>
---

## 📦 Installation

### Requirements

| Requirement | Notes |
|---|---|
| Linux / macOS / WSL | Native Windows is not supported (use WSL) |
| Python 3.11+ | 3.10 is not supported |
| pipx | Required. Install via your OS package manager if missing |
| git | For cloning the repository |

SpiderForge's installer does not touch system packages. If `pipx` or Python is missing, the installer stops and tells you what to install — it never runs `apt update`, `apt upgrade`, or `apt install`.

### Install

```bash
git clone https://github.com/milesmaro2006-dev/spider-forge.git
cd spider-forge/scripts
bash install.sh
```

What the installer does, in order:

1. Verifies Python 3.11+
2. Verifies pipx
3. Installs SpiderForge via `pipx install --force ".[web,pdf,browser]"`
4. Creates `~/.spiderforge/workspaces`, `~/.spiderforge/logs`, `~/.config/spiderforge`
5. Downloads Playwright Chromium (~300 MB, first time only)
6. Runs `spiderforge doctor` and reports health

### Verify installation

```bash
spiderforge doctor
```

Expected output:

```text
╭───────────────────────────────────────────╮
│ Checks: 22   PASS: 22   WARN: 0   FAIL: 0 │
│ System Status: Ready                      │
╰───────────────────────────────────────────╯
```

### PyPI install

Not yet available. Tracked under Phase F — Ecosystem in the roadmap below.

### Developer install (editable)

For contributors who need to edit the source live:

```bash
git clone https://github.com/milesmaro2006-dev/spider-forge.git
cd spider-forge
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[web,pdf,browser,dev]"
python -m playwright install chromium
```

---

## 🚀 Usage

### Interactive mode

```bash
spiderforge
```

You'll see the interactive control center:

```text
[1] 🎯 Run Full Assessment (Scan)
[2] 🌐 Launch Web Dashboard (GUI)
[3] 🔍 Run Reconnaissance Only
[4] 📊 Generate Reports
[5] 🩺 Run System Diagnostics (Doctor)
[6] 🚪 Exit
```

### Direct commands

```bash
# Full assessment
spiderforge scan run https://example.com

# Reconnaissance only
spiderforge recon run https://example.com

# Reports from a stored scan
spiderforge report generate --id 42 --format json,md,html,pdf

# Interactive report picker
spiderforge report generate

# System health check
spiderforge doctor
spiderforge doctor --json
spiderforge doctor --cli-only
```

---

## 🛡️ Anonymity & Privacy Layer (v3.0.0 — New)

SpiderForge v3.0.0 ships with a built-in anonymity layer for authorized engagements where source IP hygiene, request pacing, and fingerprint normalization matter.

Every request still flows through `SafeHttpClient` with SSRF protection intact — the anonymity layer is a wrapper, not a bypass.

### What it does

- Proxy rotation (HTTP / HTTPS / SOCKS4 / SOCKS5) with health checks
- User-Agent rotation from a curated pool of real-world browser signatures
- Header profile normalization (Chrome / Firefox / Safari / curl / mobile)
- Request pacing (fixed / jittered / adaptive delays)
- Cookie jar isolation per scan workspace
- DNS-over-HTTPS (Cloudflare / Google / Quad9 / custom resolver)
- Fingerprint randomization (TLS hints, header order, Accept-Language)
- Pre-flight health checks — scan fails loudly if the anonymity layer is unhealthy

### Enable from CLI

```bash
# Check status
spiderforge anonymity status

# Enable the anonymity layer for all scans
spiderforge anonymity enable

# Add a proxy
spiderforge anonymity proxy add socks5://127.0.0.1:9050
spiderforge anonymity proxy add http://user:pass@proxy.example.com:8080

# Health-check all configured proxies
spiderforge anonymity proxy test

# Rotate to the next healthy proxy
spiderforge anonymity proxy rotate

# Rotate the User-Agent
spiderforge anonymity ua rotate

# Set a header profile
spiderforge anonymity headers chrome

# Configure request pacing
spiderforge anonymity pacing --min 1.5 --max 4.0 --mode jitter

# Enable DNS-over-HTTPS
spiderforge anonymity doh enable --resolver cloudflare

# Randomize TLS / HTTP fingerprint
spiderforge anonymity fingerprint randomize

# End-to-end check
spiderforge anonymity test
```

### Auto-load in scans

When anonymity is enabled, `spiderforge scan run` auto-loads the layer. If the proxy is unreachable, the scan fails immediately with a fatal error — no silent fallback to your real IP.

```bash
spiderforge scan run https://example.com --anonymity
```

### 15 anonymity subcommands

| Command | Purpose |
|---|---|
| `anonymity status` | Show current anonymity state |
| `anonymity enable` | Enable the anonymity layer |
| `anonymity disable` | Disable the anonymity layer |
| `anonymity proxy add` | Add a proxy (HTTP/HTTPS/SOCKS4/SOCKS5) |
| `anonymity proxy list` | List configured proxies |
| `anonymity proxy test` | Health-check all proxies |
| `anonymity proxy remove` | Remove a proxy by ID |
| `anonymity proxy rotate` | Rotate to next healthy proxy |
| `anonymity ua` | List / rotate User-Agents |
| `anonymity headers` | Set / inspect header profile |
| `anonymity pacing` | Configure request pacing |
| `anonymity cookies` | Clear or inspect cookie jar |
| `anonymity doh` | Enable / disable DNS-over-HTTPS |
| `anonymity fingerprint` | Randomize TLS / HTTP fingerprint |
| `anonymity test` | End-to-end anonymity health check |

### Configuration

`~/.config/spiderforge/anonymity.toml`:

```toml
[anonymity]
enabled = true
fail_loud = true

[anonymity.proxy]
rotation = "round-robin"      # round-robin | random | sticky
health_check_interval = 300   # seconds
timeout = 10.0

[anonymity.pacing]
mode = "jitter"               # fixed | jitter | adaptive
min_delay = 1.5
max_delay = 4.0

[anonymity.doh]
enabled = true
resolver = "cloudflare"       # cloudflare | google | quad9 | custom

[anonymity.fingerprint]
randomize_tls = true
randomize_header_order = true
randomize_accept_language = true
```

> ⚠️ **Legal:** the anonymity layer is for authorized engagements only. It does not grant permission to test systems you don't own.

---

## 🌐 Web Dashboard

Fully standalone — no project directory required.

### Launch

```bash
# Foreground (Ctrl+C to stop)
spiderforge web --foreground

# Background (detached — server survives shell exit)
spiderforge web

# Custom bind address / port
spiderforge web --host 0.0.0.0 --port 9000

# Do not open the browser
spiderforge web --no-browser

# Reset saved web config and re-run the first-run wizard
spiderforge web --reset-config
```

### First-run wizard

On first launch, SpiderForge asks for:

- Port (default 8000)
- Auto-open browser (yes / no)

Preferences are saved to `~/.spiderforge/web.toml`:

```toml
[web]
host = "127.0.0.1"
port = 8000
auto_open_browser = true
theme = "dark"
accent = "blue"
first_run_done = true
```

Skip the wizard in scripts:

```bash
spiderforge web --port 9000 --no-browser
```

### Features

- Live target scanning with real-time finding feed
- Severity-badged finding cards (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- Sortable scan history
- Downloadable reports: HTML / JSON / Markdown / PDF / ZIP bundle
- REST API (`/api/*`) for automation
- Dark theme, responsive layout

### Environment overrides

| Variable | Purpose |
|---|---|
| `SPIDERFORGE_ROOT` | Force a specific backend root directory |
| `SPIDERFORGE_FRONTEND_DIR` | Force a specific frontend directory |
| `SPIDERFORGE_DEBUG` | Enable verbose logging + tracebacks |

---

## 🧭 CLI Commands (17 total)

| Command | Description |
|---|---|
| `spiderforge scan` | Run a full security assessment |
| `spiderforge recon` | Passive + active reconnaissance |
| `spiderforge crawl` | Async crawler only |
| `spiderforge discover` | Endpoint / API discovery |
| `spiderforge browser` | Playwright-driven browser checks |
| `spiderforge report` | Generate reports (JSON/MD/HTML/PDF) |
| `spiderforge scans` | List / inspect stored scans |
| `spiderforge findings` | Query findings across scans |
| `spiderforge history` | Command history + replay |
| `spiderforge modules` | List loaded analysis modules |
| `spiderforge integrations` | External tools (nmap, nuclei, ffuf, …) |
| `spiderforge scope` | Manage scope files |
| `spiderforge anonymity` | Anonymity & privacy layer (15 subcommands) |
| `spiderforge config` | Inspect / edit configuration |
| `spiderforge doctor` | System health check |
| `spiderforge web` | Web dashboard |
| `spiderforge update` | Self-update check |

Global flags:

```bash
spiderforge --version
spiderforge --help
spiderforge <command> --help
```

---

## 🔍 Scanners

| Module | Type | Severity Range |
|---|---|---|
| Security Headers | Passive | Low / Info |
| SQL Injection (Error-Based) | Active | High |
| SQL Injection (Blind) | Active | High |
| Reflected XSS | Active | Medium / High |
| Cookie Security | Passive | Low |
| CORS Misconfiguration | Passive | Medium |
| Open Redirects | Active | Medium |
| SSRF Candidates | Active | High |
| SSTI | Active | High |
| Command Injection Candidates | Active | High |
| Path Traversal | Active | High |
| File Upload Security | Active | Medium |
| IDOR Candidates | Active | Medium |

Detection modules assist authorized security assessments. Always manually validate results before treating them as confirmed vulnerabilities.

---

## 🏗️ How It Works

```text
Target
  │
  ▼
Scope Validation
  │
  ▼
Reconnaissance ──► DNS / HTTP / TLS / Tech fingerprint
  │
  ▼
HTTP Probing
  │
  ▼
Async Crawling
  │
  ▼
Endpoint & API Discovery
  │
  ▼
Security Analysis ──► (optional: Anonymity Layer)
  │
  ▼
Evidence Collection
  │
  ▼
Finding Management
  │
  ▼
Report Generation ──► JSON / MD / HTML / PDF
```

Design principles:

- **Scope First** — every request is validated against scope before dispatch
- **Evidence Driven** — every finding carries enough evidence to reproduce it
- **Safe by default** — all traffic flows through `SafeHttpClient` (SSRF-aware, no raw `requests`/`httpx` calls)
- **Modular** — recon, crawling, discovery, analysis, evidence, reporting are independent
- **Fail-loud** — if anonymity is enabled and the proxy is down, the scan aborts (no silent fallback)

---

## 📁 Project Structure

```text
spider-forge/
├── spiderforge/                  # Core Python package
│   ├── __init__.py               # __version__ = "3.0.0"
│   ├── __main__.py
│   ├── analysis/                 # 13 files — analysis modules
│   ├── anonymity/                # 9 files  — Phase C ✨
│   ├── browser/                  # 5 files  — Playwright
│   ├── cli/                      # 21 files — Phase B + C ✨
│   ├── config/                   # web_config + anonymity_config ✨
│   ├── core/                     # engine + exceptions ✨
│   ├── crawler/                  # 14 files — async crawler
│   ├── database/                 # 6 files  — SQLAlchemy
│   ├── discovery/                # 10 files — endpoint / API discovery
│   ├── evidence/                 # 7 files  — evidence + hashing
│   ├── findings/                 # 9 files  — lifecycle + CVSS
│   ├── integrations/             # 6 files  — external tools
│   ├── network/                  # 7 files  — SafeHttpClient ✨
│   ├── recon/                    # 7 files  — DNS / HTTP / tech
│   ├── reporting/                # 10 files — JSON/MD/HTML/PDF
│   ├── scanners/                 # 7 files  — security scanners
│   ├── scope/                    # 5 files  — scope validation
│   └── utils/                    # 6 files  — logging, hashing, time
│
├── backend/                      # FastAPI web backend
│   ├── main.py                   # routes + static serving ✨
│   ├── reporting.py              # canonical report renderers
│   └── static/frontend/          # packaged web UI
│
├── frontend/                     # Source frontend (mirror)
├── scripts/
│   ├── install.sh                # POSIX bash installer ✨
│   └── install.ps1               # Windows legacy
├── examples/
│   ├── config.yaml
│   └── scope.yaml
├── tests/
│   ├── unit/                     # 17 files
│   ├── integration/              # test_e2e.py
│   └── security/                 # test_no_direct_http.py, test_ssrf.py
├── .github/workflows/ci.yml
├── pyproject.toml
├── requirements.txt
├── CHANGELOG.md
├── SECURITY.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── LICENSE
├── Makefile
├── .gitignore
└── README.md
```

---

## ⚙️ Configuration

Config lives under `~/.config/spiderforge/`. Data lives under `~/.spiderforge/`.

`~/.config/spiderforge/config.yaml`:

```yaml
scanner:
  concurrency: 20
  timeout: 20.0
  max_depth: 5
  aggressive: false
recon:
  subdomains: true
  ports: false
  technologies: true
browser:
  enabled: false
  screenshots: false
reporting:
  enable_json: true
  enable_html: true
  enable_markdown: true
  enable_pdf: false
logging:
  level: INFO
```

`~/.spiderforge/web.toml`:

```toml
[web]
host = "127.0.0.1"
port = 8000
auto_open_browser = true
theme = "dark"
accent = "blue"
first_run_done = true
```

`~/.config/spiderforge/anonymity.toml`:

See the **Anonymity & Privacy Layer** section above for the full schema.

### Data directory

```text
~/.spiderforge/
├── spiderforge.db        # SQLite database
├── web.toml              # Web dashboard preferences
├── logs/
├── reports/
└── workspaces/
```

---

## 🩺 Troubleshooting

### `spiderforge web` says "Could not find the SpiderForge backend"

Run `spiderforge web` from inside the project checkout, or

Set `SPIDERFORGE_ROOT=/path/to/spider-forge`, or

Reinstall: `pipx install --force .` to refresh site-packages

### Frontend shows JSON `{"status": "online"}` instead of the UI

The frontend bundle wasn't shipped. Fix:

```bash
cd /path/to/spider-forge
pipx install --force ".[web,pdf,browser]"
```

Or set `SPIDERFORGE_FRONTEND_DIR=/path/to/frontend`.

### PDF export fails

WeasyPrint needs system libraries. SpiderForge's installer does not install them automatically (to avoid touching system packages).

If PDF is a hard requirement, install these manually with your OS package manager:

- **Debian / Ubuntu / Kali:** `libpango-1.0-0`, `libpangoft2-1.0-0`, `libcairo2`, `libgdk-pixbuf-2.0-0`
- **macOS:** `brew install pango cairo gdk-pixbuf`
- **Fedora:** `pango pango-devel cairo gdk-pixbuf2`

Other report formats keep working — the API reports PDF as unavailable with a reason.

### SOCKS proxy fails with `Missing dependencies for SOCKS support`

SpiderForge requires `socksio>=1.0.0` (declared in `pyproject.toml`). It's already included in the `[web,pdf,browser]` install performed by `install.sh`. If you installed manually:

```bash
pipx inject spiderforge socksio
```

### Proxy unreachable during scan

SpiderForge fails loudly when anonymity is enabled and the proxy is unhealthy. This is intentional — there's no silent fallback to your real IP.

Diagnose:

```bash
spiderforge anonymity proxy test
spiderforge anonymity test
```

### Port 8000 already in use

```bash
spiderforge web --port 9000
```

### Verbose debugging

```bash
SPIDERFORGE_DEBUG=1 spiderforge scan run https://example.com
```

### Reinstalling from scratch

```bash
pipx uninstall spiderforge
git clone https://github.com/milesmaro2006-dev/spider-forge.git
cd spider-forge/scripts
bash install.sh
```

---

## ⚠️ Known Issues

- **Ruff B904 / SIM102** — deferred to Phase E (tracked in `pyproject.toml` ignore list, not silenced silently)
- **`scripts/install.ps1`** — kept as a Windows legacy fallback; `scripts/install.sh` is the canonical installer
- **Playwright** requires a ~300 MB Chromium download on first install (once per user, cached in `~/.cache/ms-playwright`)
- **PyPI release** — not yet available, install from source via the script (tracked under Phase F)

---

## 🗺️ Roadmap

### ✅ Phase A + B + C — Shipped (v3.0.0)

- [x] Interactive CLI menu + 17 commands
- [x] Real SQLi (error-based + blind), XSS, headers, CORS, redirects, SSRF, SSTI, CMDi, path traversal, upload, IDOR
- [x] Async engine with shared `SafeHttpClient`
- [x] Reports: JSON / Markdown / HTML / PDF
- [x] FastAPI web dashboard (standalone, first-run wizard)
- [x] Anonymity layer (15 subcommands, proxy rotation, DoH, fingerprint)
- [x] System Doctor (health checks with exit codes)
- [x] pipx-based POSIX `install.sh` (fully automated, no system packages)
- [x] 304 tests passing · 0 ruff errors · 0 mypy errors in core

### 🚧 Phase D — Reporting & Evidence Depth

- [ ] CVSS v3.1 vector calculator UI
- [ ] Evidence screenshot pipeline (Playwright)
- [ ] SARIF export for GitHub Advanced Security
- [ ] Differential reports (scan vs. previous scan)

### 📋 Phase E — Code Quality & Compliance

- [ ] Resolve B904 / SIM102 ruff ignores
- [ ] Full mypy coverage (not just core)
- [ ] Pre-commit hooks
- [ ] Type stubs for all public APIs

### 🔭 Phase F — Ecosystem

- [ ] PyPI stable release (enables `pipx install spiderforge`)
- [ ] Docker image
- [ ] Nuclei / FFUF deep integration
- [ ] Community plugin API

---

## ⚠️ Legal Disclaimer

SpiderForge is intended only for authorized security testing, research, education, and defensive security assessments.

You must have explicit permission before scanning, crawling, fuzzing, or testing any system that you do not own or have authorization to assess.

Unauthorized security testing may violate applicable laws, regulations, contracts, or terms of service.

The authors and contributors are not responsible for misuse, damage, or unauthorized activity involving this software.

---

## 📄 License

SpiderForge is released under the MIT License. See [LICENSE](LICENSE) for the full text.

---

## 👤 Author

**Amr Shaban**  
Cybersecurity Student — Offensive Security & Web Application Security

- GitHub: https://github.com/milesmaro2006-dev

<p align="center">
  <sub>Built with ❤️ for the security community</sub>
</p>
