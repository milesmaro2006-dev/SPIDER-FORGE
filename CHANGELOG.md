# Changelog

All notable changes to SpiderForge are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [3.0.0] — 2026-09-19

### Added

#### Web Standalone (Phase B)
- `spiderforge web` — standalone web dashboard launcher.
- First-run wizard (port + auto-open browser).
- Config persistence in `~/.spiderforge/web.toml`.
- `--host`, `--port`, `--no-browser`, `--foreground`, `--reset-config` flags.
- Automatic browser open + health probe.

#### Anonymity & Privacy (Phase C)
- `spiderforge anonymity` — 15 commands to manage privacy features.
- HTTP / HTTPS proxy support (`set-proxy`).
- SOCKS5 support (`set-socks5`).
- Tor support (`set-tor`, `socks5://127.0.0.1:9050`).
- User-Agent rotation with realistic browser pool.
- Header sanitization (strips X-Forwarded-For, Via, Forwarded, ...).
- Referrer policy (`none`, `same-origin`, `custom`).
- DNS-over-HTTPS with cross-check validation.
- Random pacing between requests.
- Per-origin cookie isolation.
- TLS fingerprint impersonation (via optional `curl_cffi`).
- Config file: `~/.spiderforge/anonymity.toml`.

#### Reliability
- Pre-flight proxy health check — aborts with clear error when proxy is down.
- Fail-loud engine — aborts when every crawled URL fails (no false negatives).
- `AssessmentResult.success` + `error_msg` properties.
- Structured HTTP errors in backend (`PROXY_UNREACHABLE`, `CONNECTION_FAILED`, ...).
- `SPIDERFORGE_DEBUG=1` env var for full tracebacks.

### Fixed
- `sort_findings` — `Confidence` enum unary-minus bug.
- SafeHttpClient — DNS-rebinding check skipped when routing through proxy.
- CLI — registered 10 previously orphaned subcommands (`config`, `crawl`, `discover`, ...).
- `--version` flag now works (`SpiderForge v3.0.0`).

### Changed
- `pyproject.toml` — added `socksio>=1.0.0` as hard dependency.
- `pyproject.toml` — `line-length` raised to 200 (temporary; targeted for 120).
- Backend `backend/main.py` — frontend resolution supports pipx-installed paths.

### Known Issues
- `scripts/install.sh` is a PowerShell script on Linux (documented in README).
- `B904` (raise-without-from) and `SIM102` (collapsible-if) tracked for Phase E.
- PDF export requires WeasyPrint + system libraries (see README).

## [2.0.0] — 2026-08-01

Initial public release — see git history.
