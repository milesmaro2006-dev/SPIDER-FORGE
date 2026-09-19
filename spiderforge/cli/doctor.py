# spiderforge/cli/doctor.py
"""
SpiderForge — System Health Checker (Production-grade).

Runs a comprehensive pre-flight diagnostic before scans:
  • Environment & Runtime (Python, core libs)
  • Web Platform libs   (fastapi, uvicorn) — WARN by default
  • Reporting Engines   (PDF/HTML/MD/JSON)
  • External CLI binaries (nmap, nikto, gobuster, ffuf, whatweb)
  • Permissions & Storage (cwd writable, ~/.spiderforge, disk space)
  • Network & DNS (resolution, outbound HTTP)

Output:
  • Rich table with statuses PASS / WARN / FAIL
  • Overall summary: Ready / Degraded / Action Required
  • Copy-paste remediation commands for anything missing

Exit codes:
  0 = Ready              (no WARN, no FAIL)
  1 = Degraded           (warnings only)
  2 = Action Required    (at least one FAIL)

Usage:
  spiderforge doctor                 # default: web libs are WARN
  spiderforge doctor --cli-only      # ignore fastapi/uvicorn entirely
  spiderforge doctor --web           # treat fastapi/uvicorn as FAIL if missing
  spiderforge doctor --json          # machine-readable output (for CI)
  spiderforge doctor --quiet         # single summary line
"""

from __future__ import annotations

import importlib
import json
import os
import shutil
import socket
import sys
import time
from dataclasses import asdict, dataclass
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()


# ═══════════════════════════════════════════════════════════════
#  Check result model
# ═══════════════════════════════════════════════════════════════

PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"

STATUS_STYLE = {PASS: "bold green", WARN: "bold yellow", FAIL: "bold red"}
STATUS_ICON  = {PASS: "✓", WARN: "!", FAIL: "✗"}


@dataclass
class CheckResult:
    component: str
    category: str
    status: str
    notes: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ═══════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════

def _version_tuple(v: str) -> tuple:
    """'3.11.4' → (3, 11, 4). Non-numeric parts are dropped safely."""
    parts: list[int] = []
    for chunk in str(v).split("."):
        num = "".join(c for c in chunk if c.isdigit())
        if num == "":
            break
        parts.append(int(num))
    return tuple(parts)


def _resolve_version(mod_name: str, mod: object) -> str:
    """__version__ → importlib.metadata → 'unknown'."""
    v = getattr(mod, "__version__", None)
    if isinstance(v, str) and v.strip():
        return v.strip()
    try:
        return _pkg_version(mod_name)
    except PackageNotFoundError:
        return "unknown"
    except Exception:
        return "unknown"


def _check_python_version() -> CheckResult:
    cur = sys.version_info
    cur_str = f"{cur.major}.{cur.minor}.{cur.micro}"
    if (cur.major, cur.minor) >= (3, 10):
        return CheckResult("Python Runtime", "Environment", PASS, f"v{cur_str}", "—")
    return CheckResult(
        "Python Runtime", "Environment", FAIL,
        f"v{cur_str} (requires >= 3.10)",
        "Install Python 3.10+: sudo apt install python3.10  "
        "or use pyenv: pyenv install 3.11.9",
    )


def _check_python_venv() -> CheckResult:
    """Detect any of: standard venv, pipx-managed venv, or system Python.

    - Standard venv:  ``sys.base_prefix != sys.prefix``
    - pipx venv:      ``sys.prefix`` lives under ``.../pipx/venvs/<app>``
    - System Python:  everything else → WARN
    """
    prefix_str = str(sys.prefix).lower()
    exe_str = str(sys.executable).lower()

    # pipx installs into isolated venvs under ~/.local/share/pipx/venvs/<app>.
    # The interpreter may be symlinked, so base_prefix can equal sys.prefix
    # even though we're fully isolated. Check the paths directly.
    is_pipx = (
        "pipx" in prefix_str
        or "pipx" in exe_str
        or Path(sys.prefix).parent.name == "venvs"
    )

    if is_pipx:
        return CheckResult(
            "Virtual Environment", "Environment", PASS,
            f"pipx-managed ({Path(sys.prefix).name})", "—",
        )

    in_venv = (
        hasattr(sys, "real_prefix")
        or (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix)
    )
    if in_venv:
        return CheckResult(
            "Virtual Environment", "Environment", PASS,
            f"active ({Path(sys.prefix).name})", "—",
        )

    return CheckResult(
        "Virtual Environment", "Environment", WARN,
        "running outside a venv",
        "Recommended: python3 -m venv .venv && source .venv/bin/activate && pip install -e .",
    )


# ═══════════════════════════════════════════════════════════════
#  Lib groups
# ═══════════════════════════════════════════════════════════════

# متطلبات إجبارية للـ CLI
CORE_LIBS: list[tuple[str, str, str]] = [
    ("typer",    "typer",    "0.12.0"),
    ("rich",     "rich",     "13.0.0"),
    ("httpx",    "httpx",    "0.27.0"),
    ("pydantic", "pydantic", "2.0.0"),
]

# متطلبات الـ Web Backend — افتراضياً WARN
WEB_LIBS: list[tuple[str, str, str]] = [
    ("fastapi", "fastapi", "0.110.0"),
    ("uvicorn", "uvicorn", "0.29.0"),
]


def _check_lib_group(
    libs: list[tuple[str, str, str]],
    category: str,
    missing_status: str = FAIL,
    extra_note: str = "",
) -> list[CheckResult]:
    results: list[CheckResult] = []
    for mod_name, pip_name, min_ver in libs:
        try:
            mod = importlib.import_module(mod_name)
        except Exception as exc:  # noqa: BLE001
            note = f"not importable ({type(exc).__name__})"
            if extra_note:
                note = f"{note} — {extra_note}"
            remediation = f"pip install -U '{pip_name}>={min_ver}'"
            results.append(CheckResult(
                f"lib: {pip_name}", category, missing_status, note, remediation,
            ))
            continue

        installed = _resolve_version(mod_name, mod)
        if installed == "unknown":
            results.append(CheckResult(
                f"lib: {pip_name}", category, PASS,
                "installed (version unknown)", "—",
            ))
            continue

        try:
            ok = _version_tuple(installed) >= _version_tuple(min_ver)
        except Exception:
            ok = True

        if ok:
            results.append(CheckResult(
                f"lib: {pip_name}", category, PASS, f"v{installed}", "—",
            ))
        else:
            results.append(CheckResult(
                f"lib: {pip_name}", category, WARN,
                f"v{installed} < recommended {min_ver}",
                f"pip install -U '{pip_name}>={min_ver}'",
            ))
    return results


# ═══════════════════════════════════════════════════════════════
#  Reporting engines
# ═══════════════════════════════════════════════════════════════

def _check_weasyprint() -> CheckResult:
    try:
        wp = importlib.import_module("weasyprint")
        ver = _resolve_version("weasyprint", wp)
    except ImportError:
        return CheckResult(
            "WeasyPrint (PDF)", "Reporting", WARN,
            "not installed — PDF export disabled; HTML/JSON/MD still work",
            "pip install weasyprint  (also needs: sudo apt install "
            "libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf-2.0-0)",
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            "WeasyPrint (PDF)", "Reporting", WARN,
            f"import failed: {type(exc).__name__}: {exc}",
            "pip install --force-reinstall weasyprint",
        )

    try:
        from weasyprint import HTML  # type: ignore
        HTML(string="<p>ok</p>").write_pdf()
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            "WeasyPrint (PDF)", "Reporting", WARN,
            f"v{ver} installed but render failed ({type(exc).__name__})",
            "sudo apt install libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf-2.0-0",
        )

    return CheckResult(
        "WeasyPrint (PDF)", "Reporting", PASS, f"v{ver} — render OK", "—",
    )


def _check_reporting_modules() -> list[CheckResult]:
    results: list[CheckResult] = []
    for mod in (
        "spiderforge.reporting.json_report",
        "spiderforge.reporting.markdown_report",
        "spiderforge.reporting.html_report",
    ):
        try:
            importlib.import_module(mod)
            results.append(CheckResult(
                mod.split(".")[-1], "Reporting", PASS, "importable", "—",
            ))
        except Exception as exc:  # noqa: BLE001
            results.append(CheckResult(
                mod.split(".")[-1], "Reporting", FAIL,
                f"import error: {type(exc).__name__}: {exc}",
                "Reinstall SpiderForge: pip install -e .",
            ))
    return results


# ═══════════════════════════════════════════════════════════════
#  External CLI binaries
# ═══════════════════════════════════════════════════════════════

EXTERNAL_BINARIES: list[tuple[str, str, str, str]] = [
    ("nmap",     "recommended", "nmap",     "port scanning / service detection"),
    ("nikto",    "optional",    "nikto",    "web server scanner"),
    ("gobuster", "optional",    "gobuster", "directory/DNS brute-force"),
    ("ffuf",     "optional",    "ffuf",     "fast web fuzzing"),
    ("whatweb",  "optional",    "whatweb",  "technology fingerprinting"),
]


def _check_binaries() -> list[CheckResult]:
    results: list[CheckResult] = []
    for bin_name, _priority, apt_pkg, purpose in EXTERNAL_BINARIES:
        path = shutil.which(bin_name)
        if path:
            results.append(CheckResult(
                f"bin: {bin_name}", "External Tools", PASS,
                f"{path} ({purpose})", "—",
            ))
            continue
        results.append(CheckResult(
            f"bin: {bin_name}", "External Tools", WARN,
            f"not in PATH ({purpose})",
            f"sudo apt install {apt_pkg}   # or: sudo snap install {bin_name}",
        ))
    return results


# ═══════════════════════════════════════════════════════════════
#  Permissions & Storage
# ═══════════════════════════════════════════════════════════════

def _can_write(path: Path) -> tuple[bool, str]:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / f".sf_probe_{os.getpid()}_{int(time.time())}"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True, str(path)
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def _check_storage() -> list[CheckResult]:
    results: list[CheckResult] = []

    cwd = Path.cwd()
    ok, info = _can_write(cwd)
    results.append(CheckResult(
        "cwd writable", "Storage",
        PASS if ok else FAIL,
        info if ok else f"cannot write to {cwd}: {info}",
        "—" if ok else f"chmod u+w {cwd}   # or run from a writable directory",
    ))

    sf_home = Path.home() / ".spiderforge"
    ok2, info2 = _can_write(sf_home)
    results.append(CheckResult(
        "~/.spiderforge", "Storage",
        PASS if ok2 else WARN,
        info2 if ok2 else f"cannot create: {info2}",
        "—" if ok2 else f"mkdir -p {sf_home} && chmod 700 {sf_home}",
    ))

    try:
        usage = shutil.disk_usage(cwd)
        free_gb = usage.free / (1024 ** 3)
        if free_gb >= 1.0:
            results.append(CheckResult(
                "Disk space", "Storage", PASS, f"{free_gb:.1f} GB free", "—",
            ))
        elif free_gb >= 0.2:
            results.append(CheckResult(
                "Disk space", "Storage", WARN,
                f"low: {free_gb * 1024:.0f} MB free",
                "Free some space or set SPIDERFORGE_HOME to another volume.",
            ))
        else:
            results.append(CheckResult(
                "Disk space", "Storage", FAIL,
                f"critical: {free_gb * 1024:.0f} MB free",
                "Free disk space before running scans.",
            ))
    except Exception as exc:  # noqa: BLE001
        results.append(CheckResult(
            "Disk space", "Storage", WARN,
            f"unable to determine ({type(exc).__name__})", "—",
        ))

    return results


# ═══════════════════════════════════════════════════════════════
#  Network & DNS
# ═══════════════════════════════════════════════════════════════

def _check_dns() -> CheckResult:
    for host in ("one.one.one.one", "google.com"):
        try:
            ip = socket.gethostbyname(host)
            return CheckResult(
                "DNS resolution", "Network", PASS,
                f"resolved {host} → {ip}", "—",
            )
        except socket.gaierror:
            continue
        except Exception:
            continue
    return CheckResult(
        "DNS resolution", "Network", FAIL,
        "no DNS resolver reachable",
        "Check /etc/resolv.conf, network connection, or VPN.",
    )


def _check_outbound_http() -> CheckResult:
    try:
        import httpx
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            "Outbound HTTP", "Network", FAIL,
            f"httpx unavailable ({type(exc).__name__})",
            "pip install httpx",
        )

    probes = [
        "https://example.com",
        "https://one.one.one.one",
        "http://neverssl.com",
    ]
    last_err = ""
    for url in probes:
        try:
            t0 = time.perf_counter()
            # Diagnostic probe only: secure defaults, no redirect following.
            r = httpx.get(url, timeout=5.0)
            dt = (time.perf_counter() - t0) * 1000
            if r.status_code < 500:
                return CheckResult(
                    "Outbound HTTP", "Network", PASS,
                    f"{url} → {r.status_code} ({dt:.0f} ms)", "—",
                )
            last_err = f"{url} → HTTP {r.status_code}"
        except Exception as exc:  # noqa: BLE001
            last_err = f"{url}: {type(exc).__name__}"
            continue

    return CheckResult(
        "Outbound HTTP", "Network", WARN,
        f"all probes failed ({last_err})",
        "Check firewall/VPN/proxy. Retry from another network.",
    )


# ═══════════════════════════════════════════════════════════════
#  Aggregator
# ═══════════════════════════════════════════════════════════════

def run_all_checks(web_mode: str = "warn") -> list[CheckResult]:
    """
    web_mode:
      "warn"     → fastapi/uvicorn ناقصين = WARN (افتراضي)
      "fail"     → ناقصين = FAIL (لما تكون بتشغّل الـ web dashboard)
      "skip"     → تجاهلهم تماماً (CLI-only mode)
    """
    checks: list[CheckResult] = []
    checks.append(_check_python_version())
    checks.append(_check_python_venv())

    # Core libs (إجباري)
    checks.extend(_check_lib_group(CORE_LIBS, "Environment", missing_status=FAIL))

    # Web libs حسب الوضع
    if web_mode == "fail":
        checks.extend(_check_lib_group(
            WEB_LIBS, "Web Platform", missing_status=FAIL,
            extra_note="required for the web dashboard",
        ))
    elif web_mode == "warn":
        checks.extend(_check_lib_group(
            WEB_LIBS, "Web Platform", missing_status=WARN,
            extra_note="only needed for the web dashboard",
        ))
    # else: skip — لا نضيف أي شيء

    checks.append(_check_weasyprint())
    checks.extend(_check_reporting_modules())
    checks.extend(_check_binaries())
    checks.extend(_check_storage())
    checks.append(_check_dns())
    checks.append(_check_outbound_http())
    return checks


# ═══════════════════════════════════════════════════════════════
#  Renderer
# ═══════════════════════════════════════════════════════════════

def _overall_status(checks: list[CheckResult]) -> tuple[str, str]:
    if any(c.status == FAIL for c in checks):
        return "Action Required", "bold red"
    if any(c.status == WARN for c in checks):
        return "Degraded", "bold yellow"
    return "Ready", "bold green"


def _print_table(checks: list[CheckResult]) -> None:
    table = Table(
        title="[bold cyan]SpiderForge — System Health Report[/bold cyan]",
        header_style="bold cyan",
        show_lines=False,
        expand=False,
    )
    table.add_column("Component", style="white", overflow="fold")
    table.add_column("Category", style="dim", no_wrap=True)
    table.add_column("Status", justify="center", no_wrap=True)
    table.add_column("Notes / Remediation", overflow="fold")

    for c in checks:
        style = STATUS_STYLE.get(c.status, "white")
        icon = STATUS_ICON.get(c.status, "?")
        status_cell = Text(f"{icon} {c.status}", style=style)

        note = c.notes or ""
        if c.remediation and c.remediation != "—":
            note = f"{note}\n[dim]→ {c.remediation}[/dim]"

        table.add_row(c.component, c.category, status_cell, note)

    console.print(table)


def _print_summary(checks: list[CheckResult]) -> None:
    total = len(checks)
    n_pass = sum(1 for c in checks if c.status == PASS)
    n_warn = sum(1 for c in checks if c.status == WARN)
    n_fail = sum(1 for c in checks if c.status == FAIL)

    label, style = _overall_status(checks)
    border = style.split()[-1]

    console.print()
    console.print(
        Panel.fit(
            f"[bold]Checks:[/bold] {total}   "
            f"[green]PASS[/green]: {n_pass}   "
            f"[yellow]WARN[/yellow]: {n_warn}   "
            f"[red]FAIL[/red]: {n_fail}\n"
            f"[bold]System Status:[/bold] [{style}]{label}[/{style}]",
            border_style=border,
        )
    )


def _print_remediations(checks: list[CheckResult]) -> None:
    actionable = [c for c in checks if c.remediation and c.remediation != "—"]
    if not actionable:
        return

    console.print()
    console.print("[bold cyan]Suggested Remediations:[/bold cyan]")
    seen: set[str] = set()
    for c in actionable:
        if c.remediation in seen:
            continue
        seen.add(c.remediation)
        console.print(f"  [dim]•[/dim] [white]{c.component}[/white]")
        console.print(f"    [green]{c.remediation}[/green]")


# ═══════════════════════════════════════════════════════════════
#  Public API
# ═══════════════════════════════════════════════════════════════

def doctor_run(
    quiet: bool = False,
    json_output: bool = False,
    web_mode: str = "warn",
) -> int:
    """
    Returns exit code:
      0 = Ready
      1 = Degraded (warnings only)
      2 = Action Required (at least one FAIL)
    """
    if not quiet and not json_output:
        console.print(
            Panel.fit(
                "[bold cyan]SpiderForge Doctor[/bold cyan]\n"
                "[dim]Pre-flight system diagnostic…[/dim]",
                border_style="cyan",
            )
        )

    try:
        checks = run_all_checks(web_mode=web_mode)
    except KeyboardInterrupt:
        console.print("\n[yellow]Doctor interrupted.[/yellow]")
        return 2
    except Exception as exc:  # noqa: BLE001
        console.print(
            f"[bold red]Doctor failed to run: {type(exc).__name__}: {exc}[/bold red]"
        )
        return 2

    if json_output:
        label, _ = _overall_status(checks)
        payload = {
            "summary": {
                "total": len(checks),
                "pass": sum(1 for c in checks if c.status == PASS),
                "warn": sum(1 for c in checks if c.status == WARN),
                "fail": sum(1 for c in checks if c.status == FAIL),
                "status": label,
                "web_mode": web_mode,
            },
            "checks": [c.to_dict() for c in checks],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    elif not quiet:
        _print_table(checks)
        _print_summary(checks)
        _print_remediations(checks)

    if any(c.status == FAIL for c in checks):
        return 2
    if any(c.status == WARN for c in checks):
        return 1
    return 0


# ═══════════════════════════════════════════════════════════════
#  Typer CLI
# ═══════════════════════════════════════════════════════════════

app = typer.Typer(
    name="doctor",
    help="System health check: environment, tools, storage, network.",
    invoke_without_command=True,
)


@app.callback(invoke_without_command=True)
def _cli(
    ctx: typer.Context,
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only show summary line."),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON (for CI)."),
    cli_only: bool = typer.Option(
        False, "--cli-only",
        help="Ignore web platform libs (fastapi, uvicorn).",
    ),
    web: bool = typer.Option(
        False, "--web",
        help="Treat missing web libs as FAIL (required for web dashboard).",
    ),
) -> None:
    if ctx.invoked_subcommand is not None:
        return

    if cli_only and web:
        console.print("[red]--cli-only and --web are mutually exclusive.[/red]")
        raise typer.Exit(code=2)

    web_mode = "skip" if cli_only else ("fail" if web else "warn")

    code = doctor_run(quiet=quiet, json_output=json_output, web_mode=web_mode)
    raise typer.Exit(code=code)


if __name__ == "__main__":
    app()
