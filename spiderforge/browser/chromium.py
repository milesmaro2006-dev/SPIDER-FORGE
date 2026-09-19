from __future__ import annotations

import subprocess
import sys


def install_chromium(with_deps: bool = False) -> tuple[int, str]:
    """Run Playwright's Chromium installer. Returns (rc, combined_output)."""
    cmd = [sys.executable, "-m", "playwright", "install"]
    if with_deps:
        cmd.append("--with-deps")
    cmd.append("chromium")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
    except FileNotFoundError as exc:
        return 127, f"playwright CLI not found: {exc}"
    except subprocess.TimeoutExpired:
        return 124, "playwright install timed out after 15 minutes"
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    return proc.returncode, out
