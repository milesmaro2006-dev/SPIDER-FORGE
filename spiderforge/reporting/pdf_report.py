from __future__ import annotations

from pathlib import Path

from spiderforge.reporting.html_report import render_html
from spiderforge.reporting.models import ReportContext


def render(ctx: ReportContext, out_path: Path) -> Path:
    """Render an HTML report and convert it to PDF via WeasyPrint.

    Raises RuntimeError if WeasyPrint is not installed.
    """
    try:
        from weasyprint import HTML  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            "PDF reporting requires WeasyPrint. Install with "
            "`pip install 'spiderforge[pdf]'`."
        ) from exc

    html = render_html(ctx)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html, base_url=str(Path.cwd())).write_pdf(str(out_path))
    return out_path
