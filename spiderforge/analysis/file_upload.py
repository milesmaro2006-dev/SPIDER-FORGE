from __future__ import annotations

from spiderforge.analysis.base import ModuleContext, SecurityModule
from spiderforge.findings.models import Evidence, Finding, Severity


class FileUploadModule(SecurityModule):
    name = "file_upload"
    category = "logic"
    description = "Identify upload endpoints and analyze form-level validation signals."

    # We intentionally DO NOT upload files. The module reports candidate
    # endpoints and the client-side validation hints visible in the form so the
    # operator can decide what to test manually.

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []

        if ctx.crawl_result is None:
            return findings

        for form in ctx.crawl_result.forms:
            if not ctx.scope.is_allowed(form.action):
                continue

            has_file_input = any(f.type == "file" for f in form.fields)
            has_multipart = form.enctype == "multipart/form-data"
            if not (has_file_input or has_multipart):
                continue

            # Client-side validation signals
            file_fields = [f for f in form.fields if f.type == "file"]
            accept_values = []
            for f in file_fields:
                # FormField doesn't have `accept` currently; skip if missing
                accept_values.append(getattr(f, "accept", None))
            client_hints: list[str] = []
            if form.enctype != "multipart/form-data":
                client_hints.append("missing multipart enctype")

            findings.append(
                self.make_finding(
                    title=f"File upload endpoint at `{form.action}`",
                    category="file_upload.endpoint",
                    severity=Severity.INFO,
                    url=form.action,
                    method=form.method,
                    description=(
                        f"The form at `{form.source_url}` posts to `{form.action}` "
                        "and includes file-upload inputs. This is a candidate for "
                        "manual testing of: extension allow-lists, MIME validation, "
                        "magic-byte checks, filename sanitization, upload destination "
                        "behavior, and downstream serving (does the app serve the "
                        "file back with the original content type?)."
                    ),
                    impact="Weak upload validation can lead to remote code execution "
                    "(if the file is served with an executable content-type), stored "
                    "XSS (via HTML/SVG uploads), or denial of service (zip bombs).",
                    remediation="Enforce an extension allow-list, verify magic bytes, "
                    "generate random storage names, store uploads outside the web "
                    "root, and never serve them with the client-supplied Content-Type.",
                    confidence=0.5,
                    evidence=Evidence(
                        request=f"{form.method} {form.action}",
                        notes=(
                            f"fields={[f.name for f in form.fields]}, "
                            f"enctype={form.enctype}, hints={client_hints}"
                        ),
                    ),
                    root_cause=f"file_upload:{form.action}",
                )
            )
        return findings
