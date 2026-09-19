"""Security Headers Scanner for SpiderForge v3.

Deduplicates findings per host — a missing CSP header is a host-level
issue, not a per-URL issue.
"""


from spiderforge.evidence.collector import EvidenceCollector
from spiderforge.findings.models import Confidence, Finding, Severity
from spiderforge.scanners.base import BaseScanner


class HeadersScanner(BaseScanner):
    """Evaluates HTTP response headers against standard defensive policies."""

    name = "headers_scanner"
    category = "security_headers"

    RECOMMENDED_HEADERS = {
        "content-security-policy": (
            "Missing Content-Security-Policy Header",
            Severity.MEDIUM,
            "CWE-693",
            "Content Security Policy prevents XSS and data injection attacks.",
            "Implement a strict Content-Security-Policy HTTP header.",
        ),
        "strict-transport-security": (
            "Missing Strict-Transport-Security (HSTS) Header",
            Severity.LOW,
            "CWE-319",
            "HSTS enforces secure HTTPS connections, preventing MITM downgrade attacks.",
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
        ),
        "x-frame-options": (
            "Missing X-Frame-Options Header",
            Severity.LOW,
            "CWE-1021",
            "Protects users against Clickjacking attacks via iframe embedding.",
            "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'.",
        ),
        "x-content-type-options": (
            "Missing X-Content-Type-Options Header",
            Severity.LOW,
            "CWE-16",
            "Prevents MIME-sniffing vulnerabilities.",
            "Set 'X-Content-Type-Options: nosniff'.",
        ),
    }

    def __init__(self, client) -> None:
        super().__init__(client)
        # Per-host dedup: (host, header) → already reported
        self._seen: set[str] = set()

    async def scan(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        host = self.extract_host(url)

        try:
            resp = await self.client.get(url)
        except Exception:
            return findings

        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for header, (title, severity, cwe, desc, rem) in self.RECOMMENDED_HEADERS.items():
            if header in resp_headers_lower:
                continue

            key = f"{host}|{header}"
            if key in self._seen:
                continue
            self._seen.add(key)

            evidence = EvidenceCollector.create_evidence(
                request_url=url,
                http_method="GET",
                response_status=resp.status_code,
                response_headers=dict(resp.headers),
                payload=None,
            )
            finding = Finding(
                title=title,
                category=self.category,
                severity=severity,
                confidence=Confidence.CONFIRMED,
                cwe_id=cwe,
                url=url,
                host=host,
                http_method="GET",
                parameter="HTTP-Header",
                description=desc,
                impact="Reduces defensive layer against common client-side attacks.",
                remediation=rem,
                scanner_name=self.name,
                evidence=[evidence],
            )
            findings.append(finding)

        return findings
