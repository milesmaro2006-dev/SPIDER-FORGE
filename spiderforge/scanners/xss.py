"""Reflected XSS Candidate Scanner for SpiderForge v3."""

from html import escape
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from spiderforge.evidence.collector import EvidenceCollector
from spiderforge.findings.models import Confidence, Finding, Severity
from spiderforge.scanners.base import BaseScanner


class XSSScanner(BaseScanner):
    """Detects reflected payloads and inspects contextual encoding."""

    name = "xss_candidate_scanner"
    category = "xss"

    PROBES = [
        "sf<script>alert(1)</script>",
        "sf\"onmouseover=alert(1)//",
        "sf'onfocus=alert(1)//",
    ]

    async def scan(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return findings

        host = self.extract_host(url)

        for param in params:
            for probe in self.PROBES:
                mutated_params = dict(params)
                mutated_params[param] = probe
                mutated_query = urlencode(mutated_params, doseq=True)
                mutated_url = urlunparse(
                    (parsed.scheme, parsed.netloc, parsed.path,
                     parsed.params, mutated_query, parsed.fragment)
                )

                try:
                    resp = await self.client.get(mutated_url)
                    body = resp.safe_text()
                except Exception:
                    continue

                if probe in body:
                    confidence = (
                        Confidence.HIGH if escape(probe) not in body
                        else Confidence.MEDIUM
                    )

                    evidence = EvidenceCollector.create_evidence(
                        request_url=mutated_url,
                        http_method="GET",
                        response_status=resp.status_code,
                        response_headers=dict(resp.headers),
                        response_body=body[:1024],
                        payload=probe,
                    )
                    finding = Finding(
                        title="Reflected XSS Candidate",
                        category=self.category,
                        severity=Severity.MEDIUM,
                        confidence=confidence,
                        cwe_id="CWE-79",
                        owasp_category="A03:2021-Injection",
                        url=url,
                        host=host,
                        http_method="GET",
                        parameter=param,
                        payload_applied=probe,
                        description=(
                            f"Raw probe reflected in response body without HTML "
                            f"entity encoding for parameter '{param}'."
                        ),
                        impact=(
                            "Session hijacking, malicious redirects, or client-side "
                            "DOM manipulation."
                        ),
                        remediation=(
                            "Context-aware output encoding and strict Content "
                            "Security Policy (CSP)."
                        ),
                        scanner_name=self.name,
                        evidence=[evidence],
                    )
                    findings.append(finding)
                    break

        return findings
