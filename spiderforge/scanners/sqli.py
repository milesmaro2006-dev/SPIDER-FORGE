"""Error-Based SQL Injection Candidate Scanner for SpiderForge v3."""

import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from spiderforge.evidence.collector import EvidenceCollector
from spiderforge.findings.models import Confidence, Finding, Severity
from spiderforge.scanners.base import BaseScanner


class SQLiScanner(BaseScanner):
    """Detects database error signatures upon parameter mutation against a baseline."""

    name = "sqli_candidate_scanner"
    category = "sqli"

    ERROR_SIGNATURES = [
        re.compile(r"SQL syntax.*MySQL", re.I),
        re.compile(r"Warning.*mysql_.*", re.I),
        re.compile(r"PostgreSQL.*ERROR", re.I),
        re.compile(r"Driver.*SQL[\-\_\ ]*Server", re.I),
        re.compile(r"ORA-[0-9]{4,5}", re.I),
        re.compile(r"SQLite/JDBCDriver", re.I),
        re.compile(r"System\.Data\.SQLite\.SQLiteException", re.I),
        re.compile(r"quoted string not properly terminated", re.I),
    ]

    PROBES = ["'", "''", "1' ORDER BY 1--+", "1; SELECT 1"]

    async def scan(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return findings

        host = self.extract_host(url)

        try:
            baseline_resp = await self.client.get(url)
            baseline_body = baseline_resp.safe_text()
        except Exception:
            return findings

        for param, values in params.items():
            original_val = values[0] if values else ""
            for probe in self.PROBES:
                mutated_params = dict(params)
                mutated_params[param] = original_val + probe
                mutated_query = urlencode(mutated_params, doseq=True)
                mutated_url = urlunparse(
                    (parsed.scheme, parsed.netloc, parsed.path,
                     parsed.params, mutated_query, parsed.fragment)
                )

                try:
                    probe_resp = await self.client.get(mutated_url)
                    probe_body = probe_resp.safe_text()
                except Exception:
                    continue

                for sig in self.ERROR_SIGNATURES:
                    if sig.search(probe_body) and not sig.search(baseline_body):
                        evidence = EvidenceCollector.create_evidence(
                            request_url=mutated_url,
                            http_method="GET",
                            response_status=probe_resp.status_code,
                            response_headers=dict(probe_resp.headers),
                            response_body=probe_body[:1024],
                            payload=probe,
                        )
                        finding = Finding(
                            title="Error-Based SQL Injection Candidate",
                            category=self.category,
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            cwe_id="CWE-89",
                            owasp_category="A03:2021-Injection",
                            url=url,
                            host=host,
                            http_method="GET",
                            parameter=param,
                            payload_applied=probe,
                            description=(
                                f"Parameter '{param}' triggered database error signature "
                                f"upon probe injection."
                            ),
                            impact=(
                                "Potential database compromise, unauthorized data "
                                "extraction, or authentication bypass."
                            ),
                            remediation=(
                                "Use prepared statements, parameterized queries, "
                                "and strict input validation."
                            ),
                            scanner_name=self.name,
                            evidence=[evidence],
                        )
                        findings.append(finding)
                        break
                if findings and findings[-1].parameter == param:
                    break

        return findings
