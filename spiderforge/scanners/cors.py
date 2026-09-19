"""CORS Misconfiguration Scanner for SpiderForge v3."""


from spiderforge.evidence.collector import EvidenceCollector
from spiderforge.findings.models import Confidence, Finding, Severity
from spiderforge.scanners.base import BaseScanner


class CORSScanner(BaseScanner):
    """Detects insecure CORS configurations permitting arbitrary origins with credentials."""

    name = "cors_scanner"
    category = "cors"

    TEST_ORIGIN = "https://spiderforge-attacker.com"

    async def scan(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        host = self.extract_host(url)

        try:
            resp = await self.client.get(url, headers={"Origin": self.TEST_ORIGIN})
        except Exception:
            return findings

        acao = resp.headers.get("access-control-allow-origin", "").strip()
        acac = resp.headers.get("access-control-allow-credentials", "").strip().lower()

        if acao == self.TEST_ORIGIN and acac == "true":
            evidence = EvidenceCollector.create_evidence(
                request_url=url,
                http_method="GET",
                request_headers={"Origin": self.TEST_ORIGIN},
                response_status=resp.status_code,
                response_headers=dict(resp.headers),
                payload=self.TEST_ORIGIN,
            )
            finding = Finding(
                title="CORS Misconfiguration (Origin Reflection with Credentials)",
                category=self.category,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                cwe_id="CWE-942",
                url=url,
                host=host,
                http_method="GET",
                parameter="Origin-Header",
                description=(
                    "Server reflects arbitrary Origin header and permits credentials."
                ),
                impact=(
                    "Allows cross-origin attackers to steal authenticated user "
                    "data via CSRF/XHR."
                ),
                remediation=(
                    "Implement strict Origin whitelisting and do not reflect "
                    "untrusted origins."
                ),
                scanner_name=self.name,
                evidence=[evidence],
            )
            findings.append(finding)

        elif acao == "*":
            evidence = EvidenceCollector.create_evidence(
                request_url=url,
                http_method="GET",
                response_status=resp.status_code,
                response_headers=dict(resp.headers),
            )
            finding = Finding(
                title="CORS Misconfiguration (Wildcard Origin)",
                category=self.category,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                cwe_id="CWE-942",
                url=url,
                host=host,
                http_method="GET",
                parameter="Origin-Header",
                description="Server allows any origin access via wildcard '*'.",
                impact=(
                    "Potential exposure of non-authenticated public endpoints "
                    "to external sites."
                ),
                remediation=(
                    "Restrict Access-Control-Allow-Origin to trusted domains only."
                ),
                scanner_name=self.name,
                evidence=[evidence],
            )
            findings.append(finding)

        return findings
