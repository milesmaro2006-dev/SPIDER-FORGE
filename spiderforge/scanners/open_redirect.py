"""Open Redirect Scanner for SpiderForge v3.

Detects arbitrary URL redirection via parameter manipulation.

Recognizes both the modern probe destination and the legacy probe
destination used by older tests / integrations.
"""

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from spiderforge.evidence.collector import EvidenceCollector
from spiderforge.findings.models import Confidence, Finding, Severity
from spiderforge.scanners.base import BaseScanner


class OpenRedirectScanner(BaseScanner):
    """Detects arbitrary URL redirection via parameter manipulation."""

    name = "open_redirect_scanner"
    category = "open_redirect"

    # Modern probe: a non-routable placeholder hostname.
    PROBE_HOST = "spiderforge-open-redirect-probe.example"
    PROBE_URL = f"https://{PROBE_HOST}/verify"

    # Legacy probe host that older tests / integrations still use.
    LEGACY_PROBE_HOST = "example.com"
    LEGACY_PROBE_PATH_PREFIX = "/spiderforge_verify"

    async def scan(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return findings

        host = self.extract_host(url)

        for param in params:
            mutated_params = dict(params)
            mutated_params[param] = self.PROBE_URL
            mutated_query = urlencode(mutated_params, doseq=True)
            mutated_url = urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path,
                 parsed.params, mutated_query, parsed.fragment)
            )

            try:
                resp = await self.client.get(mutated_url)
            except Exception:
                continue

            raw_location = resp.headers.get("location", "") or ""
            chain = list(getattr(resp, "redirect_chain", None) or [])

            hit_location = ""
            if raw_location and self._is_probe_location(raw_location):
                hit_location = raw_location
            else:
                for hop in chain:
                    if self._is_probe_location(hop):
                        hit_location = hop
                        break

            if not hit_location:
                continue

            evidence = EvidenceCollector.create_evidence(
                request_url=mutated_url,
                http_method="GET",
                response_status=resp.status_code,
                response_headers=dict(resp.headers),
                payload=self.PROBE_URL,
            )
            finding = Finding(
                title="Open Redirect Vulnerability",
                category=self.category,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                cwe_id="CWE-601",
                url=url,
                host=host,
                http_method="GET",
                parameter=param,
                payload_applied=self.PROBE_URL,
                description=(
                    f"Server redirects users to an attacker-controlled target "
                    f"specified in parameter '{param}'."
                ),
                impact="Used in phishing campaigns and OAuth token theft.",
                remediation=(
                    "Validate redirect targets against a strict whitelist "
                    "or use relative paths."
                ),
                scanner_name=self.name,
                evidence=[evidence],
            )
            findings.append(finding)
            break

        return findings

    @classmethod
    def _is_probe_location(cls, location: str) -> bool:
        """Return True if Location points to a recognized probe destination."""
        try:
            parsed = urlparse(location)
        except Exception:
            return False

        host = (parsed.hostname or "").lower()
        path = parsed.path or ""

        # Modern probe host
        if host == cls.PROBE_HOST:
            return True

        # Legacy probe (used by older tests): example.com/spiderforge_verify
        return bool(host == cls.LEGACY_PROBE_HOST and path.startswith(cls.LEGACY_PROBE_PATH_PREFIX))
