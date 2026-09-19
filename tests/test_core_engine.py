"""Integration test for SpiderForge Canonical AssessmentEngine."""

import asyncio
from unittest.mock import AsyncMock, patch
import httpx

from spiderforge.core.engine import AssessmentEngine
from spiderforge.network.client import SafeResponse


def test_canonical_pipeline_end_to_end():
    """Verify that the engine coordinates scope, safe client, scanning, dedup, and events."""
    async def run_test():
        events_received = []

        def track_event(name, data):
            events_received.append(name)

        engine = AssessmentEngine(
            target_url="http://target.example.com",
            allow_private_targets=False,
            on_event=track_event,
        )

        # Mock SafeHttpClient network calls so tests run isolated & fast
        mock_response = SafeResponse(
            status_code=200,
            headers=httpx.Headers({
                "Server": "nginx/1.18.0",
                "Access-Control-Allow-Origin": "https://spiderforge-attacker.com",
                "Access-Control-Allow-Credentials": "true",
            }),
            url="http://target.example.com",
            content=b"<html>Hello SpiderForge</html>",
            text="<html>Hello SpiderForge</html>",
            http_version="HTTP/1.1",
        )

        with patch("spiderforge.core.engine.SafeHttpClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response

            result = await engine.run()

            # 1. Verify Pipeline Flow & Execution
            assert result.target == "http://target.example.com"
            assert "scan_started" in events_received
            assert "recon_started" in events_received
            assert "scanners_started" in events_received
            assert "scan_completed" in events_received

            # 2. Verify Canonical Findings Captured & Classified
            assert len(result.findings) > 0
            assert result.summary["total"] == len(result.findings)

            # 3. Ensure deduplication fingerprint works
            fingerprints = [f.fingerprint for f in result.findings]
            assert len(fingerprints) == len(set(fingerprints))  # No duplicates

    asyncio.run(run_test())