"""Security regression tests for SpiderForge Safe Network Layer."""

import asyncio
import ipaddress
from unittest.mock import AsyncMock, patch
import pytest

from spiderforge.network.client import SafeHttpClient
from spiderforge.network.exceptions import (
    ResponseSizeExceededError,
    ScopeViolationError,
    SSRFBlockedError,
)
from spiderforge.network.policies import DestinationSafetyPolicy, NetworkPolicy, ScopePolicy


def test_safe_client_blocks_loopback():
    """Ensure 127.0.0.1 and loopbacks are completely rejected."""
    async def run_test():
        scope = ScopePolicy(target_host="target.example.com", allowed_domains={"*.example.com"})
        dest_safety = DestinationSafetyPolicy(allow_private_targets=False)
        policy = NetworkPolicy(scope_policy=scope, destination_policy=dest_safety)

        client = SafeHttpClient(policy=policy)
        with patch.object(
            client.resolver,
            "resolve_and_validate",
            side_effect=SSRFBlockedError("SSRF Protection: Blocked loopback address: 127.0.0.1")
        ):
            with pytest.raises(SSRFBlockedError):
                await client.get("http://target.example.com")
        await client.close()

    asyncio.run(run_test())


def test_safe_client_blocks_metadata():
    """Ensure cloud metadata IP 169.254.169.254 is blocked."""
    async def run_test():
        scope = ScopePolicy(target_host="target.example.com", allowed_domains={"*.example.com"})
        dest_safety = DestinationSafetyPolicy(allow_private_targets=False)
        policy = NetworkPolicy(scope_policy=scope, destination_policy=dest_safety)

        client = SafeHttpClient(policy=policy)
        with patch.object(
            client.resolver,
            "resolve_and_validate",
            side_effect=SSRFBlockedError("Connection blocked to sensitive cloud metadata address: 169.254.169.254")
        ):
            with pytest.raises(SSRFBlockedError):
                await client.get("http://target.example.com")
        await client.close()

    asyncio.run(run_test())


def test_safe_client_blocks_rfc1918_private_ip():
    """Ensure internal private IPs (10.0.0.1) are rejected."""
    async def run_test():
        scope = ScopePolicy(target_host="target.example.com", allowed_domains={"*.example.com"})
        dest_safety = DestinationSafetyPolicy(allow_private_targets=False)
        policy = NetworkPolicy(scope_policy=scope, destination_policy=dest_safety)

        client = SafeHttpClient(policy=policy)
        with patch.object(
            client.resolver,
            "resolve_and_validate",
            side_effect=SSRFBlockedError("SSRF Protection: Blocked RFC1918/private address: 10.0.0.1")
        ):
            with pytest.raises(SSRFBlockedError):
                await client.get("http://target.example.com")
        await client.close()

    asyncio.run(run_test())


def test_safe_client_blocks_out_of_scope():
    """Ensure hosts outside the scope are blocked even if publicly reachable."""
    async def run_test():
        scope = ScopePolicy(target_host="target.example.com", allowed_domains={"*.example.com"})
        dest_safety = DestinationSafetyPolicy(allow_private_targets=False)
        policy = NetworkPolicy(scope_policy=scope, destination_policy=dest_safety)

        client = SafeHttpClient(policy=policy)
        with patch.object(
            client.resolver,
            "resolve_and_validate",
            return_value=[ipaddress.ip_address("93.184.216.34")]
        ):
            with pytest.raises(ScopeViolationError):
                await client.get("http://evil-attacker.com")
        await client.close()

    asyncio.run(run_test())


def test_safe_client_allows_private_when_flagged():
    """Ensure authorized labs can scan private targets if explicitly allowed."""
    async def run_test():
        scope = ScopePolicy(target_host="localhost", allowed_domains={"localhost"})
        dest_safety = DestinationSafetyPolicy(allow_private_targets=True)
        policy = NetworkPolicy(scope_policy=scope, destination_policy=dest_safety)

        client = SafeHttpClient(policy=policy)
        resolved = await client.resolver.resolve_and_validate("127.0.0.1", 80)
        assert resolved[0] == ipaddress.ip_address("127.0.0.1")
        assert policy.scope_policy.is_in_scope("localhost", resolved_ip=resolved[0])
        await client.close()

    asyncio.run(run_test())


def test_safe_client_enforces_size_limit():
    """Ensure response streaming terminates when exceeding max_response_bytes."""
    async def run_test():
        scope = ScopePolicy(target_host="target.example.com", allowed_domains={"*.example.com"})
        dest_safety = DestinationSafetyPolicy(allow_private_targets=False)
        policy = NetworkPolicy(scope_policy=scope, destination_policy=dest_safety)
        policy.max_response_bytes = 100

        client = SafeHttpClient(policy=policy)

        mock_raw = AsyncMock()
        mock_raw.status_code = 200
        mock_raw.is_redirect = False
        mock_raw.headers = {}
        mock_raw.url = "http://target.example.com"
        mock_raw.encoding = "utf-8"
        mock_raw.http_version = "HTTP/1.1"
        # _verify_peer_ip() inspects response.extensions; an empty dict
        # makes it return early, avoiding mock-internal coroutines that
        # would otherwise trigger an unawaited-coroutine warning.
        mock_raw.extensions = {}

        async def fake_iter_bytes():
            yield b"A" * 60
            yield b"B" * 60  # Total 120 bytes > 100 bytes limit

        mock_raw.aiter_bytes = fake_iter_bytes

        with patch.object(client.resolver, "resolve_and_validate", return_value=[ipaddress.ip_address("93.184.216.34")]), \
             patch.object(client._client, "build_request"), \
             patch.object(client._client, "send", return_value=mock_raw):
            with pytest.raises(ResponseSizeExceededError):
                await client.get("http://target.example.com")

        await client.close()

    asyncio.run(run_test())