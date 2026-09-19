"""Direct SafeHttpClient test — the most basic thing."""

import asyncio
import sys

from spiderforge.network.client import SafeHttpClient
from spiderforge.network.policies import (
    NetworkPolicy,
    ScopePolicy,
    DestinationSafetyPolicy,
)


async def main() -> int:
    target = "https://example.com"
    host = "example.com"

    scope = ScopePolicy(
        target_host=host,
        allowed_domains={host, f"*.{host}"},
    )
    policy = NetworkPolicy(
        scope_policy=scope,
        destination_policy=DestinationSafetyPolicy(allow_private_targets=False),
        rate_limit_rps=5.0,
    )

    print(f"[*] Testing direct request to {target}...")
    async with SafeHttpClient(policy=policy) as client:
        try:
            resp = await client.get(target)
            print(f"[OK] Status:         {resp.status_code}")
            print(f"[OK] Final URL:      {resp.final_url}")
            print(f"[OK] Content-Length: {len(resp.content)}")
            print(f"[OK] Content-Type:   {resp.headers.get('content-type')}")
            print(f"[OK] Server:         {resp.headers.get('server')}")
            body = resp.safe_text()
            print(f"[OK] Body (first 300 chars):")
            print(body[:300])
            return 0 if resp.status_code == 200 else 2
        except Exception as exc:
            print(f"[X] {type(exc).__name__}: {exc}")
            return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))