"""Network diagnostic for zero.webappsecurity.com."""

import asyncio
import socket
import httpx


async def main() -> None:
    host = "zero.webappsecurity.com"

    # 1) DNS resolution
    print("[1] DNS resolution...")
    try:
        addrinfo = socket.getaddrinfo(host, 80, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        print(f"    Resolved {len(addrinfo)} addresses:")
        for item in addrinfo[:10]:
            family = "IPv4" if item[0] == socket.AF_INET else "IPv6"
            print(f"      {family}: {item[4][0]}")
    except Exception as e:
        print(f"    [X] DNS failed: {type(e).__name__}: {e}")
        return

    # 2) Direct HTTP with long timeout
    print("\n[2] Direct HTTP (30s timeout)...")
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            r = await client.get(f"http://{host}/")
            print(f"    [OK] Status: {r.status_code}")
            print(f"    [OK] Server: {r.headers.get('server')}")
            print(f"    [OK] Body len: {len(r.text)}")
    except Exception as e:
        print(f"    [X] {type(e).__name__}: {repr(e)}")

    # 3) Force IPv4 only
    print("\n[3] Force IPv4 (30s timeout)...")
    try:
        transport = httpx.AsyncHTTPTransport(local_address="0.0.0.0")
        async with httpx.AsyncClient(
            timeout=30.0, follow_redirects=True, transport=transport
        ) as client:
            r = await client.get(f"http://{host}/")
            print(f"    [OK] Status: {r.status_code}")
            print(f"    [OK] Body len: {len(r.text)}")
    except Exception as e:
        print(f"    [X] {type(e).__name__}: {repr(e)}")


if __name__ == "__main__":
    asyncio.run(main())