from __future__ import annotations

import asyncio
from urllib.parse import urljoin

import httpx

from spiderforge.crawler.rate_limit import RateLimiter
from spiderforge.scope.validator import ScopeValidator
from spiderforge.utils.urls import normalize_url

# A compact, high-signal wordlist. Real deployments can point SPIDERFORGE_WORDLIST
# at a bigger list (SecLists etc.).
DEFAULT_WORDLIST: tuple[str, ...] = (
    # Admin / auth
    "admin", "administrator", "admin.php", "admin.html", "wp-admin", "wp-login.php",
    "login", "signin", "signup", "register", "logout", "auth", "oauth", "sso",
    "console", "dashboard", "portal", "manager", "management",
    # Config / secrets
    ".env", ".git/config", ".git/HEAD", ".svn/entries", ".htaccess",
    "config", "config.php", "config.json", "config.yaml", "config.yml",
    "settings", "web.config", "appsettings.json", "secrets.json",
    "phpinfo.php", "info.php", "test.php", "debug", "debug.log",
    # API surface
    "api", "api/v1", "api/v2", "api/v3", "api/docs", "api/swagger",
    "graphql", "gql", "swagger", "swagger-ui", "swagger.json",
    "openapi.json", "openapi.yaml", "redoc", "docs", "api-docs",
    # Backup / dump
    "backup", "backups", "backup.zip", "backup.tar.gz", "backup.sql",
    "dump.sql", "db.sql", "database.sql", "site.zip", "www.zip",
    # Common files
    "robots.txt", "sitemap.xml", "humans.txt", "security.txt",
    ".well-known/security.txt", "crossdomain.xml", "clientaccesspolicy.xml",
    "favicon.ico", "manifest.json", "service-worker.js",
    # Status / health
    "health", "healthz", "healthcheck", "status", "ping", "metrics", "version",
    "server-status", "server-info", "_status",
    # Common frameworks
    "actuator", "actuator/health", "actuator/env", "actuator/beans",
    "telescope", "_debugbar", "__debug__", "_profiler",
    # Legacy/leaks
    "old", "new", "test", "tests", "staging", "dev", "development",
    "phpmyadmin", "pma", "mysql", "adminer.php", "myadmin",
    # Upload / file
    "uploads", "upload", "files", "media", "static", "assets", "public",
    "download", "downloads", "attachment", "attachments",
)


async def probe_paths(
    origin: str,
    *,
    scope: ScopeValidator,
    client: httpx.AsyncClient,
    wordlist: list[str] | None = None,
    concurrency: int = 20,
    rate_limit: float = 0.0,
    timeout: float = 10.0,
    follow_redirects: bool = False,
    accept_status: tuple[int, ...] = (200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403),
) -> list[str]:
    """Probe common hidden paths. Returns discovered paths (full URLs).

    Respects scope on every request. Follows no redirects by default so that
    a redirect to another host does not cause an out-of-scope request.
    """
    paths = list(wordlist) if wordlist else list(DEFAULT_WORDLIST)
    origin = origin.rstrip("/") + "/"
    limiter = RateLimiter(rate_per_sec=rate_limit)
    sem = asyncio.Semaphore(concurrency)
    found: list[str] = []

    async def _one(path: str) -> None:
        url = normalize_url(urljoin(origin, path))
        if not scope.is_allowed(url):
            return
        async with sem:
            await limiter.acquire()
            try:
                resp = await client.get(url, timeout=timeout, follow_redirects=follow_redirects)
            except httpx.HTTPError:
                return
            if resp.status_code in accept_status:
                found.append(url)

    await asyncio.gather(*(_one(p) for p in paths))
    return sorted(set(found))
