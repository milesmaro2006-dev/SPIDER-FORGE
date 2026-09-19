from __future__ import annotations

from spiderforge.analysis.registry import registry

_LOADED = False


def load_builtin_modules() -> None:
    """Import every built-in module and register it. Idempotent."""
    global _LOADED
    if _LOADED:
        return

    from spiderforge.analysis.command_injection import CommandInjectionModule
    from spiderforge.analysis.cookies import CookiesModule
    from spiderforge.analysis.cors import CorsModule
    from spiderforge.analysis.file_upload import FileUploadModule
    from spiderforge.analysis.headers import HeadersModule
    from spiderforge.analysis.idor import IdorModule
    from spiderforge.analysis.path_traversal import PathTraversalModule
    from spiderforge.analysis.redirects import RedirectsModule
    from spiderforge.analysis.sqli import SqliModule
    from spiderforge.analysis.ssrf import SsrfModule
    from spiderforge.analysis.ssti import SstiModule
    from spiderforge.analysis.xss import XssModule

    for cls in (
        HeadersModule,
        CookiesModule,
        CorsModule,
        RedirectsModule,
        XssModule,
        SqliModule,
        SsrfModule,
        SstiModule,
        CommandInjectionModule,
        PathTraversalModule,
        FileUploadModule,
        IdorModule,
    ):
        try:
            registry.register(cls())
        except ValueError:
            pass  # already registered

    _LOADED = True
