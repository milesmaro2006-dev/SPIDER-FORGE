"""SpiderForge v3 — Canonical Assessment Engine.

Single point of orchestration uniting Scope, SafeHttpClient, Recon,
Crawler, Security Scanners, Evidence Collection, Deduplication,
Persistence, and Reporting.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from spiderforge.core.exceptions import CrawlFailureError
from spiderforge.crawler import Crawler
from spiderforge.crawler.models import DiscoveredEndpoint
from spiderforge.database.persistence import ScanContext
from spiderforge.findings.models import Finding
from spiderforge.network.client import SafeHttpClient
from spiderforge.network.exceptions import (
    ProxyConnectionError,
    SafeNetworkError,
)
from spiderforge.network.policies import (
    DestinationSafetyPolicy,
    NetworkPolicy,
    ScopePolicy,
)
from spiderforge.recon.runner import run as run_recon
from spiderforge.scanners.cors import CORSScanner
from spiderforge.scanners.headers import HeadersScanner
from spiderforge.scanners.open_redirect import OpenRedirectScanner
from spiderforge.scanners.sqli import SQLiScanner
from spiderforge.scanners.sqli_blind import BlindSQLiScanner
from spiderforge.scanners.xss import XSSScanner
from spiderforge.scope.parser import default_scope_for
from spiderforge.scope.validator import ScopeValidator

logger = logging.getLogger("spiderforge.engine")

if TYPE_CHECKING:
    from spiderforge.anonymity.manager import AnonymityManager


@dataclass
class AssessmentResult:
    """Canonical result bundle returned by an assessment run."""

    target: str
    scan_uid: str
    start_time: datetime
    end_time: datetime
    discovered_urls: set[str] = field(default_factory=set)
    findings: list[Finding] = field(default_factory=list)
    technologies: dict[str, str] = field(default_factory=dict)
    summary: dict[str, int] = field(default_factory=dict)
    error_msg: str | None = None

    @property
    def success(self) -> bool:
        """``True`` when the assessment completed without a fatal error."""
        return self.error_msg is None


class AssessmentEngine:
    """The unified core orchestration engine for SpiderForge."""

    def __init__(
        self,
        target_url: str,
        allowed_domains: set[str] | None = None,
        allow_private_targets: bool = False,
        verify_tls: bool = True,
        max_concurrency: int = 10,
        rate_limit_rps: float = 20.0,
        max_urls: int = 200,
        max_depth: int = 3,
        on_event: Callable[[str, dict], None] | None = None,
        *,
        persist: bool = True,
        project_name: str = "default",
        scan_uid: str | None = None,
        scope_free: bool = False,
        enable_blind_sqli: bool = True,
        anonymity: AnonymityManager | None = None,
    ):
        self.target_url = target_url
        parsed = urlparse(target_url)
        self.target_host = parsed.netloc.split(":")[0]

        domains = allowed_domains or {f"*.{self.target_host}", self.target_host}
        self.scope_policy = ScopePolicy(
            target_host=self.target_host,
            allowed_domains=domains,
            allow_all_hosts=scope_free,
        )

        self.dest_policy = DestinationSafetyPolicy(
            allow_private_targets=allow_private_targets,
        )

        self.network_policy = NetworkPolicy(
            scope_policy=self.scope_policy,
            destination_policy=self.dest_policy,
            verify_tls=verify_tls,
            max_concurrency=max_concurrency,
            rate_limit_rps=rate_limit_rps,
        )

        self.scope_validator = ScopeValidator(default_scope_for(self.target_host))

        self.on_event = on_event or (lambda event, data: None)
        self.findings_dedup: dict[str, Finding] = {}
        self.discovered_urls: set[str] = {target_url}
        self.discovered_endpoints: list[DiscoveredEndpoint] = []

        self.max_urls = max_urls
        self.max_depth = max_depth
        self.enable_blind_sqli = enable_blind_sqli

        # Anonymity (optional) — passed straight through to SafeHttpClient.
        self.anonymity = anonymity

        # Persistence config
        self.persist = persist
        self.project_name = project_name
        self.scan_uid = scan_uid or f"scan-{uuid.uuid4().hex[:16]}"

        self._scan_ctx: ScanContext | None = None

    # ─────────────────────────────────────────────────────────
    #  Internal helpers
    # ─────────────────────────────────────────────────────────

    def _emit(self, event_name: str, payload: dict) -> None:
        try:
            self.on_event(event_name, payload)
        except Exception:
            pass

    def _build_scan_targets(self) -> set[str]:
        """Return the set of URLs to feed to scanners.

        Only endpoints on the same host as the target are included so the
        crawler cannot leak the scan to external sites (e.g. github.com,
        adobe.com) when ``scope_free`` is enabled.
        """
        targets: set[str] = {self.target_url}
        target_host = self.target_host.lower()

        for ep in self.discovered_endpoints:
            try:
                ep_host = (urlparse(ep.url).hostname or "").lower()
            except Exception:
                continue

            if ep_host != target_host and not ep_host.endswith("." + target_host):
                continue

            targets.add(ep.url)
            if ep.method.upper() == "GET" and ep.parameters and "?" not in ep.url:
                param_pairs = [f"{p}=test" for p in ep.parameters[:3]]
                targets.add(f"{ep.url}?{'&'.join(param_pairs)}")

        return targets

    def _begin_persistence(self) -> None:
        if not self.persist:
            return
        try:
            self._scan_ctx = ScanContext(
                project_name=self.project_name,
                target=self.target_url,
                scan_uid=self.scan_uid,
                profile="balanced",
                scope_config={
                    "target_host": self.target_host,
                    "allowed_domains": sorted(self.scope_policy.allowed_domains),
                    "allow_all_hosts": self.scope_policy.allow_all_hosts,
                    "allow_private_targets": self.dest_policy.allow_private_targets,
                    "verify_tls": self.network_policy.verify_tls,
                },
                configuration={
                    "max_urls": self.max_urls,
                    "max_depth": self.max_depth,
                    "max_concurrency": self.network_policy.max_concurrency,
                    "rate_limit_rps": self.network_policy.rate_limit_rps,
                    "enable_blind_sqli": self.enable_blind_sqli,
                },
            )
            self._scan_ctx.begin()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Persistence init failed: %s", exc)
            self._scan_ctx = None

    # ─────────────────────────────────────────────────────────
    #  Main run loop
    # ─────────────────────────────────────────────────────────

    async def run(self) -> AssessmentResult:
        start_time = datetime.now(timezone.utc)
        self._begin_persistence()

        self._emit("scan_started", {
            "target": self.target_url,
            "scan_uid": self.scan_uid,
            "start_time": start_time.isoformat(),
        })

        technologies: dict[str, str] = {}
        error_msg: str | None = None

        try:
            async with SafeHttpClient(
                policy=self.network_policy,
                anonymity=self.anonymity,
            ) as client:

                # ── Phase A: Recon ───────────────────────────────
                self._emit("recon_started", {"target": self.target_url})
                try:
                    recon = await run_recon(
                        self.target_url,
                        scope=self.scope_validator,
                        client=client,
                        timeout=15.0,
                    )
                    for tech in recon.technologies:
                        name = tech.get("name") or tech.get("tech") or "unknown"
                        version = tech.get("version") or ""
                        technologies[str(name)] = str(version)
                        self._emit("tech_detected", {"name": name, "version": version})
                    for err in recon.errors:
                        self._emit("recon_error", {"error": err})
                except Exception as exc:
                    logger.warning("Recon phase failed: %s", exc)

                # ── Phase B: Crawl ───────────────────────────────
                self._emit("crawl_started", {"start_url": self.target_url})

                def _crawler_event(name: str, data: dict) -> None:
                    if name in ("crawl_started", "crawl_completed"):
                        return
                    self._emit(name, data)

                try:
                    crawler = Crawler(
                        client=client,
                        max_urls=self.max_urls,
                        max_depth=self.max_depth,
                        max_concurrency=self.network_policy.max_concurrency,
                        parse_js=True,
                        on_event=_crawler_event,
                    )
                    crawl_result = await crawler.crawl(self.target_url)

                    self.discovered_endpoints = list(crawl_result.endpoints)
                    self.discovered_urls.update(ep.url for ep in crawl_result.endpoints)

                    # ── Fatal-failure detection ──────────────────
                    # If we tried at least one URL and *every single one*
                    # failed, the target (or the proxy) is unreachable.
                    # Continuing to scanners would produce a misleading
                    # "no findings" result.
                    successful_pages = [
                        p for p in crawl_result.pages if p.status_code > 0
                    ]
                    if crawl_result.pages and not successful_pages:
                        sample_errors = [
                            f"{p.url}: {p.error}"
                            for p in crawl_result.pages[:3]
                            if p.error
                        ]
                        detail = "; ".join(sample_errors) or "all pages failed"
                        raise CrawlFailureError(
                            f"All {len(crawl_result.pages)} crawled URL(s) failed "
                            f"(network or proxy unreachable). First errors: {detail}"
                        )

                    self._emit("crawl_completed", {
                        "urls_discovered": len(self.discovered_urls),
                        "pages": len(crawl_result.pages),
                        "successful_pages": len(successful_pages),
                        "endpoints": len(crawl_result.endpoints),
                        "forms": len(crawl_result.forms),
                        "duration": crawl_result.duration_seconds,
                        "stopped_reason": crawl_result.stopped_reason,
                    })
                except CrawlFailureError:
                    # Propagate to the outer handler — nothing will be scanned.
                    raise
                except Exception as exc:
                    logger.warning("Crawl phase failed: %s", exc)
                    raise CrawlFailureError(
                        f"Crawler crashed: {type(exc).__name__}: {exc}"
                    ) from exc

                # ── Phase C: Scanners ────────────────────────────
                scan_targets = self._build_scan_targets()
                ordered_targets = [self.target_url] + [
                    t for t in scan_targets if t != self.target_url
                ]

                self._emit("scanners_started", {
                    "endpoints_count": len(ordered_targets),
                })

                scanners = [
                    HeadersScanner(client),
                    SQLiScanner(client),
                ]
                if self.enable_blind_sqli:
                    scanners.append(BlindSQLiScanner(client))
                scanners.extend([
                    XSSScanner(client),
                    OpenRedirectScanner(client),
                    CORSScanner(client),
                ])

                for endpoint in ordered_targets:
                    for scanner in scanners:
                        try:
                            detected = await scanner.scan(endpoint)
                            for finding in detected:
                                if finding.fingerprint in self.findings_dedup:
                                    continue
                                self.findings_dedup[finding.fingerprint] = finding

                                # Persist immediately — one transaction per finding
                                if self._scan_ctx is not None:
                                    self._scan_ctx.record_finding(finding)

                                self._emit("finding_created", {
                                    "title": finding.title,
                                    "severity": finding.severity.value,
                                    "confidence": finding.confidence.value,
                                    "url": finding.url,
                                })
                        except Exception as err:
                            logger.error(
                                "Scanner %s error on %s: %s",
                                scanner.name, endpoint, err,
                            )

        except CrawlFailureError as exc:
            error_msg = str(exc)
            self._emit("crawl_failed", {"reason": error_msg})
            logger.error("Assessment aborted: %s", error_msg)
        except ProxyConnectionError as exc:
            # Expected operational error — no traceback for the user.
            error_msg = f"{type(exc).__name__}: {exc}"
            self._emit("scan_failed", {"reason": error_msg})
            logger.error("Anonymity proxy unavailable: %s", exc)
        except SafeNetworkError as exc:
            # Other network-level failures (SSRF, scope, DNS, redirects, ...)
            # are also expected outcomes — report cleanly, no traceback.
            error_msg = f"{type(exc).__name__}: {exc}"
            self._emit("scan_failed", {"reason": error_msg})
            logger.error("Network error during assessment: %s", exc)
        except Exception as outer:
            # Anything else is a genuine bug — full traceback for debugging.
            error_msg = f"{type(outer).__name__}: {outer}"
            self._emit("scan_failed", {"reason": error_msg})
            logger.exception("Assessment engine failed: %s", outer)

        end_time = datetime.now(timezone.utc)
        all_findings = list(self.findings_dedup.values())

        summary = {
            "CRITICAL": sum(1 for f in all_findings if f.severity.value == "CRITICAL"),
            "HIGH":     sum(1 for f in all_findings if f.severity.value == "HIGH"),
            "MEDIUM":   sum(1 for f in all_findings if f.severity.value == "MEDIUM"),
            "LOW":      sum(1 for f in all_findings if f.severity.value == "LOW"),
            "INFO":     sum(1 for f in all_findings if f.severity.value == "INFO"),
            "total":    len(all_findings),
        }

        # ── Complete or fail persistence ─────────────────────────
        if self._scan_ctx is not None:
            if error_msg is None:
                self._scan_ctx.complete(
                    finding_count=len(all_findings),
                    discovered_urls_count=len(self.discovered_urls),
                )
            else:
                self._scan_ctx.fail(error_msg)

        result = AssessmentResult(
            target=self.target_url,
            scan_uid=self.scan_uid,
            start_time=start_time,
            end_time=end_time,
            discovered_urls=self.discovered_urls,
            findings=all_findings,
            technologies=technologies,
            summary=summary,
            error_msg=error_msg,
        )

        self._emit("scan_completed", {
            "findings_count": len(all_findings),
            "duration_seconds": (end_time - start_time).total_seconds(),
            "summary": summary,
            "scan_uid": self.scan_uid,
            "error": error_msg,
        })

        return result
