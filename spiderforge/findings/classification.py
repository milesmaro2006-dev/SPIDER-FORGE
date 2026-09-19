"""Vulnerability Classification Registry.

Central mapping from vulnerability categories → CWE, OWASP, CVSS preset,
and reference links.

Applied automatically to Finding instances when those fields are empty.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from spiderforge.findings.cvss import PRESETS

# ═══════════════════════════════════════════════════════════════
#  Confidence → CVSS cap
# ═══════════════════════════════════════════════════════════════

# Confidence tiers cap the maximum CVSS score we'll report.
#
# Rationale: a finding we're not confident about should not be reported
# with the same CVSS as a fully-confirmed one. The cap preserves the
# relative ordering (CONFIRMED ≥ HIGH ≥ MEDIUM ≥ LOW) while preventing
# LOW-confidence findings from being flagged CRITICAL.
#
# Values chosen so that:
#   CANDIDATE → max MEDIUM (5.9)
#   LOW       → max HIGH   (7.9)
#   MEDIUM / HIGH / CONFIRMED → no cap
_CONFIDENCE_CVSS_CAP: dict[str, float] = {
    "CANDIDATE": 5.9,
    "LOW": 7.9,
    "MEDIUM": 10.0,
    "HIGH": 10.0,
    "CONFIRMED": 10.0,
}


def _adjust_cvss_for_confidence(score: float, confidence: Any) -> float:
    """Cap the CVSS base score according to the finding's confidence tier.

    Non-destructive: never raises. Unknown confidence → no cap.
    """
    try:
        key = confidence.value if hasattr(confidence, "value") else str(confidence).upper()
    except Exception:
        return score
    cap = _CONFIDENCE_CVSS_CAP.get(key, 10.0)
    return round(min(score, cap), 1)


# ═══════════════════════════════════════════════════════════════
#  Classification model
# ═══════════════════════════════════════════════════════════════

@dataclass
class Classification:
    cwe_id: str | None = None
    cwe_name: str | None = None
    owasp_top10_2021: str | None = None
    owasp_api_top10_2023: str | None = None
    cvss_preset: str | None = None
    references: list[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════
#  Registry
# ═══════════════════════════════════════════════════════════════

REGISTRY: dict[str, Classification] = {

    # ── XSS ────────────────────────────────────────────────
    "xss": Classification(
        cwe_id="CWE-79",
        cwe_name="Improper Neutralization of Input During Web Page Generation",
        owasp_top10_2021="A03:2021 - Injection",
        cvss_preset="reflected_xss",
        references=[
            "https://owasp.org/www-community/attacks/xss/",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    ),
    "xss.reflected": Classification(
        cwe_id="CWE-79",
        cwe_name="Improper Neutralization of Input During Web Page Generation",
        owasp_top10_2021="A03:2021 - Injection",
        cvss_preset="reflected_xss",
        references=[
            "https://owasp.org/www-community/attacks/xss/",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    ),
    "xss.stored": Classification(
        cwe_id="CWE-79",
        cwe_name="Improper Neutralization of Input During Web Page Generation",
        owasp_top10_2021="A03:2021 - Injection",
        cvss_preset="stored_xss",
    ),
    "xss.dom": Classification(
        cwe_id="CWE-79",
        cwe_name="Improper Neutralization of Input During Web Page Generation",
        owasp_top10_2021="A03:2021 - Injection",
        cvss_preset="reflected_xss",
    ),

    # ── SQL Injection ─────────────────────────────────────
    "sqli": Classification(
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        owasp_top10_2021="A03:2021 - Injection",
        cvss_preset="sqli",
        references=[
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    ),
    "sqli.error": Classification(
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        owasp_top10_2021="A03:2021 - Injection",
        cvss_preset="sqli",
    ),
    "sqli.error_based": Classification(
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        owasp_top10_2021="A03:2021 - Injection",
        cvss_preset="sqli",
    ),
    "sqli.boolean": Classification(
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        owasp_top10_2021="A03:2021 - Injection",
        cvss_preset="sqli",
    ),
    "sqli.time": Classification(
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        owasp_top10_2021="A03:2021 - Injection",
        cvss_preset="sqli",
    ),
    "sqli.union": Classification(
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        owasp_top10_2021="A03:2021 - Injection",
        cvss_preset="sqli",
    ),

    # ── SSRF ──────────────────────────────────────────────
    "ssrf": Classification(
        cwe_id="CWE-918",
        cwe_name="Server-Side Request Forgery (SSRF)",
        owasp_top10_2021="A10:2021 - Server-Side Request Forgery (SSRF)",
        cvss_preset="ssrf",
        references=[
            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
            "https://cwe.mitre.org/data/definitions/918.html",
        ],
    ),

    # ── SSTI ──────────────────────────────────────────────
    "ssti": Classification(
        cwe_id="CWE-94",
        cwe_name="Improper Control of Generation of Code ('Code Injection')",
        owasp_top10_2021="A03:2021 - Injection",
        cvss_preset="ssti",
        references=[
            "https://cwe.mitre.org/data/definitions/94.html",
        ],
    ),

    # ── XXE ───────────────────────────────────────────────
    "xxe": Classification(
        cwe_id="CWE-611",
        cwe_name="Improper Restriction of XML External Entity Reference",
        owasp_top10_2021="A05:2021 - Security Misconfiguration",
        cvss_preset="xxe",
        references=[
            "https://cwe.mitre.org/data/definitions/611.html",
        ],
    ),

    # ── Path Traversal / LFI ──────────────────────────────
    "path_traversal": Classification(
        cwe_id="CWE-22",
        cwe_name="Improper Limitation of a Pathname to a Restricted Directory",
        owasp_top10_2021="A01:2021 - Broken Access Control",
        cvss_preset="path_traversal",
    ),
    "lfi": Classification(
        cwe_id="CWE-98",
        cwe_name="Improper Control of Filename for Include/Require Statement",
        owasp_top10_2021="A03:2021 - Injection",
        cvss_preset="path_traversal",
    ),

    # ── Security Headers ──────────────────────────────────
    "security_headers": Classification(
        cwe_id="CWE-693",
        cwe_name="Protection Mechanism Failure",
        owasp_top10_2021="A05:2021 - Security Misconfiguration",
        cvss_preset="missing_header",
    ),
    "headers.csp": Classification(
        cwe_id="CWE-693",
        cwe_name="Protection Mechanism Failure",
        owasp_top10_2021="A05:2021 - Security Misconfiguration",
        cvss_preset="missing_header",
    ),
    "headers.hsts": Classification(
        cwe_id="CWE-319",
        cwe_name="Cleartext Transmission of Sensitive Information",
        owasp_top10_2021="A02:2021 - Cryptographic Failures",
        cvss_preset="missing_header",
    ),
    "headers.xframe": Classification(
        cwe_id="CWE-1021",
        cwe_name="Improper Restriction of Rendered UI Layers or Frames",
        owasp_top10_2021="A05:2021 - Security Misconfiguration",
        cvss_preset="missing_header",
    ),
    "headers.xcontent": Classification(
        cwe_id="CWE-16",
        cwe_name="Configuration",
        owasp_top10_2021="A05:2021 - Security Misconfiguration",
        cvss_preset="missing_header",
    ),
    "headers.referrer": Classification(
        cwe_id="CWE-200",
        cwe_name="Exposure of Sensitive Information",
        owasp_top10_2021="A01:2021 - Broken Access Control",
        cvss_preset="missing_header",
    ),
    "headers.permissions": Classification(
        cwe_id="CWE-693",
        cwe_name="Protection Mechanism Failure",
        owasp_top10_2021="A05:2021 - Security Misconfiguration",
        cvss_preset="missing_header",
    ),

    # ── CORS ──────────────────────────────────────────────
    "cors": Classification(
        cwe_id="CWE-942",
        cwe_name="Permissive Cross-domain Policy with Untrusted Domains",
        owasp_top10_2021="A05:2021 - Security Misconfiguration",
        cvss_preset="cors_reflection_creds",
    ),
    "cors.wildcard_credentials": Classification(
        cwe_id="CWE-942",
        cwe_name="Permissive Cross-domain Policy with Untrusted Domains",
        owasp_top10_2021="A05:2021 - Security Misconfiguration",
        cvss_preset="cors_reflection_creds",
    ),
    "cors.origin_reflection_creds": Classification(
        cwe_id="CWE-942",
        cwe_name="Permissive Cross-domain Policy with Untrusted Domains",
        owasp_top10_2021="A05:2021 - Security Misconfiguration",
        cvss_preset="cors_reflection_creds",
    ),
    "cors.origin_reflection": Classification(
        cwe_id="CWE-942",
        cwe_name="Permissive Cross-domain Policy with Untrusted Domains",
        owasp_top10_2021="A05:2021 - Security Misconfiguration",
        cvss_preset="cors_reflection_creds",
    ),

    # ── Open Redirect ─────────────────────────────────────
    "open_redirect": Classification(
        cwe_id="CWE-601",
        cwe_name="URL Redirection to Untrusted Site ('Open Redirect')",
        owasp_top10_2021="A01:2021 - Broken Access Control",
        cvss_preset="open_redirect",
    ),
    "redirect": Classification(
        cwe_id="CWE-601",
        cwe_name="URL Redirection to Untrusted Site ('Open Redirect')",
        owasp_top10_2021="A01:2021 - Broken Access Control",
        cvss_preset="open_redirect",
    ),

    # ── IDOR / BOLA ───────────────────────────────────────
    "idor": Classification(
        cwe_id="CWE-639",
        cwe_name="Authorization Bypass Through User-Controlled Key",
        owasp_top10_2021="A01:2021 - Broken Access Control",
        owasp_api_top10_2023="API1:2023 - Broken Object Level Authorization",
        cvss_preset="idor",
    ),
    "bola": Classification(
        cwe_id="CWE-639",
        cwe_name="Authorization Bypass Through User-Controlled Key",
        owasp_top10_2021="A01:2021 - Broken Access Control",
        owasp_api_top10_2023="API1:2023 - Broken Object Level Authorization",
        cvss_preset="idor",
    ),

    # ── CSRF ──────────────────────────────────────────────
    "csrf": Classification(
        cwe_id="CWE-352",
        cwe_name="Cross-Site Request Forgery (CSRF)",
        owasp_top10_2021="A01:2021 - Broken Access Control",
        cvss_preset="csrf",
    ),

    # ── Info Disclosure ───────────────────────────────────
    "info_disclosure": Classification(
        cwe_id="CWE-200",
        cwe_name="Exposure of Sensitive Information",
        owasp_top10_2021="A01:2021 - Broken Access Control",
        cvss_preset="info_leak",
    ),
    "info_leak": Classification(
        cwe_id="CWE-200",
        cwe_name="Exposure of Sensitive Information",
        owasp_top10_2021="A01:2021 - Broken Access Control",
        cvss_preset="info_leak",
    ),

    # ── Cookies ───────────────────────────────────────────
    "cookies": Classification(
        cwe_id="CWE-1004",
        cwe_name="Sensitive Cookie Without 'HttpOnly' Flag",
        owasp_top10_2021="A05:2021 - Security Misconfiguration",
        cvss_preset="cookie_flag",
    ),
    "cookies.secure": Classification(
        cwe_id="CWE-614",
        cwe_name="Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        owasp_top10_2021="A05:2021 - Security Misconfiguration",
        cvss_preset="cookie_flag",
    ),
    "cookies.httponly": Classification(
        cwe_id="CWE-1004",
        cwe_name="Sensitive Cookie Without 'HttpOnly' Flag",
        owasp_top10_2021="A05:2021 - Security Misconfiguration",
        cvss_preset="cookie_flag",
    ),
    "cookies.samesite": Classification(
        cwe_id="CWE-1275",
        cwe_name="Sensitive Cookie with Improper SameSite Attribute",
        owasp_top10_2021="A05:2021 - Security Misconfiguration",
        cvss_preset="cookie_flag",
    ),
}


# ═══════════════════════════════════════════════════════════════
#  Lookup
# ═══════════════════════════════════════════════════════════════

def classify(category: str) -> Classification | None:
    """Look up classification by category, falling back to prefix match."""
    if not category:
        return None
    cat = category.strip().lower()
    if cat in REGISTRY:
        return REGISTRY[cat]
    prefix = cat.split(".")[0]
    return REGISTRY.get(prefix)


def apply_classification(finding: Any) -> None:
    """Fill missing classification fields on a Finding-like object.

    Non-destructive: only fills fields that are empty/None.

    CVSS adjustment:
        The base CVSS score from the preset is capped according to the
        finding's confidence tier (see ``_CONFIDENCE_CVSS_CAP``). This
        keeps low-confidence findings from being reported as CRITICAL.
    """
    cat = getattr(finding, "category", None)
    classification = classify(cat)
    if classification is None:
        return

    # CWE
    if not getattr(finding, "cwe_id", None) and classification.cwe_id:
        finding.cwe_id = classification.cwe_id

    # OWASP
    if not getattr(finding, "owasp_category", None) and classification.owasp_top10_2021:
        finding.owasp_category = classification.owasp_top10_2021

    # CVSS score + vector
    preset_key = classification.cvss_preset
    if preset_key:
        preset = PRESETS.get(preset_key)
        if preset is not None:
            if getattr(finding, "cvss_score", None) is None:
                base = preset.base_score()
                finding.cvss_score = _adjust_cvss_for_confidence(
                    base, getattr(finding, "confidence", None)
                )
            if not getattr(finding, "cvss_vector", None):
                finding.cvss_vector = preset.vector()


def cwe_name_for(cwe_id: str) -> str | None:
    """Look up a human-readable CWE name by CWE ID."""
    if not cwe_id:
        return None
    for c in REGISTRY.values():
        if c.cwe_id == cwe_id:
            return c.cwe_name
    return None
