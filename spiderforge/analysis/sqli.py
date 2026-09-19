from __future__ import annotations

import re
import secrets

from spiderforge.analysis.base import (
    ModuleContext,
    SecurityModule,
    body_text,
    extract_params,
    in_scope_urls,
    with_param,
)
from spiderforge.findings.models import Evidence, Finding, Severity

ERROR_SIGNATURES: tuple[tuple[str, str], ...] = (
    (r"you have an error in your sql syntax", "MySQL"),
    (r"warning.*mysql_", "MySQL"),
    (r"unclosed quotation mark after the character string", "MSSQL"),
    (r"microsoft ole db provider for sql server", "MSSQL"),
    (r"odbc sql server driver", "MSSQL"),
    (r"postgresql.*error", "PostgreSQL"),
    (r"pg_query\(\)", "PostgreSQL"),
    (r"sqlite3\.operationalerror", "SQLite"),
    (r"sqlite error", "SQLite"),
    (r"ora-\d{5}", "Oracle"),
    (r"quoted string not properly terminated", "Oracle"),
    (r"invalid input syntax for", "PostgreSQL"),
    (r"sqlstate\[\w+\]", "Generic SQLState"),
    (r"jdbc.*sqlexception", "Java/JDBC"),
    (r"syntax error.*sql", "Generic"),
)


def _scan_error(body: str) -> str | None:
    low = body.lower()
    for sig, dbms in ERROR_SIGNATURES:
        if re.search(sig, low):
            return dbms
    return None


class SqliModule(SecurityModule):
    name = "sqli"
    category = "injection"
    description = "Error-based and boolean-differential SQL injection detection."

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []
        urls = in_scope_urls(ctx, require_params=True)[:10]

        for url in urls:
            for name, original in extract_params(url):
                if not original:
                    continue  # skip empty — baseline needs a value

                # --- Baseline ------------------------------------------------
                baseline_resp = await ctx.client.get(url, follow_redirects=False) if ctx.scope.is_allowed(url) else None
                if baseline_resp is None:
                    continue
                baseline_body = body_text(baseline_resp)
                baseline_len = len(baseline_resp.content)

                # --- Error-based --------------------------------------------
                "sf" + secrets.token_hex(3)
                quote_payload = original + "'"
                test_url = with_param(url, name, quote_payload)
                if not ctx.scope.is_allowed(test_url):
                    continue
                try:
                    resp = await ctx.client.get(test_url, follow_redirects=False)
                except Exception:
                    continue
                dbms = _scan_error(body_text(resp))
                if dbms and not _scan_error(baseline_body):
                    findings.append(
                        self.make_finding(
                            title=f"SQL injection (error-based) in `{name}`",
                            category="sqli.error",
                            severity=Severity.HIGH,
                            url=url,
                            parameter=name,
                            description=(
                                f"Injecting a single quote into `{name}` triggers a "
                                f"{dbms} database error. This strongly suggests the "
                                "input reaches a SQL query unsafely."
                            ),
                            impact="Full read/write access to the database, "
                            "authentication bypass, and potentially RCE via stacked "
                            "queries or database-specific features.",
                            remediation="Use parameterized queries (prepared "
                            "statements) for every database call. Never concatenate "
                            "user input into SQL. Add a generic error handler that "
                            "does not leak DBMS details.",
                            confidence=0.9,
                            evidence=Evidence(
                                request=f"GET {test_url}",
                                response=f"HTTP {resp.status_code}\n\n"
                                + body_text(resp, 3000),
                                payload=quote_payload,
                                notes=f"DBMS signature: {dbms}",
                            ),
                            root_cause=f"sqli_error:{name}",
                        )
                    )
                    continue  # one finding per parameter

                # --- Boolean-based ------------------------------------------
                true_p = f"{original}' AND '1'='1"
                false_p = f"{original}' AND '1'='2"
                true_url = with_param(url, name, true_p)
                false_url = with_param(url, name, false_p)
                if not (ctx.scope.is_allowed(true_url) and ctx.scope.is_allowed(false_url)):
                    continue
                try:
                    r_true = await ctx.client.get(true_url, follow_redirects=False)
                    r_false = await ctx.client.get(false_url, follow_redirects=False)
                except Exception:
                    continue

                t_len = len(r_true.content)
                f_len = len(r_false.content)
                baseline_delta_true = abs(t_len - baseline_len)
                baseline_delta_false = abs(f_len - baseline_len)

                # Heuristic: TRUE close to baseline, FALSE significantly different
                if (
                    baseline_delta_true < 64
                    and baseline_delta_false > 200
                    and r_true.status_code == r_false.status_code == baseline_resp.status_code
                ):
                    findings.append(
                        self.make_finding(
                            title=f"Potential boolean-based SQL injection in `{name}`",
                            category="sqli.boolean",
                            severity=Severity.HIGH,
                            url=url,
                            parameter=name,
                            description=(
                                f"A boolean TRUE payload returns a response close to "
                                f"baseline ({t_len} vs {baseline_len} bytes), while a "
                                f"FALSE payload differs substantially ({f_len} bytes)."
                            ),
                            impact="Data exfiltration via boolean oracle; "
                            "authentication bypass.",
                            remediation="Parameterize every query. Add WAF rules only "
                            "as defense-in-depth, never as the primary control.",
                            confidence=0.6,
                            evidence=Evidence(
                                request=f"GET {true_url}\n--- vs ---\nGET {false_url}",
                                response=(
                                    f"baseline_len={baseline_len}\n"
                                    f"true_len={t_len}\nfalse_len={f_len}\n"
                                    f"status_true={r_true.status_code} "
                                    f"status_false={r_false.status_code}"
                                ),
                                payload=f"TRUE: {true_p}\nFALSE: {false_p}",
                            ),
                            root_cause=f"sqli_boolean:{name}",
                        )
                    )
        return findings
