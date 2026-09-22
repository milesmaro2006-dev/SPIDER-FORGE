'use strict';

/* ═══════════════════════════════════════════════════════════════
   SpiderForge — Utilities
   ═══════════════════════════════════════════════════════════════ */

const Utils = (() => {

    // ─── DOM helpers ────────────────────────────────────────────
    function h(tag, props = {}, children = []) {
        const el = document.createElement(tag);
        for (const [k, v] of Object.entries(props)) {
            if (v == null || v === false) continue;
            if (k === 'class')       el.className = v;
            else if (k === 'text')   el.textContent = String(v);
            else if (k === 'html')   el.innerHTML = v;
            else if (k === 'on')     for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
            else if (k === 'dataset') for (const [dk, dv] of Object.entries(v)) el.dataset[dk] = dv;
            else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
            else if (v === true)     el.setAttribute(k, '');
            else                     el.setAttribute(k, v);
        }
        for (const c of [].concat(children)) {
            if (c == null || c === false) continue;
            el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
        }
        return el;
    }

    function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }

    function frag(children) {
        const f = document.createDocumentFragment();
        for (const c of [].concat(children)) {
            if (c == null || c === false) continue;
            f.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
        }
        return f;
    }

    function svgFrom(str) {
        const t = document.createElement('template');
        t.innerHTML = str.trim();
        return t.content.firstChild;
    }

    // ─── Formatting ─────────────────────────────────────────────
    function fmtTime(iso) {
        if (!iso) return '—';
        try {
            return new Date(iso).toLocaleString('en-GB', {
                year: 'numeric', month: '2-digit', day: '2-digit',
                hour: '2-digit', minute: '2-digit',
            });
        } catch { return iso; }
    }

    function fmtDate(iso) {
        if (!iso) return '—';
        try {
            return new Date(iso).toLocaleDateString('en-GB', {
                day: '2-digit', month: 'short', year: 'numeric',
            });
        } catch { return iso; }
    }

    function fmtRelative(iso) {
        if (!iso) return '—';
        const s = (Date.now() - new Date(iso).getTime()) / 1000;
        if (s < 60)    return 'just now';
        if (s < 3600)  return `${Math.floor(s / 60)}m ago`;
        if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
        if (s < 604800) return `${Math.floor(s / 86400)}d ago`;
        return fmtDate(iso);
    }

    function fmtDuration(startIso, endIso) {
        if (!startIso) return '—';
        const s = new Date(startIso);
        const e = endIso ? new Date(endIso) : new Date();
        const sec = Math.max(0, (e - s) / 1000);
        if (sec < 60) return `${sec.toFixed(1)}s`;
        if (sec < 3600) return `${Math.floor(sec / 60)}m ${Math.round(sec % 60)}s`;
        return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
    }

    function shortTarget(url) {
        if (!url) return '—';
        try {
            const u = new URL(url);
            const path = u.pathname && u.pathname !== '/' ? u.pathname : '';
            return u.hostname + path;
        } catch { return url; }
    }

    function hostOf(url) {
        if (!url) return '—';
        try { return new URL(url).hostname; } catch { return url; }
    }

    function truncate(s, n = 60) {
        s = String(s ?? '');
        return s.length > n ? s.slice(0, n - 1) + '…' : s;
    }

    // ─── Severity ───────────────────────────────────────────────
    const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    const SEV_LIST  = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

    function severityKey(s) {
        const k = String(s || 'INFO').toUpperCase();
        return SEV_LIST.includes(k) ? k : 'INFO';
    }

    function countSeverities(findings) {
        const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
        (findings || []).forEach(f => { counts[severityKey(f.severity)]++; });
        return counts;
    }

    // ─── Escape ─────────────────────────────────────────────────
    function escHtml(s) {
        return String(s ?? '').replace(/[&<>"']/g, c => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
        }[c]));
    }

    // ─── Storage ────────────────────────────────────────────────
    const Storage = {
        get(key, fallback = null) {
            try {
                const v = localStorage.getItem(`sf.${key}`);
                return v == null ? fallback : JSON.parse(v);
            } catch { return fallback; }
        },
        set(key, value) {
            try { localStorage.setItem(`sf.${key}`, JSON.stringify(value)); }
            catch { /* ignore quota errors */ }
        },
        remove(key) {
            try { localStorage.removeItem(`sf.${key}`); } catch {}
        },
    };

    // ─── Clipboard ──────────────────────────────────────────────
    async function copy(text) {
        try {
            await navigator.clipboard.writeText(String(text));
            return true;
        } catch {
            // Fallback for insecure contexts
            try {
                const ta = document.createElement('textarea');
                ta.value = String(text);
                ta.style.position = 'fixed';
                ta.style.opacity = '0';
                document.body.appendChild(ta);
                ta.select();
                const ok = document.execCommand('copy');
                document.body.removeChild(ta);
                return ok;
            } catch { return false; }
        }
    }

    // ─── Debounce / Throttle ────────────────────────────────────
    function debounce(fn, ms = 200) {
        let t;
        return (...args) => {
            clearTimeout(t);
            t = setTimeout(() => fn(...args), ms);
        };
    }

    function throttle(fn, ms = 200) {
        let last = 0, timer;
        return (...args) => {
            const now = Date.now();
            const remaining = ms - (now - last);
            clearTimeout(timer);
            if (remaining <= 0) {
                last = now;
                fn(...args);
            } else {
                timer = setTimeout(() => { last = Date.now(); fn(...args); }, remaining);
            }
        };
    }

    // ─── Download ───────────────────────────────────────────────
    function downloadBlob(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    function downloadJSON(data, filename) {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        downloadBlob(blob, filename);
    }

    function downloadCSV(rows, headers, filename) {
        const escape = (v) => {
            const s = String(v ?? '');
            return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
        };
        const lines = [headers.join(',')];
        rows.forEach(r => lines.push(r.map(escape).join(',')));
        const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' });
        downloadBlob(blob, filename);
    }

    return {
        h, clear, frag, svgFrom,
        fmtTime, fmtDate, fmtRelative, fmtDuration,
        shortTarget, hostOf, truncate,
        SEV_ORDER, SEV_LIST, severityKey, countSeverities,
        escHtml, Storage, copy,
        debounce, throttle,
        downloadBlob, downloadJSON, downloadCSV,
    };
})();
