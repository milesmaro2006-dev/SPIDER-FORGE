'use strict';

/* ═══════════════════════════════════════════════════════════════
   SpiderForge — Unified Frontend
   ═══════════════════════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════════════════════
   PART 1: UTILS
   ═══════════════════════════════════════════════════════════════ */

const Utils = (() => {

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
        if (s < 60)     return 'just now';
        if (s < 3600)   return `${Math.floor(s / 60)}m ago`;
        if (s < 86400)  return `${Math.floor(s / 3600)}h ago`;
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

    function escHtml(s) {
        return String(s ?? '').replace(/[&<>"']/g, c => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
        }[c]));
    }

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

    async function copy(text) {
        try {
            await navigator.clipboard.writeText(String(text));
            return true;
        } catch {
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

/* ═══════════════════════════════════════════════════════════════
   PART 2: API
   ═══════════════════════════════════════════════════════════════ */

const API = (() => {

    const ENDPOINTS = {
        health:       '/api/health',
        capabilities: '/api/capabilities',
        scan:         '/api/scan',
        scans:        (limit = 20) => `/api/scans?limit=${limit}`,
        scanById:     (id) => `/api/scans/${id}`,
        findings:     (id) => `/api/scans/${id}/findings`,
        report:       (id, fmt, download = false) =>
            `/api/scans/${id}/report?format=${fmt}${download ? '&download=true' : ''}`,
        bundle:       (id) => `/api/scans/${id}/report/bundle`,
    };

    async function request(url, opts = {}) {
        let resp;
        try {
            resp = await fetch(url, opts);
        } catch (e) {
            const err = new Error('Cannot reach the SpiderForge backend. Is the server running?');
            err.code = 'NETWORK_ERROR';
            throw err;
        }

        let data = {};
        const text = await resp.text().catch(() => '');
        if (text) {
            try { data = JSON.parse(text); } catch { data = {}; }
        }

        if (!resp.ok) {
            const msg =
                data?.error?.message ||
                data?.error?.detail ||
                data?.detail ||
                `Request failed (HTTP ${resp.status})`;
            const err = new Error(msg);
            err.code = data?.error?.code || `HTTP_${resp.status}`;
            err.detail = data?.error?.detail || '';
            err.status = resp.status;
            throw err;
        }
        return data;
    }

    return {
        ENDPOINTS,
        request,
        health:       () => request(ENDPOINTS.health),
        capabilities: () => request(ENDPOINTS.capabilities),
        listScans:    (limit = 20) => request(ENDPOINTS.scans(limit)),
        getScan:      (id) => request(ENDPOINTS.scanById(id)),
        getFindings:  (id) => request(ENDPOINTS.findings(id)),

        async runScan(payload) {
            return request(ENDPOINTS.scan, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
        },

        reportUrl: (id, fmt, download = false) => ENDPOINTS.report(id, fmt, download),
        bundleUrl: (id) => ENDPOINTS.bundle(id),
    };
})();

/* ═══════════════════════════════════════════════════════════════
   PART 3: UI
   ═══════════════════════════════════════════════════════════════ */

const UI = (() => {
    const { h, svgFrom, SEV_LIST, severityKey, copy } = Utils;

    const ICON = {
        search:  `<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>`,
        check:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>`,
        warn:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.7 3.86a2 2 0 0 0-3.4 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>`,
        err:     `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>`,
        info:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>`,
        target:  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.4" fill="currentColor"/></svg>`,
        shield:  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
        activity:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 8-6-16-3 8H2"/></svg>`,
        back:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5"/><path d="m12 19-7-7 7-7"/></svg>`,
        plus:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14"/><path d="M5 12h14"/></svg>`,
        download:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg>`,
        eye:     `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>`,
        ghost:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 3 7v10l9 5 9-5V7z" opacity="0.5"/></svg>`,
        refresh: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2v6h-6"/><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M3 22v-6h6"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/></svg>`,
        x:       `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>`,
        copy:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`,
        filter:  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 3H2l8 9.5V19l4 2v-8.5z"/></svg>`,
    };

    function toast(msg, kind = 'info', timeout = 4200) {
        const host = document.getElementById('toast-host');
        if (!host) return;
        const iconKey = kind === 'error' ? 'err'
                      : kind === 'ok'    ? 'check'
                      : kind === 'warn'  ? 'warn'
                      : 'info';
        const icon = svgFrom(ICON[iconKey]);
        icon.style.color = kind === 'error' ? 'var(--err)'
                         : kind === 'ok'    ? 'var(--ok)'
                         : kind === 'warn'  ? 'var(--warn)'
                         : 'var(--cyan)';

        const t = h('div', { class: `toast ${kind === 'info' ? '' : kind}` }, [icon]);
        t.appendChild(h('div', { class: 'toast-body', text: msg }));
        host.appendChild(t);

        setTimeout(() => {
            t.style.transition = 'opacity .25s, transform .25s';
            t.style.opacity = '0';
            t.style.transform = 'translateX(16px)';
            setTimeout(() => t.remove(), 280);
        }, timeout);
    }

    function openModal({ title, body, actions = [], size = 'md' }) {
        const host = document.getElementById('modal-host');
        const modal = document.getElementById('modal');
        if (!host || !modal) return { close: () => {} };
        modal.className = `modal modal-${size}`;
        modal.innerHTML = '';

        const head = h('div', { class: 'modal-head' }, [
            h('h3', { class: 'modal-title', text: title }),
            h('button', {
                class: 'icon-btn modal-close',
                'aria-label': 'Close',
                html: ICON.x,
                on: { click: closeModal },
            }),
        ]);
        modal.appendChild(head);

        const bodyEl = h('div', { class: 'modal-body' });
        if (typeof body === 'string') bodyEl.innerHTML = body;
        else if (body) bodyEl.appendChild(body);
        modal.appendChild(bodyEl);

        if (actions.length) {
            const foot = h('div', { class: 'modal-foot' });
            actions.forEach(a => foot.appendChild(a));
            modal.appendChild(foot);
        }

        host.hidden = false;
        document.body.style.overflow = 'hidden';

        const onKey = (e) => { if (e.key === 'Escape') closeModal(); };
        document.addEventListener('keydown', onKey);
        modal._onKey = onKey;

        return { close: closeModal };
    }

    function closeModal() {
        const host = document.getElementById('modal-host');
        const modal = document.getElementById('modal');
        if (!host || !modal) return;
        if (modal._onKey) document.removeEventListener('keydown', modal._onKey);
        host.hidden = true;
        document.body.style.overflow = '';
    }

    function confirm({ title, message, confirmText = 'Confirm', cancelText = 'Cancel', danger = false }) {
        return new Promise((resolve) => {
            const body = h('p', { text: message, style: { color: 'var(--text-dim)', lineHeight: '1.6' } });

            const cancel = h('button', {
                class: 'btn btn-ghost',
                text: cancelText,
                on: { click: () => { closeModal(); resolve(false); } },
            });
            const ok = h('button', {
                class: `btn ${danger ? 'btn-danger' : 'btn-primary'}`,
                text: confirmText,
                on: { click: () => { closeModal(); resolve(true); } },
            });

            openModal({ title, body, actions: [cancel, ok] });
        });
    }

    function pageHead({ eyebrow, title, sub, actions }) {
        const head = h('div', { class: 'page-head' });
        const left = h('div');
        if (eyebrow) left.appendChild(h('div', { class: 'page-eyebrow', text: eyebrow }));
        left.appendChild(h('h1', { class: 'page-title', text: title }));
        if (sub) left.appendChild(h('p', { class: 'page-sub', text: sub }));
        head.appendChild(left);
        if (actions && actions.length) head.appendChild(h('div', { class: 'page-actions' }, actions));
        return head;
    }

    function metric(label, value, { tone = '', icon = null, small = false, hint = null } = {}) {
        const top = h('div', { class: 'metric-top' }, [
            h('span', { class: 'metric-label', text: label }),
        ]);
        if (icon) {
            const i = svgFrom(icon);
            i.setAttribute('class', 'metric-ico');
            top.appendChild(i);
        }
        const val = h('div', {
            class: `metric-value ${tone}${small ? ' is-small' : ''}`,
            text: String(value),
        });
        const wrap = h('div', { class: 'metric' }, [top, val]);
        if (hint) wrap.appendChild(h('div', { class: 'metric-hint', text: hint }));
        return wrap;
    }

    function emptyState({ icon = ICON.ghost, title, text, action = null }) {
        const wrap = h('div', { class: 'empty' });
        const ic = h('div', { class: 'empty-icon' });
        ic.appendChild(svgFrom(icon));
        wrap.appendChild(ic);
        if (title) wrap.appendChild(h('div', { class: 'empty-title', text: title }));
        if (text)  wrap.appendChild(h('div', { class: 'empty-text', text: text }));
        if (action) {
            const row = h('div', { class: 'empty-action' });
            row.appendChild(action);
            wrap.appendChild(row);
        }
        return wrap;
    }

    function errorState(err) {
        const wrap = h('div', { class: 'alert alert-error' });
        wrap.appendChild(svgFrom(ICON.err));
        const body = h('div');
        body.appendChild(h('div', { class: 'alert-title', text: err.message || 'Something went wrong.' }));
        if (err.detail) body.appendChild(h('div', { class: 'alert-detail', text: err.detail }));
        wrap.appendChild(body);
        return wrap;
    }

    function skeletonList(n = 5) {
        const wrap = h('div');
        for (let i = 0; i < n; i++) wrap.appendChild(h('div', { class: 'skeleton skeleton-row' }));
        return wrap;
    }

    function codeBlock(label, value) {
        const pre = h('pre');
        pre.appendChild(h('code', { text: String(value) }));

        const copyBtn = h('button', {
            type: 'button',
            class: 'code-copy',
            html: `${ICON.copy}<span>Copy</span>`,
            on: {
                click: async (e) => {
                    e.stopPropagation();
                    const ok = await copy(String(value));
                    copyBtn.classList.toggle('copied', ok);
                    copyBtn.querySelector('span').textContent = ok ? 'Copied' : 'Failed';
                    setTimeout(() => {
                        copyBtn.classList.remove('copied');
                        copyBtn.querySelector('span').textContent = 'Copy';
                    }, 1400);
                },
            },
        });

        return h('div', { class: 'code-block' }, [
            h('div', { class: 'code-head' }, [h('span', { text: label }), copyBtn]),
            pre,
        ]);
    }

    function buildFinding(f, { showScanLink = false } = {}) {
        const sev = severityKey(f.severity);

        const head = h('div', { class: 'finding-head' }, [
            h('div', { class: 'finding-title', text: f.title || 'Finding' }),
            h('span', { class: `badge sev-${sev.toLowerCase()}`, text: sev }),
        ]);

        const meta = h('div', { class: 'finding-meta' });
        const pushTag = (label, val, cls = '') => {
            if (val == null || val === '') return;
            meta.appendChild(h('span', { class: `tag ${cls}` }, [
                h('span', { class: 'tag-k', text: label }),
                h('span', { class: 'tag-v', text: String(val) }),
            ]));
        };

        if (f.cvss_score != null) pushTag('CVSS', f.cvss_score, 'cvss-tag');
        pushTag('URL', Utils.shortTarget(f.url));
        pushTag('Param', f.param, 'accent');
        pushTag('Category', f.category);
        pushTag('CWE', f.cwe);
        pushTag('OWASP', f.owasp);
        pushTag('Scanner', f.scanner);

        if (showScanLink && f._scanId != null) {
            const link = h('span', {
                class: 'tag accent tag-link',
                on: { click: (e) => { e.stopPropagation(); location.hash = `#/scan/${f._scanId}`; } },
            }, [
                h('span', { class: 'tag-k', text: 'Scan' }),
                h('span', { class: 'tag-v', text: `#${f._scanId}` }),
            ]);
            meta.appendChild(link);
        }

        const wrap = h('div', { class: `finding sev-${sev.toLowerCase()}` }, [head]);
        if (meta.children.length > 0) wrap.appendChild(meta);
        if (f.description) wrap.appendChild(h('div', { class: 'finding-desc', text: f.description }));

        if (f.payload)  wrap.appendChild(codeBlock('Payload', f.payload));
        if (f.evidence) wrap.appendChild(codeBlock('Evidence', f.evidence));

        if (f.remediation) {
            wrap.appendChild(h('div', { class: 'remediation' }, [
                h('strong', { text: 'Remediation' }),
                h('div', { text: f.remediation }),
            ]));
        }

        return wrap;
    }

    function severitySummary(counts, { onClick = null, active = 'all' } = {}) {
        const wrap = h('div', { class: 'sev-summary' });
        SEV_LIST.forEach(k => {
            const box = h('button', {
                type: 'button',
                class: `sev-box ${k.toLowerCase()}${active === k.toLowerCase() || active === 'all' ? '' : ' dim'}${active === k.toLowerCase() ? ' active' : ''}`,
                dataset: { sev: k.toLowerCase() },
            }, [
                h('div', { class: 'label', text: k }),
                h('div', { class: 'value', text: String(counts[k] || 0) }),
            ]);
            if (onClick) box.addEventListener('click', () => onClick(k.toLowerCase()));
            wrap.appendChild(box);
        });
        return wrap;
    }

    function reportPanel(scanId, capabilities) {
        const caps = capabilities?.reports || {};
        const pdfOk = !!(caps.pdf && caps.pdf.available);

        const panel = h('div', { class: 'panel' });
        panel.appendChild(h('div', { class: 'panel-head' }, [
            h('div', { class: 'panel-title', text: 'Reports' }),
            h('div', { class: 'panel-sub', text: 'Download or view this scan\'s report in multiple formats.' }),
        ]));

        const actions = h('div', { class: 'report-actions' });

        actions.appendChild(h('a', {
            href: API.reportUrl(scanId, 'html', false),
            target: '_blank', rel: 'noopener',
            class: 'report-action',
            html: `${ICON.eye}<span>View HTML</span>`,
        }));
        actions.appendChild(h('a', {
            href: API.reportUrl(scanId, 'json', true),
            class: 'report-action',
            html: `${ICON.download}<span>JSON</span>`,
        }));
        actions.appendChild(h('a', {
            href: API.reportUrl(scanId, 'md', true),
            class: 'report-action',
            html: `${ICON.download}<span>Markdown</span>`,
        }));

        if (pdfOk) {
            actions.appendChild(h('a', {
                href: API.reportUrl(scanId, 'pdf', true),
                class: 'report-action',
                html: `${ICON.download}<span>PDF</span>`,
            }));
        } else {
            actions.appendChild(h('a', {
                class: 'report-action disabled',
                title: caps.pdf?.reason || 'PDF renderer not installed',
                html: `${ICON.download}<span>PDF unavailable</span>`,
            }));
        }

        actions.appendChild(h('a', {
            href: API.bundleUrl(scanId),
            class: 'report-action',
            html: `${ICON.download}<span>Bundle (.zip)</span>`,
        }));

        panel.appendChild(actions);
        return panel;
    }

    function scansTable(scans, { onRowClick = null } = {}) {
        const wrap = h('div', { class: 'table-wrap' });
        const table = h('table', { class: 'table', role: 'table' });

        table.appendChild(h('thead', {}, [
            h('tr', {}, [
                h('th', { text: 'ID' }),
                h('th', { text: 'Target' }),
                h('th', { text: 'Status' }),
                h('th', { text: 'Findings', class: 'right' }),
                h('th', { text: 'Started' }),
                h('th', { text: 'Duration' }),
            ]),
        ]));

        const tbody = h('tbody');
        scans.forEach(s => {
            const row = h('tr', {
                class: 'clickable',
                tabindex: '0',
                on: {
                    click: () => onRowClick ? onRowClick(s) : (location.hash = `#/scan/${s.id}`),
                    keydown: (e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            onRowClick ? onRowClick(s) : (location.hash = `#/scan/${s.id}`);
                        }
                    },
                },
            }, [
                h('td', { class: 'mono strong', text: `#${s.id}` }),
                h('td', { class: 'strong' }, [
                    h('div', { text: Utils.shortTarget(s.target) }),
                    h('div', { class: 'row-sub mono', text: Utils.hostOf(s.target) }),
                ]),
                h('td', {}, [h('span', { class: `badge status-${s.status}`, text: s.status })]),
                h('td', { class: 'mono right' }, [
                    h('span', {
                        class: `finding-count ${s.finding_count > 0 ? 'has-findings' : 'clean'}`,
                        text: String(s.finding_count ?? 0),
                    }),
                ]),
                h('td', { class: 'mono' }, [
                    h('div', { text: Utils.fmtTime(s.started_at) }),
                    h('div', { class: 'row-sub', text: Utils.fmtRelative(s.started_at) }),
                ]),
                h('td', { class: 'mono', text: Utils.fmtDuration(s.started_at, s.finished_at) }),
            ]);
            tbody.appendChild(row);
        });
        table.appendChild(tbody);
        wrap.appendChild(table);
        return wrap;
    }

    return {
        ICON,
        toast,
        openModal, closeModal, confirm,
        pageHead, metric,
        emptyState, errorState, skeletonList,
        codeBlock, buildFinding, severitySummary,
        reportPanel, scansTable,
    };
})();

/* ═══════════════════════════════════════════════════════════════
   PART 4: CHARTS
   ═══════════════════════════════════════════════════════════════ */

const Charts = (() => {
    const { h, SEV_LIST } = Utils;

    const SEV_COLORS = {
        CRITICAL: '#ff2d55',
        HIGH:     '#ff6b35',
        MEDIUM:   '#ffb020',
        LOW:      '#00e0ff',
        INFO:     '#8899aa',
    };

    function donut(counts, { size = 180, thickness = 26 } = {}) {
        const total = SEV_LIST.reduce((a, k) => a + (counts[k] || 0), 0);
        const radius = (size - thickness) / 2;
        const cx = size / 2;
        const cy = size / 2;
        const circumference = 2 * Math.PI * radius;

        const svgNS = 'http://www.w3.org/2000/svg';
        const svg = document.createElementNS(svgNS, 'svg');
        svg.setAttribute('viewBox', `0 0 ${size} ${size}`);
        svg.setAttribute('class', 'chart-donut');
        svg.setAttribute('width', size);
        svg.setAttribute('height', size);

        const bg = document.createElementNS(svgNS, 'circle');
        bg.setAttribute('cx', cx);
        bg.setAttribute('cy', cy);
        bg.setAttribute('r', radius);
        bg.setAttribute('fill', 'none');
        bg.setAttribute('stroke', 'var(--border-2)');
        bg.setAttribute('stroke-width', thickness);
        svg.appendChild(bg);

        if (total === 0) {
            const t = document.createElementNS(svgNS, 'text');
            t.setAttribute('x', cx);
            t.setAttribute('y', cy + 6);
            t.setAttribute('text-anchor', 'middle');
            t.setAttribute('class', 'chart-donut-label');
            t.textContent = 'Clean';
            svg.appendChild(t);
            return svg;
        }

        let offset = 0;
        SEV_LIST.forEach(k => {
            const v = counts[k] || 0;
            if (v === 0) return;
            const frac = v / total;
            const dash = frac * circumference;

            const c = document.createElementNS(svgNS, 'circle');
            c.setAttribute('cx', cx);
            c.setAttribute('cy', cy);
            c.setAttribute('r', radius);
            c.setAttribute('fill', 'none');
            c.setAttribute('stroke', SEV_COLORS[k]);
            c.setAttribute('stroke-width', thickness);
            c.setAttribute('stroke-dasharray', `${dash} ${circumference - dash}`);
            c.setAttribute('stroke-dashoffset', -offset);
            c.setAttribute('transform', `rotate(-90 ${cx} ${cy})`);
            c.setAttribute('stroke-linecap', 'butt');
            c.setAttribute('class', 'chart-donut-seg');
            c.dataset.sev = k;

            const title = document.createElementNS(svgNS, 'title');
            title.textContent = `${k}: ${v} (${(frac * 100).toFixed(1)}%)`;
            c.appendChild(title);

            svg.appendChild(c);
            offset += dash;
        });

        const totalText = document.createElementNS(svgNS, 'text');
        totalText.setAttribute('x', cx);
        totalText.setAttribute('y', cy - 4);
        totalText.setAttribute('text-anchor', 'middle');
        totalText.setAttribute('class', 'chart-donut-total');
        totalText.textContent = String(total);
        svg.appendChild(totalText);

        const label = document.createElementNS(svgNS, 'text');
        label.setAttribute('x', cx);
        label.setAttribute('y', cy + 16);
        label.setAttribute('text-anchor', 'middle');
        label.setAttribute('class', 'chart-donut-sub');
        label.textContent = 'findings';
        svg.appendChild(label);

        return svg;
    }

    function bars(counts, { gap = 12 } = {}) {
        const wrap = h('div', { class: 'chart-bars', style: { gap: `${gap}px` } });
        const max = Math.max(1, ...SEV_LIST.map(k => counts[k] || 0));

        SEV_LIST.forEach(k => {
            const v = counts[k] || 0;
            const pct = (v / max) * 100;
            const bar = h('div', { class: 'chart-bar-col' }, [
                h('div', { class: 'chart-bar-value', text: String(v) }),
                h('div', { class: 'chart-bar-track' }, [
                    h('div', {
                        class: 'chart-bar-fill',
                        style: {
                            height: `${Math.max(pct, v > 0 ? 4 : 0)}%`,
                            background: SEV_COLORS[k],
                            boxShadow: `0 0 12px ${SEV_COLORS[k]}66`,
                        },
                    }),
                ]),
                h('div', { class: 'chart-bar-label', text: k }),
            ]);
            wrap.appendChild(bar);
        });
        return wrap;
    }

    function sparkline(values, { width = 120, height = 32, color = 'var(--red)' } = {}) {
        const svgNS = 'http://www.w3.org/2000/svg';
        const svg = document.createElementNS(svgNS, 'svg');
        svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
        svg.setAttribute('class', 'chart-sparkline');
        svg.setAttribute('width', width);
        svg.setAttribute('height', height);

        if (!values.length) return svg;

        const max = Math.max(1, ...values);
        const stepX = width / Math.max(1, values.length - 1);
        const points = values.map((v, i) => {
            const x = i * stepX;
            const y = height - (v / max) * (height - 4) - 2;
            return `${x},${y}`;
        }).join(' ');

        const poly = document.createElementNS(svgNS, 'polyline');
        poly.setAttribute('points', points);
        poly.setAttribute('fill', 'none');
        poly.setAttribute('stroke', color);
        poly.setAttribute('stroke-width', '1.8');
        poly.setAttribute('stroke-linecap', 'round');
        poly.setAttribute('stroke-linejoin', 'round');
        svg.appendChild(poly);

        return svg;
    }

    return { donut, bars, sparkline, SEV_COLORS };
})();

/* ═══════════════════════════════════════════════════════════════
   PART 5: MAIN APP
   ═══════════════════════════════════════════════════════════════ */

(() => {
    const { h, clear, svgFrom, Storage, SEV_ORDER, SEV_LIST,
            severityKey, countSeverities, shortTarget, fmtTime,
            fmtRelative, fmtDuration, fmtDate, downloadJSON, downloadCSV } = Utils;
    const { ICON, toast, openModal, closeModal, confirm, pageHead, metric,
            emptyState, errorState, skeletonList, codeBlock, buildFinding,
            severitySummary, reportPanel, scansTable } = UI;

    const state = {
        capabilities: null,
        scans: [],
        scansLoadedAt: 0,
        scanCache: new Map(),
        findingsCache: new Map(),
    };

    let renderToken = 0;  // ✅ منع تعارض async renders

    const SCAN_PRESETS = {
        light:    { max_urls: 50,   max_depth: 2, concurrency: 5,  rate_limit: 10 },
        balanced: { max_urls: 200,  max_depth: 3, concurrency: 10, rate_limit: 20 },
        deep:     { max_urls: 1000, max_depth: 5, concurrency: 20, rate_limit: 30 },
    };

    async function boot() {
        setupSidebar();
        setupTheme();
        setupModalBackdrop();
        setupKeyboardShortcuts();

        // ✅ تحميل capabilities + health بالتوازي
        const [caps] = await Promise.all([
            API.capabilities().catch(() => null),
            refreshStatus(),
        ]);
        state.capabilities = caps;
        setInterval(refreshStatus, 30000);

        window.addEventListener('hashchange', renderRoute);

        // ✅ منع الـ double render
        if (!location.hash) {
            history.replaceState(null, '', '#/');
        }
        await renderRoute();
    }

    function setupSidebar() {
        const btn = document.getElementById('menu-btn');
        const overlay = document.getElementById('sidebar-overlay');
        const collapseBtn = document.getElementById('sidebar-collapse');

        const close = () => document.body.classList.remove('sidebar-open');
        if (btn) btn.addEventListener('click', () => document.body.classList.toggle('sidebar-open'));
        if (overlay) overlay.addEventListener('click', close);
        document.querySelectorAll('.nav-item').forEach(a => a.addEventListener('click', close));

        // استرجاع حالة الطي
        const collapsed = Storage.get('sidebar.collapsed', false);
        if (collapsed && window.innerWidth >= 900) {
            document.body.classList.add('sidebar-collapsed');
            if (collapseBtn) collapseBtn.setAttribute('aria-expanded', 'false');
        }

        // ✅ زر الـ collapse يعمل في الحالتين
        if (collapseBtn) {
            collapseBtn.addEventListener('click', () => {
                const now = document.body.classList.toggle('sidebar-collapsed');
                Storage.set('sidebar.collapsed', now);
                collapseBtn.setAttribute('aria-expanded', String(!now));
            });
        }

        // ✅ Tooltips للـ nav items
        document.querySelectorAll('.nav-item').forEach(item => {
            const label = item.querySelector('.nav-label')?.textContent?.trim();
            if (label) item.setAttribute('data-tooltip', label);
        });

        // ✅ تنظيف الحالة عند تغيير الحجم
        const handleResize = Utils.debounce(() => {
            if (window.innerWidth < 900) {
                document.body.classList.remove('sidebar-open');
            }
        }, 150);
        window.addEventListener('resize', handleResize);

        window.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') close();
        });
    }

    function setupTheme() {
        const btn = document.getElementById('theme-toggle');
        const saved = Storage.get('theme', null);
        const prefersLight = window.matchMedia('(prefers-color-scheme: light)').matches;
        const theme = saved || (prefersLight ? 'light' : 'dark');
        applyTheme(theme);

        if (btn) {
            btn.addEventListener('click', () => {
                const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
                applyTheme(next);
                Storage.set('theme', next);
            });
        }
    }

    function applyTheme(theme) {
        document.documentElement.dataset.theme = theme;
        const meta = document.querySelector('meta[name="theme-color"]');
        if (meta) meta.content = theme === 'light' ? '#eef2f8' : '#06070b';
        document.documentElement.style.colorScheme = theme;
    }

    function setupModalBackdrop() {
        const backdrop = document.getElementById('modal-backdrop');
        if (backdrop) backdrop.addEventListener('click', closeModal);
    }

    function setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                const search = document.querySelector('.search-box input');
                if (search) { e.preventDefault(); search.focus(); }
            }
            if ((e.ctrlKey || e.metaKey) && e.key === 'n') {
                e.preventDefault();
                if (location.hash !== '#/' && location.hash !== '') {
                    location.hash = '#/';
                }
                setTimeout(() => {
                    const input = document.getElementById('target-input');
                    if (input) input.focus();
                }, 100);
            }
            if (e.key === 'g') {
                const handler = (e2) => {
                    const map = { d: '#/', s: '#/scans', f: '#/findings', r: '#/reports' };
                    const target = map[e2.key];
                    if (target) { e2.preventDefault(); location.hash = target; }
                    document.removeEventListener('keydown', handler);
                };
                document.addEventListener('keydown', handler, { once: true });
                setTimeout(() => document.removeEventListener('keydown', handler), 1200);
            }
        });
    }

    async function refreshStatus() {
        const dot = document.getElementById('status-dot');
        const dotMobile = document.getElementById('status-dot-mobile');
        const txt = document.getElementById('status-text');
        try {
            const data = await API.health();
            if (dot) dot.className = 'status-dot online';
            if (dotMobile) dotMobile.className = 'status-dot mobile-dot online';
            if (txt) txt.textContent = data.version ? `v${data.version}` : 'online';
        } catch {
            if (dot) dot.className = 'status-dot offline';
            if (dotMobile) dotMobile.className = 'status-dot mobile-dot offline';
            if (txt) txt.textContent = 'offline';
        }
    }

    function parseRoute() {
        const raw = (location.hash || '#/').replace(/^#\/?/, '');
        const parts = raw.split('/').filter(Boolean);
        return { page: parts[0] || 'dashboard', id: parts[1] || null };
    }

    async function renderRoute() {
        const myToken = ++renderToken;   // ✅
        const { page, id } = parseRoute();
        const app = document.getElementById('app');
        if (!app) return;

        clear(app);
        document.querySelectorAll('.nav-item').forEach(a => {
            a.classList.toggle('active', a.dataset.nav === page);
        });

        app.style.animation = 'none';
        void app.offsetHeight;
        app.style.animation = '';

        try {
            if (page === 'dashboard')      await renderDashboard(app);
            else if (page === 'scans')     await renderScans(app);
            else if (page === 'scan')      await renderScanDetail(app, id);
            else if (page === 'findings')  await renderFindings(app);
            else if (page === 'reports')   await renderReports(app);
            else if (page === 'settings')  await renderSettings(app);
            else                            await renderDashboard(app);
        } catch (e) {
            console.error(e);
            if (myToken === renderToken) app.appendChild(errorState(e));
            return;
        }

        // ✅ تجاهل النتائج لو الـ route اتغير
        if (myToken !== renderToken) return;

        app.focus({ preventScroll: true });
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    async function loadScans(limit = 50, { force = false } = {}) {
        const now = Date.now();
        if (!force && state.scans.length && (now - state.scansLoadedAt) < 5000) {
            return state.scans;
        }
        const data = await API.listScans(limit);
        state.scans = Array.isArray(data.scans) ? data.scans : [];
        state.scansLoadedAt = now;
        updateNavBadges();
        return state.scans;
    }

    function updateNavBadges() {
        const active = state.scans.filter(s => ['running', 'created'].includes(s.status)).length;
        const badge = document.getElementById('nav-badge-scans');
        if (badge) {
            badge.textContent = String(active);
            badge.hidden = active === 0;
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  Dashboard
    // ═══════════════════════════════════════════════════════════
    async function renderDashboard(root) {
        const refreshBtn = h('button', {
            class: 'btn btn-ghost',
            html: `${ICON.refresh}<span>Refresh</span>`,
            on: { click: () => renderRoute() },
        });

        root.appendChild(pageHead({
            eyebrow: 'Operations',
            title: 'Dashboard',
            sub: 'Security assessment overview — track activity and launch new operations.',
            actions: [refreshBtn],
        }));

        const metricsHost = h('div', { class: 'metrics' });
        for (let i = 0; i < 4; i++) metricsHost.appendChild(h('div', { class: 'skeleton skeleton-metric' }));
        root.appendChild(metricsHost);

        root.appendChild(buildNewAssessmentPanel());

        const recentHost = h('div', { id: 'recent-scans-host' });
        root.appendChild(recentHost);

        let scans = [];
        try {
            scans = await loadScans(50, { force: true });
        } catch { /* keep empty */ }

        const totalScans    = scans.length;
        const totalFindings = scans.reduce((a, s) => a + (s.finding_count || 0), 0);
        const activeScans   = scans.filter(s => ['running', 'created'].includes(s.status)).length;
        const failedScans   = scans.filter(s => s.status === 'failed').length;

        clear(metricsHost);
        metricsHost.appendChild(metric('Total Scans', totalScans, {
            tone: totalScans > 0 ? 'accent' : 'muted',
            icon: ICON.target,
            hint: scans.length ? `Latest: ${fmtRelative(scans[0].started_at)}` : 'No scans yet',
        }));
        metricsHost.appendChild(metric('Active', activeScans, {
            tone: activeScans > 0 ? 'warn' : 'muted',
            icon: ICON.activity,
            small: true,
            hint: activeScans > 0 ? 'In progress' : 'Idle',
        }));
        metricsHost.appendChild(metric('Findings', totalFindings, {
            tone: totalFindings > 0 ? 'warn' : 'ok',
            icon: ICON.shield,
            hint: totalFindings > 0 ? 'Requires review' : 'All clean',
        }));
        metricsHost.appendChild(metric('Failed', failedScans, {
            tone: failedScans > 0 ? 'accent' : 'muted',
            icon: ICON.warn,
            small: true,
            hint: failedScans > 0 ? 'Check logs' : 'No failures',
        }));

        if (scans.length === 0) {
            recentHost.appendChild(h('div', { class: 'panel' }, [
                emptyState({
                    title: 'No assessments yet',
                    text: 'Launch your first authorized security assessment to begin mapping the target attack surface.',
                }),
            ]));
        } else {
            recentHost.appendChild(scansPanel(scans.slice(0, 6), {
                title: 'Recent Scans',
                subtitle: `Last ${Math.min(scans.length, 6)} operations`,
                viewAll: scans.length > 6,
            }));
        }
    }

    function buildNewAssessmentPanel() {
        const panel = h('div', { class: 'panel' });
        panel.appendChild(h('div', { class: 'panel-head' }, [
            h('div', { class: 'panel-title', text: 'New Assessment' }),
            h('div', { class: 'panel-sub', text: 'Launch an authorized security scan.' }),
        ]));

        const input = h('input', {
            type: 'url',
            class: 'input',
            id: 'target-input',
            placeholder: 'https://example.com',
            autocomplete: 'off',
            spellcheck: 'false',
        });

        const profile = h('select', { class: 'select', id: 'profile-select' }, [
            h('option', { value: 'balanced', text: 'Balanced — recommended' }),
            h('option', { value: 'light', text: 'Light — quick surface scan' }),
            h('option', { value: 'deep', text: 'Deep — thorough assessment' }),
        ]);

        const scopeFree = h('input', { type: 'checkbox', id: 'scope-free' });
        const scopeLabel = h('label', { class: 'check', for: 'scope-free' }, [
            scopeFree,
            h('div', {}, [
                h('div', { class: 'check-title', text: 'Open scope (Burp/ZAP mode)' }),
                h('div', { class: 'check-text', text: 'Skip hostname scope validation. SSRF and loopback protection still apply.' }),
            ]),
        ]);

        const grid = h('div', { class: 'form-grid' }, [
            h('div', { class: 'field' }, [
                h('label', { class: 'field-label', for: 'target-input', text: 'Target URL' }),
                input,
            ]),
            h('div', { class: 'field' }, [
                h('label', { class: 'field-label', for: 'profile-select', text: 'Scan Profile' }),
                profile,
            ]),
        ]);

        panel.appendChild(grid);

        const chips = h('div', { class: 'chips' });
        const quickTargets = [
            'http://demo.testfire.net/',
            'http://zero.webappsecurity.com/',
            'http://testphp.vulnweb.com/',
        ];
        quickTargets.forEach(t => {
            chips.appendChild(h('button', {
                type: 'button',
                class: 'chip',
                text: t.replace(/^https?:\/\//, '').replace(/\/$/, ''),
                on: { click: () => { input.value = t; input.focus(); } },
            }));
        });
        panel.appendChild(chips);

        panel.appendChild(h('div', { class: 'field' }, [scopeLabel]));

        const btn = h('button', {
            type: 'button',
            class: 'btn btn-primary',
            html: `${ICON.plus}<span>Launch Assessment</span>`,
        });

        const submit = async () => {
            const target = input.value.trim();
            if (!target) { toast('Enter a target URL', 'error'); input.focus(); return; }
            try { new URL(target.startsWith('http') ? target : `http://${target}`); }
            catch { toast('Invalid URL', 'error'); return; }

            const originalHTML = btn.innerHTML;
            btn.disabled = true;
            clear(btn);
            btn.appendChild(h('span', { class: 'spin' }));
            btn.appendChild(document.createTextNode('Starting…'));

            const preset = SCAN_PRESETS[profile.value] || SCAN_PRESETS.balanced;
            const payload = {
                target,
                scope_free: scopeFree.checked,
                ...preset,
            };

            try {
                await runScanFlow(payload);
            } catch {
                btn.disabled = false;
                btn.innerHTML = originalHTML;
            }
        };

        btn.addEventListener('click', submit);
        input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });

        panel.appendChild(h('div', { class: 'form-actions' }, [btn]));
        return panel;
    }

    function scansPanel(scans, { title, subtitle, viewAll = false } = {}) {
        const panel = h('div', { class: 'panel no-pad' });
        const head = h('div', { class: 'panel-head panel-head-padded' }, [
            h('div', { class: 'panel-title', text: title }),
        ]);
        if (subtitle) head.appendChild(h('div', { class: 'panel-sub', text: subtitle }));
        panel.appendChild(head);
        panel.appendChild(scansTable(scans));

        if (viewAll) {
            panel.appendChild(h('div', { class: 'panel-foot' }, [
                h('button', {
                    class: 'btn btn-ghost',
                    text: 'View all scans',
                    on: { click: () => location.hash = '#/scans' },
                }),
            ]));
        }
        return panel;
    }

    function showScanOverlay(target) {
        const ov = document.getElementById('scan-overlay');
        const bar = document.getElementById('scan-ov-bar');
        const phase = document.getElementById('scan-ov-phase');
        const targetEl = document.getElementById('scan-ov-target');
        const statsEl = document.getElementById('scan-ov-stats');

        if (!ov) return { complete: () => {}, close: () => {} };

        targetEl.textContent = shortTarget(target);
        bar.style.width = '0%';
        phase.textContent = 'Initializing engine…';
        if (statsEl) statsEl.textContent = '';
        ov.hidden = false;

        const phases = [
            { at: 8,   label: 'Resolving target…' },
            { at: 18,  label: 'Crawling target surface…' },
            { at: 34,  label: 'Discovering endpoints…' },
            { at: 50,  label: 'Enumerating parameters…' },
            { at: 66,  label: 'Running security modules…' },
            { at: 80,  label: 'Collecting evidence…' },
            { at: 90,  label: 'Finalizing assessment…' },
        ];
        let i = 0;
        let pct = 0;
        let interval = null;
        let closed = false;
        const startTime = Date.now();

        const tick = () => {
            if (closed) return;
            pct += (90 - pct) * 0.06 + 0.4;
            if (pct > 90) pct = 90;
            bar.style.width = pct.toFixed(1) + '%';
            while (i < phases.length && pct >= phases[i].at) {
                phase.textContent = phases[i].label;
                i++;
            }
            if (statsEl) {
                const elapsed = ((Date.now() - startTime) / 1000).toFixed(0);
                statsEl.textContent = `Elapsed: ${elapsed}s`;
            }
        };
        tick();
        interval = setInterval(tick, 550);

        const cleanup = () => {
            closed = true;
            if (interval) { clearInterval(interval); interval = null; }
        };

        return {
            complete() {
                cleanup();
                bar.style.width = '100%';
                phase.textContent = 'Assessment complete.';
            },
            close() {
                cleanup();
                ov.hidden = true;
            },
        };
    }

    async function runScanFlow(payload) {
        const ov = showScanOverlay(payload.target);
        try {
            const result = await API.runScan(payload);
            ov.complete();
            toast(`Scan complete — ${result.total_issues} findings`, 'ok');
            state.scansLoadedAt = 0;

            try {
                const fresh = await API.listScans(1);
                const latest = fresh.scans?.[0];
                setTimeout(() => {
                    ov.close();
                    location.hash = latest ? `#/scan/${latest.id}` : '#/scans';
                }, 600);
            } catch {
                setTimeout(() => { ov.close(); location.hash = '#/scans'; }, 600);
            }
        } catch (e) {
            ov.close();
            toast(e.message || 'Scan failed.', 'error');
            throw e;
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  Scans list
    // ═══════════════════════════════════════════════════════════
    async function renderScans(root) {
        const newBtn = h('button', {
            type: 'button',
            class: 'btn btn-primary',
            html: `${ICON.plus}<span>New Scan</span>`,
            on: { click: () => location.hash = '#/' },
        });

        root.appendChild(pageHead({
            eyebrow: 'Operations',
            title: 'Scans',
            sub: 'Full assessment history. Click a row to inspect findings and reports.',
            actions: [newBtn],
        }));

        const host = h('div');
        host.appendChild(h('div', { class: 'panel' }, [skeletonList(6)]));
        root.appendChild(host);

        let scans = [];
        try {
            scans = await loadScans(100, { force: true });
        } catch (e) {
            clear(host);
            host.appendChild(errorState(e));
            return;
        }

        clear(host);

        if (scans.length === 0) {
            host.appendChild(h('div', { class: 'panel' }, [
                emptyState({
                    title: 'No scans yet',
                    text: 'Once you launch an assessment, results will appear here.',
                    action: h('button', {
                        class: 'btn btn-primary',
                        text: 'Launch first assessment',
                        on: { click: () => location.hash = '#/' },
                    }),
                }),
            ]));
            return;
        }

        const search = h('input', {
            type: 'text',
            placeholder: 'Search by target or ID… (Ctrl+K)',
            autocomplete: 'off',
        });
        const searchBox = h('div', { class: 'search-box' }, [svgFrom(ICON.search), search]);

        const statusFilters = ['all', 'completed', 'running', 'created', 'failed'];
        let activeStatus = 'all';
        let query = '';

        const pills = h('div', { class: 'filter-pills' });
        statusFilters.forEach(s => {
            const count = s === 'all' ? scans.length : scans.filter(x => x.status === s).length;
            const btn = h('button', {
                type: 'button',
                class: `pill${s === 'all' ? ' active' : ''}`,
                dataset: { status: s },
            });
            btn.appendChild(document.createTextNode(s === 'all' ? 'All' : s));
            btn.appendChild(h('span', { class: 'count', text: String(count) }));
            pills.appendChild(btn);
        });

        const filters = h('div', { class: 'filters' }, [searchBox, pills]);
        host.appendChild(filters);

        const tableHost = h('div', { class: 'panel no-pad' });
        host.appendChild(tableHost);

        const applyFilters = () => {
            clear(tableHost);
            const filtered = scans.filter(s => {
                if (activeStatus !== 'all' && s.status !== activeStatus) return false;
                if (query) {
                    const hay = `${s.id} ${s.target} ${s.scan_uid || ''}`.toLowerCase();
                    if (!hay.includes(query.toLowerCase())) return false;
                }
                return true;
            });

            if (filtered.length === 0) {
                tableHost.appendChild(emptyState({
                    title: 'No matching scans',
                    text: 'Try adjusting your filters or search query.',
                }));
                return;
            }

            tableHost.appendChild(scansTable(filtered));
        };

        search.addEventListener('input', Utils.debounce((e) => {
            query = e.target.value;
            applyFilters();
        }, 150));

        pills.querySelectorAll('.pill').forEach(p => {
            p.addEventListener('click', () => {
                pills.querySelectorAll('.pill').forEach(x => x.classList.remove('active'));
                p.classList.add('active');
                activeStatus = p.dataset.status;
                applyFilters();
            });
        });

        applyFilters();
    }

    // ═══════════════════════════════════════════════════════════
    //  Scan detail
    // ═══════════════════════════════════════════════════════════
    async function renderScanDetail(root, id) {
        if (!id) { location.hash = '#/scans'; return; }
        const scanIdNum = Number(id);
        if (!Number.isFinite(scanIdNum)) {
            root.appendChild(errorState(new Error('Invalid scan ID.')));
            return;
        }

        const backBtn = h('button', {
            type: 'button',
            class: 'btn btn-ghost',
            html: `${ICON.back}<span>Back</span>`,
            on: { click: () => location.hash = '#/scans' },
        });

        root.appendChild(h('div', { class: 'page-eyebrow', text: 'Assessment' }));
        const head = pageHead({
            title: `Scan #${id}`,
            sub: 'Loading details…',
            actions: [backBtn],
        });
        root.appendChild(head);

        const body = h('div');
        body.appendChild(h('div', { class: 'panel' }, [skeletonList(5)]));
        root.appendChild(body);

        let scan, findingsData;
        try {
            [scan, findingsData] = await Promise.all([
                API.getScan(scanIdNum),
                API.getFindings(scanIdNum),
            ]);
        } catch (e) {
            clear(body);
            body.appendChild(errorState(e));
            return;
        }

        state.scanCache.set(scanIdNum, scan);

        const findings = Array.isArray(findingsData.findings) ? findingsData.findings : [];
        const counts = countSeverities(findings);
        const sorted = findings.slice().sort((a, b) =>
            (SEV_ORDER[severityKey(a.severity)] ?? 99) - (SEV_ORDER[severityKey(b.severity)] ?? 99)
        );

        const sub = head.querySelector('.page-sub');
        if (sub) sub.textContent = scan.target;

        clear(body);

        let activeTab = 'overview';
        const tabDefs = [
            { key: 'overview', label: 'Overview' },
            { key: 'findings', label: 'Findings', count: findings.length },
            { key: 'reports',  label: 'Reports' },
        ];

        const tabs = h('div', { class: 'tabs', role: 'tablist' });
        tabDefs.forEach(t => {
            const btn = h('button', {
                type: 'button',
                class: `tab${t.key === activeTab ? ' active' : ''}`,
                role: 'tab',
                dataset: { tab: t.key },
            });
            btn.appendChild(document.createTextNode(t.label));
            if (t.count != null) {
                btn.appendChild(h('span', { class: 'count', text: String(t.count) }));
            }
            btn.addEventListener('click', () => {
                activeTab = t.key;
                tabs.querySelectorAll('.tab').forEach(x =>
                    x.classList.toggle('active', x.dataset.tab === activeTab));
                renderTab();
            });
            tabs.appendChild(btn);
        });
        body.appendChild(tabs);

        const tabHost = h('div');
        body.appendChild(tabHost);

        const renderTab = () => {
            clear(tabHost);
            if (activeTab === 'overview') tabHost.appendChild(buildOverviewTab(scan, findings, counts));
            else if (activeTab === 'findings') tabHost.appendChild(buildFindingsTab(sorted, counts));
            else if (activeTab === 'reports')  tabHost.appendChild(reportPanel(scan.id, state.capabilities));
        };

        renderTab();
    }

    function buildOverviewTab(scan, findings, counts) {
        const wrap = h('div');

        const chartRow = h('div', { class: 'overview-row' });

        const chartPanel = h('div', { class: 'panel chart-panel' });
        chartPanel.appendChild(h('div', { class: 'panel-head' }, [
            h('div', { class: 'panel-title', text: 'Severity Distribution' }),
        ]));
        chartPanel.appendChild(Charts.donut(counts));
        chartRow.appendChild(chartPanel);

        const summaryPanel = h('div', { class: 'panel' });
        summaryPanel.appendChild(h('div', { class: 'panel-head' }, [
            h('div', { class: 'panel-title', text: 'Breakdown' }),
        ]));
        summaryPanel.appendChild(Charts.bars(counts));
        chartRow.appendChild(summaryPanel);

        wrap.appendChild(chartRow);

        const metaPanel = h('div', { class: 'panel' });
        metaPanel.appendChild(h('div', { class: 'panel-head' }, [
            h('div', { class: 'panel-title', text: 'Details' }),
        ]));

        const meta = h('div', { class: 'meta-grid' });
        const cells = [
            ['Scan ID',        scan.scan_uid || `#${scan.id}`, true],
            ['Target',         scan.target, false],
            ['Status',         scan.status, false],
            ['Started',        fmtTime(scan.started_at), true],
            ['Finished',       fmtTime(scan.finished_at), true],
            ['Duration',       fmtDuration(scan.started_at, scan.finished_at), true],
            ['URLs Discovered', String(scan.discovered_urls_count ?? '—'), true],
            ['Total Findings',  String(scan.finding_count ?? findings.length), true],
        ];
        cells.forEach(([k, v, mono]) => {
            meta.appendChild(h('div', { class: 'meta-cell' }, [
                h('div', { class: 'k', text: k }),
                h('div', { class: `v${mono ? ' mono' : ''}`, text: v }),
            ]));
        });
        metaPanel.appendChild(meta);
        wrap.appendChild(metaPanel);

        if (findings.length > 0) {
            const preview = findings
                .slice()
                .sort((a, b) =>
                    (SEV_ORDER[severityKey(a.severity)] ?? 99) - (SEV_ORDER[severityKey(b.severity)] ?? 99))
                .slice(0, 3);

            const prev = h('div', { class: 'panel' });
            prev.appendChild(h('div', { class: 'panel-head' }, [
                h('div', { class: 'panel-title', text: 'Top Findings' }),
                h('div', { class: 'panel-sub', text: `Showing ${preview.length} of ${findings.length}` }),
            ]));
            preview.forEach(f => prev.appendChild(buildFinding(f)));
            wrap.appendChild(prev);
        }

        return wrap;
    }

    function buildFindingsTab(findings, counts) {
        const wrap = h('div');
        wrap.appendChild(severitySummary(counts));

        if (findings.length === 0) {
            wrap.appendChild(h('div', { class: 'panel' }, [
                emptyState({
                    icon: ICON.check,
                    title: 'No findings detected',
                    text: 'The assessment did not identify issues with the tested payloads.',
                }),
            ]));
            return wrap;
        }

        let activeSev = 'all';
        let query = '';

        const search = h('input', {
            type: 'text',
            placeholder: 'Search findings…',
            autocomplete: 'off',
        });
        const searchBox = h('div', { class: 'search-box' }, [svgFrom(ICON.search), search]);

        const pills = h('div', { class: 'filter-pills' });
        pills.appendChild(h('button', {
            type: 'button', class: 'pill active', dataset: { sev: 'all' }, text: 'All',
        }));
        SEV_LIST.forEach(s => {
            const c = counts[s] || 0;
            if (c === 0) return;
            const btn = h('button', {
                type: 'button', class: 'pill', dataset: { sev: s.toLowerCase() },
            });
            btn.appendChild(document.createTextNode(s));
            btn.appendChild(h('span', { class: 'count', text: String(c) }));
            pills.appendChild(btn);
        });

        const exportJson = h('button', {
            class: 'btn btn-ghost btn-sm',
            html: `${ICON.download}<span>JSON</span>`,
            on: { click: () => downloadJSON(findings, `findings-${Date.now()}.json`) },
        });
        const exportCsv = h('button', {
            class: 'btn btn-ghost btn-sm',
            html: `${ICON.download}<span>CSV</span>`,
            on: {
                click: () => downloadCSV(
                    findings.map(f => [f.severity, f.title, f.url, f.param, f.scanner]),
                    ['Severity', 'Title', 'URL', 'Parameter', 'Scanner'],
                    `findings-${Date.now()}.csv`
                ),
            },
        });

        const list = h('div');

        const apply = () => {
            clear(list);
            const filtered = findings.filter(f => {
                if (activeSev !== 'all' && severityKey(f.severity).toLowerCase() !== activeSev) return false;
                if (query) {
                    const hay = `${f.title} ${f.url} ${f.scanner} ${f.category}`.toLowerCase();
                    if (!hay.includes(query.toLowerCase())) return false;
                }
                return true;
            });
            filtered.forEach(f => list.appendChild(buildFinding(f)));
            if (filtered.length === 0) {
                list.appendChild(h('div', { class: 'panel' }, [
                    emptyState({ title: 'No findings match this filter.' }),
                ]));
            }
        };

        search.addEventListener('input', Utils.debounce((e) => {
            query = e.target.value;
            apply();
        }, 150));

        pills.querySelectorAll('.pill').forEach(p => {
            p.addEventListener('click', () => {
                pills.querySelectorAll('.pill').forEach(x => x.classList.remove('active'));
                p.classList.add('active');
                activeSev = p.dataset.sev;
                apply();
            });
        });

        const toolbar = h('div', { class: 'findings-toolbar' }, [
            h('div', { class: 'filters' }, [searchBox, pills]),
            h('div', { class: 'export-actions' }, [exportJson, exportCsv]),
        ]);
        wrap.appendChild(toolbar);
        wrap.appendChild(list);
        apply();
        return wrap;
    }

    // ═══════════════════════════════════════════════════════════
    //  Findings (aggregate)
    // ═══════════════════════════════════════════════════════════
    async function renderFindings(root) {
        root.appendChild(pageHead({
            eyebrow: 'Intelligence',
            title: 'Findings',
            sub: 'Aggregated security findings across your recent assessments.',
        }));

        const host = h('div');
        host.appendChild(h('div', { class: 'panel' }, [skeletonList(8)]));
        root.appendChild(host);

        let scans = [];
        try {
            scans = await loadScans(25, { force: true });
        } catch (e) {
            clear(host);
            host.appendChild(errorState(e));
            return;
        }

        if (scans.length === 0) {
            clear(host);
            host.appendChild(h('div', { class: 'panel' }, [
                emptyState({
                    title: 'No scans to aggregate',
                    text: 'Run an assessment first — findings from completed scans will appear here.',
                    action: h('button', {
                        class: 'btn btn-primary',
                        text: 'Launch assessment',
                        on: { click: () => location.hash = '#/' },
                    }),
                }),
            ]));
            return;
        }

        // ✅ استخدام allSettled لمنع فشل واحد يعطل الكل
        const MAX_SCANS_TO_FETCH = 15;
        const scansToFetch = scans.slice(0, MAX_SCANS_TO_FETCH);
        const results = await Promise.allSettled(scansToFetch.map(async (s) => {
            const data = await API.getFindings(s.id);
            return (data.findings || []).map(f => ({ ...f, _scanId: s.id, _scanTarget: s.target }));
        }));

        const all = results
            .filter(r => r.status === 'fulfilled')
            .flatMap(r => r.value)
            .sort((a, b) =>
                (SEV_ORDER[severityKey(a.severity)] ?? 99) - (SEV_ORDER[severityKey(b.severity)] ?? 99)
            );

        clear(host);

        if (all.length === 0) {
            host.appendChild(h('div', { class: 'panel' }, [
                emptyState({
                    icon: ICON.check,
                    title: 'No findings across recent scans',
                    text: 'Your recent assessments did not identify issues with the tested payloads.',
                }),
            ]));
            return;
        }

        const counts = countSeverities(all);
        host.appendChild(severitySummary(counts));

        let activeSev = 'all';
        let query = '';

        const search = h('input', {
            type: 'text',
            placeholder: 'Search findings by title, URL, or scanner…',
            autocomplete: 'off',
        });
        const searchBox = h('div', { class: 'search-box' }, [svgFrom(ICON.search), search]);

        const pills = h('div', { class: 'filter-pills' });
        pills.appendChild(h('button', {
            type: 'button', class: 'pill active', dataset: { sev: 'all' }, text: 'All',
        }));
        SEV_LIST.forEach(s => {
            const c = counts[s] || 0;
            if (c === 0) return;
            const btn = h('button', {
                type: 'button', class: 'pill', dataset: { sev: s.toLowerCase() },
            });
            btn.appendChild(document.createTextNode(s));
            btn.appendChild(h('span', { class: 'count', text: String(c) }));
            pills.appendChild(btn);
        });

        const list = h('div');
        host.appendChild(h('div', { class: 'filters' }, [searchBox, pills]));
        host.appendChild(list);

        const apply = () => {
            clear(list);
            const filtered = all.filter(f => {
                if (activeSev !== 'all' && severityKey(f.severity).toLowerCase() !== activeSev) return false;
                if (query) {
                    const hay = `${f.title} ${f.url} ${f.scanner} ${f.category}`.toLowerCase();
                    if (!hay.includes(query.toLowerCase())) return false;
                }
                return true;
            });

            if (filtered.length === 0) {
                list.appendChild(h('div', { class: 'panel' }, [
                    emptyState({ title: 'No findings match your filters.' }),
                ]));
                return;
            }

            filtered.forEach(f => list.appendChild(buildFinding(f, { showScanLink: true })));
        };

        search.addEventListener('input', Utils.debounce((e) => {
            query = e.target.value;
            apply();
        }, 150));

        pills.querySelectorAll('.pill').forEach(p => {
            p.addEventListener('click', () => {
                pills.querySelectorAll('.pill').forEach(x => x.classList.remove('active'));
                p.classList.add('active');
                activeSev = p.dataset.sev;
                apply();
            });
        });

        apply();
    }

    // ═══════════════════════════════════════════════════════════
    //  Reports
    // ═══════════════════════════════════════════════════════════
    async function renderReports(root) {
        root.appendChild(pageHead({
            eyebrow: 'Deliverables',
            title: 'Reports',
            sub: 'Download assessment reports in HTML, JSON, Markdown, PDF, or a complete bundle.',
        }));

        const host = h('div');
        host.appendChild(h('div', { class: 'panel' }, [skeletonList(4)]));
        root.appendChild(host);

        let scans = [];
        try {
            scans = await loadScans(60, { force: true });
        } catch (e) {
            clear(host);
            host.appendChild(errorState(e));
            return;
        }

        clear(host);

        if (scans.length === 0) {
            host.appendChild(h('div', { class: 'panel' }, [
                emptyState({
                    title: 'No reports available',
                    text: 'Completed assessments generate reports here. Launch a scan to get started.',
                    action: h('button', {
                        class: 'btn btn-primary',
                        text: 'Launch assessment',
                        on: { click: () => location.hash = '#/' },
                    }),
                }),
            ]));
            return;
        }

        const grid = h('div', { class: 'report-grid' });
        scans.forEach(s => grid.appendChild(buildReportCard(s)));
        host.appendChild(grid);
    }

    function buildReportCard(scan) {
        const card = h('div', { class: 'report-card' });

        const head = h('div', { class: 'report-card-head' });
        const left = h('div');
        left.appendChild(h('div', { class: 'report-card-id', text: `SF-RPT-${String(scan.id).padStart(6, '0')}` }));
        left.appendChild(h('div', { class: 'report-card-target', text: shortTarget(scan.target) }));
        head.appendChild(left);
        head.appendChild(h('span', { class: `badge status-${scan.status}`, text: scan.status }));
        card.appendChild(head);

        const meta = h('div', { class: 'report-card-meta' }, [
            h('div', {}, [
                h('div', { class: 'k', text: 'Generated' }),
                h('div', { class: 'v', text: fmtDate(scan.finished_at || scan.started_at) }),
            ]),
            h('div', {}, [
                h('div', { class: 'k', text: 'Findings' }),
                h('div', { class: 'v', text: String(scan.finding_count ?? 0) }),
            ]),
        ]);
        card.appendChild(meta);

        const actions = h('div', { class: 'report-actions' }, [
            h('a', {
                href: API.reportUrl(scan.id, 'html', false),
                target: '_blank', rel: 'noopener',
                class: 'report-action',
                html: `${ICON.eye}<span>View</span>`,
            }),
            h('a', {
                href: API.bundleUrl(scan.id),
                class: 'report-action',
                html: `${ICON.download}<span>Bundle</span>`,
            }),
            h('a', {
                href: `#/scan/${scan.id}`,
                class: 'report-action',
                html: `<span>Open scan</span>`,
            }),
        ]);
        card.appendChild(actions);

        return card;
    }

    // ═══════════════════════════════════════════════════════════
    //  Settings
    // ═══════════════════════════════════════════════════════════
    async function renderSettings(root) {
        root.appendChild(pageHead({
            eyebrow: 'System',
            title: 'Settings',
            sub: 'Backend status, runtime capabilities, and platform information.',
        }));

        const host = h('div');
        root.appendChild(host);

        let health = null;
        let healthErr = null;
        try { health = await API.health(); }
        catch (e) { healthErr = e; }

        const statusPanel = h('div', { class: 'panel' });
        statusPanel.appendChild(h('div', { class: 'panel-head' }, [
            h('div', { class: 'panel-title', text: 'Engine Status' }),
            health
                ? h('span', { class: 'badge status-completed', text: 'online' })
                : h('span', { class: 'badge status-failed', text: 'offline' }),
        ]));

        if (health) {
            const meta = h('div', { class: 'meta-grid' });
            [
                ['Service',  health.service || 'spiderforge', true],
                ['Version',  health.version || '—', true],
                ['Frontend', health.frontend ? 'installed' : 'not installed', false],
                ['API',      'reachable', false],
            ].forEach(([k, v, mono]) => {
                meta.appendChild(h('div', { class: 'meta-cell' }, [
                    h('div', { class: 'k', text: k }),
                    h('div', { class: `v${mono ? ' mono' : ''}`, text: v }),
                ]));
            });
            statusPanel.appendChild(meta);
        } else {
            statusPanel.appendChild(errorState(healthErr || new Error('Backend unreachable.')));
        }
        host.appendChild(statusPanel);

        const capPanel = h('div', { class: 'panel' });
        capPanel.appendChild(h('div', { class: 'panel-head' }, [
            h('div', { class: 'panel-title', text: 'Report Capabilities' }),
            h('div', { class: 'panel-sub', text: 'Formats available on this server.' }),
        ]));

        const reports = state.capabilities?.reports || {};
        const capMeta = h('div', { class: 'meta-grid' });
        const capRows = [
            ['JSON',     reports.json?.available,     null],
            ['HTML',     reports.html?.available,     null],
            ['Markdown', reports.markdown?.available, null],
            ['PDF',      reports.pdf?.available,      reports.pdf?.reason],
            ['Bundle',   reports.bundle?.available,   null],
        ];
        capRows.forEach(([label, available, reason]) => {
            const cell = h('div', { class: 'meta-cell' });
            cell.appendChild(h('div', { class: 'k', text: label }));
            const v = h('div', { class: 'v' });
            v.appendChild(h('span', {
                class: `badge ${available ? 'status-completed' : 'status-failed'}`,
                text: available ? 'available' : 'unavailable',
            }));
            cell.appendChild(v);
            if (!available && reason) {
                cell.appendChild(h('div', { class: 'muted', style: { marginTop: '6px', fontSize: '11.5px' }, text: reason }));
            }
            capMeta.appendChild(cell);
        });
        capPanel.appendChild(capMeta);
        host.appendChild(capPanel);

        const themePanel = h('div', { class: 'panel' });
        themePanel.appendChild(h('div', { class: 'panel-head' }, [
            h('div', { class: 'panel-title', text: 'Appearance' }),
        ]));
        const themeRow = h('div', { class: 'theme-row' });
        ['dark', 'light'].forEach(t => {
            const btn = h('button', {
                class: `theme-option${document.documentElement.dataset.theme === t ? ' active' : ''}`,
                dataset: { theme: t },
                text: t === 'dark' ? 'Dark' : 'Light',
                on: {
                    click: () => {
                        applyTheme(t);
                        Storage.set('theme', t);
                        themeRow.querySelectorAll('.theme-option').forEach(x =>
                            x.classList.toggle('active', x.dataset.theme === t));
                    },
                },
            });
            themeRow.appendChild(btn);
        });
        themePanel.appendChild(themeRow);
        host.appendChild(themePanel);

        const aboutPanel = h('div', { class: 'panel' });
        aboutPanel.appendChild(h('div', { class: 'panel-head' }, [
            h('div', { class: 'panel-title', text: 'About' }),
        ]));
        aboutPanel.appendChild(h('div', {
            class: 'about-text',
            text: 'SpiderForge is an automated web reconnaissance, crawling, and security assessment framework. It is designed for authorized security testing only — always ensure you have explicit permission before scanning a target.',
        }));
        host.appendChild(aboutPanel);
    }

    document.addEventListener('DOMContentLoaded', boot);
})();
