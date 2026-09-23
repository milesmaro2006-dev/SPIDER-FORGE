'use strict';

/* ═══════════════════════════════════════════════════════════════
   SpiderForge Frontend — Built for the real backend API
   ═══════════════════════════════════════════════════════════════ */

/* ═══════════════ Utils ═══════════════ */

const U = (() => {
    const h = (tag, props = {}, children = []) => {
        const el = document.createElement(tag);
        for (const [k, v] of Object.entries(props)) {
            if (v == null || v === false) continue;
            if (k === 'class')        el.className = v;
            else if (k === 'text')    el.textContent = String(v);
            else if (k === 'html')    el.innerHTML = v;
            else if (k === 'on')      for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
            else if (k === 'dataset') for (const [dk, dv] of Object.entries(v)) el.dataset[dk] = dv;
            else if (v === true)      el.setAttribute(k, '');
            else                      el.setAttribute(k, v);
        }
        for (const c of [].concat(children)) {
            if (c == null || c === false) continue;
            el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
        }
        return el;
    };

    const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); };

    const svg = (str) => {
        const t = document.createElement('template');
        t.innerHTML = str.trim();
        return t.content.firstChild;
    };

    const fmtTime = (iso) => {
        if (!iso) return '—';
        try {
            return new Date(iso).toLocaleString('en-GB', {
                year: 'numeric', month: '2-digit', day: '2-digit',
                hour: '2-digit', minute: '2-digit'
            });
        } catch { return iso; }
    };

    const fmtRelative = (iso) => {
        if (!iso) return '—';
        const s = (Date.now() - new Date(iso).getTime()) / 1000;
        if (s < 60) return 'just now';
        if (s < 3600) return `${Math.floor(s / 60)}m ago`;
        if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
        if (s < 604800) return `${Math.floor(s / 86400)}d ago`;
        return fmtTime(iso).split(',')[0];
    };

    const fmtDuration = (startIso, endIso) => {
        if (!startIso) return '—';
        if (!endIso) return 'running…';
        const sec = Math.max(0, (new Date(endIso) - new Date(startIso)) / 1000);
        if (sec < 60) return `${sec.toFixed(1)}s`;
        if (sec < 3600) return `${Math.floor(sec / 60)}m ${Math.round(sec % 60)}s`;
        return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
    };

    const shortTarget = (url) => {
        if (!url) return '—';
        try {
            const u = new URL(url);
            return u.hostname + (u.pathname !== '/' ? u.pathname : '');
        } catch { return url; }
    };

    const hostOf = (url) => {
        if (!url) return '—';
        try { return new URL(url).hostname; } catch { return url; }
    };

    const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    const SEV_LIST = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

    const severityKey = (s) => {
        const k = String(s || 'INFO').toUpperCase();
        return SEV_LIST.includes(k) ? k : 'INFO';
    };

    const countSevs = (findings) => {
        const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
        (findings || []).forEach(f => c[severityKey(f.severity)]++);
        return c;
    };

    const copy = async (text) => {
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
    };

    const Storage = {
        get(k, d = null) {
            try {
                const v = localStorage.getItem(`sf.${k}`);
                return v == null ? d : JSON.parse(v);
            } catch { return d; }
        },
        set(k, v) {
            try { localStorage.setItem(`sf.${k}`, JSON.stringify(v)); } catch {}
        },
    };

    const debounce = (fn, ms = 200) => {
        let t;
        return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
    };

    // Normalize a finding — POST /api/scan uses `http_method`, DB endpoint uses `method`
    const normFinding = (f) => ({
        ...f,
        method: f.method || f.http_method || 'GET',
        evidence: f.evidence || null,
    });

    return {
        h, clear, svg,
        fmtTime, fmtRelative, fmtDuration, shortTarget, hostOf,
        SEV_ORDER, SEV_LIST, severityKey, countSevs,
        copy, Storage, debounce, normFinding,
    };
})();

/* ═══════════════ API ═══════════════ */

const API = (() => {
    const request = async (url, opts = {}) => {
        let resp;
        try {
            resp = await fetch(url, opts);
        } catch {
            const e = new Error('Cannot reach the backend. Is the server running?');
            e.code = 'NETWORK_ERROR';
            throw e;
        }

        const text = await resp.text().catch(() => '');
        let data = {};
        if (text) { try { data = JSON.parse(text); } catch {} }

        if (!resp.ok) {
            const msg = data?.error?.message
                     || data?.error?.detail
                     || `Request failed (HTTP ${resp.status})`;
            const e = new Error(msg);
            e.code = data?.error?.code || `HTTP_${resp.status}`;
            e.detail = data?.error?.detail || '';
            e.status = resp.status;
            throw e;
        }
        return data;
    };

    return {
        health:       () => request('/api/health'),
        capabilities: () => request('/api/capabilities'),
        listScans:    (limit = 50) => request(`/api/scans?limit=${limit}`),
        getScan:      (id) => request(`/api/scans/${id}`),
        getFindings:  (id) => request(`/api/scans/${id}/findings`),
        runScan:      (payload) => request('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        }),
        reportUrl: (id, fmt, dl = false) =>
            `/api/scans/${id}/report?format=${fmt}${dl ? '&download=true' : ''}`,
        bundleUrl: (id) => `/api/scans/${id}/report/bundle`,
    };
})();

/* ═══════════════ Icons ═══════════════ */

const ICON = {
    err:     `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>`,
    warn:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.7 3.86a2 2 0 0 0-3.4 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>`,
    check:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>`,
    info:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>`,
    back:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5"/><path d="m12 19-7-7 7-7"/></svg>`,
    plus:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14"/><path d="M5 12h14"/></svg>`,
    download:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg>`,
    eye:     `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>`,
    copy:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`,
    refresh: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2v6h-6"/><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M3 22v-6h6"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/></svg>`,
};

/* ═══════════════ UI Helpers ═══════════════ */

const UI = (() => {
    const { h, svg } = U;

    const toast = (msg, kind = 'info', timeout = 4200) => {
        const host = document.getElementById('toast-host');
        if (!host) return;
        const iconKey = kind === 'error' ? 'err' : kind === 'ok' ? 'check' : kind === 'warn' ? 'warn' : 'info';
        const icon = svg(ICON[iconKey]);
        icon.style.color = kind === 'error' ? 'var(--err)'
                         : kind === 'ok'    ? 'var(--ok)'
                         : kind === 'warn'  ? 'var(--warn)'
                         : 'var(--cyan)';
        const t = h('div', { class: `toast ${kind === 'info' ? '' : kind}` }, [icon, h('div', { text: msg })]);
        host.appendChild(t);
        setTimeout(() => {
            t.style.transition = 'opacity .25s, transform .25s';
            t.style.opacity = '0';
            t.style.transform = 'translateX(16px)';
            setTimeout(() => t.remove(), 280);
        }, timeout);
    };

    const empty = ({ title, text, action = null }) => {
        const wrap = h('div', { class: 'empty' });
        if (title) wrap.appendChild(h('div', { class: 'empty-title', text: title }));
        if (text)  wrap.appendChild(h('div', { class: 'empty-text', text }));
        if (action) wrap.appendChild(h('div', { class: 'empty-action' }, [action]));
        return wrap;
    };

    const errorBox = (err) => {
        const wrap = h('div', { class: 'alert alert-error' });
        wrap.appendChild(svg(ICON.err));
        const body = h('div');
        body.appendChild(h('div', { class: 'alert-title', text: err.message || 'Something went wrong.' }));
        if (err.detail) body.appendChild(h('div', { class: 'alert-detail', text: err.detail }));
        wrap.appendChild(body);
        return wrap;
    };

    const skeletons = (n = 5) => {
        const wrap = h('div');
        for (let i = 0; i < n; i++) wrap.appendChild(h('div', { class: 'skeleton skeleton-row' }));
        return wrap;
    };

    const codeBlock = (label, value) => {
        const pre = h('pre', {}, [h('code', { text: String(value) })]);
        const copyBtn = h('button', {
            type: 'button',
            class: 'code-copy',
            html: `${ICON.copy}<span>Copy</span>`,
            on: {
                click: async (e) => {
                    e.stopPropagation();
                    const ok = await U.copy(String(value));
                    copyBtn.querySelector('span').textContent = ok ? 'Copied' : 'Failed';
                    setTimeout(() => { copyBtn.querySelector('span').textContent = 'Copy'; }, 1400);
                }
            }
        });
        return h('div', { class: 'code-block' }, [
            h('div', { class: 'code-head' }, [h('span', { text: label }), copyBtn]),
            pre
        ]);
    };

    const findingCard = (f) => {
        const sev = U.severityKey(f.severity);
        const head = h('div', { class: 'finding-head' }, [
            h('div', { class: 'finding-title', text: f.title || 'Finding' }),
            h('span', { class: `badge sev-${sev.toLowerCase()}`, text: sev }),
        ]);

        const meta = h('div', { class: 'finding-meta' });
        const pushTag = (k, v, cls = '') => {
            if (v == null || v === '') return;
            meta.appendChild(h('span', { class: `tag ${cls}` }, [
                h('span', { class: 'tag-k', text: k }),
                h('span', { class: 'tag-v', text: String(v) }),
            ]));
        };
        if (f.cvss_score != null) pushTag('CVSS', f.cvss_score, 'cvss-tag');
        pushTag('URL', U.shortTarget(f.url));
        pushTag('Param', f.param, 'accent');
        pushTag('Method', f.method);
        pushTag('Category', f.category);
        pushTag('CWE', f.cwe);
        pushTag('OWASP', f.owasp);
        pushTag('Scanner', f.scanner);
        pushTag('Confidence', f.confidence);

        const wrap = h('div', { class: `finding sev-${sev.toLowerCase()}` }, [head]);
        if (meta.children.length) wrap.appendChild(meta);

        if (f.description) wrap.appendChild(h('div', { class: 'finding-desc', text: f.description }));
        if (f.payload)     wrap.appendChild(codeBlock('Payload', f.payload));

        // Evidence can be a string (from POST) or an object (from history endpoint)
        let evidenceText = '';
        if (typeof f.evidence === 'string') {
            evidenceText = f.evidence;
        } else if (f.evidence && typeof f.evidence === 'object') {
            evidenceText = f.evidence.response_body || f.evidence.note || f.evidence.payload || '';
        }
        if (evidenceText) wrap.appendChild(codeBlock('Evidence', evidenceText));

        if (f.impact) {
            wrap.appendChild(h('div', { class: 'note impact' }, [
                h('strong', { text: 'Impact' }),
                h('p', { text: f.impact }),
            ]));
        }
        if (f.remediation) {
            wrap.appendChild(h('div', { class: 'note remediation' }, [
                h('strong', { text: 'Remediation' }),
                h('p', { text: f.remediation }),
            ]));
        }

        return wrap;
    };

    return { toast, empty, errorBox, skeletons, codeBlock, findingCard };
})();

/* ═══════════════ Main App ═══════════════ */

(() => {
    const { h, clear, svg, Storage, SEV_LIST, SEV_ORDER, severityKey, countSevs, normFinding } = U;
    const { toast, empty, errorBox, skeletons, findingCard } = UI;

    // Cache: { scanId: findings } from POST responses (they include evidence)
    const freshFindingsCache = new Map();

    const state = {
        capabilities: null,
    };

    /* Profiles — map to backend's real ScanRequest fields */
    const PROFILES = {
        light:    { max_urls: 50,   max_depth: 2, concurrency: 5,  rate_limit: 10 },
        balanced: { max_urls: 200,  max_depth: 3, concurrency: 10, rate_limit: 20 },
        deep:     { max_urls: 1000, max_depth: 5, concurrency: 20, rate_limit: 30 },
    };

    /* ─── Boot ─── */

    async function boot() {
        setupTheme();
        refreshStatus();
        setInterval(refreshStatus, 30000);

        try { state.capabilities = await API.capabilities(); } catch {}

        window.addEventListener('hashchange', render);
        if (!location.hash) history.replaceState(null, '', '#/');
        await render();
    }

    /* ─── Theme ─── */

    function setupTheme() {
        const btn = document.getElementById('theme-toggle');
        const saved = Storage.get('theme');
        const prefers = window.matchMedia('(prefers-color-scheme: light)').matches;
        applyTheme(saved || (prefers ? 'light' : 'dark'));

        if (btn) {
            btn.addEventListener('click', () => {
                const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
                applyTheme(next);
                Storage.set('theme', next);
            });
        }
    }

    function applyTheme(t) {
        document.documentElement.dataset.theme = t;
        document.documentElement.style.colorScheme = t;
    }

    /* ─── Status ─── */

    async function refreshStatus() {
        const dot = document.getElementById('status-dot');
        const txt = document.getElementById('status-text');
        try {
            const d = await API.health();
            if (dot) dot.className = 'status-dot online';
            if (txt) txt.textContent = d.version ? `v${d.version}` : 'online';
        } catch {
            if (dot) dot.className = 'status-dot offline';
            if (txt) txt.textContent = 'offline';
        }
    }

    /* ─── Router ─── */

    function parse() {
        const raw = (location.hash || '#/').replace(/^#\/?/, '');
        const parts = raw.split('/').filter(Boolean);
        return { page: parts[0] || 'dashboard', id: parts[1] || null };
    }

    async function render() {
        const { page, id } = parse();
        const app = document.getElementById('app');
        clear(app);

        document.querySelectorAll('.nav-link').forEach(a => {
            a.classList.toggle('active', a.dataset.nav === page);
        });

        try {
            if (page === 'scan' && id)     await renderScanDetail(app, id);
            else if (page === 'settings')  renderSettings(app);
            else                            await renderDashboard(app);
        } catch (e) {
            console.error(e);
            app.appendChild(errorBox(e));
        }

        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    /* ═══════════════ Dashboard ═══════════════ */

    async function renderDashboard(app) {
        app.appendChild(h('div', { class: 'page-head' }, [
            h('h1', { class: 'page-title', text: 'Dashboard' }),
            h('div', { class: 'page-sub', text: 'Launch a new assessment and review recent scans.' }),
        ]));

        app.appendChild(buildScanForm());

        const listHost = h('div');
        app.appendChild(listHost);
        listHost.appendChild(h('div', { class: 'panel' }, [skeletons(4)]));

        let scans;
        try {
            const data = await API.listScans(50);
            scans = data.scans || [];
        } catch (e) {
            clear(listHost);
            listHost.appendChild(h('div', { class: 'panel' }, [errorBox(e)]));
            return;
        }

        clear(listHost);

        if (!scans.length) {
            listHost.appendChild(h('div', { class: 'panel' }, [
                empty({
                    title: 'No scans yet',
                    text: 'Enter a target URL above to launch your first assessment.',
                })
            ]));
            return;
        }

        listHost.appendChild(h('div', { class: 'panel no-pad' }, [
            h('div', { style: { padding: '18px 22px 14px' } }, [
                h('div', { class: 'panel-title', style: { marginBottom: '0' },
                    text: `Recent scans · ${scans.length}` }),
            ]),
            scansTable(scans),
        ]));
    }

    function scansTable(scans) {
        const tbody = h('tbody');
        scans.forEach(s => {
            tbody.appendChild(h('tr', {
                class: 'clickable',
                tabindex: '0',
                on: {
                    click: () => location.hash = `#/scan/${s.id}`,
                    keydown: (e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            location.hash = `#/scan/${s.id}`;
                        }
                    }
                }
            }, [
                h('td', { class: 'mono strong', text: `#${s.id}` }),
                h('td', { class: 'strong' }, [
                    h('div', { text: U.shortTarget(s.target) }),
                    h('div', { style: { fontSize: '11px', color: 'var(--text-mute)', marginTop: '2px' },
                        text: U.hostOf(s.target) }),
                ]),
                h('td', {}, [h('span', { class: `badge status-${s.status}`, text: s.status })]),
                h('td', { class: 'mono', text: String(s.finding_count ?? 0) }),
                h('td', { class: 'mono' }, [
                    h('div', { text: U.fmtTime(s.started_at) }),
                    h('div', { style: { fontSize: '11px', color: 'var(--text-mute)' },
                        text: U.fmtRelative(s.started_at) }),
                ]),
                h('td', { class: 'mono muted', text: U.fmtDuration(s.started_at, s.finished_at) }),
            ]));
        });

        return h('div', { class: 'table-wrap' }, [
            h('table', { class: 'table' }, [
                h('thead', {}, [
                    h('tr', {}, [
                        h('th', { text: 'ID' }),
                        h('th', { text: 'Target' }),
                        h('th', { text: 'Status' }),
                        h('th', { text: 'Findings' }),
                        h('th', { text: 'Started' }),
                        h('th', { text: 'Duration' }),
                    ])
                ]),
                tbody
            ])
        ]);
    }

    function buildScanForm() {
        const panel = h('div', { class: 'panel' });
        panel.appendChild(h('div', { class: 'panel-title', text: 'New scan' }));

        const target = h('input', {
            type: 'text', class: 'input', id: 'target-input',
            placeholder: 'https://example.com', autocomplete: 'off', spellcheck: 'false',
        });

        const profile = h('select', { class: 'select', id: 'profile-select' }, [
            h('option', { value: 'balanced', text: 'Balanced — recommended' }),
            h('option', { value: 'light', text: 'Light — quick' }),
            h('option', { value: 'deep', text: 'Deep — thorough' }),
        ]);

        panel.appendChild(h('div', { class: 'form-grid' }, [
            h('div', { class: 'field', style: { marginBottom: '0' } }, [
                h('label', { class: 'field-label', for: 'target-input', text: 'Target URL' }),
                target,
            ]),
            h('div', { class: 'field', style: { marginBottom: '0' } }, [
                h('label', { class: 'field-label', for: 'profile-select', text: 'Profile' }),
                profile,
            ]),
        ]));

        /* Advanced options — real backend fields */
        const scopeFree = h('input', { type: 'checkbox' });
        const verifyTls = h('input', { type: 'checkbox', checked: true });
        const allowPrivate = h('input', { type: 'checkbox' });

        const advanced = h('details', { class: 'advanced' }, [
            h('summary', { text: 'Advanced options' }),
            h('div', { class: 'advanced-body' }, [
                h('label', { class: 'check' }, [
                    scopeFree,
                    h('div', {}, [
                        h('div', { class: 'check-title', text: 'Open scope' }),
                        h('div', { class: 'check-text',
                            text: 'Skip hostname scope validation (like Burp/ZAP). SSRF protection still applies.' }),
                    ]),
                ]),
                h('label', { class: 'check' }, [
                    verifyTls,
                    h('div', {}, [
                        h('div', { class: 'check-title', text: 'Verify TLS certificates' }),
                        h('div', { class: 'check-text',
                            text: 'Uncheck to allow scans against hosts with self-signed or invalid certificates.' }),
                    ]),
                ]),
                h('label', { class: 'check' }, [
                    allowPrivate,
                    h('div', {}, [
                        h('div', { class: 'check-title', text: 'Allow private / internal targets' }),
                        h('div', { class: 'check-text',
                            text: 'Enable scanning of private IPs and localhost. Use only on networks you own.' }),
                    ]),
                ]),
            ]),
        ]);

        panel.appendChild(advanced);

        const btn = h('button', {
            type: 'button', class: 'btn btn-primary',
            html: `${ICON.plus}<span>Launch Scan</span>`,
        });

        const submit = async () => {
            const url = target.value.trim();
            if (!url) { toast('Enter a target URL', 'error'); target.focus(); return; }
            try {
                new URL(url.startsWith('http') ? url : `http://${url}`);
            } catch { toast('Invalid URL', 'error'); return; }

            const originalHTML = btn.innerHTML;
            btn.disabled = true;
            clear(btn);
            btn.appendChild(h('span', { class: 'spin' }));
            btn.appendChild(document.createTextNode('Scanning…'));

            const preset = PROFILES[profile.value] || PROFILES.balanced;
            const payload = {
                target: url,
                ...preset,
                scope_free: scopeFree.checked,
                verify_tls: verifyTls.checked,
                allow_private: allowPrivate.checked,
            };

            try {
                const result = await API.runScan(payload);
                const total = result.total_issues ?? 0;
                toast(`Scan complete — ${total} ${total === 1 ? 'finding' : 'findings'}`, 'ok');

                // Fetch the latest scan to obtain its DB id
                let scanId = null;
                try {
                    const list = await API.listScans(1);
                    scanId = list.scans?.[0]?.id ?? null;
                } catch {}

                // Cache findings with evidence for the detail page
                if (scanId && Array.isArray(result.findings)) {
                    freshFindingsCache.set(scanId, result.findings.map(normFinding));
                }

                if (scanId) {
                    location.hash = `#/scan/${scanId}`;
                } else {
                    await render();
                }
            } catch (e) {
                btn.disabled = false;
                btn.innerHTML = originalHTML;
                toast(e.message || 'Scan failed.', 'error', 6000);
            }
        };

        btn.addEventListener('click', submit);
        target.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });

        panel.appendChild(h('div', { class: 'form-actions' }, [btn]));
        return panel;
    }

    /* ═══════════════ Scan detail ═══════════════ */

    async function renderScanDetail(app, id) {
        const scanId = Number(id);
        if (!Number.isFinite(scanId)) {
            app.appendChild(errorBox(new Error('Invalid scan ID.')));
            return;
        }

        const back = h('a', {
            class: 'back-link',
            href: '#/',
            html: `${ICON.back}<span>Back to dashboard</span>`,
        });
        app.appendChild(back);

        const head = h('div', { class: 'page-head' }, [
            h('h1', { class: 'page-title', text: `Scan #${scanId}` }),
            h('div', { class: 'page-sub', text: 'Loading…' }),
        ]);
        app.appendChild(head);

        const body = h('div');
        app.appendChild(body);
        body.appendChild(h('div', { class: 'panel' }, [skeletons(4)]));

        let scan;
        try {
            scan = await API.getScan(scanId);
        } catch (e) {
            clear(body);
            body.appendChild(h('div', { class: 'panel' }, [errorBox(e)]));
            return;
        }

        const sub = head.querySelector('.page-sub');
        if (sub) sub.textContent = scan.target || '—';

        /* Findings: prefer fresh cache (has evidence), else fetch from DB */
        let findings;
        if (freshFindingsCache.has(scanId)) {
            findings = freshFindingsCache.get(scanId);
        } else {
            try {
                const data = await API.getFindings(scanId);
                findings = (data.findings || []).map(normFinding);
            } catch (e) {
                findings = [];
                console.error('Failed to load findings:', e);
            }
        }

        const sorted = findings.slice().sort((a, b) =>
            (SEV_ORDER[severityKey(a.severity)] ?? 99) - (SEV_ORDER[severityKey(b.severity)] ?? 99)
        );
        const counts = countSevs(findings);

        clear(body);

        /* Metadata */
        body.appendChild(buildMetaPanel(scan, findings.length));

        /* Scan error, if any */
        if (scan.error) {
            const errBox = h('div', { class: 'alert alert-error' });
            errBox.appendChild(svg(ICON.err));
            const errBody = h('div');
            errBody.appendChild(h('div', { class: 'alert-title', text: 'Scan reported an error' }));
            errBody.appendChild(h('div', { class: 'alert-detail', text: scan.error }));
            errBox.appendChild(errBody);
            body.appendChild(errBox);
        }

        /* Scope */
        if (scan.scope_config) {
            const scopePanel = buildScopePanel(scan.scope_config);
            if (scopePanel) body.appendChild(scopePanel);
        }

        /* Reports */
        body.appendChild(buildReportsPanel(scanId));

        /* Findings */
        if (findings.length === 0) {
            body.appendChild(h('div', { class: 'panel' }, [
                empty({
                    title: 'No findings',
                    text: 'This scan did not identify issues with the tested payloads.',
                })
            ]));
        } else {
            body.appendChild(buildFindingsSection(sorted, counts));
        }
    }

    function buildMetaPanel(scan, findingsCount) {
        const meta = h('div', { class: 'meta-grid' });
        const cells = [
            ['Scan ID',        scan.scan_uid || `#${scan.id}`, true],
            ['Target',         scan.target || '—', false],
            ['Status',         scan.status || '—', false],
            ['Profile',        scan.profile || '—', true],
            ['Started',        U.fmtTime(scan.started_at), true],
            ['Finished',       U.fmtTime(scan.finished_at), true],
            ['Duration',       U.fmtDuration(scan.started_at, scan.finished_at), true],
            ['Findings',       String(findingsCount), true],
            ['Discovered URLs', String(scan.discovered_urls_count ?? 0), true],
            ['Finding count (DB)', String(scan.finding_count ?? 0), true],
        ];

        cells.forEach(([k, v, mono]) => {
            meta.appendChild(h('div', { class: 'meta-cell' }, [
                h('div', { class: 'k', text: k }),
                h('div', { class: `v${mono ? ' mono' : ''}`, text: v }),
            ]));
        });

        return h('div', { class: 'panel' }, [
            h('div', { class: 'panel-title', text: 'Details' }),
            meta,
        ]);
    }

    function buildScopePanel(scopeConfig) {
        let scope;
        try {
            scope = typeof scopeConfig === 'string' ? JSON.parse(scopeConfig) : scopeConfig;
        } catch { return null; }

        const include = Array.isArray(scope?.include) ? scope.include : [];
        const exclude = Array.isArray(scope?.exclude) ? scope.exclude : [];
        if (!include.length && !exclude.length) return null;

        const list = (arr) => h('ul', { style: { listStyle: 'none', padding: '0', margin: '0' } },
            arr.map(s => h('li', {
                style: { fontFamily: 'var(--mono)', fontSize: '12px',
                         color: 'var(--text-dim)', padding: '4px 0', wordBreak: 'break-all' },
                text: s,
            }))
        );

        const panel = h('div', { class: 'panel' });
        panel.appendChild(h('div', { class: 'panel-title', text: 'Scope' }));

        const grid = h('div', { style: { display: 'grid', gap: '14px' } });

        if (include.length) {
            grid.appendChild(h('div', {}, [
                h('div', { style: { fontSize: '11px', fontFamily: 'var(--mono)',
                    color: 'var(--text-mute)', letterSpacing: '1.2px',
                    textTransform: 'uppercase', marginBottom: '6px' }, text: 'Included' }),
                list(include),
            ]));
        }
        if (exclude.length) {
            grid.appendChild(h('div', {}, [
                h('div', { style: { fontSize: '11px', fontFamily: 'var(--mono)',
                    color: 'var(--text-mute)', letterSpacing: '1.2px',
                    textTransform: 'uppercase', marginBottom: '6px' }, text: 'Excluded' }),
                list(exclude),
            ]));
        }

        panel.appendChild(grid);
        return panel;
    }

    function buildReportsPanel(scanId) {
        const caps = state.capabilities?.reports || {};
        const pdfOk = !!caps.pdf?.available;

        const actions = h('div', { class: 'report-actions' });

        actions.appendChild(h('a', {
            href: API.reportUrl(scanId, 'html'),
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
            actions.appendChild(h('span', {
                class: 'report-action disabled',
                title: caps.pdf?.reason || 'PDF not available',
                html: `${ICON.download}<span>PDF unavailable</span>`,
            }));
        }

        actions.appendChild(h('a', {
            href: API.bundleUrl(scanId),
            class: 'report-action',
            html: `${ICON.download}<span>Bundle (.zip)</span>`,
        }));

        return h('div', { class: 'panel' }, [
            h('div', { class: 'panel-title', text: 'Reports' }),
            actions,
        ]);
    }

    function buildFindingsSection(findings, counts) {
        const wrap = h('div', { class: 'panel' });
        wrap.appendChild(h('div', { class: 'panel-title', text: `Findings · ${findings.length}` }));

        let activeSev = 'all';
        const pills = h('div', { class: 'filters' });

        const makePill = (label, count, val) => {
            const p = h('button', {
                type: 'button',
                class: `pill${activeSev === val ? ' active' : ''}`,
                dataset: { sev: val },
            });
            p.appendChild(document.createTextNode(label));
            if (count != null) p.appendChild(h('span', { class: 'count', text: String(count) }));
            return p;
        };

        pills.appendChild(makePill('All', findings.length, 'all'));
        SEV_LIST.forEach(s => {
            if (!counts[s]) return;
            pills.appendChild(makePill(s, counts[s], s.toLowerCase()));
        });

        const list = h('div');
        const apply = () => {
            clear(list);
            const filtered = activeSev === 'all'
                ? findings
                : findings.filter(f => severityKey(f.severity).toLowerCase() === activeSev);
            filtered.forEach(f => list.appendChild(findingCard(f)));
        };

        pills.querySelectorAll('.pill').forEach(p => {
            p.addEventListener('click', () => {
                pills.querySelectorAll('.pill').forEach(x => x.classList.remove('active'));
                p.classList.add('active');
                activeSev = p.dataset.sev;
                apply();
            });
        });

        wrap.appendChild(pills);
        wrap.appendChild(list);
        apply();
        return wrap;
    }

    /* ═══════════════ Settings ═══════════════ */

    function renderSettings(app) {
        app.appendChild(h('div', { class: 'page-head' }, [
            h('h1', { class: 'page-title', text: 'Settings' }),
        ]));

        /* Appearance */
        const themePanel = h('div', { class: 'panel' });
        themePanel.appendChild(h('div', { class: 'panel-title', text: 'Appearance' }));
        const themeRow = h('div', { class: 'theme-row' });
        ['dark', 'light'].forEach(t => {
            const btn = h('button', {
                class: `theme-option${document.documentElement.dataset.theme === t ? ' active' : ''}`,
                text: t === 'dark' ? 'Dark' : 'Light',
                on: {
                    click: () => {
                        applyTheme(t);
                        Storage.set('theme', t);
                        themeRow.querySelectorAll('.theme-option').forEach(x =>
                            x.classList.toggle('active', x.textContent.toLowerCase() === t));
                    }
                }
            });
            themeRow.appendChild(btn);
        });
        themePanel.appendChild(themeRow);
        app.appendChild(themePanel);

        /* Report capabilities */
        const caps = state.capabilities?.reports || {};
        const capPanel = h('div', { class: 'panel' });
        capPanel.appendChild(h('div', { class: 'panel-title', text: 'Report capabilities' }));

        const capGrid = h('div', { class: 'meta-grid' });
        const capRows = [
            ['JSON',     caps.json?.available !== false],
            ['HTML',     caps.html?.available !== false],
            ['Markdown', caps.markdown?.available !== false],
            ['PDF',      !!caps.pdf?.available],
            ['Bundle',   caps.bundle?.available !== false],
        ];

        capRows.forEach(([label, available]) => {
            const cell = h('div', { class: 'meta-cell' });
            cell.appendChild(h('div', { class: 'k', text: label }));
            const v = h('div', { class: 'v' });
            v.appendChild(h('span', {
                class: `badge ${available ? 'status-completed' : 'status-failed'}`,
                text: available ? 'available' : 'unavailable',
            }));
            cell.appendChild(v);

            if (label === 'PDF' && !available && caps.pdf?.reason) {
                cell.appendChild(h('div', {
                    style: { marginTop: '8px', fontSize: '11.5px', color: 'var(--text-mute)', lineHeight: '1.5' },
                    text: caps.pdf.reason,
                }));
            }
            capGrid.appendChild(cell);
        });
        capPanel.appendChild(capGrid);
        app.appendChild(capPanel);

        /* About */
        const aboutPanel = h('div', { class: 'panel' });
        aboutPanel.appendChild(h('div', { class: 'panel-title', text: 'About' }));
        aboutPanel.appendChild(h('div', {
            class: 'about-text',
            text: 'SpiderForge is an automated web reconnaissance and security assessment tool. ' +
                  'For authorized security testing only — always ensure you have explicit permission ' +
                  'before scanning a target.',
        }));
        app.appendChild(aboutPanel);
    }

    document.addEventListener('DOMContentLoaded', boot);
})();
