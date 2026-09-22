'use strict';

/* ═══════════════════════════════════════════════════════════════
   SpiderForge — Frontend
   ═══════════════════════════════════════════════════════════════ */

const API = {
    health:       '/api/health',
    capabilities: '/api/capabilities',
    scan:         '/api/scan',
    scans:        '/api/scans',
    scanById:     (id) => `/api/scans/${id}`,
    findings:     (id) => `/api/scans/${id}/findings`,
    report:       (id, fmt, download = false) =>
        `/api/scans/${id}/report?format=${fmt}${download ? '&download=true' : ''}`,
    bundle:       (id) => `/api/scans/${id}/report/bundle`,
};

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
const SEV_LIST  = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

const state = {
    capabilities: null,
};

/* ═══════════════════════════════════════════════════════════════
   Icons (shared inline SVG strings)
   ═══════════════════════════════════════════════════════════════ */

const ICON = {
    search:  `<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>`,
    check:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>`,
    warn:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.7 3.86a2 2 0 0 0-3.4 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>`,
    err:     `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>`,
    info:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>`,
    target:  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.4" fill="currentColor"/></svg>`,
    shield:  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
    activity:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 8-6-16-3 8H2"/></svg>`,
    arrow:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>`,
    back:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5"/><path d="m12 19-7-7 7-7"/></svg>`,
    plus:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14"/><path d="M5 12h14"/></svg>`,
    download:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg>`,
    eye:     `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>`,
    ghost:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 3 7v10l9 5 9-5V7z" opacity="0.5"/></svg>`,
};

/* ═══════════════════════════════════════════════════════════════
   DOM helpers
   ═══════════════════════════════════════════════════════════════ */

function h(tag, props = {}, children = []) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
        if (k === 'class')       el.className = v;
        else if (k === 'text')   el.textContent = String(v);
        else if (k === 'html')   el.innerHTML = v;
        else if (k === 'on')     for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
        else if (k === 'dataset') for (const [dk, dv] of Object.entries(v)) el.dataset[dk] = dv;
        else if (v === true)     el.setAttribute(k, '');
        else if (v != null && v !== false) el.setAttribute(k, v);
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

/* ═══════════════════════════════════════════════════════════════
   API client
   ═══════════════════════════════════════════════════════════════ */

async function api(url, opts = {}) {
    let resp;
    try {
        resp = await fetch(url, opts);
    } catch {
        throw new Error('Cannot reach the SpiderForge backend. Is the server running?');
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
        throw err;
    }
    return data;
}

/* ═══════════════════════════════════════════════════════════════
   Utilities
   ═══════════════════════════════════════════════════════════════ */

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

function fmtDuration(startIso, endIso) {
    if (!startIso) return '—';
    const s = new Date(startIso);
    const e = endIso ? new Date(endIso) : new Date();
    const sec = Math.max(0, (e - s) / 1000);
    if (sec < 60) return `${sec.toFixed(1)}s`;
    return `${Math.floor(sec / 60)}m ${Math.round(sec % 60)}s`;
}

function shortTarget(url) {
    if (!url) return '—';
    try {
        const u = new URL(url);
        return u.hostname + (u.pathname && u.pathname !== '/' ? u.pathname : '');
    } catch { return url; }
}

function hostOf(url) {
    if (!url) return '—';
    try { return new URL(url).hostname; } catch { return url; }
}

function severityKey(s) {
    const k = String(s || 'INFO').toUpperCase();
    return SEV_LIST.includes(k) ? k : 'INFO';
}

function escHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
}

/* ═══════════════════════════════════════════════════════════════
   Toast
   ═══════════════════════════════════════════════════════════════ */

function toast(msg, kind = 'info') {
    const host = document.getElementById('toast-host');
    const iconKey = kind === 'error' ? 'err'
                  : kind === 'ok'    ? 'check'
                  : kind === 'warn'  ? 'warn'
                  : 'info';
    const icon = svgFrom(ICON[iconKey]);
    icon.style.color = kind === 'error' ? 'var(--err)'
                     : kind === 'ok'    ? 'var(--ok)'
                     : kind === 'warn'  ? 'var(--warn)'
                     : 'var(--blue)';

    const t = h('div', { class: `toast ${kind === 'info' ? '' : kind}` }, [icon]);
    t.appendChild(h('div', { text: msg }));
    host.appendChild(t);

    setTimeout(() => {
        t.style.transition = 'opacity .25s, transform .25s';
        t.style.opacity = '0';
        t.style.transform = 'translateX(16px)';
        setTimeout(() => t.remove(), 280);
    }, 4200);
}

/* ═══════════════════════════════════════════════════════════════
   Sidebar (mobile toggle)
   ═══════════════════════════════════════════════════════════════ */

function setupSidebar() {
    const btn = document.getElementById('menu-btn');
    const overlay = document.getElementById('sidebar-overlay');
    if (!btn || !overlay) return;
    const close = () => document.body.classList.remove('sidebar-open');
    btn.addEventListener('click', () => document.body.classList.toggle('sidebar-open'));
    overlay.addEventListener('click', close);
    document.querySelectorAll('.nav-item').forEach(a => a.addEventListener('click', close));
    window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') close();
    });
}

/* ═══════════════════════════════════════════════════════════════
   Engine status
   ═══════════════════════════════════════════════════════════════ */

async function refreshStatus() {
    const dot = document.getElementById('status-dot');
    const dotMobile = document.getElementById('status-dot-mobile');
    const txt = document.getElementById('status-text');
    try {
        await api(API.health);
        dot.className = 'status-dot online';
        if (dotMobile) dotMobile.className = 'status-dot mobile-dot online';
        txt.textContent = 'online';
    } catch {
        dot.className = 'status-dot offline';
        if (dotMobile) dotMobile.className = 'status-dot mobile-dot offline';
        txt.textContent = 'offline';
    }
}

/* ═══════════════════════════════════════════════════════════════
   Router
   ═══════════════════════════════════════════════════════════════ */

function parseRoute() {
    const raw = (location.hash || '#/').replace(/^#\/?/, '');
    const parts = raw.split('/').filter(Boolean);
    return { page: parts[0] || 'dashboard', id: parts[1] || null };
}

function navigate(path) { location.hash = path; }

async function renderRoute() {
    const { page, id } = parseRoute();
    const app = document.getElementById('app');
    clear(app);

    document.querySelectorAll('.nav-item').forEach(a => {
        a.classList.toggle('active', a.dataset.nav === page);
    });

    // Reset page animation
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
        app.appendChild(errorState(e));
    }

    app.focus({ preventScroll: true });
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

/* ═══════════════════════════════════════════════════════════════
   Shared components
   ═══════════════════════════════════════════════════════════════ */

function pageHead({ eyebrow, title, sub, actions }) {
    const head = h('div', { class: 'page-head' });
    const left = h('div');
    if (eyebrow) left.appendChild(h('div', { class: 'page-eyebrow', text: eyebrow }));
    left.appendChild(h('h1', { class: 'page-title', text: title }));
    if (sub) left.appendChild(h('p', { class: 'page-sub', text: sub }));
    head.appendChild(left);
    if (actions) head.appendChild(h('div', { class: 'page-actions' }, actions));
    return head;
}

function metric(label, value, { tone = '', icon = null, small = false } = {}) {
    const top = h('div', { class: 'metric-top' }, [
        h('span', { class: 'metric-label', text: label }),
    ]);
    if (icon) {
        const i = svgFrom(icon);
        i.setAttribute('class', 'metric-ico');
        top.appendChild(i);
    }
    return h('div', { class: 'metric' }, [
        top,
        h('div', {
            class: `metric-value ${tone}${small ? ' is-small' : ''}`,
            text: String(value),
        }),
    ]);
}

function emptyState({ icon = ICON.ghost, title, text, action = null }) {
    const wrap = h('div', { class: 'empty' });
    const ic = h('div', { class: 'empty-icon' });
    ic.appendChild(svgFrom(icon));
    wrap.appendChild(ic);
    if (title) wrap.appendChild(h('div', { class: 'empty-title', text: title }));
    if (text)  wrap.appendChild(h('div', { class: 'empty-text', text: text }));
    if (action) {
        const row = h('div', { style: 'display:flex;justify-content:center;gap:8px;' });
        row.appendChild(action);
        wrap.appendChild(row);
    }
    return wrap;
}

function errorState(err) {
    const wrap = h('div', { class: 'alert alert-error' });
    const ic = svgFrom(ICON.err);
    wrap.appendChild(ic);
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
        text: 'Copy',
        on: {
            click: async (e) => {
                e.stopPropagation();
                try {
                    await navigator.clipboard.writeText(String(value));
                    copyBtn.textContent = 'Copied';
                } catch {
                    copyBtn.textContent = 'Failed';
                }
                setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1200);
            },
        },
    });

    return h('div', { class: 'code-block' }, [
        h('div', { class: 'code-head' }, [h('span', { text: label }), copyBtn]),
        pre,
    ]);
}

function buildFinding(f) {
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
            h('span', { text: String(val) }),
        ]));
    };

    if (f.cvss_score != null) pushTag('CVSS', f.cvss_score, 'cvss-tag');
    pushTag('URL', shortTarget(f.url));
    pushTag('Param', f.param, 'accent');
    pushTag('Category', f.category);
    pushTag('CWE', f.cwe);
    pushTag('OWASP', f.owasp);
    pushTag('Scanner', f.scanner);

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

function buildReportPanel(scanId) {
    const panel = h('div', { class: 'panel' });
    panel.appendChild(h('div', { class: 'panel-head' }, [
        h('div', { class: 'panel-title', text: 'Reports' }),
        h('div', { class: 'panel-sub', text: 'Download or view this scan\'s report in multiple formats.' }),
    ]));

    const caps = state.capabilities?.reports || {};
    const pdfOk = !!(caps.pdf && caps.pdf.available);

    const actions = h('div', { class: 'report-actions' });

    actions.appendChild(h('a', {
        href: API.report(scanId, 'html', false),
        target: '_blank', rel: 'noopener',
        html: `${ICON.eye}<span>View HTML</span>`,
    }));
    actions.appendChild(h('a', {
        href: API.report(scanId, 'json', true),
        html: `${ICON.download}<span>JSON</span>`,
    }));
    actions.appendChild(h('a', {
        href: API.report(scanId, 'md', true),
        html: `${ICON.download}<span>Markdown</span>`,
    }));

    if (pdfOk) {
        actions.appendChild(h('a', {
            href: API.report(scanId, 'pdf', true),
            html: `${ICON.download}<span>PDF</span>`,
        }));
    } else {
        actions.appendChild(h('a', {
            class: 'disabled',
            title: caps.pdf?.reason || 'PDF renderer not installed',
            html: `${ICON.download}<span>PDF unavailable</span>`,
        }));
    }

    actions.appendChild(h('a', {
        href: API.bundle(scanId),
        html: `${ICON.download}<span>Bundle (.zip)</span>`,
    }));

    panel.appendChild(actions);
    return panel;
}

function severitySummary(counts) {
    const wrap = h('div', { class: 'sev-summary' });
    SEV_LIST.forEach(k => {
        wrap.appendChild(h('div', { class: `sev-box ${k.toLowerCase()}` }, [
            h('div', { class: 'label', text: k }),
            h('div', { class: 'value', text: String(counts[k] || 0) }),
        ]));
    });
    return wrap;
}

function countSeverities(findings) {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    findings.forEach(f => { counts[severityKey(f.severity)]++; });
    return counts;
}

/* ═══════════════════════════════════════════════════════════════
   New Assessment — modal overlay flow
   ═══════════════════════════════════════════════════════════════ */

const SCAN_PRESETS = {
    light:    { max_urls: 50,   max_depth: 2, concurrency: 5,  rate_limit: 10 },
    balanced: { max_urls: 200,  max_depth: 3, concurrency: 10, rate_limit: 20 },
    deep:     { max_urls: 1000, max_depth: 5, concurrency: 20, rate_limit: 30 },
};

function showScanOverlay(target) {
    const ov = document.getElementById('scan-overlay');
    const bar = document.getElementById('scan-ov-bar');
    const phase = document.getElementById('scan-ov-phase');
    const targetEl = document.getElementById('scan-ov-target');

    targetEl.textContent = shortTarget(target);
    bar.style.width = '0%';
    phase.textContent = 'Initializing engine…';
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

    const tick = () => {
        // Asymptotic approach to 90%
        pct += (90 - pct) * 0.06 + 0.4;
        if (pct > 90) pct = 90;
        bar.style.width = pct.toFixed(1) + '%';
        while (i < phases.length && pct >= phases[i].at) {
            phase.textContent = phases[i].label;
            i++;
        }
    };
    tick();
    const interval = setInterval(tick, 550);

    return {
        complete() {
            clearInterval(interval);
            bar.style.width = '100%';
            phase.textContent = 'Assessment complete.';
        },
        close() {
            clearInterval(interval);
            ov.hidden = true;
        },
    };
}

async function runScan(payload, { onDone } = {}) {
    const ov = showScanOverlay(payload.target);
    try {
        const result = await api(API.scan, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        ov.complete();
        toast(`Scan complete — ${result.total_issues} findings`, 'ok');

        // Fetch the freshly persisted scan
        try {
            const fresh = await api(`${API.scans}?limit=1`);
            const latest = fresh.scans?.[0];
            setTimeout(() => {
                ov.close();
                if (latest) {
                    navigate(`#/scan/${latest.id}`);
                } else {
                    navigate('#/scans');
                }
                if (onDone) onDone(latest);
            }, 500);
        } catch {
            setTimeout(() => { ov.close(); navigate('#/scans'); }, 500);
        }
    } catch (e) {
        ov.close();
        toast(e.message || 'Scan failed.', 'error');
        throw e;
    }
}

/* ═══════════════════════════════════════════════════════════════
   Page — Dashboard
   ═══════════════════════════════════════════════════════════════ */

async function renderDashboard(root) {
    root.appendChild(pageHead({
        eyebrow: 'Operations',
        title: 'Dashboard',
        sub: 'Security assessment overview — track activity and launch new operations.',
    }));

    // Skeleton metrics
    const metricsHost = h('div', { class: 'metrics' });
    for (let i = 0; i < 4; i++) metricsHost.appendChild(h('div', { class: 'skeleton skeleton-metric' }));
    root.appendChild(metricsHost);

    // New assessment panel
    root.appendChild(buildNewAssessmentPanel());

    // Recent scans host (filled after fetch)
    const recentHost = h('div', { id: 'recent-scans-host' });
    root.appendChild(recentHost);

    // Fetch scans
    let scans = [];
    try {
        const data = await api(`${API.scans}?limit=50`);
        scans = Array.isArray(data.scans) ? data.scans : [];
    } catch { /* keep empty */ }

    // Metrics
    const totalScans    = scans.length;
    const totalFindings = scans.reduce((a, s) => a + (s.finding_count || 0), 0);
    const activeScans   = scans.filter(s => ['running', 'created'].includes(s.status)).length;
    const failedScans   = scans.filter(s => s.status === 'failed').length;

    clear(metricsHost);
    metricsHost.appendChild(metric('Total Scans', totalScans, {
        tone: totalScans > 0 ? 'accent' : 'muted',
        icon: ICON.target,
    }));
    metricsHost.appendChild(metric('Active', activeScans, {
        tone: activeScans > 0 ? 'warn' : 'muted',
        icon: ICON.activity,
        small: true,
    }));
    metricsHost.appendChild(metric('Findings', totalFindings, {
        tone: totalFindings > 0 ? 'warn' : 'ok',
        icon: ICON.shield,
    }));
    metricsHost.appendChild(metric('Failed', failedScans, {
        tone: failedScans > 0 ? 'accent' : 'muted',
        icon: ICON.warn,
        small: true,
    }));

    // Recent scans
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

    // Quick targets
    const chips = h('div', { class: 'chips' });
    ['http://demo.testfire.net/', 'http://zero.webappsecurity.com/', 'http://testphp.vulnweb.com/']
        .forEach(t => {
            chips.appendChild(h('button', {
                type: 'button',
                class: 'chip',
                text: t.replace(/^https?:\/\//, '').replace(/\/$/, ''),
                on: { click: () => { input.value = t; input.focus(); } },
            }));
        });
    panel.appendChild(chips);

    panel.appendChild(h('div', { style: 'margin-top:16px' }, [scopeLabel]));

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
            await runScan(payload, {
                onDone: () => { /* navigation handled by runScan */ },
            });
        } catch {
            btn.disabled = false;
            clear(btn);
            btn.innerHTML = `${ICON.plus}<span>Launch Assessment</span>`;
        }
    };

    btn.addEventListener('click', submit);
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });

    panel.appendChild(h('div', { style: 'margin-top:18px; display:flex; justify-content:flex-end' }, [btn]));
    return panel;
}

/* ═══════════════════════════════════════════════════════════════
   Page — Scans list
   ═══════════════════════════════════════════════════════════════ */

async function renderScans(root) {
    const newBtn = h('button', {
        type: 'button',
        class: 'btn btn-primary',
        html: `${ICON.plus}<span>New Scan</span>`,
        on: { click: () => navigate('#/') },
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
        const data = await api(`${API.scans}?limit=100`);
        scans = Array.isArray(data.scans) ? data.scans : [];
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
                    on: { click: () => navigate('#/') },
                }),
            }),
        ]));
        return;
    }

    // Filter bar
    const search = h('input', {
        type: 'text',
        placeholder: 'Search by target or ID…',
        autocomplete: 'off',
    });
    const searchBox = h('div', { class: 'search-box' }, [svgFrom(ICON.search), search]);

    const statusFilters = ['all', 'completed', 'running', 'created', 'failed'];
    let activeStatus = 'all';
    let query = '';

    const pills = h('div', { class: 'filter-pills' });
    statusFilters.forEach(s => {
        pills.appendChild(h('button', {
            type: 'button',
            class: `pill${s === 'all' ? ' active' : ''}`,
            dataset: { status: s },
            text: s === 'all' ? 'All' : s,
        }));
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

    search.addEventListener('input', (e) => { query = e.target.value; applyFilters(); });

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

function scansPanel(scans, { title, subtitle, viewAll = false } = {}) {
    const panel = h('div', { class: 'panel no-pad' });
    const head = h('div', { class: 'panel-head', style: 'padding:18px 20px 0' }, [
        h('div', { class: 'panel-title', text: title }),
    ]);
    if (subtitle) head.appendChild(h('div', { class: 'panel-sub', text: subtitle }));
    panel.appendChild(head);
    panel.appendChild(scansTable(scans));

    if (viewAll) {
        const row = h('div', { style: 'padding:0 20px 18px' }, [
            h('button', {
                class: 'btn btn-ghost',
                text: 'View all scans',
                on: { click: () => navigate('#/scans') },
            }),
        ]);
        panel.appendChild(row);
    }
    return panel;
}

function scansTable(scans) {
    const wrap = h('div', { class: 'table-wrap' });
    const table = h('table', { class: 'table' });

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
        tbody.appendChild(h('tr', {
            class: 'clickable',
            on: { click: () => navigate(`#/scan/${s.id}`) },
        }, [
            h('td', { class: 'mono strong', text: `#${s.id}` }),
            h('td', { class: 'strong', text: shortTarget(s.target) }),
            h('td', {}, [h('span', { class: `badge status-${s.status}`, text: s.status })]),
            h('td', { class: 'mono right', text: String(s.finding_count ?? 0) }),
            h('td', { class: 'mono', text: fmtTime(s.started_at) }),
            h('td', { class: 'mono', text: fmtDuration(s.started_at, s.finished_at) }),
        ]));
    }));
    table.appendChild(tbody);
    wrap.appendChild(table);
    return wrap;
}

/* ═══════════════════════════════════════════════════════════════
   Page — Scan Detail
   ═══════════════════════════════════════════════════════════════ */

async function renderScanDetail(root, id) {
    if (!id) { navigate('#/scans'); return; }

    const backBtn = h('button', {
        type: 'button',
        class: 'btn btn-ghost',
        html: `${ICON.back}<span>Back</span>`,
        on: { click: () => navigate('#/scans') },
    });

    root.appendChild(h('div', { class: 'page-eyebrow', text: 'Assessment' }));
    root.appendChild(pageHead({
        title: `Scan #${id}`,
        sub: 'Loading details…',
        actions: [backBtn],
    }));

    const body = h('div');
    body.appendChild(h('div', { class: 'panel' }, [skeletonList(5)]));
    root.appendChild(body);

    let scan, findingsData;
    try {
        [scan, findingsData] = await Promise.all([
            api(API.scanById(id)),
            api(API.findings(id)),
        ]);
    } catch (e) {
        clear(body);
        body.appendChild(errorState(e));
        return;
    }

    const findings = Array.isArray(findingsData.findings) ? findingsData.findings : [];
    const counts = countSeverities(findings);
    const sorted = findings.slice().sort((a, b) =>
        (SEV_ORDER[severityKey(a.severity)] ?? 99) - (SEV_ORDER[severityKey(b.severity)] ?? 99)
    );

    // Update header sub
    const sub = root.querySelector('.page-sub');
    if (sub) sub.textContent = scan.target;

    clear(body);

    // Tabs
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
        else if (activeTab === 'reports')  tabHost.appendChild(buildReportPanel(scan.id));
    };

    renderTab();
}

function buildOverviewTab(scan, findings, counts) {
    const wrap = h('div');

    // Metadata
    const metaPanel = h('div', { class: 'panel' });
    metaPanel.appendChild(h('div', { class: 'panel-head' }, [
        h('div', { class: 'panel-title', text: 'Details' }),
    ]));

    const meta = h('div', { class: 'meta-grid' });
    const cells = [
        ['Scan ID',      scan.scan_uid || `#${scan.id}`, true],
        ['Target',       scan.target, false],
        ['Status',       scan.status, false],
        ['Started',      fmtTime(scan.started_at), true],
        ['Finished',     fmtTime(scan.finished_at), true],
        ['Duration',     fmtDuration(scan.started_at, scan.finished_at), true],
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

    // Severity summary
    wrap.appendChild(severitySummary(counts));

    // Quick findings preview
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

    // Filter
    let activeSev = 'all';
    const pills = h('div', { class: 'filter-pills' });
    pills.appendChild(h('button', {
        type: 'button',
        class: 'pill active',
        dataset: { sev: 'all' },
        text: 'All',
    }));
    SEV_LIST.forEach(s => {
        const c = counts[s] || 0;
        if (c === 0) return;
        const btn = h('button', {
            type: 'button',
            class: 'pill',
            dataset: { sev: s.toLowerCase() },
        });
        btn.appendChild(document.createTextNode(s));
        btn.appendChild(h('span', { class: 'count', text: String(c) }));
        pills.appendChild(btn);
    });

    const list = h('div');

    const apply = () => {
        clear(list);
        const filtered = activeSev === 'all'
            ? findings
            : findings.filter(f => severityKey(f.severity).toLowerCase() === activeSev);
        filtered.forEach(f => list.appendChild(buildFinding(f)));
        if (filtered.length === 0) {
            list.appendChild(h('div', { class: 'panel' }, [
                emptyState({ title: 'No findings match this filter.' }),
            ]));
        }
    };

    pills.querySelectorAll('.pill').forEach(p => {
        p.addEventListener('click', () => {
            pills.querySelectorAll('.pill').forEach(x => x.classList.remove('active'));
            p.classList.add('active');
            activeSev = p.dataset.sev;
            apply();
        });
    });

    wrap.appendChild(h('div', { class: 'filters' }, [pills]));
    wrap.appendChild(list);
    apply();
    return wrap;
}

/* ═══════════════════════════════════════════════════════════════
   Page — Findings (aggregate across recent scans)
   ═══════════════════════════════════════════════════════════════ */

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
        const data = await api(`${API.scans}?limit=25`);
        scans = Array.isArray(data.scans) ? data.scans : [];
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
                    on: { click: () => navigate('#/') },
                }),
            }),
        ]));
        return;
    }

    // Fetch findings for scans in parallel (bounded)
    const results = await Promise.all(scans.map(async (s) => {
        try {
            const data = await api(API.findings(s.id));
            return (data.findings || []).map(f => ({ ...f, _scanId: s.id, _scanTarget: s.target }));
        } catch { return []; }
    }));

    const all = results.flat().sort((a, b) =>
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

    // Filter row
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

    host.appendChild(h('div', { class: 'filters' }, [searchBox, pills]));

    const list = h('div');
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

        filtered.forEach(f => {
            const card = buildFinding(f);
            // Add scan-context badge
            const meta = card.querySelector('.finding-meta');
            if (meta) {
                const ctx = h('span', {
                    class: 'tag accent',
                    style: 'cursor:pointer',
                    on: {
                        click: (e) => {
                            e.stopPropagation();
                            navigate(`#/scan/${f._scanId}`);
                        },
                    },
                }, [
                    h('span', { class: 'tag-k', text: 'Scan' }),
                    h('span', { text: `#${f._scanId}` }),
                ]);
                meta.appendChild(ctx);
            }
            list.appendChild(card);
        });
    };

    search.addEventListener('input', (e) => { query = e.target.value; apply(); });
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

/* ═══════════════════════════════════════════════════════════════
   Page — Reports
   ═══════════════════════════════════════════════════════════════ */

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
        const data = await api(`${API.scans}?limit=60`);
        scans = Array.isArray(data.scans) ? data.scans : [];
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
                    on: { click: () => navigate('#/') },
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
            href: API.report(scan.id, 'html', false),
            target: '_blank', rel: 'noopener',
            html: `${ICON.eye}<span>View</span>`,
        }),
        h('a', {
            href: API.bundle(scan.id),
            html: `${ICON.download}<span>Bundle</span>`,
        }),
        h('a', {
            href: `#/scan/${scan.id}`,
            html: `<span>Open scan</span>`,
        }),
    ]);
    card.appendChild(actions);

    return card;
}

/* ═══════════════════════════════════════════════════════════════
   Page — Settings
   ═══════════════════════════════════════════════════════════════ */

async function renderSettings(root) {
    root.appendChild(pageHead({
        eyebrow: 'System',
        title: 'Settings',
        sub: 'Backend status, runtime capabilities, and platform information.',
    }));

    const host = h('div');
    root.appendChild(host);

    // Engine status
    let health = null;
    let healthErr = null;
    try { health = await api(API.health); }
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

    // Capabilities
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
            cell.appendChild(h('div', { class: 'muted', style: 'margin-top:6px;font-size:11.5px;', text: reason }));
        }
        capMeta.appendChild(cell);
    });
    capPanel.appendChild(capMeta);
    host.appendChild(capPanel);

    // About
    const aboutPanel = h('div', { class: 'panel' });
    aboutPanel.appendChild(h('div', { class: 'panel-head' }, [
        h('div', { class: 'panel-title', text: 'About' }),
    ]));
    aboutPanel.appendChild(h('div', {
        style: 'color:var(--text-dim); font-size:13px; line-height:1.7;',
        text: 'SpiderForge is an automated web reconnaissance, crawling, and security assessment framework. It is designed for authorized security testing only — always ensure you have explicit permission before scanning a target.',
    }));
    host.appendChild(aboutPanel);
}

/* ═══════════════════════════════════════════════════════════════
   Boot
   ═══════════════════════════════════════════════════════════════ */

async function boot() {
    setupSidebar();

    try { state.capabilities = await api(API.capabilities); }
    catch { state.capabilities = null; }

    await refreshStatus();
    setInterval(refreshStatus, 30000);

    window.addEventListener('hashchange', renderRoute);

    if (!location.hash) location.hash = '#/';
    await renderRoute();
}

document.addEventListener('DOMContentLoaded', boot);
