'use strict';

/* ═══════════════════════════════════════════════════════════════
   SpiderForge — Balanced UI
   ═══════════════════════════════════════════════════════════════ */

const API = {
    health:       '/api/health',
    capabilities: '/api/capabilities',
    scan:         '/api/scan',                 // POST — create new scan
    scans:        '/api/scans',                // GET — list all scans
    scanById:     (id) => `/api/scans/${id}`,  // GET — single scan
    findings:     (id) => `/api/scans/${id}/findings`,
    report:       (id, fmt, download = false) =>
        `/api/scans/${id}/report?format=${fmt}${download ? '&download=true' : ''}`,
    bundle:       (id) => `/api/scans/${id}/report/bundle`,
};

const state = { capabilities: null };

/* ═══════════════════════════════════════════════════════════════
   DOM helpers
   ═══════════════════════════════════════════════════════════════ */

function h(tag, props = {}, children = []) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
        if (k === 'class')      el.className = v;
        else if (k === 'text')  el.textContent = String(v);
        else if (k === 'html')  el.innerHTML = v;
        else if (k === 'on')    for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
        else if (v != null)     el.setAttribute(k, v);
    }
    for (const c of [].concat(children)) {
        if (c == null || c === false) continue;
        el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    }
    return el;
}

function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }

/* ═══════════════════════════════════════════════════════════════
   API client
   ═══════════════════════════════════════════════════════════════ */

async function api(url, opts = {}) {
    let resp;
    try {
        resp = await fetch(url, opts);
    } catch {
        throw new Error('Cannot reach server. Is the backend running?');
    }

    let data = {};
    const text = await resp.text().catch(() => '');
    if (text) { try { data = JSON.parse(text); } catch { data = {}; } }

    if (!resp.ok) {
        const msg =
            data?.error?.message ||
            data?.error?.detail ||
            data?.detail ||
            `HTTP ${resp.status}`;
        throw new Error(msg);
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

function severityKey(s) {
    const k = String(s || 'INFO').toUpperCase();
    return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(k) ? k : 'INFO';
}

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

/* ═══════════════════════════════════════════════════════════════
   Toast
   ═══════════════════════════════════════════════════════════════ */

function toast(msg, kind = 'info') {
    let host = document.querySelector('.toast-host');
    if (!host) {
        host = h('div', { class: 'toast-host' });
        document.body.appendChild(host);
    }
    const t = h('div', { class: `toast ${kind}`, text: msg });
    host.appendChild(t);
    setTimeout(() => {
        t.style.transition = 'opacity 0.25s, transform 0.25s';
        t.style.opacity = '0';
        t.style.transform = 'translateX(14px)';
        setTimeout(() => t.remove(), 300);
    }, 3600);
}

/* ═══════════════════════════════════════════════════════════════
   Engine status
   ═══════════════════════════════════════════════════════════════ */

async function refreshStatus() {
    const dot = document.getElementById('status-dot');
    const txt = document.getElementById('status-text');
    try {
        await api(API.health);
        dot.className = 'status-dot online';
        txt.textContent = 'online';
    } catch {
        dot.className = 'status-dot offline';
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

    document.querySelectorAll('.nav a').forEach(a => {
        a.classList.toggle('active', a.dataset.nav === page);
    });

    try {
        if (page === 'dashboard')      await renderDashboard(app);
        else if (page === 'scans')     await renderScans(app);
        else if (page === 'scan')      await renderScanDetail(app, id);
        else                            await renderDashboard(app);
    } catch (e) {
        app.appendChild(h('div', { class: 'alert alert-error', text: e.message }));
    }
}

/* ═══════════════════════════════════════════════════════════════
   Page — Dashboard
   ═══════════════════════════════════════════════════════════════ */

async function renderDashboard(root) {
    let scans = [];
    try {
        const data = await api(`${API.scans}?limit=50`);
        scans = Array.isArray(data.scans) ? data.scans : [];
    } catch { /* empty */ }

    root.appendChild(h('div', { class: 'page-head' }, [
        h('div', {}, [
            h('h1', { text: 'Dashboard' }),
            h('p', { text: 'Security assessment overview' }),
        ]),
    ]));

    const totalScans    = scans.length;
    const totalFindings = scans.reduce((a, s) => a + (s.finding_count || 0), 0);
    const activeScans   = scans.filter(s => ['running', 'created'].includes(s.status)).length;

    root.appendChild(h('div', { class: 'metrics' }, [
        metric('Total Scans', totalScans, totalScans > 0 ? 'accent' : 'muted'),
        metric('Active', activeScans, activeScans > 0 ? 'warn' : 'muted'),
        metric('Findings', totalFindings, totalFindings > 0 ? 'warn' : 'ok'),
        metric('Engine', 'online', 'ok'),
    ]));

    // ── New assessment form ──
    const panel = h('div', { class: 'panel' });
    panel.appendChild(h('div', { class: 'panel-title', text: 'New Assessment' }));

    const input = h('input', {
        type: 'url',
        id: 'target-input',
        placeholder: 'https://example.com',
        autocomplete: 'off',
        spellcheck: 'false',
    });
    const btn = h('button', { class: 'btn', id: 'scan-btn', text: 'Start Scan' });

    const submit = async () => {
        const target = input.value.trim();
        if (!target) { toast('Enter a target URL', 'error'); input.focus(); return; }
        try { new URL(target); } catch { toast('Invalid URL', 'error'); return; }

        btn.disabled = true;
        clear(btn);
        btn.appendChild(h('span', { class: 'spinner-inline' }));
        btn.appendChild(document.createTextNode('Scanning…'));

        try {
            const result = await api(API.scan, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, scope_free: true }),
            });
            toast(`Complete — ${result.total_issues} findings`, 'ok');
            const fresh = await api(`${API.scans}?limit=1`);
            const latest = fresh.scans?.[0];
            if (latest) navigate(`#/scan/${latest.id}`);
            else navigate('#/scans');
        } catch (e) {
            toast(e.message, 'error');
            btn.disabled = false;
            clear(btn);
            btn.textContent = 'Start Scan';
        }
    };

    btn.addEventListener('click', submit);
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });

    panel.appendChild(h('div', { class: 'form-row' }, [input, btn]));

    const quick = h('div', { class: 'quick-targets' });
    ['http://demo.testfire.net/', 'http://zero.webappsecurity.com/', 'http://testphp.vulnweb.com/']
        .forEach(t => {
            quick.appendChild(h('button', {
                text: t.replace(/^https?:\/\//, '').replace(/\/$/, ''),
                on: { click: () => { input.value = t; input.focus(); } },
            }));
        });
    panel.appendChild(quick);

    root.appendChild(panel);

    if (scans.length > 0) {
        root.appendChild(scansPanel(scans.slice(0, 5), {
            title: 'Recent Scans',
            viewAll: scans.length > 5,
        }));
    }
}

function metric(label, value, cls = '') {
    return h('div', { class: 'metric' }, [
        h('div', { class: 'metric-label', text: label }),
        h('div', { class: `metric-value ${cls}`, text: String(value) }),
    ]);
}

/* ═══════════════════════════════════════════════════════════════
   Page — Scans list
   ═══════════════════════════════════════════════════════════════ */

async function renderScans(root) {
    root.appendChild(h('div', { class: 'page-head' }, [
        h('div', {}, [
            h('h1', { text: 'Scans' }),
            h('p', { text: 'Assessment history' }),
        ]),
    ]));

    let scans = [];
    try {
        const data = await api(`${API.scans}?limit=100`);
        scans = Array.isArray(data.scans) ? data.scans : [];
    } catch (e) {
        root.appendChild(h('div', { class: 'alert alert-error', text: e.message }));
        return;
    }

    if (scans.length === 0) {
        root.appendChild(h('div', { class: 'panel empty' }, [
            h('div', { class: 'empty-icon', text: '◇' }),
            'No scans yet — run one from the Dashboard.',
        ]));
        return;
    }

    root.appendChild(scansPanel(scans, { title: `All Scans (${scans.length})` }));
}

function scansPanel(scans, { title, viewAll = false } = {}) {
    const panel = h('div', { class: 'panel' });
    panel.appendChild(h('div', { class: 'panel-title', text: title }));

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
    });
    table.appendChild(tbody);
    panel.appendChild(table);

    if (viewAll) {
        panel.appendChild(h('div', { class: 'quick-targets' }, [
            h('button', { text: 'View all →', on: { click: () => navigate('#/scans') } }),
        ]));
    }

    return panel;
}

/* ═══════════════════════════════════════════════════════════════
   Page — Scan Detail
   ═══════════════════════════════════════════════════════════════ */

async function renderScanDetail(root, id) {
    if (!id) { navigate('#/scans'); return; }

    let scan, findingsData;
    try {
        [scan, findingsData] = await Promise.all([
            api(API.scanById(id)),
            api(API.findings(id)),
        ]);
    } catch (e) {
        root.appendChild(h('div', { class: 'alert alert-error', text: `Could not load scan: ${e.message}` }));
        root.appendChild(h('button', {
            class: 'btn btn-ghost', text: '← Back',
            on: { click: () => navigate('#/scans') },
        }));
        return;
    }

    const findings = Array.isArray(findingsData.findings) ? findingsData.findings : [];

    root.appendChild(h('div', { class: 'page-head' }, [
        h('div', {}, [
            h('h1', { text: `Scan #${scan.id}` }),
            h('p', { text: scan.target }),
        ]),
        h('button', {
            class: 'btn btn-ghost',
            text: '← Back',
            on: { click: () => navigate('#/scans') },
        }),
    ]));

    // ── Metadata ──
    const meta = h('div', { class: 'panel' });
    meta.appendChild(h('div', { class: 'panel-title', text: 'Details' }));
    const metaTable = h('table', { class: 'table' });
    const metaBody = h('tbody');
    [
        ['Scan ID', scan.scan_uid || `#${scan.id}`],
        ['Target', scan.target],
        ['Status', scan.status],
        ['Started', fmtTime(scan.started_at)],
        ['Finished', fmtTime(scan.finished_at)],
        ['Duration', fmtDuration(scan.started_at, scan.finished_at)],
        ['URLs discovered', String(scan.discovered_urls_count ?? '—')],
        ['Total findings', String(scan.finding_count ?? findings.length)],
    ].forEach(([k, v]) => {
        metaBody.appendChild(h('tr', {}, [
            h('td', { style: 'width:180px; color:var(--text-mute);', text: k }),
            h('td', { class: 'mono', text: v }),
        ]));
    });
    metaTable.appendChild(metaBody);
    meta.appendChild(metaTable);
    root.appendChild(meta);

    // ── Reports ──
    root.appendChild(buildReportPanel(scan.id));

    // ── Severity summary ──
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    findings.forEach(f => { counts[severityKey(f.severity)]++; });

    const sev = h('div', { class: 'sev-summary' });
    ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].forEach(k => {
        sev.appendChild(h('div', { class: `sev-box ${k.toLowerCase()}` }, [
            h('div', { class: 'label', text: k }),
            h('div', { class: 'value', text: String(counts[k]) }),
        ]));
    });
    root.appendChild(sev);

    // ── Findings ──
    root.appendChild(h('div', { class: 'panel-title', text: `Findings (${findings.length})` }));

    if (findings.length === 0) {
        root.appendChild(h('div', { class: 'panel empty' }, [
            h('div', { class: 'empty-icon', text: '✓' }),
            'No findings detected for this scan.',
        ]));
        return;
    }

    const sorted = findings.slice().sort((a, b) =>
        (SEV_ORDER[severityKey(a.severity)] ?? 99) - (SEV_ORDER[severityKey(b.severity)] ?? 99)
    );

    sorted.forEach(f => root.appendChild(buildFinding(f)));
}

function buildFinding(f) {
    const sev = severityKey(f.severity);

    const head = h('div', { class: 'finding-head' }, [
        h('div', { class: 'finding-title', text: f.title || 'Finding' }),
        h('span', { class: `badge sev-${sev.toLowerCase()}`, text: sev }),
    ]);

    const meta = h('div', { class: 'finding-meta' });
    if (f.cvss_score != null) {
        meta.appendChild(h('span', { class: 'tag cvss-tag', text: `CVSS ${f.cvss_score}` }));
    }
    if (f.url)      meta.appendChild(h('span', { class: 'tag', text: shortTarget(f.url) }));
    if (f.param)    meta.appendChild(h('span', { class: 'tag accent', text: `param: ${f.param}` }));
    if (f.category) meta.appendChild(h('span', { class: 'tag', text: f.category }));
    if (f.cwe)      meta.appendChild(h('span', { class: 'tag', text: f.cwe }));
    if (f.owasp)    meta.appendChild(h('span', { class: 'tag', text: f.owasp }));
    if (f.scanner)  meta.appendChild(h('span', { class: 'tag', text: f.scanner }));

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

function codeBlock(label, value) {
    const pre = h('pre');
    pre.appendChild(h('code', { text: String(value) }));

    const copyBtn = h('button', {
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

/* ═══════════════════════════════════════════════════════════════
   Report Panel
   ═══════════════════════════════════════════════════════════════ */

function buildReportPanel(scanId) {
    const panel = h('div', { class: 'panel' });
    panel.appendChild(h('div', { class: 'panel-title', text: 'Reports' }));

    const caps = state.capabilities?.reports || {};
    const pdfOk = !!(caps.pdf && caps.pdf.available);

    const actions = h('div', { class: 'report-actions' });

    actions.appendChild(h('a', {
        href: API.report(scanId, 'html', false),
        target: '_blank', rel: 'noopener', text: 'View HTML',
    }));
    actions.appendChild(h('a', { href: API.report(scanId, 'json', true), text: 'JSON' }));
    actions.appendChild(h('a', { href: API.report(scanId, 'md', true),   text: 'Markdown' }));

    if (pdfOk) {
        actions.appendChild(h('a', { href: API.report(scanId, 'pdf', true), text: 'PDF' }));
    } else {
        actions.appendChild(h('a', {
            class: 'disabled',
            text: 'PDF unavailable',
            title: caps.pdf?.reason || 'PDF renderer not installed',
        }));
    }

    actions.appendChild(h('a', { href: API.bundle(scanId), text: 'Bundle (.zip)' }));

    panel.appendChild(actions);
    return panel;
}

/* ═══════════════════════════════════════════════════════════════
   Boot
   ═══════════════════════════════════════════════════════════════ */

async function boot() {
    try { state.capabilities = await api(API.capabilities); }
    catch { state.capabilities = null; }

    await refreshStatus();
    setInterval(refreshStatus, 30000);

    window.addEventListener('hashchange', renderRoute);

    if (!location.hash) location.hash = '#/';
    await renderRoute();
}

document.addEventListener('DOMContentLoaded', boot);
