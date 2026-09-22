'use strict';

/* ═══════════════════════════════════════════════════════════════
   SpiderForge — UI Components
   ═══════════════════════════════════════════════════════════════ */

const UI = (() => {
    const { h, svgFrom, SEV_LIST, severityKey, copy } = Utils;

    // ─── Icons ──────────────────────────────────────────────────
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

    // ─── Toast ──────────────────────────────────────────────────
    function toast(msg, kind = 'info', timeout = 4200) {
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
        t.appendChild(h('div', { class: 'toast-body', text: msg }));
        host.appendChild(t);

        setTimeout(() => {
            t.style.transition = 'opacity .25s, transform .25s';
            t.style.opacity = '0';
            t.style.transform = 'translateX(16px)';
            setTimeout(() => t.remove(), 280);
        }, timeout);
    }

    // ─── Modal ──────────────────────────────────────────────────
    function openModal({ title, body, actions = [], size = 'md' }) {
        const host = document.getElementById('modal-host');
        const modal = document.getElementById('modal');
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
        if (modal._onKey) document.removeEventListener('keydown', modal._onKey);
        host.hidden = true;
        document.body.style.overflow = '';
    }

    // ─── Confirm ────────────────────────────────────────────────
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

    // ─── Page head ──────────────────────────────────────────────
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

    // ─── Metric card ────────────────────────────────────────────
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

    // ─── Empty state ────────────────────────────────────────────
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

    // ─── Error state ────────────────────────────────────────────
    function errorState(err) {
        const wrap = h('div', { class: 'alert alert-error' });
        wrap.appendChild(svgFrom(ICON.err));
        const body = h('div');
        body.appendChild(h('div', { class: 'alert-title', text: err.message || 'Something went wrong.' }));
        if (err.detail) body.appendChild(h('div', { class: 'alert-detail', text: err.detail }));
        wrap.appendChild(body);
        return wrap;
    }

    // ─── Skeleton ───────────────────────────────────────────────
    function skeletonList(n = 5) {
        const wrap = h('div');
        for (let i = 0; i < n; i++) wrap.appendChild(h('div', { class: 'skeleton skeleton-row' }));
        return wrap;
    }

    // ─── Code block ─────────────────────────────────────────────
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

    // ─── Finding card ───────────────────────────────────────────
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

    // ─── Severity summary ───────────────────────────────────────
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

    // ─── Report actions panel ───────────────────────────────────
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

    // ─── Scans table ────────────────────────────────────────────
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
