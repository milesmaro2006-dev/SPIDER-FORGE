'use strict';

/* ═══════════════════════════════════════════════════════════════
   SpiderForge — Main Application
   ═══════════════════════════════════════════════════════════════ */

(() => {
    const { h, clear, svgFrom, Storage, SEV_ORDER, SEV_LIST,
            severityKey, countSeverities, shortTarget, fmtTime,
            fmtRelative, fmtDuration, fmtDate, downloadJSON, downloadCSV } = Utils;
    const { ICON, toast, openModal, closeModal, confirm, pageHead, metric,
            emptyState, errorState, skeletonList, codeBlock, buildFinding,
            severitySummary, reportPanel, scansTable } = UI;

    // ─── State ──────────────────────────────────────────────────
    const state = {
        capabilities: null,
        scans: [],
        scansLoadedAt: 0,
        scanCache: new Map(),
        findingsCache: new Map(),
        lastRoute: null,
    };

    // ─── Scan presets ───────────────────────────────────────────
    const SCAN_PRESETS = {
        light:    { max_urls: 50,   max_depth: 2, concurrency: 5,  rate_limit: 10 },
        balanced: { max_urls: 200,  max_depth: 3, concurrency: 10, rate_limit: 20 },
        deep:     { max_urls: 1000, max_depth: 5, concurrency: 20, rate_limit: 30 },
    };

    // ═══════════════════════════════════════════════════════════
    //  Boot
    // ═══════════════════════════════════════════════════════════
    async function boot() {
        setupSidebar();
        setupTheme();
        setupModalBackdrop();
        setupKeyboardShortcuts();

        try { state.capabilities = await API.capabilities(); }
        catch { state.capabilities = null; }

        await refreshStatus();
        setInterval(refreshStatus, 30000);

        window.addEventListener('hashchange', renderRoute);
        if (!location.hash) location.hash = '#/';
        await renderRoute();
    }

    // ═══════════════════════════════════════════════════════════
    //  Sidebar
    // ═══════════════════════════════════════════════════════════
    function setupSidebar() {
        const btn = document.getElementById('menu-btn');
        const overlay = document.getElementById('sidebar-overlay');
        const collapseBtn = document.getElementById('sidebar-collapse');

        const close = () => document.body.classList.remove('sidebar-open');
        if (btn) btn.addEventListener('click', () => document.body.classList.toggle('sidebar-open'));
        if (overlay) overlay.addEventListener('click', close);
        document.querySelectorAll('.nav-item').forEach(a => a.addEventListener('click', close));

        // Collapse toggle (desktop)
        const collapsed = Storage.get('sidebar.collapsed', false);
        if (collapsed) document.body.classList.add('sidebar-collapsed');
        if (collapseBtn) {
            collapseBtn.addEventListener('click', () => {
                const now = document.body.classList.toggle('sidebar-collapsed');
                Storage.set('sidebar.collapsed', now);
            });
        }

        window.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') close();
        });
    }

    // ═══════════════════════════════════════════════════════════
    //  Theme
    // ═══════════════════════════════════════════════════════════
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
        if (meta) meta.content = theme === 'light' ? '#f8fafc' : '#080a0f';
    }

    // ═══════════════════════════════════════════════════════════
    //  Modal backdrop + keyboard
    // ═══════════════════════════════════════════════════════════
    function setupModalBackdrop() {
        const backdrop = document.getElementById('modal-backdrop');
        if (backdrop) backdrop.addEventListener('click', closeModal);
    }

    function setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl/Cmd + K → focus search
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                const search = document.querySelector('.search-box input');
                if (search) { e.preventDefault(); search.focus(); }
            }
            // Ctrl/Cmd + N → new scan
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
            // G + D/S/F/R → navigate
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

    // ═══════════════════════════════════════════════════════════
    //  Engine status
    // ═══════════════════════════════════════════════════════════
    async function refreshStatus() {
        const dot = document.getElementById('status-dot');
        const dotMobile = document.getElementById('status-dot-mobile');
        const txt = document.getElementById('status-text');
        try {
            const data = await API.health();
            dot.className = 'status-dot online';
            if (dotMobile) dotMobile.className = 'status-dot mobile-dot online';
            txt.textContent = data.version ? `v${data.version}` : 'online';
        } catch {
            dot.className = 'status-dot offline';
            if (dotMobile) dotMobile.className = 'status-dot mobile-dot offline';
            txt.textContent = 'offline';
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  Router
    // ═══════════════════════════════════════════════════════════
    function parseRoute() {
        const raw = (location.hash || '#/').replace(/^#\/?/, '');
        const parts = raw.split('/').filter(Boolean);
        return { page: parts[0] || 'dashboard', id: parts[1] || null };
    }

    async function renderRoute() {
        const { page, id } = parseRoute();
        const app = document.getElementById('app');
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
            app.appendChild(errorState(e));
        }

        app.focus({ preventScroll: true });
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    // ═══════════════════════════════════════════════════════════
    //  Data helpers
    // ═══════════════════════════════════════════════════════════
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
    //  Page — Dashboard
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

        // Skeleton
        const metricsHost = h('div', { class: 'metrics' });
        for (let i = 0; i < 4; i++) metricsHost.appendChild(h('div', { class: 'skeleton skeleton-metric' }));
        root.appendChild(metricsHost);

        // New assessment panel
        root.appendChild(buildNewAssessmentPanel());

        // Recent scans host
        const recentHost = h('div', { id: 'recent-scans-host' });
        root.appendChild(recentHost);

        let scans = [];
        try {
            scans = await loadScans(50, { force: true });
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
                clear(btn);
                btn.innerHTML = `${ICON.plus}<span>Launch Assessment</span>`;
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

    // ═══════════════════════════════════════════════════════════
    //  Scan flow (overlay + API + redirect)
    // ═══════════════════════════════════════════════════════════
    function showScanOverlay(target) {
        const ov = document.getElementById('scan-overlay');
        const bar = document.getElementById('scan-ov-bar');
        const phase = document.getElementById('scan-ov-phase');
        const targetEl = document.getElementById('scan-ov-target');
        const statsEl = document.getElementById('scan-ov-stats');

        targetEl.textContent = shortTarget(target);
        bar.style.width = '0%';
        phase.textContent = 'Initializing engine…';
        statsEl.textContent = '';
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
        const startTime = Date.now();

        const tick = () => {
            pct += (90 - pct) * 0.06 + 0.4;
            if (pct > 90) pct = 90;
            bar.style.width = pct.toFixed(1) + '%';
            while (i < phases.length && pct >= phases[i].at) {
                phase.textContent = phases[i].label;
                i++;
            }
            const elapsed = ((Date.now() - startTime) / 1000).toFixed(0);
            statsEl.textContent = `Elapsed: ${elapsed}s`;
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
    //  Page — Scans list
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

        // Filter bar
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
    //  Page — Scan Detail
    // ═══════════════════════════════════════════════════════════
    async function renderScanDetail(root, id) {
        if (!id) { location.hash = '#/scans'; return; }

        const backBtn = h('button', {
            type: 'button',
            class: 'btn btn-ghost',
            html: `${ICON.back}<span>Back</span>`,
            on: { click: () => location.hash = '#/scans' },
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
                API.getScan(id),
                API.getFindings(id),
            ]);
        } catch (e) {
            clear(body);
            body.appendChild(errorState(e));
            return;
        }

        state.scanCache.set(Number(id), scan);

        const findings = Array.isArray(findingsData.findings) ? findingsData.findings : [];
        const counts = countSeverities(findings);
        const sorted = findings.slice().sort((a, b) =>
            (SEV_ORDER[severityKey(a.severity)] ?? 99) - (SEV_ORDER[severityKey(b.severity)] ?? 99)
        );

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
            else if (activeTab === 'reports')  tabHost.appendChild(reportPanel(scan.id, state.capabilities));
        };

        renderTab();
    }

    function buildOverviewTab(scan, findings, counts) {
        const wrap = h('div');

        // Chart + Summary side-by-side
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

        // Metadata
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

        let activeSev = 'all';
        let query = '';

        // Search
        const search = h('input', {
            type: 'text',
            placeholder: 'Search findings…',
            autocomplete: 'off',
        });
        const searchBox = h('div', { class: 'search-box' }, [svgFrom(ICON.search), search]);

        // Severity pills
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

        // Export buttons
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
    //  Page — Findings (aggregate)
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

        // Fetch findings for first 15 scans in parallel
        const scansToFetch = scans.slice(0, 15);
        const results = await Promise.all(scansToFetch.map(async (s) => {
            try {
                const data = await API.getFindings(s.id);
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
    //  Page — Reports
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
    //  Page — Settings
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
                cell.appendChild(h('div', { class: 'muted', style: { marginTop: '6px', fontSize: '11.5px' }, text: reason }));
            }
            capMeta.appendChild(cell);
        });
        capPanel.appendChild(capMeta);
        host.appendChild(capPanel);

        // Theme
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

        // About
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

    // ─── Start ──────────────────────────────────────────────────
    document.addEventListener('DOMContentLoaded', boot);
})();
