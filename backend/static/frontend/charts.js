'use strict';

/* ═══════════════════════════════════════════════════════════════
   SpiderForge — Lightweight SVG Charts (no external deps)
   ═══════════════════════════════════════════════════════════════ */

const Charts = (() => {
    const { h, SEV_LIST } = Utils;

    const SEV_COLORS = {
        CRITICAL: '#ef4444',
        HIGH:     '#f97316',
        MEDIUM:   '#f59e0b',
        LOW:      '#3b82f6',
        INFO:     '#6b7280',
    };

    // ─── Donut chart ────────────────────────────────────────────
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

        // Background ring
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

        // Center total
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

    // ─── Bar chart ──────────────────────────────────────────────
    function bars(counts, { height = 140, gap = 12 } = {}) {
        const wrap = h('div', { class: 'chart-bars', style: { gap: `${gap}px` } });
        const max = Math.max(1, ...SEV_LIST.map(k => counts[k] || 0));

        SEV_LIST.forEach(k => {
            const v = counts[k] || 0;
            const pct = (v / max) * 100;
            const bar = h('div', { class: 'chart-bar-col' }, [
                h('div', { class: 'chart-bar-value', text: String(v) }),
                h('div', { class: 'chart-bar-track', style: { height: `${height}px` } }, [
                    h('div', {
                        class: 'chart-bar-fill',
                        style: {
                            height: `${Math.max(pct, v > 0 ? 4 : 0)}%`,
                            background: SEV_COLORS[k],
                        },
                    }),
                ]),
                h('div', { class: 'chart-bar-label', text: k }),
            ]);
            wrap.appendChild(bar);
        });
        return wrap;
    }

    // ─── Sparkline ──────────────────────────────────────────────
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
