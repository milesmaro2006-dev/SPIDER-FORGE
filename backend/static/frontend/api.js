'use strict';

/* ═══════════════════════════════════════════════════════════════
   SpiderForge — API Client
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
