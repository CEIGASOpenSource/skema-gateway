/* skema gateway dashboard — single page, plain JS, no framework.
 *
 * Talks to /api/gateway/* (served by the same daemon on the same port).
 * Routes/sections switch by hash. No auth headers — everything is bound
 * to 127.0.0.1 and the user owns the process.
 */
(function () {
    'use strict';

    // ── Helpers ────────────────────────────────────────
    function esc(s) {
        const d = document.createElement('div');
        d.textContent = String(s == null ? '' : s);
        return d.innerHTML;
    }

    function relTime(iso) {
        if (!iso) return '—';
        const then = new Date(iso).getTime();
        if (isNaN(then)) return '—';
        const s = Math.max(0, Math.floor((Date.now() - then) / 1000));
        if (s < 60) return s + 's ago';
        if (s < 3600) return Math.floor(s / 60) + 'm ago';
        if (s < 86400) return Math.floor(s / 3600) + 'h ago';
        return Math.floor(s / 86400) + 'd ago';
    }

    function formatBytes(n) {
        if (!n) return '0 B';
        const units = ['B','KB','MB','GB','TB'];
        let i = 0;
        while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
        return n.toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
    }

    async function fetchJSON(url, opts) {
        const r = await fetch(url, opts || {});
        if (!r.ok) {
            let body = '';
            try { body = await r.text(); } catch (_) {}
            throw new Error('HTTP ' + r.status + ' ' + body.slice(0, 200));
        }
        return r.json();
    }

    function $(id) { return document.getElementById(id); }

    // ── Routing ────────────────────────────────────────
    function activate(target) {
        document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === target));
        document.querySelectorAll('.navlink').forEach(a => a.classList.toggle('active', a.dataset.target === target));
    }

    function fromHash() {
        const h = (location.hash || '#status').slice(1);
        const map = {
            status: 'view-status', audit: 'view-audit', operators: 'view-operators',
            backup: 'view-backup', anchors: 'view-anchors',
        };
        return map[h] || 'view-status';
    }

    window.addEventListener('hashchange', () => activate(fromHash()));

    document.querySelectorAll('.navlink').forEach(a => {
        a.addEventListener('click', e => {
            const tgt = a.dataset.target;
            activate(tgt);
        });
    });

    // ── STATUS ─────────────────────────────────────────
    async function loadStatus() {
        try {
            const s = await fetchJSON('/api/gateway/status');
            $('status-upstream').textContent = s.upstream_url || '—';
            $('status-upstream-meta').textContent = s.upstream_url ? 'mTLS · pinned' : 'not configured';
            $('status-fingerprint').textContent = s.cert_fingerprint
                ? s.cert_fingerprint.slice(0, 24) + '…'
                : '—';
            $('status-bonded-at').textContent = s.bonded_at
                ? 'bonded ' + relTime(s.bonded_at)
                : 'no anchor redeemed';
            $('status-listen').textContent = s.listen_host + ':' + s.listen_port;
            $('status-reachable').textContent = s.upstream_reachable ? 'yes' : 'no';
            $('status-reachable-meta').textContent = s.upstream_reachable
                ? 'last check ' + relTime(s.upstream_last_check)
                : (s.upstream_reachable_err || '—');
            $('topright-version').textContent = 'gateway ' + (s.version || 'dev');

            const checks = $('health-list');
            const items = s.checks || [];
            if (items.length === 0) {
                checks.innerHTML = '<div class="empty">No health probes wired yet.</div>';
            } else {
                checks.innerHTML = items.map(c => `
                    <div class="row">
                      <div class="row-main">
                        <div class="row-title">${esc(c.name)}</div>
                        <div class="row-sub">${esc(c.detail || '')}</div>
                      </div>
                      <div class="row-aside" style="color: ${c.ok ? 'var(--moss)' : 'var(--clay)'}">${c.ok ? 'ok' : 'fail'}</div>
                    </div>`).join('');
            }
        } catch (err) {
            console.error('status load', err);
        }
    }

    // ── AUDIT ──────────────────────────────────────────
    let audit_cursor = null;
    let audit_loaded = false;

    async function loadAudit(reset) {
        if (reset) { audit_cursor = null; $('audit-list').innerHTML = '<div class="empty">Loading…</div>'; }
        try {
            const params = new URLSearchParams({ limit: 50 });
            if (audit_cursor != null) params.set('before', audit_cursor);
            const data = await fetchJSON('/api/gateway/audit/entries?' + params.toString());
            const entries = data.entries || [];

            const list = $('audit-list');
            const html = entries.map(e => `
                <div class="row audit-row">
                  <div class="row-main">
                    <div class="row-title">
                      <span class="audit-domain">${esc(e.source_domain)} → ${esc(e.target_domain)}</span>
                      · <span class="audit-action">${esc(e.action)}</span>
                    </div>
                    <div class="row-sub">
                      log_id=${e.log_id} · ${esc(relTime(e.occurred_at))} · op ${esc((e.operator_id || '').slice(0, 8))}…
                      ${e.ceigas_crossing_id ? '· crossing ' + esc(e.ceigas_crossing_id.slice(0, 8)) + '…' : ''}
                    </div>
                    ${e.params ? '<div class="audit-params">' + esc(JSON.stringify(e.params)) + '</div>' : ''}
                  </div>
                </div>`).join('');
            list.innerHTML = (reset || !audit_loaded)
                ? (html || '<div class="empty">No audit entries yet.</div>')
                : list.innerHTML + html;
            audit_loaded = true;
            audit_cursor = data.next_before;
            $('btn-audit-more').hidden = audit_cursor == null;
        } catch (err) {
            console.error('audit load', err);
            $('audit-list').innerHTML = '<div class="empty">Could not load audit: ' + esc(err.message) + '</div>';
        }
    }

    async function verifyChain() {
        const out = $('verify-result');
        out.textContent = 'verifying…';
        try {
            const r = await fetchJSON('/api/gateway/audit/verify');
            if (r.ok) {
                out.textContent = '✓ chain intact (' + r.checked + ' rows)';
                out.style.color = 'var(--moss)';
            } else {
                out.textContent = '✗ chain broken at log_id=' + r.broken_at;
                out.style.color = 'var(--clay)';
            }
        } catch (err) {
            out.textContent = 'verify failed: ' + err.message;
            out.style.color = 'var(--clay)';
        }
    }

    // ── OPERATORS ─────────────────────────────────────
    async function loadOperators() {
        try {
            const data = await fetchJSON('/api/gateway/operators');
            const list = $('operators-list');
            const ops = data.operators || [];
            if (ops.length === 0) {
                list.innerHTML = '<div class="empty">No operators have connected yet. Point a client at <code>http://localhost:' + (data.listen_port || '7878') + '/mcp</code> with an <code>X-Operator-Id</code> header to see entries here.</div>';
                return;
            }
            list.innerHTML = ops.map(o => `
                <div class="row">
                  <div class="row-main">
                    <div class="row-title mono">${esc(o.operator_id)}</div>
                    <div class="row-sub">${esc(o.call_count)} calls · last seen ${esc(relTime(o.last_seen))}</div>
                  </div>
                  <div class="row-aside">${esc(o.actions_top || '')}</div>
                </div>`).join('');
        } catch (err) {
            console.error('operators', err);
        }
    }

    // ── BACKUP ────────────────────────────────────────
    async function loadBackup() {
        try {
            const s = await fetchJSON('/api/gateway/backup/state');
            $('pill-passphrase').textContent = s.passphrase_set ? 'passphrase: set' : 'passphrase: not set';
            $('pill-passphrase').className = 'pill ' + (s.passphrase_set ? 'ok' : 'warn');
            $('pill-recovery').textContent = s.recovery_set ? 'recovery code: stored' : 'recovery code: not stored';
            $('pill-recovery').className = 'pill ' + (s.recovery_set ? 'ok' : 'warn');
            $('pill-lastsync').textContent = 'last sync: ' + (s.last_sync_at ? relTime(s.last_sync_at) : 'never');
            $('pill-lastsync').className = 'pill ' + (s.last_sync_at ? 'ok' : '');

            $('backup-stats').innerHTML = s.passphrase_set
                ? `${s.blob_count || 0} encrypted rows · ${formatBytes(s.blob_bytes || 0)} pushed to container`
                : 'No backup configured yet. Set a passphrase below to start.';

            $('backup-setup-block').hidden = s.passphrase_set;
            $('backup-configured-block').hidden = !s.passphrase_set;
        } catch (err) {
            console.error('backup state', err);
        }
    }

    async function setPassphrase() {
        const pp1 = $('input-passphrase').value;
        const pp2 = $('input-passphrase-confirm').value;
        if (!pp1 || pp1.length < 8) { alert('passphrase must be at least 8 characters'); return; }
        if (pp1 !== pp2) { alert('passphrases do not match'); return; }
        const btn = $('btn-set-passphrase');
        btn.disabled = true; btn.textContent = 'generating keys…';
        try {
            const r = await fetchJSON('/api/gateway/backup/set-passphrase', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ passphrase: pp1 }),
            });
            $('input-passphrase').value = '';
            $('input-passphrase-confirm').value = '';
            $('recovery-display').hidden = false;
            $('recovery-code').textContent = r.recovery_code;
        } catch (err) {
            alert('failed: ' + err.message);
        } finally {
            btn.disabled = false; btn.textContent = 'Generate keys + start backup';
        }
    }

    async function syncNow() {
        const btn = $('btn-sync-now');
        const out = $('sync-status');
        btn.disabled = true; out.textContent = 'syncing…'; out.style.color = 'var(--ash)';
        try {
            const r = await fetchJSON('/api/gateway/backup/sync-now', { method: 'POST' });
            out.textContent = `pushed ${r.rows} rows (${formatBytes(r.bytes || 0)})`;
            out.style.color = 'var(--moss)';
            loadBackup();
        } catch (err) {
            out.textContent = 'sync failed: ' + err.message;
            out.style.color = 'var(--clay)';
        } finally {
            btn.disabled = false;
        }
    }

    // ── ANCHORS ───────────────────────────────────────
    async function loadAnchors() {
        try {
            const data = await fetchJSON('/api/gateway/anchors');
            const list = $('anchors-list');
            const a = data.anchors || [];
            if (a.length === 0) {
                list.innerHTML = '<div class="empty">No anchors redeemed yet. Run <code>gatewayd anchor redeem &lt;code&gt;</code> to bond this machine.</div>';
                return;
            }
            list.innerHTML = a.map(x => `
                <div class="row">
                  <div class="row-main">
                    <div class="row-title">${esc(x.handle || 'anchor')}</div>
                    <div class="row-sub mono">redeemed ${esc(relTime(x.redeemed_at))} · ${esc(x.cert_fingerprint || '').slice(0, 24)}…</div>
                  </div>
                  <div class="row-aside" style="color: ${x.revoked_at ? 'var(--clay)' : 'var(--moss)'}">${x.revoked_at ? 'revoked' : 'active'}</div>
                </div>`).join('');
        } catch (err) {
            console.error('anchors', err);
        }
    }

    // ── Boot ──────────────────────────────────────────
    function refreshAll() {
        loadStatus();
        loadAudit(true);
        loadOperators();
        loadBackup();
        loadAnchors();
        $('footer-refreshed').textContent = 'refreshed ' + new Date().toLocaleTimeString();
    }

    document.addEventListener('DOMContentLoaded', () => {
        activate(fromHash());

        $('btn-verify-chain').addEventListener('click', verifyChain);
        $('btn-audit-more').addEventListener('click', () => loadAudit(false));
        $('btn-set-passphrase').addEventListener('click', setPassphrase);
        $('btn-recovery-confirmed').addEventListener('click', () => {
            $('recovery-display').hidden = true;
            loadBackup();
        });
        $('btn-sync-now').addEventListener('click', syncNow);

        refreshAll();
        setInterval(refreshAll, 30000);
    });
})();
