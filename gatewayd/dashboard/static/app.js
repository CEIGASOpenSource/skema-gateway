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
        const h = (location.hash || '#containers').slice(1);
        const map = {
            containers: 'view-containers',
            status: 'view-status', audit: 'view-audit', operators: 'view-operators',
            backup: 'view-backup', anchors: 'view-anchors',
        };
        return map[h] || 'view-containers';
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

    // ── OPERATORS (tile grid + detail) ────────────────
    const ICON_GLYPH = {
        'claude-code': 'CC',
        'codex':       'CX',
        'openclaw':    'OC',
        'hermes':      'H',
        'generic':     '?',
    };

    async function loadOperators() {
        try {
            const data = await fetchJSON('/api/gateway/operators');
            const grid = $('operators-grid');
            const ops = data.operators || [];
            if (ops.length === 0) {
                grid.innerHTML = '<div class="empty">No operators have connected yet. Point a client at <code>http://localhost:' + (data.listen_port || '7878') + '/mcp</code> with an <code>X-Operator-Id</code> header to see entries here.</div>';
                return;
            }
            grid.innerHTML = ops.map(o => renderOperatorTile(o)).join('');
            grid.querySelectorAll('.operator-tile').forEach(el => {
                el.addEventListener('click', () => openOperatorDetail(el.dataset.id, el.dataset.name, el.dataset.icon || ''));
            });
        } catch (err) {
            console.error('operators', err);
        }
    }

    function renderOperatorTile(o) {
        const slug = o.icon_slug || 'generic';
        const glyph = ICON_GLYPH[slug] || '?';
        return `
            <div class="operator-tile" data-id="${esc(o.operator_id)}" data-name="${esc(o.display_name)}" data-icon="${esc(slug)}">
                <div class="operator-icon" data-icon="${esc(slug)}">${esc(glyph)}</div>
                <div class="operator-body">
                    <div class="operator-name">${esc(o.display_name)}</div>
                    <div class="operator-meta">${o.call_count} calls · last seen ${esc(relTime(o.last_seen))}</div>
                </div>
            </div>
        `;
    }

    async function openOperatorDetail(opId, name, slug) {
        const grid = $('operators-grid');
        const panel = $('operator-detail');
        grid.style.display = 'none';
        panel.hidden = false;
        $('operator-detail-title').textContent = name;
        $('operator-detail-name').value = name;
        $('operator-detail-icon').value = slug || '';
        const feed = $('operator-detail-feed');
        feed.innerHTML = '<div class="empty">Loading…</div>';
        panel.dataset.operatorId = opId;
        try {
            const data = await fetchJSON('/api/gateway/operators/' + encodeURIComponent(opId) + '/activity');
            const events = data.activity || [];
            if (events.length === 0) {
                feed.innerHTML = '<div class="empty">No activity recorded for this operator.</div>';
                return;
            }
            feed.innerHTML = events.map(e => `
                <div class="operator-event outcome-${esc(e.outcome || 'ok')}">
                    <div class="operator-event-time">${esc(relTime(e.occurred_at))}</div>
                    <div>
                        <div class="operator-event-action">${esc(e.action || '')}</div>
                        <div class="operator-event-meta">→ ${esc(e.target_domain || '?')}${e.entity_id ? ' · entity ' + esc(String(e.entity_id)) : ''}${e.latency_ms != null ? ' · ' + esc(String(e.latency_ms)) + 'ms' : ''}${e.error_summary ? ' · ' + esc(e.error_summary) : ''}</div>
                    </div>
                    <div class="operator-event-meta">${esc(e.outcome || 'ok')}</div>
                </div>
            `).join('');
        } catch (err) {
            console.error('operator activity', err);
            feed.innerHTML = '<div class="empty">Failed to load activity.</div>';
        }
    }

    function closeOperatorDetail() {
        $('operators-grid').style.display = '';
        $('operator-detail').hidden = true;
        loadOperators();  // re-render in case rename happened
    }

    async function saveOperatorProfile() {
        const panel = $('operator-detail');
        const opId = panel.dataset.operatorId;
        if (!opId) return;
        const body = {
            display_name: $('operator-detail-name').value.trim(),
            icon_slug:    $('operator-detail-icon').value || null,
        };
        try {
            await fetchJSON('/api/gateway/operators/' + encodeURIComponent(opId), {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
            closeOperatorDetail();
        } catch (err) {
            console.error('operator save', err);
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

    // ── CONTAINERS (tile grid) ────────────────────────
    async function loadContainers() {
        const grid = $('tile-grid');
        const emptyMsg = $('tile-grid-empty');
        if (!grid) return;
        try {
            const data = await fetchJSON('/api/gateway/tiles/containers');
            const tiles = data.tiles || [];
            if (tiles.length === 0) {
                grid.innerHTML = '';
                if (emptyMsg) emptyMsg.style.display = '';
                return;
            }
            if (emptyMsg) emptyMsg.style.display = 'none';
            grid.innerHTML = tiles.map(t => renderTile(t)).join('');
            grid.querySelectorAll('.tile').forEach(el => {
                el.addEventListener('click', e => {
                    if (e.target.closest('.tile-action')) return;  // ignore action button clicks here
                    selectTile(el.dataset.name);
                });
            });
            grid.querySelectorAll('.tile-action[data-action="open"]').forEach(btn => {
                btn.addEventListener('click', e => {
                    e.stopPropagation();
                    const url = btn.dataset.url;
                    if (url) window.open(url, '_blank', 'noopener,noreferrer');
                });
            });
        } catch (err) {
            console.error('containers', err);
            grid.innerHTML = '<p class="view-sub">Failed to load containers: ' + esc(String(err)) + '</p>';
        }
    }

    function renderTile(t) {
        const bg = t.has_wallpaper
            ? `background-image: url('/api/gateway/tiles/wallpaper/${encodeURIComponent(t.name)}')`
            : '';
        const klass = ['tile'];
        if (t.active) klass.push('active');
        if (!t.has_wallpaper) klass.push('tile-fallback');
        const kindLabel = t.kind === 'service_container' ? 'Service' : 'Entity';
        return `
            <div class="${klass.join(' ')}" data-name="${esc(t.name)}" style="${bg}" title="Click to make active">
                ${t.active ? '<div class="tile-active-badge">Active</div>' : ''}
                <div class="tile-actions">
                    <button class="tile-action" data-action="open" data-url="${esc(t.url)}">Open ↗</button>
                </div>
                <div class="tile-overlay">
                    <div class="tile-name">${esc(t.display_name)}</div>
                    <div class="tile-kind">${kindLabel}</div>
                </div>
            </div>
        `;
    }

    async function selectTile(name) {
        try {
            await fetchJSON('/api/gateway/select', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name }),
            });
            loadContainers();   // re-render to update active badge
            loadStatus();       // status view shows active upstream — refresh
        } catch (err) {
            console.error('select', err);
        }
    }

    // ── Boot ──────────────────────────────────────────
    function refreshAll() {
        loadContainers();
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
        const opBack = $('operator-detail-back');
        if (opBack) opBack.addEventListener('click', closeOperatorDetail);
        const opSave = $('operator-detail-save');
        if (opSave) opSave.addEventListener('click', saveOperatorProfile);
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
