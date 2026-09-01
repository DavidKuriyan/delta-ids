'use strict';

const state = { refreshInFlight: false, alertSearch: '', trafficSearch: '', incidentSearch: '', ruleSearch: '' };
const $ = id => document.getElementById(id);
const esc = value => { const node = document.createElement('span'); node.textContent = value == null ? '—' : String(value); return node.innerHTML; };
const number = value => Number(value || 0).toLocaleString();
const envelope = data => data && Array.isArray(data.items) ? data : { items: [], total: 0 };
// MAC addresses are capture-plane metadata only and must never be rendered in
// the user-facing interface (alerts and traffic views show IPv4/IPv6 addresses
// and protocol fields instead).
function stripMacs(value) {
    if (Array.isArray(value)) return value.map(stripMacs);
    if (value && typeof value === 'object') {
        const out = {};
        for (const [key, entry] of Object.entries(value)) {
            if (key.toLowerCase().includes('mac')) continue;
            out[key] = stripMacs(entry);
        }
        return out;
    }
    return value;
}
function modalTitle(text) { const title = $('alert-details-title'); if (title) title.textContent = text; }
async function api(path, options = {}) {
    const response = await fetch(path, { ...options, headers: { Accept: 'application/json', ...(options.headers || {}) } });
    if (!response.ok) {
        let message = `API returned HTTP ${response.status}`;
        try { message = (await response.json()).error || message; } catch (_) {}
        throw new Error(message);
    }
    return response.json();
}
function value(id, content) { if ($(id)) $(id).textContent = content == null || content === '' ? '—' : content; }
function notice(message) { const target = $('global-error'); if (target) { target.textContent = message || ''; target.hidden = !message; } }
function severity(value) { const name = String(value || 'LOW').toUpperCase(); return `<span class="badge ${['CRITICAL','HIGH','MEDIUM','LOW'].includes(name) ? name.toLowerCase() : 'low'}">${esc(name)}</span>`; }
function time(value) { if (!value) return '—'; const date = new Date(Number(value) * 1000); if (Number.isNaN(date.getTime())) return esc(value); return esc(new Intl.DateTimeFormat('en-IN', { dateStyle: 'medium', timeStyle: 'medium', timeZone: 'Asia/Kolkata' }).format(date)); }
function table(headers, rows, empty) { return rows.length ? `<div class="table-wrap"><table class="data-table"><thead><tr>${headers.map(esc).map(x => `<th>${x}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>` : `<div class="empty">${esc(empty)}</div>`; }
function navigate(target) { document.querySelectorAll('.view').forEach(view => view.classList.toggle('active', view.id === target)); document.querySelectorAll('.nav-link').forEach(link => link.classList.toggle('active', link.dataset.target === target)); if (target !== 'overview') loadView(target); }
document.querySelectorAll('[data-target]').forEach(item => item.addEventListener('click', () => navigate(item.dataset.target)));
function alertRow(item) { return `<tr class="clickable" data-alert-id="${esc(item.id)}"><td>${esc(item.id)}</td><td>${time(item.last_seen || item.first_seen)}</td><td>${severity(item.severity)}</td><td class="mono">${esc(item.sid)}</td><td>${esc(item.source_ip)}</td><td>${esc(item.destination_ip)}</td><td>${esc(item.protocol)}</td><td>${esc(item.message)}</td></tr>`; }
function renderSeverity(items) { const target = $('severity'); if (!target) return; const levels = ['CRITICAL','HIGH','MEDIUM','LOW']; const counts = levels.map(level => [level, items.filter(item => String(item.severity || '').toUpperCase() === level).length]); const max = Math.max(...counts.map(x => x[1]), 1); target.innerHTML = counts.map(([level, count]) => `<div class="severity-row"><span class="severity-label ${level.toLowerCase()}">${level}</span><b>${count}</b><span class="bar ${level.toLowerCase()}"><i style="width:${count / max * 100}%"></i></span></div>`).join(''); }
async function loadAlerts(search = '') { const suffix = search ? `&search=${encodeURIComponent(search)}` : ''; const page = envelope(await api(`/api/alerts?page=1&page_size=500${suffix}`)); const rows = page.items.map(alertRow); if ($('alerts-table')) $('alerts-table').innerHTML = table(['ID','Timestamp','Severity','SID','Source','Destination','Protocol','Message'], rows, 'No alerts match this search.'); if ($('recent-alerts')) $('recent-alerts').innerHTML = table(['ID','Timestamp','Severity','SID','Source','Destination','Protocol','Message'], page.items.slice(0, 8).map(alertRow), 'No alerts have been recorded.'); renderSeverity(page.items); }
async function loadTraffic(search = '') { const suffix = search ? `&search=${encodeURIComponent(search)}` : ''; const page = envelope(await api(`/api/traffic?page=1&page_size=500${suffix}`)); if ($('traffic-table')) $('traffic-table').innerHTML = table(['Time','Source','Destination','Protocol','Length','ID'], page.items.map(item => `<tr class="clickable" data-traffic-id="${esc(item.id)}"><td>${time(item.timestamp)}</td><td class="mono">${esc(item.src_ip)}${item.src_port ? ':' + esc(item.src_port) : ''}</td><td class="mono">${esc(item.dst_ip)}${item.dst_port ? ':' + esc(item.dst_port) : ''}</td><td>${esc(item.protocol)}</td><td>${number(item.length)}</td><td>${esc(item.id)}</td></tr>`), 'No traffic logs match this search.'); }
async function loadIncidents(search = '') { const suffix = search ? `&search=${encodeURIComponent(search)}` : ''; const page = envelope(await api(`/api/incidents?page=1&page_size=500${suffix}`)); if ($('incidents-table')) $('incidents-table').innerHTML = table(['ID','First seen','Last seen','Status','Severity','Category','Events','Confidence','Risk','Explanation'], page.items.map(item => `<tr class="clickable" data-incident-id="${esc(item.id)}"><td>${esc(item.id)}</td><td>${time(item.first_seen)}</td><td>${time(item.last_seen)}</td><td>${esc(item.status)}</td><td>${severity(item.severity)}</td><td>${esc(item.category)}</td><td>${esc(item.event_count)}</td><td>${esc(item.confidence)}</td><td>${esc(item.risk)}</td><td>${esc(item.explanation)}</td></tr>`), 'No incidents have been recorded.'); }
function ruleRow(item) {
    const enabled = Boolean(item.enabled);
    const identity = `${esc(item.sid)}-${esc(item.revision)}`;
    return `<tr class="${enabled ? '' : 'paused-rule'}" data-rule-detail="" data-rule-detail-sid="${esc(item.sid)}" data-rule-detail-revision="${esc(item.revision)}" title="${enabled ? 'Click for rule details; Pause disables this rule' : 'Double-click to enable this paused rule'}"><td class="mono">${esc(item.sid)}</td><td>${esc(item.revision)}</td><td>${esc(item.message)}</td><td>${esc(item.protocol)}</td><td>${esc(item.category)}</td><td><span class="rule-status ${enabled ? 'enabled' : 'paused'}">${enabled ? 'enabled' : 'paused'}</span></td><td class="rule-actions"><button class="button rule-details" data-sid="${esc(item.sid)}" data-revision="${esc(item.revision)}">Details</button><button class="button rule-toggle" data-sid="${esc(item.sid)}" data-revision="${esc(item.revision)}" data-enabled="${enabled}">${enabled ? 'Pause' : 'Enable'}</button><button class="button danger rule-delete" data-sid="${esc(item.sid)}" data-revision="${esc(item.revision)}">Delete</button></td><td class="rule-text">${esc(item.rule_text || identity)}</td></tr>`;
}
async function loadRules(search = '') {
    const suffix = search ? `&search=${encodeURIComponent(search)}` : '';
    const page = envelope(await api(`/api/rules?page=1&page_size=500${suffix}`));
    if ($('rules-table')) $('rules-table').innerHTML = table(['SID','Revision','Message','Protocol','Category','Status','Controls','Rule'], page.items.map(ruleRow), 'No rules match this search.');
}
async function loadView(target) { const container = $(`${target}-table`); if (container) container.innerHTML = '<div class="loading">Loading data from the backend…</div>'; try { await ({ alerts: () => loadAlerts(state.alertSearch), traffic: () => loadTraffic(state.trafficSearch), incidents: () => loadIncidents(state.incidentSearch), rules: () => loadRules(state.ruleSearch) }[target])(); } catch (error) { if (container) container.innerHTML = `<div class="notice error">${esc(error.message)}</div>`; } }
function updateClock(system) { const date = new Date(Number(system.epoch_seconds) * 1000); let formatted; try { formatted = new Intl.DateTimeFormat('en-IN', { dateStyle: 'medium', timeStyle: 'medium', timeZone: 'Asia/Kolkata' }).format(date); } catch (_) { formatted = date.toISOString(); } const parts = formatted.split(','); value('clock-date', parts.shift()); value('clock-time', parts.join(',').trim()); }
async function refresh() {
    if (state.refreshInFlight) return;
    state.refreshInFlight = true;
    const refreshButton = $('refresh');
    if (refreshButton) { refreshButton.disabled = true; refreshButton.textContent = 'Refreshing…'; }
    try {
        const [status, stats, system, config] = await Promise.all([api('/api/status'), api('/api/stats'), api('/api/system'), api('/api/config')]);
        value('metric-packets', number(stats.packets_processed)); value('metric-alerts', number(stats.alerts)); value('metric-incidents', number(stats.incidents));
        value('engine-status', status.status); value('system-platform', system.platform); value('system-timezone', system.timezone_name); value('api-bind', `${config.api_host}:${config.api_port}`);
        if ($('runtime')) $('runtime').innerHTML = [['API status', status.api_status === 'connected' ? 'Connected' : 'Unavailable'], ['Detection engine', status.detection_engine || status.status], ['Capture status', status.capture_activity || status.capture_status || 'Not reported by backend'], ['Interface', status.interface || 'See capture process configuration'], ['Packets captured', number(status.packets_captured ?? stats.packets_received ?? 0)], ['Packets processed', number(stats.packets_processed)], ['Packet processing failures', number(status.packets_failed ?? 0)], ['Last packet', status.last_packet_time ? time(status.last_packet_time) : 'Not observed'], ['Rules loaded', number(status.rules_loaded)], ['Runtime', system.uptime_seconds == null ? 'Not reported by backend' : `${number(system.uptime_seconds)} seconds`]].map(([key, val]) => `<div><dt>${esc(key)}</dt><dd>${esc(val)}</dd></div>`).join('');
        updateClock(system); const badge = $('api-status'); if (badge) { badge.textContent = 'API CONNECTED'; badge.className = 'status status-ok'; } notice('');
        await Promise.all([loadAlerts(state.alertSearch), $('traffic-table') ? loadTraffic(state.trafficSearch) : Promise.resolve(), $('incidents-table') ? loadIncidents(state.incidentSearch) : Promise.resolve(), $('rules-table') ? loadRules(state.ruleSearch) : Promise.resolve()]);
    } catch (error) { notice(error.message); if ($('runtime')) $('runtime').innerHTML = '<div class="notice error">Backend unavailable</div>'; value('engine-status', 'API unavailable'); const badge = $('api-status'); if (badge) { badge.textContent = 'API UNAVAILABLE'; badge.className = 'status status-down'; } }
    finally { state.refreshInFlight = false; if (refreshButton) { refreshButton.disabled = false; refreshButton.textContent = 'Refresh now'; } }
}
async function showIncidentDetails(id) { const modal = $('alert-details'); if (!modal) return; modal.hidden = false; modalTitle('Incident details'); const content = $('alert-details-content'); content.innerHTML = '<div class="loading">Loading incident details…</div>'; try { const incident = await api(`/api/incidents/${encodeURIComponent(id)}`); const fields = [['Incident ID', incident.id],['Status', incident.status],['Severity', incident.severity],['Category', incident.category],['First detected', time(incident.first_seen)],['Last detected', time(incident.last_seen)],['Event count', incident.event_count],['Confidence', incident.confidence],['Risk', incident.risk],['Correlation explanation', incident.explanation]]; content.innerHTML = `<dl class="facts">${fields.filter(([, v]) => v !== undefined && v !== null && v !== '').map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join('')}</dl>${incident.alerts ? `<h3>Related alerts</h3>${table(['ID','SID','Severity','Source','Destination','Protocol','Evidence'], incident.alerts.map(alert => `<tr><td>${esc(alert.id)}</td><td>${esc(alert.sid)}</td><td>${severity(alert.severity)}</td><td>${esc(alert.source_ip)}</td><td>${esc(alert.destination_ip)}</td><td>${esc(alert.protocol)}</td><td>${esc(alert.evidence)}</td></tr>`), 'No related alerts.')}` : '<div class="empty">No related alert details were returned by the backend.</div>'}`; } catch (error) { content.innerHTML = `<div class="notice error">${esc(error.message)}</div>`; } }
async function showTrafficDetails(id) { const modal = $('alert-details'); if (!modal) return; modal.hidden = false; modalTitle('Traffic record'); const content = $('alert-details-content'); content.innerHTML = '<div class="loading">Loading packet details…</div>'; try { const packet = await api(`/api/traffic/${encodeURIComponent(id)}`); const clean = stripMacs(packet); let serialized = clean.details; if (typeof serialized === 'string') { try { serialized = JSON.stringify(stripMacs(JSON.parse(serialized)), null, 2); } catch (_) { serialized = clean.details; } } content.innerHTML = `<h3>Traffic record ${esc(clean.id)}</h3><dl class="facts">${Object.entries(clean).filter(([k, v]) => k !== 'details' && v !== undefined && v !== null && v !== '').map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(typeof v === 'object' ? JSON.stringify(v) : v)}</dd></div>`).join('')}</dl><pre class="packet-json">${esc(serialized || '')}</pre>`; } catch (error) { content.innerHTML = `<div class="notice error">${esc(error.message)}</div>`; } }
async function showAlertDetails(id) { const modal = $('alert-details'); if (!modal) return; modal.hidden = false; modalTitle('Alert details'); const content = $('alert-details-content'); content.innerHTML = '<div class="loading">Loading alert details…</div>'; try { const alert = await api(`/api/alerts/${encodeURIComponent(id)}`); let packet = null; if (alert.traffic_id) { try { packet = await api(`/api/traffic/${encodeURIComponent(alert.traffic_id)}`); } catch (_) {} } let details = {}; try { details = packet?.details ? JSON.parse(packet.details) : {}; } catch (_) {} details = stripMacs(details); const fields = [['Alert ID', alert.id],['SID', alert.sid],['Revision', alert.revision],['Severity', alert.severity],['Message', alert.message],['Detection time', time(alert.last_seen || alert.first_seen)],['Source', alert.source_ip],['Destination', alert.destination_ip],['Protocol', alert.protocol],['Packet length', packet?.length],['TTL', details.ip_ttl],['ICMP type', details.icmp_type],['ICMP code', details.icmp_code],['ICMP identifier', details.icmp_id],['ICMP sequence', details.icmp_sequence],['TCP sequence', details.tcp_sequence],['TCP acknowledgment', details.tcp_acknowledgment],['UDP length', details.udp_length]]; content.innerHTML = `<dl class="facts">${fields.filter(([, v]) => v !== undefined && v !== null && v !== '').map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join('')}</dl>${packet ? `<h3>Decoded packet details</h3><pre class="packet-json">${esc(JSON.stringify(details, null, 2))}</pre>` : '<div class="empty">Packet details are unavailable for this alert.</div>'}`; } catch (error) { content.innerHTML = `<div class="notice error">${esc(error.message)}</div>`; } }
async function showRuleDetails(sid, revision) {
    const modal = $('rule-details'); if (!modal) return;
    modal.hidden = false;
    const content = $('rule-details-content');
    content.innerHTML = '<div class="loading">Loading rule details…</div>';
    try {
        const rule = await api(`/api/rules/${encodeURIComponent(sid)}/${encodeURIComponent(revision)}`);
        const contentValue = Array.isArray(rule.content) ? rule.content.join(', ') : rule.content;
        const fields = [
            ['GID : SID', `${rule.gid}:${rule.sid}`],
            ['Revision', rule.revision],
            ['Message', rule.message],
            ['Action', rule.action],
            ['Protocol', rule.protocol],
            ['Direction', rule.direction],
            ['Source network', rule.src_ip],
            ['Source port', rule.src_port],
            ['Destination network', rule.dst_ip],
            ['Destination port', rule.dst_port],
            ['Severity', rule.severity],
            ['Priority', rule.priority],
            ['Classification / category', rule.category || rule.classification],
            ['Content patterns', contentValue],
            ['PCRE / regex', rule.pcre || rule.regex],
            ['No-case', rule.nocase == null ? null : String(rule.nocase)],
            ['Service', rule.service],
            ['Status', rule.enabled ? 'ENABLED' : 'PAUSED'],
            ['Loaded from', rule.source_file || 'runtime'],
            ['Last modified', rule.updated_at ? new Date(Math.floor(Number(rule.updated_at) / 1e6)).toLocaleString() : null],
        ];
        content.innerHTML = `<dl class="facts">${fields.filter(([, v]) => v !== undefined && v !== null && v !== '').map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join('')}</dl>${rule.rule_text ? `<h3>Rule text</h3><pre class="packet-json">${esc(rule.rule_text)}</pre>` : ''}`;
    } catch (error) { content.innerHTML = `<div class="notice error">${esc(error.message)}</div>`; }
}
async function downloadTraffic() { try { const suffix = state.trafficSearch ? `?search=${encodeURIComponent(state.trafficSearch)}` : ''; const response = await fetch(`/api/traffic/export${suffix}`, { headers: { Accept: 'application/json' } }); if (!response.ok) throw new Error(`API returned HTTP ${response.status}`); const blob = await response.blob(); const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = `delta-nids-traffic-${new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Kolkata' }).format(new Date())}.json`; document.body.appendChild(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(link.href), 0); } catch (error) { notice(error.message); } }
async function downloadAlerts() { try { const suffix = state.alertSearch ? `?search=${encodeURIComponent(state.alertSearch)}` : ''; const response = await fetch(`/api/alerts/export${suffix}`, { headers: { Accept: 'application/json' } }); if (!response.ok) throw new Error(`API returned HTTP ${response.status}`); const blob = await response.blob(); const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = `delta-nids-alerts-${new Date().toISOString().slice(0, 10)}.json`; document.body.appendChild(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(link.href), 0); } catch (error) { notice(error.message); } }
async function toggleRule(sid, revision, enabled) { return api(`/api/rules/${encodeURIComponent(sid)}/${encodeURIComponent(revision)}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled }) }); }
function collectRuleFields() {
    const mode = $('rule-dst-port-mode')?.value || 'any';
    let dstPort = 'any';
    if (mode === 'group') dstPort = $('rule-dst-port-group')?.value || '$HTTP_PORTS';
    else if (mode !== 'any') dstPort = $('rule-dst-port')?.value.trim() || '';
    const severity = $('rule-severity')?.value.trim();
    const fields = {
        action: $('rule-action')?.value || 'alert',
        protocol: $('rule-protocol')?.value || 'tcp',
        src_ip: $('rule-src-ip')?.value.trim() || 'any',
        src_port: $('rule-src-port')?.value.trim() || 'any',
        direction: $('rule-direction')?.value || '->',
        dst_ip: $('rule-dst-ip')?.value.trim() || 'any',
        dst_port: dstPort,
        message: $('rule-message')?.value.trim() || '',
        content: $('rule-content')?.value.trim() || '',
        sid: Number($('rule-sid')?.value || 0),
        rev: Number($('rule-rev')?.value || 1),
    };
    if (severity) fields.severity = severity;
    return fields;
}
function setRulePreview(text) { const preview = $('rule-preview-text'); if (preview) { preview.textContent = text || ''; preview.hidden = !text; } }
function setRuleStatus(message, isError = false) { const status = $('rule-form-status'); if (status) { status.textContent = message || ''; status.className = `form-status${isError ? ' error' : ''}`; } }
function updateDstPortMode() {
    const mode = $('rule-dst-port-mode')?.value || 'any';
    const input = $('rule-dst-port'); const group = $('rule-dst-port-group');
    if (input) input.hidden = mode === 'any' || mode === 'group';
    if (group) group.hidden = mode !== 'group';
}
async function validateRuleFields(fields) {
    return api('/api/rules/validate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ rule: { fields } }) });
}
async function validateRule() {
    const status = $('rule-form-status');
    try {
        const result = await validateRuleFields(collectRuleFields());
        setRulePreview(result.rule_text || '');
        setRuleStatus(result.valid ? 'Rule is valid and would be accepted by the detection engine.' : '', !result.valid);
    } catch (error) { setRulePreview(''); setRuleStatus(error.message, true); }
}
async function addRule(event) {
    event.preventDefault();
    const status = $('rule-form-status');
    const fields = collectRuleFields();
    if (!fields.sid || fields.sid <= 0) { setRuleStatus('A positive SID is required.'); return; }
    try {
        const validated = await validateRuleFields(fields);
        if (validated && validated.rule_text) setRulePreview(validated.rule_text);
        const result = await api('/api/rules', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ rule: { fields } }) });
        setRuleStatus(`Rule ${result.sid}/${result.revision} added and will be active on the next packet.`);
        setRulePreview('');
        await loadRules(state.ruleSearch);
    } catch (error) { setRuleStatus(error.message, true); }
}
function bindControls() {
    $('refresh')?.addEventListener('click', refresh);
    $('add-rule-form')?.addEventListener('submit', addRule);
    $('rule-validate-btn')?.addEventListener('click', validateRule);
    $('rule-dst-port-mode')?.addEventListener('change', updateDstPortMode);
    ['rule-action','rule-protocol','rule-direction','rule-dst-port-mode','rule-dst-port-group'].forEach(id => { $(id)?.addEventListener('change', debounceRulePreview); });
    ['rule-src-ip','rule-src-port','rule-dst-ip','rule-dst-port','rule-message','rule-content','rule-severity','rule-sid','rule-rev'].forEach(id => { $(id)?.addEventListener('input', debounceRulePreview); });
    updateDstPortMode();
    function debounceRulePreview() {
        clearTimeout(window.__rulePreviewTimer);
        window.__rulePreviewTimer = setTimeout(() => { if ($('rule-preview-text') && !$('rule-preview-text').hidden) validateRule(); }, 600);
    }
    $('clear-all-data')?.addEventListener('click', async () => { if (!confirm('Clear All Data?\n\nThis permanently deletes alerts, traffic, incidents, flows, and telemetry history. Loaded rules are preserved.')) return; try { await api('/api/reset', { method: 'DELETE' }); state.alertSearch = ''; state.trafficSearch = ''; state.incidentSearch = ''; state.ruleSearch = ''; ['alert-search','traffic-search','incident-search','rule-search'].forEach(id => { if ($(id)) $(id).value = ''; }); await refresh(); notice('All historical data cleared. Capture and rules remain active.'); } catch (error) { notice(error.message); } });
    $('alert-search-form')?.addEventListener('submit', event => { event.preventDefault(); state.alertSearch = $('alert-search').value.trim(); loadAlerts(state.alertSearch); });
    $('traffic-search-form')?.addEventListener('submit', event => { event.preventDefault(); state.trafficSearch = $('traffic-search').value.trim(); loadTraffic(state.trafficSearch); });
    $('incident-search-form')?.addEventListener('submit', event => { event.preventDefault(); state.incidentSearch = $('incident-search').value.trim(); loadIncidents(state.incidentSearch); });
    $('rule-search-form')?.addEventListener('submit', event => { event.preventDefault(); state.ruleSearch = $('rule-search').value.trim(); loadRules(state.ruleSearch); });
    $('clear-alert-search')?.addEventListener('click', () => { state.alertSearch = ''; $('alert-search').value = ''; loadAlerts(); });
    $('clear-traffic-search')?.addEventListener('click', () => { state.trafficSearch = ''; $('traffic-search').value = ''; loadTraffic(); });
    $('clear-incident-search')?.addEventListener('click', () => { state.incidentSearch = ''; $('incident-search').value = ''; loadIncidents(); });
    $('clear-rule-search')?.addEventListener('click', () => { state.ruleSearch = ''; $('rule-search').value = ''; loadRules(); });
    $('clear-alerts')?.addEventListener('click', async () => { if (confirm('Clear All Alerts?\n\nThis will permanently delete all stored alerts.')) { try { await api('/api/alerts', { method: 'DELETE' }); await refresh(); } catch (error) { notice(error.message); } } });
    $('download-traffic')?.addEventListener('click', downloadTraffic); $('download-alerts')?.addEventListener('click', downloadAlerts);
    $('clear-traffic')?.addEventListener('click', async () => { if (confirm('Clear All Traffic Logs?\n\nThis will permanently delete all stored traffic logs.')) { try { await api('/api/traffic', { method: 'DELETE' }); await refresh(); } catch (error) { notice(error.message); } } });
    $('rules-table')?.addEventListener('click', async event => {
        const toggle = event.target.closest('.rule-toggle');
        const remove = event.target.closest('.rule-delete');
        try {
            if (toggle) { await toggleRule(toggle.dataset.sid, toggle.dataset.revision, toggle.dataset.enabled !== 'true'); await loadRules(state.ruleSearch); }
            if (remove && confirm(`Delete rule ${remove.dataset.sid}/${remove.dataset.revision}?\n\nThis stops the rule immediately and cannot be undone.`)) { await api(`/api/rules/${encodeURIComponent(remove.dataset.sid)}/${encodeURIComponent(remove.dataset.revision)}`, { method: 'DELETE' }); await loadRules(state.ruleSearch); }
            if (!toggle && !remove) {
                const row = event.target.closest('[data-rule-detail]');
                if (row) showRuleDetails(row.dataset.ruleDetailSid, row.dataset.ruleDetailRevision);
            }
        } catch (error) { notice(error.message); }
    });
    $('rules-table')?.addEventListener('dblclick', async event => { const row = event.target.closest('.paused-rule'); if (!row) return; try { await toggleRule(row.dataset.ruleSid, row.dataset.ruleRevision, true); await loadRules(state.ruleSearch); } catch (error) { notice(error.message); } });
    document.addEventListener('click', event => { const alertRow = event.target.closest('[data-alert-id]'); if (alertRow) showAlertDetails(alertRow.dataset.alertId); const incidentRow = event.target.closest('[data-incident-id]'); if (incidentRow) showIncidentDetails(incidentRow.dataset.incidentId); const trafficRow = event.target.closest('[data-traffic-id]'); if (trafficRow) showTrafficDetails(trafficRow.dataset.trafficId); });
    $('close-alert-details')?.addEventListener('click', () => { $('alert-details').hidden = true; });
    $('close-rule-details')?.addEventListener('click', () => { $('rule-details').hidden = true; });
}
bindControls(); refresh(); setInterval(refresh, 3000);
