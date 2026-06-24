/* Route 53 Optimizer */
'use strict';

// ── State ─────────────────────────────────────────────────────────────────────
let _mode        = null;    // 'demo' | 'live'
let _sessionToken = null;   // JWT-like token for live sessions
let _analysisData = null;

// ── Boot ──────────────────────────────────────────────────────────────────────
// Show welcome overlay; if a previous live session token exists, skip re-auth
document.addEventListener('DOMContentLoaded', () => {
  const saved = sessionStorage.getItem('r53_session');
  if (saved) {
    // Verify it's still valid before skipping the welcome screen
    fetch('/api/auth/status', { headers: { 'X-Session-Token': saved } })
      .then(r => r.json())
      .then(data => {
        if (data.valid) {
          _sessionToken = saved;
          _mode = 'live';
          enterApp();
        }
        // Otherwise just show the welcome screen (default)
      })
      .catch(() => { /* show welcome screen */ });
  }
});

// ── Welcome screen navigation ─────────────────────────────────────────────────

function chooseDemo() {
  _mode = 'demo';
  _sessionToken = null;
  dismissWelcome();
  enterApp();
}

function chooseAWS() {
  showStep('step-credentials');
  document.getElementById('inp-key-id').focus();
}

function backToChoose() {
  clearAuthError();
  showStep('step-choose');
}

function showStep(id) {
  document.querySelectorAll('.wc-step').forEach(el => el.classList.remove('active'));
  document.getElementById(id).classList.add('active');
}

// ── Credential form ───────────────────────────────────────────────────────────

function toggleSecret() {
  const inp = document.getElementById('inp-secret');
  inp.type = inp.type === 'password' ? 'text' : 'password';
}

async function submitCredentials(event) {
  event.preventDefault();
  clearAuthError();

  const keyId  = document.getElementById('inp-key-id').value.trim();
  const secret = document.getElementById('inp-secret').value.trim();
  const region = document.getElementById('inp-region').value;

  if (!keyId || !secret) {
    showAuthError('Please enter both an Access Key ID and Secret Access Key.');
    return;
  }

  setConnectLoading(true);

  try {
    const res = await fetch('/api/auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        access_key_id: keyId,
        secret_access_key: secret,
        region,
      }),
    });

    const data = await res.json();

    if (!res.ok) {
      showAuthError(data.detail || 'Authentication failed.');
      return;
    }

    // Success — store session token and enter the app
    _sessionToken = data.token;
    _mode = 'live';
    sessionStorage.setItem('r53_session', _sessionToken);

    // Show account info in the nav
    document.getElementById('session-info').textContent =
      `Account: ${data.account_id}`;

    dismissWelcome();
    enterApp();
  } catch {
    showAuthError('Could not reach the server. Make sure the API is running.');
  } finally {
    setConnectLoading(false);
  }
}

function setConnectLoading(on) {
  const btn     = document.getElementById('btn-connect');
  const text    = document.getElementById('btn-connect-text');
  const spinner = document.getElementById('btn-connect-spinner');
  btn.disabled = on;
  text.textContent = on ? 'Validating…' : 'Validate & Connect';
  spinner.classList.toggle('hidden', !on);
}

function showAuthError(msg) {
  const el = document.getElementById('auth-error');
  el.textContent = msg;
  el.classList.remove('hidden');
}

function clearAuthError() {
  document.getElementById('auth-error').classList.add('hidden');
}

// ── App entry / exit ──────────────────────────────────────────────────────────

function dismissWelcome() {
  const overlay = document.getElementById('welcome-overlay');
  overlay.classList.add('fade-out');
  setTimeout(() => overlay.style.display = 'none', 350);
}

function enterApp() {
  document.getElementById('app').style.display = 'flex';

  if (_mode === 'demo') {
    document.getElementById('demo-banner').classList.remove('hidden');
    document.getElementById('session-info').textContent = 'Demo data — acme-corp.com';
  }
}

function returnToWelcome() {
  // Log out server-side session
  if (_sessionToken) {
    fetch('/api/auth', {
      method: 'DELETE',
      headers: { 'X-Session-Token': _sessionToken },
    }).catch(() => {});
    sessionStorage.removeItem('r53_session');
    _sessionToken = null;
  }

  _mode = null;
  _analysisData = null;

  // Reset UI state
  document.getElementById('demo-banner').classList.add('hidden');
  document.getElementById('session-info').textContent = '';
  document.getElementById('summary-bar').classList.add('hidden');
  document.getElementById('findings-panel').classList.add('hidden');
  document.getElementById('error-panel').classList.add('hidden');
  document.getElementById('welcome-hint').classList.remove('hidden');
  document.getElementById('zone-list').innerHTML =
    '<div class="empty-state">Run analysis to load zones</div>';

  document.getElementById('app').style.display = 'none';

  // Reset welcome overlay
  const overlay = document.getElementById('welcome-overlay');
  overlay.style.display = '';
  overlay.classList.remove('fade-out');
  clearAuthError();
  document.getElementById('inp-key-id').value  = '';
  document.getElementById('inp-secret').value  = '';
  showStep('step-choose');
}

// ── Analyze ───────────────────────────────────────────────────────────────────

async function analyzeAll() {
  const btn = document.getElementById('btn-analyze');
  btn.disabled = true;

  hide('welcome-hint');
  hide('findings-panel');
  hide('error-panel');
  document.getElementById('loading-msg').textContent =
    _mode === 'demo' ? 'Loading demo data…' : 'Connecting to AWS Route 53…';
  show('loading');

  try {
    const url = _mode === 'demo' ? '/api/analysis?demo=true' : '/api/analysis';
    const headers = {};
    if (_sessionToken) headers['X-Session-Token'] = _sessionToken;

    const res = await fetch(url, { headers });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Analysis failed');
    }
    _analysisData = await res.json();
    renderSummary(_analysisData);
    renderZoneList(_analysisData.zones);

    const sorted = [..._analysisData.zones].sort((a, b) => b.findings.length - a.findings.length);
    if (sorted.length) selectZone(sorted[0].zone_id);
  } catch (err) {
    showError(err.message);
  } finally {
    btn.disabled = false;
    hide('loading');
  }
}

// ── Summary bar ───────────────────────────────────────────────────────────────

function renderSummary(data) {
  document.getElementById('stat-zones').textContent    = data.zone_count;
  document.getElementById('stat-records').textContent  = data.record_count;
  document.getElementById('stat-critical').textContent = data.critical_count;
  document.getElementById('stat-warning').textContent  = data.warning_count;
  document.getElementById('stat-info').textContent     = data.info_count;
  show('summary-bar');
}

// ── Zone sidebar ──────────────────────────────────────────────────────────────

function renderZoneList(zones) {
  const list = document.getElementById('zone-list');
  list.innerHTML = '';

  const sorted = [...zones].sort((a, b) => {
    const ca = count(a.findings, 'critical'), cb = count(b.findings, 'critical');
    return cb !== ca ? cb - ca : b.findings.length - a.findings.length;
  });

  for (const zone of sorted) {
    const item = document.createElement('div');
    item.className = 'zone-item';
    item.dataset.zoneId = zone.zone_id;
    item.onclick = () => selectZone(zone.zone_id);

    const c = count(zone.findings, 'critical');
    const w = count(zone.findings, 'warning');
    const i = count(zone.findings, 'info');

    let chips = '';
    if (c) chips += `<span class="chip chip-critical">● ${c} critical</span>`;
    if (w) chips += `<span class="chip chip-warning">● ${w} warning</span>`;
    if (i) chips += `<span class="chip chip-info">● ${i} info</span>`;
    if (!zone.findings.length) chips += `<span class="chip chip-ok">✓ Clean</span>`;
    if (zone.is_private) chips += `<span class="chip chip-private">Private</span>`;

    item.innerHTML = `
      <div class="zone-name">${esc(zone.zone_name.replace(/\.$/, ''))}</div>
      <div class="zone-chips">${chips}</div>`;
    list.appendChild(item);
  }
}

// ── Findings ──────────────────────────────────────────────────────────────────

function selectZone(zoneId) {
  document.querySelectorAll('.zone-item').forEach(el =>
    el.classList.toggle('active', el.dataset.zoneId === zoneId));

  const zone = _analysisData.zones.find(z => z.zone_id === zoneId);
  if (!zone) return;

  document.getElementById('zone-title').textContent = zone.zone_name.replace(/\.$/, '');
  document.getElementById('zone-meta').textContent =
    `${zone.record_count} records · ${zone.zone_id}${zone.is_private ? ' · Private' : ' · Public'}`;

  const chips = document.getElementById('findings-summary');
  const c = count(zone.findings, 'critical');
  const w = count(zone.findings, 'warning');
  const i = count(zone.findings, 'info');
  chips.innerHTML = '';
  if (c) chips.innerHTML += `<span class="chip chip-critical">● ${c} Critical</span>`;
  if (w) chips.innerHTML += `<span class="chip chip-warning">● ${w} Warning</span>`;
  if (i) chips.innerHTML += `<span class="chip chip-info">● ${i} Info</span>`;
  if (!zone.findings.length) chips.innerHTML = `<span class="chip chip-ok">✓ No issues</span>`;

  const list = document.getElementById('findings-list');
  list.innerHTML = '';

  if (!zone.findings.length) {
    list.innerHTML = '<div class="no-findings">✓ No optimization opportunities found for this zone.</div>';
  } else {
    const groups = { critical: [], warning: [], info: [] };
    for (const f of zone.findings) groups[f.severity]?.push(f);
    const labels = { critical: 'Critical', warning: 'Warning', info: 'Info' };
    for (const [sev, findings] of Object.entries(groups)) {
      if (!findings.length) continue;
      const title = document.createElement('div');
      title.className = 'severity-section-title';
      title.innerHTML = `<span class="severity-dot ${sev}"></span>${labels[sev]}`;
      list.appendChild(title);
      for (const f of findings) list.appendChild(buildCard(f));
    }
  }

  hide('welcome-hint');
  show('findings-panel');
}

function buildCard(f) {
  const card = document.createElement('div');
  card.className = `finding-card ${f.severity}`;
  const badgeClass = { critical: 'chip-critical', warning: 'chip-warning', info: 'chip-info' }[f.severity];
  const label      = { critical: 'Critical', warning: 'Warning', info: 'Info' }[f.severity];

  card.innerHTML = `
    <div class="finding-header" onclick="toggleCard(this)">
      <span class="severity-dot ${f.severity}"></span>
      <div class="finding-title-group">
        <div class="finding-title">${esc(f.title)}</div>
        <div class="finding-record">${esc(f.record_name)} · ${esc(f.record_type)}</div>
      </div>
      <div class="finding-badges">
        <span class="chip ${badgeClass}">${label}</span>
        <span class="chip" style="background:#f1f5f9;color:#475569;font-size:11px">${esc(f.rule_id)}</span>
      </div>
      <svg class="finding-toggle" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <polyline points="6 9 12 15 18 9"/>
      </svg>
    </div>
    <div class="finding-body">
      <div class="finding-body-inner">
        <div>
          <div class="finding-section-label">Description</div>
          <div class="finding-description">${esc(f.description)}</div>
        </div>
        <div>
          <div class="finding-section-label">Recommendation</div>
          <div class="finding-recommendation">${esc(f.recommendation)}</div>
        </div>
        ${detailsSection(f.details)}
      </div>
    </div>`;
  return card;
}

function detailsSection(details) {
  if (!details || !Object.keys(details).length) return '';
  const rows = Object.entries(details).map(([k, v]) => {
    const val = Array.isArray(v) ? v.join(', ') : String(v);
    return `<tr>
      <td style="color:var(--text-muted);padding-right:16px;font-size:12px;white-space:nowrap">${esc(k)}</td>
      <td style="font-family:monospace;font-size:12px">${esc(val)}</td>
    </tr>`;
  }).join('');
  return `<div><div class="finding-section-label">Details</div><table style="border-collapse:collapse">${rows}</table></div>`;
}

function toggleCard(header) {
  const body = header.nextElementSibling;
  const icon = header.querySelector('.finding-toggle');
  const open = body.classList.toggle('open');
  icon.style.transform = open ? 'rotate(180deg)' : '';
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function count(findings, severity) {
  return findings.filter(f => f.severity === severity).length;
}

function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function show(id) { document.getElementById(id)?.classList.remove('hidden'); }
function hide(id) { document.getElementById(id)?.classList.add('hidden'); }

function showError(msg) {
  hide('loading');
  document.getElementById('error-msg').textContent = msg;
  show('error-panel');
}
