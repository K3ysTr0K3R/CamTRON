(() => {
  const els = {
    targetsInput: document.getElementById('targetsInput'),
    targetCount: document.getElementById('targetCount'),
    fileInput: document.getElementById('fileInput'),
    portChips: document.getElementById('portChips'),
    portsCustom: document.getElementById('portsCustom'),
    threadsRange: document.getElementById('threadsRange'),
    threadsValue: document.getElementById('threadsValue'),
    retriesRange: document.getElementById('retriesRange'),
    retriesValue: document.getElementById('retriesValue'),
    authCheck: document.getElementById('authCheck'),
    startBtn: document.getElementById('startBtn'),
    cancelBtn: document.getElementById('cancelBtn'),
    statusPill: document.getElementById('statusPill'),
    statusLabel: document.getElementById('statusLabel'),
    statTotal: document.getElementById('statTotal'),
    statScanned: document.getElementById('statScanned'),
    statFound: document.getElementById('statFound'),
    statElapsed: document.getElementById('statElapsed'),
    statRate: document.getElementById('statRate'),
    progressFill: document.getElementById('progressFill'),
    progressPct: document.getElementById('progressPct'),
    monitorWall: document.getElementById('monitorWall'),
    wallEmpty: document.getElementById('wallEmpty'),
    terminalBody: document.getElementById('terminalBody'),
    exportCsv: document.getElementById('exportCsv'),
    exportJson: document.getElementById('exportJson'),
  };

  let currentScanId = null;
  let eventSource = null;

  // ---- targets ----

  function countTargetLines() {
    const raw = els.targetsInput.value;
    const n = raw.split(/[\n,]/).map(l => l.trim()).filter(l => l && !l.startsWith('#')).length;
    els.targetCount.textContent = `${n} target${n === 1 ? '' : 's'} queued (before CIDR expansion)`;
    return n;
  }

  function refreshStartEnabled() {
    const hasTargets = countTargetLines() > 0;
    els.startBtn.disabled = !(hasTargets && els.authCheck.checked);
  }

  els.targetsInput.addEventListener('input', refreshStartEnabled);
  els.authCheck.addEventListener('change', refreshStartEnabled);

  els.fileInput.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const text = await file.text();
    const sep = els.targetsInput.value.trim() ? '\n' : '';
    els.targetsInput.value = els.targetsInput.value.trim() + sep + text.trim();
    refreshStartEnabled();
  });

  // ---- ports ----

  els.portChips.addEventListener('click', (e) => {
    const chip = e.target.closest('.chip');
    if (!chip) return;
    chip.classList.toggle('active');
  });

  function getPorts() {
    const chipPorts = Array.from(els.portChips.querySelectorAll('.chip.active')).map(c => c.dataset.port);
    const custom = els.portsCustom.value.split(',').map(p => p.trim()).filter(Boolean);
    const all = Array.from(new Set([...chipPorts, ...custom]));
    return all.join(',') || '80';
  }

  // ---- sliders ----

  els.threadsRange.addEventListener('input', () => els.threadsValue.textContent = els.threadsRange.value);
  els.retriesRange.addEventListener('input', () => els.retriesValue.textContent = els.retriesRange.value);

  // ---- terminal + wall helpers ----

  function logLine(html, cls) {
    const div = document.createElement('div');
    div.className = cls || 'line-info';
    div.innerHTML = html;
    els.terminalBody.appendChild(div);
    els.terminalBody.scrollTop = els.terminalBody.scrollHeight;
  }

  function tileGlyphFor(brands) {
    // purely decorative glyph, no real imagery
    return '▣';
  }

  function addMonitorTile(finding) {
    els.wallEmpty.style.display = 'none';
    const tile = document.createElement('div');
    tile.className = 'monitor-tile';
    const badges = finding.brands.map(b => `<span class="brand-badge">${escapeHtml(b)}</span>`).join('');
    tile.innerHTML = `
      <div class="tile-top">
        <span class="tile-rec"><span class="tile-rec-dot"></span>LIVE</span>
        <span>${escapeHtml(finding.timestamp)}</span>
      </div>
      <div class="tile-body">
        <div class="tile-glyph">${tileGlyphFor(finding.brands)}</div>
        <div class="tile-host">${escapeHtml(finding.host)}</div>
        <div class="tile-brands">${badges}</div>
      </div>
      <div class="tile-bottom">
        <span>HTTP</span>
        <span>DETECTED</span>
      </div>
    `;
    els.monitorWall.prepend(tile);
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
  }

  // ---- scan lifecycle ----

  function setStatus(state, label) {
    els.statusPill.dataset.state = state;
    els.statusLabel.textContent = label;
  }

  function resetUI() {
    els.monitorWall.querySelectorAll('.monitor-tile').forEach(t => t.remove());
    els.wallEmpty.style.display = '';
    els.terminalBody.innerHTML = '';
    els.progressFill.style.width = '0%';
    els.progressPct.textContent = '0%';
    els.statScanned.textContent = '0';
    els.statFound.textContent = '0';
    els.statElapsed.textContent = '0.0s';
    els.statRate.textContent = '0/s';
    els.exportCsv.disabled = true;
    els.exportJson.disabled = true;
  }

  async function startScan() {
    resetUI();
    const ports = getPorts();
    const threads = parseInt(els.threadsRange.value, 10);
    const retries = parseInt(els.retriesRange.value, 10);

    logLine(`Submitting scan · ports ${escapeHtml(ports)} · concurrency ${threads} · retries ${retries}`);

    let res;
    try {
      res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targets: els.targetsInput.value, ports, threads, retries }),
      });
    } catch (err) {
      logLine(`Failed to reach server: ${escapeHtml(String(err))}`, 'line-done');
      return;
    }

    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      logLine(`Error: ${escapeHtml(body.error || res.statusText)}`, 'line-done');
      return;
    }

    const data = await res.json();
    currentScanId = data.id;
    els.statTotal.textContent = data.total;

    setStatus('scanning', 'SCANNING');
    els.startBtn.disabled = true;
    els.cancelBtn.disabled = false;

    logLine(`Loaded ${data.total} targets, scanning ports [${data.ports.join(', ')}] with ${data.threads} workers`);

    openStream(currentScanId, data.total);
  }

  function openStream(id, total) {
    if (eventSource) eventSource.close();
    eventSource = new EventSource(`/api/scan/${id}/stream`);

    eventSource.onmessage = (evt) => {
      const msg = JSON.parse(evt.data);

      if (msg.type === 'found') {
        addMonitorTile(msg);
        logLine(
          `[${escapeHtml(msg.timestamp)}] <span class="host">${escapeHtml(msg.host)}</span> :: <span class="brands">${escapeHtml(msg.brands.join(', '))}</span>`,
          'line-found'
        );
      }

      if (msg.type === 'progress' || msg.type === 'done') {
        const pct = total ? Math.min(100, Math.round((msg.processed / total) * 100)) : 0;
        els.progressFill.style.width = pct + '%';
        els.progressPct.textContent = pct + '%';
        els.statScanned.textContent = msg.processed;
        els.statFound.textContent = msg.found;
      }

      if (msg.type === 'done') {
        setStatus('done', 'COMPLETE');
        els.startBtn.disabled = !els.authCheck.checked ? true : false;
        els.cancelBtn.disabled = true;
        els.statElapsed.textContent = msg.elapsed.toFixed(1) + 's';
        els.statRate.textContent = msg.rate.toFixed(1) + '/s';
        els.exportCsv.disabled = msg.found === 0;
        els.exportJson.disabled = msg.found === 0;
        logLine(`Scan completed: ${msg.found} device(s) from ${msg.total} targets in ${msg.elapsed.toFixed(2)}s (${msg.rate.toFixed(1)}/s)`, 'line-done');
        eventSource.close();
        refreshStartEnabled();
      }
    };

    eventSource.onerror = () => {
      // Browser auto-retries; if the scan is actually done the server has
      // already closed the stream, so treat repeated errors as a hard stop.
    };
  }

  async function cancelScan() {
    if (!currentScanId) return;
    await fetch(`/api/scan/${currentScanId}/cancel`, { method: 'POST' });
    logLine('Cancellation requested — draining in-flight workers…', 'line-info');
    els.cancelBtn.disabled = true;
  }

  els.startBtn.addEventListener('click', startScan);
  els.cancelBtn.addEventListener('click', cancelScan);
  els.exportCsv.addEventListener('click', () => {
    if (currentScanId) window.location.href = `/api/scan/${currentScanId}/export?format=csv`;
  });
  els.exportJson.addEventListener('click', () => {
    if (currentScanId) window.location.href = `/api/scan/${currentScanId}/export?format=json`;
  });

  refreshStartEnabled();
})();
