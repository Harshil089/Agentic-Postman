(function initSecurityReportPage() {
  const STORAGE_KEYS = {
    workspace: 'agentman:workspace',
    securityReport: 'agentman:securityRunReport'
  };

  const state = {
    report: { runs: [], activeRunId: null },
    filters: { run: 'latest', vector: 'all', severity: 'all' },
    scoped: { runs: [], timeline: [], lineage: [], findings: [] }
  };

  function escHtml(value) {
    return String(value == null ? '' : value)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  function parseJsonSafe(raw) {
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  function normalizeReport(value) {
    const source = value && typeof value === 'object' ? value : {};
    const runs = Array.isArray(source.runs)
      ? source.runs
          .filter(run => run && typeof run === 'object')
          .map((run, index) => ({
            id: typeof run.id === 'string' && run.id.trim() ? run.id : `run_${Date.now()}_${index}`,
            startedAt: typeof run.startedAt === 'string' ? run.startedAt : new Date().toISOString(),
            endedAt: typeof run.endedAt === 'string' ? run.endedAt : null,
            status: typeof run.status === 'string' ? run.status : 'completed',
            mode: typeof run.mode === 'string' ? run.mode : 'agent',
            target: typeof run.target === 'string' ? run.target : '',
            instruction: typeof run.instruction === 'string' ? run.instruction : '',
            timeline: Array.isArray(run.timeline) ? run.timeline : [],
            findings: Array.isArray(run.findings) ? run.findings : [],
            lineage: Array.isArray(run.lineage) ? run.lineage : []
          }))
          .slice(-25)
      : [];
    const activeRunId = typeof source.activeRunId === 'string' ? source.activeRunId : null;
    return { runs, activeRunId };
  }

  function loadReport() {
    const direct = parseJsonSafe(localStorage.getItem(STORAGE_KEYS.securityReport) || '');
    const normalizedDirect = normalizeReport(direct);
    if (normalizedDirect.runs.length) return normalizedDirect;

    const workspace = parseJsonSafe(localStorage.getItem(STORAGE_KEYS.workspace) || '');
    return normalizeReport(workspace?.securityRunReport);
  }

  function getUrlFilters() {
    const params = new URLSearchParams(window.location.search || '');
    const run = params.get('run') || 'latest';
    const vector = params.get('vector') || 'all';
    const severity = params.get('severity') || 'all';
    return { run, vector, severity };
  }

  function setSelectValue(id, value, fallback = 'all') {
    const el = document.getElementById(id);
    if (!el) return;
    const exists = Array.from(el.options).some(option => option.value === value);
    el.value = exists ? value : fallback;
  }

  function readFiltersFromUi() {
    return {
      run: document.getElementById('report-run-filter')?.value || 'latest',
      vector: document.getElementById('report-vector-filter')?.value || 'all',
      severity: document.getElementById('report-severity-filter')?.value || 'all'
    };
  }

  function selectedRuns(filters) {
    const runs = state.report.runs;
    if (filters.run === 'all') return runs;
    if (filters.run === 'latest') return runs.length ? [runs[runs.length - 1]] : [];
    return runs.filter(run => run.id === filters.run);
  }

  function getVectorOptions(runs) {
    const values = new Set(['all']);
    runs.forEach(run => {
      (run.lineage || []).forEach(item => values.add(String(item.vector || 'Unknown')));
    });
    return Array.from(values);
  }

  function renderFilterOptions() {
    const runEl = document.getElementById('report-run-filter');
    const vectorEl = document.getElementById('report-vector-filter');
    const severityEl = document.getElementById('report-severity-filter');
    if (!runEl || !vectorEl || !severityEl) return;

    const allRuns = state.report.runs;
    const runOptions = ['<option value="latest">Latest run</option>', '<option value="all">All runs</option>'];
    allRuns.slice().reverse().forEach(run => {
      runOptions.push(`<option value="${escHtml(run.id)}">${escHtml(`${run.id} (${run.status})`)}</option>`);
    });
    runEl.innerHTML = runOptions.join('');
    setSelectValue('report-run-filter', state.filters.run, 'latest');

    const vectors = getVectorOptions(selectedRuns(state.filters));
    vectorEl.innerHTML = vectors
      .map(vector => `<option value="${escHtml(vector)}">${escHtml(vector === 'all' ? 'All vectors' : vector)}</option>`)
      .join('');
    setSelectValue('report-vector-filter', state.filters.vector, 'all');

    const allowedSeverities = new Set(['all', 'info', 'low', 'medium', 'high', 'critical']);
    if (!allowedSeverities.has(state.filters.severity)) state.filters.severity = 'all';
    setSelectValue('report-severity-filter', state.filters.severity, 'all');
  }

  function eventMatches(event, filters) {
    if (!event || typeof event !== 'object') return false;
    const details = event.details && typeof event.details === 'object' ? event.details : {};
    if (filters.vector !== 'all') {
      const vector = String(details.vector || '');
      if (vector && vector !== filters.vector) return false;
      if (!vector && event.type === 'probe') return false;
    }
    if (filters.severity !== 'all') {
      const severity = String(details.severity || '').toLowerCase();
      if (severity && severity !== filters.severity) return false;
      if (!severity && event.type === 'finding') return false;
    }
    return true;
  }

  function applyFilters() {
    const filters = state.filters;
    const runs = selectedRuns(filters);
    const lineage = [];
    const findings = [];
    const timeline = [];

    runs.forEach(run => {
      (run.lineage || []).forEach(item => {
        const vector = String(item.vector || 'Unknown');
        if (filters.vector !== 'all' && vector !== filters.vector) return;
        lineage.push(item);
      });

      (run.findings || []).forEach(item => {
        const severity = String(item.severity || 'info').toLowerCase();
        if (filters.severity !== 'all' && severity !== filters.severity) return;
        findings.push(item);
      });

      (run.timeline || []).forEach(item => {
        if (!eventMatches(item, filters)) return;
        timeline.push(item);
      });
    });

    state.scoped = { runs, timeline, lineage, findings };
  }

  function formatTime(iso) {
    if (!iso) return 'n/a';
    const dt = new Date(iso);
    if (Number.isNaN(dt.getTime())) return 'n/a';
    return dt.toLocaleString();
  }

  function summarizeEventDetails(details) {
    if (!details || typeof details !== 'object') return '';
    const keys = ['vector', 'tier', 'status', 'severity', 'id', 'vulnerability', 'message'];
    const known = keys
      .filter(key => details[key] !== undefined && details[key] !== null && details[key] !== '')
      .map(key => `${key}=${String(details[key])}`);
    if (known.length) return known.join(' | ');
    const compact = JSON.stringify(details);
    return compact.length > 220 ? `${compact.slice(0, 220)}...` : compact;
  }

  function renderKpis() {
    const kpisEl = document.getElementById('report-kpis');
    if (!kpisEl) return;
    const { runs, timeline, lineage, findings } = state.scoped;
    const criticalCount = findings.filter(item => String(item.severity || '').toLowerCase() === 'critical').length;
    const highCount = findings.filter(item => String(item.severity || '').toLowerCase() === 'high').length;
    const cards = [
      ['Runs', String(runs.length)],
      ['Timeline Events', String(timeline.length)],
      ['Probe Lineage', String(lineage.length)],
      ['Findings', String(findings.length)],
      ['Critical', String(criticalCount)],
      ['High', String(highCount)]
    ];
    kpisEl.innerHTML = cards
      .map(([label, value]) => `<div class="kpi-card"><span class="kpi-label">${escHtml(label)}</span><span class="kpi-value">${escHtml(value)}</span></div>`)
      .join('');
  }

  function renderTimeline() {
    const listEl = document.getElementById('timeline-list');
    if (!listEl) return;
    const items = state.scoped.timeline;
    if (!items.length) {
      listEl.innerHTML = '<div class="empty">No timeline events for selected filters.</div>';
      return;
    }
    listEl.innerHTML = items
      .slice()
      .reverse()
      .map(item => {
        const details = summarizeEventDetails(item.details);
        return [
          '<div class="list-item">',
          `<div><strong>${escHtml(String(item.type || 'event'))}</strong></div>`,
          `<div class="meta-line">${escHtml(formatTime(item.at))}</div>`,
          details ? `<div class="meta-line mono">${escHtml(details)}</div>` : '',
          '</div>'
        ].join('');
      })
      .join('');
  }

  function renderLineage() {
    const listEl = document.getElementById('lineage-list');
    if (!listEl) return;
    const items = state.scoped.lineage;
    if (!items.length) {
      listEl.innerHTML = '<div class="empty">No probe lineage items for selected filters.</div>';
      return;
    }
    listEl.innerHTML = items
      .slice()
      .reverse()
      .map(item => {
        const drift = item?.drift
          ? `drift=${item.drift.status_delta || 'n/a'} leaks+${(item.drift.newly_leaked || []).length}`
          : '';
        return [
          '<div class="list-item">',
          `<div><strong>${escHtml(String(item.method || 'GET'))}</strong> <span class="mono">${escHtml(String(item.url || ''))}</span></div>`,
          `<div class="meta-line">vector=${escHtml(String(item.vector || 'Unknown'))} | tier=${escHtml(String(item.tier || 'safe'))} | status=${escHtml(String(item.status || 0))}</div>`,
          `<div class="meta-line">${escHtml(formatTime(item.at))}</div>`,
          drift ? `<div class="meta-line mono">${escHtml(drift)}</div>` : '',
          '</div>'
        ].join('');
      })
      .join('');
  }

  function severityClass(severity) {
    const value = String(severity || 'info').toLowerCase();
    if (value === 'critical') return 'sev-critical';
    if (value === 'high') return 'sev-high';
    if (value === 'medium') return 'sev-medium';
    if (value === 'low') return 'sev-low';
    return 'sev-info';
  }

  function renderFindings() {
    const listEl = document.getElementById('findings-list');
    if (!listEl) return;
    const items = state.scoped.findings;
    if (!items.length) {
      listEl.innerHTML = '<div class="empty">No findings for selected filters.</div>';
      return;
    }
    listEl.innerHTML = items
      .slice()
      .reverse()
      .map(item => {
        const severity = String(item.severity || 'info').toLowerCase();
        const confidenceRaw = Number(item.confidence);
        const confidence = Number.isFinite(confidenceRaw) ? confidenceRaw.toFixed(2) : 'n/a';
        return [
          '<div class="list-item">',
          `<div><span class="sev-badge ${severityClass(severity)}">${escHtml(severity)}</span><strong>${escHtml(String(item.vulnerability || item.id || 'Finding'))}</strong></div>`,
          item.id ? `<div class="meta-line mono">id=${escHtml(String(item.id))}</div>` : '',
          `<div class="meta-line">confidence=${escHtml(confidence)}</div>`,
          item.evidence ? `<div class="meta-line">${escHtml(String(item.evidence))}</div>` : '',
          item.evidence_delta ? `<div class="meta-line mono">delta=${escHtml(String(item.evidence_delta))}</div>` : '',
          item.recommendation ? `<div class="meta-line">${escHtml(String(item.recommendation))}</div>` : '',
          '</div>'
        ].join('');
      })
      .join('');
  }

  function renderHeaderSummary() {
    const summaryEl = document.getElementById('report-header-summary');
    if (!summaryEl) return;
    const { runs, lineage, findings } = state.scoped;
    if (!runs.length) {
      summaryEl.textContent = 'No report runs found. Run a security scan first.';
      return;
    }
    const latest = runs[runs.length - 1];
    summaryEl.textContent = `Showing ${runs.length} run(s) | Latest: ${latest.id} (${latest.status}) | Probes: ${lineage.length} | Findings: ${findings.length}`;
  }

  function renderAll() {
    applyFilters();
    renderHeaderSummary();
    renderKpis();
    renderTimeline();
    renderLineage();
    renderFindings();
  }

  function createScopedExportPayload() {
    return {
      generated_at: new Date().toISOString(),
      filters: { ...state.filters },
      summary: {
        runs: state.scoped.runs.length,
        timeline: state.scoped.timeline.length,
        lineage: state.scoped.lineage.length,
        findings: state.scoped.findings.length
      },
      runs: state.scoped.runs.map(run => ({
        id: run.id,
        startedAt: run.startedAt,
        endedAt: run.endedAt,
        status: run.status,
        mode: run.mode,
        target: run.target,
        instruction: run.instruction
      })),
      timeline: state.scoped.timeline,
      lineage: state.scoped.lineage,
      findings: state.scoped.findings
    };
  }

  function buildMarkdown(payload) {
    const lines = [
      '# AgentMan Security Report',
      '',
      `- Generated: ${payload.generated_at}`,
      `- Filters: run=${payload.filters.run}, vector=${payload.filters.vector}, severity=${payload.filters.severity}`,
      `- Runs: ${payload.summary.runs}`,
      `- Timeline events: ${payload.summary.timeline}`,
      `- Probe lineage: ${payload.summary.lineage}`,
      `- Findings: ${payload.summary.findings}`,
      ''
    ];

    lines.push('## Runs');
    if (!payload.runs.length) lines.push('- none');
    payload.runs.forEach(run => {
      lines.push(`- ${run.id} status=${run.status} mode=${run.mode} target=${run.target || 'n/a'}`);
    });

    lines.push('', '## Timeline');
    if (!payload.timeline.length) lines.push('- none');
    payload.timeline.forEach(event => {
      lines.push(`- [${event.at}] ${event.type}: ${summarizeEventDetails(event.details) || 'n/a'}`);
    });

    lines.push('', '## Probe Lineage');
    if (!payload.lineage.length) lines.push('- none');
    payload.lineage.forEach(item => {
      lines.push(`- [${item.at}] ${item.method} ${item.url} vector=${item.vector} tier=${item.tier} status=${item.status}`);
    });

    lines.push('', '## Findings');
    if (!payload.findings.length) lines.push('- none');
    payload.findings.forEach(item => {
      lines.push(`- ${item.id || 'FINDING'} ${item.vulnerability || 'Unknown'} severity=${item.severity || 'info'} confidence=${item.confidence ?? 'n/a'}`);
      if (item.evidence) lines.push(`  evidence: ${item.evidence}`);
      if (item.evidence_delta) lines.push(`  evidence_delta: ${item.evidence_delta}`);
    });

    return lines.join('\n');
  }

  function download(name, data, type) {
    const blob = new Blob([data], { type });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = name;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  function syncUrlToFilters() {
    const params = new URLSearchParams({
      run: state.filters.run,
      vector: state.filters.vector,
      severity: state.filters.severity
    });
    const next = `${window.location.pathname}?${params.toString()}`;
    window.history.replaceState({}, '', next);
  }

  function applyFromUi() {
    state.filters = readFiltersFromUi();
    syncUrlToFilters();
    renderFilterOptions();
    renderAll();
  }

  function wireEvents() {
    document.getElementById('apply-filter-btn')?.addEventListener('click', applyFromUi);
    ['report-run-filter', 'report-vector-filter', 'report-severity-filter'].forEach(id => {
      document.getElementById(id)?.addEventListener('change', applyFromUi);
    });
    document.getElementById('back-btn')?.addEventListener('click', () => {
      window.location.href = '/agentman.html';
    });
    document.getElementById('export-json-btn')?.addEventListener('click', () => {
      const payload = createScopedExportPayload();
      const body = JSON.stringify(payload, null, 2);
      const runToken = state.filters.run === 'latest' ? 'latest' : state.filters.run || 'all';
      download(`security-report-${runToken}.json`, body, 'application/json');
    });
    document.getElementById('export-md-btn')?.addEventListener('click', () => {
      const payload = createScopedExportPayload();
      const body = buildMarkdown(payload);
      const runToken = state.filters.run === 'latest' ? 'latest' : state.filters.run || 'all';
      download(`security-report-${runToken}.md`, body, 'text/markdown');
    });
    document.getElementById('export-pdf-btn')?.addEventListener('click', () => {
      window.print();
    });
  }

  function init() {
    state.report = loadReport();
    state.filters = getUrlFilters();
    renderFilterOptions();
    renderAll();
    wireEvents();
  }

  init();
})();
