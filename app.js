const OPENROUTER_MODELS = {
  default: 'openrouter/auto',
  advanced: 'openai/gpt-4o-mini',
  security: 'openai/gpt-4o'
};
const GEMINI_MODELS = {
  default: 'gemini-1.5-flash',
  advanced: 'gemini-1.5-flash',
  security: 'gemini-1.5-flash'
};
const MODEL_PROVIDERS = {
  openrouter: 'openrouter',
  gemini: 'gemini'
};
const BACKEND_ENDPOINTS = {
  agent: '/api/agent',
  assertions: '/api/assertions',
  request: '/api/request',
  securityAgent: '/api/security-agent'
};

const AGENT_WELCOME_HTML = `
  <div class="msg agent">
    <div class="msg-role">Agent</div>
    <div class="msg-bubble">
      Hi! I can help you build API requests from plain English. Try something like:<br><br>
      <em style="color:var(--text2);">"GET all users from JSONPlaceholder"</em><br>
      <em style="color:var(--text2);">"POST a new todo with a random title"</em><br>
      <em style="color:var(--text2);">"Chain: get user 1, then fetch their posts"</em><br><br>
      I can also auto-debug errors and generate test assertions.
    </div>
  </div>
`;

let requests = [
  { id: 1, name: 'Get Users', method: 'GET', url: 'https://jsonplaceholder.typicode.com/users', params: [], headers: [], body: '', assertions: [], chainOf: null },
  { id: 2, name: 'Create Post', method: 'POST', url: 'https://jsonplaceholder.typicode.com/posts', params: [], headers: [{ k: 'Content-Type', v: 'application/json' }], body: '{\n  "title": "foo",\n  "body": "bar",\n  "userId": 1\n}', assertions: [], chainOf: null },
];
let activeId = 1;
let lastResponse = null;
let idCounter = 3;
let agentMode = 'agent';
let selectedModelProvider = MODEL_PROVIDERS.openrouter;
let chatSessionId = 1;
let chatGoal = '';
let conversationHistory = [];
let securityTestHistory = [];
let securityThreatLevel = 'none';
const scanProgressState = {
  active: false,
  status: 'idle',
  target: 'No active scan',
  total: 0,
  current: 0,
  passed: 0,
  failed: 0,
  skipped: 0,
  detail: '0/0 steps',
  lastFinishedAt: ''
};
const agentRunState = {
  isRunning: false,
  stopRequested: false,
  abortController: null
};

const SECURITY_THREAT_RANK = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

const AGENT_MODE_META = {
  agent: { label: 'Agent', button: 'Run Agent ↗', placeholder: 'Describe a request. Agent mode will apply and auto-run generated request actions.' },
  planning: { label: 'Planning', button: 'Plan ↗', placeholder: 'Describe your goal. Planning mode returns a plan and suggested actions without auto-running.' },
  ask: { label: 'Ask', button: 'Ask ↗', placeholder: 'Ask API questions. Ask mode focuses on explanation, guidance, and debugging insights.' }
};

function getActive() { return requests.find(r => r.id === activeId); }

function renderSidebar() {
  const list = document.getElementById('sidebar-list');
  list.innerHTML = requests.map(r => `
    <div class="req-item ${r.id === activeId ? 'active' : ''}" onclick="selectRequest(${r.id})">
      <span class="method-badge m-${r.method}">${r.method}</span>
      <span class="req-name">${r.name}</span>
      ${r.chainOf ? `<span class="req-chain">⛓</span>` : ''}
    </div>
  `).join('');
}

function selectRequest(id) {
  saveActive();
  activeId = id;
  loadActive();
  renderSidebar();
}

function saveActive() {
  const r = getActive();
  if (!r) return;
  r.url = document.getElementById('url-input').value;
  r.method = document.getElementById('method-select').value;
  r.body = document.getElementById('body-editor').value;
  r.params = readKVTable('params-body');
  r.headers = readKVTable('headers-body');
}

function loadActive() {
  const r = getActive();
  if (!r) return;
  document.getElementById('url-input').value = r.url;
  document.getElementById('method-select').value = r.method;
  document.getElementById('body-editor').value = r.body;
  populateKVTable('params-body', r.params);
  populateKVTable('headers-body', r.headers);
  renderAssertions(r.assertions);
  lastResponse = null;
  document.getElementById('response-body').innerHTML = `<div class="empty-state"><div class="empty-icon">◎</div><div>Send a request or ask the agent to generate one</div></div>`;
  document.getElementById('status-tag').textContent = '';
  document.getElementById('time-tag').textContent = '';
}

function readKVTable(tbodyId) {
  const rows = document.querySelectorAll(`#${tbodyId} tr`);
  const result = [];
  rows.forEach(row => {
    const inputs = row.querySelectorAll('input');
    if (inputs[0] && inputs[0].value) result.push({ k: inputs[0].value, v: inputs[1]?.value || '' });
  });
  return result;
}

function populateKVTable(tbodyId, data) {
  const tbody = document.getElementById(tbodyId);
  tbody.innerHTML = '';
  (data || []).forEach(({ k, v }) => addKVRow(tbodyId, k, v));
  if (!data || data.length === 0) addKVRow(tbodyId);
}

function addKVRow(tbodyId, k = '', v = '') {
  const tbody = document.getElementById(tbodyId);
  const tr = document.createElement('tr');
  tr.innerHTML = `
    <td><input class="kv-input" placeholder="key" value="${escHtml(k)}" /></td>
    <td><input class="kv-input" placeholder="value" value="${escHtml(v)}" /></td>
  `;
  tbody.appendChild(tr);
}

function escHtml(s) { return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function normalizeConversationText(text) {
  return String(text || '')
    .replace(/<[^>]*>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function recordConversationTurn(role, text) {
  const normalized = normalizeConversationText(text);
  if (!normalized) return;
  conversationHistory.push({ role, text: normalized });
  if (conversationHistory.length > 40) {
    conversationHistory = conversationHistory.slice(-40);
  }
}

function renderAgentMode() {
  const switchEl = document.getElementById('agent-mode-switch');
  const sendBtn = document.getElementById('agent-send-btn');
  const inputEl = document.getElementById('agent-input');
  if (!switchEl || !sendBtn || !inputEl) return;

  switchEl.querySelectorAll('.mode-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.mode === agentMode);
  });

  const meta = AGENT_MODE_META[agentMode] || AGENT_MODE_META.agent;
  sendBtn.textContent = agentRunState.isRunning ? 'Running…' : meta.button;
  inputEl.placeholder = meta.placeholder;
  syncAgentRunControls();
}

function renderModelProvider() {
  const switchEl = document.getElementById('provider-switch');
  if (!switchEl) return;
  switchEl.querySelectorAll('.provider-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.provider === selectedModelProvider);
  });
}

function setModelProvider(provider) {
  if (!Object.values(MODEL_PROVIDERS).includes(provider)) return;
  if (agentRunState.isRunning) {
    addAgentMsg('system', 'Stop the current run before switching model provider.');
    return;
  }
  selectedModelProvider = provider;
  renderModelProvider();
  const label = provider === MODEL_PROVIDERS.gemini ? 'Gemini' : 'OpenRouter';
  addAgentMsg('system', `Model provider switched to ${label}.`);
}

function setAgentMode(mode) {
  if (!AGENT_MODE_META[mode]) return;
  if (agentRunState.isRunning) {
    addAgentMsg('system', 'Stop the current run before switching modes.');
    return;
  }
  agentMode = mode;
  renderAgentMode();
  addAgentMsg('system', `Mode switched to ${AGENT_MODE_META[mode].label}.`);
}

function syncAgentRunControls() {
  const sendBtn = document.getElementById('agent-send-btn');
  const stopBtn = document.getElementById('agent-stop-btn');
  if (!sendBtn || !stopBtn) return;
  sendBtn.disabled = agentRunState.isRunning;
  stopBtn.disabled = !agentRunState.isRunning;
  stopBtn.textContent = agentRunState.stopRequested ? 'Stopping…' : 'Stop';
}

function requestStopAgentRun() {
  if (!agentRunState.isRunning) return;
  agentRunState.stopRequested = true;
  if (agentRunState.abortController) {
    try { agentRunState.abortController.abort(); } catch {}
  }
  syncAgentRunControls();
  addAgentMsg('system', 'Stop requested. Finishing current step and halting autonomous run.');
}

function renderWelcomeMessage() {
  const el = document.getElementById('agent-messages');
  if (!el) return;
  el.innerHTML = AGENT_WELCOME_HTML;
  el.scrollTop = el.scrollHeight;
}

function startNewChat() {
  if (agentRunState.isRunning) {
    requestStopAgentRun();
  }
  chatSessionId += 1;
  chatGoal = '';
  conversationHistory = [];
  securityTestHistory = [];
  securityThreatLevel = 'none';
  resetScanProgress('No active scan');
  renderWelcomeMessage();
  addAgentMsg('system', `Started new chat context (session ${chatSessionId}).`);
}

function normalizeScanStatusLabel(status) {
  const map = {
    idle: 'IDLE',
    running: 'RUNNING',
    completed: 'COMPLETED',
    failed: 'FAILED',
    stopped: 'STOPPED'
  };
  return map[status] || 'IDLE';
}

function renderScanProgress() {
  const panel = document.getElementById('scan-progress-panel');
  const statusEl = document.getElementById('scan-progress-status');
  const targetEl = document.getElementById('scan-progress-target');
  const barEl = document.getElementById('scan-progress-bar');
  const metaEl = document.getElementById('scan-progress-meta');
  const passEl = document.getElementById('scan-badge-pass');
  const failEl = document.getElementById('scan-badge-fail');
  const skipEl = document.getElementById('scan-badge-skip');
  const finishedEl = document.getElementById('scan-progress-finished');
  if (!panel || !statusEl || !targetEl || !barEl || !metaEl || !passEl || !failEl || !skipEl || !finishedEl) return;

  panel.style.display = scanProgressState.active || scanProgressState.status !== 'idle' ? 'flex' : 'none';
  statusEl.textContent = normalizeScanStatusLabel(scanProgressState.status);
  targetEl.textContent = scanProgressState.target;

  const total = Number(scanProgressState.total || 0);
  const current = Number(scanProgressState.current || 0);
  const pct = total > 0 ? Math.min(100, Math.max(0, (current / total) * 100)) : 0;
  barEl.style.width = `${pct}%`;

  metaEl.textContent = scanProgressState.detail || `${current}/${total} steps`;
  passEl.textContent = `Pass ${scanProgressState.passed}`;
  failEl.textContent = `Fail ${scanProgressState.failed}`;
  skipEl.textContent = `Skip ${scanProgressState.skipped}`;
  finishedEl.textContent = scanProgressState.lastFinishedAt
    ? `Last finished: ${scanProgressState.lastFinishedAt}`
    : 'Last finished: —';
}

function resetScanProgress(targetText = 'No active scan') {
  scanProgressState.active = false;
  scanProgressState.status = 'idle';
  scanProgressState.target = targetText;
  scanProgressState.total = 0;
  scanProgressState.current = 0;
  scanProgressState.passed = 0;
  scanProgressState.failed = 0;
  scanProgressState.skipped = 0;
  scanProgressState.detail = '0/0 steps';
  scanProgressState.lastFinishedAt = '';
  renderScanProgress();
}

function startScanProgress(totalSteps, target) {
  scanProgressState.active = true;
  scanProgressState.status = 'running';
  scanProgressState.target = target || 'Current endpoint';
  scanProgressState.total = Number(totalSteps || 0);
  scanProgressState.current = 0;
  scanProgressState.passed = 0;
  scanProgressState.failed = 0;
  scanProgressState.skipped = 0;
  scanProgressState.detail = `0/${scanProgressState.total} steps`;
  renderScanProgress();
}

function updateScanProgressStep(index, total, vector) {
  const current = Number(index || 0);
  const max = Number(total || scanProgressState.total || 0);
  scanProgressState.current = current;
  scanProgressState.total = max;
  scanProgressState.detail = `${current}/${max} · ${vector || 'Unknown vector'}`;
  renderScanProgress();
}

function finalizeScanProgress(status, detail) {
  scanProgressState.active = false;
  scanProgressState.status = status || 'completed';
  if (typeof detail === 'string' && detail.trim()) {
    scanProgressState.detail = detail;
  }
  scanProgressState.lastFinishedAt = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  renderScanProgress();
}

// TABS
document.querySelectorAll('.tab').forEach(t => {
  t.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(x => x.classList.remove('visible'));
    t.classList.add('active');
    document.getElementById('tab-' + t.dataset.tab).classList.add('visible');
  });
});

// SEND
document.getElementById('send-btn').addEventListener('click', sendRequest);

async function sendRequest() {
  saveActive();
  const r = getActive();
  const btn = document.getElementById('send-btn');
  btn.disabled = true; btn.textContent = 'Sending…';

  let url = r.url.trim();
  const params = r.params.filter(p => p.k);
  if (params.length) {
    const qs = params.map(p => `${encodeURIComponent(p.k)}=${encodeURIComponent(p.v)}`).join('&');
    url += (url.includes('?') ? '&' : '?') + qs;
  }

  const fetchOpts = { method: r.method, headers: {} };
  (r.headers || []).filter(h => h.k).forEach(h => { fetchOpts.headers[h.k] = h.v; });
  if (r.body && ['POST','PUT','PATCH'].includes(r.method)) {
    fetchOpts.body = r.body;
    if (!fetchOpts.headers['Content-Type']) fetchOpts.headers['Content-Type'] = 'application/json';
  }

  try {
    const data = await callBackendJson(BACKEND_ENDPOINTS.request, {
      method: r.method,
      url,
      headers: fetchOpts.headers,
      body: fetchOpts.body || ''
    });

    const elapsed = Number(data.elapsed_ms || 0);
    const text = typeof data.body === 'string' ? data.body : '';
    let formatted = text;
    try { formatted = JSON.stringify(JSON.parse(text), null, 2); } catch {}
    lastResponse = { status: data.status, text: formatted, elapsed, headers: data.headers || {}, url };

    const stEl = document.getElementById('status-tag');
    stEl.textContent = `${data.status} ${data.statusText || ''}`.trim();
    stEl.className = 'status-tag ' + (data.status < 300 ? 's-2xx' : data.status < 500 ? 's-4xx' : 's-5xx');
    document.getElementById('time-tag').textContent = `${elapsed}ms`;
    document.getElementById('response-body').textContent = formatted;

    runAssertions(r.assertions, lastResponse);
    if (r.assertions.length === 0) autoSuggestAssertions();
    return lastResponse;
  } catch (e) {
    lastResponse = { error: e.message };
    document.getElementById('response-body').innerHTML = `<span style="color:var(--red);">Error: ${e.message}</span>`;
    document.getElementById('status-tag').textContent = 'FAILED';
    document.getElementById('status-tag').className = 'status-tag s-4xx';
    addAgentMsg('system', `Request failed: ${e.message}. Ask me to debug this error.`);
    return null;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Send';
  }
}

function isSecurityInstruction(text) {
  const msg = (text || '').toLowerCase();
  return [
    'security', 'pentest', 'penetration', 'idor', 'sqli', 'nosqli', 'ssrf',
    'xxe', 'bola', 'mass assignment', 'scan', 'audit', 'test all',
    'full check', 'auth bypass', 'path traversal', 'fuzz'
  ].some(token => msg.includes(token));
}

function getBaseTargetUrl(urlText) {
  try {
    const parsed = new URL(urlText || '');
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return '';
  }
}

function parseJsonSafely(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function deriveAuthContext(headers) {
  const list = Array.isArray(headers) ? headers : [];
  const map = new Map();
  list.forEach(h => {
    if (!h || typeof h.k !== 'string') return;
    map.set(h.k.toLowerCase(), typeof h.v === 'string' ? h.v : '');
  });

  const auth = map.get('authorization') || '';
  if (auth.toLowerCase().startsWith('bearer ')) {
    return { type: 'bearer', value: auth.slice(7).trim() };
  }
  if (auth.toLowerCase().startsWith('basic ')) {
    return { type: 'basic', value: auth.slice(6).trim() };
  }
  if (map.has('x-api-key')) {
    return { type: 'apikey', value: map.get('x-api-key') || '' };
  }
  if (map.has('api-key')) {
    return { type: 'apikey', value: map.get('api-key') || '' };
  }
  return { type: 'none', value: '' };
}

function buildSecurityContext(req, resp, userMsg) {
  return {
    target_url: getBaseTargetUrl(req.url),
    current_request: {
      method: req.method,
      url: req.url,
      headers: req.headers,
      params: req.params,
      body: req.body
    },
    last_response: resp && typeof resp.status === 'number'
      ? {
          status: resp.status,
          elapsed_ms: Number(resp.elapsed || 0),
          body_preview: (resp.text || '').substring(0, 1200)
        }
      : null,
    auth_context: deriveAuthContext(req.headers),
    test_history: securityTestHistory,
    user_instruction: userMsg
  };
}

function updateThreatLevel(level) {
  const normalized = typeof level === 'string' ? level.toLowerCase() : 'none';
  if (!(normalized in SECURITY_THREAT_RANK)) return;
  if (SECURITY_THREAT_RANK[normalized] > SECURITY_THREAT_RANK[securityThreatLevel]) {
    securityThreatLevel = normalized;
  }
}

function parseSecurityPayload(raw) {
  const parsed = raw && typeof raw === 'object' ? raw : parseJsonSafely(String(raw || ''));
  if (!parsed || typeof parsed !== 'object') throw new Error('Security agent returned invalid JSON payload.');
  if (typeof parsed.message !== 'string') throw new Error('Security agent response is missing message.');
  if (!Array.isArray(parsed.actions)) throw new Error('Security agent response is missing actions array.');
  if (!Array.isArray(parsed.findings)) throw new Error('Security agent response is missing findings array.');
  if (typeof parsed.threat_level !== 'string') throw new Error('Security agent response is missing threat_level.');
  return parsed;
}

function normalizeSecurityAction(action) {
  if (!action || typeof action !== 'object' || typeof action.type !== 'string') return null;
  const allowedMethods = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);

  if (action.type === 'probe') {
    const method = String(action.method || '').toUpperCase();
    if (!allowedMethods.has(method) || typeof action.url !== 'string' || !action.url.trim()) return null;
    return {
      type: 'probe',
      name: typeof action.name === 'string' ? action.name : 'Security probe',
      method,
      url: action.url,
      headers: normalizeKVList(action.headers),
      params: normalizeKVList(action.params),
      body: typeof action.body === 'string' ? action.body : '',
      vector: typeof action.vector === 'string' ? action.vector : 'Unknown',
      hypothesis: typeof action.hypothesis === 'string' ? action.hypothesis : '',
      auto_chain: Boolean(action.auto_chain)
    };
  }

  if (action.type === 'probe_chain') {
    if (!Array.isArray(action.steps) || !action.steps.length) return null;
    const steps = action.steps
      .map(step => {
        const method = String(step?.method || '').toUpperCase();
        if (!allowedMethods.has(method)) return null;
        if (typeof step?.url !== 'string' || !step.url.trim()) return null;
        return {
          step: Number(step.step || 0),
          name: typeof step.name === 'string' ? step.name : `Step ${step.step || ''}`,
          method,
          url: step.url,
          headers: normalizeKVList(step.headers),
          body: typeof step.body === 'string' ? step.body : '',
          vector: typeof step.vector === 'string' ? step.vector : 'Unknown',
          hypothesis: typeof step.hypothesis === 'string' ? step.hypothesis : '',
          extract: step.extract && typeof step.extract === 'object' ? step.extract : null
        };
      })
      .filter(Boolean);
    if (!steps.length) return null;
    return {
      type: 'probe_chain',
      name: typeof action.name === 'string' ? action.name : 'Security probe chain',
      steps
    };
  }

  if (action.type === 'fuzz_list') {
    const payloads = Array.isArray(action.payloads)
      ? action.payloads.filter(x => typeof x === 'string' && x.trim())
      : [];
    if (!payloads.length) return null;
    return {
      type: 'fuzz_list',
      vector: typeof action.vector === 'string' ? action.vector : 'Unknown',
      target_param: typeof action.target_param === 'string' ? action.target_param : '',
      target_location: typeof action.target_location === 'string' ? action.target_location : 'query',
      payloads,
      success_indicators: action.success_indicators && typeof action.success_indicators === 'object'
        ? action.success_indicators
        : {}
    };
  }

  if (action.type === 'scan_plan') {
    return {
      type: 'scan_plan',
      target: typeof action.target === 'string' ? action.target : '',
      method_coverage: Array.isArray(action.method_coverage) ? action.method_coverage : [],
      steps: Array.isArray(action.steps) ? action.steps : []
    };
  }

  if (action.type === 'set_assertions') {
    const assertions = Array.isArray(action.assertions)
      ? action.assertions.filter(x => typeof x === 'string' && x.trim())
      : [];
    if (!assertions.length) return null;
    return { type: 'set_assertions', assertions };
  }

  if (action.type === 'debug_info') {
    return validateAndNormalizeAction(action);
  }

  return null;
}

function renderSecurityFindings(findings, threatLevel) {
  const list = Array.isArray(findings) ? findings.filter(Boolean) : [];
  if (!list.length) {
    addAgentMsg('system', `Security threat level: ${String(threatLevel || 'none').toUpperCase()}. No confirmed findings yet.`);
    return;
  }

  const lines = list.map(item => {
    const id = escHtml(item.id || 'FINDING');
    const name = escHtml(item.vulnerability || 'Unknown');
    const sev = escHtml(item.severity || 'info');
    const evidence = escHtml(item.evidence || 'No evidence supplied');
    const remediation = escHtml(item.remediation || 'No remediation supplied');
    return `<strong>${id} · ${name} (${sev})</strong><br>Evidence: ${evidence}<br>Fix: ${remediation}`;
  });

  addAgentMsg('agent', `<strong>Threat level:</strong> ${escHtml(String(threatLevel || 'none').toUpperCase())}<br><br>${lines.join('<br><br>')}`);
}

function renderScanPlan(action) {
  const methodCoverage = Array.isArray(action.method_coverage) ? action.method_coverage.join(', ') : '';
  const steps = Array.isArray(action.steps)
    ? action.steps.map(step => {
        const order = Number(step?.order || 0);
        const vector = escHtml(step?.vector || 'Unknown');
        const description = escHtml(step?.description || '');
        return `${order > 0 ? `${order}. ` : ''}<strong>${vector}</strong> - ${description}`;
      }).join('<br>')
    : '';

  addAgentMsg('agent', `<strong>Security scan plan</strong><br>Target: ${escHtml(action.target || 'current endpoint')}<br>Methods: ${escHtml(methodCoverage || 'n/a')}<br><br>${steps || 'No steps provided.'}`);
}

function renderFuzzList(action) {
  const indicator = escHtml(JSON.stringify(action.success_indicators || {}));
  const payloads = action.payloads.map(payload => `• ${escHtml(payload)}`).join('<br>');
  addAgentMsg('agent', `<strong>Fuzz list (${escHtml(action.vector)})</strong><br>Target: ${escHtml(action.target_location)}.${escHtml(action.target_param)}<br><br>${payloads}<br><br><strong>Success indicators:</strong> ${indicator}`);
}

function appendSecurityHistory(entry) {
  if (!entry || typeof entry !== 'object') return;
  securityTestHistory.push(entry);
  if (securityTestHistory.length > 80) {
    securityTestHistory = securityTestHistory.slice(-80);
  }
}

function applyProbeAction(action, options = {}) {
  const { skipMessage = false } = options;
  applySetRequest({
    type: 'set_request',
    name: action.name || `Probe ${action.vector}`,
    method: action.method,
    url: action.url,
    headers: action.headers || [],
    params: action.params || [],
    body: action.body || ''
  }, { skipMessage: true });

  if (!skipMessage) {
    addAgentMsg('system', `Applied security probe (${action.vector}): ${action.method} ${action.url}`);
  }
}

function replaceExtractTokens(text, extractValues) {
  if (typeof text !== 'string' || !text.includes('{{extract.')) return text;
  return text.replace(/\{\{extract\.([^}]+)\}\}/g, (_, key) => {
    return Object.prototype.hasOwnProperty.call(extractValues, key) ? String(extractValues[key]) : '';
  });
}

function readJsonPath(json, path) {
  if (!json || typeof path !== 'string' || !path.startsWith('json.')) return undefined;
  const expr = path.slice(5);
  const tokens = [];
  const regex = /([^[.\]]+)|\[(\d+)\]/g;
  let match;
  while ((match = regex.exec(expr)) !== null) {
    tokens.push(match[1] !== undefined ? match[1] : Number(match[2]));
  }
  return tokens.reduce((acc, token) => (acc == null ? undefined : acc[token]), json);
}

function canAutoRunProbe(action) {
  return action.method === 'GET';
}

function requiresMutationConfirmation(method) {
  return String(method || '').toUpperCase() !== 'GET';
}

async function executeSecurityProbe(action, options = {}) {
  const {
    forceConfirmNonGet = true,
    skipApplyMessage = true,
    sourceLabel = 'security'
  } = options;

  if (forceConfirmNonGet && requiresMutationConfirmation(action.method)) {
    const proceed = window.confirm(
      `This probe uses ${action.method} and may modify remote state.\n\nVector: ${action.vector || 'Unknown'}\nURL: ${action.url}\n\nContinue?`
    );
    if (!proceed) {
      appendSecurityHistory({
        method: action.method,
        url: action.url,
        status: 0,
        finding: `${action.vector || 'Probe'} skipped by user (${sourceLabel})`
      });
      addAgentMsg('system', `Skipped ${action.method} probe for ${action.vector || 'Unknown'} after confirmation prompt.`);
      return { executed: false, skipped: true, response: null };
    }
  }

  applyProbeAction(action, { skipMessage: skipApplyMessage });
  const response = await sendRequest();
  appendSecurityHistory({
    method: action.method,
    url: action.url,
    status: response?.status || 0,
    finding: action.vector || 'Probe'
  });
  return { executed: Boolean(response), skipped: false, response };
}

async function executeProbeChain(action, options = {}) {
  const { forceConfirmNonGet = true, sourceLabel = 'probe_chain' } = options;
  const extractValues = {};
  addAgentMsg('system', `Executing security probe chain: ${action.name}`);

  for (const step of action.steps) {
    if (agentRunState.stopRequested) {
      addAgentMsg('system', 'Probe chain execution stopped by user.');
      return false;
    }

    const resolvedUrl = replaceExtractTokens(step.url, extractValues);
    const resolvedHeaders = (step.headers || []).map(h => ({
      k: h.k,
      v: replaceExtractTokens(h.v, extractValues)
    }));
    const resolvedBody = replaceExtractTokens(step.body || '', extractValues);

    addAgentMsg('system', `Running chain step ${step.step || '?'}: ${step.name}`);
    const result = await executeSecurityProbe({
      ...step,
      url: resolvedUrl,
      headers: resolvedHeaders,
      body: resolvedBody,
      params: []
    }, {
      forceConfirmNonGet,
      skipApplyMessage: true,
      sourceLabel
    });

    if (result.skipped) {
      addAgentMsg('system', `Stopped chain because step ${step.step || '?'} was skipped.`);
      return false;
    }

    const response = result.response;
    if (!response) {
      return false;
    }

    if (step.extract && typeof step.extract === 'object') {
      const json = parseJsonSafely(response.text);
      Object.entries(step.extract).forEach(([key, expr]) => {
        const value = readJsonPath(json, String(expr));
        if (value !== undefined) {
          extractValues[key] = value;
        }
      });
    }
  }

  addAgentMsg('system', `Completed security probe chain: ${action.name}`);
  return true;
}

async function generateProbeForScanStep(scanPlan, planStep) {
  const r = getActive();
  const stepInstruction = [
    `Generate exactly one probe for scan plan step ${planStep.order || '?'} on target ${scanPlan.target || r.url}.`,
    `Vector: ${planStep.vector || 'Unknown'}.`,
    `Step description: ${planStep.description || 'n/a'}.`,
    'Return one action only, prioritizing type "probe". If not possible, return one "probe_chain".'
  ].join(' ');

  const context = buildSecurityContext(r, lastResponse, stepInstruction);
  const raw = await callSecurityAgent(
    context.target_url,
    context.current_request,
    context.last_response,
    context.auth_context,
    context.test_history,
    context.user_instruction
  );

  const parsed = parseSecurityPayload(raw);
  updateThreatLevel(parsed.threat_level);
  renderSecurityFindings(parsed.findings, securityThreatLevel);

  const actions = (parsed.actions || []).map(normalizeSecurityAction).filter(Boolean);
  const probe = actions.find(action => action.type === 'probe');
  if (probe) return { probe, chain: null, message: parsed.message, assertions: actions.filter(a => a.type === 'set_assertions') };
  const chain = actions.find(action => action.type === 'probe_chain');
  return { probe: null, chain, message: parsed.message, assertions: actions.filter(a => a.type === 'set_assertions') };
}

async function executeScanPlan(scanPlan) {
  if (scanProgressState.active) {
    addAgentMsg('system', 'A scan plan is already running. Stop it or wait for completion before starting another.');
    return false;
  }

  const steps = Array.isArray(scanPlan.steps)
    ? [...scanPlan.steps].sort((a, b) => Number(a?.order || 0) - Number(b?.order || 0))
    : [];
  if (!steps.length) {
    addAgentMsg('system', 'Scan plan has no executable steps.');
    return false;
  }

  startScanProgress(steps.length, scanPlan.target || 'Current endpoint');
  addAgentMsg('system', `Running scan plan with ${steps.length} step(s).`);

  for (let i = 0; i < steps.length; i += 1) {
    const planStep = steps[i];
    if (agentRunState.stopRequested) {
      addAgentMsg('system', 'Scan plan execution stopped by user.');
      finalizeScanProgress('stopped', `Stopped at step ${i + 1}/${steps.length}`);
      return false;
    }

    updateScanProgressStep(i + 1, steps.length, planStep.vector || 'Unknown');
    addAgentMsg('system', `Preparing step ${planStep.order || '?'} (${planStep.vector || 'Unknown'}).`);

    let generated;
    try {
      generated = await generateProbeForScanStep(scanPlan, planStep);
    } catch (error) {
      addAgentMsg('error', `Failed to generate probe for step ${planStep.order || '?'}: ${error.message}`);
      scanProgressState.failed += 1;
      finalizeScanProgress('failed', `Generation failed at step ${i + 1}/${steps.length}`);
      return false;
    }

    if (generated.message) {
      addAgentMsg('agent', escHtml(generated.message));
    }

    if (generated.assertions.length) {
      applyAssertions(generated.assertions[0].assertions, { skipMessage: true });
    }

    if (generated.probe) {
      const result = await executeSecurityProbe(generated.probe, {
        forceConfirmNonGet: true,
        skipApplyMessage: true,
        sourceLabel: `scan_plan_step_${planStep.order || 'x'}`
      });
      if (result.skipped) {
        scanProgressState.skipped += 1;
        finalizeScanProgress('stopped', `Skipped at step ${i + 1}/${steps.length}`);
        return false;
      }
      if (!result.executed) {
        addAgentMsg('system', `Step ${planStep.order || '?'} did not execute successfully.`);
        scanProgressState.failed += 1;
        finalizeScanProgress('failed', `Execution failed at step ${i + 1}/${steps.length}`);
        return false;
      }

      if (result.response && Number(result.response.status) < 400) {
        scanProgressState.passed += 1;
      } else {
        scanProgressState.failed += 1;
      }
      renderScanProgress();
      continue;
    }

    if (generated.chain) {
      const ok = await executeProbeChain(generated.chain, {
        forceConfirmNonGet: true,
        sourceLabel: `scan_plan_step_${planStep.order || 'x'}_chain`
      });
      if (!ok) {
        scanProgressState.failed += 1;
        finalizeScanProgress('failed', `Chain failed at step ${i + 1}/${steps.length}`);
        return false;
      }
      scanProgressState.passed += 1;
      renderScanProgress();
      continue;
    }

    addAgentMsg('system', `No executable probe returned for step ${planStep.order || '?'}.`);
    scanProgressState.failed += 1;
    finalizeScanProgress('failed', `No probe returned at step ${i + 1}/${steps.length}`);
    return false;
  }

  finalizeScanProgress('completed', `${steps.length}/${steps.length} steps completed`);
  addAgentMsg('system', 'Scan plan execution completed.');
  return true;
}

// ASSERTIONS
function renderAssertions(list) {
  const el = document.getElementById('assertions-list');
  const count = document.getElementById('assertion-count');
  count.textContent = (list || []).length;
  if (!list || list.length === 0) { el.innerHTML = `<div style="color:var(--text3);font-size:12px;padding:8px;">No assertions yet. Ask the agent to generate them after sending.</div>`; return; }
  el.innerHTML = list.map((a, i) => `
    <div class="assertion-item">
      <div class="assertion-status ${a.status === 'pass' ? 'a-pass' : a.status === 'fail' ? 'a-fail' : 'a-pending'}"></div>
      <span class="assertion-text">${escHtml(a.expr)}</span>
      <span class="assertion-result ${a.status === 'pass' ? 'a-pass-text' : a.status === 'fail' ? 'a-fail-text' : ''}">${a.status === 'pass' ? '✓' : a.status === 'fail' ? `✗ ${escHtml(a.error||'')}` : '—'}</span>
      <button class="icon-btn" style="margin-left:4px;" onclick="removeAssertion(${i})">×</button>
    </div>
  `).join('');
}

function runAssertions(assertions, resp) {
  if (!assertions || !assertions.length) return;
  let parsed;
  try { parsed = JSON.parse(resp.text); } catch {}

  assertions.forEach(a => {
    try {
      const fn = new Function('status', 'body', 'json', `return (${a.expr})`);
      const result = fn(resp.status, resp.text, parsed);
      a.status = result ? 'pass' : 'fail';
      if (!result) a.error = 'returned false';
    } catch(e) { a.status = 'fail'; a.error = e.message; }
  });
  renderAssertions(assertions);
  switchTab('assertions');
}

function removeAssertion(i) {
  const r = getActive(); r.assertions.splice(i, 1); renderAssertions(r.assertions);
}

function addManualAssertion() {
  const expr = prompt('Assertion expression (JS):\nVariables: status, json, body\n\nExample: status === 200');
  if (!expr) return;
  const r = getActive(); r.assertions.push({ expr, status: 'pending' }); renderAssertions(r.assertions);
}

function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => { t.classList.toggle('active', t.dataset.tab === name); });
  document.querySelectorAll('.tab-content').forEach(c => { c.classList.toggle('visible', c.id === 'tab-' + name); });
}

async function autoSuggestAssertions() {
  if (!lastResponse) return;
  const preview = lastResponse.text?.substring(0, 600);
  try {
    const parsed = await callBackendJson(BACKEND_ENDPOINTS.assertions, {
      status: lastResponse.status,
      body_preview: preview,
      provider: selectedModelProvider,
      model: selectedModelProvider === MODEL_PROVIDERS.gemini ? GEMINI_MODELS.default : OPENROUTER_MODELS.default
    });
    const arr = Array.isArray(parsed?.assertions) ? parsed.assertions : [];
    if (!arr.length) return;
    const r = getActive();
    r.assertions = arr.map(expr => ({ expr, status: 'pending' }));
    renderAssertions(r.assertions);
    addAgentMsg('system', `Generated ${arr.length} assertions. Run the request again to execute them, or switch to the Assertions tab.`);
  } catch {}
}

function buildUserContext(req, resp, userMsg) {
  return JSON.stringify({
    current_mode: agentMode,
    chat_session_id: chatSessionId,
    chat_goal: chatGoal,
    conversation_history: conversationHistory,
    current_request: {
      method: req.method,
      url: req.url,
      headers: req.headers,
      params: req.params,
      body: req.body
    },
    last_response: resp ? {
      status: resp.status,
      elapsed_ms: resp.elapsed,
      body_preview: (resp.text || '').substring(0, 800)
    } : null,
    current_assertions: (req.assertions || []).map(a => a.expr),
    user_message: userMsg
  });
}

function pickAgentModel(userMsg) {
  if (selectedModelProvider === MODEL_PROVIDERS.gemini) {
    return GEMINI_MODELS.default;
  }
  const msg = (userMsg || '').toLowerCase();
  if (msg.includes('complex debug') || (msg.includes('debug') && msg.includes('chain'))) {
    return OPENROUTER_MODELS.advanced;
  }
  return OPENROUTER_MODELS.default;
}

function parseAgentPayload(raw) {
  let parsed;
  if (raw && typeof raw === 'object') {
    parsed = raw;
  } else {
    try {
      parsed = JSON.parse((raw || '').trim());
    } catch {
      throw new Error('Agent returned invalid JSON.');
    }
  }
  if (!parsed || typeof parsed !== 'object') throw new Error('Agent response must be a JSON object.');
  if (typeof parsed.message !== 'string') throw new Error('Agent response is missing message.');
  if (!Array.isArray(parsed.actions)) throw new Error('Agent response is missing actions array.');
  return parsed;
}

function normalizeKVList(value) {
  if (!Array.isArray(value)) return [];
  return value
    .filter(item => item && typeof item.k === 'string')
    .map(item => ({ k: item.k, v: typeof item.v === 'string' ? item.v : '' }));
}

function validateAndNormalizeAction(action) {
  if (!action || typeof action !== 'object' || typeof action.type !== 'string') return null;
  const allowedMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

  if (action.type === 'set_request') {
    if (!allowedMethods.includes(action.method) || typeof action.url !== 'string' || !action.url.trim()) return null;
    return {
      type: 'set_request',
      name: typeof action.name === 'string' ? action.name : 'Generated Request',
      method: action.method,
      url: action.url,
      params: normalizeKVList(action.params),
      headers: normalizeKVList(action.headers),
      body: typeof action.body === 'string' ? action.body : ''
    };
  }

  if (action.type === 'set_assertions') {
    if (!Array.isArray(action.assertions)) return null;
    const assertions = action.assertions.filter(x => typeof x === 'string' && x.trim());
    if (!assertions.length) return null;
    return { type: 'set_assertions', assertions };
  }

  if (action.type === 'chain_request') {
    if (!allowedMethods.includes(action.method) || typeof action.url !== 'string' || !action.url.trim()) return null;
    if (typeof action.name !== 'string' || !action.name.trim()) return null;
    return {
      type: 'chain_request',
      name: action.name,
      method: action.method,
      url: action.url,
      params: normalizeKVList(action.params),
      headers: normalizeKVList(action.headers),
      body: typeof action.body === 'string' ? action.body : '',
      chainNote: typeof action.chainNote === 'string' ? action.chainNote : ''
    };
  }

  if (action.type === 'debug_info') {
    const findings = Array.isArray(action.findings)
      ? action.findings.filter(x => typeof x === 'string' && x.trim())
      : [];
    if (!findings.length) return null;
    const normalized = {
      type: 'debug_info',
      findings,
      fix: typeof action.fix === 'string' ? action.fix : ''
    };
    if (action.patch && typeof action.patch === 'object') normalized.patch = action.patch;
    return normalized;
  }

  return null;
}

// AGENT
document.getElementById('agent-send-btn').addEventListener('click', askAgent);
document.getElementById('agent-input').addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); askAgent(); }
});

function addAgentMsg(role, text, chips = [], options = {}) {
  const { track = true } = options;
  const el = document.getElementById('agent-messages');
  const roleLabels = { user: 'You', agent: 'Agent', system: 'System', error: 'Error' };
  const div = document.createElement('div');
  div.className = `msg ${role}`;
  div.innerHTML = `<div class="msg-role">${roleLabels[role] || role}</div><div class="msg-bubble">${text}</div>`;
  if (chips.length) {
    const chipRow = document.createElement('div');
    chipRow.style.display = 'flex'; chipRow.style.flexWrap = 'wrap'; chipRow.style.gap = '6px'; chipRow.style.paddingLeft = '0';
    chips.forEach(c => {
      const btn = document.createElement('button');
      btn.className = `action-chip ${c.cls || ''}`;
      btn.textContent = c.label;
      btn.onclick = c.fn;
      chipRow.appendChild(btn);
    });
    div.appendChild(chipRow);
  }
  el.appendChild(div);
  el.scrollTop = el.scrollHeight;
  if (track) recordConversationTurn(role, text);
  return div;
}

function addTypingIndicator() {
  const el = document.getElementById('agent-messages');
  const div = document.createElement('div');
  div.className = 'msg agent'; div.id = 'typing-indicator';
  div.innerHTML = `<div class="msg-role">Agent</div><div class="msg-bubble"><div class="typing-dots"><span></span><span></span><span></span></div></div>`;
  el.appendChild(div); el.scrollTop = el.scrollHeight;
}
function removeTypingIndicator() { document.getElementById('typing-indicator')?.remove(); }

function quickPrompt(text) { document.getElementById('agent-input').value = text; askAgent(); }

function promptSecurityTarget() {
  const domain = window.prompt(
    'Enter target domain or URL for security scan.\n\nExamples:\n  example.com\n  https://api.example.com\n  http://localhost:8080\n\nLeave blank to use current endpoint.'
  );
  if (domain === null) return;

  let targetUrl = domain.trim();
  if (!targetUrl) {
    const current = getActive();
    targetUrl = current?.url || 'current endpoint';
  } else if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    targetUrl = 'https://' + targetUrl;
  }

  const msg = `Run a full security scan on ${targetUrl}`;
  document.getElementById('agent-input').value = msg;
  askAgent();
}

function renderDebugInfoAction(action) {
  let dbgText = `<strong>Debug findings:</strong><br>`;
  dbgText += action.findings.map(f => `• ${escHtml(f)}`).join('<br>');
  if (action.fix) dbgText += `<br><br><strong>Fix:</strong> ${escHtml(action.fix)}`;
  if (action.patch?.headers?.length) dbgText += `<br><br><strong>Suggested patch headers:</strong> ${escHtml(JSON.stringify(action.patch.headers))}`;
  addAgentMsg('agent', dbgText, []);
}

function buildAgentContinuationMessage(baseMessage, step) {
  if (step === 0) return baseMessage;
  return `${baseMessage}\n\nContinue autonomously from the latest response and execute the next best step. If the task is complete, return actions: [] and put a final one-paragraph summary in message starting with "Conclusion:".`;
}

async function runSecurityAgent(initialUserMsg) {
  const seenProbeSignatures = new Set();
  let step = 0;
  let continueAutonomousRun = true;

  while (continueAutonomousRun) {
    if (agentRunState.stopRequested) {
      addAgentMsg('system', 'Autonomous run stopped by user.');
      break;
    }

    const stepUserMsg = buildAgentContinuationMessage(initialUserMsg, step);
    const r = getActive();
    const context = buildSecurityContext(r, lastResponse, stepUserMsg);

    let raw;
    try {
      const controller = new AbortController();
      agentRunState.abortController = controller;
      raw = await callSecurityAgent(
        context.target_url,
        context.current_request,
        context.last_response,
        context.auth_context,
        context.test_history,
        context.user_instruction,
        { signal: controller.signal }
      );
    } catch (e) {
      if (agentRunState.stopRequested && e?.name === 'AbortError') {
        addAgentMsg('system', 'Autonomous run stopped by user.');
        break;
      }
      throw e;
    } finally {
      agentRunState.abortController = null;
    }

    const parsed = parseSecurityPayload(raw);
    const normalizedActions = (parsed.actions || []).map(normalizeSecurityAction).filter(Boolean);
    const chips = [];
    let didAutoSend = false;

    updateThreatLevel(parsed.threat_level);
    renderSecurityFindings(parsed.findings, securityThreatLevel);

    normalizedActions.forEach(action => {
      if (action.type === 'scan_plan') {
        renderScanPlan(action);
        chips.push({
          label: `▶ Run scan plan (${Array.isArray(action.steps) ? action.steps.length : 0})`,
          cls: 'chain',
          fn: () => executeScanPlan(action)
        });
        return;
      }
      if (action.type === 'fuzz_list') {
        renderFuzzList(action);
        return;
      }
      if (action.type === 'debug_info') {
        renderDebugInfoAction(action);
      }
    });

    if (agentMode === 'agent') {
      const probe = normalizedActions.find(action => action.type === 'probe');
      if (probe) {
        const signature = `${probe.method} ${probe.url} ${probe.vector}`;
        if (seenProbeSignatures.has(signature)) {
          addAgentMsg('system', `Security run concluded to avoid a loop (repeated probe): ${probe.method} ${probe.url}`);
          break;
        }
        seenProbeSignatures.add(signature);

        if (canAutoRunProbe(probe)) {
          addAgentMsg('system', `Auto-running non-destructive probe (${probe.vector}) step ${step + 1}.`);
          const result = await executeSecurityProbe(probe, {
            forceConfirmNonGet: false,
            skipApplyMessage: true,
            sourceLabel: 'autonomous_probe'
          });
          if (result.executed) {
            didAutoSend = true;
          }
        } else {
          chips.push({
            label: `Run probe: ${probe.method} ${probe.vector}`,
            cls: 'apply',
            fn: async () => {
              await executeSecurityProbe(probe, {
                forceConfirmNonGet: true,
                skipApplyMessage: false,
                sourceLabel: 'manual_probe'
              });
            }
          });
        }
      }
    }

    normalizedActions.forEach(action => {
      if (action.type === 'set_assertions') {
        if (agentMode === 'agent' && didAutoSend) {
          applyAssertions(action.assertions, { skipMessage: true });
        } else {
          chips.push({ label: `✓ Add ${action.assertions.length} security assertions`, cls: 'apply', fn: () => applyAssertions(action.assertions) });
        }
      }

      if (action.type === 'probe' && agentMode !== 'agent') {
        chips.push({
          label: `Apply probe: ${action.method} ${action.vector}`,
          cls: 'apply',
          fn: () => applyProbeAction(action)
        });
      }

      if (action.type === 'probe_chain') {
        chips.push({
          label: `Run chain: ${action.name}`,
          cls: 'chain',
          fn: () => executeProbeChain(action, { forceConfirmNonGet: true, sourceLabel: 'manual_probe_chain' })
        });
      }
    });

    if (agentMode === 'ask' && normalizedActions.length) {
      addAgentMsg('system', 'Ask mode is read-only: security actions were not auto-executed.');
    }
    if (agentMode === 'planning' && normalizedActions.length) {
      addAgentMsg('system', 'Planning mode produced a security test plan and suggested actions.');
    }

    addAgentMsg('agent', escHtml(parsed.message || 'Security check complete.'), chips);

    if (agentMode !== 'agent') break;
    if (normalizedActions.length === 0) {
      addAgentMsg('system', 'Security autonomous run concluded.');
      break;
    }
    if (!didAutoSend) {
      addAgentMsg('system', 'Security run paused: no auto-executable probe returned. Use the action chips to continue.');
      break;
    }

    step += 1;
  }
}

async function askAgent() {
  const inputEl = document.getElementById('agent-input');
  const initialUserMsg = inputEl.value.trim();
  if (!initialUserMsg) return;
  if (agentRunState.isRunning) {
    addAgentMsg('system', 'Agent run is already active. Use Stop to terminate it first.');
    return;
  }
  inputEl.value = '';
  if (!chatGoal) chatGoal = initialUserMsg;

  addAgentMsg('user', initialUserMsg);
  addTypingIndicator();
  agentRunState.isRunning = true;
  agentRunState.stopRequested = false;
  syncAgentRunControls();
  renderAgentMode();

  try {
    if (isSecurityInstruction(initialUserMsg)) {
      await runSecurityAgent(initialUserMsg);
      return;
    }

    const seenRequests = new Set();
    let step = 0;
    let continueAutonomousRun = true;

    while (continueAutonomousRun) {
      if (agentRunState.stopRequested) {
        addAgentMsg('system', 'Autonomous run stopped by user.');
        break;
      }

      const stepUserMsg = buildAgentContinuationMessage(initialUserMsg, step);
      const r = getActive();
      const userContext = buildUserContext(r, lastResponse, stepUserMsg);
      const model = pickAgentModel(stepUserMsg);
      const provider = selectedModelProvider;

      let raw;
      try {
        const controller = new AbortController();
        agentRunState.abortController = controller;
        raw = await callBackendJson(BACKEND_ENDPOINTS.agent, {
          provider,
          model,
          context: JSON.parse(userContext)
        }, { signal: controller.signal });
      } catch (e) {
        if (agentRunState.stopRequested && e?.name === 'AbortError') {
          addAgentMsg('system', 'Autonomous run stopped by user.');
          break;
        }
        throw e;
      } finally {
        agentRunState.abortController = null;
      }

      const parsed = parseAgentPayload(raw);
      const chips = [];
      let didAutoSend = false;

      const normalizedActions = (parsed.actions || [])
        .map(validateAndNormalizeAction)
        .filter(Boolean);

      if (agentMode === 'agent') {
        const setRequestAction = normalizedActions.find(action => action.type === 'set_request');
        if (setRequestAction) {
          const requestSignature = `${setRequestAction.method} ${setRequestAction.url}`;
          if (seenRequests.has(requestSignature)) {
            addAgentMsg('system', `Autonomous run concluded to avoid a loop (repeated request): ${requestSignature}`);
            continueAutonomousRun = false;
          } else {
            seenRequests.add(requestSignature);
            applySetRequest(setRequestAction);
            normalizedActions
              .filter(action => action.type === 'set_assertions')
              .forEach(action => applyAssertions(action.assertions, { skipMessage: true }));
            addAgentMsg('system', `Auto-sending request generated by the agent (step ${step + 1}).`);
            await sendRequest();
            didAutoSend = true;
          }
        }
      }

      normalizedActions.forEach(action => {
        if (action.type === 'set_request' && agentMode !== 'agent') {
          chips.push({ label: `↓ Apply: ${action.method} ${shortenUrl(action.url)}`, cls: 'apply', fn: () => applySetRequest(action) });
        }
        if (action.type === 'set_assertions' && !didAutoSend) {
          chips.push({ label: `✓ Add ${action.assertions?.length} assertions`, cls: 'apply', fn: () => applyAssertions(action.assertions) });
        }
        if (action.type === 'chain_request') {
          chips.push({ label: `⛓ Add chain: ${action.name}`, cls: 'chain', fn: () => applyChainRequest(action) });
        }
        if (action.type === 'debug_info') {
          renderDebugInfoAction(action);
        }
      });

      if (agentMode === 'ask' && normalizedActions.length) {
        addAgentMsg('system', 'Ask mode is read-only: suggested actions were not auto-applied.');
      }
      if (agentMode === 'planning' && normalizedActions.length) {
        addAgentMsg('system', 'Planning mode produced suggested actions. Review and apply chips if you want to execute.');
      }

      addAgentMsg('agent', escHtml(parsed.message || 'Done.'), chips);

      if (agentMode !== 'agent') break;
      if (normalizedActions.length === 0) {
        addAgentMsg('system', 'Autonomous run concluded. Summary provided above.');
        break;
      }
      if (!didAutoSend) {
        addAgentMsg('system', 'Autonomous run paused: no executable request action returned. Review suggested actions to continue.');
        break;
      }

      step += 1;
    }
  } catch(e) {
    addAgentMsg('error', `Agent error: ${e.message}`);
  } finally {
    agentRunState.isRunning = false;
    agentRunState.stopRequested = false;
    agentRunState.abortController = null;
    removeTypingIndicator();
    syncAgentRunControls();
    renderAgentMode();
  }
}

function applySetRequest(action, options = {}) {
  const { skipMessage = false } = options;
  saveActive();
  const r = getActive();
  r.method = action.method; r.url = action.url;
  r.headers = action.headers || [];
  r.body = action.body || '';
  r.params = action.params || [];
  r.name = action.name || r.name;
  loadActive(); renderSidebar();
  if (!skipMessage) addAgentMsg('system', `Applied: ${action.method} ${action.url}`);
}

function applyAssertions(list, options = {}) {
  const { skipMessage = false } = options;
  const r = getActive();
  r.assertions = (list || []).map(expr => ({ expr, status: 'pending' }));
  renderAssertions(r.assertions);
  switchTab('assertions');
  if (!skipMessage) addAgentMsg('system', `Added ${list.length} assertions. Send the request to run them.`);
}

function applyChainRequest(action) {
  saveActive();
  const newReq = {
    id: idCounter++, name: action.name || 'Chained Request',
    method: action.method, url: action.url,
    params: action.params || [], headers: action.headers || [],
    body: action.body || '', assertions: [], chainOf: activeId,
    chainNote: action.chainNote || '',
  };
  requests.push(newReq);
  renderSidebar();
  addAgentMsg('system', `Chained request added: "${newReq.name}". ${action.chainNote || ''} Select it in the sidebar and hit Send.`);
}

function shortenUrl(url) {
  try { const u = new URL(url); return u.hostname + u.pathname.substring(0, 20); }
  catch { return url.substring(0, 30); }
}

async function callSecurityAgent(targetUrl, currentRequest, lastResponseData, authContext, testHistory, userInstruction, options = {}) {
  const provider = selectedModelProvider;
  const model = provider === MODEL_PROVIDERS.gemini ? GEMINI_MODELS.security : OPENROUTER_MODELS.security;
  return callBackendJson(BACKEND_ENDPOINTS.securityAgent, {
    provider,
    context: {
      target_url: targetUrl,
      current_request: currentRequest,
      last_response: lastResponseData,
      auth_context: authContext,
      test_history: Array.isArray(testHistory) ? testHistory : [],
      user_instruction: userInstruction
    },
    model
  }, options);
}

async function callBackendJson(path, payload, options = {}) {
  const { signal } = options;
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    signal
  });

  let data;
  try {
    data = await res.json();
  } catch {
    throw new Error(`Backend returned non-JSON response (${res.status}).`);
  }

  if (!res.ok) {
    throw new Error(data?.error || data?.message || `Backend request failed (${res.status}).`);
  }
  return data;
}

// New request
document.getElementById('new-req-btn').addEventListener('click', () => {
  saveActive();
  const newReq = { id: idCounter++, name: 'New Request', method: 'GET', url: '', params: [], headers: [], body: '', assertions: [], chainOf: null };
  requests.push(newReq);
  activeId = newReq.id;
  loadActive(); renderSidebar();
});

// Copy response
document.getElementById('copy-res-btn').addEventListener('click', () => {
  if (lastResponse?.text) navigator.clipboard.writeText(lastResponse.text);
});

// Chain URL resolver — expand {{json.field}} at send time
const origSend = window.fetch;
// We patch the send to resolve chain templates before actual fetch
function resolveChainTemplate(url) {
  if (!url.includes('{{')) return url;
  if (!lastResponse?.text) return url;
  let parsed; try { parsed = JSON.parse(lastResponse.text); } catch { return url; }

  const readPath = (obj, path) => {
    const tokens = [];
    const regex = /([^[.\]]+)|\[(\d+)\]/g;
    let m;
    while ((m = regex.exec(path)) !== null) {
      tokens.push(m[1] !== undefined ? m[1] : Number(m[2]));
    }
    return tokens.reduce((acc, token) => (acc == null ? undefined : acc[token]), obj);
  };

  return url.replace(/\{\{json\.([^}]+)\}\}/g, (_, path) => {
    const val = readPath(parsed, path);
    return val !== undefined ? val : _;
  });
}
const origSendBtn = document.getElementById('send-btn');
origSendBtn.addEventListener('click', () => {}, true);
// Override URL resolution in sendRequest
const origSendRequest = sendRequest;

// Patch sendRequest to resolve templates
(function() {
  const origFn = window.sendRequest;
  window.sendRequest = function() {
    const r = getActive();
    if (r && r.chainOf && lastResponse) r.url = resolveChainTemplate(r.url);
    return origSendRequest.apply(this, arguments);
  };
})();

// Init
loadActive();
renderSidebar();
renderModelProvider();
renderAgentMode();
syncAgentRunControls();
renderScanProgress();
