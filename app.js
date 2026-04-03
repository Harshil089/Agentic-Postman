let OPENROUTER_MODELS = {
  default: 'openrouter/auto',
  advanced: 'openai/gpt-4o-mini',
  security: 'openai/gpt-4o'
};
let GEMINI_MODELS = {
  default: 'gemini-2.5-flash',
  advanced: 'gemini-2.5-flash',
  security: 'gemini-2.5-flash'
};
let GROQ_MODELS = {
  default: 'groq/gpt-oss-120b',
  advanced: 'groq/gpt-oss-120b',
  security: 'groq/gpt-oss-120b'
};
let GROQ_MODEL_OPTIONS = [
  'groq/compound',
  'groq/compound-mini',
  'groq/gpt-oss-120b',
  'groq/gpt-oss-20b',
  'groq/gpt-oss-safeguard-20b',
  'groq/qwen3-32b'
];
const GEMINI_MODEL_ALIASES = {
  'gemini-flash-latest': 'gemini-2.5-flash',
  'gemini-2.0-flash': 'gemini-2.5-flash',
  'gemini-2.0-flash-lite': 'gemini-2.5-flash',
  'gemini-1.5-flash': 'gemini-2.5-flash',
  'gemini-1.5-flash-8b': 'gemini-2.5-flash',
  'gemini-1.5-pro': 'gemini-2.5-flash'
};
const MODEL_PROVIDERS = {
  openrouter: 'openrouter',
  gemini: 'gemini',
  groq: 'groq'
};
const BACKEND_ENDPOINTS = {
  agent: '/api/agent',
  assertions: '/api/assertions',
  request: '/api/request',
  securityAgent: '/api/security-agent',
  config: '/api/config'
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

const COMPONENT_INTEGRATION_PROMPT = ``;

let requests = [
  { id: 1, name: 'Get Users', method: 'GET', url: 'https://jsonplaceholder.typicode.com/users', params: [], headers: [], body: '', assertions: [], chainOf: null },
  { id: 2, name: 'Create Post', method: 'POST', url: 'https://jsonplaceholder.typicode.com/posts', params: [], headers: [{ k: 'Content-Type', v: 'application/json' }], body: '{\n  "title": "foo",\n  "body": "bar",\n  "userId": 1\n}', assertions: [], chainOf: null },
];
let activeId = 1;
let lastResponse = null;
let idCounter = 3;
let agentMode = 'agent';
let selectedModelProvider = MODEL_PROVIDERS.openrouter;
let selectedGroqModel = GROQ_MODELS.default;
let chatSessionId = 1;
let chatGoal = '';
let conversationHistory = [];
let securityTestHistory = [];
let securityThreatLevel = 'none';
let activeSidebarWindow = 'requests';
let errorLogEntries = [];
let structuredDiagnosticsEntries = [];
let scanPaceSetting = '0';
let adaptiveScanPacingMs = 2000;
let agentPanelOpen = true;
const AGENT_INPUT_MAX_CHARS = 2000;
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

const STORAGE_KEYS = {
  provider: 'agentman:modelProvider',
  groqModel: 'agentman:groqModel',
  sidebarWindow: 'agentman:sidebarWindow',
  scanPaceMs: 'agentman:scanPaceMs',
  scanPaceSetting: 'agentman:scanPaceSetting'
};

const SCAN_PACE_VALUES = new Set(['0', '2000', '5000', '8000', 'adaptive']);

function normalizeGeminiModel(model) {
  const value = typeof model === 'string' ? model.trim().replace(/^models\//, '') : '';
  if (!value) return 'gemini-2.5-flash';
  return GEMINI_MODEL_ALIASES[value] || value;
}

function normalizeGeminiModelsConfig(models) {
  const source = models && typeof models === 'object' ? models : {};
  return {
    default: normalizeGeminiModel(source.default),
    advanced: normalizeGeminiModel(source.advanced),
    security: normalizeGeminiModel(source.security)
  };
}

function loadModelPreferences() {
  try {
    const storedProvider = localStorage.getItem(STORAGE_KEYS.provider);
    if (Object.values(MODEL_PROVIDERS).includes(storedProvider)) {
      selectedModelProvider = storedProvider;
    }

    const storedGroqModel = localStorage.getItem(STORAGE_KEYS.groqModel);
    if (GROQ_MODEL_OPTIONS.includes(storedGroqModel)) {
      selectedGroqModel = storedGroqModel;
    }

    const storedSidebarWindow = localStorage.getItem(STORAGE_KEYS.sidebarWindow);
    if (storedSidebarWindow === 'requests' || storedSidebarWindow === 'errors' || storedSidebarWindow === 'diagnostics') {
      activeSidebarWindow = storedSidebarWindow;
    }

    const storedScanPaceSetting = localStorage.getItem(STORAGE_KEYS.scanPaceSetting);
    if (SCAN_PACE_VALUES.has(storedScanPaceSetting)) {
      scanPaceSetting = storedScanPaceSetting;
    } else {
      const storedScanPaceMs = Number(localStorage.getItem(STORAGE_KEYS.scanPaceMs));
      if (Number.isFinite(storedScanPaceMs) && SCAN_PACE_VALUES.has(String(storedScanPaceMs))) {
        scanPaceSetting = String(storedScanPaceMs);
      }
    }
  } catch {}
}

function saveModelPreferences() {
  try {
    localStorage.setItem(STORAGE_KEYS.provider, selectedModelProvider);
    localStorage.setItem(STORAGE_KEYS.groqModel, selectedGroqModel);
    localStorage.setItem(STORAGE_KEYS.scanPaceMs, scanPaceSetting === 'adaptive' ? String(adaptiveScanPacingMs) : scanPaceSetting);
    localStorage.setItem(STORAGE_KEYS.scanPaceSetting, scanPaceSetting);
  } catch {}
}

async function loadRuntimeConfig() {
  try {
    const res = await fetch(BACKEND_ENDPOINTS.config);
    if (!res.ok) return;
    const data = await res.json();
    if (data?.models?.openrouter && typeof data.models.openrouter === 'object') {
      OPENROUTER_MODELS = { ...OPENROUTER_MODELS, ...data.models.openrouter };
    }
    if (data?.models?.gemini && typeof data.models.gemini === 'object') {
      GEMINI_MODELS = normalizeGeminiModelsConfig({ ...GEMINI_MODELS, ...data.models.gemini });
    }
    if (data?.models?.groq && typeof data.models.groq === 'object') {
      GROQ_MODELS = { ...GROQ_MODELS, ...data.models.groq };
    }
    if (Array.isArray(data?.models?.groq_options) && data.models.groq_options.length) {
      GROQ_MODEL_OPTIONS = data.models.groq_options.slice();
    }
    renderModelProviderOptions();
  } catch (error) {
    logError('config', `Failed to load runtime config: ${error.message}`);
  }
}

function renderModelProviderOptions() {
  const groqSelectEl = document.getElementById('groq-model-select');
  if (!groqSelectEl) return;
  groqSelectEl.innerHTML = GROQ_MODEL_OPTIONS
    .map(modelId => `<option value="${escHtml(modelId)}">${escHtml(modelId)}</option>`)
    .join('');
}

function getCurrentScanPacingMs() {
  if (scanPaceSetting === 'adaptive') return adaptiveScanPacingMs;
  const fixed = Number(scanPaceSetting);
  return Number.isFinite(fixed) ? fixed : 0;
}

function bumpAdaptiveScanPacing(delayHintMs = 0) {
  if (scanPaceSetting !== 'adaptive') return;
  const base = Math.max(2000, adaptiveScanPacingMs);
  const hinted = Number.isFinite(delayHintMs) && delayHintMs > 0 ? Math.min(15000, Math.ceil(delayHintMs / 1000) * 1000) : base;
  adaptiveScanPacingMs = Math.min(15000, Math.max(base + 1000, hinted));
  saveModelPreferences();
}

function relaxAdaptiveScanPacing() {
  if (scanPaceSetting !== 'adaptive') return;
  adaptiveScanPacingMs = Math.max(2000, adaptiveScanPacingMs - 500);
  saveModelPreferences();
}

function renderScanPaceControl() {
  const selectEl = document.getElementById('scan-pace-select');
  if (!selectEl) return;
  if (!SCAN_PACE_VALUES.has(scanPaceSetting)) {
    scanPaceSetting = '0';
  }
  selectEl.value = scanPaceSetting;
}

function setScanPace(msRaw) {
  const normalized = String(msRaw || '').trim();
  if (!SCAN_PACE_VALUES.has(normalized)) return;
  scanPaceSetting = normalized;
  if (scanPaceSetting === 'adaptive') {
    adaptiveScanPacingMs = 2000;
  }
  saveModelPreferences();
  renderScanPaceControl();
  const label = scanPaceSetting === 'adaptive'
    ? 'Adaptive (starts at 2s and auto-adjusts on rate limits)'
    : Number(scanPaceSetting) === 0 ? 'No delay' : `${Math.round(Number(scanPaceSetting) / 1000)}s`;
  addAgentMsg('system', `Scan pace set to ${label}.`, [], { track: false });
}

function getActive() { return requests.find(r => r.id === activeId); }

function renderSidebar() {
  renderSidebarWindowNav();
  renderSidebarHeader();
  if (activeSidebarWindow === 'errors') {
    renderErrorSidebar();
    return;
  }
  if (activeSidebarWindow === 'diagnostics') {
    renderDiagnosticsSidebar();
    return;
  }
  const list = document.getElementById('sidebar-list');
  if (!list) return;
  list.innerHTML = requests.map(r => `
    <div class="req-item ${r.id === activeId ? 'active' : ''}" onclick="selectRequest(${r.id})">
      <span class="method-badge m-${r.method}">${r.method}</span>
      <span class="req-name">${r.name}</span>
      ${r.chainOf ? `<span class="req-chain">⛓</span>` : ''}
    </div>
  `).join('');
}

function renderSidebarWindowNav() {
  const nav = document.getElementById('sidebar-nav');
  if (!nav) return;
  nav.querySelectorAll('.sidebar-window-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.window === activeSidebarWindow);
  });

  const badge = document.getElementById('errors-count-badge');
  if (badge) badge.textContent = String(errorLogEntries.length);
  const diagBadge = document.getElementById('diagnostics-count-badge');
  if (diagBadge) diagBadge.textContent = String(structuredDiagnosticsEntries.length);
}

function renderSidebarHeader() {
  const title = document.getElementById('sidebar-title');
  const actionBtn = document.getElementById('new-req-btn');
  const clearErrorsBtn = document.getElementById('clear-errors-btn');
  if (title) {
    title.textContent = activeSidebarWindow === 'errors'
      ? 'Errors'
      : activeSidebarWindow === 'diagnostics'
        ? 'Diagnostics'
        : 'Requests';
  }
  if (actionBtn) {
    actionBtn.style.display = activeSidebarWindow === 'requests' ? 'flex' : 'none';
  }
  if (clearErrorsBtn) {
    clearErrorsBtn.style.display = activeSidebarWindow === 'errors' ? 'flex' : 'none';
  }
}

function renderDiagnosticsSidebar() {
  const list = document.getElementById('sidebar-list');
  if (!list) return;
  if (!structuredDiagnosticsEntries.length) {
    list.innerHTML = `<div class="error-empty">No structured-output diagnostics yet.</div>`;
    return;
  }

  list.innerHTML = structuredDiagnosticsEntries
    .slice()
    .reverse()
    .map(entry => {
      const statusLabel = entry.repaired ? 'repaired' : entry.status || 'valid';
      const errorSummary = Array.isArray(entry.errors) && entry.errors.length
        ? `Last error: ${escHtml(entry.errors[entry.errors.length - 1].message || '')}`
        : 'No validation errors.';
      return `
        <div class="diag-item">
          <div class="diag-item-header">
            <span class="diag-item-source">${escHtml(entry.engine || entry.source || 'engine')}</span>
            <span class="diag-item-time">${escHtml(entry.time || '')}</span>
          </div>
          <div class="diag-item-body">${errorSummary}</div>
          <div class="diag-chip-row">
            <span class="diag-chip">status: ${escHtml(statusLabel)}</span>
            <span class="diag-chip">attempts: ${escHtml(String(entry.attempts || 0))}</span>
            <span class="diag-chip">repairs: ${escHtml(String(entry.repairCount || 0))}</span>
            <span class="diag-chip">${escHtml(entry.provider || '')}/${escHtml(entry.model || '')}</span>
          </div>
        </div>
      `;
    })
    .join('');
}

function renderErrorSidebar() {
  const list = document.getElementById('sidebar-list');
  if (!list) return;
  if (!errorLogEntries.length) {
    list.innerHTML = `<div class="error-empty">No errors logged yet.</div>`;
    return;
  }

  list.innerHTML = errorLogEntries
    .slice()
    .reverse()
    .map(entry => `
      <div class="error-item">
        <div class="error-item-header">
          <span class="error-item-source">${escHtml(entry.source || 'error')}</span>
          <span class="error-item-time">${escHtml(entry.time || '')}</span>
        </div>
        <div class="error-item-message">${escHtml(entry.message || '')}</div>
      </div>
    `)
    .join('');
}

function setSidebarWindow(windowName) {
  if (windowName !== 'requests' && windowName !== 'errors' && windowName !== 'diagnostics') return;
  activeSidebarWindow = windowName;
  try {
    localStorage.setItem(STORAGE_KEYS.sidebarWindow, windowName);
  } catch {}
  renderSidebar();
}

function clearErrorLogs() {
  errorLogEntries = [];
  renderSidebar();
  addAgentMsg('system', 'Cleared error log entries.', [], { track: false });
}

function logStructuredDiagnostics(sourcePath, diagnostics) {
  if (!diagnostics || typeof diagnostics !== 'object') return;
  structuredDiagnosticsEntries.push({
    source: sourcePath,
    engine: typeof diagnostics.engine === 'string' ? diagnostics.engine : 'unknown',
    provider: typeof diagnostics.provider === 'string' ? diagnostics.provider : '',
    model: typeof diagnostics.model === 'string' ? diagnostics.model : '',
    attempts: Number(diagnostics.attempts || 0),
    repairCount: Number(diagnostics.repairCount || 0),
    repaired: Boolean(diagnostics.repaired),
    status: typeof diagnostics.status === 'string' ? diagnostics.status : 'unknown',
    errors: Array.isArray(diagnostics.errors) ? diagnostics.errors : [],
    time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  });
  if (structuredDiagnosticsEntries.length > 200) {
    structuredDiagnosticsEntries = structuredDiagnosticsEntries.slice(-200);
  }
  renderSidebarWindowNav();
  if (activeSidebarWindow === 'diagnostics') {
    renderDiagnosticsSidebar();
  }
}

function logError(source, message) {
  const msg = String(message || '').trim();
  if (!msg) return;
  errorLogEntries.push({
    source: String(source || 'error'),
    message: msg,
    time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  });
  if (errorLogEntries.length > 200) {
    errorLogEntries = errorLogEntries.slice(-200);
  }
  renderSidebarWindowNav();
  if (activeSidebarWindow === 'errors') {
    renderErrorSidebar();
  }
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

function sanitizeRichText(html) {
  const template = document.createElement('template');
  template.innerHTML = String(html || '');

  const allowedTags = new Set(['BR', 'EM', 'STRONG', 'CODE']);

  function sanitizeNode(node) {
    if (node.nodeType === Node.TEXT_NODE) {
      return document.createTextNode(node.textContent || '');
    }
    if (node.nodeType !== Node.ELEMENT_NODE) {
      return document.createDocumentFragment();
    }

    const tag = node.tagName.toUpperCase();
    if (!allowedTags.has(tag)) {
      const fragment = document.createDocumentFragment();
      Array.from(node.childNodes).forEach(child => {
        fragment.appendChild(sanitizeNode(child));
      });
      return fragment;
    }

    const clean = document.createElement(tag.toLowerCase());
    Array.from(node.childNodes).forEach(child => {
      clean.appendChild(sanitizeNode(child));
    });
    return clean;
  }

  const fragment = document.createDocumentFragment();
  Array.from(template.content.childNodes).forEach(child => {
    fragment.appendChild(sanitizeNode(child));
  });
  return fragment;
}

function setBubbleContent(element, text) {
  element.replaceChildren(sanitizeRichText(text));
}

function renderAgentPanelState() {
  const panel = document.querySelector('.agent-panel');
  if (!panel) return;
  panel.classList.add('open');
}

function toggleAgentPanel(forceOpen) {
  agentPanelOpen = true;
  renderAgentPanelState();
}

function renderAgentCharCount() {
  const inputEl = document.getElementById('agent-input');
  const countEl = document.getElementById('agent-char-count');
  const maxEl = document.getElementById('agent-char-max');
  if (!inputEl || !countEl || !maxEl) return;
  countEl.textContent = String(inputEl.value.length);
  maxEl.textContent = String(AGENT_INPUT_MAX_CHARS);
}

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
  sendBtn.textContent = agentRunState.isRunning ? 'Running…' : meta.button.replace(' ↗', '');
  inputEl.placeholder = meta.placeholder;
  syncAgentRunControls();
  renderAgentCharCount();
}

function renderModelProvider() {
  const selectEl = document.getElementById('model-provider-select');
  const groqSelectEl = document.getElementById('groq-model-select');
  const groqRowEl = document.getElementById('groq-model-row');
  const modelBadgeEl = document.getElementById('agent-model-badge');
  if (!selectEl) return;
  selectEl.value = selectedModelProvider;
  if (groqSelectEl) {
    if (!GROQ_MODEL_OPTIONS.includes(selectedGroqModel)) {
      selectedGroqModel = GROQ_MODELS.default;
    }
    groqSelectEl.value = selectedGroqModel;
  }
  if (groqRowEl) {
    groqRowEl.style.display = selectedModelProvider === MODEL_PROVIDERS.groq ? 'flex' : 'none';
  }
  
  const statusText = document.getElementById('provider-status-text');
  if (statusText) {
    const labels = {
      openrouter: 'OpenRouter',
      gemini: 'Gemini',
      groq: 'Groq'
    };
    if (selectedModelProvider === MODEL_PROVIDERS.groq) {
      statusText.textContent = `Groq (${selectedGroqModel})`;
    } else {
      statusText.textContent = labels[selectedModelProvider] || 'OpenRouter';
    }
  }
  if (modelBadgeEl) {
    if (selectedModelProvider === MODEL_PROVIDERS.groq) {
      modelBadgeEl.textContent = `Groq · ${selectedGroqModel}`;
    } else {
      modelBadgeEl.textContent = selectedModelProvider === MODEL_PROVIDERS.gemini ? 'Gemini' : 'OpenRouter';
    }
  }
}

function setModelProvider(provider) {
  if (!Object.values(MODEL_PROVIDERS).includes(provider)) return;
  if (agentRunState.isRunning) {
    addAgentMsg('system', 'Stop the current run before switching model provider.');
    return;
  }
  selectedModelProvider = provider;
  saveModelPreferences();
  renderModelProvider();
  const labels = {
    openrouter: 'OpenRouter',
    gemini: 'Gemini',
    groq: 'Groq'
  };
  addAgentMsg('system', `Model provider switched to ${labels[provider]}.`);
}

function setGroqModel(model) {
  if (!GROQ_MODEL_OPTIONS.includes(model)) return;
  if (agentRunState.isRunning) {
    addAgentMsg('system', 'Stop the current run before switching Groq model.');
    renderModelProvider();
    return;
  }
  selectedGroqModel = model;
  saveModelPreferences();
  renderModelProvider();
  addAgentMsg('system', `Groq model switched to ${model}.`);
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
  el.innerHTML = '';
  addAgentMsg('agent', `
      I can build API requests from plain English, chain follow-up calls, debug failures, and generate assertions.<br><br>
      <em>"GET all users from JSONPlaceholder"</em><br>
      <em>"Chain: get user 1, then fetch their posts"</em>
    `, [], { track: false });
}

function loadComponentIntegrationPrompt(options = {}) {
  const { overwrite = true } = options;
  const inputEl = document.getElementById('agent-input');
  if (!inputEl) return;
  if (!overwrite && inputEl.value.trim()) return;
  inputEl.value = COMPONENT_INTEGRATION_PROMPT;
  renderAgentCharCount();
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
  loadComponentIntegrationPrompt();
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

async function sendRequest(options = {}) {
  let { confirmMutation = false, skipAutoAssertions = false } = options;
  saveActive();
  const r = getActive();
  const btn = document.getElementById('send-btn');
  btn.disabled = true; btn.textContent = 'Sending…';

  const methodUpper = String(r.method || 'GET').toUpperCase();
  if (!['GET', 'HEAD', 'OPTIONS'].includes(methodUpper) && !confirmMutation) {
    const proceed = window.confirm(
      `${methodUpper} requests can modify remote state.\n\nURL: ${r.url || '(empty)'}\n\nContinue?`
    );
    if (!proceed) {
      btn.disabled = false;
      btn.textContent = 'Send';
      addAgentMsg('system', `Cancelled ${methodUpper} request before execution.`, [], { track: false });
      return null;
    }
    confirmMutation = true;
  }

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
      body: fetchOpts.body || '',
      confirm_mutation: confirmMutation
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
    if (r.assertions.length === 0 && !skipAutoAssertions) autoSuggestAssertions();
    return lastResponse;
  } catch (e) {
    lastResponse = { error: e.message };
    document.getElementById('response-body').innerHTML = `<span style="color:var(--red);">Error: ${e.message}</span>`;
    document.getElementById('status-tag').textContent = 'FAILED';
    document.getElementById('status-tag').className = 'status-tag s-4xx';
    logError('request', `${r.method} ${r.url} - ${e.message}`);
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

function isRateLimitErrorMessage(message) {
  const msg = String(message || '').toLowerCase();
  return msg.includes('rate limit')
    || msg.includes('tokens per minute')
    || msg.includes('please try again in')
    || msg.includes('quota');
}

function getRetryDelayMs(message) {
  const raw = String(message || '');
  const match = raw.match(/try again in\s*([0-9]+(?:\.[0-9]+)?)s/i);
  if (match) {
    const seconds = Number(match[1]);
    if (Number.isFinite(seconds) && seconds > 0) {
      return Math.min(30000, Math.ceil(seconds * 1000) + 300);
    }
  }
  return 1800;
}

function waitMs(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
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

function getSecurityProviderFallbackOrder(preferredProvider) {
  const order = [preferredProvider, MODEL_PROVIDERS.openrouter, MODEL_PROVIDERS.groq, MODEL_PROVIDERS.gemini];
  return order.filter((provider, index) => provider && order.indexOf(provider) === index);
}

function getProviderModel(provider, taskType = 'security') {
  if (provider === MODEL_PROVIDERS.gemini) {
    return taskType === 'security' ? GEMINI_MODELS.security : GEMINI_MODELS.default;
  }
  if (provider === MODEL_PROVIDERS.groq) {
    return selectedGroqModel;
  }
  return taskType === 'security' ? OPENROUTER_MODELS.security : OPENROUTER_MODELS.default;
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
  return false;
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
  const response = await sendRequest({
    confirmMutation: !['GET', 'HEAD', 'OPTIONS'].includes(String(action.method || '').toUpperCase()),
    skipAutoAssertions: true
  });
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
  let raw;
  let lastRateError = null;
  let hadRateLimit = false;
  const providersToTry = getSecurityProviderFallbackOrder(selectedModelProvider);

  providerLoop:
  for (const provider of providersToTry) {
    const maxAttempts = provider === selectedModelProvider ? 2 : 1;
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      try {
        raw = await callSecurityAgent(
          context.target_url,
          context.current_request,
          context.last_response,
          context.auth_context,
          context.test_history,
          context.user_instruction,
          {
            providerOverride: provider,
            modelOverride: getProviderModel(provider, 'security')
          }
        );
        break providerLoop;
      } catch (error) {
        const message = error?.message || 'Unknown error';
        if (!isRateLimitErrorMessage(message)) {
          throw error;
        }
        lastRateError = error;
        hadRateLimit = true;
        const delayMs = Math.min(getRetryDelayMs(message), 4000);
        bumpAdaptiveScanPacing(delayMs);

        if (attempt < maxAttempts) {
          addAgentMsg('system', `Rate limit detected while generating probe for step ${planStep.order || '?'} with ${provider}. Retrying in ${Math.ceil(delayMs / 1000)}s...`, [], { track: false });
          await waitMs(delayMs);
          continue;
        }

        if (provider !== providersToTry[providersToTry.length - 1]) {
          addAgentMsg('system', `Rate limit detected while generating probe for step ${planStep.order || '?'} with ${provider}. Falling back to the next provider.`, [], { track: false });
          continue providerLoop;
        }
      }
    }
  }

  if (!raw && lastRateError) {
    throw lastRateError;
  }

  const parsed = parseSecurityPayload(raw);
  updateThreatLevel(parsed.threat_level);
  renderSecurityFindings(parsed.findings, securityThreatLevel);

  const actionBatch = normalizeSecurityActionsStrict(parsed.actions || []);
  if (actionBatch.invalidCount > 0) {
    throw new Error(`Blocked malformed security action batch at indexes: ${actionBatch.invalidIndexes.join(', ')}`);
  }
  const actions = actionBatch.normalized;
  const probe = actions.find(action => action.type === 'probe');
  if (probe) return { probe, chain: null, message: parsed.message, assertions: actions.filter(a => a.type === 'set_assertions'), hadRateLimit };
  const chain = actions.find(action => action.type === 'probe_chain');
  return { probe: null, chain, message: parsed.message, assertions: actions.filter(a => a.type === 'set_assertions'), hadRateLimit };
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

    const stepDelayMs = i > 0 ? getCurrentScanPacingMs() : 0;
    if (stepDelayMs > 0) {
      const seconds = Math.round(stepDelayMs / 1000);
      const modeLabel = scanPaceSetting === 'adaptive' ? 'adaptive' : 'fixed';
      addAgentMsg('system', `Scan pacing (${modeLabel}): waiting ${seconds}s before step ${i + 1}.`, [], { track: false });
      await waitMs(stepDelayMs);
      if (agentRunState.stopRequested) {
        addAgentMsg('system', 'Scan plan execution stopped by user.');
        finalizeScanProgress('stopped', `Stopped at step ${i + 1}/${steps.length}`);
        return false;
      }
    }

    updateScanProgressStep(i + 1, steps.length, planStep.vector || 'Unknown');
    addAgentMsg('system', `Preparing step ${planStep.order || '?'} (${planStep.vector || 'Unknown'}).`);

    let generated;
    try {
      generated = await generateProbeForScanStep(scanPlan, planStep);
      if (scanPaceSetting === 'adaptive' && !generated.hadRateLimit) {
        relaxAdaptiveScanPacing();
      }
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
function tokenizeAssertionExpression(input) {
  const text = String(input || '');
  const tokens = [];
  let i = 0;
  const multiCharOps = ['===', '!==', '>=', '<=', '&&', '||'];
  const singleCharOps = new Set(['(', ')', '[', ']', '.', ',', '!', '>', '<']);

  while (i < text.length) {
    const ch = text[i];

    if (/\s/.test(ch)) {
      i += 1;
      continue;
    }

    const op = multiCharOps.find(candidate => text.startsWith(candidate, i));
    if (op) {
      tokens.push({ type: 'op', value: op });
      i += op.length;
      continue;
    }

    if (singleCharOps.has(ch)) {
      tokens.push({ type: 'op', value: ch });
      i += 1;
      continue;
    }

    if (ch === '"' || ch === '\'') {
      const quote = ch;
      let value = '';
      i += 1;
      while (i < text.length) {
        const current = text[i];
        if (current === '\\') {
          if (text[i + 1]) value += text[i + 1];
          i += 2;
          continue;
        }
        if (current === quote) {
          i += 1;
          break;
        }
        value += current;
        i += 1;
      }
      tokens.push({ type: 'string', value });
      continue;
    }

    if (/[0-9]/.test(ch)) {
      const start = i;
      i += 1;
      while (i < text.length && /[0-9.]/.test(text[i])) i += 1;
      tokens.push({ type: 'number', value: Number(text.slice(start, i)) });
      continue;
    }

    if (/[A-Za-z_$]/.test(ch)) {
      const start = i;
      i += 1;
      while (i < text.length && /[A-Za-z0-9_$]/.test(text[i])) i += 1;
      tokens.push({ type: 'identifier', value: text.slice(start, i) });
      continue;
    }

    throw new Error(`Unsupported token: ${ch}`);
  }

  return tokens;
}

function parseAssertionExpression(input) {
  const tokens = tokenizeAssertionExpression(input);
  let index = 0;

  function peek(offset = 0) {
    return tokens[index + offset];
  }

  function consume(expected) {
    const token = tokens[index];
    if (!token || (expected && token.value !== expected)) {
      throw new Error(`Expected ${expected || 'token'}.`);
    }
    index += 1;
    return token;
  }

  function parsePrimary() {
    const token = peek();
    if (!token) throw new Error('Unexpected end of expression.');

    if (token.type === 'number' || token.type === 'string') {
      index += 1;
      return { type: 'literal', value: token.value };
    }

    if (token.type === 'identifier') {
      if (token.value === 'true' || token.value === 'false') {
        index += 1;
        return { type: 'literal', value: token.value === 'true' };
      }
      if (token.value === 'null') {
        index += 1;
        return { type: 'literal', value: null };
      }
      index += 1;
      return { type: 'identifier', name: token.value };
    }

    if (token.value === '(') {
      consume('(');
      const expr = parseLogicalOr();
      consume(')');
      return expr;
    }

    throw new Error(`Unexpected token: ${token.value}`);
  }

  function parsePostfix() {
    let expr = parsePrimary();

    while (true) {
      const token = peek();
      if (!token) break;

      if (token.value === '.') {
        consume('.');
        const property = consume();
        if (property.type !== 'identifier') throw new Error('Expected property name.');
        expr = {
          type: 'member',
          object: expr,
          property: { type: 'literal', value: property.value },
          computed: false
        };
        continue;
      }

      if (token.value === '[') {
        consume('[');
        const property = parseLogicalOr();
        consume(']');
        expr = { type: 'member', object: expr, property, computed: true };
        continue;
      }

      if (token.value === '(') {
        consume('(');
        const args = [];
        if (peek() && peek().value !== ')') {
          while (true) {
            args.push(parseLogicalOr());
            if (!peek() || peek().value !== ',') break;
            consume(',');
          }
        }
        consume(')');
        expr = { type: 'call', callee: expr, args };
        continue;
      }

      break;
    }

    return expr;
  }

  function parseUnary() {
    const token = peek();
    if (token && token.type === 'identifier' && token.value === 'typeof') {
      consume();
      return { type: 'unary', operator: 'typeof', argument: parseUnary() };
    }
    if (token && token.value === '!') {
      consume('!');
      return { type: 'unary', operator: '!', argument: parseUnary() };
    }
    return parsePostfix();
  }

  function parseComparison() {
    let expr = parseUnary();
    while (peek() && ['>', '<', '>=', '<='].includes(peek().value)) {
      const operator = consume().value;
      expr = { type: 'binary', operator, left: expr, right: parseUnary() };
    }
    return expr;
  }

  function parseEquality() {
    let expr = parseComparison();
    while (peek() && ['===', '!=='].includes(peek().value)) {
      const operator = consume().value;
      expr = { type: 'binary', operator, left: expr, right: parseComparison() };
    }
    return expr;
  }

  function parseLogicalAnd() {
    let expr = parseEquality();
    while (peek() && peek().value === '&&') {
      consume('&&');
      expr = { type: 'logical', operator: '&&', left: expr, right: parseEquality() };
    }
    return expr;
  }

  function parseLogicalOr() {
    let expr = parseLogicalAnd();
    while (peek() && peek().value === '||') {
      consume('||');
      expr = { type: 'logical', operator: '||', left: expr, right: parseLogicalAnd() };
    }
    return expr;
  }

  const expression = parseLogicalOr();
  if (index !== tokens.length) {
    throw new Error(`Unexpected token: ${tokens[index].value}`);
  }
  return expression;
}

function evaluateAssertionAst(node, scope) {
  if (node.type === 'literal') return node.value;

  if (node.type === 'identifier') {
    if (!Object.prototype.hasOwnProperty.call(scope, node.name)) {
      throw new Error(`Identifier not allowed: ${node.name}`);
    }
    return scope[node.name];
  }

  if (node.type === 'unary') {
    const value = evaluateAssertionAst(node.argument, scope);
    if (node.operator === '!') return !value;
    if (node.operator === 'typeof') return typeof value;
    throw new Error(`Unary operator not allowed: ${node.operator}`);
  }

  if (node.type === 'member') {
    const object = evaluateAssertionAst(node.object, scope);
    const property = node.computed ? evaluateAssertionAst(node.property, scope) : node.property.value;
    if (object == null) return undefined;
    return object[property];
  }

  if (node.type === 'binary') {
    const left = evaluateAssertionAst(node.left, scope);
    const right = evaluateAssertionAst(node.right, scope);
    switch (node.operator) {
      case '===': return left === right;
      case '!==': return left !== right;
      case '>': return left > right;
      case '<': return left < right;
      case '>=': return left >= right;
      case '<=': return left <= right;
      default: throw new Error(`Binary operator not allowed: ${node.operator}`);
    }
  }

  if (node.type === 'logical') {
    if (node.operator === '&&') return evaluateAssertionAst(node.left, scope) && evaluateAssertionAst(node.right, scope);
    if (node.operator === '||') return evaluateAssertionAst(node.left, scope) || evaluateAssertionAst(node.right, scope);
    throw new Error(`Logical operator not allowed: ${node.operator}`);
  }

  if (node.type === 'call') {
    if (
      node.callee.type === 'member'
      && node.callee.object.type === 'identifier'
      && node.callee.object.name === 'Array'
      && node.callee.property.value === 'isArray'
    ) {
      const args = node.args.map(arg => evaluateAssertionAst(arg, scope));
      return Array.isArray(args[0]);
    }

    if (node.callee.type === 'member') {
      const target = evaluateAssertionAst(node.callee.object, scope);
      const property = node.callee.computed ? evaluateAssertionAst(node.callee.property, scope) : node.callee.property.value;
      const args = node.args.map(arg => evaluateAssertionAst(arg, scope));

      if (property === 'includes' && (typeof target === 'string' || Array.isArray(target))) {
        return target.includes(args[0]);
      }
      if (property === 'startsWith' && typeof target === 'string') {
        return target.startsWith(args[0]);
      }
      if (property === 'endsWith' && typeof target === 'string') {
        return target.endsWith(args[0]);
      }
      if (property === 'hasOwnProperty' && target && typeof target === 'object') {
        return Object.prototype.hasOwnProperty.call(target, args[0]);
      }
      throw new Error(`Method not allowed: ${property}`);
    }

    throw new Error('Function call not allowed.');
  }

  throw new Error(`Expression node not supported: ${node.type}`);
}

function evaluateAssertionExpression(expression, scope) {
  return evaluateAssertionAst(parseAssertionExpression(expression), scope);
}

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
      const result = evaluateAssertionExpression(a.expr, {
        status: resp.status,
        body: resp.text,
        json: parsed,
        Array
      });
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
    const preferredProvider = selectedModelProvider === MODEL_PROVIDERS.gemini
      ? MODEL_PROVIDERS.openrouter
      : selectedModelProvider;
    const preferredModel = preferredProvider === MODEL_PROVIDERS.groq
      ? selectedGroqModel
      : preferredProvider === MODEL_PROVIDERS.gemini
        ? GEMINI_MODELS.default
        : OPENROUTER_MODELS.default;
    const parsed = await callBackendJson(BACKEND_ENDPOINTS.assertions, {
      status: lastResponse.status,
      body_preview: preview,
      provider: preferredProvider,
      model: preferredModel
    });
    const arr = Array.isArray(parsed?.assertions) ? parsed.assertions : [];
    if (!arr.length) return;
    const r = getActive();
    r.assertions = arr.map(expr => ({ expr, status: 'pending' }));
    renderAssertions(r.assertions);
    switchTab('assertions');
    addAgentMsg('system', `Generated ${arr.length} assertions. Check the Assertions tab to review and run them.`);
  } catch (error) {
    logError('assertions', `Automatic assertion generation failed: ${error.message}`);
    addAgentMsg('system', `Automatic assertion generation failed: ${escHtml(error.message)}.`, [], { track: false });
  }
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
  if (selectedModelProvider === MODEL_PROVIDERS.groq) {
    return selectedGroqModel;
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

function normalizeAgentActionsStrict(actions) {
  const source = Array.isArray(actions) ? actions : [];
  const normalized = [];
  const invalidIndexes = [];

  source.forEach((action, index) => {
    const parsed = validateAndNormalizeAction(action);
    if (!parsed) invalidIndexes.push(index);
    else normalized.push(parsed);
  });

  return {
    normalized,
    invalidIndexes,
    invalidCount: invalidIndexes.length
  };
}

function normalizeSecurityActionsStrict(actions) {
  const source = Array.isArray(actions) ? actions : [];
  const normalized = [];
  const invalidIndexes = [];

  source.forEach((action, index) => {
    const parsed = normalizeSecurityAction(action);
    if (!parsed) invalidIndexes.push(index);
    else normalized.push(parsed);
  });

  return {
    normalized,
    invalidIndexes,
    invalidCount: invalidIndexes.length
  };
}

// AGENT
document.getElementById('agent-send-btn').addEventListener('click', askAgent);
document.getElementById('agent-input').addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); askAgent(); }
});
document.getElementById('agent-input').addEventListener('input', renderAgentCharCount);

function addAgentMsg(role, text, chips = [], options = {}) {
  const { track = true } = options;
  const el = document.getElementById('agent-messages');
  const roleLabels = { user: 'You', agent: 'Agent', system: 'System', error: 'Error' };
  const div = document.createElement('div');
  div.className = `msg ${role}`;
  const roleEl = document.createElement('div');
  roleEl.className = 'msg-role';
  roleEl.textContent = roleLabels[role] || role;
  const bubbleEl = document.createElement('div');
  bubbleEl.className = 'msg-bubble';
  setBubbleContent(bubbleEl, text);
  div.appendChild(roleEl);
  div.appendChild(bubbleEl);
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
  if (role === 'error') {
    const plainText = String(text || '').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
    logError('agent', plainText || 'Agent error');
  }
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

function quickPrompt(text) {
  document.getElementById('agent-input').value = text;
  renderAgentCharCount();
  askAgent();
}

function runSelectedAgentAction() {
  const selectEl = document.getElementById('agent-action-select');
  if (!selectEl) return;
  const value = selectEl.value;
  if (!value) return;

  if (value.startsWith('prompt:')) {
    selectEl.value = '';
    quickPrompt(value.slice(7));
    return;
  }

  if (value === 'component-prompt') {
    loadComponentIntegrationPrompt();
  } else if (value === 'security-target') {
    promptSecurityTarget();
  } else if (value === 'new-chat') {
    startNewChat();
  }

  selectEl.value = '';
}

function describeActiveModel() {
  if (selectedModelProvider === MODEL_PROVIDERS.groq) return `Groq / ${selectedGroqModel}`;
  if (selectedModelProvider === MODEL_PROVIDERS.gemini) return 'Gemini';
  return 'OpenRouter';
}

function formatDiagnosticsLabel(diagnostics) {
  const provider = String(diagnostics?.provider || '').trim();
  const model = String(diagnostics?.model || '').trim();
  const requestedProvider = String(diagnostics?.requested_provider || '').trim();

  if (!provider && !model) return '';
  const providerLabel = provider ? provider.charAt(0).toUpperCase() + provider.slice(1) : 'Unknown';
  const base = model ? `${providerLabel} / ${model}` : providerLabel;

  if (requestedProvider && provider && requestedProvider !== provider) {
    const requestedLabel = requestedProvider.charAt(0).toUpperCase() + requestedProvider.slice(1);
    return `Resolved with ${base} (fallback from ${requestedLabel}).`;
  }
  return `Resolved with ${base}.`;
}

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
  renderAgentCharCount();
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

    const diagnosticsLabel = formatDiagnosticsLabel(raw?.diagnostics);
    if (diagnosticsLabel) {
      addAgentMsg('system', diagnosticsLabel, [], { track: false });
    }

    const parsed = parseSecurityPayload(raw);
    const actionBatch = normalizeSecurityActionsStrict(parsed.actions || []);
    if (actionBatch.invalidCount > 0) {
      addAgentMsg('error', `Blocked malformed security action batch at indexes: ${actionBatch.invalidIndexes.join(', ')}.`);
      break;
    }
    const normalizedActions = actionBatch.normalized;
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
  renderAgentCharCount();
  if (!chatGoal) chatGoal = initialUserMsg;

  addAgentMsg('user', initialUserMsg);
  addAgentMsg('system', `Using model: ${describeActiveModel()}.`, [], { track: false });
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

      const diagnosticsLabel = formatDiagnosticsLabel(raw?.diagnostics);
      if (diagnosticsLabel) {
        addAgentMsg('system', diagnosticsLabel, [], { track: false });
      }

      const parsed = parseAgentPayload(raw);
      const chips = [];
      let didAutoSend = false;

      const actionBatch = normalizeAgentActionsStrict(parsed.actions || []);
      if (actionBatch.invalidCount > 0) {
        addAgentMsg('error', `Blocked malformed agent action batch at indexes: ${actionBatch.invalidIndexes.join(', ')}.`);
        break;
      }
      const normalizedActions = actionBatch.normalized;

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
            if (['GET', 'HEAD', 'OPTIONS'].includes(setRequestAction.method)) {
              addAgentMsg('system', `Auto-sending request generated by the agent (step ${step + 1}).`);
              await sendRequest();
              didAutoSend = true;
            } else {
              chips.push({
                label: `Review before sending ${setRequestAction.method}`,
                cls: 'apply',
                fn: () => sendRequest({ confirmMutation: true })
              });
              addAgentMsg('system', `Agent generated a mutating request (${setRequestAction.method}). Review it before sending.`, [], { track: false });
            }
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
  const provider = options.providerOverride || selectedModelProvider;
  const model = options.modelOverride || (
    provider === MODEL_PROVIDERS.gemini ? GEMINI_MODELS.security :
    provider === MODEL_PROVIDERS.groq ? GROQ_MODELS.security :
    OPENROUTER_MODELS.security
  );
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
  if (data?.diagnostics) {
    logStructuredDiagnostics(path, data.diagnostics);
  }
  return data;
}

function createFluidNoise() {
  const permutation = [
    151, 160, 137, 91, 90, 15, 131, 13, 201, 95, 96, 53, 194, 233, 7, 225, 140,
    36, 103, 30, 69, 142, 8, 99, 37, 240, 21, 10, 23, 190, 6, 148, 247, 120,
    234, 75, 0, 26, 197, 62, 94, 252, 219, 203, 117, 35, 11, 32, 57, 177, 33,
    88, 237, 149, 56, 87, 174, 20, 125, 136, 171, 168, 68, 175, 74, 165, 71,
    134, 139, 48, 27, 166, 77, 146, 158, 231, 83, 111, 229, 122, 60, 211, 133,
    230, 220, 105, 92, 41, 55, 46, 245, 40, 244, 102, 143, 54, 65, 25, 63, 161,
    1, 216, 80, 73, 209, 76, 132, 187, 208, 89, 18, 169, 200, 196, 135, 130,
    116, 188, 159, 86, 164, 100, 109, 198, 173, 186, 3, 64, 52, 217, 226, 250,
    124, 123, 5, 202, 38, 147, 118, 126, 255, 82, 85, 212, 207, 206, 59, 227,
    47, 16, 58, 17, 182, 189, 28, 42, 223, 183, 170, 213, 119, 248, 152, 2, 44,
    154, 163, 70, 221, 153, 101, 155, 167, 43, 172, 9, 129, 22, 39, 253, 19, 98,
    108, 110, 79, 113, 224, 232, 178, 185, 112, 104, 218, 246, 97, 228, 251, 34,
    242, 193, 238, 210, 144, 12, 191, 179, 162, 241, 81, 51, 145, 235, 249, 14,
    239, 107, 49, 192, 214, 31, 181, 199, 106, 157, 184, 84, 204, 176, 115, 121,
    50, 45, 127, 4, 150, 254, 138, 236, 205, 93, 222, 114, 67, 29, 24, 72, 243,
    141, 128, 195, 78, 66, 215, 61, 156, 180
  ];

  const p = new Array(512);
  for (let i = 0; i < 256; i += 1) p[256 + i] = p[i] = permutation[i];

  function fade(t) {
    return t * t * t * (t * (t * 6 - 15) + 10);
  }

  function lerp(t, a, b) {
    return a + t * (b - a);
  }

  function grad(hash, x, y, z) {
    const h = hash & 15;
    const u = h < 8 ? x : y;
    const v = h < 4 ? y : h === 12 || h === 14 ? x : z;
    return ((h & 1) === 0 ? u : -u) + ((h & 2) === 0 ? v : -v);
  }

  return {
    simplex3(x, y, z) {
      const X = Math.floor(x) & 255;
      const Y = Math.floor(y) & 255;
      const Z = Math.floor(z) & 255;

      x -= Math.floor(x);
      y -= Math.floor(y);
      z -= Math.floor(z);

      const u = fade(x);
      const v = fade(y);
      const w = fade(z);

      const A = p[X] + Y;
      const AA = p[A] + Z;
      const AB = p[A + 1] + Z;
      const B = p[X + 1] + Y;
      const BA = p[B] + Z;
      const BB = p[B + 1] + Z;

      return lerp(
        w,
        lerp(
          v,
          lerp(u, grad(p[AA], x, y, z), grad(p[BA], x - 1, y, z)),
          lerp(u, grad(p[AB], x, y - 1, z), grad(p[BB], x - 1, y - 1, z))
        ),
        lerp(
          v,
          lerp(u, grad(p[AA + 1], x, y, z - 1), grad(p[BA + 1], x - 1, y, z - 1)),
          lerp(u, grad(p[AB + 1], x, y - 1, z - 1), grad(p[BB + 1], x - 1, y - 1, z - 1))
        )
      );
    }
  };
}

function initFluidBackground() {
  const canvas = document.getElementById('fluid-bg-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d', { alpha: true });
  if (!ctx) return;

  const noise = createFluidNoise();
  const particles = [];
  let animationFrameId = 0;

  function resizeCanvas() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }

  resizeCanvas();

  const particleCount = Math.min(1800, Math.max(900, Math.floor((canvas.width * canvas.height) / 850)));
  for (let i = 0; i < particleCount; i += 1) {
    particles.push({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      size: Math.random() * 1.8 + 0.4,
      velocity: { x: 0, y: 0 },
      life: Math.random() * 100,
      maxLife: 100 + Math.random() * 80
    });
  }

  function animate() {
    ctx.fillStyle = 'rgba(5, 7, 11, 0.16)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    const time = Date.now() * 0.0001;
    for (const particle of particles) {
      particle.life += 1;
      if (particle.life > particle.maxLife) {
        particle.life = 0;
        particle.x = Math.random() * canvas.width;
        particle.y = Math.random() * canvas.height;
      }

      const opacity = Math.sin((particle.life / particle.maxLife) * Math.PI) * 0.15;
      const flow = noise.simplex3(particle.x * 0.0028, particle.y * 0.0028, time);
      const angle = flow * Math.PI * 4;

      particle.velocity.x = Math.cos(angle) * 1.7;
      particle.velocity.y = Math.sin(angle) * 1.7;
      particle.x += particle.velocity.x;
      particle.y += particle.velocity.y;

      if (particle.x < 0) particle.x = canvas.width;
      if (particle.x > canvas.width) particle.x = 0;
      if (particle.y < 0) particle.y = canvas.height;
      if (particle.y > canvas.height) particle.y = 0;

      ctx.fillStyle = `rgba(255, 255, 255, ${opacity})`;
      ctx.beginPath();
      ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
      ctx.fill();
    }

    animationFrameId = window.requestAnimationFrame(animate);
  }

  function handleResize() {
    resizeCanvas();
  }

  window.addEventListener('resize', handleResize);
  animate();

  return () => {
    window.cancelAnimationFrame(animationFrameId);
    window.removeEventListener('resize', handleResize);
  };
}

// New request
document.getElementById('new-req-btn').addEventListener('click', () => {
  saveActive();
  const newReq = { id: idCounter++, name: 'New Request', method: 'GET', url: '', params: [], headers: [], body: '', assertions: [], chainOf: null };
  requests.push(newReq);
  activeId = newReq.id;
  loadActive(); renderSidebar();
});

document.getElementById('clear-errors-btn').addEventListener('click', clearErrorLogs);

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
(async function initApp() {
  initFluidBackground();
  loadModelPreferences();
  await loadRuntimeConfig();
  loadActive();
  renderWelcomeMessage();
  loadComponentIntegrationPrompt({ overwrite: false });
  renderAgentPanelState();
  renderAgentCharCount();
  renderSidebar();
  renderModelProvider();
  renderScanPaceControl();
  renderAgentMode();
  syncAgentRunControls();
  renderScanProgress();
})();
