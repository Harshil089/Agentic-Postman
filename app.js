const OPENROUTER_QWEN_DEFAULT_MODEL = 'qwen/qwen3.6-plus:free';
let OPENROUTER_MODELS = {
  default: OPENROUTER_QWEN_DEFAULT_MODEL,
  advanced: OPENROUTER_QWEN_DEFAULT_MODEL,
  security: OPENROUTER_QWEN_DEFAULT_MODEL
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
  config: '/api/config',
  importOpenapi: '/api/import-openapi',
  importPostman: '/api/import-postman'
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
let lastComparisonResult = null;
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
let requestHistoryEntries = [];
let environments = [];
let activeEnvironmentId = 'default';
let snapshots = [];
let scanPaceSetting = '0';
let adaptiveScanPacingMs = 2000;
let agentPanelOpen = true;
let compareSnapshotsOnSend = true;
let requestHistoryIdCounter = 1;
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
  scanPaceSetting: 'agentman:scanPaceSetting',
  workspace: 'agentman:workspace'
};

const SCAN_PACE_VALUES = new Set(['0', '2000', '5000', '8000', 'adaptive']);
const SCAN_PROFILE_VALUES = new Set(['quick', 'standard', 'deep']);
let securityScanProfile = 'standard';
const WORKSPACE_SCHEMA_VERSION = 2;
const WORKSPACE_HISTORY_LIMIT = 60;
const WORKSPACE_TEXT_PREVIEW_LIMIT = 320;
const DEFAULT_ENVIRONMENT_ID = 'default';
const workspaceUtils = (typeof window !== 'undefined' && window.AgentmanWorkspaceUtils)
  ? window.AgentmanWorkspaceUtils
  : {
      summarizePreview: (text, limit = WORKSPACE_TEXT_PREVIEW_LIMIT) => {
        const value = String(text || '').trim();
        if (!value) return '';
        return value.length > limit ? `${value.slice(0, limit).trimEnd()}...` : value;
      },
      describeRequestDiff: () => 'request: no changes; response: no previous run',
      resolveChainTemplate: (url) => url,
      resolveVariableTemplate: (text) => text
    };

function createDefaultEnvironment() {
  return {
    id: DEFAULT_ENVIRONMENT_ID,
    name: 'Default',
    variables: [{ k: 'baseUrl', v: '' }],
    headers: []
  };
}

function cloneSerializable(value) {
  if (value == null) return value;
  try {
    return JSON.parse(JSON.stringify(value));
  } catch {
    return null;
  }
}

function sanitizeKeyValueEntries(entries) {
  return Array.isArray(entries)
    ? entries
        .map(entry => ({
          k: typeof entry?.k === 'string' ? entry.k : '',
          v: typeof entry?.v === 'string' ? entry.v : ''
        }))
        .filter(entry => entry.k || entry.v)
    : [];
}

function sanitizeAssertionEntries(assertions) {
  return Array.isArray(assertions)
    ? assertions
        .map(entry => ({
          expr: typeof entry?.expr === 'string' ? entry.expr : '',
          status: typeof entry?.status === 'string' ? entry.status : 'pending',
          error: typeof entry?.error === 'string' ? entry.error : ''
        }))
        .filter(entry => entry.expr)
    : [];
}

function normalizeImportMeta(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const source = typeof raw.source === 'string' ? raw.source : '';
  const param_candidates = Array.isArray(raw.param_candidates)
    ? raw.param_candidates.filter(x => typeof x === 'string').slice(0, 40)
    : [];
  if (!source && !param_candidates.length) return null;
  return { source, param_candidates };
}

function normalizeRequestRecord(record, fallbackId) {
  const source = record && typeof record === 'object' ? record : {};
  const numericId = Number(source.id);
  const id = Number.isFinite(numericId) && numericId > 0 ? numericId : fallbackId;
  const method = typeof source.method === 'string' ? source.method.toUpperCase() : 'GET';
  const importMeta = normalizeImportMeta(source.importMeta);
  return {
    id,
    name: typeof source.name === 'string' && source.name.trim() ? source.name : `Request ${id}`,
    method: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(method) ? method : 'GET',
    url: typeof source.url === 'string' ? source.url : '',
    params: sanitizeKeyValueEntries(source.params),
    headers: sanitizeKeyValueEntries(source.headers),
    body: typeof source.body === 'string' ? source.body : '',
    assertions: sanitizeAssertionEntries(source.assertions),
    chainOf: Number.isFinite(Number(source.chainOf)) ? Number(source.chainOf) : null,
    chainNote: typeof source.chainNote === 'string' ? source.chainNote : '',
    ...(importMeta ? { importMeta } : {})
  };
}

function normalizeConversationEntries(entries) {
  return Array.isArray(entries)
    ? entries
        .map(entry => ({
          role: typeof entry?.role === 'string' ? entry.role : 'system',
          text: typeof entry?.text === 'string' ? entry.text : ''
        }))
        .filter(entry => entry.text)
    : [];
}

function normalizeEnvironmentRecord(env, fallbackIndex) {
  const source = env && typeof env === 'object' ? env : {};
  const rawId = typeof source.id === 'string' ? source.id.trim() : '';
  const id = rawId || `env-${fallbackIndex}`;
  const name = typeof source.name === 'string' && source.name.trim() ? source.name.trim() : `Environment ${fallbackIndex}`;
  let variables = sanitizeKeyValueEntries(source.variables);
  if (!variables.some(entry => entry.k === 'baseUrl')) {
    variables = [{ k: 'baseUrl', v: '' }, ...variables];
  }
  return {
    id,
    name,
    variables,
    headers: sanitizeKeyValueEntries(source.headers)
  };
}

function normalizeGenericLogEntries(entries) {
  return Array.isArray(entries) ? entries.map(entry => cloneSerializable(entry)).filter(Boolean) : [];
}

function normalizeHistoryEntry(entry) {
  const source = entry && typeof entry === 'object' ? entry : {};
  const requestSnapshot = normalizeRequestRecord(source.requestSnapshot || source.request || {}, Number(source.requestId || 1));
  const numericStatus = Number(source.status);
  const numericElapsed = Number(source.elapsed_ms);
  return {
    id: typeof source.id === 'string' && source.id.trim() ? source.id : `history-${requestHistoryIdCounter++}`,
    requestId: requestSnapshot.id,
    requestName: typeof source.requestName === 'string' && source.requestName.trim() ? source.requestName : requestSnapshot.name,
    method: typeof source.method === 'string' && source.method.trim() ? source.method : requestSnapshot.method,
    url: typeof source.url === 'string' && source.url.trim() ? source.url : requestSnapshot.url,
    status: Number.isFinite(numericStatus) ? numericStatus : 0,
    statusText: typeof source.statusText === 'string' ? source.statusText : '',
    elapsed_ms: Number.isFinite(numericElapsed) ? numericElapsed : 0,
    responsePreview: typeof source.responsePreview === 'string' ? source.responsePreview : '',
    diffSummary: typeof source.diffSummary === 'string' ? source.diffSummary : '',
    createdAt: typeof source.createdAt === 'string' && source.createdAt.trim() ? source.createdAt : new Date().toISOString(),
    requestSnapshot,
    responseHeaders: source.responseHeaders && typeof source.responseHeaders === 'object' ? cloneSerializable(source.responseHeaders) || {} : {}
  };
}

function normalizeSnapshotRecord(snapshot) {
  const source = snapshot && typeof snapshot === 'object' ? snapshot : {};
  return {
    id: typeof source.id === 'string' && source.id.trim() ? source.id : `snap-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
    requestId: Number.isFinite(Number(source.requestId)) ? Number(source.requestId) : 0,
    environmentId: typeof source.environmentId === 'string' ? source.environmentId : DEFAULT_ENVIRONMENT_ID,
    createdAt: typeof source.createdAt === 'string' && source.createdAt.trim() ? source.createdAt : new Date().toISOString(),
    assertions: sanitizeAssertionEntries(source.assertions),
    status: Number.isFinite(Number(source.status)) ? Number(source.status) : 0,
    statusText: typeof source.statusText === 'string' ? source.statusText : '',
    elapsedMs: Number.isFinite(Number(source.elapsedMs)) ? Number(source.elapsedMs) : 0,
    responseBodyHash: typeof source.responseBodyHash === 'string' ? source.responseBodyHash : '',
    responseHeaders: source.responseHeaders && typeof source.responseHeaders === 'object' ? cloneSerializable(source.responseHeaders) || {} : {},
    responsePreviewFirst: typeof source.responsePreviewFirst === 'string' ? source.responsePreviewFirst : '',
    notes: typeof source.notes === 'string' ? source.notes.slice(0, 200) : ''
  };
}

function migrateWorkspaceV1toV2(v1State) {
  return {
    ...cloneSerializable(v1State),
    version: 2,
    snapshots: []
  };
}

function summarizePreview(text, limit = WORKSPACE_TEXT_PREVIEW_LIMIT) {
  return workspaceUtils.summarizePreview(text, limit);
}

function describeRequestDiff(previousRequest, currentRequest, previousResponse, currentResponse) {
  return workspaceUtils.describeRequestDiff(previousRequest, currentRequest, previousResponse, currentResponse);
}

function buildWorkspaceState() {
  return {
    version: WORKSPACE_SCHEMA_VERSION,
    requests: requests.map(request => cloneSerializable(request)).filter(Boolean),
    activeId,
    idCounter,
    chatGoal,
    conversationHistory: cloneSerializable(conversationHistory) || [],
    securityTestHistory: cloneSerializable(securityTestHistory) || [],
    errorLogEntries: cloneSerializable(errorLogEntries) || [],
    structuredDiagnosticsEntries: cloneSerializable(structuredDiagnosticsEntries) || [],
    requestHistoryEntries: cloneSerializable(requestHistoryEntries) || [],
    requestHistoryIdCounter,
    environments: cloneSerializable(environments) || [],
    activeEnvironmentId,
    snapshots: cloneSerializable(snapshots) || [],
    ui: {
      activeSidebarWindow,
      agentMode,
      selectedModelProvider,
      selectedGroqModel,
      scanPaceSetting,
      adaptiveScanPacingMs,
      agentPanelOpen,
      securityScanProfile,
      compareSnapshotsOnSend
    }
  };
}

function saveWorkspaceState() {
  try {
    localStorage.setItem(STORAGE_KEYS.workspace, JSON.stringify(buildWorkspaceState()));
  } catch {}
}

function loadWorkspaceState() {
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.workspace);
    if (!raw) return false;
    let stored = parseJsonSafely(raw);
    if (!stored || typeof stored !== 'object') return false;
    
    // Migrate from v1 to v2 if needed
    const storedVersion = Number(stored.version);
    if (storedVersion === 1) {
      stored = migrateWorkspaceV1toV2(stored);
    }
    
    if (Number(stored.version) !== WORKSPACE_SCHEMA_VERSION) return false;

    const restoredRequests = Array.isArray(stored.requests)
      ? stored.requests.map((request, index) => normalizeRequestRecord(request, index + 1))
      : [];
    requests = restoredRequests.length ? restoredRequests : [normalizeRequestRecord({ id: 1, name: 'New Request' }, 1)];

    const maxRequestId = requests.reduce((max, request) => Math.max(max, Number(request.id) || 0), 0);
    const storedActiveId = Number(stored.activeId);
    activeId = requests.some(request => request.id === storedActiveId) ? storedActiveId : requests[0].id;
    idCounter = Math.max(maxRequestId + 1, Number(stored.idCounter) || 0, 1);

    chatGoal = typeof stored.chatGoal === 'string' ? stored.chatGoal : chatGoal;
    conversationHistory = normalizeConversationEntries(stored.conversationHistory).slice(-40);
    securityTestHistory = normalizeGenericLogEntries(stored.securityTestHistory).slice(-80);
    errorLogEntries = normalizeGenericLogEntries(stored.errorLogEntries).slice(-200);
    structuredDiagnosticsEntries = normalizeGenericLogEntries(stored.structuredDiagnosticsEntries).slice(-200);
    requestHistoryEntries = Array.isArray(stored.requestHistoryEntries)
      ? stored.requestHistoryEntries.map(entry => normalizeHistoryEntry(entry)).slice(-WORKSPACE_HISTORY_LIMIT)
      : [];
    requestHistoryIdCounter = Math.max(Number(stored.requestHistoryIdCounter) || 1, requestHistoryEntries.length + 1);
    environments = Array.isArray(stored.environments)
      ? stored.environments.map((env, index) => normalizeEnvironmentRecord(env, index + 1))
      : [createDefaultEnvironment()];
    if (!environments.length) environments = [createDefaultEnvironment()];
    const storedEnvironmentId = typeof stored.activeEnvironmentId === 'string' ? stored.activeEnvironmentId : DEFAULT_ENVIRONMENT_ID;
    activeEnvironmentId = environments.some(env => env.id === storedEnvironmentId)
      ? storedEnvironmentId
      : environments[0].id;

    snapshots = Array.isArray(stored.snapshots)
      ? stored.snapshots.map(snap => normalizeSnapshotRecord(snap))
      : [];

    const ui = stored.ui && typeof stored.ui === 'object' ? stored.ui : {};
    if (typeof ui.activeSidebarWindow === 'string' && ['requests', 'history', 'errors', 'diagnostics'].includes(ui.activeSidebarWindow)) {
      activeSidebarWindow = ui.activeSidebarWindow;
    }
    if (typeof ui.agentMode === 'string' && AGENT_MODE_META[ui.agentMode]) {
      agentMode = ui.agentMode;
    }
    if (Object.values(MODEL_PROVIDERS).includes(ui.selectedModelProvider)) {
      selectedModelProvider = ui.selectedModelProvider;
    }
    if (typeof ui.selectedGroqModel === 'string' && GROQ_MODEL_OPTIONS.includes(ui.selectedGroqModel)) {
      selectedGroqModel = ui.selectedGroqModel;
    }
    if (SCAN_PACE_VALUES.has(ui.scanPaceSetting)) {
      scanPaceSetting = ui.scanPaceSetting;
    }
    if (Number.isFinite(Number(ui.adaptiveScanPacingMs))) {
      adaptiveScanPacingMs = Number(ui.adaptiveScanPacingMs);
    }
    if (typeof ui.agentPanelOpen === 'boolean') {
      agentPanelOpen = ui.agentPanelOpen;
    }
    if (SCAN_PROFILE_VALUES.has(ui.securityScanProfile)) {
      securityScanProfile = ui.securityScanProfile;
    }
    if (typeof ui.compareSnapshotsOnSend === 'boolean') {
      compareSnapshotsOnSend = ui.compareSnapshotsOnSend;
    }
    renderEnvironmentEditor();
    return true;
  } catch {
    environments = [createDefaultEnvironment()];
    activeEnvironmentId = DEFAULT_ENVIRONMENT_ID;
    snapshots = [];
    return false;
  }
}

function recordRequestHistoryEntry(request, response) {
  if (!request || !response || typeof response.status !== 'number') return null;
  const requestSnapshot = normalizeRequestRecord(cloneSerializable(request) || request, request.id || idCounter);
  const previousEntry = [...requestHistoryEntries].reverse().find(entry => entry.requestId === requestSnapshot.id);
  const responsePreview = summarizePreview(response.text, WORKSPACE_TEXT_PREVIEW_LIMIT);
  const nextEntry = {
    id: `history-${requestHistoryIdCounter++}`,
    requestId: requestSnapshot.id,
    requestName: requestSnapshot.name,
    method: requestSnapshot.method,
    url: requestSnapshot.url,
    status: response.status,
    statusText: typeof response.statusText === 'string' ? response.statusText : '',
    elapsed_ms: Number(response.elapsed || response.elapsed_ms || 0),
    responsePreview,
    diffSummary: describeRequestDiff(previousEntry?.requestSnapshot, requestSnapshot, previousEntry, {
      status: response.status,
      elapsed_ms: Number(response.elapsed || response.elapsed_ms || 0),
      responsePreview
    }),
    createdAt: new Date().toISOString(),
    requestSnapshot,
    responseHeaders: response.headers && typeof response.headers === 'object' ? cloneSerializable(response.headers) || {} : {}
  };
  requestHistoryEntries.push(nextEntry);
  if (requestHistoryEntries.length > WORKSPACE_HISTORY_LIMIT) {
    requestHistoryEntries = requestHistoryEntries.slice(-WORKSPACE_HISTORY_LIMIT);
  }
  saveWorkspaceState();
  renderSidebarWindowNav();
  if (activeSidebarWindow === 'history') renderSidebar();
  return nextEntry;
}

function replayHistoryEntry(entryId) {
  const entry = requestHistoryEntries.find(item => item.id === entryId);
  if (!entry) return;
  saveActive();
  const activeRequest = getActive();
  if (!activeRequest) return;
  const restored = normalizeRequestRecord(entry.requestSnapshot, activeRequest.id);
  restored.id = activeRequest.id;
  const index = requests.findIndex(request => request.id === activeRequest.id);
  if (index >= 0) {
    requests[index] = restored;
  }
  loadActive();
  renderSidebar();
  saveWorkspaceState();
  addAgentMsg('system', `Replayed history entry for ${restored.method} ${restored.url || '(empty URL)'}.`, [], { track: false });
}

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
    if (storedSidebarWindow === 'requests' || storedSidebarWindow === 'history' || storedSidebarWindow === 'errors' || storedSidebarWindow === 'diagnostics') {
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

function renderSecurityScanProfileControl() {
  const selectEl = document.getElementById('scan-profile-select');
  if (!selectEl) return;
  if (!SCAN_PROFILE_VALUES.has(securityScanProfile)) {
    securityScanProfile = 'standard';
  }
  selectEl.value = securityScanProfile;
}

function setSecurityScanProfile(raw) {
  const normalized = String(raw || '').trim();
  if (!SCAN_PROFILE_VALUES.has(normalized)) return;
  securityScanProfile = normalized;
  saveWorkspaceState();
  renderSecurityScanProfileControl();
  addAgentMsg('system', `Security scan profile: ${normalized} (affects context width and model guidance).`, [], { track: false });
}

function getActive() { return requests.find(r => r.id === activeId); }

function getActiveEnvironment() {
  const selected = environments.find(env => env.id === activeEnvironmentId);
  if (selected) return selected;
  if (!environments.length) {
    environments = [createDefaultEnvironment()];
  }
  activeEnvironmentId = environments[0].id;
  return environments[0];
}

function getEnvironmentVariableMap(environment) {
  const env = environment || getActiveEnvironment();
  const map = {};
  (env?.variables || []).forEach(entry => {
    if (!entry || typeof entry.k !== 'string') return;
    const key = entry.k.trim();
    if (!key) return;
    map[key] = typeof entry.v === 'string' ? entry.v : '';
  });
  return map;
}

function resolveEnvironmentTemplate(text, variableMap) {
  return workspaceUtils.resolveVariableTemplate(text, variableMap, true);
}

function mergeEnvironmentHeaders(targetHeaders, environment) {
  const merged = targetHeaders && typeof targetHeaders === 'object' ? targetHeaders : {};
  const existingLower = new Set(Object.keys(merged).map(key => key.toLowerCase()));
  (environment?.headers || []).forEach(entry => {
    const key = String(entry?.k || '').trim();
    if (!key || existingLower.has(key.toLowerCase())) return;
    merged[key] = String(entry?.v || '');
  });
  return merged;
}

function joinBaseUrl(baseUrl, pathPart) {
  const base = String(baseUrl || '').trim();
  const path = String(pathPart || '').trim();
  if (!base || !path || /^https?:\/\//i.test(path)) return path;
  const left = base.endsWith('/') ? base.slice(0, -1) : base;
  const right = path.startsWith('/') ? path : `/${path}`;
  return `${left}${right}`;
}

function saveEnvironmentFromEditor() {
  const env = getActiveEnvironment();
  if (!env) return;
  env.variables = readKVTable('env-vars-body');
  if (!env.variables.some(entry => entry.k === 'baseUrl')) {
    env.variables = [{ k: 'baseUrl', v: '' }, ...env.variables];
  }
  env.headers = readKVTable('env-headers-body');
  saveWorkspaceState();
}

function renderEnvironmentEditor() {
  const select = document.getElementById('env-select');
  const varsBody = document.getElementById('env-vars-body');
  const headersBody = document.getElementById('env-headers-body');
  if (!select || !varsBody || !headersBody) return;

  if (!environments.length) {
    environments = [createDefaultEnvironment()];
  }
  if (!environments.some(env => env.id === activeEnvironmentId)) {
    activeEnvironmentId = environments[0].id;
  }

  select.innerHTML = environments
    .map(env => `<option value="${escHtml(env.id)}">${escHtml(env.name)}</option>`)
    .join('');
  select.value = activeEnvironmentId;

  const env = getActiveEnvironment();
  populateKVTable('env-vars-body', env.variables);
  populateKVTable('env-headers-body', env.headers);
}

function setActiveEnvironment(environmentId) {
  const id = String(environmentId || '').trim();
  if (!id || !environments.some(env => env.id === id)) return;
  saveEnvironmentFromEditor();
  activeEnvironmentId = id;
  renderEnvironmentEditor();
  saveWorkspaceState();
}

function createEnvironment() {
  const label = prompt('Environment name:', `Environment ${environments.length + 1}`);
  if (!label) return;
  saveEnvironmentFromEditor();
  const id = `env-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  environments.push({
    id,
    name: label.trim() || `Environment ${environments.length + 1}`,
    variables: [{ k: 'baseUrl', v: '' }],
    headers: []
  });
  activeEnvironmentId = id;
  renderEnvironmentEditor();
  saveWorkspaceState();
}

function deleteActiveEnvironment() {
  if (environments.length <= 1) {
    addAgentMsg('system', 'At least one environment is required.', [], { track: false });
    return;
  }
  const env = getActiveEnvironment();
  const proceed = confirm(`Delete environment "${env.name}"?`);
  if (!proceed) return;
  environments = environments.filter(item => item.id !== env.id);
  activeEnvironmentId = environments[0].id;
  renderEnvironmentEditor();
  saveWorkspaceState();
}

// ============ Snapshot (Regression) Functions ============

function getSnapshotKeyForRequest(requestId, envId = null) {
  const env = envId || activeEnvironmentId;
  return `${requestId}__${env}`;
}

async function saveCurrentResponseAsSnapshot(request, response, notes = '') {
  if (!request || !response) return null;
  
  // Compute body hash asynchronously
  let bodyHash = '';
  if (response.text && typeof response.text === 'string') {
    bodyHash = await workspaceUtils.computeSha256Hash(response.text);
  }

  const snapshot = {
    id: `snap-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
    requestId: request.id,
    environmentId: activeEnvironmentId,
    createdAt: new Date().toISOString(),
    assertions: request.assertions ? cloneSerializable(request.assertions) : [],
    status: Number(response.status) || 0,
    statusText: response.statusText || '',
    elapsedMs: Number(response.elapsed) || Number(response.elapsedMs) || 0,
    responseBodyHash: bodyHash,
    responseHeaders: response.headers && typeof response.headers === 'object' ? cloneSerializable(response.headers) : {},
    responsePreviewFirst: summarizePreview(response.text, WORKSPACE_TEXT_PREVIEW_LIMIT),
    notes: String(notes).slice(0, 200)
  };

  snapshots.push(snapshot);
  saveWorkspaceState();
  return snapshot;
}

function getSnapshotsForRequest(requestId, envId = null) {
  const env = envId || activeEnvironmentId;
  return snapshots
    .filter(s => s.requestId === requestId && s.environmentId === env)
    .sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));
}

function getSnapshotForRequest(requestId, envId = null) {
  const list = getSnapshotsForRequest(requestId, envId);
  return list.length ? list[0] : null;
}

async function compareCurrentResponseToSnapshot(request, response) {
  if (!request || !response) return null;
  if (!compareSnapshotsOnSend) return null;
  const snapshot = getSnapshotForRequest(request.id);
  if (!snapshot) return null;

  // Compute current response hash
  let bodyHash = '';
  if (response.text && typeof response.text === 'string') {
    bodyHash = await workspaceUtils.computeSha256Hash(response.text);
  }

  const responseWithHash = { ...response, bodyHash };
  return workspaceUtils.compareToSnapshot(request, responseWithHash, snapshot);
}

function deleteSnapshot(snapshotId) {
  snapshots = snapshots.filter(s => s.id !== snapshotId);
  saveWorkspaceState();
}

function exportSnapshotsForActiveRequest() {
  const activeRequest = getActive();
  if (!activeRequest) return;
  const payload = {
    version: WORKSPACE_SCHEMA_VERSION,
    exportedAt: new Date().toISOString(),
    requestId: activeRequest.id,
    requestName: activeRequest.name,
    snapshots: snapshots.filter(s => s.requestId === activeRequest.id)
  };
  const json = JSON.stringify(payload, null, 2);
  const blob = new window.Blob([json], { type: 'application/json' });
  const url = window.URL.createObjectURL(blob);
  const safeName = String(activeRequest.name || 'request').replace(/[^a-z0-9_-]+/gi, '-').replace(/^-+|-+$/g, '').toLowerCase() || 'request';
  const a = document.createElement('a');
  a.href = url;
  a.download = `snapshots-${safeName}-${activeRequest.id}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

function renderSnapshotsPanel() {
  const panel = document.getElementById('snapshots-panel');
  if (!panel) return;

  const activeRequest = getActive();
  if (!activeRequest) {
    panel.innerHTML = '<p style="padding: 12px; color: var(--text2);">No active request</p>';
    return;
  }

  const snapshot = getSnapshotForRequest(activeRequest.id);
  const snapshotList = getSnapshotsForRequest(activeRequest.id);
  const lastComparison = lastComparisonResult || null;

  let html = '<div class="snapshots-panel">';

  // Section 1: Current snapshot for this environment
  html += '<div class="snap-section">';
  html += '<h4 class="snap-section-title">Snapshots for this request</h4>';
  
  // Environment selector
  html += '<div class="snap-env-selector">';
  html += '<label>Environment: </label>';
  html += '<select id="snap-env-select" style="padding: 6px; margin-bottom: 8px;">';
  environments.forEach(env => {
    const selected = env.id === activeEnvironmentId ? 'selected' : '';
    html += `<option value="${env.id}" ${selected}>${env.name}</option>`;
  });
  html += '</select>';
  html += '</div>';

  if (snapshot) {
    const createdDate = new Date(snapshot.createdAt).toLocaleString();
    html += `<div style="font-size: 0.85rem; color: var(--text2); margin-bottom: 8px;">`;
    html += `Created: ${createdDate}<br>`;
    if (snapshot.notes) {
      html += `Notes: ${escHtml(snapshot.notes)}`;
    }
    html += `</div>`;
    html += `<button class="btn btn-small" id="delete-snapshot-btn" data-snapshot-id="${snapshot.id}">Delete Latest</button>`;
  } else {
    html += '<p style="color: var(--text2); font-size: 0.85rem;">No snapshot yet for this environment</p>';
  }
  html += `<button class="btn btn-small" id="export-snapshots-btn" style="margin-left:8px;">Export JSON</button>`;

  if (snapshotList.length > 0) {
    html += '<div style="margin-top: 10px; border-top: 1px solid var(--border); padding-top: 8px;">';
    html += '<div style="font-size: 0.8rem; color: var(--text2); margin-bottom: 6px;">Snapshot history (latest first)</div>';
    html += '<div style="display:flex; flex-direction:column; gap:6px; max-height:180px; overflow:auto;">';
    snapshotList.slice(0, 10).forEach((item, index) => {
      const dt = new Date(item.createdAt).toLocaleString();
      const hash = item.responseBodyHash ? item.responseBodyHash.slice(0, 8) : 'nohash';
      const notes = item.notes ? escHtml(item.notes) : '';
      html += '<div style="border:1px solid var(--border); border-radius:4px; padding:6px 8px;">';
      html += `<div style="font-size:0.8rem; color:var(--text2);">#${index + 1} ${dt}</div>`;
      html += `<div style="font-size:0.82rem;">${item.status} • ${item.elapsedMs}ms • ${hash}</div>`;
      if (notes) html += `<div style="font-size:0.78rem; color:var(--text2); margin-top:2px;">${notes}</div>`;
      html += `<button class="btn btn-small snap-delete-item-btn" data-snapshot-id="${item.id}" style="margin-top:6px;">Delete</button>`;
      html += '</div>';
    });
    html += '</div></div>';
  }
  html += '</div>';

  // Section 2: Save new snapshot
  html += '<div class="snap-section" style="margin-top: 16px;">';
  html += '<h4 class="snap-section-title">Save current response as snapshot</h4>';
  
  if (lastResponse) {
    const hash = lastResponse.bodyHash ? lastResponse.bodyHash.slice(0, 8) : 'N/A';
    html += `<div style="font-size: 0.85rem; color: var(--text2); margin-bottom: 8px;">`;
    html += `Status: ${lastResponse.status} ${lastResponse.statusText || ''}<br>`;
    html += `Elapsed: ${lastResponse.elapsed || 0} ms<br>`;
    html += `Body hash: ${hash}...`;
    html += `</div>`;
    
    html += `<textarea id="snap-notes-input" placeholder="Optional notes (max 200 chars)" style="width: 100%; height: 60px; margin-bottom: 8px; padding: 6px; border: 1px solid var(--border); border-radius: 4px; font-family: inherit; font-size: 0.9rem;" maxlength="200"></textarea>`;
    html += `<label style="display: flex; gap: 8px; margin-bottom: 8px; font-size: 0.9rem;">`;
    html += `<input type="checkbox" id="snap-compare-on-send" ${compareSnapshotsOnSend ? 'checked' : ''}>`;
    html += `Compare to snapshot on every send`;
    html += `</label>`;
    html += `<button class="btn btn-primary btn-small" id="save-snapshot-btn">Save snapshot</button>`;
  } else {
    html += '<p style="color: var(--text2); font-size: 0.85rem;">Send a request first to save a snapshot.</p>';
  }
  html += '</div>';

  // Section 3: Comparison result
  if (lastComparison) {
    html += '<div class="snap-section" style="margin-top: 16px;">';
    html += '<h4 class="snap-section-title">Comparison result</h4>';
    
    const badgeClass = lastComparison.matches ? 'snap-badge-match' : 'snap-badge-mismatch';
    const badgeText = lastComparison.matches ? '✓ Matches baseline' : '✗ Regression detected';
    html += `<div class="${badgeClass}" style="padding: 8px; margin-bottom: 12px; border-radius: 4px; font-weight: bold;">`;
    html += badgeText;
    html += `</div>`;

    if (lastComparison.notes) {
      html += `<p style="font-size: 0.85rem; color: var(--text2); margin: 0;">`;
      html += escHtml(lastComparison.notes);
      html += `</p>`;
    }

    if (!lastComparison.response.statusMatch) {
      const delta = lastComparison.response.statusDelta;
      html += `<p style="font-size: 0.8rem; color: #d64545; margin: 4px 0;">Status: ${delta.expected} → ${delta.actual}</p>`;
    }
    if (lastComparison.response.timingDelta) {
      const delta = lastComparison.response.timingDelta.delta;
      const sign = delta >= 0 ? '+' : '';
      html += `<p style="font-size: 0.8rem; color: var(--text2); margin: 4px 0;">Timing: ${sign}${delta}ms</p>`;
    }
    if (lastComparison.assertions.fail > 0) {
      html += `<p style="font-size: 0.8rem; color: #d64545; margin: 4px 0;">Failed assertions: ${lastComparison.assertions.fail}</p>`;
    }
    if (lastComparison.response.headerChanges.length > 0) {
      html += `<p style="font-size: 0.8rem; color: var(--text2); margin: 4px 0;">Header changes: ${lastComparison.response.headerChanges.map(h => `${h.key} (${h.status})`).join(', ')}</p>`;
    }

    html += '</div>';
  }

  html += '</div>';
  panel.innerHTML = html;

  // Event listeners
  const deleteBtn = panel.querySelector('#delete-snapshot-btn');
  if (deleteBtn) {
    deleteBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      const snapId = deleteBtn.getAttribute('data-snapshot-id');
      deleteSnapshot(snapId);
      renderSnapshotsPanel();
    });
  }
  panel.querySelectorAll('.snap-delete-item-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const snapId = btn.getAttribute('data-snapshot-id');
      deleteSnapshot(snapId);
      renderSnapshotsPanel();
    });
  });

  const exportBtn = panel.querySelector('#export-snapshots-btn');
  if (exportBtn) {
    exportBtn.addEventListener('click', (e) => {
      e.preventDefault();
      exportSnapshotsForActiveRequest();
    });
  }

  const saveBtn = panel.querySelector('#save-snapshot-btn');
  if (saveBtn) {
    saveBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      const notes = panel.querySelector('#snap-notes-input')?.value || '';
      await saveCurrentResponseAsSnapshot(activeRequest, lastResponse, notes);
      renderSnapshotsPanel();
      addAgentMsg('system', 'Snapshot saved.', [], { track: false });
    });
  }

  const envSelect = panel.querySelector('#snap-env-select');
  if (envSelect) {
    envSelect.addEventListener('change', (e) => {
      activeEnvironmentId = e.target.value;
      saveWorkspaceState();
      renderSnapshotsPanel();
    });
  }

  const compareToggle = panel.querySelector('#snap-compare-on-send');
  if (compareToggle) {
    compareToggle.addEventListener('change', (e) => {
      compareSnapshotsOnSend = Boolean(e.target.checked);
      saveWorkspaceState();
    });
  }
}

function renderSidebar() {
  renderSidebarWindowNav();
  renderSidebarHeader();
  if (activeSidebarWindow === 'errors') {
    renderErrorSidebar();
    return;
  }
  if (activeSidebarWindow === 'history') {
    renderRequestHistorySidebar();
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
  const historyBadge = document.getElementById('history-count-badge');
  if (historyBadge) historyBadge.textContent = String(requestHistoryEntries.length);
}

function renderSidebarHeader() {
  const title = document.getElementById('sidebar-title');
  const actionBtn = document.getElementById('new-req-btn');
  const clearErrorsBtn = document.getElementById('clear-errors-btn');
  if (title) {
    title.textContent = activeSidebarWindow === 'errors'
      ? 'Errors'
      : activeSidebarWindow === 'history'
        ? 'History'
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

function renderRequestHistorySidebar() {
  const list = document.getElementById('sidebar-list');
  if (!list) return;
  if (!requestHistoryEntries.length) {
    list.innerHTML = `<div class="error-empty">No request history yet.</div>`;
    return;
  }

  list.innerHTML = requestHistoryEntries
    .slice()
    .reverse()
    .map(entry => {
      const statusClass = entry.status >= 500 ? 's-5xx' : entry.status >= 400 ? 's-4xx' : 's-2xx';
      return `
        <div class="history-item">
          <div class="history-item-header">
            <span class="history-item-source">${escHtml(entry.requestName || entry.method || 'Request')}</span>
            <span class="history-item-time">${escHtml(entry.createdAt || '')}</span>
          </div>
          <div class="history-item-meta">
            <span class="history-chip m-${escHtml(entry.method || 'GET')}">${escHtml(entry.method || 'GET')}</span>
            <span class="history-chip ${statusClass}">${escHtml(String(entry.status || ''))}</span>
            <span class="history-chip">${escHtml(String(entry.elapsed_ms || 0))}ms</span>
          </div>
          <div class="history-item-body">${escHtml(entry.responsePreview || 'No response preview.')}</div>
          <div class="history-item-diff">${escHtml(entry.diffSummary || 'No diff summary available.')}</div>
          <div class="history-item-actions">
            <button class="history-replay-btn" type="button" onclick="replayHistoryEntry('${escHtml(entry.id)}')">Replay</button>
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
  if (windowName !== 'requests' && windowName !== 'history' && windowName !== 'errors' && windowName !== 'diagnostics') return;
  activeSidebarWindow = windowName;
  try {
    localStorage.setItem(STORAGE_KEYS.sidebarWindow, windowName);
  } catch {}
  saveWorkspaceState();
  renderSidebar();
}

function clearErrorLogs() {
  errorLogEntries = [];
  saveWorkspaceState();
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
  saveWorkspaceState();
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
  saveWorkspaceState();
  renderSidebarWindowNav();
  if (activeSidebarWindow === 'errors') {
    renderErrorSidebar();
  }
}

function selectRequest(id) {
  saveActive();
  activeId = id;
  loadActive();
  saveWorkspaceState();
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
  saveWorkspaceState();
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
  renderEnvironmentEditor();
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
  if (tbodyId === 'env-vars-body' || tbodyId === 'env-headers-body') {
    saveEnvironmentFromEditor();
  }
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
  saveWorkspaceState();
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
  saveWorkspaceState();
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
  saveWorkspaceState();
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
  saveWorkspaceState();
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
  saveEnvironmentFromEditor();
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

  const activeEnvironment = getActiveEnvironment();
  const envVarMap = getEnvironmentVariableMap(activeEnvironment);

  let url = resolveEnvironmentTemplate(r.url.trim(), envVarMap);
  if (/^\//.test(url) && !/^\/\//.test(url) && envVarMap.baseUrl) {
    url = joinBaseUrl(envVarMap.baseUrl, url);
  }

  const params = r.params
    .map(p => ({
      k: resolveEnvironmentTemplate(String(p?.k || ''), envVarMap),
      v: resolveEnvironmentTemplate(String(p?.v || ''), envVarMap)
    }))
    .filter(p => p.k);
  if (params.length) {
    const qs = params.map(p => `${encodeURIComponent(p.k)}=${encodeURIComponent(p.v)}`).join('&');
    url += (url.includes('?') ? '&' : '?') + qs;
  }
  url = resolveChainTemplate(url);

  const fetchOpts = { method: r.method, headers: {} };
  (r.headers || [])
    .map(h => ({
      k: resolveEnvironmentTemplate(String(h?.k || ''), envVarMap),
      v: resolveEnvironmentTemplate(String(h?.v || ''), envVarMap)
    }))
    .filter(h => h.k)
    .forEach(h => { fetchOpts.headers[h.k] = h.v; });
  mergeEnvironmentHeaders(fetchOpts.headers, {
    headers: (activeEnvironment?.headers || []).map(h => ({
      k: resolveEnvironmentTemplate(String(h?.k || ''), envVarMap),
      v: resolveEnvironmentTemplate(String(h?.v || ''), envVarMap)
    }))
  });
  if (r.body && ['POST','PUT','PATCH'].includes(r.method)) {
    fetchOpts.body = resolveEnvironmentTemplate(r.body, envVarMap);
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
    lastResponse.bodyHash = await workspaceUtils.computeSha256Hash(formatted);

    const stEl = document.getElementById('status-tag');
    stEl.textContent = `${data.status} ${data.statusText || ''}`.trim();
    stEl.className = 'status-tag ' + (data.status < 300 ? 's-2xx' : data.status < 500 ? 's-4xx' : 's-5xx');
    document.getElementById('time-tag').textContent = `${elapsed}ms`;
    document.getElementById('response-body').textContent = formatted;

    runAssertions(r.assertions, lastResponse);
    recordRequestHistoryEntry(r, lastResponse);

    lastComparisonResult = null;
    // Compare to regression snapshot if one exists
    lastComparisonResult = await compareCurrentResponseToSnapshot(r, lastResponse);
    
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
    || msg.includes('quota')
    || msg.includes('insufficient balance')
    || msg.includes('insufficient_balance')
    || msg.includes('credit');
}

function isQuotaBalanceErrorMessage(message) {
  const msg = String(message || '').toLowerCase();
  return msg.includes('insufficient balance')
    || msg.includes('insufficient_balance')
    || msg.includes('quota')
    || msg.includes('billing')
    || msg.includes('credit');
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
    scan_profile: SCAN_PROFILE_VALUES.has(securityScanProfile) ? securityScanProfile : 'standard',
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
    const rawSteps = Array.isArray(action.steps) ? action.steps : [];
    const steps = rawSteps.map((step, i) => ({
      order: Number(step?.order || i + 1),
      vector: typeof step?.vector === 'string' ? step.vector : 'Unknown',
      description: typeof step?.description === 'string' ? step.description : '',
      target_param: typeof step?.target_param === 'string' ? step.target_param : '',
      owasp_api_label: typeof step?.owasp_api_label === 'string' ? step.owasp_api_label : ''
    }));
    const param_matrix = Array.isArray(action.param_matrix)
      ? action.param_matrix
        .map(entry => ({
          param: typeof entry?.param === 'string' ? entry.param.trim() : '',
          location: ['query', 'body', 'header'].includes(String(entry?.location)) ? entry.location : 'query'
        }))
        .filter(entry => entry.param)
      : [];
    return {
      type: 'scan_plan',
      target: typeof action.target === 'string' ? action.target : '',
      method_coverage: Array.isArray(action.method_coverage) ? action.method_coverage : [],
      steps,
      param_matrix
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
    const owasp = item.owasp_api_label
      ? `<br><span class="security-owasp-label">OWASP: ${escHtml(item.owasp_api_label)}</span>`
      : '';
    const evidence = escHtml(item.evidence || 'No evidence supplied');
    const remediation = escHtml(item.remediation || 'No remediation supplied');
    return `<strong>${id} · ${name} (${sev})</strong>${owasp}<br>Evidence: ${evidence}<br>Fix: ${remediation}`;
  });

  addAgentMsg('agent', `<strong>Threat level:</strong> ${escHtml(String(threatLevel || 'none').toUpperCase())}<br><br>${lines.join('<br><br>')}`);
}

function renderScanPlan(action) {
  const methodCoverage = Array.isArray(action.method_coverage) ? action.method_coverage.join(', ') : '';
  const matrixLine = Array.isArray(action.param_matrix) && action.param_matrix.length
    ? `<br>Param matrix: ${escHtml(action.param_matrix.map(m => `${m.param} (${m.location})`).join(', '))}`
    : '';
  const steps = Array.isArray(action.steps)
    ? action.steps.map(step => {
        const order = Number(step?.order || 0);
        const vector = escHtml(step?.vector || 'Unknown');
        const description = escHtml(step?.description || '');
        const stepOwasp = step?.owasp_api_label
          ? ` <span class="security-owasp-label">[${escHtml(step.owasp_api_label)}]</span>`
          : '';
        return `${order > 0 ? `${order}. ` : ''}<strong>${vector}</strong>${stepOwasp} - ${description}`;
      }).join('<br>')
    : '';

  addAgentMsg('agent', `<strong>Security scan plan</strong><br>Target: ${escHtml(action.target || 'current endpoint')}<br>Methods: ${escHtml(methodCoverage || 'n/a')}${matrixLine}<br><br>${steps || 'No steps provided.'}`);
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
  saveWorkspaceState();
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

function resolveScanTargetUrl(scanPlan) {
  const activeUrl = String(getActive()?.url || '').trim();
  const scanTarget = String(scanPlan?.target || '').trim();
  const invalidTarget = !scanTarget
    || /api\.example\.com/i.test(scanTarget)
    || /\{id\}/i.test(scanTarget)
    || /\{.+\}/.test(scanTarget);

  if (!invalidTarget) return scanTarget;
  if (activeUrl) return activeUrl;
  return scanTarget || '';
}

function resolveProbeParamKey(vector, planStep, scanPlan, candidates) {
  const candList = Array.isArray(candidates) ? candidates : [];
  if (planStep && typeof planStep.target_param === 'string' && planStep.target_param.trim()) {
    return planStep.target_param.trim();
  }
  const matrix = Array.isArray(scanPlan?.param_matrix) ? scanPlan.param_matrix : [];
  const preferLoc = vector === 'NoSQLi' || vector === 'MassAssignment' || vector === 'SSRF' || vector === 'XXE'
    ? 'body'
    : 'query';
  const matrixHit = matrix.find(m => m.param && (m.location === preferLoc || !m.location));
  if (matrixHit && matrixHit.param) return matrixHit.param;

  const vectorDefaults = {
    IDOR: ['id', 'userId', 'user_id', 'resourceId'],
    BOLA: ['id', 'userId', 'resourceId'],
    SQLi: ['id', 'q', 'search', 'query', 'filter'],
    PathTraversal: ['file', 'path', 'filename', 'name', 'filepath'],
    NoSQLi: ['username', 'email', 'password'],
    ParameterPollution: ['id', 'q']
  };
  const defaults = vectorDefaults[vector] || ['id'];
  const hit = defaults.find(d => candList.includes(d));
  if (hit) return hit;
  const first = candList.find(Boolean);
  if (first) return first;
  return defaults[0] || 'id';
}

function evaluateFuzzSuccessIndicators(indicators, { status, text, elapsedMs }) {
  const ind = indicators && typeof indicators === 'object' ? indicators : {};
  const codes = Array.isArray(ind.status_codes) ? ind.status_codes.map(Number).filter(Number.isFinite) : [];
  const needles = Array.isArray(ind.body_contains) ? ind.body_contains.filter(Boolean) : [];
  const td = Number(ind.time_delta_ms);
  const hasAny = codes.length > 0 || needles.length > 0 || (Number.isFinite(td) && td > 0);
  if (!hasAny) return false;
  if (codes.length && !codes.includes(Number(status))) return false;
  if (needles.length && !needles.some(n => text.includes(n))) return false;
  if (Number.isFinite(td) && td > 0 && elapsedMs < td) return false;
  return true;
}

function buildFuzzRequestFromListAction(action, payload) {
  const r = getActive();
  if (!r) return null;
  const method = String(r.method || 'GET').toUpperCase();
  const loc = action.target_location || 'query';
  const param = action.target_param || 'id';
  if (loc === 'query') {
    const params = [...(r.params || [])];
    const idx = params.findIndex(p => p.k === param);
    if (idx >= 0) params[idx] = { ...params[idx], v: payload };
    else params.push({ k: param, v: payload });
    return { method, url: r.url, headers: [...(r.headers || [])], params, body: r.body || '' };
  }
  if (loc === 'header') {
    const headers = [...(r.headers || [])];
    const idx = headers.findIndex(h => String(h.k).toLowerCase() === String(param).toLowerCase());
    if (idx >= 0) headers[idx] = { ...headers[idx], v: payload };
    else headers.push({ k: param, v: payload });
    return { method, url: r.url, headers, params: [...(r.params || [])], body: r.body || '' };
  }
  if (loc === 'body') {
    let body = r.body || '';
    const headers = [...(r.headers || [])];
    const ct = headers.find(h => String(h.k).toLowerCase() === 'content-type');
    const isJson = (ct?.v || '').toLowerCase().includes('json') || body.trim().startsWith('{');
    if (isJson && body.trim()) {
      try {
        const obj = JSON.parse(body);
        if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
          body = JSON.stringify({ ...obj, [param]: payload }, null, 2);
        } else {
          body = payload;
        }
      } catch {
        body = payload;
      }
    } else {
      body = payload;
    }
    if (!headers.some(h => String(h.k).toLowerCase() === 'content-type') && ['POST', 'PUT', 'PATCH'].includes(method)) {
      headers.push({ k: 'Content-Type', v: 'application/json' });
    }
    return { method, url: r.url, headers, params: [...(r.params || [])], body };
  }
  return null;
}

async function executeFuzzListAction(action) {
  const payloads = Array.isArray(action.payloads) ? action.payloads : [];
  if (!payloads.length) {
    addAgentMsg('system', 'No payloads in fuzz list.');
    return;
  }
  const proceed = window.confirm(
    `Run ${payloads.length} fuzz requests (${action.target_location || 'query'}.${action.target_param || 'param'})?`
  );
  if (!proceed) return;

  const indicators = action.success_indicators || {};
  const matches = [];
  for (let i = 0; i < payloads.length; i += 1) {
    if (agentRunState.stopRequested) break;
    const payload = payloads[i];
    const built = buildFuzzRequestFromListAction(action, payload);
    if (!built) {
      addAgentMsg('error', 'Could not build fuzz request from the active request.');
      return;
    }
    applySetRequest({
      type: 'set_request',
      name: `Fuzz ${i + 1}/${payloads.length}`,
      method: built.method,
      url: built.url,
      headers: built.headers,
      params: built.params,
      body: built.body
    }, { skipMessage: true });

    const response = await sendRequest({
      confirmMutation: true,
      skipAutoAssertions: true
    });
    if (!response) {
      matches.push({ index: i + 1, payload, match: false, note: 'request failed', status: 0, elapsedMs: 0 });
    } else {
      const text = String(response.text || '');
      const elapsedMs = Number(response.elapsed || 0);
      const match = evaluateFuzzSuccessIndicators(indicators, {
        status: response.status,
        text,
        elapsedMs
      });
      matches.push({
        index: i + 1,
        payload,
        match,
        status: response.status,
        elapsedMs
      });
    }
    const delayMs = i < payloads.length - 1 ? Math.min(getCurrentScanPacingMs(), 3000) : 0;
    if (delayMs > 0) await waitMs(delayMs);
  }

  const hitCount = matches.filter(m => m.match).length;
  const lines = matches.map(m => {
    const tag = m.match ? 'MATCH' : '—';
    const snippet = escHtml(String(m.payload || '').slice(0, 80));
    return `#${m.index} ${tag} status=${m.status} ${snippet}${String(m.payload || '').length > 80 ? '…' : ''}`;
  }).join('<br>');
  addAgentMsg('agent', `<strong>Fuzz list results</strong><br>Indicator hits: ${hitCount}/${matches.length}<br><br>${lines}`);
}

function buildDeterministicProbeForScanStep(scanPlan, planStep, activeRequest) {
  const targetUrl = resolveScanTargetUrl(scanPlan);
  if (!targetUrl) return null;

  const vector = String(planStep?.vector || '').trim() || 'Unknown';
  const candidates = workspaceUtils.collectParamCandidatesFromRequest(activeRequest || {});
  const paramKey = resolveProbeParamKey(vector, planStep, scanPlan, candidates);
  const baseProbe = {
    type: 'probe',
    name: `${vector} probe`,
    method: 'GET',
    url: targetUrl,
    headers: [],
    params: [],
    body: '',
    vector,
    hypothesis: '',
    auto_chain: false
  };

  switch (vector) {
    case 'InfoDisclosure':
      return {
        ...baseProbe,
        name: 'Unauthenticated access check',
        hypothesis: 'A positive result is a 200 response, verbose headers, or sensitive data exposure without authentication.'
      };
    case 'AuthBypass':
      return {
        ...baseProbe,
        name: 'Auth bypass header check',
        headers: [
          { k: 'X-Forwarded-For', v: '127.0.0.1' },
          { k: 'X-Original-URL', v: '/' },
          { k: 'Authorization', v: 'Bearer undefined' }
        ],
        hypothesis: 'A positive result is access granted or a materially different response when bypass-style headers are supplied.'
      };
    case 'IDOR':
    case 'BOLA':
      return {
        ...baseProbe,
        name: `${vector} identifier manipulation`,
        params: [{ k: paramKey, v: '99999' }],
        hypothesis: 'A positive result is access to another object, different authorization behavior, or unexpected data for a manipulated identifier.'
      };
    case 'SQLi':
      return {
        ...baseProbe,
        name: 'SQL injection query check',
        params: [{ k: paramKey, v: "' OR 1=1 --" }],
        hypothesis: 'A positive result is an error signature, altered response shape, or unexpected success on an injected parameter.'
      };
    case 'NoSQLi': {
      const pk = paramKey || 'username';
      const bodyObj = {
        [pk]: { $gt: '' },
        password: { $gt: '' }
      };
      return {
        ...baseProbe,
        name: 'NoSQL injection body check',
        method: 'POST',
        headers: [{ k: 'Content-Type', v: 'application/json' }],
        body: JSON.stringify(bodyObj, null, 2),
        hypothesis: 'A positive result is authentication bypass or unexpected acceptance of object operators in JSON input.'
      };
    }
    case 'MassAssignment':
      return {
        ...baseProbe,
        name: 'Mass assignment field injection',
        method: 'POST',
        headers: [{ k: 'Content-Type', v: 'application/json' }],
        body: JSON.stringify({ role: 'admin', isAdmin: true }, null, 2),
        hypothesis: 'A positive result is privileged fields being accepted or reflected without server-side filtering.'
      };
    case 'PathTraversal':
      return {
        ...baseProbe,
        name: 'Path traversal filename check',
        params: [{ k: paramKey, v: '../../etc/passwd' }],
        hypothesis: 'A positive result is local file content, traversal error leakage, or unusual file resolution behavior.'
      };
    case 'CachePoisoning':
      return {
        ...baseProbe,
        name: 'Cache poisoning header check',
        headers: [{ k: 'X-Forwarded-Host', v: 'evil.example' }],
        hypothesis: 'A positive result is reflected untrusted host data or cache-affecting behavior driven by inbound headers.'
      };
    case 'UnrestrictedUpload':
      return {
        ...baseProbe,
        name: 'Upload metadata acceptance check',
        method: 'POST',
        headers: [{ k: 'Content-Type', v: 'application/json' }],
        body: JSON.stringify({ filename: 'shell.php', contentType: 'application/x-php' }, null, 2),
        hypothesis: 'A positive result is acceptance of risky file metadata or weak validation on upload-related inputs.'
      };
    case 'SSRF':
      return {
        ...baseProbe,
        name: 'SSRF URL parameter check',
        method: 'POST',
        headers: [{ k: 'Content-Type', v: 'application/json' }],
        body: JSON.stringify({ url: 'http://169.254.169.254/latest/meta-data/' }, null, 2),
        hypothesis: 'A positive result is server-side fetching behavior, internal host access, or metadata-service related errors.'
      };
    case 'XXE':
      return {
        ...baseProbe,
        name: 'XXE XML payload check',
        method: 'POST',
        headers: [{ k: 'Content-Type', v: 'application/xml' }],
        body: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        hypothesis: 'A positive result is XML parser expansion, local file disclosure, or parser errors revealing external entity handling.'
      };
    case 'ParameterPollution':
      return {
        ...baseProbe,
        name: 'Duplicate parameter pollution check',
        params: [
          { k: paramKey, v: '1' },
          { k: paramKey, v: '2' }
        ],
        hypothesis: 'A positive result is inconsistent routing, merged parameter handling, or unexpected precedence between duplicate parameters.'
      };
    case 'CommandInjection':
      return {
        ...baseProbe,
        name: 'Command injection input check',
        method: 'POST',
        headers: [{ k: 'Content-Type', v: 'application/json' }],
        body: JSON.stringify({ input: 'test; id' }, null, 2),
        hypothesis: 'A positive result is shell error leakage, command output, or execution timing anomalies tied to command separators.'
      };
    case 'BusinessLogic':
      return {
        ...baseProbe,
        name: 'Business logic abuse input check',
        method: 'POST',
        headers: [{ k: 'Content-Type', v: 'application/json' }],
        body: JSON.stringify({ quantity: -1, price: 0, role: 'premium' }, null, 2),
        hypothesis: 'A positive result is acceptance of impossible state transitions, negative values, or privilege-changing business fields.'
      };
    default:
      return null;
  }
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
  const deterministicProbe = buildDeterministicProbeForScanStep(scanPlan, planStep, getActive());
  if (deterministicProbe) {
    return {
      probe: deterministicProbe,
      chain: null,
      message: `Prepared a deterministic ${deterministicProbe.vector} probe for step ${planStep.order || '?'}.`,
      assertions: [],
      hadRateLimit: false
    };
  }

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
  if (!list || list.length === 0) {
    el.innerHTML = `<div style="color:var(--text3);font-size:12px;padding:8px;">No assertions yet. Send a request, then use <strong>Generate with AI</strong> below (or ask the agent).</div>`;
    return;
  }
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

  const elapsedMs = Number(resp.elapsed ?? resp.elapsed_ms ?? 0);

  assertions.forEach(a => {
    try {
      const result = evaluateAssertionExpression(a.expr, {
        status: resp.status,
        body: resp.text,
        json: parsed,
        Array,
        elapsed_ms: elapsedMs,
        elapsed: elapsedMs
      });
      a.status = result ? 'pass' : 'fail';
      if (!result) a.error = 'returned false';
    } catch(e) { a.status = 'fail'; a.error = e.message; }
  });
  renderAssertions(assertions);
  switchTab('assertions');
  saveWorkspaceState();
}

function removeAssertion(i) {
  const r = getActive(); r.assertions.splice(i, 1); renderAssertions(r.assertions); saveWorkspaceState();
}

function addManualAssertion() {
  const expr = prompt('Assertion expression (JS):\nVariables: status, json, body, elapsed_ms, elapsed\n\nExample: status === 200');
  if (!expr) return;
  const r = getActive(); r.assertions.push({ expr, status: 'pending' }); renderAssertions(r.assertions); saveWorkspaceState();
}

function detectImportKind(json) {
  if (!json || typeof json !== 'object') return null;
  if (Array.isArray(json.item) && json.info && typeof json.info === 'object') return 'postman';
  if (typeof json.openapi === 'string' || (json.paths && typeof json.paths === 'object')) return 'openapi';
  return null;
}

function mergeImportedRequests(newRequests, meta = {}) {
  if (!Array.isArray(newRequests) || !newRequests.length) {
    addAgentMsg('system', 'Nothing to import.');
    return;
  }
  saveActive();
  let maxId = requests.reduce((m, r) => Math.max(m, Number(r.id) || 0), 0);
  newRequests.forEach((raw) => {
    maxId += 1;
    const normalized = normalizeRequestRecord({ ...raw, id: maxId }, maxId);
    requests.push(normalized);
  });
  idCounter = Math.max(idCounter, maxId + 1);
  renderSidebar();
  saveWorkspaceState();
  const parts = [`Imported ${newRequests.length} request(s).`];
  if (meta.truncated) parts.push('List was truncated (max operations cap).');
  if (Array.isArray(meta.warnings) && meta.warnings.length) {
    parts.push(meta.warnings.join(' '));
  }
  addAgentMsg('system', parts.join(' '));
  setSidebarWindow('requests');
}

async function runImportSpecFile(file) {
  const text = await file.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    addAgentMsg('error', 'Import failed: file is not valid JSON.');
    return;
  }
  const kind = detectImportKind(json);
  if (!kind) {
    addAgentMsg('error', 'Import failed: expected OpenAPI (3.x or Swagger 2) or Postman v2 collection (info + item).');
    return;
  }
  const path = kind === 'postman' ? BACKEND_ENDPOINTS.importPostman : BACKEND_ENDPOINTS.importOpenapi;
  const payload = kind === 'postman'
    ? { collection: json, maxOperations: 120 }
    : { spec: json, maxOperations: 120 };
  try {
    const data = await callBackendJson(path, payload);
    mergeImportedRequests(data.requests || [], { warnings: data.warnings, truncated: data.truncated });
  } catch (e) {
    addAgentMsg('error', `Import failed: ${escHtml(e.message)}`);
  }
}

function collectAssertionGoalsFromUi() {
  const raw = document.getElementById('assertion-gen-goals')?.value || '';
  return raw.split('\n').map(l => l.trim()).filter(Boolean).slice(0, 12);
}

function parseExpectedSchemaFromUi() {
  const raw = document.getElementById('assertion-gen-schema')?.value?.trim();
  if (!raw) return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error('expected_schema JSON is invalid.');
  }
}

async function generateAssertionsFromUi() {
  if (!lastResponse) {
    addAgentMsg('system', 'Send a request first so there is a response to assert against.');
    switchTab('assertions');
    return;
  }
  const mode = document.getElementById('assertion-gen-mode')?.value || 'functional';
  let expected_schema;
  try {
    expected_schema = parseExpectedSchemaFromUi();
  } catch (e) {
    addAgentMsg('error', e.message);
    return;
  }
  const goals = collectAssertionGoalsFromUi();
  const opts = {
    mode,
    assertion_goals: goals.length ? goals : undefined
  };
  if (expected_schema !== undefined) opts.expected_schema = expected_schema;
  await autoSuggestAssertions(opts);
}

function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => { t.classList.toggle('active', t.dataset.tab === name); });
  document.querySelectorAll('.tab-content').forEach(c => { c.classList.toggle('visible', c.id === 'tab-' + name); });
  
  // Render snapshots panel when snapshots tab is shown
  if (name === 'snapshots') {
    renderSnapshotsPanel();
  }
}

async function autoSuggestAssertions(options = {}) {
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
    const payload = {
      status: lastResponse.status,
      body_preview: preview,
      provider: preferredProvider,
      model: preferredModel,
      mode: typeof options.mode === 'string' ? options.mode : 'functional'
    };
    if (Array.isArray(options.assertion_goals)) payload.assertion_goals = options.assertion_goals;
    if (options.expected_schema !== undefined) payload.expected_schema = options.expected_schema;
    const parsed = await callBackendJson(BACKEND_ENDPOINTS.assertions, payload);
    const arr = Array.isArray(parsed?.assertions) ? parsed.assertions : [];
    if (!arr.length) return;
    const r = getActive();
    r.assertions = arr.map(expr => ({ expr, status: 'pending' }));
    renderAssertions(r.assertions);
    switchTab('assertions');
    saveWorkspaceState();
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

      if (action.type === 'fuzz_list' && Array.isArray(action.payloads) && action.payloads.length) {
        chips.push({
          label: `Run fuzz list (${action.payloads.length})`,
          cls: 'chain',
          fn: () => executeFuzzListAction(action)
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
    if (isQuotaBalanceErrorMessage(e?.message)) {
      addAgentMsg('error', `Provider quota/balance error: ${e.message}`);
      addAgentMsg('system', 'If auto-fallback was unavailable, switch provider or add credits to the current provider key.');
    } else {
      addAgentMsg('error', `Agent error: ${e.message}`);
    }
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
  loadActive(); renderSidebar(); saveWorkspaceState();
  if (!skipMessage) addAgentMsg('system', `Applied: ${action.method} ${action.url}`);
}

function applyAssertions(list, options = {}) {
  const { skipMessage = false } = options;
  const r = getActive();
  r.assertions = (list || []).map(expr => ({ expr, status: 'pending' }));
  renderAssertions(r.assertions);
  switchTab('assertions');
  saveWorkspaceState();
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
  saveWorkspaceState();
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
      scan_profile: SCAN_PROFILE_VALUES.has(securityScanProfile) ? securityScanProfile : 'standard',
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
  loadActive(); renderSidebar(); saveWorkspaceState();
});

document.getElementById('clear-errors-btn').addEventListener('click', clearErrorLogs);

['url-input', 'body-editor', 'method-select', 'params-body', 'headers-body'].forEach(id => {
  const element = document.getElementById(id);
  if (!element) return;
  element.addEventListener(id === 'method-select' ? 'change' : 'input', () => saveActive());
});

const envSelectEl = document.getElementById('env-select');
if (envSelectEl) {
  envSelectEl.addEventListener('change', event => {
    setActiveEnvironment(event.target.value);
  });
}

const envNewBtnEl = document.getElementById('env-new-btn');
if (envNewBtnEl) {
  envNewBtnEl.addEventListener('click', createEnvironment);
}

const envDeleteBtnEl = document.getElementById('env-delete-btn');
if (envDeleteBtnEl) {
  envDeleteBtnEl.addEventListener('click', deleteActiveEnvironment);
}

['env-vars-body', 'env-headers-body'].forEach(id => {
  const tbody = document.getElementById(id);
  if (!tbody) return;
  tbody.addEventListener('input', () => saveEnvironmentFromEditor());
});

window.addEventListener('beforeunload', () => {
  try {
    saveEnvironmentFromEditor();
    saveActive();
    saveWorkspaceState();
  } catch {}
});

// Copy response
document.getElementById('copy-res-btn').addEventListener('click', () => {
  if (lastResponse?.text) navigator.clipboard.writeText(lastResponse.text);
});

// Chain URL resolver — expand {{json.field}} at send time
function resolveChainTemplate(url) {
  return workspaceUtils.resolveChainTemplate(url, lastResponse?.text || '');
}

// Init
(async function initApp() {
  initFluidBackground();
  loadModelPreferences();
  loadWorkspaceState();
  await loadRuntimeConfig();
  loadActive();
  renderWelcomeMessage();
  loadComponentIntegrationPrompt({ overwrite: false });
  renderAgentPanelState();
  renderAgentCharCount();
  renderSidebar();
  renderModelProvider();
  renderScanPaceControl();
  renderSecurityScanProfileControl();
  renderAgentMode();
  syncAgentRunControls();
  renderScanProgress();

  const importInput = document.getElementById('import-spec-input');
  if (importInput) {
    importInput.addEventListener('change', (e) => {
      const f = e.target.files[0];
      if (f) runImportSpecFile(f);
      e.target.value = '';
    });
  }
  const importBtn = document.getElementById('import-spec-btn');
  if (importBtn && importInput) {
    importBtn.addEventListener('click', () => importInput.click());
  }
  const assertionGenBtn = document.getElementById('assertion-generate-btn');
  if (assertionGenBtn) {
    assertionGenBtn.addEventListener('click', () => generateAssertionsFromUi());
  }
})();
