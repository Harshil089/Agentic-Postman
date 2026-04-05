const path = require('path');
const fs = require('fs');
const net = require('net');
const dns = require('dns').promises;
const express = require('express');
const dotenv = require('dotenv');
const workspaceUtils = require('./workspace-utils');
const importSpec = require('./import-spec');

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || '';
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';
const GROQ_API_KEY = process.env.GROQ_API_KEY || '';
const OPENROUTER_QWEN_DEFAULT_MODEL = process.env.OPENROUTER_DEFAULT_MODEL || 'qwen/qwen3.6-plus:free';

const MODEL_PROVIDERS = {
  openrouter: 'openrouter',
  gemini: 'gemini',
  groq: 'groq'
};

const OPENROUTER_MODELS = {
  default: OPENROUTER_QWEN_DEFAULT_MODEL,
  advanced: process.env.OPENROUTER_ADVANCED_MODEL || OPENROUTER_QWEN_DEFAULT_MODEL,
  security: process.env.OPENROUTER_SECURITY_MODEL || OPENROUTER_QWEN_DEFAULT_MODEL
};
const OPENROUTER_MODEL_ALIASES = {
  'openrouter/auto': OPENROUTER_QWEN_DEFAULT_MODEL,
  'qwen/qwen3.6-plus': OPENROUTER_QWEN_DEFAULT_MODEL,
  'qwen3.6-plus': OPENROUTER_QWEN_DEFAULT_MODEL,
  'qwen 3.6 plus': OPENROUTER_QWEN_DEFAULT_MODEL,
  'qwen 3.6 plus free': OPENROUTER_QWEN_DEFAULT_MODEL,
  'deepseek/deepseek-v3.2': 'deepseek/deepseek-v3.2',
  'deepseek v3.2': 'deepseek/deepseek-v3.2',
  'deepseek-v3.2': 'deepseek/deepseek-v3.2'
};

const GEMINI_MODELS = {
  default: process.env.GEMINI_DEFAULT_MODEL || 'gemini-2.5-flash',
  advanced: process.env.GEMINI_ADVANCED_MODEL || 'gemini-2.5-flash',
  security: process.env.GEMINI_SECURITY_MODEL || 'gemini-2.5-flash'
};

const GEMINI_FALLBACK_MODELS = [
  'gemini-2.5-flash'
];
const GEMINI_MODEL_ALIASES = {
  'gemini-flash-latest': 'gemini-2.5-flash',
  'gemini-2.0-flash': 'gemini-2.5-flash',
  'gemini-2.0-flash-lite': 'gemini-2.5-flash',
  'gemini-1.5-flash': 'gemini-2.5-flash',
  'gemini-1.5-flash-8b': 'gemini-2.5-flash',
  'gemini-1.5-pro': 'gemini-2.5-flash'
};

const GROQ_MODEL_ALIASES = {
  'groq/compound': 'groq/compound',
  'groq/compound-mini': 'groq/compound-mini',
  'groq/gpt-oss-120b': 'openai/gpt-oss-120b',
  'groq/gpt-oss-20b': 'openai/gpt-oss-20b',
  'groq/gpt-oss-safeguard-20b': 'openai/gpt-oss-safeguard-20b',
  'groq/qwen3-32b': 'qwen/qwen3-32b'
};

const GROQ_MODELS = {
  default: 'groq/gpt-oss-120b',
  advanced: 'groq/gpt-oss-120b',
  security: 'groq/gpt-oss-120b'
};

const GROQ_MODEL_ORDER = [
  'groq/gpt-oss-120b',
  'groq/gpt-oss-20b',
  'groq/gpt-oss-safeguard-20b',
  'groq/compound',
  'groq/compound-mini',
  'groq/qwen3-32b'
];
const GEMINI_REQUEST_TIMEOUT_MS = Number(process.env.GEMINI_REQUEST_TIMEOUT_MS || 12000);
const OUTBOUND_REQUEST_TIMEOUT_MS = Number(process.env.OUTBOUND_REQUEST_TIMEOUT_MS || 15000);
const OUTBOUND_RESPONSE_MAX_BYTES = Number(process.env.OUTBOUND_RESPONSE_MAX_BYTES || 2 * 1024 * 1024);
const DNS_LOOKUP_TIMEOUT_MS = Number(process.env.DNS_LOOKUP_TIMEOUT_MS || 5000);

const TASK_TYPES = {
  agent: 'agent',
  assertions: 'assertions',
  security: 'security'
};

const MODEL_CAPABILITY_REGISTRY_PATH = path.join(__dirname, 'model-capabilities.json');
const MODEL_RUNTIME_STATS = new Map();
const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'metadata.google.internal'
]);
const BLOCKED_HOST_SUFFIXES = [
  '.localhost',
  '.local',
  '.internal',
  '.home',
  '.arpa'
];
const BLOCKED_CIDRS = [
  '127.0.0.0/8',
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '169.254.0.0/16',
  '0.0.0.0/8',
  '100.64.0.0/10',
  '::1/128',
  'fc00::/7',
  'fe80::/10'
];
const BLOCKED_HEADER_NAMES = new Set([
  'host',
  'content-length',
  'connection',
  'proxy-connection',
  'upgrade',
  'transfer-encoding',
  'te',
  'trailer',
  'proxy-authorization',
  'proxy-authenticate',
  'proxy-agent',
  'forwarded',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-real-ip',
  'cf-connecting-ip',
  'true-client-ip',
  'cookie',
  'cookie2',
  'set-cookie',
  'authorization'
]);

function loadModelCapabilityRegistry() {
  try {
    const raw = fs.readFileSync(MODEL_CAPABILITY_REGISTRY_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object') {
      return parsed;
    }
  } catch {}
  return {};
}

function ipv4ToInt(ip) {
  return ip.split('.').reduce((acc, octet) => ((acc << 8) + Number(octet)) >>> 0, 0);
}

function normalizeIpv6(ip) {
  if (!ip.includes(':')) return null;
  const [headRaw, tailRaw] = ip.split('::');
  const head = headRaw ? headRaw.split(':').filter(Boolean) : [];
  const tail = tailRaw ? tailRaw.split(':').filter(Boolean) : [];

  if (tail.length && tail[tail.length - 1].includes('.')) {
    const v4 = tail.pop();
    const octets = v4.split('.').map(Number);
    if (octets.length !== 4 || octets.some(o => !Number.isInteger(o) || o < 0 || o > 255)) return null;
    tail.push(((octets[0] << 8) | octets[1]).toString(16));
    tail.push(((octets[2] << 8) | octets[3]).toString(16));
  }

  const missing = 8 - (head.length + tail.length);
  const groups = ip.includes('::')
    ? [...head, ...Array(Math.max(0, missing)).fill('0'), ...tail]
    : [...head, ...tail];

  if (groups.length !== 8) return null;

  return groups.map(group => group.padStart(4, '0')).join('');
}

function isIpv4InCidr(ip, cidrIp, prefix) {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(cidrIp) & mask);
}

function isIpv6InCidr(ip, cidrIp, prefix) {
  const ipHex = normalizeIpv6(ip);
  const cidrHex = normalizeIpv6(cidrIp);
  if (!ipHex || !cidrHex) return false;
  const chars = Math.floor(prefix / 4);
  const remainder = prefix % 4;
  if (ipHex.slice(0, chars) !== cidrHex.slice(0, chars)) return false;
  if (!remainder) return true;
  const mask = 0xf << (4 - remainder);
  return (parseInt(ipHex[chars], 16) & mask) === (parseInt(cidrHex[chars], 16) & mask);
}

function isIpBlocked(ip) {
  const family = net.isIP(ip);
  if (!family) return false;
  return BLOCKED_CIDRS.some(cidr => {
    const [range, prefixRaw] = cidr.split('/');
    const prefix = Number(prefixRaw);
    if (family === 4 && net.isIP(range) === 4) {
      return isIpv4InCidr(ip, range, prefix);
    }
    if (family === 6 && net.isIP(range) === 6) {
      return isIpv6InCidr(ip, range, prefix);
    }
    return false;
  });
}

function isHostnameBlocked(hostname) {
  const normalized = String(hostname || '').toLowerCase();
  return BLOCKED_HOSTNAMES.has(normalized)
    || BLOCKED_HOST_SUFFIXES.some(suffix => normalized.endsWith(suffix));
}

async function assertUrlAllowed(parsedUrl) {
  const hostname = String(parsedUrl.hostname || '').toLowerCase();
  if (!hostname) {
    const err = new Error('URL is missing a hostname.');
    err.status = 400;
    throw err;
  }
  if (isHostnameBlocked(hostname) || isIpBlocked(hostname)) {
    const err = new Error('Target host is blocked by outbound request policy.');
    err.status = 403;
    throw err;
  }

  let lookupResults;
  let lookupTimer = null;
  try {
    const lookupPromise = dns.lookup(hostname, { all: true });
    const timeoutPromise = new Promise((_, reject) => {
      lookupTimer = setTimeout(() => {
        const err = new Error(`DNS lookup timed out after ${DNS_LOOKUP_TIMEOUT_MS}ms.`);
        err.status = 502;
        reject(err);
      }, DNS_LOOKUP_TIMEOUT_MS);
    });
    lookupResults = await Promise.race([lookupPromise, timeoutPromise]);
  } catch (error) {
    const err = error instanceof Error ? error : new Error('Failed to resolve target host.');
    if (!err.status) err.status = 502;
    if (!err.message || err.message === 'Error') {
      err.message = 'Failed to resolve target host.';
    }
    throw err;
  } finally {
    if (lookupTimer) clearTimeout(lookupTimer);
  }

  if (lookupResults.some(result => isIpBlocked(result.address))) {
    const err = new Error('Resolved target address is blocked by outbound request policy.');
    err.status = 403;
    throw err;
  }
}

async function readResponseTextWithLimit(response, maxBytes) {
  if (!response.body) return '';

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let totalBytes = 0;
  let text = '';

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;

      const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
      totalBytes += chunk.byteLength;
      if (totalBytes > maxBytes) {
        const err = new Error(`Upstream response exceeded the ${Math.round(maxBytes / (1024 * 1024))}MB limit.`);
        err.status = 413;
        throw err;
      }

      text += decoder.decode(chunk, { stream: true });
    }

    text += decoder.decode();
    return text;
  } finally {
    try {
      reader.releaseLock();
    } catch {}
  }
}

function sanitizeOutboundHeaders(headers) {
  const source = headers && typeof headers === 'object' ? headers : {};
  const safe = {};
  for (const [key, value] of Object.entries(source)) {
    if (typeof value !== 'string') continue;
    const normalized = key.toLowerCase();
    if (BLOCKED_HEADER_NAMES.has(normalized)) continue;
    safe[key] = value;
  }
  return safe;
}

const MODEL_CAPABILITY_REGISTRY = loadModelCapabilityRegistry();

function getModelRuntimeKey(provider, model) {
  return `${provider}:${model}`;
}

function getModelRuntimeStats(provider, model) {
  const key = getModelRuntimeKey(provider, model);
  if (!MODEL_RUNTIME_STATS.has(key)) {
    MODEL_RUNTIME_STATS.set(key, {
      provider,
      model,
      attempts: 0,
      successes: 0,
      failures: 0,
      failureReasons: {},
      taskFailures: {},
      lastFailureAt: null,
      lastFailureReason: null,
      lastSuccessAt: null
    });
  }
  return MODEL_RUNTIME_STATS.get(key);
}

function classifyFailureReason(error) {
  const status = Number(error?.status || 0);
  const msg = String(error?.message || '').toLowerCase();

  if (status === 401 || status === 403 || msg.includes('api key')) return 'auth';
  if (status === 429 || msg.includes('rate limit') || msg.includes('quota') || msg.includes('billing')) return 'rate_limit';
  if (msg.includes('failed to validate json') || msg.includes('json_validate_failed') || msg.includes('invalid json')) return 'json_validation';
  if (msg.includes('decommissioned') || msg.includes('not found') || msg.includes('not supported') || msg.includes('unsupported') || msg.includes('blocked at the project level')) return 'model_unavailable';
  if (msg.includes('requires more credits') || msg.includes('fewer max_tokens') || msg.includes('can only afford') || msg.includes('requested up to')) return 'token_budget';
  if (status >= 500) return 'provider_error';
  return 'unknown';
}

function recordModelAttempt({ provider, model, taskType, ok, error }) {
  const stats = getModelRuntimeStats(provider, model);
  stats.attempts += 1;

  if (ok) {
    stats.successes += 1;
    stats.lastSuccessAt = new Date().toISOString();
    return;
  }

  const reason = classifyFailureReason(error);
  stats.failures += 1;
  stats.lastFailureAt = new Date().toISOString();
  stats.lastFailureReason = reason;
  stats.failureReasons[reason] = Number(stats.failureReasons[reason] || 0) + 1;
  if (taskType) {
    stats.taskFailures[taskType] = Number(stats.taskFailures[taskType] || 0) + 1;
  }
}

function getCapability(provider, model) {
  const capability = MODEL_CAPABILITY_REGISTRY[model];
  if (!capability || capability.provider !== provider) return null;
  return capability;
}

function getFailurePenalty(stats) {
  if (!stats || !stats.attempts) return 0;
  const rate = stats.failures / Math.max(1, stats.attempts);
  const reasons = stats.failureReasons || {};
  return (
    rate * 40
    + Number(reasons.model_unavailable || 0) * 12
    + Number(reasons.json_validation || 0) * 10
    + Number(reasons.rate_limit || 0) * 8
    + Number(reasons.token_budget || 0) * 6
  );
}

function getModelRuntimeScore({ provider, model, taskType }) {
  const capability = getCapability(provider, model);
  const stats = getModelRuntimeStats(provider, model);
  const taskFit = Number(capability?.taskFit?.[taskType] ?? 0.6);
  const jsonReliability = Number(capability?.jsonReliability ?? 0.75);
  const securityQuality = Number(capability?.securityScanQuality ?? 0.5);
  const maxContext = Number(capability?.maxContext ?? 32000);
  const contextBoost = Math.min(6, Math.log10(Math.max(1000, maxContext)));
  const successBoost = stats.successes > 0 ? Math.min(8, stats.successes * 0.8) : 0;
  const failurePenalty = getFailurePenalty(stats);

  return (
    taskFit * 100
    + jsonReliability * 25
    + (taskType === TASK_TYPES.security ? securityQuality * 20 : securityQuality * 8)
    + contextBoost
    + successBoost
    - failurePenalty
  );
}

function rankModelsForTask(provider, candidates, taskType) {
  const unique = [...new Set((candidates || []).filter(Boolean))];
  return unique.sort((a, b) => {
    const scoreDelta = getModelRuntimeScore({ provider, model: b, taskType })
      - getModelRuntimeScore({ provider, model: a, taskType });
    if (scoreDelta !== 0) return scoreDelta;
    return a.localeCompare(b);
  });
}

function buildAdaptiveTokenPlan(baseTokens, fallbackTokens, stats) {
  const defaults = [baseTokens, ...(fallbackTokens || [])].filter(x => Number.isFinite(x) && x > 0);
  const unique = [...new Set(defaults)];
  const reasons = stats?.failureReasons || {};
  const tokenBudgetPressure = Number(reasons.token_budget || 0);
  const rateLimitPressure = Number(reasons.rate_limit || 0);

  if (tokenBudgetPressure >= 2) {
    const lowered = [Math.min(baseTokens, 800), 700, 600, 500, 400, 300, 200]
      .filter(x => Number.isFinite(x) && x > 0);
    return [...new Set([...lowered, ...unique])];
  }

  if (rateLimitPressure >= 2) {
    return unique.slice(0, Math.min(unique.length, 3));
  }

  return unique;
}

const AGENT_MASTER_PROMPT = `You are AgentMan — an agentic backend engine for a Postman-like API IDE.
You receive structured context about the user's current HTTP request and last response,
then return a strict JSON action payload that the IDE frontend executes directly.

CONTEXT YOU WILL RECEIVE (per turn)
- current_mode: "planning" | "ask" | "agent"
- chat_session_id: number
- chat_goal: string
- conversation_history: array of { role, text }
- current_request: { method, url, headers[], params[], body }
- last_response:   { status, elapsed_ms, body_preview (first 800 chars) } | null
- current_assertions: string[] of JS expressions | []
- user_message: plain English instruction

OUTPUT CONTRACT — STRICT JSON, NO MARKDOWN
Always respond with exactly this shape:
{
  "message": "one-sentence natural language summary for the user",
  "actions": [ ...action objects ]
}

Actions array may be empty or contain multiple objects.
Each action MUST be one of the following typed objects:

1. SET_REQUEST
{
  "type": "set_request",
  "name": "short display name",
  "method": "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
  "url": "https://full.url/path",
  "params":  [ { "k": "key", "v": "value" } ],
  "headers": [ { "k": "Content-Type", "v": "application/json" } ],
  "body": "raw string body or empty string"
}

2. SET_ASSERTIONS
{
  "type": "set_assertions",
  "assertions": [
    "status === 200",
    "Array.isArray(json)",
    "json.length > 0",
    "json[0].hasOwnProperty('id')",
    "typeof json[0].name === 'string'"
  ]
}
Assertions are JS expressions. Available variables: status (number), json (parsed object or null), body (raw string).

3. CHAIN_REQUEST
{
  "type": "chain_request",
  "name": "short display name",
  "method": "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
  "url": "https://api.example.com/users/{{json.id}}/posts",
  "params":  [],
  "headers": [],
  "body": "",
  "chainNote": "one sentence: what data is being chained and why"
}
Use {{json.fieldPath}} for dot-path references into the previous response JSON.
Examples: {{json.id}}, {{json.data.token}}, {{json.results[0].uuid}}

4. DEBUG_INFO
{
  "type": "debug_info",
  "findings": [
    "Status 401 — Authorization header is missing",
    "Content-Type is not set for a POST with body"
  ],
  "fix": "Add Authorization: Bearer <token> header and set Content-Type: application/json",
  "patch": {
    "headers": [ { "k": "Authorization", "v": "Bearer <token>" } ]
  }
}
patch is optional — include it only when the fix is a direct request mutation.

BEHAVIORAL RULES
1. NEVER return markdown, prose, or code fences. Raw JSON only.
2. For public demo APIs default to: jsonplaceholder.typicode.com, reqres.in, httpbin.org.
3. For assertion generation: always produce 4–6 expressions. Cover status code,
   response shape (Array.isArray, typeof), key field existence, and one value check.
4. For chaining: inspect last_response body_preview to infer real field names.
   Prefer json.id, json.data.id, json.results[0].id in that priority order.
5. For debugging: check in order — status code semantics, missing auth headers,
   wrong Content-Type, malformed JSON body, CORS (if browser error), URL typos.
6. If user_message is ambiguous, prefer set_request over asking a clarifying question.
   Make a reasonable assumption and state it in "message".
7. Actions may be combined in one response. Example: set_request + set_assertions together.
8. Never include secrets or real credentials. Use placeholder strings like <your-token>.`;

const MODE_RULES_PROMPT = `MODE-SPECIFIC BEHAVIOR
- If current_mode is "ask": focus on explanation, debugging analysis, or guidance. Return actions as [] unless the user explicitly asks to build/modify a request.
- If current_mode is "planning": provide a concise execution plan in message and suggest non-destructive actions only. Do not assume immediate execution.
- If current_mode is "agent": you may return executable actions for request construction and test flow automation.
- In "agent" mode, when the task is complete, return actions: [] and set message to a final summary that starts with "Conclusion:".`;

const CONTEXT_AWARENESS_PROMPT = `CONTEXT-AWARENESS
- Use chat_goal and conversation_history to avoid repeating already completed steps.
- Keep continuity with prior turns in the same chat_session_id.
- If the user starts a new objective, adapt quickly and state the updated objective in message.`;

const SECURITY_MASTER_PROMPT = `You are AgentMan Security - an agentic penetration testing engine embedded in an API IDE.
You systematically probe REST endpoints for security vulnerabilities using HTTP requests.
You think like an offensive security researcher: methodical, evidence-based, non-destructive by default.

THREAT CATEGORIES YOU TEST (mapped to HTTP methods)

GET  -> Information disclosure, IDOR, path traversal, parameter pollution,
        unauthenticated access, verbose error leakage, cache poisoning

POST -> Injection (SQLi, NoSQLi, command), mass assignment, authentication bypass,
        SSRF, XXE, unrestricted file upload, business logic abuse, rate limit bypass

PUT  -> Unauthorized resource overwrite, privilege escalation via body fields,
        IDOR on resource IDs, schema pollution

PATCH -> Partial update abuse, role/permission field tampering, BOLA

DELETE -> Unauthorized deletion, IDOR, cascade delete abuse, soft-delete bypass

CONTEXT YOU RECEIVE PER TURN
- target_url        : base URL under test
- current_request   : { method, url, headers[], params[], body }
- last_response     : { status, elapsed_ms, body_preview } | null
- auth_context      : { type: "none"|"bearer"|"basic"|"apikey", value: string } | null
- test_history      : [ { method, url, status, finding } ]
- user_instruction  : plain English command from the tester
- param_candidates  : string[] — query keys, body keys, and param-table keys from current_request; prefer these for probes/fuzz_list targets instead of guessing "id" only
- scan_profile      : "quick" | "standard" | "deep" — quick=fewer probes; standard=balanced; deep=more fuzz_list rows and param rotation

OUTPUT CONTRACT - RAW JSON ONLY, ZERO MARKDOWN
{
  "message": "one sentence summary of what you are doing and why",
  "threat_level": "none" | "low" | "medium" | "high" | "critical",
  "findings": [
    {
      "id": "FINDING-001",
      "vulnerability": "short name e.g. IDOR, SQLi, Auth Bypass",
      "severity": "info" | "low" | "medium" | "high" | "critical",
      "evidence": "exact field/value/header from the response that proves this",
      "cve_hint": "CVE-YYYY-NNNNN or CWE-NNN if applicable, else null",
      "owasp_api_label": "optional OWASP API Top 10 2023 label e.g. API1:2023 Broken Object Level Authorization",
      "remediation": "one sentence fix"
    }
  ],
  "actions": [ ...action objects ]
}

ACTION TYPES

1) PROBE
{
  "type": "probe",
  "name": "short test name",
  "method": "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
  "url": "full URL with injected payload if needed",
  "headers": [ { "k": "Authorization", "v": "Bearer <tampered_token>" } ],
  "params": [ { "k": "id", "v": "' OR 1=1 --" } ],
  "body": "raw string - JSON, XML, or raw payload",
  "vector": "IDOR" | "SQLi" | "NoSQLi" | "AuthBypass" | "SSRF" | "XXE" |
            "MassAssignment" | "RateLimit" | "PathTraversal" | "BOLA" |
            "InfoDisclosure" | "CommandInjection" | "ParameterPollution" |
            "CachePoisoning" | "UnrestrictedUpload" | "BusinessLogic",
  "hypothesis": "what a positive result looks like",
  "auto_chain": true | false
}

2) PROBE_CHAIN
{
  "type": "probe_chain",
  "name": "attack chain name",
  "steps": [
    {
      "step": 1,
      "name": "Register low-priv user",
      "method": "POST",
      "url": "https://target.com/api/register",
      "headers": [],
      "body": "{\"username\":\"attacker01\",\"password\":\"P@ssw0rd!\",\"role\":\"admin\"}",
      "vector": "MassAssignment",
      "extract": { "token": "json.token", "userId": "json.id" }
    }
  ]
}

3) FUZZ_LIST
{
  "type": "fuzz_list",
  "target_param": "id",
  "target_location": "url" | "body" | "header" | "query",
  "vector": "SQLi",
  "payloads": ["' OR 1=1 --"],
  "success_indicators": {
    "status_codes": [200, 500],
    "body_contains": ["syntax error", "mysql", "ORA-", "pg_query", "unclosed quotation"],
    "time_delta_ms": 4500
  }
}

4) SET_ASSERTIONS
{
  "type": "set_assertions",
  "assertions": [
    "status !== 200",
    "!body.includes('stack trace')",
    "!body.includes('SQLException')",
    "!body.includes('password')",
    "json === null || !json.hasOwnProperty('role')",
    "status === 401 || status === 403"
  ]
}

5) SCAN_PLAN
{
  "type": "scan_plan",
  "target": "https://api.target.com/users/{id}",
  "method_coverage": ["GET", "POST", "PUT", "DELETE"],
  "param_matrix": [
    { "param": "id", "location": "query" },
    { "param": "userId", "location": "body" }
  ],
  "steps": [
    {
      "order": 1,
      "vector": "InfoDisclosure",
      "description": "Hit without auth - check for 401 vs 200 vs 403",
      "target_param": "optional — which param to manipulate for this step",
      "owasp_api_label": "optional e.g. API5:2023 Broken Function Level Authorization"
    }
  ]
}

6) DEBUG_INFO
{
  "type": "debug_info",
  "findings": ["Status 500 leaks internal stack trace", "Server header exposes framework version"],
  "fix": "Suppress verbose errors in production; strip Server header",
  "patch": {
    "headers": [ { "k": "X-Custom-Header", "v": "test" } ]
  }
}

PAYLOAD BANKS - use these verbatim in fuzz_list and probe bodies

SQL INJECTION (GET param / POST body):
  ' OR 1=1 --
  ' OR '1'='1'; --
  1 UNION SELECT null,table_name FROM information_schema.tables --
  ' AND SLEEP(5) --
  '; EXEC xp_cmdshell('id') --
  ' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects)) --

NOSQL INJECTION (JSON body):
  {"username": {"$gt": ""}, "password": {"$gt": ""}}
  {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
  {"$where": "this.role == 'admin'"}

SSRF (URL params / body fields pointing to URLs):
  http://169.254.169.254/latest/meta-data/
  http://127.0.0.1:6379/
  http://0.0.0.0:22/
  http://internal-service.local/admin
  file:///etc/passwd

PATH TRAVERSAL (filename / path params):
  ../../etc/passwd
  ..%2F..%2Fetc%2Fpasswd
  ....//....//etc/passwd
  %2e%2e%2f%2e%2e%2fetc%2fpasswd

XXE (XML POST body):
  <?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>

MASS ASSIGNMENT (POST/PUT JSON body - inject privileged fields):
  {"role": "admin"}
  {"isAdmin": true}
  {"permissions": ["read","write","delete","admin"]}
  {"__proto__": {"isAdmin": true}}
  {"constructor": {"prototype": {"isAdmin": true}}}

AUTH BYPASS HEADERS:
  X-Original-URL: /admin
  X-Forwarded-For: 127.0.0.1
  X-Remote-User: admin
  X-Custom-IP-Authorization: 127.0.0.1
  Authorization: Bearer null
  Authorization: Bearer undefined
  Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ.

BEHAVIORAL RULES
1. Raw JSON only. No markdown, no prose, no code fences.
2. This is an API IDE and learning tool. Do not refuse a scan or plan solely because the target is a public or production domain.
3. Prefer planning and non-destructive probes first. When the request is broad ("scan", "audit", "full check"), return scan_plan first and then the safest useful next actions.
4. One vector per probe action.
5. evidence in findings MUST quote actual response content - never inferred.
6. If last_response.status === 500 -> always generate a debug_info action.
7. If last_response body contains "password", "secret", "token", "key" in plaintext -> auto-elevate finding to HIGH and include in findings array.
8. For IDOR probes, always test: id-1, id+1, id*2, id=0, id=99999, id=null, id=-1.
9. For auth tests, always test: no header, wrong scheme, expired token, alg:none JWT, and role-escalated JWT payload.
10. scan_plan is always the first action when user_instruction contains "scan", "audit", "test all", or "full check".
11. threat_level escalation is permanent within a session - it never decreases once raised.
12. When scan_profile is "deep", include param_matrix covering param_candidates where relevant, and add fuzz_list actions for SQLi/NoSQLi on distinct params when safe.
13. Map findings to OWASP API Top 10 (2023) in owasp_api_label when applicable (API1 Broken Object Level Authorization … API10 Unsafe Consumption of APIs).`;

app.use(express.json({ limit: '2mb' }));
app.use(express.static(__dirname));

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'agentman.html'));
});

app.post('/api/import-openapi', (req, res) => {
  try {
    const spec = req.body?.spec ?? req.body;
    const maxOperations = req.body?.maxOperations;
    const result = importSpec.parseOpenApiToRequests(spec, { maxOperations });
    return res.json({
      requests: result.requests,
      warnings: result.warnings,
      truncated: result.truncated
    });
  } catch (error) {
    const status = Number(error.status || 400);
    return res.status(status).json({ error: error.message || 'OpenAPI import failed.' });
  }
});

app.post('/api/import-postman', (req, res) => {
  try {
    const collection = req.body?.collection ?? req.body;
    const maxOperations = req.body?.maxOperations;
    const result = importSpec.parsePostmanCollectionToRequests(collection, { maxOperations });
    return res.json({
      requests: result.requests,
      warnings: result.warnings,
      truncated: result.truncated
    });
  } catch (error) {
    const status = Number(error.status || 400);
    return res.status(status).json({ error: error.message || 'Postman import failed.' });
  }
});

function parseProvider(providerRaw) {
  if (providerRaw === MODEL_PROVIDERS.gemini) return MODEL_PROVIDERS.gemini;
  if (providerRaw === MODEL_PROVIDERS.groq) return MODEL_PROVIDERS.groq;
  return MODEL_PROVIDERS.openrouter;
}

function assertApiKeyConfigured(provider) {
  if (provider === MODEL_PROVIDERS.gemini && !GEMINI_API_KEY) {
    const err = new Error('Server is missing GEMINI_API_KEY. Add it to .env.');
    err.status = 500;
    throw err;
  }
  if (provider === MODEL_PROVIDERS.groq && !GROQ_API_KEY) {
    const err = new Error('Server is missing GROQ_API_KEY. Add it to .env.');
    err.status = 500;
    throw err;
  }
  if (provider === MODEL_PROVIDERS.openrouter && !OPENROUTER_API_KEY) {
    const err = new Error('Server is missing OPENROUTER_API_KEY. Add it to .env.');
    err.status = 500;
    throw err;
  }
}

function parseOpenRouterModel(model) {
  if (typeof model === 'string' && model.trim()) {
    const normalized = model.trim();
    const aliasKey = normalized.toLowerCase();
    return OPENROUTER_MODEL_ALIASES[aliasKey] || OPENROUTER_MODEL_ALIASES[normalized] || normalized;
  }
  return OPENROUTER_MODELS.default;
}

function buildOpenRouterModelCandidates(requestedModel, taskType = TASK_TYPES.agent) {
  const preferred = parseOpenRouterModel(requestedModel);
  const defaults = [
    taskType === TASK_TYPES.security ? OPENROUTER_MODELS.security : OPENROUTER_MODELS.default,
    OPENROUTER_MODELS.advanced,
    OPENROUTER_MODELS.security,
    OPENROUTER_MODELS.default
  ].filter(Boolean);
  const providerRegistryModels = Object.entries(MODEL_CAPABILITY_REGISTRY)
    .filter(([, capability]) => capability?.provider === MODEL_PROVIDERS.openrouter)
    .map(([modelId]) => modelId);
  return rankModelsForTask(
    MODEL_PROVIDERS.openrouter,
    [preferred, ...defaults, ...providerRegistryModels],
    taskType
  );
}

function parseGeminiModel(model, profile = 'default', taskType = TASK_TYPES.agent) {
  const requested = typeof model === 'string' && model.trim()
    ? model.trim().replace(/^models\//, '')
    : '';
  if (requested) {
    return GEMINI_MODEL_ALIASES[requested] || requested;
  }
  if (taskType === TASK_TYPES.security) return GEMINI_MODEL_ALIASES[GEMINI_MODELS.security] || GEMINI_MODELS.security;
  if (profile === 'security') return GEMINI_MODEL_ALIASES[GEMINI_MODELS.security] || GEMINI_MODELS.security;
  if (profile === 'advanced') return GEMINI_MODEL_ALIASES[GEMINI_MODELS.advanced] || GEMINI_MODELS.advanced;
  return GEMINI_MODEL_ALIASES[GEMINI_MODELS.default] || GEMINI_MODELS.default;
}

function buildGeminiModelCandidates(requestedModel, profile = 'default', taskType = TASK_TYPES.agent) {
  const preferred = parseGeminiModel(requestedModel, profile, taskType);
  const envCandidates = [GEMINI_MODELS.default, GEMINI_MODELS.advanced, GEMINI_MODELS.security]
    .map(x => parseGeminiModel(x, profile, taskType));
  const fallbackCandidates = GEMINI_FALLBACK_MODELS.map(x => parseGeminiModel(x, profile, taskType));
  const ordered = [preferred, ...envCandidates, ...fallbackCandidates].filter(Boolean);
  return rankModelsForTask(MODEL_PROVIDERS.gemini, ordered, taskType);
}

function parseGroqModel(model, profile = 'default', taskType = TASK_TYPES.agent) {
  const requested = typeof model === 'string' ? model.trim() : '';
  if (requested && GROQ_MODEL_ALIASES[requested]) {
    return GROQ_MODEL_ALIASES[requested];
  }

  const aliasValues = Object.values(GROQ_MODEL_ALIASES);
  if (requested && aliasValues.includes(requested)) {
    return requested;
  }

  const profileAlias = (taskType === TASK_TYPES.security || profile === 'security')
    ? GROQ_MODELS.security
    : profile === 'advanced'
      ? GROQ_MODELS.advanced
      : GROQ_MODELS.default;
  return GROQ_MODEL_ALIASES[profileAlias] || GROQ_MODEL_ALIASES[GROQ_MODELS.default];
}

function buildGroqModelCandidates(requestedModel, profile = 'default', allowModelFallback = true, taskType = TASK_TYPES.agent) {
  const preferred = parseGroqModel(requestedModel, profile, taskType);
  if (!allowModelFallback) {
    return preferred ? [preferred] : [];
  }
  const orderedResolved = GROQ_MODEL_ORDER
    .map(alias => GROQ_MODEL_ALIASES[alias])
    .filter(Boolean);
  return rankModelsForTask(MODEL_PROVIDERS.groq, [preferred, ...orderedResolved], taskType);
}

function extractGeminiText(data) {
  const parts = data?.candidates?.[0]?.content?.parts;
  const text = Array.isArray(parts)
    ? parts
      .map(part => (part && typeof part.text === 'string' ? part.text : ''))
      .join('')
      .trim()
    : '';
  return text;
}

function isGeminiRetryableModelError(status, message) {
  const msg = String(message || '').toLowerCase();
  return status === 404
    || msg.includes('not found')
    || msg.includes('not supported')
    || msg.includes('unsupported')
    || msg.includes('models/');
}

function isGeminiSchemaFieldError(message) {
  const msg = String(message || '').toLowerCase();
  return msg.includes('unknown name "systeminstruction"')
    || msg.includes('unknown name "responsemimetype"')
    || msg.includes('unknown name "generationconfig"')
    || msg.includes('unknown name "system_instruction"')
    || msg.includes('unknown name "response_mime_type"')
    || msg.includes('cannot find field');
}

function buildGeminiRequestPayload({
  systemPrompt,
  userContent,
  temperature,
  maxTokens,
  withJsonMime,
  snakeCase,
  includeSystemInstruction
}) {
  const userText = includeSystemInstruction
    ? userContent
    : `System instructions:\n${systemPrompt}\n\nUser payload:\n${userContent}`;

  if (snakeCase) {
    const generation_config = {
      temperature,
      max_output_tokens: maxTokens
    };
    if (withJsonMime) generation_config.response_mime_type = 'application/json';

    const payload = {
      contents: [
        {
          role: 'user',
          parts: [{ text: userText }]
        }
      ],
      generation_config
    };

    if (includeSystemInstruction) {
      payload.system_instruction = {
        role: 'system',
        parts: [{ text: systemPrompt }]
      };
    }
    return payload;
  }

  const generationConfig = {
    temperature,
    maxOutputTokens: maxTokens
  };
  if (withJsonMime) generationConfig.responseMimeType = 'application/json';

  const payload = {
    contents: [
      {
        role: 'user',
        parts: [{ text: userText }]
      }
    ],
    generationConfig
  };

  if (includeSystemInstruction) {
    payload.systemInstruction = {
      role: 'system',
      parts: [{ text: systemPrompt }]
    };
  }

  return payload;
}

function isGeminiQuotaError(error) {
  const status = Number(error?.status || 0);
  const msg = String(error?.message || '').toLowerCase();
  return status === 429
    || msg.includes('quota exceeded')
    || msg.includes('rate limit')
    || msg.includes('billing')
    || msg.includes('free_tier');
}

function isGeminiTransientError(status, message) {
  const code = Number(status || 0);
  const msg = String(message || '').toLowerCase();
  return code === 500
    || code === 502
    || code === 503
    || code === 504
    || msg.includes('high demand')
    || msg.includes('temporarily unavailable')
    || msg.includes('try again later')
    || msg.includes('unavailable');
}

async function openRouterGenerateJson({ model, systemPrompt, userContent, temperature = 0.2, maxTokens = 1000 }) {
  assertApiKeyConfigured(MODEL_PROVIDERS.openrouter);

  const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
      'HTTP-Referer': `http://localhost:${PORT}`,
      'X-Title': 'AgentMan'
    },
    body: JSON.stringify({
      model: parseOpenRouterModel(model),
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userContent }
      ],
      reasoning: { enabled: true },
      temperature,
      max_tokens: maxTokens,
      response_format: { type: 'json_object' }
    })
  });

  let data;
  try {
    data = await response.json();
  } catch {
    const err = new Error('OpenRouter API returned a non-JSON response.');
    err.status = 502;
    throw err;
  }

  if (!response.ok) {
    const err = new Error(data?.error?.message || `OpenRouter API error (${response.status}).`);
    err.status = response.status;
    throw err;
  }

  const content = data?.choices?.[0]?.message?.content;
  if (typeof content === 'string' && content.trim()) return content;
  if (Array.isArray(content)) {
    const text = content
      .map(part => {
        if (typeof part === 'string') return part;
        if (part && typeof part.text === 'string') return part.text;
        return '';
      })
      .join('');
    if (text.trim()) return text;
  }

  const err = new Error('OpenRouter API returned an unexpected content shape.');
  err.status = 502;
  throw err;
}

async function geminiGenerateJson({
  model,
  profile = 'default',
  taskType = TASK_TYPES.agent,
  systemPrompt,
  userContent,
  temperature = 0.2,
  maxTokens = 1000,
  fallbackTokens = [800, 600]
}) {
  assertApiKeyConfigured(MODEL_PROVIDERS.gemini);

  const apiVersions = ['v1beta', 'v1'];
  const modelCandidates = buildGeminiModelCandidates(model, profile, taskType);
  const mimeModes = [true, false];
  let lastRetryableError = null;

  candidateLoop:
  for (const candidateModel of modelCandidates) {
    const candidateStats = getModelRuntimeStats(MODEL_PROVIDERS.gemini, candidateModel);
    const tokenPlan = buildAdaptiveTokenPlan(maxTokens, fallbackTokens, candidateStats);

    for (const tokens of tokenPlan) {
      for (const apiVersion of apiVersions) {
        for (const withJsonMime of mimeModes) {
        const requestModes = [
          { snakeCase: false, includeSystemInstruction: false },
          { snakeCase: false, includeSystemInstruction: true },
          { snakeCase: true, includeSystemInstruction: false }
        ];

        for (const mode of requestModes) {
        const url = `https://generativelanguage.googleapis.com/${apiVersion}/models/${encodeURIComponent(candidateModel)}:generateContent`;
        const payload = buildGeminiRequestPayload({
          systemPrompt,
          userContent,
          temperature,
          maxTokens: tokens,
          withJsonMime,
          snakeCase: mode.snakeCase,
          includeSystemInstruction: mode.includeSystemInstruction
        });

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), GEMINI_REQUEST_TIMEOUT_MS);

        let response;
        try {
          response = await fetch(url, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-goog-api-key': GEMINI_API_KEY
            },
            body: JSON.stringify(payload),
            signal: controller.signal
          });
        } catch (error) {
          clearTimeout(timeoutId);
          const err = new Error(error?.name === 'AbortError'
            ? `Gemini request timed out after ${GEMINI_REQUEST_TIMEOUT_MS}ms.`
            : `Gemini request failed: ${String(error?.message || 'Unknown error')}`);
          err.status = error?.name === 'AbortError' ? 504 : 502;
          lastRetryableError = err;
          recordModelAttempt({
            provider: MODEL_PROVIDERS.gemini,
            model: candidateModel,
            taskType,
            ok: false,
            error: err
          });
          continue candidateLoop;
        }

        let data;
        try {
          data = await response.json();
        } catch {
          clearTimeout(timeoutId);
          const err = new Error('Gemini API returned a non-JSON response.');
          err.status = 502;
          throw err;
        }
        clearTimeout(timeoutId);

        if (!response.ok) {
          const message = data?.error?.message || `Gemini API error (${response.status}).`;
          if (isGeminiTransientError(response.status, message)) {
            const err = new Error(message);
            err.status = response.status;
            lastRetryableError = err;
            recordModelAttempt({
              provider: MODEL_PROVIDERS.gemini,
              model: candidateModel,
              taskType,
              ok: false,
              error: err
            });
            continue candidateLoop;
          }
          if (isGeminiRetryableModelError(response.status, message)) {
            const err = new Error(message);
            err.status = response.status;
            lastRetryableError = err;
            recordModelAttempt({
              provider: MODEL_PROVIDERS.gemini,
              model: candidateModel,
              taskType,
              ok: false,
              error: err
            });
            continue candidateLoop;
          }
          if (isGeminiSchemaFieldError(message)) {
            const err = new Error(message);
            err.status = response.status;
            lastRetryableError = err;
            recordModelAttempt({
              provider: MODEL_PROVIDERS.gemini,
              model: candidateModel,
              taskType,
              ok: false,
              error: err
            });
            continue;
          }
          const err = new Error(message);
          err.status = response.status;
          recordModelAttempt({
            provider: MODEL_PROVIDERS.gemini,
            model: candidateModel,
            taskType,
            ok: false,
            error: err
          });
          throw err;
        }

        const text = extractGeminiText(data);
        if (text) {
          recordModelAttempt({
            provider: MODEL_PROVIDERS.gemini,
            model: candidateModel,
            taskType,
            ok: true
          });
          return {
            raw: text,
            provider: MODEL_PROVIDERS.gemini,
            model: candidateModel
          };
        }

        const err = new Error('Gemini API returned an unexpected content shape.');
        err.status = 502;
        recordModelAttempt({
          provider: MODEL_PROVIDERS.gemini,
          model: candidateModel,
          taskType,
          ok: false,
          error: err
        });
        throw err;
      }
      }
    }
    }
  }

  const err = new Error(
    `Gemini model was unavailable across fallback attempts. Tried models: ${modelCandidates.join(', ')}. ${lastRetryableError ? `Last error: ${lastRetryableError.message}` : ''}`
  );
  err.status = Number(lastRetryableError?.status || 502);
  throw err;
}

async function groqGenerateJson({ model, systemPrompt, userContent, temperature = 0.2, maxTokens = 1000 }) {
  assertApiKeyConfigured(MODEL_PROVIDERS.groq);

  const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${GROQ_API_KEY}`
    },
    body: JSON.stringify({
      model: model || GROQ_MODELS.default,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userContent }
      ],
      temperature,
      max_tokens: maxTokens,
      response_format: { type: 'json_object' }
    })
  });

  let data;
  try {
    data = await response.json();
  } catch {
    const err = new Error('Groq API returned a non-JSON response.');
    err.status = 502;
    throw err;
  }

  if (!response.ok) {
    const err = new Error(data?.error?.message || `Groq API error (${response.status}).`);
    err.status = response.status;
    throw err;
  }

  const content = data?.choices?.[0]?.message?.content;
  if (typeof content === 'string' && content.trim()) return content;
  if (Array.isArray(content)) {
    const text = content
      .map(part => {
        if (typeof part === 'string') return part;
        if (part && typeof part.text === 'string') return part.text;
        return '';
      })
      .join('');
    if (text.trim()) return text;
  }

  const err = new Error('Groq API returned an unexpected content shape.');
  err.status = 502;
  throw err;
}


function isGroqTokenBudgetError(error) {
  const msg = String(error?.message || '').toLowerCase();
  return msg.includes('requires more credits')
    || msg.includes('fewer max_tokens')
    || msg.includes('can only afford');
}

function isGroqRetryableModelError(error) {
  const status = Number(error?.status || 0);
  const msg = String(error?.message || '').toLowerCase();
  return status === 413
    || msg.includes('request entity too large')
    || msg.includes('decommissioned')
    || msg.includes('not found')
    || msg.includes('blocked at the project level')
    || msg.includes('failed to validate json')
    || msg.includes('json_validate_failed');
}

function isGroqRateLimitError(error) {
  const status = Number(error?.status || 0);
  const msg = String(error?.message || '').toLowerCase();
  return status === 429
    || msg.includes('rate limit')
    || msg.includes('tokens per minute')
    || msg.includes('please try again in');
}

function getGroqRetryDelayMs(error) {
  const message = String(error?.message || '');
  const match = message.match(/try again in\s*([0-9]+(?:\.[0-9]+)?)s/i);
  if (match) {
    const seconds = Number(match[1]);
    if (Number.isFinite(seconds) && seconds > 0) {
      return Math.min(30000, Math.ceil(seconds * 1000) + 300);
    }
  }
  return 1800;
}

function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function truncateText(value, maxLength) {
  const text = typeof value === 'string' ? value : value == null ? '' : String(value);
  if (!Number.isFinite(maxLength) || maxLength <= 0) return '';
  if (text.length <= maxLength) return text;
  return `${text.slice(0, Math.max(0, maxLength - 1))}...`;
}

function compactHeaderLikeList(list, maxItems = 8, maxValueLength = 120) {
  const source = Array.isArray(list) ? list : [];
  return source
    .slice(0, maxItems)
    .map(item => ({
      k: truncateText(item?.k, 40),
      v: truncateText(item?.v, maxValueLength)
    }))
    .filter(item => item.k);
}

const SCAN_PROFILES = new Set(['quick', 'standard', 'deep']);

function normalizeScanProfile(raw) {
  const s = typeof raw === 'string' ? raw.toLowerCase().trim() : '';
  return SCAN_PROFILES.has(s) ? s : 'standard';
}

function compactSecurityContext(context, provider) {
  const isGroq = provider === MODEL_PROVIDERS.groq;
  const scanProfile = normalizeScanProfile(context?.scan_profile);
  const deep = scanProfile === 'deep';
  const paramCandidates = workspaceUtils.collectParamCandidatesFromRequest(
    context?.current_request && typeof context.current_request === 'object'
      ? context.current_request
      : {}
  );
  const maxCandidates = isGroq ? (deep ? 28 : 18) : deep ? 36 : 28;
  const currentRequest = context?.current_request && typeof context.current_request === 'object'
    ? context.current_request
    : {};
  const lastResponse = context?.last_response && typeof context.last_response === 'object'
    ? context.last_response
    : null;
  const testHistory = Array.isArray(context?.test_history) ? context.test_history : [];

  const bodyLimit = isGroq ? (deep ? 900 : 400) : deep ? 1800 : 1200;
  const urlLimit = isGroq ? (deep ? 380 : 320) : deep ? 400 : 320;
  const instructLimit = isGroq ? (deep ? 520 : 320) : deep ? 1600 : 1200;
  const historyFindingLimit = isGroq ? (deep ? 120 : 90) : deep ? 200 : 180;
  const respPreviewLimit = isGroq ? (deep ? 900 : 450) : deep ? 1600 : 1200;

  return {
    target_url: truncateText(context?.target_url, 240),
    scan_profile: scanProfile,
    param_candidates: paramCandidates.slice(0, maxCandidates),
    current_request: {
      method: truncateText(currentRequest.method, 12),
      url: truncateText(currentRequest.url, urlLimit),
      headers: compactHeaderLikeList(currentRequest.headers, isGroq ? (deep ? 8 : 6) : (deep ? 12 : 10), isGroq ? (deep ? 100 : 80) : (deep ? 160 : 140)),
      params: compactHeaderLikeList(currentRequest.params, isGroq ? (deep ? 8 : 6) : (deep ? 12 : 10), isGroq ? (deep ? 100 : 80) : (deep ? 160 : 140)),
      body: truncateText(currentRequest.body, bodyLimit)
    },
    last_response: lastResponse ? {
      status: Number(lastResponse.status || 0),
      elapsed_ms: Number(lastResponse.elapsed_ms || 0),
      body_preview: truncateText(lastResponse.body_preview, respPreviewLimit)
    } : null,
    auth_context: context?.auth_context && typeof context.auth_context === 'object'
      ? {
          type: truncateText(context.auth_context.type, 20),
          value: truncateText(context.auth_context.value, isGroq ? (deep ? 120 : 80) : (deep ? 180 : 140))
        }
      : null,
    test_history: testHistory.slice(isGroq ? (deep ? -8 : -6) : deep ? -16 : -12).map(entry => ({
      method: truncateText(entry?.method, 12),
      url: truncateText(entry?.url, 220),
      status: Number(entry?.status || 0),
      finding: truncateText(entry?.finding, historyFindingLimit)
    })),
    user_instruction: truncateText(context?.user_instruction, instructLimit)
  };
}

async function groqGenerateJsonWithFallback({
  model,
  profile = 'default',
  taskType = TASK_TYPES.agent,
  allowModelFallback = true,
  systemPrompt,
  userContent,
  temperature = 0.2,
  maxTokens = 1000,
  fallbackTokens = [800, 600, 500, 400, 300, 200],
  rateLimitRetries = 3
}) {
  const modelCandidates = buildGroqModelCandidates(model, profile, allowModelFallback, taskType);
  const tried = new Set();
  const rateRetryCount = new Map();
  let lastError;

  for (const candidateModel of modelCandidates) {
    const stats = getModelRuntimeStats(MODEL_PROVIDERS.groq, candidateModel);
    const tokenPlan = buildAdaptiveTokenPlan(maxTokens, fallbackTokens, stats);

    for (const tokens of tokenPlan) {
      const key = `${candidateModel}::${tokens}`;
      if (tried.has(key)) continue;
      tried.add(key);

      try {
        const raw = await groqGenerateJson({
          model: candidateModel,
          systemPrompt,
          userContent,
          temperature,
          maxTokens: tokens
        });
        recordModelAttempt({
          provider: MODEL_PROVIDERS.groq,
          model: candidateModel,
          taskType,
          ok: true
        });
        return {
          raw,
          provider: MODEL_PROVIDERS.groq,
          model: candidateModel
        };
      } catch (error) {
        recordModelAttempt({
          provider: MODEL_PROVIDERS.groq,
          model: candidateModel,
          taskType,
          ok: false,
          error
        });
        lastError = error;

        if (isGroqRateLimitError(error)) {
          const keyRetry = `${candidateModel}::${tokens}`;
          const used = Number(rateRetryCount.get(keyRetry) || 0);
          if (used < rateLimitRetries) {
            rateRetryCount.set(keyRetry, used + 1);
            await wait(getGroqRetryDelayMs(error));
            continue;
          }
          throw error;
        }

        if (!isGroqTokenBudgetError(error)) {
          if (!isGroqRetryableModelError(error)) {
            throw error;
          }
        }
        continue;
      }
    }
  }

  throw lastError || new Error('Groq request failed after token fallback attempts.');
}

async function openRouterGenerateJsonWithFallback({
  model,
  taskType = TASK_TYPES.agent,
  modelCandidates,
  systemPrompt,
  userContent,
  temperature = 0.2,
  maxTokens = 1000,
  fallbackTokens = [1400, 1200, 1000, 800, 600]
}) {
  const candidates = Array.isArray(modelCandidates) && modelCandidates.length > 0
    ? rankModelsForTask(MODEL_PROVIDERS.openrouter, modelCandidates, taskType)
    : buildOpenRouterModelCandidates(model, taskType);
  const tried = new Set();
  let lastError;

  for (const candidateModel of candidates) {
    const stats = getModelRuntimeStats(MODEL_PROVIDERS.openrouter, candidateModel);
    const tokenPlan = buildAdaptiveTokenPlan(maxTokens, fallbackTokens, stats);

    for (const tokens of tokenPlan) {
      const key = `${candidateModel}::${tokens}`;
      if (tried.has(key)) continue;
      tried.add(key);

      try {
        const raw = await openRouterGenerateJson({
          model: candidateModel,
          systemPrompt,
          userContent,
          temperature,
          maxTokens: tokens
        });
        recordModelAttempt({
          provider: MODEL_PROVIDERS.openrouter,
          model: candidateModel,
          taskType,
          ok: true
        });
        return {
          raw,
          provider: MODEL_PROVIDERS.openrouter,
          model: candidateModel
        };
      } catch (error) {
        recordModelAttempt({
          provider: MODEL_PROVIDERS.openrouter,
          model: candidateModel,
          taskType,
          ok: false,
          error
        });
        lastError = error;
        const reason = classifyFailureReason(error);
        if (!['token_budget', 'rate_limit', 'model_unavailable'].includes(reason)) {
          throw error;
        }
      }
    }
  }

  throw lastError || new Error('OpenRouter request failed after token fallback attempts.');
}

function resolveModelSelection({ provider, requestedModel, profile = 'default', taskType = TASK_TYPES.agent, allowModelFallback = true }) {
  const hasRequestedModel = typeof requestedModel === 'string' && requestedModel.trim().length > 0;

  if (!allowModelFallback && hasRequestedModel) {
    if (provider === MODEL_PROVIDERS.groq) {
      const preferred = parseGroqModel(requestedModel, profile, taskType);
      return { preferred, candidates: preferred ? [preferred] : [] };
    }
    if (provider === MODEL_PROVIDERS.gemini) {
      const preferred = parseGeminiModel(requestedModel, profile, taskType);
      return { preferred, candidates: preferred ? [preferred] : [] };
    }
    const preferred = parseOpenRouterModel(requestedModel);
    return { preferred, candidates: preferred ? [preferred] : [] };
  }

  if (provider === MODEL_PROVIDERS.groq) {
    const candidates = buildGroqModelCandidates(requestedModel, profile, allowModelFallback, taskType);
    return {
      preferred: candidates[0] || parseGroqModel(null, profile, taskType),
      candidates
    };
  }

  if (provider === MODEL_PROVIDERS.gemini) {
    const candidates = buildGeminiModelCandidates(requestedModel, profile, taskType);
    return {
      preferred: candidates[0] || parseGeminiModel(null, profile, taskType),
      candidates
    };
  }

  const candidates = buildOpenRouterModelCandidates(requestedModel, taskType);
  return {
    preferred: candidates[0] || parseOpenRouterModel(null),
    candidates
  };
}

function normalizeGenerationResult(result, fallbackProvider, fallbackModel) {
  if (typeof result === 'string') {
    return {
      raw: result,
      provider: fallbackProvider,
      model: fallbackModel
    };
  }
  return {
    raw: String(result?.raw || ''),
    provider: result?.provider || fallbackProvider,
    model: result?.model || fallbackModel
  };
}

function parseJsonObjectLoose(raw) {
  const text = String(raw || '').trim();
  if (!text) {
    const err = new Error('Model output was empty.');
    err.status = 502;
    throw err;
  }

  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
  } catch {}

  const firstCurly = text.indexOf('{');
  const lastCurly = text.lastIndexOf('}');
  if (firstCurly >= 0 && lastCurly > firstCurly) {
    const slice = text.slice(firstCurly, lastCurly + 1);
    try {
      const parsed = JSON.parse(slice);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
    } catch {}
  }

  const err = new Error('Model output was not valid JSON.');
  err.status = 502;
  throw err;
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function normalizeKVArray(arr) {
  if (!Array.isArray(arr)) return [];
  return arr
    .filter(item => item && typeof item === 'object' && typeof item.k === 'string')
    .map(item => ({
      k: item.k,
      v: typeof item.v === 'string' ? item.v : ''
    }));
}

function validateAgentAction(action, index) {
  if (!action || typeof action !== 'object') {
    return { error: `actions[${index}] must be an object.` };
  }

  const allowedMethods = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
  const type = action.type;
  if (!isNonEmptyString(type)) {
    return { error: `actions[${index}].type must be a non-empty string.` };
  }

  if (type === 'set_request') {
    if (!allowedMethods.has(String(action.method || '').toUpperCase())) return { error: `actions[${index}] invalid method.` };
    if (!isNonEmptyString(action.url)) return { error: `actions[${index}] missing url.` };
    return {
      value: {
        type,
        name: isNonEmptyString(action.name) ? action.name : 'Generated Request',
        method: String(action.method).toUpperCase(),
        url: action.url,
        params: normalizeKVArray(action.params),
        headers: normalizeKVArray(action.headers),
        body: typeof action.body === 'string' ? action.body : ''
      }
    };
  }

  if (type === 'set_assertions') {
    const assertions = Array.isArray(action.assertions)
      ? action.assertions.filter(x => isNonEmptyString(x))
      : [];
    if (!assertions.length) return { error: `actions[${index}] has no valid assertions.` };
    return { value: { type, assertions } };
  }

  if (type === 'chain_request') {
    if (!allowedMethods.has(String(action.method || '').toUpperCase())) return { error: `actions[${index}] invalid method.` };
    if (!isNonEmptyString(action.url) || !isNonEmptyString(action.name)) {
      return { error: `actions[${index}] missing name/url.` };
    }
    return {
      value: {
        type,
        name: action.name,
        method: String(action.method).toUpperCase(),
        url: action.url,
        params: normalizeKVArray(action.params),
        headers: normalizeKVArray(action.headers),
        body: typeof action.body === 'string' ? action.body : '',
        chainNote: typeof action.chainNote === 'string' ? action.chainNote : ''
      }
    };
  }

  if (type === 'debug_info') {
    const findings = Array.isArray(action.findings)
      ? action.findings.filter(x => isNonEmptyString(x))
      : [];
    if (!findings.length) return { error: `actions[${index}] has no valid findings.` };
    return {
      value: {
        type,
        findings,
        fix: typeof action.fix === 'string' ? action.fix : '',
        patch: action.patch && typeof action.patch === 'object' ? action.patch : undefined
      }
    };
  }

  return { error: `actions[${index}] unsupported type: ${type}.` };
}

function validateSecurityAction(action, index) {
  if (!action || typeof action !== 'object') {
    return { error: `actions[${index}] must be an object.` };
  }

  const type = action.type;
  const allowedMethods = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
  if (!isNonEmptyString(type)) return { error: `actions[${index}].type must be a non-empty string.` };

  if (type === 'probe') {
    const method = String(action.method || '').toUpperCase();
    if (!allowedMethods.has(method) || !isNonEmptyString(action.url)) {
      return { error: `actions[${index}] invalid probe method/url.` };
    }
    return {
      value: {
        type,
        name: isNonEmptyString(action.name) ? action.name : 'Security probe',
        method,
        url: action.url,
        headers: normalizeKVArray(action.headers),
        params: normalizeKVArray(action.params),
        body: typeof action.body === 'string' ? action.body : '',
        vector: isNonEmptyString(action.vector) ? action.vector : 'Unknown',
        hypothesis: typeof action.hypothesis === 'string' ? action.hypothesis : '',
        auto_chain: Boolean(action.auto_chain)
      }
    };
  }

  if (type === 'probe_chain') {
    const steps = Array.isArray(action.steps) ? action.steps : [];
    if (!steps.length) return { error: `actions[${index}] probe_chain requires steps.` };
    const normalizedSteps = [];
    for (let i = 0; i < steps.length; i += 1) {
      const step = steps[i];
      const method = String(step?.method || '').toUpperCase();
      if (!allowedMethods.has(method) || !isNonEmptyString(step?.url)) {
        return { error: `actions[${index}].steps[${i}] invalid method/url.` };
      }
      normalizedSteps.push({
        step: Number(step.step || i + 1),
        name: isNonEmptyString(step.name) ? step.name : `Step ${i + 1}`,
        method,
        url: step.url,
        headers: normalizeKVArray(step.headers),
        body: typeof step.body === 'string' ? step.body : '',
        vector: isNonEmptyString(step.vector) ? step.vector : 'Unknown',
        hypothesis: typeof step.hypothesis === 'string' ? step.hypothesis : '',
        extract: step.extract && typeof step.extract === 'object' ? step.extract : undefined
      });
    }
    return {
      value: {
        type,
        name: isNonEmptyString(action.name) ? action.name : 'Security probe chain',
        steps: normalizedSteps
      }
    };
  }

  if (type === 'fuzz_list') {
    const payloads = Array.isArray(action.payloads)
      ? action.payloads.filter(x => isNonEmptyString(x))
      : [];
    if (!payloads.length) return { error: `actions[${index}] fuzz_list requires payloads.` };
    return {
      value: {
        type,
        vector: isNonEmptyString(action.vector) ? action.vector : 'Unknown',
        target_param: typeof action.target_param === 'string' ? action.target_param : '',
        target_location: typeof action.target_location === 'string' ? action.target_location : 'query',
        payloads,
        success_indicators: action.success_indicators && typeof action.success_indicators === 'object' ? action.success_indicators : {}
      }
    };
  }

  if (type === 'scan_plan') {
    const rawSteps = Array.isArray(action.steps) ? action.steps : [];
    const normalizedSteps = rawSteps.map((step, i) => ({
      order: Number(step?.order || i + 1),
      vector: isNonEmptyString(step?.vector) ? step.vector : 'Unknown',
      description: typeof step?.description === 'string' ? step.description : '',
      target_param: typeof step?.target_param === 'string' ? step.target_param : '',
      owasp_api_label: typeof step?.owasp_api_label === 'string' ? step.owasp_api_label : ''
    }));
    const param_matrix = Array.isArray(action.param_matrix)
      ? action.param_matrix
        .map(entry => ({
          param: typeof entry?.param === 'string' ? entry.param.trim() : '',
          location: ['query', 'body', 'header'].includes(String(entry?.location))
            ? entry.location
            : 'query'
        }))
        .filter(entry => entry.param)
      : [];
    return {
      value: {
        type,
        target: typeof action.target === 'string' ? action.target : '',
        method_coverage: Array.isArray(action.method_coverage)
          ? action.method_coverage.map(m => String(m).toUpperCase()).filter(Boolean)
          : [],
        steps: normalizedSteps,
        param_matrix
      }
    };
  }

  if (type === 'set_assertions') {
    const assertions = Array.isArray(action.assertions)
      ? action.assertions.filter(x => isNonEmptyString(x))
      : [];
    if (!assertions.length) return { error: `actions[${index}] has no valid assertions.` };
    return { value: { type, assertions } };
  }

  if (type === 'debug_info') {
    const findings = Array.isArray(action.findings)
      ? action.findings.filter(x => isNonEmptyString(x))
      : [];
    if (!findings.length) return { error: `actions[${index}] has no valid findings.` };
    return {
      value: {
        type,
        findings,
        fix: typeof action.fix === 'string' ? action.fix : '',
        patch: action.patch && typeof action.patch === 'object' ? action.patch : undefined
      }
    };
  }

  return { error: `actions[${index}] unsupported type: ${type}.` };
}

function parseAgentPayload(raw) {
  const parsed = parseJsonObjectLoose(raw);
  if (!isNonEmptyString(parsed.message) || !Array.isArray(parsed.actions)) {
    const err = new Error('Model output is missing required fields: message/actions.');
    err.status = 502;
    throw err;
  }

  const normalizedActions = [];
  const errors = [];
  parsed.actions.forEach((action, index) => {
    const result = validateAgentAction(action, index);
    if (result.error) errors.push(result.error);
    else normalizedActions.push(result.value);
  });

  if (errors.length) {
    const err = new Error(`Invalid agent actions: ${errors.join(' | ')}`);
    err.status = 502;
    throw err;
  }

  return {
    message: parsed.message,
    actions: normalizedActions
  };
}

function parseSecurityPayload(raw) {
  const parsed = parseJsonObjectLoose(raw);
  const levels = new Set(['none', 'low', 'medium', 'high', 'critical']);
  const findingSeverities = new Set(['info', 'low', 'medium', 'high', 'critical']);

  if (!isNonEmptyString(parsed.message)) {
    const err = new Error('Security model output is missing required field: message.');
    err.status = 502;
    throw err;
  }
  if (!levels.has(parsed.threat_level)) {
    const err = new Error('Security model output has invalid threat_level.');
    err.status = 502;
    throw err;
  }
  if (!Array.isArray(parsed.findings) || !Array.isArray(parsed.actions)) {
    const err = new Error('Security model output is missing required arrays: findings/actions.');
    err.status = 502;
    throw err;
  }

  const normalizedFindings = [];
  parsed.findings.forEach((finding, index) => {
    if (!finding || typeof finding !== 'object') {
      const err = new Error(`Security finding at index ${index} must be an object.`);
      err.status = 502;
      throw err;
    }
    if (!findingSeverities.has(finding.severity)) {
      const err = new Error(`Security finding at index ${index} has invalid severity.`);
      err.status = 502;
      throw err;
    }
    normalizedFindings.push({
      id: typeof finding.id === 'string' ? finding.id : `FINDING-${String(index + 1).padStart(3, '0')}`,
      vulnerability: typeof finding.vulnerability === 'string' ? finding.vulnerability : 'Unknown',
      severity: finding.severity,
      evidence: typeof finding.evidence === 'string' ? finding.evidence : '',
      cve_hint: typeof finding.cve_hint === 'string' || finding.cve_hint === null ? finding.cve_hint : null,
      owasp_api_label: typeof finding.owasp_api_label === 'string' && finding.owasp_api_label.trim()
        ? truncateText(finding.owasp_api_label, 160)
        : null,
      remediation: typeof finding.remediation === 'string' ? finding.remediation : ''
    });
  });

  const normalizedActions = [];
  const errors = [];
  parsed.actions.forEach((action, index) => {
    const result = validateSecurityAction(action, index);
    if (result.error) errors.push(result.error);
    else normalizedActions.push(result.value);
  });
  if (errors.length) {
    const err = new Error(`Invalid security actions: ${errors.join(' | ')}`);
    err.status = 502;
    throw err;
  }

  return {
    message: parsed.message,
    threat_level: parsed.threat_level,
    findings: normalizedFindings,
    actions: normalizedActions
  };
}

function parseAssertionsPayload(raw) {
  const parsed = parseJsonObjectLoose(raw);
  const assertions = Array.isArray(parsed?.assertions)
    ? parsed.assertions.filter(x => isNonEmptyString(x))
    : [];
  if (!assertions.length) {
    const err = new Error('Assertions payload is missing a non-empty assertions array.');
    err.status = 502;
    throw err;
  }
  return { assertions };
}

const ASSERTIONS_MODES = new Set(['functional', 'security', 'contract']);

function normalizeAssertionsMode(raw) {
  const m = typeof raw === 'string' ? raw.toLowerCase().trim() : '';
  return ASSERTIONS_MODES.has(m) ? m : 'functional';
}

function buildAssertionsSystemPrompt(mode) {
  switch (mode) {
    case 'security':
      return 'You are an API security testing assistant. Generate assertions that detect verbose errors, stack traces, SQL/NoSQL error signatures, missing authentication when it should be required, and sensitive tokens in plaintext. Use variables: status (number), json (parsed object or null), body (string). Return strict JSON only: {"assertions": string[]}.';
    case 'contract':
      return 'You are an API contract testing assistant. Generate assertions that validate required fields, types, and array lengths using expected_schema when provided. Use variables: status, json, body. Return strict JSON only: {"assertions": string[]}.';
    default:
      return 'You are an API testing assistant. Return strict JSON only.';
  }
}

function buildAssertionsInstructionText(mode) {
  switch (mode) {
    case 'security':
      return 'Generate 5 to 8 assertions as JS expressions. Prefer negative checks (!body.includes), auth expectations, and status gates.';
    case 'contract':
      return 'Generate 4 to 8 assertions validating the response against expected_schema and response shape.';
    default:
      return 'Generate 4 to 6 useful test assertions as JS expressions using variables: status, json, body. Return shape: {"assertions": ["..."]}.';
  }
}

async function parseWithRepairLoop({
  initialRaw,
  parseFn,
  buildRepairInput,
  runRepair,
  maxAttempts = 3
}) {
  let raw = initialRaw;
  let lastError = null;
  const diagnostics = {
    attempts: 0,
    repairCount: 0,
    repaired: false,
    errors: [],
    maxAttempts,
    status: 'pending'
  };

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    diagnostics.attempts = attempt;
    try {
      const payload = parseFn(raw);
      diagnostics.repaired = diagnostics.repairCount > 0;
      diagnostics.status = diagnostics.repaired ? 'repaired' : 'valid';
      return { payload, diagnostics };
    } catch (error) {
      lastError = error;
      diagnostics.errors.push({
        attempt,
        message: String(error?.message || 'Unknown validation error')
      });
      if (attempt >= maxAttempts) {
        error.diagnostics = diagnostics;
        throw error;
      }
      const repairInput = buildRepairInput({ attempt, error, raw });
      diagnostics.repairCount += 1;
      raw = await runRepair(repairInput);
    }
  }

  const fallbackError = lastError || new Error('Structured parse failed.');
  fallbackError.diagnostics = diagnostics;
  throw fallbackError;
}

app.post('/api/agent', async (req, res) => {
  try {
    const context = req.body?.context;
    const requestedModel = req.body?.model;
    const hasExplicitModel = typeof requestedModel === 'string' && requestedModel.trim().length > 0;
    const provider = parseProvider(req.body?.provider);
    const selection = resolveModelSelection({
      provider,
      requestedModel,
      profile: 'default',
      taskType: TASK_TYPES.agent,
      allowModelFallback: !hasExplicitModel
    });

    if (!context || typeof context !== 'object') {
      return res.status(400).json({ error: 'Missing request body field: context (object).' });
    }

    const systemPrompt = `${AGENT_MASTER_PROMPT}\n\n${MODE_RULES_PROMPT}\n\n${CONTEXT_AWARENESS_PROMPT}`;
    const userContent = JSON.stringify(context);
    const runAgentGeneration = async ({ systemPromptOverride, userContentOverride }) => {
      const effectiveSystemPrompt = systemPromptOverride || systemPrompt;
      const effectiveUserContent = userContentOverride || userContent;
      if (provider === MODEL_PROVIDERS.gemini) {
        try {
          return normalizeGenerationResult(await geminiGenerateJson({
            model: selection.preferred,
            profile: 'default',
            taskType: TASK_TYPES.agent,
            systemPrompt: effectiveSystemPrompt,
            userContent: effectiveUserContent
          }), MODEL_PROVIDERS.gemini, selection.preferred);
        } catch (error) {
          if (!hasExplicitModel && isGeminiQuotaError(error) && OPENROUTER_API_KEY) {
            return normalizeGenerationResult(await openRouterGenerateJsonWithFallback({
              modelCandidates: buildOpenRouterModelCandidates(OPENROUTER_MODELS.default, TASK_TYPES.agent),
              taskType: TASK_TYPES.agent,
              systemPrompt: effectiveSystemPrompt,
              userContent: effectiveUserContent
            }), MODEL_PROVIDERS.openrouter, OPENROUTER_MODELS.default);
          }
          throw error;
        }
      }

      if (provider === MODEL_PROVIDERS.groq) {
        return normalizeGenerationResult(await groqGenerateJsonWithFallback({
          model: selection.preferred,
          profile: 'default',
          taskType: TASK_TYPES.agent,
          allowModelFallback: !hasExplicitModel,
          systemPrompt: effectiveSystemPrompt,
          userContent: effectiveUserContent,
          maxTokens: 1000,
          fallbackTokens: [800, 600, 500, 400, 300, 200]
        }), MODEL_PROVIDERS.groq, selection.preferred);
      }

      return normalizeGenerationResult(await openRouterGenerateJsonWithFallback({
        model: selection.preferred,
        modelCandidates: selection.candidates,
        taskType: TASK_TYPES.agent,
        systemPrompt: effectiveSystemPrompt,
        userContent: effectiveUserContent
      }), MODEL_PROVIDERS.openrouter, selection.preferred);
    };

    const initialResult = await runAgentGeneration({});
    const repaired = await parseWithRepairLoop({
      initialRaw: initialResult.raw,
      parseFn: parseAgentPayload,
      buildRepairInput: ({ error, raw, attempt }) => {
        const repairSystemPrompt = `${systemPrompt}\n\nSTRICT STRUCTURED OUTPUT REPAIR\nReturn only valid JSON matching {\"message\": string, \"actions\": array}. Do not include markdown.`;
        const repairUserContent = JSON.stringify({
          task: 'repair_agent_output',
          attempt,
          validation_error: error.message,
          original_output: String(raw || '').slice(0, 12000),
          required_schema: {
            message: 'string',
            actions: ['set_request | set_assertions | chain_request | debug_info']
          }
        });
        return { repairSystemPrompt, repairUserContent };
      },
      runRepair: async ({ repairSystemPrompt, repairUserContent }) => (await runAgentGeneration({
        systemPromptOverride: repairSystemPrompt,
        userContentOverride: repairUserContent
      })).raw,
      maxAttempts: 3
    });
    return res.json({
      ...repaired.payload,
      diagnostics: {
        ...repaired.diagnostics,
        engine: 'agent',
        provider: initialResult.provider,
        model: initialResult.model,
        requested_provider: provider,
        requested_model: selection.preferred
      }
    });
  } catch (error) {
    const status = Number(error.status || 500);
    return res.status(status).json({ error: error.message || 'Failed to process agent request.' });
  }
});

app.post('/api/assertions', async (req, res) => {
  try {
    const responseStatus = req.body?.status;
    const bodyPreview = req.body?.body_preview;
    const requestedModel = req.body?.model;
    const hasExplicitModel = typeof requestedModel === 'string' && requestedModel.trim().length > 0;
    const provider = parseProvider(req.body?.provider);
    const selection = resolveModelSelection({
      provider,
      requestedModel,
      profile: 'default',
      taskType: TASK_TYPES.assertions,
      allowModelFallback: !hasExplicitModel
    });

    if (typeof responseStatus !== 'number') {
      return res.status(400).json({ error: 'Missing request body field: status (number).' });
    }

    const mode = normalizeAssertionsMode(req.body?.mode);
    const assertionGoals = Array.isArray(req.body?.assertion_goals)
      ? req.body.assertion_goals.filter(x => typeof x === 'string' && x.trim()).slice(0, 12)
      : [];
    const expectedSchema = req.body?.expected_schema;
    const instruction = {
      mode,
      instruction: buildAssertionsInstructionText(mode),
      assertion_goals: assertionGoals,
      ...(expectedSchema !== undefined && expectedSchema !== null ? { expected_schema: expectedSchema } : {}),
      status: responseStatus,
      body_preview: typeof bodyPreview === 'string' ? bodyPreview : ''
    };

    const systemPrompt = buildAssertionsSystemPrompt(mode);
    const userContent = JSON.stringify(instruction);
    const runAssertionsGeneration = async ({ systemPromptOverride, userContentOverride }) => {
      const effectiveSystemPrompt = systemPromptOverride || systemPrompt;
      const effectiveUserContent = userContentOverride || userContent;

      if (provider === MODEL_PROVIDERS.gemini) {
        try {
          return normalizeGenerationResult(await geminiGenerateJson({
            model: selection.preferred,
            profile: 'default',
            taskType: TASK_TYPES.assertions,
            systemPrompt: effectiveSystemPrompt,
            userContent: effectiveUserContent
          }), MODEL_PROVIDERS.gemini, selection.preferred);
        } catch (error) {
          if (!hasExplicitModel && isGeminiQuotaError(error) && OPENROUTER_API_KEY) {
            return normalizeGenerationResult(await openRouterGenerateJsonWithFallback({
              modelCandidates: buildOpenRouterModelCandidates(OPENROUTER_MODELS.default, TASK_TYPES.assertions),
              taskType: TASK_TYPES.assertions,
              systemPrompt: effectiveSystemPrompt,
              userContent: effectiveUserContent
            }), MODEL_PROVIDERS.openrouter, OPENROUTER_MODELS.default);
          }
          throw error;
        }
      }

      if (provider === MODEL_PROVIDERS.groq) {
        return normalizeGenerationResult(await groqGenerateJsonWithFallback({
          model: selection.preferred,
          profile: 'default',
          taskType: TASK_TYPES.assertions,
          allowModelFallback: !hasExplicitModel,
          systemPrompt: effectiveSystemPrompt,
          userContent: effectiveUserContent,
          maxTokens: 800,
          fallbackTokens: [600, 500, 400, 300, 200]
        }), MODEL_PROVIDERS.groq, selection.preferred);
      }

      return normalizeGenerationResult(await openRouterGenerateJsonWithFallback({
        model: selection.preferred,
        modelCandidates: selection.candidates,
        taskType: TASK_TYPES.assertions,
        systemPrompt: effectiveSystemPrompt,
        userContent: effectiveUserContent
      }), MODEL_PROVIDERS.openrouter, selection.preferred);
    };

    const initialResult = await runAssertionsGeneration({});
    const repaired = await parseWithRepairLoop({
      initialRaw: initialResult.raw,
      parseFn: parseAssertionsPayload,
      buildRepairInput: ({ error, raw, attempt }) => {
        const countHint = mode === 'security' ? '5-8' : mode === 'contract' ? '4-8' : '4-6';
        const repairSystemPrompt = `${systemPrompt}\n\nSTRICT STRUCTURED OUTPUT REPAIR\nReturn only valid JSON matching {\"assertions\": string[]} with ${countHint} assertions.`;
        const repairUserContent = JSON.stringify({
          task: 'repair_assertions_output',
          attempt,
          validation_error: error.message,
          original_output: String(raw || '').slice(0, 10000)
        });
        return { repairSystemPrompt, repairUserContent };
      },
      runRepair: async ({ repairSystemPrompt, repairUserContent }) => (await runAssertionsGeneration({
        systemPromptOverride: repairSystemPrompt,
        userContentOverride: repairUserContent
      })).raw,
      maxAttempts: 3
    });

    return res.json({
      assertions: repaired.payload.assertions,
      mode,
      diagnostics: {
        ...repaired.diagnostics,
        engine: 'assertions',
        provider: initialResult.provider,
        model: initialResult.model,
        requested_provider: provider,
        requested_model: selection.preferred
      }
    });
  } catch (error) {
    const errStatus = Number(error.status || 500);
    return res.status(errStatus).json({ error: error.message || 'Failed to generate assertions.' });
  }
});

app.post('/api/security-agent', async (req, res) => {
  try {
    const provider = parseProvider(req.body?.provider);
    const requestedModel = req.body?.model;
    const hasExplicitModel = typeof requestedModel === 'string' && requestedModel.trim().length > 0;
    const selection = resolveModelSelection({
      provider,
      requestedModel,
      profile: 'security',
      taskType: TASK_TYPES.security,
      allowModelFallback: !hasExplicitModel
    });
    const bodyContext = req.body?.context;
    const context = bodyContext && typeof bodyContext === 'object'
      ? bodyContext
      : {
          target_url: req.body?.target_url ?? '',
          current_request: req.body?.current_request ?? null,
          last_response: req.body?.last_response ?? null,
          auth_context: req.body?.auth_context ?? null,
          test_history: req.body?.test_history ?? [],
          user_instruction: req.body?.user_instruction ?? ''
        };

    if (!context || typeof context !== 'object') {
      return res.status(400).json({ error: 'Missing security context object.' });
    }
    if (typeof req.body?.scan_profile === 'string' && context.scan_profile == null) {
      context.scan_profile = req.body.scan_profile;
    }

    const securityUserContent = JSON.stringify(compactSecurityContext(context, provider));
    const runSecurityGeneration = async ({ systemPromptOverride, userContentOverride }) => {
      const effectiveSystemPrompt = systemPromptOverride || SECURITY_MASTER_PROMPT;
      const effectiveUserContent = userContentOverride || securityUserContent;

      if (provider === MODEL_PROVIDERS.gemini) {
        try {
          return normalizeGenerationResult(await geminiGenerateJson({
            model: selection.preferred,
            profile: 'security',
            taskType: TASK_TYPES.security,
            systemPrompt: effectiveSystemPrompt,
            userContent: effectiveUserContent,
            temperature: 0.1,
            maxTokens: 1200
          }), MODEL_PROVIDERS.gemini, selection.preferred);
        } catch (error) {
          if (!hasExplicitModel && isGeminiQuotaError(error) && OPENROUTER_API_KEY) {
            return normalizeGenerationResult(await openRouterGenerateJsonWithFallback({
              modelCandidates: buildOpenRouterModelCandidates(OPENROUTER_MODELS.security, TASK_TYPES.security),
              taskType: TASK_TYPES.security,
              systemPrompt: effectiveSystemPrompt,
              userContent: effectiveUserContent,
              temperature: 0.1,
              maxTokens: 1400,
              fallbackTokens: [1200, 1000, 800, 600]
            }), MODEL_PROVIDERS.openrouter, OPENROUTER_MODELS.security);
          }
          throw error;
        }
      }

      if (provider === MODEL_PROVIDERS.groq) {
        return normalizeGenerationResult(await groqGenerateJsonWithFallback({
          model: selection.preferred,
          profile: 'security',
          taskType: TASK_TYPES.security,
          allowModelFallback: !hasExplicitModel,
          systemPrompt: effectiveSystemPrompt,
          userContent: effectiveUserContent,
          temperature: 0.1,
          maxTokens: 800,
          fallbackTokens: [600, 500, 400, 300, 200]
        }), MODEL_PROVIDERS.groq, selection.preferred);
      }

      return normalizeGenerationResult(await openRouterGenerateJsonWithFallback({
        model: selection.preferred,
        modelCandidates: selection.candidates,
        taskType: TASK_TYPES.security,
        systemPrompt: effectiveSystemPrompt,
        userContent: effectiveUserContent,
        temperature: 0.1,
        maxTokens: 1400,
        fallbackTokens: [1200, 1000, 800, 600]
      }), MODEL_PROVIDERS.openrouter, selection.preferred);
    };

    const initialResult = await runSecurityGeneration({});
    const repaired = await parseWithRepairLoop({
      initialRaw: initialResult.raw,
      parseFn: parseSecurityPayload,
      buildRepairInput: ({ error, raw, attempt }) => {
        const repairSystemPrompt = `${SECURITY_MASTER_PROMPT}\n\nSTRICT STRUCTURED OUTPUT REPAIR\nReturn only valid JSON with fields: message, threat_level, findings[], actions[].`;
        const repairUserContent = JSON.stringify({
          task: 'repair_security_output',
          attempt,
          validation_error: error.message,
          original_output: String(raw || '').slice(0, 12000)
        });
        return { repairSystemPrompt, repairUserContent };
      },
      runRepair: async ({ repairSystemPrompt, repairUserContent }) => (await runSecurityGeneration({
        systemPromptOverride: repairSystemPrompt,
        userContentOverride: repairUserContent
      })).raw,
      maxAttempts: 3
    });

    return res.json({
      ...repaired.payload,
      diagnostics: {
        ...repaired.diagnostics,
        engine: 'security',
        provider: initialResult.provider,
        model: initialResult.model,
        requested_provider: provider,
        requested_model: selection.preferred
      }
    });
  } catch (error) {
    const status = Number(error.status || 500);
    return res.status(status).json({ error: error.message || 'Failed to process security agent request.' });
  }
});

app.post('/api/request', async (req, res) => {
  try {
    const method = typeof req.body?.method === 'string' ? req.body.method.toUpperCase() : 'GET';
    const url = typeof req.body?.url === 'string' ? req.body.url.trim() : '';
    const headers = req.body?.headers && typeof req.body.headers === 'object' ? req.body.headers : {};
    const body = typeof req.body?.body === 'string' ? req.body.body : '';
    const confirmMutation = req.body?.confirm_mutation === true;

    const allowedMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
    if (!allowedMethods.includes(method)) {
      return res.status(400).json({ error: `Unsupported method: ${method}` });
    }

    if (!url) {
      return res.status(400).json({ error: 'Missing request field: url' });
    }

    let parsedUrl;
    try {
      parsedUrl = new URL(url);
    } catch {
      return res.status(400).json({ error: 'Invalid URL' });
    }

    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      return res.status(400).json({ error: 'Only http/https URLs are allowed.' });
    }

    await assertUrlAllowed(parsedUrl);

    if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && !confirmMutation) {
      return res.status(400).json({ error: 'Mutation requests require explicit confirmation.' });
    }

    const forwardHeaders = sanitizeOutboundHeaders(headers);

    const outbound = {
      method,
      headers: forwardHeaders
    };

    if (body && !['GET', 'HEAD'].includes(method)) {
      outbound.body = body;
      if (!outbound.headers['Content-Type'] && !outbound.headers['content-type']) {
        outbound.headers['Content-Type'] = 'application/json';
      }
    }

    const startedAt = Date.now();
    const timeoutController = new AbortController();
    const timeoutId = setTimeout(() => timeoutController.abort(), OUTBOUND_REQUEST_TIMEOUT_MS);

    let upstream;
    try {
      upstream = await fetch(parsedUrl.toString(), { ...outbound, signal: timeoutController.signal });
    } finally {
      clearTimeout(timeoutId);
    }

    const text = await readResponseTextWithLimit(upstream, OUTBOUND_RESPONSE_MAX_BYTES);
    const elapsed_ms = Date.now() - startedAt;
    const responseHeaders = Object.fromEntries(upstream.headers.entries());

    return res.status(200).json({
      status: upstream.status,
      statusText: upstream.statusText,
      elapsed_ms,
      headers: responseHeaders,
      body: text
    });
  } catch (error) {
    const status = Number(error?.status || (error?.name === 'AbortError' ? 504 : 502));
    const message = error?.name === 'AbortError'
      ? `Upstream request timed out after ${OUTBOUND_REQUEST_TIMEOUT_MS}ms.`
      : error?.message || 'Upstream request failed.';
    return res.status(status).json({ error: message });
  }
});

app.get('/api/health', (_req, res) => {
  const modelStats = [...MODEL_RUNTIME_STATS.values()];
  res.json({
    ok: true,
    model_default: OPENROUTER_MODELS.default,
    model_security: OPENROUTER_MODELS.security,
    reliability_registry_size: Object.keys(MODEL_CAPABILITY_REGISTRY).length,
    runtime_model_stats: modelStats.length,
    providers: {
      openrouter: Boolean(OPENROUTER_API_KEY),
      gemini: Boolean(GEMINI_API_KEY),
      groq: Boolean(GROQ_API_KEY)
    }
  });
});

app.get('/api/config', (_req, res) => {
  res.json({
    providers: MODEL_PROVIDERS,
    models: {
      openrouter: OPENROUTER_MODELS,
      gemini: GEMINI_MODELS,
      groq: GROQ_MODELS,
      groq_options: GROQ_MODEL_ORDER
    },
    outbound_policy: {
      blocks_auth_headers: true,
      mutation_confirmation_required: true
    }
  });
});

app.get('/api/model-reliability', (_req, res) => {
  const stats = [...MODEL_RUNTIME_STATS.values()]
    .sort((a, b) => {
      const aFailureRate = a.failures / Math.max(1, a.attempts);
      const bFailureRate = b.failures / Math.max(1, b.attempts);
      if (bFailureRate !== aFailureRate) return bFailureRate - aFailureRate;
      return b.attempts - a.attempts;
    });

  res.json({
    registry: MODEL_CAPABILITY_REGISTRY,
    runtime: stats
  });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`AgentMan server listening on http://localhost:${PORT}`);
  });
}

module.exports = app;
