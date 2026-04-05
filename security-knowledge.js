const fs = require('fs');
const path = require('path');
const securityPayloadPacks = require('./security-payload-packs');

const DATASET_PATH = path.join(__dirname, 'security-cve-dataset.json');

let cachedDataset = null;

function loadSecurityDataset() {
  if (cachedDataset) return cachedDataset;
  try {
    const raw = fs.readFileSync(DATASET_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    const families = Array.isArray(parsed?.families) ? parsed.families : [];
    cachedDataset = { families };
  } catch {
    cachedDataset = { families: [] };
  }
  return cachedDataset;
}

function tokenizeText(value) {
  return String(value || '')
    .toLowerCase()
    .split(/[^a-z0-9]+/g)
    .map(token => token.trim())
    .filter(Boolean);
}

function collectContextTokens(context = {}) {
  const tokenCounts = new Map();
  const add = (value, boost = 1) => {
    tokenizeText(value).forEach(token => {
      tokenCounts.set(token, Number(tokenCounts.get(token) || 0) + boost);
    });
  };

  const currentRequest = context.current_request && typeof context.current_request === 'object'
    ? context.current_request
    : {};

  add(context.target_url, 2);
  add(context.user_instruction, 2);
  add(currentRequest.url, 3);
  add(currentRequest.body, 1);
  add(currentRequest.method, 1);

  const headers = Array.isArray(currentRequest.headers) ? currentRequest.headers : [];
  headers.forEach(entry => {
    add(entry?.k, 1);
    add(entry?.v, 1);
  });

  const params = Array.isArray(currentRequest.params) ? currentRequest.params : [];
  params.forEach(entry => {
    add(entry?.k, 2);
    add(entry?.v, 1);
  });

  const importMeta = currentRequest.importMeta && typeof currentRequest.importMeta === 'object'
    ? currentRequest.importMeta
    : null;
  if (Array.isArray(importMeta?.param_descriptors)) {
    importMeta.param_descriptors.forEach(entry => {
      add(entry?.name, 3);
      add(entry?.path, 2);
      add(entry?.location, 1);
      add(entry?.type, 1);
    });
  }

  return tokenCounts;
}

function collectResponseClues(context = {}) {
  const clueCounts = new Map();
  const add = (value, boost = 1) => {
    tokenizeText(value).forEach(token => {
      clueCounts.set(token, Number(clueCounts.get(token) || 0) + boost);
    });
  };

  const lastResponse = context.last_response && typeof context.last_response === 'object'
    ? context.last_response
    : {};
  add(lastResponse.body_preview, 2);
  add(lastResponse.json_summary, 1);
  add(lastResponse.status, 1);

  const headers = lastResponse.headers && typeof lastResponse.headers === 'object'
    ? lastResponse.headers
    : {};
  Object.entries(headers).forEach(([key, value]) => {
    add(key, 2);
    add(value, 1);
  });

  return clueCounts;
}

function getContextPatternBoost(tokenCounts) {
  const has = token => tokenCounts.has(token);
  return {
    auth: has('login') || has('signin') || has('auth') || has('password') || has('session') || has('token'),
    upload: has('upload') || has('file') || has('attachment') || has('avatar') || has('document'),
    admin: has('admin') || has('role') || has('permission'),
    resource: has('user') || has('account') || has('profile') || has('resource') || has('id'),
    urlFetch: has('url') || has('callback') || has('webhook') || has('preview') || has('import'),
    workflow: has('verify') || has('otp') || has('checkout') || has('coupon') || has('payment')
  };
}

function scoreFamily(family, tokenCounts, responseClues, method, patternBoost) {
  let score = 0;
  const matchedTerms = [];

  if (Array.isArray(family.methods) && family.methods.includes(method)) {
    score += 4;
    matchedTerms.push(`method:${method}`);
  }

  const tags = Array.isArray(family.tags) ? family.tags : [];
  tags.forEach(tag => {
    const token = String(tag).toLowerCase();
    if (tokenCounts.has(token)) {
      score += 2 * Number(tokenCounts.get(token) || 1);
      matchedTerms.push(`tag:${token}`);
    }
  });

  const keywords = Array.isArray(family.endpoint_keywords) ? family.endpoint_keywords : [];
  keywords.forEach(keyword => {
    const token = String(keyword).toLowerCase();
    if (tokenCounts.has(token)) {
      score += 3 * Number(tokenCounts.get(token) || 1);
      matchedTerms.push(`keyword:${token}`);
    }
  });

  const fingerprints = Array.isArray(family.endpoint_fingerprints) ? family.endpoint_fingerprints : [];
  fingerprints.forEach(fingerprint => {
    const token = String(fingerprint?.token || '').toLowerCase();
    if (!token || !tokenCounts.has(token)) return;
    const weight = Number(fingerprint.weight || 1);
    score += weight * Number(tokenCounts.get(token) || 1);
    matchedTerms.push(`fingerprint:${token}`);
  });

  const responseKeywords = Array.isArray(family.response_clue_keywords) ? family.response_clue_keywords : [];
  responseKeywords.forEach(keyword => {
    const token = String(keyword).toLowerCase();
    if (responseClues.has(token)) {
      score += 4 * Number(responseClues.get(token) || 1);
      matchedTerms.push(`response:${token}`);
    }
  });

  if (patternBoost.auth && ['auth-bypass', 'session-integrity'].includes(family.family_id)) score += 8;
  if (patternBoost.upload && family.family_id === 'path-traversal-upload') score += 8;
  if (patternBoost.admin && ['bola-idor', 'privilege-mass-assignment'].includes(family.family_id)) score += 7;
  if (patternBoost.resource && family.family_id === 'bola-idor') score += 6;
  if (patternBoost.urlFetch && family.family_id === 'ssrf-url-fetch') score += 8;
  if (patternBoost.workflow && family.family_id === 'business-logic-rate-limit') score += 8;

  return {
    score,
    matchedTerms: [...new Set(matchedTerms)]
  };
}

function summarizeFamily(family, scoreResult) {
  const payloadPack = securityPayloadPacks.resolvePayloadPackForFamily(family.family_id);
  return {
    family_id: family.family_id,
    family: family.family,
    title: family.title,
    cwe: family.cwe,
    owasp_api_label: family.owasp_api_label,
    tags: Array.isArray(family.tags) ? family.tags.slice(0, 8) : [],
    signal_patterns: Array.isArray(family.signal_patterns) ? family.signal_patterns.slice(0, 4) : [],
    safe_test_objectives: Array.isArray(family.safe_test_objectives) ? family.safe_test_objectives.slice(0, 3) : [],
    prompt_hints: Array.isArray(family.prompt_hints) ? family.prompt_hints.slice(0, 3) : [],
    safe_detection_templates: Array.isArray(family.safe_detection_templates) ? family.safe_detection_templates.slice(0, 3) : [],
    mutation_risk_templates: Array.isArray(family.mutation_risk_templates) ? family.mutation_risk_templates.slice(0, 3) : [],
    negative_assertion_templates: Array.isArray(family.negative_assertion_templates) ? family.negative_assertion_templates.slice(0, 3) : [],
    payload_packs: payloadPack,
    execution_guards: Array.isArray(payloadPack.execution_guards) ? payloadPack.execution_guards.slice(0, 6) : [],
    cve_examples: Array.isArray(family.cve_examples) ? family.cve_examples.slice(0, 3) : [],
    matched_terms: scoreResult.matchedTerms.slice(0, 8),
    score: scoreResult.score,
    safety_profile: Array.isArray(family.mutation_risk_templates) && family.mutation_risk_templates.length
      ? 'safe-and-mutation-mixed'
      : 'safe-detection'
  };
}

function selectRelevantSecurityKnowledge(context = {}, options = {}) {
  const dataset = loadSecurityDataset();
  const currentRequest = context.current_request && typeof context.current_request === 'object'
    ? context.current_request
    : {};
  const method = String(currentRequest.method || 'GET').toUpperCase();
  const tokenCounts = collectContextTokens(context);
  const responseClues = collectResponseClues(context);
  const patternBoost = getContextPatternBoost(tokenCounts);
  const maxResults = Number.isFinite(options.maxResults) ? Math.max(1, Math.floor(options.maxResults)) : 4;

  return dataset.families
    .map(family => {
      const scoreResult = scoreFamily(family, tokenCounts, responseClues, method, patternBoost);
      return {
        family,
        scoreResult
      };
    })
    .filter(entry => entry.scoreResult.score > 0)
    .sort((a, b) => b.scoreResult.score - a.scoreResult.score || String(a.family.family_id).localeCompare(String(b.family.family_id)))
    .slice(0, maxResults)
    .map(entry => summarizeFamily(entry.family, entry.scoreResult));
}

module.exports = {
  loadSecurityDataset,
  selectRelevantSecurityKnowledge
};
