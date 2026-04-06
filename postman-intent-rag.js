const ALLOW_KEYWORDS = new Set([
  'api', 'apis', 'http', 'https', 'endpoint', 'endpoints', 'request', 'requests', 'response', 'responses',
  'header', 'headers', 'param', 'params', 'query', 'json', 'body', 'status', 'latency',
  'postman', 'collection', 'assertion', 'assertions', 'auth', 'authorization', 'bearer', 'token',
  'debug', 'test', 'testing', 'scan', 'security', 'idor', 'sqli', 'ssrf', 'cve', 'cwe',
  'get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'openapi', 'swagger'
]);

const DENY_KEYWORDS = new Set([
  'essay', 'poem', 'story', 'lyrics', 'song', 'vibes', 'memory', 'memories', 'joke', 'jokes',
  'recipe', 'travel', 'movie', 'movies', 'fitness', 'workout', 'diet', 'horoscope',
  'astrology', 'romance', 'novel', 'homework', 'assignment'
]);

const ALLOW_DOCS = [
  { id: 'api-debug', text: 'debug api request response headers status code latency and auth behavior in postman' },
  { id: 'request-build', text: 'build and modify get post put patch delete requests with params headers and json body' },
  { id: 'assertions', text: 'generate functional contract and security assertions for api response validation' },
  { id: 'security', text: 'run api security scans for idor sqli ssrf auth bypass and information disclosure' },
  { id: 'collections', text: 'import openapi swagger specs and create postman style collections and chained requests' }
];

const DENY_DOCS = [
  { id: 'creative-writing', text: 'write essay poem story lyrics or personal reflections and memories' },
  { id: 'general-chitchat', text: 'casual chat about good vibes entertainment lifestyle and non technical topics' }
];

function normalizeText(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9\s:/._-]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function tokenize(value) {
  const text = normalizeText(value);
  if (!text) return [];
  return text.split(' ').filter(Boolean);
}

function jaccardScore(aTokens, bTokens) {
  const a = new Set(aTokens);
  const b = new Set(bTokens);
  if (!a.size || !b.size) return 0;
  let intersection = 0;
  a.forEach(token => {
    if (b.has(token)) intersection += 1;
  });
  const union = new Set([...a, ...b]).size;
  return union ? intersection / union : 0;
}

function keywordScore(tokens, keywordSet) {
  if (!tokens.length) return 0;
  const hits = tokens.filter(token => keywordSet.has(token)).length;
  return hits / tokens.length;
}

function retrieveTopScore(queryTokens, docs) {
  let best = { id: null, score: 0 };
  docs.forEach(doc => {
    const score = jaccardScore(queryTokens, tokenize(doc.text));
    if (score > best.score) best = { id: doc.id, score };
  });
  return best;
}

function extractQuery(context = {}) {
  const parts = [
    context.user_message,
    context.user_instruction,
    context.chat_goal
  ];
  return parts.filter(Boolean).join(' ').trim();
}

function evaluateAskIntent(context = {}) {
  const query = extractQuery(context);
  const queryTokens = tokenize(query);
  if (!queryTokens.length) {
    return {
      allowed: false,
      confidence: 0,
      reason: 'empty_query',
      query,
      layer1: { allow: 0, deny: 0 },
      layer2: { allow: { id: null, score: 0 }, deny: { id: null, score: 0 } }
    };
  }

  const layer1Allow = keywordScore(queryTokens, ALLOW_KEYWORDS);
  const layer1Deny = keywordScore(queryTokens, DENY_KEYWORDS);
  const layer2Allow = retrieveTopScore(queryTokens, ALLOW_DOCS);
  const layer2Deny = retrieveTopScore(queryTokens, DENY_DOCS);

  const allowComposite = layer1Allow * 0.55 + layer2Allow.score * 0.45;
  const denyComposite = layer1Deny * 0.6 + layer2Deny.score * 0.4;
  const margin = allowComposite - denyComposite;

  const allowed = (layer1Allow >= 0.06 && layer1Deny === 0) || (allowComposite >= 0.08 && margin >= 0.02);
  const confidence = Number(Math.max(0, Math.min(1, Math.abs(margin) + (allowed ? allowComposite : denyComposite))).toFixed(3));

  return {
    allowed,
    confidence,
    reason: allowed ? 'postman_intent_detected' : 'out_of_scope_intent',
    query,
    layer1: {
      allow: Number(layer1Allow.toFixed(3)),
      deny: Number(layer1Deny.toFixed(3))
    },
    layer2: {
      allow: { id: layer2Allow.id, score: Number(layer2Allow.score.toFixed(3)) },
      deny: { id: layer2Deny.id, score: Number(layer2Deny.score.toFixed(3)) }
    }
  };
}

function verifyAskResponseScope(payload = {}) {
  const message = normalizeText(payload.message || '');
  const tokens = tokenize(message);
  if (!tokens.length) return { allowed: false, confidence: 0, reason: 'empty_response_message' };

  const allow = keywordScore(tokens, ALLOW_KEYWORDS);
  const deny = keywordScore(tokens, DENY_KEYWORDS);
  const allowed = allow >= 0.03 || (Array.isArray(payload.actions) && payload.actions.length > 0);
  if (!allowed && deny > 0) {
    return { allowed: false, confidence: Number(Math.min(1, deny + 0.2).toFixed(3)), reason: 'response_out_of_scope' };
  }
  return { allowed, confidence: Number(Math.min(1, allow + 0.1).toFixed(3)), reason: allowed ? 'response_in_scope' : 'response_low_signal' };
}

module.exports = {
  evaluateAskIntent,
  verifyAskResponseScope
};
