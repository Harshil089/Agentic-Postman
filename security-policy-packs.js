const PACK_IDS = new Set(['none', 'auto', 'owasp-api-2023', 'asvs-lite', 'internal-baseline']);

const POLICY_PACKS = {
  'owasp-api-2023': {
    id: 'owasp-api-2023',
    name: 'OWASP API Top 10 (2023)',
    assertions: [
      'status !== 500',
      '!body.includes("stack trace")',
      '!body.includes("SQLException")',
      '!body.includes("token") || status === 200',
      'status !== 200 || json !== null'
    ]
  },
  'asvs-lite': {
    id: 'asvs-lite',
    name: 'ASVS-lite',
    assertions: [
      'status !== 500',
      'elapsed_ms < 5000',
      '!body.includes("password")',
      '!body.includes("secret")',
      'status === 200 || status === 201 || status === 202 || status === 204 || status === 400 || status === 401 || status === 403 || status === 404 || status === 409 || status === 422'
    ]
  },
  'internal-baseline': {
    id: 'internal-baseline',
    name: 'Internal Baseline',
    assertions: [
      'status !== 500',
      '!body.includes("debug")',
      '!body.includes("exception")',
      '!body.includes("traceback")',
      'elapsed_ms < 7000'
    ]
  }
};

function normalizePolicyPackId(value) {
  const id = typeof value === 'string' ? value.trim().toLowerCase() : 'auto';
  return PACK_IDS.has(id) ? id : 'auto';
}

function inferPolicyPackId(context = {}, preferred = 'auto') {
  const normalized = normalizePolicyPackId(preferred);
  if (normalized !== 'auto') return normalized;

  const url = String(context?.current_request?.url || '').toLowerCase();
  const method = String(context?.current_request?.method || 'GET').toUpperCase();
  if (url.includes('/admin') || url.includes('/internal') || method !== 'GET') {
    return 'internal-baseline';
  }
  if (url.includes('/auth') || url.includes('/login') || url.includes('/session')) {
    return 'asvs-lite';
  }
  return 'owasp-api-2023';
}

function getPolicyPack(id) {
  return POLICY_PACKS[id] || null;
}

function mergePolicyAssertions(baseAssertions = [], policyAssertions = []) {
  const seen = new Set();
  const merged = [];
  [...baseAssertions, ...policyAssertions].forEach(entry => {
    const value = typeof entry === 'string' ? entry.trim() : '';
    if (!value) return;
    if (seen.has(value)) return;
    seen.add(value);
    merged.push(value);
  });
  return merged;
}

module.exports = {
  POLICY_PACKS,
  normalizePolicyPackId,
  inferPolicyPackId,
  getPolicyPack,
  mergePolicyAssertions
};
