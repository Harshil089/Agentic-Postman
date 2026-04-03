const workspaceUtils = require('./workspace-utils');

const HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);

function clampMaxOps(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 120;
  return Math.min(500, Math.max(1, Math.floor(n)));
}

function joinBaseUrlAndPath(serverUrl, pathTemplate) {
  const path = typeof pathTemplate === 'string' ? pathTemplate : '';
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  const base = typeof serverUrl === 'string' ? serverUrl.trim().replace(/\/$/, '') : '';
  if (!base) return `{{baseUrl}}${normalizedPath}`;
  return `${base}${normalizedPath}`;
}

function jsonBodyFromRequestBody(requestBody) {
  if (!requestBody || typeof requestBody !== 'object') return '';
  const content = requestBody.content && typeof requestBody.content === 'object' ? requestBody.content : {};
  const jsonMedia = content['application/json'] || content['application/*+json'];
  if (!jsonMedia || typeof jsonMedia !== 'object') return '';
  if (jsonMedia.example !== undefined) {
    return typeof jsonMedia.example === 'string'
      ? jsonMedia.example
      : JSON.stringify(jsonMedia.example, null, 2);
  }
  if (jsonMedia.examples && typeof jsonMedia.examples === 'object') {
    const first = Object.values(jsonMedia.examples)[0];
    if (first && typeof first === 'object' && first.value !== undefined) {
      return typeof first.value === 'string'
        ? first.value
        : JSON.stringify(first.value, null, 2);
    }
  }
  return '';
}

function queryParamsFromParameters(parameters) {
  const params = [];
  if (!Array.isArray(parameters)) return params;
  parameters.forEach(p => {
    if (!p || p.in !== 'query' || typeof p.name !== 'string' || !p.name.trim()) return;
    let def = '';
    if (p.schema && p.schema.default !== undefined) {
      def = String(p.schema.default);
    }
    params.push({ k: p.name, v: def });
  });
  return params;
}

/**
 * @param {object} spec - OpenAPI 3.x document
 * @param {{ maxOperations?: number }} [options]
 * @returns {{ requests: object[], warnings: string[], truncated: boolean }}
 */
function parseOpenApiToRequests(spec, options = {}) {
  const warnings = [];
  const maxOps = clampMaxOps(options.maxOperations);
  if (!spec || typeof spec !== 'object') {
    const err = new Error('Invalid OpenAPI document: expected object.');
    err.status = 400;
    throw err;
  }
  if (spec.openapi && !String(spec.openapi).startsWith('3')) {
    warnings.push('Spec openapi field is not 3.x; import may be incomplete.');
  }
  const servers = Array.isArray(spec.servers) ? spec.servers : [];
  let baseUrl = servers[0] && typeof servers[0].url === 'string' ? servers[0].url.trim() : '';
  if (!baseUrl && spec.swagger && spec.host) {
    const scheme = (Array.isArray(spec.schemes) && spec.schemes[0]) ? spec.schemes[0] : 'https';
    const bp = typeof spec.basePath === 'string' ? spec.basePath : '';
    const host = String(spec.host).trim();
    baseUrl = `${scheme}://${host}${bp.startsWith('/') ? bp : `/${bp}`}`.replace(/\/$/, '');
    warnings.push('Swagger 2.x detected: built base URL from host/basePath/schemes.');
  }
  const paths = spec.paths && typeof spec.paths === 'object' ? spec.paths : {};
  const requests = [];
  const methodKeys = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'];

  for (const [pathTemplate, pathItem] of Object.entries(paths)) {
    if (!pathItem || typeof pathItem !== 'object') continue;
    for (const mk of methodKeys) {
      if (requests.length >= maxOps) break;
      const op = pathItem[mk];
      if (!op || typeof op !== 'object') continue;
      const method = mk.toUpperCase();
      if (!HTTP_METHODS.has(method)) continue;
      const name = op.operationId || op.summary || `${method} ${pathTemplate}`;
      const parameters = Array.isArray(op.parameters) ? op.parameters : [];
      const params = queryParamsFromParameters(parameters);
      let body = '';
      if (op.requestBody) {
        body = jsonBodyFromRequestBody(op.requestBody);
      }
      const url = joinBaseUrlAndPath(baseUrl, pathTemplate);
      const headers = [];
      if (body && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
        headers.push({ k: 'Content-Type', v: 'application/json' });
      }
      const record = {
        name: String(name).slice(0, 160),
        method,
        url,
        params,
        headers,
        body,
        assertions: [],
        chainOf: null,
        chainNote: ''
      };
      record.importMeta = buildImportMeta(record, 'openapi');
      requests.push(record);
    }
    if (requests.length >= maxOps) break;
  }

  if (!requests.length) {
    warnings.push('No operations found under paths.');
  }

  return {
    requests,
    warnings,
    truncated: Object.keys(paths).length > 0 && requests.length >= maxOps
  };
}

function buildImportMeta(record, source) {
  const param_candidates = workspaceUtils.collectParamCandidatesFromRequest({
    method: record.method,
    url: record.url,
    params: record.params,
    headers: record.headers,
    body: record.body
  });
  return {
    source,
    param_candidates
  };
}

function extractPostmanUrl(urlField) {
  if (typeof urlField === 'string') return urlField.trim();
  if (!urlField || typeof urlField !== 'object') return '';
  if (typeof urlField.raw === 'string' && urlField.raw.trim()) return urlField.raw.trim();
  const protocol = Array.isArray(urlField.protocol) ? urlField.protocol[0] : urlField.protocol || 'https';
  const host = Array.isArray(urlField.host) ? urlField.host.join('.') : (urlField.host || '');
  const pathPart = Array.isArray(urlField.path) ? urlField.path.join('/') : (urlField.path || '');
  const query = Array.isArray(urlField.query)
    ? urlField.query
        .filter(q => q && q.key)
        .map(q => `${encodeURIComponent(q.key)}=${encodeURIComponent(q.value ?? '')}`)
        .join('&')
    : '';
  if (!host && !pathPart) return '';
  const base = `${String(protocol).replace(/:\/$/, '')}://${host}`;
  const path = pathPart ? (pathPart.startsWith('/') ? pathPart : `/${pathPart}`) : '';
  let full = `${base}${path}`;
  if (query) full += (full.includes('?') ? '&' : '?') + query;
  return full;
}

function headersFromPostman(headerList) {
  if (!Array.isArray(headerList)) return [];
  return headerList
    .filter(h => h && typeof h.key === 'string' && h.key.trim())
    .map(h => ({ k: h.key, v: typeof h.value === 'string' ? h.value : '' }));
}

function bodyFromPostman(bodyField) {
  if (!bodyField || typeof bodyField !== 'object') return '';
  if (bodyField.mode === 'raw' && typeof bodyField.raw === 'string') return bodyField.raw;
  if (bodyField.mode === 'urlencoded' && Array.isArray(bodyField.urlencoded)) {
    try {
      const o = {};
      bodyField.urlencoded.forEach(p => {
        if (p && p.key) o[p.key] = p.value ?? '';
      });
      return JSON.stringify(o, null, 2);
    } catch {
      return '';
    }
  }
  return '';
}

function walkPostmanItems(items, out) {
  if (!Array.isArray(items)) return;
  items.forEach(item => {
    if (!item || typeof item !== 'object') return;
    if (item.request) out.push(item);
    if (item.item) walkPostmanItems(item.item, out);
  });
}

/**
 * @param {object} collection - Postman collection v2.1
 */
function parsePostmanCollectionToRequests(collection, options = {}) {
  const warnings = [];
  const maxOps = clampMaxOps(options.maxOperations);
  if (!collection || typeof collection !== 'object') {
    const err = new Error('Invalid Postman collection: expected object.');
    err.status = 400;
    throw err;
  }
  const info = collection.info && typeof collection.info === 'object' ? collection.info : {};
  if (info.schema && !String(info.schema).includes('2.1')) {
    warnings.push('Collection schema may not be v2.1; import may be incomplete.');
  }
  const flat = [];
  walkPostmanItems(collection.item, flat);
  const requests = [];

  const baseUrl = '{{baseUrl}}';
  for (const item of flat) {
    if (requests.length >= maxOps) break;
    const req = item.request;
    if (!req || typeof req !== 'object') continue;
    const method = String(req.method || 'GET').toUpperCase();
    if (!HTTP_METHODS.has(method)) continue;
    let url = extractPostmanUrl(req.url);
    if (!url) url = baseUrl;
    const name = typeof item.name === 'string' && item.name.trim()
      ? item.name.trim()
      : `${method} request`;
    const headers = headersFromPostman(req.header);
    const body = bodyFromPostman(req.body);
    const params = [];
    if (req.url && typeof req.url === 'object' && Array.isArray(req.url.query)) {
      req.url.query.forEach(q => {
        if (q && q.key) params.push({ k: q.key, v: q.value != null ? String(q.value) : '' });
      });
    }
    const record = {
      name: String(name).slice(0, 160),
      method,
      url,
      params,
      headers,
      body,
      assertions: [],
      chainOf: null,
      chainNote: ''
    };
    record.importMeta = buildImportMeta(record, 'postman');
    requests.push(record);
  }

  if (!requests.length) {
    warnings.push('No requests found in collection.');
  }

  return {
    requests,
    warnings,
    truncated: flat.length > requests.length
  };
}

module.exports = {
  parseOpenApiToRequests,
  parsePostmanCollectionToRequests,
  clampMaxOps
};
