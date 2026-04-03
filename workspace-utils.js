(function initWorkspaceUtils(globalScope) {
  function summarizePreview(text, limit = 320) {
    const value = String(text || '').trim();
    if (!value) return '';
    return value.length > limit ? `${value.slice(0, limit).trimEnd()}...` : value;
  }

  function describeRequestDiff(previousRequest, currentRequest, previousResponse, currentResponse) {
    const changes = [];
    const prev = previousRequest && typeof previousRequest === 'object' ? previousRequest : {};
    const next = currentRequest && typeof currentRequest === 'object' ? currentRequest : {};
    const compareFields = [
      ['method', 'method'],
      ['url', 'url'],
      ['body', 'body'],
      ['params', 'params'],
      ['headers', 'headers'],
      ['assertions', 'assertions']
    ];

    compareFields.forEach(([field, label]) => {
      const prevValue = JSON.stringify(prev[field] ?? null);
      const nextValue = JSON.stringify(next[field] ?? null);
      if (prevValue !== nextValue) changes.push(label);
    });

    const responseChanges = [];
    if (previousResponse && previousResponse.status !== currentResponse.status) {
      responseChanges.push(`status ${previousResponse.status}->${currentResponse.status}`);
    }
    if (previousResponse && previousResponse.elapsed_ms !== currentResponse.elapsed_ms) {
      responseChanges.push(`elapsed ${previousResponse.elapsed_ms}ms->${currentResponse.elapsed_ms}ms`);
    }
    if (previousResponse && previousResponse.responsePreview !== currentResponse.responsePreview) {
      responseChanges.push('response preview changed');
    }

    const requestSummary = changes.length ? `request: ${changes.join(', ')}` : 'request: no changes';
    const responseSummary = responseChanges.length ? `response: ${responseChanges.join(', ')}` : 'response: no previous run';
    return `${requestSummary}; ${responseSummary}`;
  }

  function resolveChainTemplate(url, lastResponseText) {
    if (typeof url !== 'string' || !url.includes('{{')) return url;
    if (!lastResponseText) return url;

    let parsed;
    try {
      parsed = JSON.parse(lastResponseText);
    } catch {
      return url;
    }

    const readPath = (obj, path) => {
      const tokens = [];
      const regex = /([^[.\]]+)|\[(\d+)\]/g;
      let match;
      while ((match = regex.exec(path)) !== null) {
        tokens.push(match[1] !== undefined ? match[1] : Number(match[2]));
      }
      return tokens.reduce((acc, token) => (acc == null ? undefined : acc[token]), obj);
    };

    return url.replace(/\{\{json\.([^}]+)\}\}/g, (fullToken, path) => {
      const value = readPath(parsed, path);
      return value !== undefined ? String(value) : fullToken;
    });
  }

  function resolveVariableTemplate(text, variables, preserveUnknown = true) {
    if (typeof text !== 'string' || !text.includes('{{')) return text;
    const source = variables && typeof variables === 'object' ? variables : {};

    return text.replace(/\{\{\s*([^}]+?)\s*\}\}/g, (fullToken, rawKey) => {
      const key = String(rawKey || '').trim();
      if (!key) return fullToken;
      if (Object.prototype.hasOwnProperty.call(source, key)) {
        return String(source[key] ?? '');
      }
      return preserveUnknown ? fullToken : '';
    });
  }

  /**
   * Collects query param keys, KV param keys, and JSON body top-level keys for scan/agent context.
   * @param {object} currentRequest - { url, params[], headers[], body }
   * @returns {string[]}
   */
  function collectParamCandidatesFromRequest(currentRequest) {
    const keys = new Set();
    const cr = currentRequest && typeof currentRequest === 'object' ? currentRequest : {};
    if (Array.isArray(cr.params)) {
      cr.params.forEach(p => {
        const k = typeof p?.k === 'string' ? p.k.trim() : '';
        if (k) keys.add(k);
      });
    }
    const urlRaw = typeof cr.url === 'string' ? cr.url : '';
    if (urlRaw) {
      try {
        const href = urlRaw.includes('://')
          ? urlRaw
          : `https://placeholder.invalid${urlRaw.startsWith('/') ? '' : '/'}${urlRaw}`;
        const u = new URL(href);
        u.searchParams.forEach((_v, k) => {
          if (k) keys.add(k);
        });
      } catch {
        const q = urlRaw.indexOf('?');
        if (q >= 0) {
          try {
            const sp = new URLSearchParams(urlRaw.slice(q + 1));
            sp.forEach((_v, k) => {
              if (k) keys.add(k);
            });
          } catch {
            /* ignore */
          }
        }
      }
    }
    const body = typeof cr.body === 'string' ? cr.body : '';
    const headers = Array.isArray(cr.headers) ? cr.headers : [];
    const ct = headers.find(h => String(h?.k || '').toLowerCase() === 'content-type');
    const ctype = ct ? String(ct.v || '').toLowerCase() : '';
    if (body && (ctype.includes('json') || body.trim().startsWith('{'))) {
      try {
        const parsed = JSON.parse(body);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          Object.keys(parsed).slice(0, 40).forEach(k => keys.add(k));
        }
      } catch {
        /* ignore */
      }
    }
    return [...keys].filter(Boolean).slice(0, 40);
  }

  const api = {
    summarizePreview,
    describeRequestDiff,
    resolveChainTemplate,
    resolveVariableTemplate,
    collectParamCandidatesFromRequest
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  if (globalScope) {
    globalScope.AgentmanWorkspaceUtils = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
