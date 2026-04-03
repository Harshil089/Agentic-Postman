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

  const api = {
    summarizePreview,
    describeRequestDiff,
    resolveChainTemplate,
    resolveVariableTemplate
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  if (globalScope) {
    globalScope.AgentmanWorkspaceUtils = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
