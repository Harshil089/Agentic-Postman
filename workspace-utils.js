(function initWorkspaceUtils(globalScope) {
  const aiContracts = (typeof globalScope !== 'undefined' && globalScope.AgentmanAiContracts)
    ? globalScope.AgentmanAiContracts
    : (typeof require === 'function' ? require('./ai-contracts') : null);

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

  function arrayBufferToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes)
      .map(byte => byte.toString(16).padStart(2, '0'))
      .join('');
  }

  async function computeSha256Hash(text) {
    if (typeof text !== 'string') {
      return '';
    }
    try {
      const Encoder = (typeof globalThis !== 'undefined' && globalThis.TextEncoder) ? globalThis.TextEncoder : null;
      if (!Encoder) return '';
      if (typeof globalScope !== 'undefined' && globalScope.crypto && globalScope.crypto.subtle) {
        const encoder = new Encoder();
        const data = encoder.encode(text);
        const hashBuffer = await globalScope.crypto.subtle.digest('SHA-256', data);
        return arrayBufferToHex(hashBuffer);
      } else if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
        const encoder = new Encoder();
        const data = encoder.encode(text);
        const hashBuffer = await globalThis.crypto.subtle.digest('SHA-256', data);
        return arrayBufferToHex(hashBuffer);
      }
    } catch {
      /* fallback if crypto unavailable */
    }
    return '';
  }

  function compareToSnapshot(request, response, snapshot) {
    if (!snapshot || typeof snapshot !== 'object') {
      return null;
    }
    const safeRequest = request && typeof request === 'object' ? request : {};
    const safeResponse = response && typeof response === 'object' ? response : {};

    const result = {
      matches: true,
      assertions: {
        pass: 0,
        fail: 0,
        changes: []
      },
      response: {
        statusMatch: true,
        statusDelta: null,
        timingDelta: null,
        bodyHashMatch: true,
        headerChanges: []
      },
      notes: ''
    };

    // Compare status
    const currentStatus = Number(safeResponse.status) || 0;
    const expectedStatus = Number(snapshot.status) || 0;
    if (currentStatus !== expectedStatus) {
      result.response.statusMatch = false;
      result.response.statusDelta = { expected: expectedStatus, actual: currentStatus };
      result.matches = false;
    }

    // Compare timing
    const currentElapsed = Number(safeResponse.elapsed) || Number(safeResponse.elapsedMs) || 0;
    const expectedElapsed = Number(snapshot.elapsedMs) || 0;
    if (currentElapsed !== expectedElapsed) {
      const delta = currentElapsed - expectedElapsed;
      result.response.timingDelta = { expected: expectedElapsed, actual: currentElapsed, delta };
    }

    // Compare body hash (if both exist)
    const currentBodyHash = typeof safeResponse.bodyHash === 'string' ? safeResponse.bodyHash : '';
    const expectedBodyHash = typeof snapshot.responseBodyHash === 'string' ? snapshot.responseBodyHash : '';
    if (currentBodyHash && expectedBodyHash && currentBodyHash !== expectedBodyHash) {
      result.response.bodyHashMatch = false;
      result.matches = false;
    }

    // Compare assertions
    const snapshotAssertions = Array.isArray(snapshot.assertions) ? snapshot.assertions : [];
    const currentAssertions = Array.isArray(safeRequest.assertions) ? safeRequest.assertions : [];
    
    if (snapshotAssertions.length > 0) {
      snapshotAssertions.forEach(snap => {
        const curr = currentAssertions.find(a => a.expr === snap.expr);
        if (curr) {
          if (curr.status === 'pass') {
            result.assertions.pass += 1;
          } else {
            result.assertions.fail += 1;
            result.assertions.changes.push({
              expr: snap.expr,
              expected: 'pass',
              actual: curr.status,
              status: curr.status
            });
            result.matches = false;
          }
        }
      });
    }

    // Compare headers (sample key changes)
    const snapshotHeaders = snapshot.responseHeaders && typeof snapshot.responseHeaders === 'object' 
      ? snapshot.responseHeaders 
      : {};
    const currentHeaders = safeResponse.headers && typeof safeResponse.headers === 'object' 
      ? safeResponse.headers 
      : {};
    
    const allHeaderKeys = new Set([...Object.keys(snapshotHeaders), ...Object.keys(currentHeaders)]);
    const sampleHeadersToTrack = Array.from(allHeaderKeys).slice(0, 5);
    
    sampleHeadersToTrack.forEach(key => {
      const snapVal = snapshotHeaders[key];
      const currVal = currentHeaders[key];
      if (currVal === undefined && snapVal !== undefined) {
        result.response.headerChanges.push({ key, status: 'removed' });
      } else if (currVal !== undefined && snapVal === undefined) {
        result.response.headerChanges.push({ key, status: 'added' });
      } else if (currVal !== snapVal) {
        result.response.headerChanges.push({ key, status: 'changed' });
      }
    });

    // Generate human-readable notes
    const notes = [];
    if (!result.response.statusMatch) {
      notes.push(`Status mismatch (${expectedStatus}→${currentStatus})`);
    }
    if (result.response.timingDelta) {
      const sign = result.response.timingDelta.delta >= 0 ? '+' : '';
      notes.push(`timing ${sign}${result.response.timingDelta.delta}ms`);
    }
    if (!result.response.bodyHashMatch) {
      notes.push('body hash mismatch');
    }
    if (result.assertions.fail > 0) {
      notes.push(`${result.assertions.fail} assertion(s) failed`);
    }
    
    result.notes = notes.length > 0 ? notes.join(', ') : 'Matches baseline';

    return result;
  }

  function inferPrimitiveType(value) {
    if (value === null) return 'null';
    if (Array.isArray(value)) return 'array';
    if (typeof value === 'number') return Number.isInteger(value) ? 'integer' : 'number';
    if (typeof value === 'boolean') return 'boolean';
    if (typeof value === 'string') return 'string';
    if (value && typeof value === 'object') return 'object';
    return 'unknown';
  }

  function normalizeDescriptor(raw, index) {
    if (aiContracts && typeof aiContracts.normalizeParamDescriptor === 'function') {
      return aiContracts.normalizeParamDescriptor(raw, index);
    }
    return raw;
  }

  function appendDescriptor(target, seen, raw) {
    const descriptor = normalizeDescriptor(raw, target.length);
    if (!descriptor || !descriptor.name || !descriptor.path) return;
    const key = `${descriptor.location}:${descriptor.path}`;
    if (seen.has(key)) return;
    seen.add(key);
    target.push(descriptor);
  }

  function collectJsonParamDescriptors(value, basePath, target, seen, options = {}) {
    const {
      maxDepth = 3,
      depth = 0,
      source = 'request.body'
    } = options;
    if (value == null || depth > maxDepth) return;

    if (Array.isArray(value)) {
      const sample = value[0];
      appendDescriptor(target, seen, {
        name: basePath.split('.').pop() || 'item',
        path: basePath,
        location: 'body',
        type: 'array',
        required: false,
        source,
        example: Array.isArray(sample) || (sample && typeof sample === 'object') ? undefined : sample
      });
      if (sample && typeof sample === 'object') {
        collectJsonParamDescriptors(sample, `${basePath}[0]`, target, seen, {
          maxDepth,
          depth: depth + 1,
          source
        });
      }
      return;
    }

    if (typeof value === 'object') {
      if (basePath) {
        appendDescriptor(target, seen, {
          name: basePath.split('.').pop() || basePath,
          path: basePath,
          location: 'body',
          type: 'object',
          required: false,
          source
        });
      }
      Object.entries(value).slice(0, 40).forEach(([key, nested]) => {
        const path = basePath ? `${basePath}.${key}` : key;
        appendDescriptor(target, seen, {
          name: key,
          path,
          location: 'body',
          type: inferPrimitiveType(nested),
          required: false,
          source,
          example: nested !== null && typeof nested !== 'object' ? nested : undefined
        });
        if (nested && typeof nested === 'object') {
          collectJsonParamDescriptors(nested, path, target, seen, {
            maxDepth,
            depth: depth + 1,
            source
          });
        }
      });
    }
  }

  function collectParamDescriptorsFromRequest(currentRequest) {
    const descriptors = [];
    const seen = new Set();
    const cr = currentRequest && typeof currentRequest === 'object' ? currentRequest : {};

    const importMeta = cr.importMeta && typeof cr.importMeta === 'object' ? cr.importMeta : null;
    if (importMeta && Array.isArray(importMeta.param_descriptors)) {
      importMeta.param_descriptors.forEach(entry => appendDescriptor(descriptors, seen, entry));
    }

    const urlRaw = typeof cr.url === 'string' ? cr.url : '';
    if (urlRaw) {
      const placeholderMatches = [...urlRaw.matchAll(/\{([^}]+)\}/g)];
      placeholderMatches.forEach(match => {
        const name = String(match[1] || '').trim();
        if (!name) return;
        appendDescriptor(descriptors, seen, {
          name,
          path: name,
          location: 'path',
          type: 'string',
          required: true,
          source: 'request.url'
        });
      });

      try {
        const href = urlRaw.includes('://')
          ? urlRaw
          : `https://placeholder.invalid${urlRaw.startsWith('/') ? '' : '/'}${urlRaw}`;
        const url = new URL(href);
        url.searchParams.forEach((value, key) => {
          appendDescriptor(descriptors, seen, {
            name: key,
            path: key,
            location: 'query',
            type: inferPrimitiveType(value),
            required: false,
            source: 'request.url',
            example: value
          });
        });
      } catch {
        const queryIndex = urlRaw.indexOf('?');
        if (queryIndex >= 0) {
          try {
            const params = new URLSearchParams(urlRaw.slice(queryIndex + 1));
            params.forEach((value, key) => {
              appendDescriptor(descriptors, seen, {
                name: key,
                path: key,
                location: 'query',
                type: inferPrimitiveType(value),
                required: false,
                source: 'request.url',
                example: value
              });
            });
          } catch {
            /* ignore */
          }
        }
      }
    }

    if (Array.isArray(cr.params)) {
      cr.params.forEach(entry => {
        const key = typeof entry?.k === 'string' ? entry.k.trim() : '';
        if (!key) return;
        appendDescriptor(descriptors, seen, {
          name: key,
          path: key,
          location: 'query',
          type: inferPrimitiveType(entry.v),
          required: false,
          source: 'request.params',
          example: typeof entry.v === 'string' ? entry.v : undefined
        });
      });
    }

    if (Array.isArray(cr.headers)) {
      cr.headers.forEach(entry => {
        const key = typeof entry?.k === 'string' ? entry.k.trim() : '';
        if (!key) return;
        appendDescriptor(descriptors, seen, {
          name: key,
          path: key,
          location: 'header',
          type: 'string',
          required: false,
          source: 'request.headers',
          example: typeof entry.v === 'string' ? entry.v : undefined
        });
      });
    }

    const body = typeof cr.body === 'string' ? cr.body : '';
    const headers = Array.isArray(cr.headers) ? cr.headers : [];
    const ct = headers.find(header => String(header?.k || '').toLowerCase() === 'content-type');
    const ctype = ct ? String(ct.v || '').toLowerCase() : '';
    if (body && (ctype.includes('json') || body.trim().startsWith('{') || body.trim().startsWith('['))) {
      try {
        const parsed = JSON.parse(body);
        collectJsonParamDescriptors(parsed, '', descriptors, seen, {
          maxDepth: 3,
          source: 'request.body'
        });
      } catch {
        /* ignore */
      }
    }

    return descriptors.slice(0, 80);
  }

  /**
   * Collects query param keys, KV param keys, and JSON body keys for scan/agent context.
   * @param {object} currentRequest - { url, params[], headers[], body }
   * @returns {string[]}
   */
  function collectParamCandidatesFromRequest(currentRequest) {
    return [...new Set(
      collectParamDescriptorsFromRequest(currentRequest)
        .map(entry => entry.name)
        .filter(Boolean)
    )].slice(0, 40);
  }

  const api = {
    summarizePreview,
    describeRequestDiff,
    resolveChainTemplate,
    resolveVariableTemplate,
    collectParamDescriptorsFromRequest,
    collectParamCandidatesFromRequest,
    arrayBufferToHex,
    computeSha256Hash,
    compareToSnapshot
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  if (globalScope) {
    globalScope.AgentmanWorkspaceUtils = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
