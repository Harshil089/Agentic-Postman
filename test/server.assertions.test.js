const loadApp = () => {
  jest.resetModules();
  return require('../server');
};

describe('server assertion internals', () => {
  test('extractStructuredTextPayload accepts object content payloads', () => {
    const app = loadApp();
    const text = app.__internals.extractStructuredTextPayload({
      assertions: ['status === 200']
    });

    expect(text).toContain('status === 200');
  });

  test('parseAssertionsPayload rejects duplicate and weak assertions', () => {
    const app = loadApp();

    expect(() => app.__internals.parseAssertionsPayload(JSON.stringify({
      assertions: [
        'status === 200',
        'status === 200',
        'true'
      ]
    }), {
      mode: 'functional',
      parsedJson: { id: 1, name: 'Ada' },
      preferences: { include_negative_checks: true, include_timing_checks: false }
    })).toThrow(/semantic validation/i);
  });

  test('parseAssertionsPayload accepts specific functional coverage', () => {
    const app = loadApp();
    const parsed = app.__internals.parseAssertionsPayload(JSON.stringify({
      assertions: [
        'status === 200',
        'json !== null && json.hasOwnProperty("id")',
        'typeof json.name === "string"',
        '!body.includes("error")'
      ]
    }), {
      mode: 'functional',
      parsedJson: { id: 1, name: 'Ada' },
      preferences: { include_negative_checks: true, include_timing_checks: false }
    });

    expect(parsed.assertions).toHaveLength(4);
  });

  test('normalizeAssertionPreferences includes policy pack', () => {
    const app = loadApp();
    const prefs = app.__internals.normalizeAssertionPreferences({
      strictness: 'strict',
      auth_expectation: 'required',
      policy_pack: 'asvs-lite',
      include_negative_checks: true,
      include_timing_checks: false
    });

    expect(prefs.policy_pack).toBe('asvs-lite');
  });

  test('validateGeneratedAssertions enforces timing when requested', () => {
    const app = loadApp();
    const result = app.__internals.validateGeneratedAssertions([
      'status === 200',
      '!body.includes("error")',
      'json !== null && json.hasOwnProperty("id")'
    ], {
      mode: 'functional',
      parsedJson: { id: 1 },
      preferences: { include_negative_checks: true, include_timing_checks: true }
    });

    expect(result.ok).toBe(false);
    expect(result.errors.join(' ')).toMatch(/timing/i);
  });

  test('compactSecurityContext preserves current_mode for security prompting', () => {
    const app = loadApp();
    const compacted = app.__internals.compactSecurityContext({
      current_mode: 'agent',
      target_url: 'https://example.com',
      current_request: {
        method: 'GET',
        url: 'https://example.com/users?id=1',
        headers: [],
        params: [],
        body: ''
      },
      user_instruction: 'Run a full security scan'
    }, 'openrouter');

    expect(compacted.current_mode).toBe('agent');
    expect(Array.isArray(compacted.matched_cve_records)).toBe(true);
    if (compacted.matched_cve_records.length) {
      expect(compacted.matched_cve_records[0]).toHaveProperty('family_id');
      expect(compacted.matched_cve_records[0]).toHaveProperty('matched_terms');
      expect(compacted.matched_cve_records[0]).toHaveProperty('cve_examples');
      expect(compacted.matched_cve_records[0]).toHaveProperty('safe_detection_templates');
      expect(compacted.matched_cve_records[0]).toHaveProperty('mutation_risk_templates');
      expect(compacted.matched_cve_records[0]).toHaveProperty('negative_assertion_templates');
      expect(compacted.matched_cve_records[0]).toHaveProperty('payload_packs');
      expect(compacted.matched_cve_records[0]).toHaveProperty('execution_guards');
      expect(compacted.matched_cve_records[0]).toHaveProperty('safety_profile');
    }
  });

  test('validateSecurityPayloadSemantics requires scan_plan in planning mode', () => {
    const app = loadApp();

    expect(() => app.__internals.validateSecurityPayloadSemantics({
      message: 'Scanning target',
      threat_level: 'none',
      findings: [],
      actions: []
    }, {
      current_mode: 'planning'
    })).toThrow(/planning mode requires a scan_plan action/i);
  });

  test('validateSecurityPayloadSemantics accepts planning payloads that start with scan_plan', () => {
    const app = loadApp();
    const payload = app.__internals.validateSecurityPayloadSemantics({
      message: 'Prepared a plan.',
      threat_level: 'none',
      findings: [],
      actions: [
        {
          type: 'scan_plan',
          target: 'https://example.com/login',
          method_coverage: ['GET', 'POST'],
          steps: [
            { order: 1, vector: 'AuthBypass', description: 'Check unauthenticated behavior.' }
          ],
          param_matrix: []
        }
      ]
    }, {
      current_mode: 'planning'
    });

    expect(payload.actions[0].type).toBe('scan_plan');
  });

  test('parseSecurityPayload enriches findings with evidence delta and confidence', () => {
    const app = loadApp();
    const parsed = app.__internals.parseSecurityPayload(JSON.stringify({
      message: 'Detected disclosure.',
      threat_level: 'medium',
      findings: [
        {
          id: 'F-1',
          vulnerability: 'InfoDisclosure',
          severity: 'medium',
          evidence: 'stack trace',
          cve_hint: 'CWE-209',
          remediation: 'Hide stack traces.'
        }
      ],
      actions: []
    }), {
      context: {
        last_response: {
          status: 500,
          body_preview: 'Unhandled exception with stack trace in body'
        },
        test_history: [{ status: 401 }]
      }
    });

    expect(parsed.findings[0]).toHaveProperty('evidence_delta');
    expect(parsed.findings[0]).toHaveProperty('confidence');
    expect(parsed.findings[0].confidence).toBeGreaterThan(0);
  });
});
