const securityKnowledge = require('../security-knowledge');

describe('security-knowledge', () => {
  test('loads the curated CVE dataset', () => {
    const dataset = securityKnowledge.loadSecurityDataset();
    expect(Array.isArray(dataset.families)).toBe(true);
    expect(dataset.families.length).toBeGreaterThan(0);
    expect(dataset.families[0]).toHaveProperty('family_id');
    expect(Array.isArray(dataset.families[0].cve_examples)).toBe(true);
    expect(Array.isArray(dataset.families[0].safe_detection_templates)).toBe(true);
    expect(Array.isArray(dataset.families[0].negative_assertion_templates)).toBe(true);
  });

  test('selectRelevantSecurityKnowledge prioritizes login/auth records for login endpoints', () => {
    const matches = securityKnowledge.selectRelevantSecurityKnowledge({
      target_url: 'https://example.com/login',
      user_instruction: 'Run a security check against the login API',
      current_request: {
        method: 'POST',
        url: 'https://example.com/api/login',
        headers: [{ k: 'Content-Type', v: 'application/json' }],
        params: [],
        body: '{"username":"demo","password":"demo"}'
      }
    }, { maxResults: 3 });

    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0]).toHaveProperty('family_id');
    expect(matches[0]).toHaveProperty('matched_terms');
    expect(matches[0]).toHaveProperty('safe_detection_templates');
    expect(matches[0]).toHaveProperty('mutation_risk_templates');
    expect(matches[0]).toHaveProperty('negative_assertion_templates');
    expect(matches[0]).toHaveProperty('payload_packs');
    expect(matches[0]).toHaveProperty('execution_guards');
    expect(matches.some(record => record.family === 'authentication-bypass' || record.family === 'session-management')).toBe(true);
  });

  test('selectRelevantSecurityKnowledge weights upload fingerprints for upload endpoints', () => {
    const matches = securityKnowledge.selectRelevantSecurityKnowledge({
      target_url: 'https://example.com/api/upload/avatar',
      user_instruction: 'Check file upload handling',
      current_request: {
        method: 'POST',
        url: 'https://example.com/api/upload/avatar',
        headers: [{ k: 'Content-Type', v: 'application/json' }],
        params: [{ k: 'filename', v: 'avatar.png' }],
        body: '{"filename":"avatar.png","path":"avatars/"}',
        importMeta: {
          param_descriptors: [
            { name: 'filename', path: 'filename', location: 'body', type: 'string' }
          ]
        }
      }
    }, { maxResults: 2 });

    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].family_id).toBe('path-traversal-upload');
  });

  test('selectRelevantSecurityKnowledge boosts families from last_response clues', () => {
    const matches = securityKnowledge.selectRelevantSecurityKnowledge({
      target_url: 'https://example.com/api/search',
      user_instruction: 'Inspect the failing lookup endpoint',
      current_request: {
        method: 'GET',
        url: 'https://example.com/api/search?q=test',
        headers: [],
        params: [{ k: 'q', v: 'test' }],
        body: ''
      },
      last_response: {
        status: 500,
        body_preview: 'SQLException: syntax error near SELECT in database query',
        headers: {
          'content-type': 'text/plain'
        }
      }
    }, { maxResults: 2 });

    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].family_id).toBe('sql-injection');
    expect(matches[0].matched_terms.some(term => term.startsWith('response:'))).toBe(true);
  });
});
