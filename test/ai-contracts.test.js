const aiContracts = require('../ai-contracts');

describe('ai-contracts', () => {
  test('normalizeImportMeta preserves param descriptors and candidates', () => {
    const meta = aiContracts.normalizeImportMeta({
      source: 'openapi',
      param_candidates: ['userId'],
      param_descriptors: [
        { name: 'userId', path: 'userId', location: 'query', type: 'integer', required: true, source: 'openapi.parameter' },
        { name: 'role', path: 'role', location: 'body', type: 'string', required: false, source: 'openapi.requestBody' }
      ]
    });

    expect(meta.source).toBe('openapi');
    expect(meta.param_candidates).toEqual(expect.arrayContaining(['userId', 'role']));
    expect(meta.param_descriptors[0].location).toBe('query');
  });

  test('validateAgentAction rejects chain request without json template', () => {
    const result = aiContracts.validateAgentAction({
      type: 'chain_request',
      name: 'Broken chain',
      method: 'GET',
      url: 'https://api.example.com/users',
      params: [],
      headers: [],
      body: ''
    }, 0);

    expect(result.error).toMatch(/json\.\*/i);
  });

  test('evaluateAssertionExpression supports shared safe syntax', () => {
    const result = aiContracts.evaluateAssertionExpression(
      'status === 200 && Array.isArray(json) && !body.includes("error")',
      {
        status: 200,
        json: [{ id: 1 }],
        body: '{"ok":true}',
        elapsed: 120,
        elapsed_ms: 120,
        Array
      }
    );

    expect(result).toBe(true);
  });

  test('normalizeSecurityAction requires fuzz_list target param', () => {
    const result = aiContracts.validateSecurityAction({
      type: 'fuzz_list',
      vector: 'SQLi',
      payloads: ['1 OR 1=1']
    }, 0);

    expect(result.error).toMatch(/target_param/i);
  });
});
