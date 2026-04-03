const {
  summarizePreview,
  describeRequestDiff,
  resolveChainTemplate,
  resolveVariableTemplate,
  collectParamCandidatesFromRequest
} = require('../workspace-utils');

describe('workspace-utils', () => {
  test('summarizePreview trims and limits long text', () => {
    expect(summarizePreview('   hello world   ', 20)).toBe('hello world');
    expect(summarizePreview('abcdefghijklmnopqrstuvwxyz', 10)).toBe('abcdefghij...');
  });

  test('describeRequestDiff reports request and response changes', () => {
    const diff = describeRequestDiff(
      { method: 'GET', url: 'https://a.com', body: '', params: [], headers: [], assertions: [] },
      { method: 'POST', url: 'https://a.com/v2', body: '{"x":1}', params: [], headers: [{ k: 'x', v: '1' }], assertions: ['status===200'] },
      { status: 200, elapsed_ms: 90, responsePreview: 'ok' },
      { status: 201, elapsed_ms: 120, responsePreview: 'created' }
    );

    expect(diff).toMatch(/request:/);
    expect(diff).toMatch(/method/);
    expect(diff).toMatch(/url/);
    expect(diff).toMatch(/status 200->201/);
  });

  test('resolveChainTemplate interpolates json paths and preserves missing tokens', () => {
    const url = 'https://api.example.com/users/{{json.user.id}}/posts/{{json.posts[0].id}}/{{json.missing.value}}';
    const response = JSON.stringify({ user: { id: 42 }, posts: [{ id: 7 }] });
    const resolved = resolveChainTemplate(url, response);

    expect(resolved).toContain('/users/42/posts/7/');
    expect(resolved).toContain('{{json.missing.value}}');
  });

  test('resolveChainTemplate no-ops when response is not valid json', () => {
    const url = 'https://api.example.com/{{json.user.id}}';
    expect(resolveChainTemplate(url, 'not-json')).toBe(url);
  });

  test('resolveVariableTemplate resolves placeholders and preserves unknown tokens by default', () => {
    const input = '{{baseUrl}}/users/{{userId}}?next={{missing}}';
    const result = resolveVariableTemplate(input, { baseUrl: 'https://api.example.com', userId: 7 });

    expect(result).toBe('https://api.example.com/users/7?next={{missing}}');
  });

  test('resolveVariableTemplate can drop unknown tokens', () => {
    const input = 'token={{secret}}&unused={{unknown}}';
    const result = resolveVariableTemplate(input, { secret: 'abc123' }, false);

    expect(result).toBe('token=abc123&unused=');
  });

  test('collectParamCandidatesFromRequest merges query, kv params, and json keys', () => {
    const req = {
      url: 'https://api.example.com/items?sort=name&page=1',
      params: [{ k: 'filter', v: 'x' }],
      headers: [{ k: 'Content-Type', v: 'application/json' }],
      body: JSON.stringify({ title: 'a', nested: { skip: true } })
    };
    const keys = collectParamCandidatesFromRequest(req);
    expect(keys).toEqual(expect.arrayContaining(['sort', 'page', 'filter', 'title', 'nested']));
  });
});
