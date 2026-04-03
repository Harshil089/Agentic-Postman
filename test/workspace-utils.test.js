const {
  summarizePreview,
  describeRequestDiff,
  resolveChainTemplate,
  resolveVariableTemplate,
  collectParamCandidatesFromRequest,
  arrayBufferToHex,
  computeSha256Hash,
  compareToSnapshot
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

  test('compareToSnapshot detects matching response', () => {
    const snapshot = {
      status: 200,
      statusText: 'OK',
      elapsedMs: 100,
      responseBodyHash: 'abc123',
      responseHeaders: { 'content-type': 'application/json' },
      assertions: []
    };
    const request = { id: 1, assertions: [] };
    const response = { status: 200, statusText: 'OK', elapsed: 100, headers: {}, bodyHash: 'abc123' };

    const result = compareToSnapshot(request, response, snapshot);
    expect(result.matches).toBe(true);
    expect(result.response.statusMatch).toBe(true);
    expect(result.notes).toContain('Matches');
  });

  test('compareToSnapshot flags status mismatch', () => {
    const snapshot = { status: 200, statusText: 'OK', elapsedMs: 100, responseBodyHash: 'hash1', responseHeaders: {}, assertions: [] };
    const request = { id: 1, assertions: [] };
    const response = { status: 500, statusText: 'Error', elapsed: 100, headers: {}, bodyHash: 'hash1' };

    const result = compareToSnapshot(request, response, snapshot);
    expect(result.matches).toBe(false);
    expect(result.response.statusMatch).toBe(false);
    expect(result.response.statusDelta.actual).toBe(500);
    expect(result.notes).toContain('Status mismatch');
  });

  test('compareToSnapshot detects body hash mismatch', () => {
    const snapshot = { status: 200, statusText: 'OK', elapsedMs: 100, responseBodyHash: 'hash1', responseHeaders: {}, assertions: [] };
    const request = { id: 1, assertions: [] };
    const response = { status: 200, statusText: 'OK', elapsed: 100, headers: {}, bodyHash: 'hash2' };

    const result = compareToSnapshot(request, response, snapshot);
    expect(result.matches).toBe(false);
    expect(result.response.bodyHashMatch).toBe(false);
    expect(result.notes).toContain('body hash mismatch');
  });

  test('compareToSnapshot reports timing delta', () => {
    const snapshot = { status: 200, statusText: 'OK', elapsedMs: 100, responseBodyHash: 'hash1', responseHeaders: {}, assertions: [] };
    const request = { id: 1, assertions: [] };
    const response = { status: 200, statusText: 'OK', elapsed: 350, headers: {}, bodyHash: 'hash1' };

    const result = compareToSnapshot(request, response, snapshot);
    expect(result.response.timingDelta).toBeDefined();
    expect(result.response.timingDelta.delta).toBe(250);
    expect(result.notes).toContain('+250ms');
  });

  test('computeSha256Hash produces consistent hex', async () => {
    const hash1 = await computeSha256Hash('test-data');
    const hash2 = await computeSha256Hash('test-data');
    expect(hash1).toBe(hash2);
    expect(hash1.length).toBe(64); // SHA256 = 64 hex chars
  });

  test('computeSha256Hash produces different hashes for different inputs', async () => {
    const hash1 = await computeSha256Hash('data1');
    const hash2 = await computeSha256Hash('data2');
    expect(hash1).not.toBe(hash2);
  });

  test('arrayBufferToHex converts buffer to hex string', () => {
    const buffer = new ArrayBuffer(4);
    const view = new Uint8Array(buffer);
    view[0] = 0xFF;
    view[1] = 0x00;
    view[2] = 0xAB;
    view[3] = 0xCD;

    const hex = arrayBufferToHex(buffer);
    expect(hex).toBe('ff00abcd');
  });

  test('arrayBufferToHex pads single-digit bytes with zero', () => {
    const buffer = new ArrayBuffer(2);
    const view = new Uint8Array(buffer);
    view[0] = 0x01;
    view[1] = 0x0F;

    const hex = arrayBufferToHex(buffer);
    expect(hex).toBe('010f');
  });
});
