const request = require('supertest');

const mockDnsLookup = jest.fn();

jest.mock('dns', () => ({
  promises: {
    lookup: (...args) => mockDnsLookup(...args)
  }
}));

function createMockBody(chunks) {
  return {
    getReader() {
      let index = 0;
      return {
        async read() {
          if (index >= chunks.length) {
            return { done: true, value: undefined };
          }
          const value = Buffer.from(chunks[index], 'utf8');
          index += 1;
          return { done: false, value };
        },
        releaseLock() {}
      };
    }
  };
}

function createFetchResponse({
  status = 200,
  statusText = 'OK',
  headers = [['content-type', 'application/json']],
  bodyChunks = ['{"ok":true}']
} = {}) {
  return {
    status,
    statusText,
    headers: {
      entries() {
        return headers[Symbol.iterator]();
      }
    },
    body: createMockBody(bodyChunks)
  };
}

function loadAppWithEnv(env = {}) {
  jest.resetModules();
  process.env.OUTBOUND_REQUEST_TIMEOUT_MS = String(env.requestTimeoutMs || 40);
  process.env.OUTBOUND_RESPONSE_MAX_BYTES = String(env.maxBytes || 48);
  process.env.DNS_LOOKUP_TIMEOUT_MS = String(env.dnsTimeoutMs || 40);
  return require('../server');
}

describe('/api/request', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    global.fetch = jest.fn();
    mockDnsLookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
  });

  afterEach(() => {
    delete global.fetch;
  });

  test('returns 403 for blocked hostname policy errors', async () => {
    const app = loadAppWithEnv();

    const res = await request(app)
      .post('/api/request')
      .send({ method: 'GET', url: 'http://localhost:8080/users', headers: {}, body: '' });

    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/blocked/i);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test('returns 502 when DNS lookup fails', async () => {
    mockDnsLookup.mockRejectedValue(new Error('lookup failed'));
    const app = loadAppWithEnv();

    const res = await request(app)
      .post('/api/request')
      .send({ method: 'GET', url: 'https://example.com/users', headers: {}, body: '' });

    expect(res.status).toBe(502);
    expect(res.body.error).toMatch(/resolve|lookup|target host/i);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test('returns 400 when mutation confirmation is missing', async () => {
    const app = loadAppWithEnv();

    const res = await request(app)
      .post('/api/request')
      .send({
        method: 'POST',
        url: 'https://example.com/items',
        headers: {},
        body: '{"name":"x"}',
        confirm_mutation: false
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/confirmation/i);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test('returns 400 for unsupported HTTP methods', async () => {
    const app = loadAppWithEnv();

    const res = await request(app)
      .post('/api/request')
      .send({ method: 'TRACE', url: 'https://example.com/x', headers: {}, body: '' });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/unsupported method/i);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test('returns 400 for non-http protocols', async () => {
    const app = loadAppWithEnv();

    const res = await request(app)
      .post('/api/request')
      .send({ method: 'GET', url: 'ftp://example.com/file', headers: {}, body: '' });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/http\/https/i);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test('returns 504 when upstream request aborts by timeout', async () => {
    const app = loadAppWithEnv({ requestTimeoutMs: 25 });
    const abortError = new Error('aborted');
    abortError.name = 'AbortError';
    global.fetch.mockRejectedValue(abortError);

    const res = await request(app)
      .post('/api/request')
      .send({ method: 'GET', url: 'https://example.com/slow', headers: {}, body: '' });

    expect(res.status).toBe(504);
    expect(res.body.error).toMatch(/timed out/i);
  });

  test('returns 413 when response body exceeds max bytes', async () => {
    const app = loadAppWithEnv({ maxBytes: 10 });
    global.fetch.mockResolvedValue(
      createFetchResponse({
        status: 200,
        statusText: 'OK',
        bodyChunks: ['1234567890', '1234']
      })
    );

    const res = await request(app)
      .post('/api/request')
      .send({ method: 'GET', url: 'https://example.com/large', headers: {}, body: '' });

    expect(res.status).toBe(413);
    expect(res.body.error).toMatch(/exceeded/i);
  });

  test('returns 200 with upstream metadata for successful calls', async () => {
    const app = loadAppWithEnv();
    global.fetch.mockResolvedValue(
      createFetchResponse({
        status: 201,
        statusText: 'Created',
        headers: [['x-test', 'true']],
        bodyChunks: ['{"id":1}']
      })
    );

    const res = await request(app)
      .post('/api/request')
      .send({ method: 'GET', url: 'https://example.com/resource', headers: {}, body: '' });

    expect(res.status).toBe(200);
    expect(res.body.status).toBe(201);
    expect(res.body.statusText).toBe('Created');
    expect(res.body.headers['x-test']).toBe('true');
    expect(res.body.body).toContain('id');
  });

  test('strips blocked outbound headers before fetch', async () => {
    const app = loadAppWithEnv();
    global.fetch.mockResolvedValue(createFetchResponse());

    await request(app)
      .post('/api/request')
      .send({
        method: 'GET',
        url: 'https://example.com/resource',
        headers: {
          Authorization: 'Bearer secret',
          Host: 'evil.example',
          'X-Custom': 'ok'
        },
        body: ''
      });

    const fetchCall = global.fetch.mock.calls[0];
    expect(fetchCall).toBeTruthy();
    expect(fetchCall[1].headers.Authorization).toBeUndefined();
    expect(fetchCall[1].headers.Host).toBeUndefined();
    expect(fetchCall[1].headers['X-Custom']).toBe('ok');
  });
});
