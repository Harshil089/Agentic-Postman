const {
  parseOpenApiToRequests,
  parsePostmanCollectionToRequests
} = require('../import-spec');

describe('import-spec', () => {
  test('parseOpenApiToRequests builds GET from paths', () => {
    const spec = {
      openapi: '3.0.0',
      paths: {
        '/users': {
          get: { summary: 'List users' }
        }
      }
    };
    const { requests, warnings } = parseOpenApiToRequests(spec);
    expect(requests.length).toBe(1);
    expect(requests[0].method).toBe('GET');
    expect(requests[0].url).toContain('users');
    expect(requests[0].name).toMatch(/users/i);
    expect(requests[0].importMeta.source).toBe('openapi');
    expect(Array.isArray(requests[0].importMeta.param_candidates)).toBe(true);
    expect(warnings.some(w => /No operations/i.test(w))).toBe(false);
  });

  test('parseOpenApiToRequests maps query parameters', () => {
    const spec = {
      openapi: '3.0.0',
      paths: {
        '/search': {
          get: {
            parameters: [
              { name: 'q', in: 'query', schema: { default: 'test' } }
            ]
          }
        }
      }
    };
    const { requests } = parseOpenApiToRequests(spec);
    expect(requests[0].params.some(p => p.k === 'q')).toBe(true);
    expect(requests[0].importMeta.param_descriptors).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: 'q', location: 'query' })
    ]));
  });

  test('parsePostmanCollectionToRequests flattens items', () => {
    const collection = {
      info: { name: 'Demo', schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json' },
      item: [
        {
          name: 'Get users',
          request: {
            method: 'GET',
            url: 'https://example.com/users'
          }
        }
      ]
    };
    const { requests } = parsePostmanCollectionToRequests(collection);
    expect(requests.length).toBe(1);
    expect(requests[0].method).toBe('GET');
    expect(requests[0].url).toContain('example.com');
    expect(requests[0].importMeta.source).toBe('postman');
  });
});
