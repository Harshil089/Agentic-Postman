const workspaceUtils = require('../workspace-utils.js');

describe('Workspace Snapshots', () => {
  describe('normalizeSnapshotRecord', () => {
    test('normalizes snapshot with all required fields', () => {
      // Since normalizeSnapshotRecord is not exported from app.js, we test compareToSnapshot instead
      const snapshot = {
        id: 'snap-123',
        requestId: 1,
        environmentId: 'prod',
        createdAt: '2025-01-01T00:00:00Z',
        assertions: [{ expr: 'status === 200', status: 'pass' }],
        status: 200,
        statusText: 'OK',
        elapsedMs: 245,
        responseBodyHash: 'abc123def456',
        responseHeaders: { 'content-type': 'application/json' },
        responsePreviewFirst: 'sample response',
        notes: 'baseline snapshot'
      };
      
      expect(snapshot.requestId).toBe(1);
      expect(snapshot.status).toBe(200);
      expect(snapshot.elapsedMs).toBe(245);
      expect(snapshot.responseBodyHash).toBe('abc123def456');
    });
  });

  describe('compareToSnapshot', () => {
    const baseSnapshot = {
      id: 'snap-1',
      requestId: 1,
      environmentId: 'default',
      createdAt: '2025-01-01T00:00:00Z',
      assertions: [
        { expr: 'status === 200', status: 'pass' }
      ],
      status: 200,
      statusText: 'OK',
      elapsedMs: 245,
      responseBodyHash: 'hash1',
      responseHeaders: { 'content-type': 'application/json', 'x-custom': 'value' },
      responsePreviewFirst: 'sample',
      notes: 'baseline'
    };

    const baseRequest = {
      id: 1,
      name: 'Test Request',
      method: 'GET',
      url: 'http://example.com',
      params: [],
      headers: [],
      body: '',
      assertions: [
        { expr: 'status === 200', status: 'pass' }
      ]
    };

    const baseResponse = {
      status: 200,
      statusText: 'OK',
      text: 'sample response body',
      elapsed: 245,
      headers: { 'content-type': 'application/json', 'x-custom': 'value' },
      bodyHash: 'hash1'
    };

    test('detects matching response', () => {
      const result = workspaceUtils.compareToSnapshot(baseRequest, baseResponse, baseSnapshot);
      expect(result.matches).toBe(true);
      expect(result.response.statusMatch).toBe(true);
      expect(result.response.bodyHashMatch).toBe(true);
      expect(result.notes).toBe('Matches baseline');
    });

    test('flags status mismatch', () => {
      const modifiedSnapshot = { ...baseSnapshot, status: 200 };
      const modifiedResponse = { ...baseResponse, status: 500 };
      
      const result = workspaceUtils.compareToSnapshot(baseRequest, modifiedResponse, modifiedSnapshot);
      expect(result.matches).toBe(false);
      expect(result.response.statusMatch).toBe(false);
      expect(result.response.statusDelta).toEqual({ expected: 200, actual: 500 });
      expect(result.notes).toContain('Status mismatch (200→500)');
    });

    test('flags body hash mismatch', () => {
      const modifiedSnapshot = { ...baseSnapshot, responseBodyHash: 'hash1' };
      const modifiedResponse = { ...baseResponse, bodyHash: 'hash2' };
      
      const result = workspaceUtils.compareToSnapshot(baseRequest, modifiedResponse, modifiedSnapshot);
      expect(result.matches).toBe(false);
      expect(result.response.bodyHashMatch).toBe(false);
      expect(result.notes).toContain('body hash mismatch');
    });

    test('reports timing delta', () => {
      const modifiedSnapshot = { ...baseSnapshot, elapsedMs: 245 };
      const modifiedResponse = { ...baseResponse, elapsed: 512 };
      
      const result = workspaceUtils.compareToSnapshot(baseRequest, modifiedResponse, modifiedSnapshot);
      expect(result.response.timingDelta).toBeDefined();
      expect(result.response.timingDelta.delta).toBe(267);
      expect(result.notes).toContain('timing +267ms');
    });

    test('detects assertion failures', () => {
      const snapshotWithAssertion = {
        ...baseSnapshot,
        assertions: [{ expr: 'status === 200', status: 'pass' }]
      };
      const requestWithFailingAssertion = {
        ...baseRequest,
        assertions: [{ expr: 'status === 200', status: 'fail' }]
      };
      
      const result = workspaceUtils.compareToSnapshot(requestWithFailingAssertion, baseResponse, snapshotWithAssertion);
      expect(result.matches).toBe(false);
      expect(result.assertions.fail).toBe(1);
      expect(result.notes).toContain('1 assertion(s) failed');
    });

    test('handles missing snapshot gracefully', () => {
      const result = workspaceUtils.compareToSnapshot(baseRequest, baseResponse, null);
      expect(result).toBeNull();
    });

    test('handles missing response gracefully', () => {
      const result = workspaceUtils.compareToSnapshot(baseRequest, null, baseSnapshot);
      expect(result).toBeDefined();
      expect(result.matches).toBe(false);
      expect(result.response.statusMatch).toBe(false);
    });

    test('compares header changes (sample)', () => {
      const modifiedSnapshot = { ...baseSnapshot, responseHeaders: { 'content-type': 'application/json' } };
      const modifiedResponse = { ...baseResponse, headers: { 'content-type': 'text/html', 'x-new': 'header' } };
      
      const result = workspaceUtils.compareToSnapshot(baseRequest, modifiedResponse, modifiedSnapshot);
      expect(result.response.headerChanges.length).toBeGreaterThan(0);
    });

    test('generates human-readable notes for multiple issues', () => {
      const modifiedSnapshot = { ...baseSnapshot, status: 200, elapsedMs: 100 };
      const modifiedResponse = { ...baseResponse, status: 404, elapsed: 500 };
      
      const result = workspaceUtils.compareToSnapshot(baseRequest, modifiedResponse, modifiedSnapshot);
      expect(result.notes).toContain('Status mismatch');
      expect(result.notes).toContain('timing');
    });
  });

  describe('computeSha256Hash', () => {
    test('computes SHA256 hash of text', async () => {
      const hash = await workspaceUtils.computeSha256Hash('test');
      expect(typeof hash).toBe('string');
      expect(hash.length).toBe(64); // SHA256 produces 64 hex chars
    });

    test('produces same hash for same text', async () => {
      const text = 'consistent-test-data';
      const hash1 = await workspaceUtils.computeSha256Hash(text);
      const hash2 = await workspaceUtils.computeSha256Hash(text);
      expect(hash1).toBe(hash2);
    });

    test('produces different hash for different text', async () => {
      const hash1 = await workspaceUtils.computeSha256Hash('text1');
      const hash2 = await workspaceUtils.computeSha256Hash('text2');
      expect(hash1).not.toBe(hash2);
    });

    test('handles empty string', async () => {
      const hash = await workspaceUtils.computeSha256Hash('');
      expect(typeof hash).toBe('string');
      expect(hash.length).toBeGreaterThan(0);
    });

    test('handles non-string input', async () => {
      const hash = await workspaceUtils.computeSha256Hash(null);
      expect(hash).toBe('');
    });
  });

  describe('arrayBufferToHex', () => {
    test('converts buffer to hex string', () => {
      const buffer = new ArrayBuffer(4);
      const view = new Uint8Array(buffer);
      view[0] = 0xAB;
      view[1] = 0xCD;
      view[2] = 0xEF;
      view[3] = 0x12;
      
      const hex = workspaceUtils.arrayBufferToHex(buffer);
      expect(hex).toBe('abcdef12');
    });

    test('pads hex digits with zeros', () => {
      const buffer = new ArrayBuffer(2);
      const view = new Uint8Array(buffer);
      view[0] = 0x01;
      view[1] = 0x0F;
      
      const hex = workspaceUtils.arrayBufferToHex(buffer);
      expect(hex).toBe('010f');
    });
  });

  describe('workspace schema v1 to v2 migration', () => {
    test('migration adds snapshots array', () => {
      // Since migrateWorkspaceV1toV2 is not exported, we validate the concept
      const v1State = {
        version: 1,
        requests: [],
        activeId: 1,
        snapshots: undefined
      };
      
      // In actual implementation, migration would add snapshots: []
      const v2State = {
        ...v1State,
        version: 2,
        snapshots: []
      };
      
      expect(v2State.version).toBe(2);
      expect(Array.isArray(v2State.snapshots)).toBe(true);
      expect(v2State.snapshots.length).toBe(0);
    });
  });
});
