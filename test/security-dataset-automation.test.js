const automation = require('../security-dataset-automation');

describe('security-dataset-automation', () => {
  test('dedupeFamilies merges duplicate family ids and CVE examples', () => {
    const merged = automation.dedupeFamilies([
      {
        family_id: 'sql-injection',
        tags: ['sql'],
        cve_examples: [{ id: 'CVE-2023-1', title: 'A' }]
      },
      {
        family_id: 'sql-injection',
        tags: ['query'],
        cve_examples: [{ id: 'CVE-2023-1', title: 'A duplicate' }, { id: 'CVE-2023-2', title: 'B' }]
      }
    ]);

    expect(merged).toHaveLength(1);
    expect(merged[0].tags).toEqual(expect.arrayContaining(['sql', 'query']));
    expect(merged[0].cve_examples).toHaveLength(2);
  });

  test('benchmarkDataset scores expected families', () => {
    const report = automation.benchmarkDataset({
      families: [
        { family_id: 'auth-bypass' },
        { family_id: 'session-integrity' }
      ]
    }, [
      { id: 'fixture-1', expected_family_ids: ['auth-bypass'] },
      { id: 'fixture-2', expected_family_ids: ['auth-bypass', 'bola-idor'] }
    ]);

    expect(report.fixture_count).toBe(2);
    expect(report.average_score).toBeCloseTo(0.75, 2);
  });
});
