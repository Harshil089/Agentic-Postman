const policyPacks = require('../security-policy-packs');

describe('security-policy-packs', () => {
  test('normalizes policy pack ids', () => {
    expect(policyPacks.normalizePolicyPackId('owasp-api-2023')).toBe('owasp-api-2023');
    expect(policyPacks.normalizePolicyPackId('unknown')).toBe('auto');
  });

  test('infers policy pack from endpoint shape', () => {
    expect(policyPacks.inferPolicyPackId({
      current_request: { method: 'POST', url: 'https://example.com/admin/users' }
    }, 'auto')).toBe('internal-baseline');
  });

  test('merges and dedupes policy assertions', () => {
    const merged = policyPacks.mergePolicyAssertions(
      ['status !== 500', '!body.includes("stack trace")'],
      ['status !== 500', 'elapsed_ms < 5000']
    );
    expect(merged).toEqual([
      'status !== 500',
      '!body.includes("stack trace")',
      'elapsed_ms < 5000'
    ]);
  });
});
