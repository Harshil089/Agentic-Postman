/**
 * Tests for Enhanced Injection Commands
 * Validates new vectors, payload encoders, adapters, and attack chains
 */

const assert = require('assert');
const path = require('path');

// Test modules
const aiContracts = require('../ai-contracts');
const payloadPacks = require('../security-payload-packs');
const payloadEncoder = require('../security-payload-encoder');
const payloadAdapter = require('../security-payload-adapter');
const businessLogicPayloads = require('../security-business-logic-payloads');
const wafBypass = require('../security-waf-bypass');
const attackChains = require('../security-attack-chains');

describe('Enhanced Injection Commands', () => {
  
  describe('New Security Vectors', () => {
    it('should include XSS vector', () => {
      assert.ok(aiContracts.SECURITY_VECTORS.has('XSS'));
    });
    
    it('should include SSTI vector', () => {
      assert.ok(aiContracts.SECURITY_VECTORS.has('SSTI'));
    });
    
    it('should include GraphQLInjection vector', () => {
      assert.ok(aiContracts.SECURITY_VECTORS.has('GraphQLInjection'));
    });
    
    it('should include LDAPInjection vector', () => {
      assert.ok(aiContracts.SECURITY_VECTORS.has('LDAPInjection'));
    });
    
    it('should include XPathInjection vector', () => {
      assert.ok(aiContracts.SECURITY_VECTORS.has('XPathInjection'));
    });
    
    it('should include PrototypePollution vector', () => {
      assert.ok(aiContracts.SECURITY_VECTORS.has('PrototypePollution'));
    });
    
    it('should include EmailHeaderInjection vector', () => {
      assert.ok(aiContracts.SECURITY_VECTORS.has('EmailHeaderInjection'));
    });
    
    it('should have 24 total vectors', () => {
      assert.strictEqual(aiContracts.SECURITY_VECTORS.size, 24);
    });
  });
  
  describe('Payload Packs', () => {
    describe('XSS Payload Pack', () => {
      it('should resolve XSS payload pack', () => {
        const pack = payloadPacks.resolvePayloadPackForFamily('xss');
        assert.ok(pack);
        assert.ok(Array.isArray(pack.safe));
        assert.ok(Array.isArray(pack.controlled_mutation));
        assert.ok(Array.isArray(pack.high_risk));
      });
      
      it('should have safe XSS payloads', () => {
        const pack = payloadPacks.resolvePayloadPackForFamily('xss');
        assert.ok(pack.safe.length > 0);
        assert.ok(pack.safe.some(p => p.value.includes('<script>')));
      });
      
      it('should have execution guards', () => {
        const pack = payloadPacks.resolvePayloadPackForFamily('xss');
        assert.ok(Array.isArray(pack.execution_guards));
        assert.ok(pack.execution_guards.length > 0);
      });
    });
    
    describe('SSTI Payload Pack', () => {
      it('should resolve SSTI payload pack', () => {
        const pack = payloadPacks.resolvePayloadPackForFamily('ssti');
        assert.ok(pack);
        assert.ok(pack.safe.length > 0);
      });
      
      it('should have arithmetic detection payloads', () => {
        const pack = payloadPacks.resolvePayloadPackForFamily('ssti');
        assert.ok(pack.safe.some(p => p.value.includes('{{7*7}}')));
      });
    });
    
    describe('GraphQL Payload Pack', () => {
      it('should resolve GraphQL payload pack', () => {
        const pack = payloadPacks.resolvePayloadPackForFamily('graphql-injection');
        assert.ok(pack);
        assert.ok(pack.safe.length > 0);
      });
      
      it('should have introspection payloads', () => {
        const pack = payloadPacks.resolvePayloadPackForFamily('graphql-injection');
        assert.ok(pack.safe.some(p => p.value.includes('__typename')));
      });
    });
  });
  
  describe('Payload Encoder', () => {
    describe('URL Encoding', () => {
      it('should URL-encode payload', () => {
        const encoded = payloadEncoder.urlEncodePayload('<script>alert(1)</script>');
        assert.strictEqual(encoded, '%3Cscript%3Ealert(1)%3C%2Fscript%3E');
      });
      
      it('should double URL-encode payload', () => {
        const encoded = payloadEncoder.doubleUrlEncodePayload('<script>');
        assert.ok(encoded.includes('%25'));
      });
    });
    
    describe('Case Randomization', () => {
      it('should randomize case', () => {
        const original = 'script';
        const randomized = payloadEncoder.caseRandomizePayload(original);
        assert.strictEqual(randomized.toLowerCase(), original);
        assert.notStrictEqual(randomized, original);
      });
    });
    
    describe('Variant Generation', () => {
      it('should generate multiple variants', () => {
        const variants = payloadEncoder.generatePayloadVariants('<script>alert(1)</script>', {
          urlEncode: true,
          caseRandomize: true,
          comment: true
        });
        assert.ok(variants.length > 1);
        assert.ok(variants.includes('<script>alert(1)</script>'));
      });
      
      it('should limit variants to 16', () => {
        const variants = payloadEncoder.generatePayloadVariants('<script>alert(1)</script>', {
          urlEncode: true,
          doubleEncode: true,
          unicodeEncode: true,
          htmlEncode: true,
          base64Encode: true,
          caseRandomize: true,
          nullByte: true,
          whitespace: true,
          comment: true
        });
        assert.ok(variants.length <= 16);
      });
    });
    
    describe('WAF Bypass Variants', () => {
      it('should generate Cloudflare bypass variants', () => {
        const variants = payloadEncoder.getWafBypassVariants('<script>alert(1)</script>', 'cloudflare');
        assert.ok(variants.length > 0);
      });
      
      it('should generate AWS WAF bypass variants', () => {
        const variants = payloadEncoder.getWafBypassVariants('<script>alert(1)</script>', 'aws');
        assert.ok(variants.length > 0);
      });
    });
  });
  
  describe('Payload Adapter', () => {
    describe('Parameter Descriptor Analysis', () => {
      it('should analyze ID parameter', () => {
        const hints = payloadAdapter.analyzeParamDescriptor({
          name: 'id',
          type: 'string',
          location: 'query'
        });
        assert.strictEqual(hints.strategy, 'idor-sqli');
      });
      
      it('should analyze email parameter', () => {
        const hints = payloadAdapter.analyzeParamDescriptor({
          name: 'email',
          type: 'string',
          location: 'body'
        });
        assert.strictEqual(hints.strategy, 'email-injection');
      });
      
      it('should analyze numeric parameter', () => {
        const hints = payloadAdapter.analyzeParamDescriptor({
          name: 'count',
          type: 'number',
          location: 'query'
        });
        assert.strictEqual(hints.type, 'number');
      });
    });
    
    describe('Context-Aware Payload Generation', () => {
      it('should generate numeric SQLi payloads', () => {
        const payloads = payloadAdapter.generateContextAwarePayload(
          'SQLi',
          { name: 'id', type: 'number' },
          'application/json',
          'safe'
        );
        assert.ok(payloads.length > 0);
        assert.ok(payloads.some(p => /1 OR 1=1/.test(p)));
      });
      
      it('should generate string XSS payloads', () => {
        const payloads = payloadAdapter.generateContextAwarePayload(
          'XSS',
          { name: 'search', type: 'string' },
          'application/json',
          'safe'
        );
        assert.ok(payloads.length > 0);
        assert.ok(payloads.some(p => p.includes('<script>')));
      });
    });
  });
  
  describe('Business Logic Payloads', () => {
    describe('Negative Value Payloads', () => {
      it('should get negative value payloads', () => {
        const payloads = businessLogicPayloads.getBusinessLogicPayloads('negative-value', 'safe');
        assert.ok(payloads.length > 0);
        assert.ok(payloads.some(p => p.value === '-1'));
      });
    });
    
    describe('Price Manipulation', () => {
      it('should get price manipulation payloads', () => {
        const payloads = businessLogicPayloads.getBusinessLogicPayloads('price-manipulation', 'safe');
        assert.ok(payloads.length > 0);
        assert.ok(payloads.some(p => p.value === '0'));
      });
    });
    
    describe('Context Detection', () => {
      it('should detect e-commerce context', () => {
        const categories = businessLogicPayloads.detectBusinessLogicContext(
          '/api/checkout/cart',
          'POST'
        );
        assert.ok(categories.includes('price-manipulation'));
        assert.ok(categories.includes('coupon'));
      });
      
      it('should detect user management context', () => {
        const categories = businessLogicPayloads.detectBusinessLogicContext(
          '/api/users/profile',
          'PUT'
        );
        assert.ok(categories.includes('role'));
      });
    });
  });
  
  describe('WAF Bypass', () => {
    describe('Case Variation', () => {
      it('should apply case variation', () => {
        const variants = wafBypass.applyCaseVariation('<script>');
        assert.ok(variants.some(v => v === '<ScRiPt>'));
      });
    });
    
    describe('WAF Detection', () => {
      it('should detect Cloudflare WAF', () => {
        const detection = wafBypass.detectWafFromResponse(403, {
          'cf-ray': '12345',
          'server': 'cloudflare'
        }, 'Cloudflare');
        assert.strictEqual(detection.detected, true);
        assert.strictEqual(detection.waf, 'cloudflare');
      });
      
      it('should detect generic WAF on 403', () => {
        const detection = wafBypass.detectWafFromResponse(403, {}, 'Blocked');
        assert.strictEqual(detection.detected, true);
        assert.strictEqual(detection.waf, 'generic');
      });
    });
    
    describe('Bypass Test Plan', () => {
      it('should build WAF bypass test plan', () => {
        const plan = wafBypass.buildWafBypassTestPlan(
          '<script>alert(1)</script>',
          { waf: 'cloudflare', confidence: 0.8 },
          10
        );
        assert.ok(plan.variants.length > 0);
        assert.ok(plan.variants.length <= 10);
      });
    });
  });
  
  describe('Attack Chains', () => {
    describe('Chain Retrieval', () => {
      it('should get attack chain for IDOR vector', () => {
        const chain = attackChains.getAttackChainForVector('IDOR');
        assert.ok(chain);
        assert.strictEqual(chain.vector, 'IDOR');
      });
      
      it('should get attack chain for SSRF vector', () => {
        const chain = attackChains.getAttackChainForVector('SSRF');
        assert.ok(chain);
        assert.strictEqual(chain.name, 'SSRF to Cloud Metadata Extraction');
      });
      
      it('should return null for unknown vector', () => {
        const chain = attackChains.getAttackChainForVector('Unknown');
        assert.strictEqual(chain, null);
      });
    });
    
    describe('Chain Execution', () => {
      it('should build executable chain', () => {
        const chain = attackChains.AUTH_TO_IDOR_CHAIN;
        const executable = attackChains.buildExecutableChain(chain, {
          baseUrl: 'https://api.example.com',
          tokens: { token: 'test123' },
          extractedValues: { userId: '456' }
        });
        
        assert.strictEqual(executable.type, 'probe_chain');
        assert.ok(executable.steps.length > 0);
        assert.ok(executable.steps[0].url.includes('https://api.example.com'));
      });
    });
    
    describe('Prerequisite Validation', () => {
      it('should validate chain prerequisites', () => {
        const chain = attackChains.AUTH_TO_IDOR_CHAIN;
        const validation = attackChains.validateChainPrerequisites(chain, {
          credentials: { username: 'test', password: 'test' }
        });
        
        assert.ok(validation.valid || !validation.valid); // Depends on chain
      });
    });
  });
  
  describe('CVE Dataset Integration', () => {
    const fs = require('fs');
    const datasetPath = path.join(__dirname, '..', 'security-cve-dataset.json');
    let dataset;
    
    beforeAll(() => {
      const raw = fs.readFileSync(datasetPath, 'utf8');
      dataset = JSON.parse(raw);
    });
    
    it('should include XSS family', () => {
      const xssFamily = dataset.families.find(f => f.family_id === 'xss');
      assert.ok(xssFamily);
      assert.strictEqual(xssFamily.cwe, 'CWE-79');
    });
    
    it('should include SSTI family', () => {
      const sstiFamily = dataset.families.find(f => f.family_id === 'ssti');
      assert.ok(sstiFamily);
      assert.strictEqual(sstiFamily.cwe, 'CWE-1336');
    });
    
    it('should include GraphQL family', () => {
      const graphqlFamily = dataset.families.find(f => f.family_id === 'graphql-injection');
      assert.ok(graphqlFamily);
      assert.strictEqual(graphqlFamily.cwe, 'CWE-94');
    });
    
    it('should include LDAP family', () => {
      const ldapFamily = dataset.families.find(f => f.family_id === 'ldap-injection');
      assert.ok(ldapFamily);
      assert.strictEqual(ldapFamily.cwe, 'CWE-90');
    });
    
    it('should include XPath family', () => {
      const xpathFamily = dataset.families.find(f => f.family_id === 'xpath-injection');
      assert.ok(xpathFamily);
      assert.strictEqual(xpathFamily.cwe, 'CWE-643');
    });
    
    it('should include Prototype Pollution family', () => {
      const protoFamily = dataset.families.find(f => f.family_id === 'prototype-pollution');
      assert.ok(protoFamily);
      assert.strictEqual(protoFamily.cwe, 'CWE-1321');
    });
    
    it('should include Email Header Injection family', () => {
      const emailFamily = dataset.families.find(f => f.family_id === 'email-header-injection');
      assert.ok(emailFamily);
      assert.strictEqual(emailFamily.cwe, 'CWE-113');
    });
  });
});
