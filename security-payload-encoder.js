/**
 * Security Payload Encoder
 * Provides encoding variants for WAF bypass and injection testing
 */

/**
 * URL-encode a payload
 * @param {string} payload - Raw payload string
 * @returns {string} URL-encoded payload
 */
function urlEncodePayload(payload) {
  if (typeof payload !== 'string') return payload;
  return encodeURIComponent(payload);
}

/**
 * Double URL-encode a payload (for WAF bypass)
 * @param {string} payload - Raw payload string
 * @returns {string} Double URL-encoded payload
 */
function doubleUrlEncodePayload(payload) {
  if (typeof payload !== 'string') return payload;
  return encodeURIComponent(encodeURIComponent(payload));
}

/**
 * Unicode encode a payload (for normalization bypass)
 * @param {string} payload - Raw payload string
 * @returns {string} Unicode-encoded payload
 */
function unicodeEncodePayload(payload) {
  if (typeof payload !== 'string') return payload;
  return payload.split('').map(char => {
    const code = char.charCodeAt(0);
    if (code > 127) {
      return `\\u${code.toString(16).padStart(4, '0')}`;
    }
    return char;
  }).join('');
}

/**
 * HTML entity encode a payload
 * @param {string} payload - Raw payload string
 * @returns {string} HTML entity-encoded payload
 */
function htmlEntityEncodePayload(payload) {
  if (typeof payload !== 'string') return payload;
  const entities = {
    '<': '&lt;',
    '>': '&gt;',
    '&': '&amp;',
    '"': '&quot;',
    "'": '&#x27;',
    '/': '&#x2F;',
    '=': '&#x3D;'
  };
  return payload.replace(/[<>&"'/=]/g, char => entities[char] || char);
}

/**
 * Base64 encode a payload
 * @param {string} payload - Raw payload string
 * @returns {string} Base64-encoded payload
 */
function base64EncodePayload(payload) {
  if (typeof payload !== 'string') return payload;
  try {
    return Buffer.from(payload, 'utf-8').toString('base64');
  } catch {
    return payload;
  }
}

/**
 * Case randomize a payload (for case-insensitive WAF bypass)
 * @param {string} payload - Raw payload string
 * @returns {string} Case-randomized payload
 */
function caseRandomizePayload(payload) {
  if (typeof payload !== 'string') return payload;
  return payload.split('').map(char => {
    if (/[a-zA-Z]/.test(char)) {
      return Math.random() > 0.5 ? char.toUpperCase() : char.toLowerCase();
    }
    return char;
  }).join('');
}

/**
 * Add null byte injection to payload
 * @param {string} payload - Raw payload string
 * @returns {string} Payload with null byte
 */
function nullByteInjectPayload(payload) {
  if (typeof payload !== 'string') return payload;
  return payload.replace(/(.)/g, '$1%00');
}

/**
 * Add whitespace/randomization to payload
 * @param {string} payload - Raw payload string
 * @returns {string} Payload with inserted whitespace
 */
function whitespaceInjectPayload(payload) {
  if (typeof payload !== 'string') return payload;
  // Insert random whitespace in strategic positions
  return payload
    .replace(/</g, '< ')
    .replace(/>/g, ' >')
    .replace(/=/g, ' = ')
    .replace(/\(/g, ' ( ')
    .replace(/\)/g, ' ) ');
}

/**
 * Comment obfuscation for script tags
 * @param {string} payload - Raw payload string
 * @returns {string} Comment-obfuscated payload
 */
function commentObfuscatePayload(payload) {
  if (typeof payload !== 'string') return payload;
  return payload
    .replace(/<script/gi, '<scr<!-- -->ipt')
    .replace(/<\/script/gi, '</scr<!-- -->ipt')
    .replace(/<img/gi, '<im<!-- -->g')
    .replace(/<svg/gi, '<sv<!-- -->g');
}

/**
 * Generate all encoding variants for a payload
 * @param {string} payload - Raw payload string
 * @param {Object} options - Encoding options
 * @param {boolean} options.urlEncode - Apply URL encoding
 * @param {boolean} options.doubleEncode - Apply double URL encoding
 * @param {boolean} options.unicodeEncode - Apply Unicode encoding
 * @param {boolean} options.htmlEncode - Apply HTML entity encoding
 * @param {boolean} options.base64Encode - Apply Base64 encoding
 * @param {boolean} options.caseRandomize - Apply case randomization
 * @param {boolean} options.nullByte - Apply null byte injection
 * @param {boolean} options.whitespace - Apply whitespace injection
 * @param {boolean} options.comment - Apply comment obfuscation
 * @returns {string[]} Array of encoded payload variants
 */
function generatePayloadVariants(payload, options = {}) {
  if (typeof payload !== 'string') return [];
  
  const variants = [payload]; // Original payload
  
  const {
    urlEncode = false,
    doubleEncode = false,
    unicodeEncode = false,
    htmlEncode = false,
    base64Encode = false,
    caseRandomize = false,
    nullByte = false,
    whitespace = false,
    comment = false
  } = options;
  
  // Apply individual encodings
  if (urlEncode) variants.push(urlEncodePayload(payload));
  if (doubleEncode) variants.push(doubleUrlEncodePayload(payload));
  if (unicodeEncode) variants.push(unicodeEncodePayload(payload));
  if (htmlEncode) variants.push(htmlEntityEncodePayload(payload));
  if (base64Encode) variants.push(base64EncodePayload(payload));
  if (caseRandomize) variants.push(caseRandomizePayload(payload));
  if (nullByte) variants.push(nullByteInjectPayload(payload));
  if (whitespace) variants.push(whitespaceInjectPayload(payload));
  if (comment) variants.push(commentObfuscatePayload(payload));
  
  // Apply combined encodings (common WAF bypass patterns)
  if (urlEncode && caseRandomize) {
    variants.push(urlEncodePayload(caseRandomizePayload(payload)));
  }
  if (comment && caseRandomize) {
    variants.push(commentObfuscatePayload(caseRandomizePayload(payload)));
  }
  
  // Remove duplicates and limit to reasonable number
  const uniqueVariants = [...new Set(variants)];
  return uniqueVariants.slice(0, 16); // Cap at 16 variants
}

/**
 * Get WAF bypass encodings for a specific WAF type
 * @param {string} payload - Raw payload string
 * @param {string} wafType - WAF type: 'cloudflare', 'aws', 'akamai', 'generic'
 * @returns {string[]} Array of WAF-specific bypass variants
 */
function getWafBypassVariants(payload, wafType = 'generic') {
  if (typeof payload !== 'string') return [];
  
  switch (wafType.toLowerCase()) {
    case 'cloudflare':
      return generatePayloadVariants(payload, {
        caseRandomize: true,
        comment: true,
        unicodeEncode: true
      });
    case 'aws':
      return generatePayloadVariants(payload, {
        urlEncode: true,
        doubleEncode: true,
        whitespace: true
      });
    case 'akamai':
      return generatePayloadVariants(payload, {
        htmlEncode: true,
        nullByte: true,
        caseRandomize: true
      });
    default: // generic
      return generatePayloadVariants(payload, {
        caseRandomize: true,
        urlEncode: true,
        comment: true
      });
  }
}

module.exports = {
  urlEncodePayload,
  doubleUrlEncodePayload,
  unicodeEncodePayload,
  htmlEntityEncodePayload,
  base64EncodePayload,
  caseRandomizePayload,
  nullByteInjectPayload,
  whitespaceInjectPayload,
  commentObfuscatePayload,
  generatePayloadVariants,
  getWafBypassVariants
};
