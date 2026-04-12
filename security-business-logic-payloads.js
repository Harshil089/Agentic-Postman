/**
 * Security Business Logic Payloads
 * Specialized payloads for business logic abuse testing
 */

/**
 * Negative quantity and value manipulation payloads
 */
const NEGATIVE_VALUE_PAYLOADS = {
  safe: [
    { field: 'quantity', value: '-1', description: 'Negative quantity test' },
    { field: 'amount', value: '-100', description: 'Negative amount test' },
    { field: 'count', value: '-999', description: 'Large negative count' }
  ],
  controlled_mutation: [
    { field: 'quantity', value: '-9999', description: 'Extreme negative quantity' },
    { field: 'balance', value: '-1000000', description: 'Negative balance injection' }
  ],
  high_risk: [
    { field: 'transferAmount', value: '-999999999', description: 'Extreme value transfer' }
  ]
};

/**
 * Price manipulation payloads
 */
const PRICE_MANIPULATION_PAYLOADS = {
  safe: [
    { field: 'price', value: '0', description: 'Zero price test' },
    { field: 'price', value: '0.01', description: 'Minimal price test' },
    { field: 'price', value: '0.00', description: 'Free price test' },
    { field: 'total', value: '-1', description: 'Negative total test' }
  ],
  controlled_mutation: [
    { field: 'price', value: '0.001', description: 'Fractional price test' },
    { field: 'discount', value: '100', description: '100% discount test' },
    { field: 'discount', value: '150', description: 'Over-100% discount test' }
  ],
  high_risk: [
    { field: 'price', value: '-999.99', description: 'Negative price - potential credit' },
    { field: 'refundAmount', value: '999999', description: 'Extreme refund amount' }
  ]
};

/**
 * Date and time bypass payloads
 */
const DATE_TIME_PAYLOADS = {
  safe: [
    { field: 'date', value: '1970-01-01', description: 'Unix epoch test' },
    { field: 'date', value: '2099-12-31', description: 'Far future date test' },
    { field: 'startDate', value: '2000-01-01', description: 'Y2K date test' },
    { field: 'endDate', value: '1999-12-31', description: 'Reverse date range test' }
  ],
  controlled_mutation: [
    { field: 'expiryDate', value: '2099-12-31T23:59:59Z', description: 'Far future expiry' },
    { field: 'birthDate', value: '2025-01-01', description: 'Future birth date - age bypass' },
    { field: 'validFrom', value: '2050-01-01', description: 'Future validity start' }
  ],
  high_risk: [
    { field: 'contractDate', value: '1900-01-01', description: 'Historical date - legal bypass' },
    { field: 'timestamp', value: '9999999999', description: 'Integer overflow timestamp' }
  ]
};

/**
 * Coupon and discount abuse payloads
 */
const COUPON_PAYLOADS = {
  safe: [
    { field: 'couponCode', value: 'TEST', description: 'Generic test coupon' },
    { field: 'promoCode', value: 'FREE', description: 'FREE promo test' },
    { field: 'discountCode', value: '100OFF', description: 'Large discount code' }
  ],
  controlled_mutation: [
    { field: 'couponCode', value: 'ADMIN', description: 'Privileged coupon test' },
    { field: 'promoCode', value: 'STAFF', description: 'Staff promo test' },
    { field: 'discountPercent', value: '100', description: '100% discount injection' },
    { field: 'discountPercent', value: '200', description: 'Over-100% discount injection' }
  ],
  high_risk: [
    { field: 'couponCode', value: 'COMP_ADMIN_FREE_LIFETIME', description: 'Extreme privilege coupon' },
    { field: 'discountAmount', value: '999999999', description: 'Extreme discount amount' }
  ]
};

/**
 * Rate limit bypass payloads
 */
const RATE_LIMIT_PAYLOADS = {
  safe: [
    { field: 'limit', value: '1000', description: 'High limit test' },
    { field: 'maxResults', value: '10000', description: 'Large result set test' },
    { field: 'pageSize', value: '999', description: 'Large page size test' }
  ],
  controlled_mutation: [
    { field: 'requestsPerSecond', value: '1000', description: 'High RPS test' },
    { field: 'dailyLimit', value: '999999', description: 'Extreme daily limit' },
    { field: 'burstSize', value: '500', description: 'Burst size manipulation' }
  ],
  high_risk: [
    { field: 'rateLimit', value: '0', description: 'Disable rate limit test' },
    { field: 'throttleEnabled', value: 'false', description: 'Disable throttle test' }
  ]
};

/**
 * Inventory and stock manipulation payloads
 */
const INVENTORY_PAYLOADS = {
  safe: [
    { field: 'stock', value: '99999', description: 'High stock test' },
    { field: 'available', value: '0', description: 'Zero availability test' },
    { field: 'reserved', value: '-1', description: 'Negative reservation test' }
  ],
  controlled_mutation: [
    { field: 'inventoryCount', value: '-999', description: 'Negative inventory test' },
    { field: 'backorder', value: '999999', description: 'Extreme backorder test' }
  ],
  high_risk: [
    { field: 'stock', value: 'null', description: 'Null stock injection' },
    { field: 'available', value: 'undefined', description: 'Undefined availability' }
  ]
};

/**
 * User role and permission payloads
 */
const ROLE_MANIPULATION_PAYLOADS = {
  safe: [
    { field: 'role', value: 'user', description: 'Standard role test' },
    { field: 'role', value: 'guest', description: 'Guest role test' },
    { field: 'userType', value: 'basic', description: 'Basic user type test' }
  ],
  controlled_mutation: [
    { field: 'role', value: 'admin', description: 'Admin role injection' },
    { field: 'role', value: 'moderator', description: 'Moderator role injection' },
    { field: 'permissions', value: '["read","write"]', description: 'Permission array injection' },
    { field: 'accessLevel', value: '5', description: 'High access level test' }
  ],
  high_risk: [
    { field: 'role', value: 'superadmin', description: 'Super admin role injection' },
    { field: 'permissions', value: '["*"]', description: 'Wildcard permission injection' },
    { field: 'isAdmin', value: 'true', description: 'Boolean admin flag injection' },
    { field: 'accessLevel', value: '999', description: 'Extreme access level' }
  ]
};

/**
 * Workflow bypass payloads
 */
const WORKFLOW_PAYLOADS = {
  safe: [
    { field: 'step', value: '10', description: 'Skip workflow steps test' },
    { field: 'stage', value: 'complete', description: 'Jump to completion test' },
    { field: 'status', value: 'approved', description: 'Direct approval test' }
  ],
  controlled_mutation: [
    { field: 'workflowStep', value: '999', description: 'Extreme step skip' },
    { field: 'verificationStatus', value: 'verified', description: 'Skip verification test' },
    { field: 'paymentStatus', value: 'paid', description: 'Direct payment status' }
  ],
  high_risk: [
    { field: 'approvalStatus', value: 'auto-approved', description: 'Auto-approval bypass' },
    { field: 'complianceCheck', value: 'passed', description: 'Compliance bypass' }
  ]
};

/**
 * Get payloads for a specific business logic category
 * @param {string} category - Category name
 * @param {string} safetyTier - Safety tier: 'safe', 'controlled-mutation', 'high-risk'
 * @returns {Object[]} Array of payload objects
 */
function getBusinessLogicPayloads(category, safetyTier = 'safe') {
  const categoryMap = {
    'negative-value': NEGATIVE_VALUE_PAYLOADS,
    'price-manipulation': PRICE_MANIPULATION_PAYLOADS,
    'date-time': DATE_TIME_PAYLOADS,
    'coupon': COUPON_PAYLOADS,
    'rate-limit': RATE_LIMIT_PAYLOADS,
    'inventory': INVENTORY_PAYLOADS,
    'role': ROLE_MANIPULATION_PAYLOADS,
    'workflow': WORKFLOW_PAYLOADS
  };
  
  const payloads = categoryMap[category?.toLowerCase()];
  if (!payloads) return [];
  
  const tier = payloads[safetyTier] || payloads.safe;
  return tier.map(p => ({
    location: 'body',
    key: p.field,
    value: p.value,
    description: p.description,
    vector: 'BusinessLogic',
    safety_tier: safetyTier
  }));
}

/**
 * Get all business logic payloads for comprehensive testing
 * @param {string} safetyTier - Safety tier
 * @returns {Object} All categories with payloads
 */
function getAllBusinessLogicPayloads(safetyTier = 'safe') {
  return {
    negativeValue: getBusinessLogicPayloads('negative-value', safetyTier),
    priceManipulation: getBusinessLogicPayloads('price-manipulation', safetyTier),
    dateTime: getBusinessLogicPayloads('date-time', safetyTier),
    coupon: getBusinessLogicPayloads('coupon', safetyTier),
    rateLimit: getBusinessLogicPayloads('rate-limit', safetyTier),
    inventory: getBusinessLogicPayloads('inventory', safetyTier),
    role: getBusinessLogicPayloads('role', safetyTier),
    workflow: getBusinessLogicPayloads('workflow', safetyTier)
  };
}

/**
 * Detect business logic context from endpoint and suggest relevant categories
 * @param {string} url - Endpoint URL
 * @param {string} method - HTTP method
 * @returns {string[]} Relevant business logic categories
 */
function detectBusinessLogicContext(url, method) {
  const urlLower = url.toLowerCase();
  const categories = [];
  
  // E-commerce contexts
  if (urlLower.includes('checkout') || urlLower.includes('cart') || urlLower.includes('order')) {
    categories.push('price-manipulation', 'coupon', 'negative-value');
  }
  
  if (urlLower.includes('payment') || urlLower.includes('refund')) {
    categories.push('price-manipulation', 'negative-value');
  }
  
  if (urlLower.includes('coupon') || urlLower.includes('promo') || urlLower.includes('discount')) {
    categories.push('coupon');
  }
  
  // Inventory contexts
  if (urlLower.includes('inventory') || urlLower.includes('stock') || urlLower.includes('product')) {
    categories.push('inventory', 'negative-value');
  }
  
  // User management contexts
  if (urlLower.includes('user') || urlLower.includes('account') || urlLower.includes('profile')) {
    categories.push('role', 'workflow');
  }
  
  if (urlLower.includes('admin') || urlLower.includes('permission')) {
    categories.push('role');
  }
  
  // Time-based contexts
  if (urlLower.includes('booking') || urlLower.includes('reservation') || urlLower.includes('schedule')) {
    categories.push('date-time');
  }
  
  if (urlLower.includes('subscription') || urlLower.includes('expiry')) {
    categories.push('date-time', 'workflow');
  }
  
  // Rate limiting contexts
  if (urlLower.includes('limit') || urlLower.includes('rate') || urlLower.includes('throttle')) {
    categories.push('rate-limit');
  }
  
  // Workflow contexts
  if (urlLower.includes('approval') || urlLower.includes('verification') || urlLower.includes('workflow')) {
    categories.push('workflow');
  }
  
  if (urlLower.includes('step') || urlLower.includes('stage') || urlLower.includes('process')) {
    categories.push('workflow');
  }
  
  return [...new Set(categories)];
}

/**
 * Build business logic test plan for an endpoint
 * @param {string} url - Endpoint URL
 * @param {string} method - HTTP method
 * @param {string} safetyTier - Safety tier
 * @returns {Object} Business logic test plan
 */
function buildBusinessLogicTestPlan(url, method, safetyTier = 'safe') {
  const relevantCategories = detectBusinessLogicContext(url, method);
  
  if (!relevantCategories.length) {
    return {
      applicable: false,
      categories: [],
      payloads: []
    };
  }
  
  const payloads = relevantCategories.flatMap(cat => 
    getBusinessLogicPayloads(cat, safetyTier)
  );
  
  return {
    applicable: true,
    categories: relevantCategories,
    payloads,
    test_objectives: [
      'Verify business rules are enforced server-side',
      'Check for client-trusted values that should be server-controlled',
      'Test boundary conditions and extreme values',
      'Validate workflow step enforcement'
    ]
  };
}

module.exports = {
  NEGATIVE_VALUE_PAYLOADS,
  PRICE_MANIPULATION_PAYLOADS,
  DATE_TIME_PAYLOADS,
  COUPON_PAYLOADS,
  RATE_LIMIT_PAYLOADS,
  INVENTORY_PAYLOADS,
  ROLE_MANIPULATION_PAYLOADS,
  WORKFLOW_PAYLOADS,
  getBusinessLogicPayloads,
  getAllBusinessLogicPayloads,
  detectBusinessLogicContext,
  buildBusinessLogicTestPlan
};
