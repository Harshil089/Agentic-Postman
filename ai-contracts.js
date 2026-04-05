(function initAgentmanAiContracts(globalScope) {
  const ALLOWED_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
  const SECURITY_VECTORS = new Set([
    'IDOR',
    'SQLi',
    'NoSQLi',
    'AuthBypass',
    'SSRF',
    'XXE',
    'MassAssignment',
    'RateLimit',
    'PathTraversal',
    'BOLA',
    'InfoDisclosure',
    'CommandInjection',
    'ParameterPollution',
    'CachePoisoning',
    'UnrestrictedUpload',
    'BusinessLogic',
    'Unknown'
  ]);
  const SECURITY_THREAT_LEVELS = new Set(['none', 'low', 'medium', 'high', 'critical']);
  const SECURITY_FINDING_SEVERITIES = new Set(['info', 'low', 'medium', 'high', 'critical']);
  const SECURITY_SAFETY_TIERS = new Set(['safe', 'controlled-mutation', 'high-risk']);

  function isNonEmptyString(value) {
    return typeof value === 'string' && value.trim().length > 0;
  }

  function normalizeText(value) {
    return typeof value === 'string' ? value.trim() : '';
  }

  function normalizeKVEntries(entries, options = {}) {
    const {
      maxItems = 64,
      allowEmptyValue = true
    } = options;
    if (!Array.isArray(entries)) return [];
    return entries
      .filter(entry => entry && typeof entry === 'object' && typeof entry.k === 'string')
      .map(entry => ({
        k: normalizeText(entry.k),
        v: typeof entry.v === 'string' ? entry.v : ''
      }))
      .filter(entry => entry.k && (allowEmptyValue || entry.v))
      .slice(0, maxItems);
  }

  function normalizeParamDescriptor(raw, index = 0) {
    if (!raw || typeof raw !== 'object') return null;
    const location = ['path', 'query', 'header', 'body'].includes(raw.location) ? raw.location : 'query';
    const path = normalizeText(raw.path || raw.name);
    const name = normalizeText(raw.name || path.split('.').pop() || path);
    if (!name && !path) return null;
    const normalized = {
      name: name || `param_${index + 1}`,
      path: path || name,
      location,
      type: isNonEmptyString(raw.type) ? normalizeText(raw.type) : 'unknown',
      required: Boolean(raw.required),
      source: isNonEmptyString(raw.source) ? normalizeText(raw.source) : 'unknown'
    };
    if (raw.example !== undefined && raw.example !== null) normalized.example = raw.example;
    if (raw.default !== undefined && raw.default !== null) normalized.default = raw.default;
    if (Array.isArray(raw.enum) && raw.enum.length) normalized.enum = raw.enum.slice(0, 20);
    if (isNonEmptyString(raw.description)) normalized.description = raw.description.trim().slice(0, 240);
    return normalized;
  }

  function normalizeImportMeta(raw) {
    if (!raw || typeof raw !== 'object') return null;
    const source = normalizeText(raw.source);
    const descriptors = Array.isArray(raw.param_descriptors)
      ? raw.param_descriptors
        .map((entry, index) => normalizeParamDescriptor(entry, index))
        .filter(Boolean)
        .slice(0, 80)
      : [];
    const paramCandidates = Array.isArray(raw.param_candidates)
      ? raw.param_candidates
        .map(candidate => normalizeText(candidate))
        .filter(Boolean)
        .slice(0, 40)
      : [];
    const mergedCandidates = [...new Set([
      ...paramCandidates,
      ...descriptors.map(entry => entry.name).filter(Boolean)
    ])].slice(0, 40);
    if (!source && !descriptors.length && !mergedCandidates.length) return null;
    return {
      source,
      param_candidates: mergedCandidates,
      param_descriptors: descriptors
    };
  }

  function tokenizeAssertionExpression(expression) {
    const source = String(expression || '').trim();
    if (!source) throw new Error('Assertion expression is empty.');
    const tokens = [];
    let index = 0;

    const matchRegex = regex => {
      const match = regex.exec(source.slice(index));
      if (!match) return null;
      index += match[0].length;
      return match[0];
    };

    while (index < source.length) {
      if (matchRegex(/^\s+/)) continue;

      const operator = matchRegex(/^(===|!==|>=|<=|&&|\|\||[()![\].,<>=])/);
      if (operator) {
        tokens.push({ type: 'operator', value: operator });
        continue;
      }

      if (source[index] === ',') {
        tokens.push({ type: 'operator', value: ',' });
        index += 1;
        continue;
      }

      const numberToken = matchRegex(/^-?\d+(?:\.\d+)?/);
      if (numberToken) {
        tokens.push({ type: 'number', value: Number(numberToken) });
        continue;
      }

      if (source[index] === '\'' || source[index] === '"') {
        const quote = source[index];
        let end = index + 1;
        let value = '';
        while (end < source.length) {
          const char = source[end];
          if (char === '\\') {
            if (end + 1 >= source.length) throw new Error('Invalid string escape.');
            value += source[end + 1];
            end += 2;
            continue;
          }
          if (char === quote) break;
          value += char;
          end += 1;
        }
        if (end >= source.length || source[end] !== quote) throw new Error('Unterminated string literal.');
        tokens.push({ type: 'string', value });
        index = end + 1;
        continue;
      }

      const identifier = matchRegex(/^[A-Za-z_$][A-Za-z0-9_$]*/);
      if (identifier) {
        tokens.push({ type: 'identifier', value: identifier });
        continue;
      }

      throw new Error(`Unexpected token near "${source.slice(index, index + 12)}".`);
    }

    return tokens;
  }

  function parseAssertionExpression(expression) {
    const tokens = tokenizeAssertionExpression(expression);
    let index = 0;

    function peek() {
      return tokens[index];
    }

    function consume(expectedValue) {
      const token = tokens[index];
      if (!token) throw new Error('Unexpected end of expression.');
      if (expectedValue && token.value !== expectedValue) {
        throw new Error(`Expected "${expectedValue}" but found "${token.value}".`);
      }
      index += 1;
      return token;
    }

    function parsePrimary() {
      const token = peek();
      if (!token) throw new Error('Unexpected end of expression.');

      if (token.type === 'number' || token.type === 'string') {
        index += 1;
        return { type: 'literal', value: token.value };
      }

      if (token.type === 'identifier') {
        if (token.value === 'true' || token.value === 'false') {
          index += 1;
          return { type: 'literal', value: token.value === 'true' };
        }
        if (token.value === 'null') {
          index += 1;
          return { type: 'literal', value: null };
        }
        index += 1;
        return { type: 'identifier', name: token.value };
      }

      if (token.value === '(') {
        consume('(');
        const expr = parseLogicalOr();
        consume(')');
        return expr;
      }

      throw new Error(`Unexpected token: ${token.value}`);
    }

    function parsePostfix() {
      let expr = parsePrimary();

      while (true) {
        const token = peek();
        if (!token) break;

        if (token.value === '.') {
          consume('.');
          const property = consume();
          if (property.type !== 'identifier') throw new Error('Expected property name.');
          expr = {
            type: 'member',
            object: expr,
            property: { type: 'literal', value: property.value },
            computed: false
          };
          continue;
        }

        if (token.value === '[') {
          consume('[');
          const property = parseLogicalOr();
          consume(']');
          expr = { type: 'member', object: expr, property, computed: true };
          continue;
        }

        if (token.value === '(') {
          consume('(');
          const args = [];
          if (peek() && peek().value !== ')') {
            while (true) {
              args.push(parseLogicalOr());
              if (!peek() || peek().value !== ',') break;
              consume(',');
            }
          }
          consume(')');
          expr = { type: 'call', callee: expr, args };
          continue;
        }

        break;
      }

      return expr;
    }

    function parseUnary() {
      const token = peek();
      if (token && token.type === 'identifier' && token.value === 'typeof') {
        consume();
        return { type: 'unary', operator: 'typeof', argument: parseUnary() };
      }
      if (token && token.value === '!') {
        consume('!');
        return { type: 'unary', operator: '!', argument: parseUnary() };
      }
      return parsePostfix();
    }

    function parseComparison() {
      let expr = parseUnary();
      while (peek() && ['>', '<', '>=', '<='].includes(peek().value)) {
        const operator = consume().value;
        expr = { type: 'binary', operator, left: expr, right: parseUnary() };
      }
      return expr;
    }

    function parseEquality() {
      let expr = parseComparison();
      while (peek() && ['===', '!=='].includes(peek().value)) {
        const operator = consume().value;
        expr = { type: 'binary', operator, left: expr, right: parseComparison() };
      }
      return expr;
    }

    function parseLogicalAnd() {
      let expr = parseEquality();
      while (peek() && peek().value === '&&') {
        consume('&&');
        expr = { type: 'logical', operator: '&&', left: expr, right: parseEquality() };
      }
      return expr;
    }

    function parseLogicalOr() {
      let expr = parseLogicalAnd();
      while (peek() && peek().value === '||') {
        consume('||');
        expr = { type: 'logical', operator: '||', left: expr, right: parseLogicalAnd() };
      }
      return expr;
    }

    const parsed = parseLogicalOr();
    if (index !== tokens.length) {
      throw new Error(`Unexpected token: ${tokens[index].value}`);
    }
    return parsed;
  }

  function evaluateAssertionAst(node, scope) {
    if (node.type === 'literal') return node.value;

    if (node.type === 'identifier') {
      if (!Object.prototype.hasOwnProperty.call(scope, node.name)) {
        throw new Error(`Identifier not allowed: ${node.name}`);
      }
      return scope[node.name];
    }

    if (node.type === 'unary') {
      const value = evaluateAssertionAst(node.argument, scope);
      if (node.operator === '!') return !value;
      if (node.operator === 'typeof') return typeof value;
      throw new Error(`Unary operator not allowed: ${node.operator}`);
    }

    if (node.type === 'member') {
      const object = evaluateAssertionAst(node.object, scope);
      const property = node.computed ? evaluateAssertionAst(node.property, scope) : node.property.value;
      if (object == null) return undefined;
      return object[property];
    }

    if (node.type === 'binary') {
      const left = evaluateAssertionAst(node.left, scope);
      const right = evaluateAssertionAst(node.right, scope);
      switch (node.operator) {
        case '===': return left === right;
        case '!==': return left !== right;
        case '>': return left > right;
        case '<': return left < right;
        case '>=': return left >= right;
        case '<=': return left <= right;
        default: throw new Error(`Binary operator not allowed: ${node.operator}`);
      }
    }

    if (node.type === 'logical') {
      if (node.operator === '&&') return evaluateAssertionAst(node.left, scope) && evaluateAssertionAst(node.right, scope);
      if (node.operator === '||') return evaluateAssertionAst(node.left, scope) || evaluateAssertionAst(node.right, scope);
      throw new Error(`Logical operator not allowed: ${node.operator}`);
    }

    if (node.type === 'call') {
      if (
        node.callee.type === 'member'
        && node.callee.object.type === 'identifier'
        && node.callee.object.name === 'Array'
        && node.callee.property.value === 'isArray'
      ) {
        const args = node.args.map(arg => evaluateAssertionAst(arg, scope));
        return Array.isArray(args[0]);
      }

      if (node.callee.type === 'member') {
        const target = evaluateAssertionAst(node.callee.object, scope);
        const property = node.callee.computed ? evaluateAssertionAst(node.callee.property, scope) : node.callee.property.value;
        const args = node.args.map(arg => evaluateAssertionAst(arg, scope));

        if (property === 'includes' && (typeof target === 'string' || Array.isArray(target))) {
          return target.includes(args[0]);
        }
        if (property === 'startsWith' && typeof target === 'string') {
          return target.startsWith(args[0]);
        }
        if (property === 'endsWith' && typeof target === 'string') {
          return target.endsWith(args[0]);
        }
        if (property === 'hasOwnProperty' && target && typeof target === 'object') {
          return Object.prototype.hasOwnProperty.call(target, args[0]);
        }
        throw new Error(`Method not allowed: ${property}`);
      }

      throw new Error('Function call not allowed.');
    }

    throw new Error(`Expression node not supported: ${node.type}`);
  }

  function evaluateAssertionExpression(expression, scope) {
    return evaluateAssertionAst(parseAssertionExpression(expression), scope);
  }

  function collectAssertionMetadata(expression) {
    const ast = parseAssertionExpression(expression);
    const metadata = {
      expression: String(expression || ''),
      references: [],
      identifiers: new Set(),
      methods: new Set(),
      operators: new Set(),
      categories: new Set()
    };

    function extractPath(node) {
      if (!node) return null;
      if (node.type === 'identifier') return { root: node.name, path: node.name };
      if (node.type === 'member') {
        const base = extractPath(node.object);
        if (!base) return null;
        const segment = node.computed
          ? (node.property.type === 'literal' ? String(node.property.value) : null)
          : String(node.property.value);
        if (segment == null) return null;
        return {
          root: base.root,
          path: `${base.path}.${segment}`
        };
      }
      return null;
    }

    function walk(node) {
      if (!node || typeof node !== 'object') return;
      if (node.type === 'identifier') {
        metadata.identifiers.add(node.name);
        if (['status', 'body', 'json', 'elapsed', 'elapsed_ms'].includes(node.name)) {
          metadata.categories.add(node.name === 'status' ? 'status' : node.name.startsWith('elapsed') ? 'timing' : 'content');
        }
        return;
      }

      if (node.type === 'member') {
        const reference = extractPath(node);
        if (reference && reference.root === 'json') {
          metadata.references.push(reference.path.replace(/^json\./, ''));
          metadata.categories.add('field');
        }
        walk(node.object);
        walk(node.property);
        return;
      }

      if (node.type === 'call') {
        if (node.callee.type === 'member') {
          const methodName = node.callee.computed ? null : node.callee.property.value;
          if (methodName) metadata.methods.add(methodName);
          if (methodName === 'includes' || methodName === 'startsWith' || methodName === 'endsWith') {
            metadata.categories.add('negative');
          }
          if (methodName === 'hasOwnProperty') {
            metadata.categories.add('shape');
            const targetPath = extractPath(node.callee.object);
            if (targetPath && targetPath.root === 'json') {
              const firstArg = node.args[0];
              if (firstArg && firstArg.type === 'literal' && typeof firstArg.value === 'string') {
                metadata.references.push(`${targetPath.path.replace(/^json\.?/, '')}.${firstArg.value}`.replace(/^\./, ''));
              }
            }
          }
        }
        walk(node.callee);
        node.args.forEach(walk);
        return;
      }

      if (node.operator) metadata.operators.add(node.operator);
      if (node.left) walk(node.left);
      if (node.right) walk(node.right);
      if (node.argument) walk(node.argument);
    }

    walk(ast);
    if (metadata.identifiers.has('status')) metadata.categories.add('status');
    if (metadata.identifiers.has('json') || metadata.references.length) metadata.categories.add('shape');
    if (metadata.identifiers.has('body')) metadata.categories.add('negative');
    if (metadata.identifiers.has('elapsed') || metadata.identifiers.has('elapsed_ms')) metadata.categories.add('timing');
    return {
      ast,
      references: metadata.references.filter(Boolean),
      identifiers: [...metadata.identifiers],
      methods: [...metadata.methods],
      operators: [...metadata.operators],
      categories: [...metadata.categories]
    };
  }

  function normalizeAssertionExpressions(assertions, options = {}) {
    const { maxItems = 12 } = options;
    if (!Array.isArray(assertions)) return [];
    const seen = new Set();
    const normalized = [];
    assertions.forEach(entry => {
      if (!isNonEmptyString(entry)) return;
      const expr = entry.trim();
      const dedupeKey = expr.replace(/\s+/g, ' ');
      if (seen.has(dedupeKey)) return;
      seen.add(dedupeKey);
      normalized.push(expr);
    });
    return normalized.slice(0, maxItems);
  }

  function validateUrlLike(value) {
    return isNonEmptyString(value);
  }

  function hasChainTemplate(action) {
    const textParts = [
      action.url,
      action.body,
      ...(Array.isArray(action.params) ? action.params.map(entry => `${entry.k}:${entry.v}`) : []),
      ...(Array.isArray(action.headers) ? action.headers.map(entry => `${entry.k}:${entry.v}`) : [])
    ].filter(Boolean);
    return textParts.some(text => String(text).includes('{{json.'));
  }

  function validateAgentAction(action, index = 0) {
    if (!action || typeof action !== 'object') {
      return { error: `actions[${index}] must be an object.` };
    }

    const type = normalizeText(action.type);
    if (!type) {
      return { error: `actions[${index}].type must be a non-empty string.` };
    }

    if (type === 'set_request') {
      const method = String(action.method || '').toUpperCase();
      if (!ALLOWED_METHODS.has(method)) return { error: `actions[${index}] invalid method.` };
      if (!validateUrlLike(action.url)) return { error: `actions[${index}] missing url.` };
      return {
        value: {
          type,
          name: isNonEmptyString(action.name) ? action.name.trim() : 'Generated Request',
          method,
          url: String(action.url).trim(),
          params: normalizeKVEntries(action.params),
          headers: normalizeKVEntries(action.headers),
          body: typeof action.body === 'string' ? action.body : ''
        }
      };
    }

    if (type === 'set_assertions') {
      const assertions = normalizeAssertionExpressions(action.assertions);
      if (!assertions.length) return { error: `actions[${index}] has no valid assertions.` };
      return { value: { type, assertions } };
    }

    if (type === 'chain_request') {
      const method = String(action.method || '').toUpperCase();
      if (!ALLOWED_METHODS.has(method)) return { error: `actions[${index}] invalid method.` };
      if (!validateUrlLike(action.url) || !isNonEmptyString(action.name)) {
        return { error: `actions[${index}] missing name/url.` };
      }
      const value = {
        type,
        name: action.name.trim(),
        method,
        url: String(action.url).trim(),
        params: normalizeKVEntries(action.params),
        headers: normalizeKVEntries(action.headers),
        body: typeof action.body === 'string' ? action.body : '',
        chainNote: typeof action.chainNote === 'string' ? action.chainNote : ''
      };
      if (!hasChainTemplate(value)) {
        return { error: `actions[${index}] chain_request requires a {{json.*}} template.` };
      }
      return { value };
    }

    if (type === 'debug_info') {
      const findings = Array.isArray(action.findings)
        ? action.findings.filter(isNonEmptyString).map(entry => entry.trim()).slice(0, 12)
        : [];
      if (!findings.length) return { error: `actions[${index}] has no valid findings.` };
      return {
        value: {
          type,
          findings,
          fix: typeof action.fix === 'string' ? action.fix : '',
          patch: action.patch && typeof action.patch === 'object' ? action.patch : undefined
        }
      };
    }

    return { error: `actions[${index}] unsupported type: ${type}.` };
  }

  function normalizeAgentActionsStrict(actions) {
    const source = Array.isArray(actions) ? actions : [];
    const normalized = [];
    const invalidIndexes = [];
    const errors = [];
    source.forEach((action, index) => {
      const result = validateAgentAction(action, index);
      if (result.error) {
        invalidIndexes.push(index);
        errors.push(result.error);
      } else {
        normalized.push(result.value);
      }
    });
    return { normalized, invalidIndexes, invalidCount: invalidIndexes.length, errors };
  }

  function normalizeSecurityFinding(raw, index = 0) {
    if (!raw || typeof raw !== 'object') return null;
    if (!SECURITY_FINDING_SEVERITIES.has(raw.severity)) return null;
    const confidence = Number(raw.confidence);
    return {
      id: isNonEmptyString(raw.id) ? raw.id.trim() : `FINDING-${String(index + 1).padStart(3, '0')}`,
      vulnerability: isNonEmptyString(raw.vulnerability) ? raw.vulnerability.trim() : 'Unknown',
      severity: raw.severity,
      evidence: typeof raw.evidence === 'string' ? raw.evidence : '',
      evidence_delta: typeof raw.evidence_delta === 'string' ? raw.evidence_delta : '',
      confidence: Number.isFinite(confidence) ? Math.max(0, Math.min(1, confidence)) : 0.5,
      cve_hint: typeof raw.cve_hint === 'string' || raw.cve_hint === null ? raw.cve_hint : null,
      owasp_api_label: isNonEmptyString(raw.owasp_api_label) ? raw.owasp_api_label.trim() : null,
      remediation: typeof raw.remediation === 'string' ? raw.remediation : ''
    };
  }

  function validateSecurityAction(action, index = 0) {
    if (!action || typeof action !== 'object') {
      return { error: `actions[${index}] must be an object.` };
    }

    const type = normalizeText(action.type);
    if (!type) return { error: `actions[${index}].type must be a non-empty string.` };

    if (type === 'probe') {
      const method = String(action.method || '').toUpperCase();
      if (!ALLOWED_METHODS.has(method) || !validateUrlLike(action.url)) {
        return { error: `actions[${index}] invalid probe method/url.` };
      }
      const vector = isNonEmptyString(action.vector) ? action.vector.trim() : 'Unknown';
      if (!SECURITY_VECTORS.has(vector)) return { error: `actions[${index}] invalid probe vector.` };
      return {
        value: {
          type,
          name: isNonEmptyString(action.name) ? action.name.trim() : 'Security probe',
          method,
          url: String(action.url).trim(),
          headers: normalizeKVEntries(action.headers),
          params: normalizeKVEntries(action.params),
          body: typeof action.body === 'string' ? action.body : '',
          vector,
          safety_tier: SECURITY_SAFETY_TIERS.has(String(action.safety_tier || '').trim())
            ? String(action.safety_tier).trim()
            : 'safe',
          hypothesis: typeof action.hypothesis === 'string' ? action.hypothesis : '',
          auto_chain: Boolean(action.auto_chain)
        }
      };
    }

    if (type === 'probe_chain') {
      const steps = Array.isArray(action.steps) ? action.steps : [];
      if (!steps.length) return { error: `actions[${index}] probe_chain requires steps.` };
      const normalizedSteps = [];
      for (let stepIndex = 0; stepIndex < steps.length; stepIndex += 1) {
        const step = steps[stepIndex];
        const method = String(step?.method || '').toUpperCase();
        const vector = isNonEmptyString(step?.vector) ? step.vector.trim() : 'Unknown';
        if (!ALLOWED_METHODS.has(method) || !validateUrlLike(step?.url)) {
          return { error: `actions[${index}].steps[${stepIndex}] invalid method/url.` };
        }
        if (!SECURITY_VECTORS.has(vector)) {
          return { error: `actions[${index}].steps[${stepIndex}] invalid vector.` };
        }
        normalizedSteps.push({
          step: Number(step.step || stepIndex + 1),
          name: isNonEmptyString(step.name) ? step.name.trim() : `Step ${stepIndex + 1}`,
          method,
          url: String(step.url).trim(),
          headers: normalizeKVEntries(step.headers),
          body: typeof step.body === 'string' ? step.body : '',
          vector,
          hypothesis: typeof step.hypothesis === 'string' ? step.hypothesis : '',
          extract: step.extract && typeof step.extract === 'object' ? step.extract : undefined
        });
      }
      return {
        value: {
          type,
          name: isNonEmptyString(action.name) ? action.name.trim() : 'Security probe chain',
          steps: normalizedSteps
        }
      };
    }

    if (type === 'fuzz_list') {
      const payloads = normalizeAssertionExpressions(action.payloads, { maxItems: 24 });
      if (!payloads.length) return { error: `actions[${index}] fuzz_list requires payloads.` };
      const vector = isNonEmptyString(action.vector) ? action.vector.trim() : 'Unknown';
      if (!SECURITY_VECTORS.has(vector)) return { error: `actions[${index}] invalid fuzz vector.` };
      const targetLocation = ['url', 'body', 'header', 'query', 'path'].includes(String(action.target_location))
        ? String(action.target_location)
        : 'query';
      if (!isNonEmptyString(action.target_param)) return { error: `actions[${index}] fuzz_list requires target_param.` };
      return {
        value: {
          type,
          vector,
          target_param: action.target_param.trim(),
          target_location: targetLocation,
          payloads,
          success_indicators: action.success_indicators && typeof action.success_indicators === 'object'
            ? action.success_indicators
            : {}
        }
      };
    }

    if (type === 'scan_plan') {
      const rawSteps = Array.isArray(action.steps) ? action.steps : [];
      if (!rawSteps.length) return { error: `actions[${index}] scan_plan requires steps.` };
      const steps = rawSteps.map((step, stepIndex) => ({
        order: Number(step?.order || stepIndex + 1),
        vector: isNonEmptyString(step?.vector) && SECURITY_VECTORS.has(step.vector.trim()) ? step.vector.trim() : 'Unknown',
        description: typeof step?.description === 'string' ? step.description : '',
        target_param: typeof step?.target_param === 'string' ? step.target_param : '',
        owasp_api_label: typeof step?.owasp_api_label === 'string' ? step.owasp_api_label : ''
      }));
      const paramMatrix = Array.isArray(action.param_matrix)
        ? action.param_matrix
          .map((entry, entryIndex) => normalizeParamDescriptor({
            ...(entry || {}),
            location: ['query', 'body', 'header', 'path'].includes(String(entry?.location)) ? String(entry.location) : 'query',
            source: entry?.source || 'scan_plan'
          }, entryIndex))
          .filter(Boolean)
        : [];
      return {
        value: {
          type,
          target: typeof action.target === 'string' ? action.target : '',
          method_coverage: Array.isArray(action.method_coverage)
            ? action.method_coverage.map(method => String(method).toUpperCase()).filter(method => ALLOWED_METHODS.has(method))
            : [],
          steps,
          param_matrix: paramMatrix
        }
      };
    }

    if (type === 'set_assertions') {
      const assertions = normalizeAssertionExpressions(action.assertions);
      if (!assertions.length) return { error: `actions[${index}] has no valid assertions.` };
      return { value: { type, assertions } };
    }

    if (type === 'debug_info') {
      return validateAgentAction(action, index);
    }

    return { error: `actions[${index}] unsupported type: ${type}.` };
  }

  function normalizeSecurityActionsStrict(actions) {
    const source = Array.isArray(actions) ? actions : [];
    const normalized = [];
    const invalidIndexes = [];
    const errors = [];
    source.forEach((action, index) => {
      const result = validateSecurityAction(action, index);
      if (result.error) {
        invalidIndexes.push(index);
        errors.push(result.error);
      } else {
        normalized.push(result.value);
      }
    });
    return { normalized, invalidIndexes, invalidCount: invalidIndexes.length, errors };
  }

  const api = {
    ALLOWED_METHODS,
    SECURITY_THREAT_LEVELS,
    SECURITY_FINDING_SEVERITIES,
    SECURITY_VECTORS,
    isNonEmptyString,
    normalizeKVEntries,
    normalizeParamDescriptor,
    normalizeImportMeta,
    tokenizeAssertionExpression,
    parseAssertionExpression,
    evaluateAssertionExpression,
    collectAssertionMetadata,
    normalizeAssertionExpressions,
    validateAgentAction,
    normalizeAgentActionsStrict,
    validateSecurityAction,
    normalizeSecurityActionsStrict,
    normalizeSecurityFinding
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  if (globalScope) {
    globalScope.AgentmanAiContracts = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
