// Polyglot embedded-language taint (P4.7).
//
// Strings embedded inside one language often carry a second language that
// has its own sinks. The classic example: a SQL string literal inside Java
// is technically just a String to Java, but it's a SQL statement to the DB.
// If a tainted value is concatenated into it BEFORE handing to .executeQuery,
// it's a SQL injection — even if no obvious sink shape is matched.
//
// Embeddings we recognize:
//   - SQL          inside Java / C# / Python / Go / Node strings
//   - HTML         inside JS template literals + .innerHTML/.outerHTML lhs
//   - JavaScript   inside HTML <script>, inline `on*` attrs, javascript: URIs
//   - Shell        inside .exec/.execSync/.spawn strings (existing sink)
//   - Regex        inside .new RegExp(<concat>) — REDoS surface
//   - CSS          inside style="..." HTML attrs, .style.cssText assignments
//   - JSON-as-code inside eval/Function constructors
//   - LDAP         inside .search(filter:) calls
//   - XPath        inside .evaluate(expr:) calls
//   - Mongo $where inside aggregate / find expressions
//   - JNDI         inside lookup() / context.lookup() strings (Log4Shell shape)
//
// This module's job is to RECOGNIZE the embedded language inside a string
// expression and tell the engine "this string is actually X — apply X's
// sink rules to any concatenation/template-hole inside it." It does NOT
// re-parse the embedded grammar; the heuristic is shape-based, with a
// confidence score so the engine can demote weak matches.
//
// Public API:
//   identifyEmbedding(strValue)       → { lang, confidence, evidence }
//   findInterpolationHoles(strNode)   → [{ index, expr }] for template literals
//   shouldFlagPolyglot(lang, holeExpr, holeTainted)
//                                     → boolean — should we emit a finding?

/** SQL recognition — keyword + structure. */
const SQL_KEYWORDS = /\b(SELECT|INSERT|UPDATE|DELETE|UPSERT|MERGE|CREATE|DROP|ALTER|TRUNCATE|GRANT|REVOKE)\b/i;
const SQL_CLAUSE   = /\b(FROM|WHERE|JOIN|UNION|ORDER\s+BY|GROUP\s+BY|HAVING|LIMIT|OFFSET|INTO|SET|VALUES)\b/i;

/** HTML recognition. */
const HTML_TAG     = /<\/?\s*[a-zA-Z][a-zA-Z0-9-]*(\s[^>]*)?>/;
const HTML_ENTITY  = /&(?:lt|gt|amp|quot|apos|nbsp|#\d+);/;

/** JS recognition (inside HTML or eval). */
const JS_KEYWORDS  = /\b(function|var|let|const|return|new\s+\w+|console\.|document\.|window\.|=>)\b/;

/** Shell — common command words at start, after whitespace. */
const SHELL_CMD    = /(^|;|\|\||&&|\|)\s*(cat|ls|rm|cp|mv|chmod|chown|curl|wget|bash|sh|sudo|tar|grep|sed|awk|find|kill|ps|netstat|ip|iptables|nc|ssh|scp)\b/;

/** LDAP filter shape. */
const LDAP_FILTER  = /\(\s*[a-zA-Z]+\s*=\s*[^)]+\)/;

/** XPath shape. */
const XPATH_SHAPE  = /\/\/?[a-zA-Z*][a-zA-Z0-9_-]*(\[.*?\])?(\/|$)/;

/** JNDI / JNDI lookup pattern. */
const JNDI_PATTERN = /\$\{(jndi|ldap|rmi|dns):/i;

/** Mongo $where as JS expression. */
const MONGO_WHERE  = /this\.\w+\s*[=<>!]/;

/** CSS — property:value pairs. */
const CSS_PROP     = /^[^{}]*\{?\s*[a-zA-Z-]+\s*:\s*[^;]+;?/;

/**
 * Identify the embedded language of a string value (the literal text of
 * a string literal or the concatenation skeleton of a template). Returns
 * { lang, confidence: 0..1, evidence: [matchedPattern, ...] }.
 *
 * lang values:
 *   'sql' | 'html' | 'js' | 'shell' | 'ldap' | 'xpath' | 'jndi' |
 *   'mongo' | 'css' | 'regex' | 'none'
 */
export function identifyEmbedding(strValue) {
  if (typeof strValue !== 'string' || !strValue) return { lang: 'none', confidence: 0, evidence: [] };
  const s = strValue;
  const evidence = [];
  let lang = 'none';
  let confidence = 0;

  // JNDI first — single pattern, very high signal.
  if (JNDI_PATTERN.test(s)) {
    return { lang: 'jndi', confidence: 1.0, evidence: ['jndi:lookup pattern'] };
  }

  if (SQL_KEYWORDS.test(s) && SQL_CLAUSE.test(s)) {
    evidence.push('sql-keyword+clause');
    return { lang: 'sql', confidence: 0.95, evidence };
  }
  if (SQL_KEYWORDS.test(s)) {
    evidence.push('sql-keyword');
    confidence = 0.6; lang = 'sql';
  }

  if (HTML_TAG.test(s) && (HTML_ENTITY.test(s) || s.includes('</'))) {
    return { lang: 'html', confidence: 0.9, evidence: ['html-tag+entity/closer'] };
  }
  if (HTML_TAG.test(s) && lang === 'none') {
    evidence.push('html-tag');
    lang = 'html'; confidence = 0.6;
  }

  if (lang === 'html' && JS_KEYWORDS.test(s) && /<script\b/i.test(s)) {
    // HTML embedding JS — call it HTML (the host); but flag js-in-html
    // separately via shouldFlagPolyglot.
    evidence.push('script-block');
    confidence = Math.max(confidence, 0.85);
  }

  if (SHELL_CMD.test(s)) {
    return { lang: 'shell', confidence: 0.7, evidence: ['shell-builtin'] };
  }
  if (LDAP_FILTER.test(s) && /\(\|/.test(s)) {
    return { lang: 'ldap', confidence: 0.85, evidence: ['ldap-filter+or'] };
  }
  if (LDAP_FILTER.test(s) && lang === 'none') {
    evidence.push('ldap-filter');
    lang = 'ldap'; confidence = 0.5;
  }
  if (XPATH_SHAPE.test(s) && lang === 'none') {
    evidence.push('xpath-shape');
    lang = 'xpath'; confidence = 0.6;
  }
  if (MONGO_WHERE.test(s) && lang === 'none') {
    return { lang: 'mongo', confidence: 0.7, evidence: ['mongo-where'] };
  }
  if (CSS_PROP.test(s) && /[a-z-]+:[^;]+;/.test(s) && lang === 'none') {
    evidence.push('css-prop');
    lang = 'css'; confidence = 0.45;
  }
  return { lang, confidence, evidence };
}

/**
 * For a template literal AST node, return the array of interpolation holes
 * with their `index` (position among quasis) and `expr` (AST subtree).
 *
 * Expected shape: { kind: 'template', quasis: [string,...], expressions: [expr,...] }
 */
export function findInterpolationHoles(strNode) {
  if (!strNode || strNode.kind !== 'template') return [];
  const exprs = strNode.expressions || [];
  return exprs.map((e, i) => ({ index: i, expr: e }));
}

/** Stitch a template literal into its skeleton string (placeholders blanked). */
export function templateSkeleton(strNode) {
  if (!strNode || strNode.kind !== 'template') {
    if (strNode && strNode.kind === 'literal' && typeof strNode.value === 'string') return strNode.value;
    return '';
  }
  const qs = strNode.quasis || [];
  // Stitch with a sentinel that won't confuse the recognizers.
  return qs.join(' __HOLE__ ');
}

/**
 * Decide whether an interpolation hole in an embedded-language string
 * should fire a polyglot finding. The engine calls this after identifying
 * the host string and checking which holes are tainted.
 */
export function shouldFlagPolyglot(lang, hole, holeTainted, opts = {}) {
  if (!holeTainted) return false;
  if (!lang || lang === 'none') return false;
  // Some embeddings are always sensitive when tainted.
  const sensitive = new Set(['sql', 'shell', 'jndi', 'ldap', 'xpath', 'mongo', 'js']);
  if (sensitive.has(lang)) return true;
  // For HTML, only flag if the hole appears in an attribute or script context.
  // We don't have positional info here; defer to engine context.
  if (lang === 'html') return !!opts.inAttribute || !!opts.inScript;
  if (lang === 'css')  return !!opts.inExpression || !!opts.inUrlFn;
  return true;
}

/**
 * Map a recognized embedded language to a finding family / CWE for emission.
 */
export function embeddingToCwe(lang) {
  switch (lang) {
    case 'sql':   return { family: 'sql-injection',        cwe: 'CWE-89'  };
    case 'shell': return { family: 'command-injection',    cwe: 'CWE-78'  };
    case 'html':  return { family: 'xss',                  cwe: 'CWE-79'  };
    case 'js':    return { family: 'xss-script',           cwe: 'CWE-79'  };
    case 'ldap':  return { family: 'ldap-injection',       cwe: 'CWE-90'  };
    case 'xpath': return { family: 'xpath-injection',      cwe: 'CWE-643' };
    case 'mongo': return { family: 'nosql-injection',      cwe: 'CWE-943' };
    case 'jndi':  return { family: 'jndi-injection',       cwe: 'CWE-1188'};
    case 'css':   return { family: 'css-injection',        cwe: 'CWE-79'  };
    case 'regex': return { family: 'redos',                cwe: 'CWE-1333'};
    default:      return null;
  }
}
