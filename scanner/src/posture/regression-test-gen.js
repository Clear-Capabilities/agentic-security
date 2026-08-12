// Regression-test generator (FR-VER-3).
//
// For each finding that has a PoC (from P1.1 / poc-generator), emit a
// framework-idiomatic test file that:
//   - Fails on the vulnerable code state (asserts the exploit succeeds)
//   - Passes after the fix is applied (assert flips to "did not succeed")
//
// We piggy-back on the existing PoC template — the test wraps the same
// HTTP call but uses the framework's test runner (Jest / pytest / JUnit)
// for assertion + reporting.
//
// Output: `f.regression_test = { lang, framework, code, runHint, filename }`.
//
// Harness-engineering note (post-derived): generated code is parsed before
// emit. A test that doesn't even compile is worse than no test — it gives
// the agent the illusion of progress while shipping a broken artifact.
// JS/TS: @babel/parser. Python: heuristic indentation + paren-balance check
// (we can't run python3 from inside Node deterministically).

import { parse as babelParse } from '@babel/parser';

const FRAMEWORK_FOR_LANG = Object.freeze({
  node: 'jest',
  python: 'pytest',
  java: 'junit',
});

function _validateJs(code) {
  try {
    babelParse(code, { sourceType: 'module', allowAwaitOutsideFunction: false, errorRecovery: false });
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `parse-failed: ${e.message}` };
  }
}

function _validatePython(code) {
  // Best-effort balance check without a Python parser.
  // Catches the common breakage: an unescaped quote in the PoC payload
  // bleeding into the test source and unbalancing the assertion string.
  let parens = 0, brackets = 0, braces = 0;
  let inStr = false, q = '';
  for (let i = 0; i < code.length; i++) {
    const c = code[i];
    if (inStr) {
      if (c === '\\') { i++; continue; }
      if (c === q) inStr = false;
      continue;
    }
    if (c === '"' || c === "'") { inStr = true; q = c; continue; }
    if (c === '(') parens++;
    else if (c === ')') parens--;
    else if (c === '[') brackets++;
    else if (c === ']') brackets--;
    else if (c === '{') braces++;
    else if (c === '}') braces--;
  }
  if (parens || brackets || braces) {
    return { ok: false, reason: `parse-failed: unbalanced delimiters (parens=${parens} brackets=${brackets} braces=${braces})` };
  }
  if (inStr) {
    return { ok: false, reason: 'parse-failed: unterminated string literal' };
  }
  return { ok: true };
}

function _filenameFor(finding, lang) {
  const slug = (finding.stableId || finding.id || 'finding')
    .replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 40);
  if (lang === 'python') return `test_security_${slug}.py`;
  if (lang === 'java')   return `SecurityRegression_${slug}.java`;
  return `security_${slug}.test.mjs`;
}

function _renderJest(finding, poc) {
  // Wrap the PoC's HTTP call in a Jest test. The PoC's `process.exit(0)`
  // becomes `expect(...).toBe(true)`; exit(1) becomes `expect(...).toBe(false)`.
  const url = _extractUrl(poc.code) || 'http://localhost:3000';
  const method = _extractMethod(poc.code) || 'POST';
  const payloadLine = _extractPayloadLine(poc.code);
  return `// Regression test for ${finding.vuln} (${finding.cwe || 'unknown CWE'}).
// Auto-generated from P1.1 PoC; fails on vulnerable code, passes after the fix.

import { test, expect } from '@jest/globals';

test('${finding.vuln.replace(/'/g, "\\'")}', async () => {
  const URL_ = ${JSON.stringify(url)};
  const METHOD = ${JSON.stringify(method)};
  ${payloadLine}
  const body = METHOD === 'GET' ? null : JSON.stringify({ input: PAYLOAD });
  const reqUrl = METHOD === 'GET'
    ? URL_ + (URL_.includes('?') ? '&' : '?') + 'input=' + encodeURIComponent(PAYLOAD)
    : URL_;
  const r = await fetch(reqUrl, { method: METHOD, headers: { 'Content-Type': 'application/json' }, body });
  const text = await r.text();
  // The assertion below is the "exploit demonstrated" signal — when this
  // test PASSES, the vuln is still present. After the fix, this assertion
  // SHOULD fail. Inverse the assertion in a green build.
  const demonstrated = text.includes('PoC') || /syntax error/i.test(text) || text.includes('<script>');
  expect(demonstrated).toBe(false);
});
`;
}

function _renderPytest(finding, poc) {
  // Same finding-specific extraction _renderJest uses, not the hardcoded
  // SQL-injection payload every call used to emit regardless of the actual
  // vulnerability class. poc.code is assumed to follow this project's own
  // URL_/METHOD/PAYLOAD synthesis convention (poc-generator.js), same as
  // the JS PoCs this extraction already works against.
  const url = _extractUrl(poc.code) || 'http://localhost:3000';
  const method = (_extractMethod(poc.code) || 'POST').toLowerCase();
  const payload = _extractPayloadValue(poc.code) || 'PoC';
  return `# Regression test for ${finding.vuln} (${finding.cwe || 'unknown CWE'}).
# Auto-generated from P1.1 PoC; fails on vulnerable code, passes after the fix.

import requests


def test_${(finding.stableId || finding.id || 'finding').replace(/[^a-zA-Z0-9_]/g, '_').slice(0, 40)}():
    url = ${JSON.stringify(url)}
    payload = ${JSON.stringify(payload)}
    r = requests.${method}(url, json={'input': payload}) if ${JSON.stringify(method)} != 'get' \\
        else requests.get(url, params={'input': payload})
    # The assertion below is the "exploit demonstrated" signal — when this
    # test PASSES, the vuln is still present. After the fix, this assertion
    # SHOULD fail. Inverse the assertion in a green build.
    text = r.text
    demonstrated = 'PoC' in text or 'syntax error' in text.lower() or '<script>' in text
    assert not demonstrated, f'Vulnerability still present: {text[:200]}'
`;
}

function _extractUrl(code) {
  const m = String(code || '').match(/URL_ = (['"])([^'"]+)\1/);
  return m ? m[2] : null;
}
function _extractMethod(code) {
  const m = String(code || '').match(/METHOD = (['"])([A-Z]+)\1/);
  return m ? m[2] : null;
}
function _extractPayloadValue(code) {
  const m = String(code || '').match(/PAYLOAD = `([^`]+)`/);
  return m ? m[1] : null;
}
function _extractPayloadLine(code) {
  const v = _extractPayloadValue(code);
  return `const PAYLOAD = ${JSON.stringify(v || 'PoC')};`;
}

/**
 * Public API. Annotates findings with f.regression_test = {...} when a PoC
 * is available.
 */
export function annotateRegressionTests(findings) {
  if (!Array.isArray(findings)) return;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    if (!f.poc) { f.regression_test = null; continue; }
    // Harness-engineering note (post-derived): refuse to emit a runnable
    // regression test when the underlying PoC's parameter key was inferred
    // with low confidence. A test that posts to the wrong handler key
    // ALWAYS passes (because the exploit never demonstrates), giving the
    // illusion of "fix verified" — exactly the silent-failure mode the
    // post warns against. Surface the skip instead.
    if (f.poc.paramKeyConfidence === 'low') {
      f.regression_test = {
        lang: f.poc.lang,
        framework: null,
        filename: null,
        runHint: null,
        code: null,
        _skipped: 'poc-param-key-unverified',
        _explain: 'PoC param key inference was low-confidence (no `req.body.X` / `req.query.X` / form-key match found in the handler window). A regression test against the wrong key would always pass and would falsely suggest the fix landed.',
      };
      continue;
    }
    const lang = f.poc.lang;
    const framework = FRAMEWORK_FOR_LANG[lang];
    if (!framework) { f.regression_test = null; continue; }
    let code;
    try {
      code = framework === 'jest' ? _renderJest(f, f.poc)
           : framework === 'pytest' ? _renderPytest(f, f.poc)
           : null;
    } catch { code = null; }
    if (!code) { f.regression_test = null; continue; }
    // Parse the generated source before claiming it's a runnable test.
    const validation = framework === 'jest' ? _validateJs(code)
                     : framework === 'pytest' ? _validatePython(code)
                     : { ok: true };
    if (!validation.ok) {
      f.regression_test = {
        lang,
        framework,
        filename: _filenameFor(f, lang),
        runHint: null,
        code: null,
        _skipped: validation.reason,
        _explain: 'Generated test source did not parse cleanly. The test would have shipped as a broken artifact; reporting unverified instead.',
        _attemptedCode: code.length <= 4000 ? code : null,
      };
      continue;
    }
    f.regression_test = {
      lang,
      framework,
      filename: _filenameFor(f, lang),
      runHint: framework === 'jest' ? 'npx jest' : framework === 'pytest' ? 'pytest -q' : 'mvn test',
      code,
    };
  }
}

export const _internals = { FRAMEWORK_FOR_LANG };
