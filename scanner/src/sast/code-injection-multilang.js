// Cross-language code-injection detector (CWE-94) — Java / C# / Go / Kotlin.
//
// The JS/Python/Ruby eval-family sinks are covered by the flow engine + the
// per-language modules. The compiled second-tier languages had no CWE-94
// coverage at all. This module flags the canonical dynamic-code-execution
// sinks in those languages when the evaluated argument is NON-LITERAL (a
// variable or expression) — a literal `eval("1+1")` is not injection.
//
// Sinks covered:
//   Java/Kotlin (JVM):
//     - javax.script ScriptEngine.eval(<expr>)
//     - GroovyShell().evaluate(<expr>) / GroovyShell.parse
//     - Spring SpEL: (Spel)ExpressionParser().parseExpression(<expr>)
//     - MVEL.eval / OGNL: Ognl.getValue / OgnlUtil
//   C#:
//     - Roslyn: CSharpScript.EvaluateAsync/RunAsync(<expr>)
//     - DataTable().Compute(<expr>, …)  (expression evaluator → injection)
//   Go:
//     - yaegi/gomacro interpreter: interp.Eval(<expr>)
//     - text/template|html/template Parse(<expr>) of a NON-LITERAL template
//       (user-controlled template body → action/code execution)
//
// Precision: the matched argument must not be a string literal. Escaped/safe
// constructs (a literal template, a constant expression) don't match.

import { blankComments } from './_comment-strip.js';

const lineOf = (raw, idx) => raw.substring(0, idx).split('\n').length;

// A non-literal argument: an identifier / member / call expression — i.e. NOT
// a bare string/char/number literal as the whole argument. Used as a trailing
// assertion `(?!\s*STRING\s*\))` after the opening paren.
const STR_LIT = String.raw`(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|@?"[^"]*")`;

const REMEDIATION =
  'Never evaluate runtime-built code. Replace the dynamic evaluator with an explicit ' +
  'dispatch table / allow-list of operations, a sandboxed expression library with no ' +
  'I/O and a fixed grammar, or precompiled templates whose body is never user-controlled. ' +
  'For Spring SpEL use a SimpleEvaluationContext (no type/bean access); for Go templates ' +
  'keep the template body static and pass values as data, never Parse user input.';

// Per-language sink patterns. Each is built so the argument is captured and a
// negative lookahead rejects a pure string-literal argument.
function patternsFor(lang) {
  // `(?!\s*<str>\s*[),])` — reject when the FIRST argument is a bare literal.
  const notLiteral = String.raw`(?!\s*${STR_LIT}\s*[),])`;
  if (lang === 'java' || lang === 'kt') {
    return [
      // ScriptEngine.eval(expr) — but not eval(reader) literal; require non-literal.
      { key: 'script-eval', re: new RegExp(String.raw`\.\s*eval\s*\(\s*${notLiteral}`, 'g'),
        gate: /\b(?:ScriptEngine|ScriptEngineManager|getEngineByName|javax\.script|NashornScriptEngine)\b/ },
      { key: 'groovy', re: new RegExp(String.raw`\bGroovyShell\s*\([^)]*\)\s*\.\s*(?:evaluate|parse)\s*\(\s*${notLiteral}`, 'g') },
      { key: 'groovy2', re: new RegExp(String.raw`\b(?:GroovyShell|GroovyClassLoader)\b[\s\S]{0,120}?\.\s*(?:evaluate|parse|parseClass)\s*\(\s*${notLiteral}`, 'g') },
      { key: 'spel', re: new RegExp(String.raw`\bparseExpression\s*\(\s*${notLiteral}`, 'g'),
        gate: /\b(?:SpelExpressionParser|ExpressionParser|org\.springframework\.expression)\b/ },
      { key: 'mvel', re: new RegExp(String.raw`\bMVEL\s*\.\s*(?:eval|evalToString|compileExpression|executeExpression)\s*\(\s*${notLiteral}`, 'g') },
      { key: 'ognl', re: new RegExp(String.raw`\bOgnl\s*\.\s*(?:getValue|setValue|parseExpression)\s*\(\s*${notLiteral}`, 'g') },
    ];
  }
  if (lang === 'cs') {
    return [
      { key: 'roslyn', re: new RegExp(String.raw`\bCSharpScript\s*\.\s*(?:EvaluateAsync|RunAsync|Create)\s*\(\s*${notLiteral}`, 'g') },
      { key: 'datatable-compute', re: new RegExp(String.raw`\.\s*Compute\s*\(\s*${notLiteral}`, 'g'),
        gate: /\b(?:DataTable|DataColumn|DataView)\b/ },
    ];
  }
  if (lang === 'js') {
    // Server-side JS code injection. Measured gap, not a speculative one: on the
    // independent population CWE-94 scored 0/6, and the missed sink in
    // GHSA-3769-jgqc-cxm7 was `vm.run(\`...${code}...\`)` — the NodeVM / vm2
    // sandbox family. `eval` and `new Function` were already covered elsewhere
    // (client-side.js, agent-untrusted-flow.js); a library whose entire purpose
    // is executing supplied code was not covered anywhere.
    //
    // A SANDBOX IS NOT A CONTROL HERE. vm/vm2 are routinely reached for as the
    // "safe" way to run untrusted code, and both have a long history of escapes.
    // Running attacker-influenced source inside one is still code injection, so
    // these fire on a non-literal argument exactly like every other sink in this
    // module.
    return [
      // vm.run / NodeVM#run / VM#run — the vm2 and @n8n/vm2 family.
      { key: 'vm-run', re: new RegExp(String.raw`\.\s*run\s*\(\s*${notLiteral}`, 'g'),
        gate: /\b(?:NodeVM|VM|vm2|createContext|new\s+VM\b)\b/ },
      // node:vm's own evaluators. runInNewContext takes the code first.
      { key: 'vm-run-in-context',
        re: new RegExp(String.raw`\.\s*(?:runInNewContext|runInThisContext|runInContext)\s*\(\s*${notLiteral}`, 'g') },
      // new vm.Script(src) compiles before it runs; the injection is here.
      { key: 'vm-script', re: new RegExp(String.raw`\bnew\s+(?:vm\s*\.\s*)?Script\s*\(\s*${notLiteral}`, 'g'),
        gate: /\b(?:vm|node:vm)\b/ },
      // Server-side eval / Function, which client-side.js only covers for browsers.
      { key: 'js-eval', re: new RegExp(String.raw`(?:^|[^.\w])eval\s*\(\s*${notLiteral}`, 'gm') },
      { key: 'js-new-function', re: new RegExp(String.raw`\bnew\s+Function\s*\(\s*${notLiteral}`, 'g') },
    ];
  }
  if (lang === 'go') {
    return [
      // yaegi / gomacro interpreter eval of a non-literal.
      { key: 'interp-eval', re: new RegExp(String.raw`\.\s*Eval\s*\(\s*${notLiteral}`, 'g'),
        gate: /\b(?:interp|yaegi|gomacro|Interpreter)\b/ },
      // template Parse of a non-literal template body (user-controlled template).
      { key: 'template-parse', re: new RegExp(String.raw`\.\s*Parse\s*\(\s*${notLiteral}`, 'g'),
        gate: /\b(?:text\/template|html\/template|template\.New)\b/ },
    ];
  }
  return [];
}

function _lang(fp) {
  if (/\.java$/i.test(fp)) return 'java';
  if (/\.kt$/i.test(fp)) return 'kt';
  if (/\.cs$/i.test(fp)) return 'cs';
  if (/\.go$/i.test(fp)) return 'go';
  if (/\.(?:js|jsx|mjs|cjs|ts|tsx)$/i.test(fp)) return 'js';
  return null;
}

export function scanCodeInjectionMultilang(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  const lang = _lang(fp);
  if (!lang) return [];
  const code = blankComments(raw);
  const pats = patternsFor(lang);
  const findings = [];
  const seen = new Set();

  for (const { key, re, gate } of pats) {
    if (gate && !gate.test(code)) continue;
    const r = new RegExp(re.source, re.flags);
    let m;
    while ((m = r.exec(code))) {
      const line = lineOf(code, m.index);
      const id = `code-injection-ml:${fp}:${line}:${key}`;
      if (seen.has(id)) continue;
      seen.add(id);
      findings.push({
        id, file: fp, line,
        vuln: 'Code Injection — dynamic code/expression evaluation of a non-literal argument',
        severity: 'critical', cwe: 'CWE-94', family: 'code-injection',
        parser: lang.toUpperCase(), confidence: 0.7, stride: 'Elevation of Privilege',
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: REMEDIATION,
      });
    }
  }
  return findings;
}
