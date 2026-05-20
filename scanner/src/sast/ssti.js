// Server-Side Template Injection (CWE-94 / OWASP A03).
//
// Pattern: user-controlled string fed to a template-engine compile or
// from_string. The attacker controls the template body, so they can
// invoke the language's expression-evaluation surface (often equivalent
// to code execution via Jinja2's `__class__.__bases__` / Handlebars's
// helpers / EJS's `<% %>`).
//
// We catch the high-confidence shapes — when the template body is built
// from a user-derived source (req.body, request.args, params.<x>, …) or
// the body has obvious concatenation/interpolation. We do NOT flag the
// pattern with a constant string body — that's the secure form.
//
// Engines covered (v1):
//   - Jinja2 (Python):       Environment.from_string(x), Template(x)
//   - Handlebars (JS):       Handlebars.compile(x)
//   - EJS (JS):              ejs.compile(x), ejs.render(x)
//   - Mustache (JS):         Mustache.render(x, …)  when x is non-literal
//   - Twig (PHP):            $twig->createTemplate($x)
//   - Pug (JS, no AST):      pug.compile(x)
//   - Velocity (Java):       Velocity.evaluate(ctx, w, log, x) when x is non-literal
//
// Severity: critical (template-injection → RCE in most engines).

import { blankComments } from './_comment-strip.js';

const TAINT_HINT_RE =
  /\b(?:req\.|request\.|params\.|query\.|body\.|ctx\.query|ctx\.request|c\.Query|r\.URL\.Query|_GET|_POST|_REQUEST|process\.argv|getenv|environ)\b|`[^`]*\$\{|"[^"]*"\s*\+\s*\w|'[^']*'\s*\+\s*\w|\bf['"]/;

// PATTERNS: [lang, regex, engine]. Each captures the call's first arg
// region in group 1 so we can test for taint hints.
const PATTERNS = [
  // Jinja2 from_string — most common SSTI shape. Accept any `<ident>.from_string`
  // because the Environment is often stored in a local (e.g. `env = Environment()`).
  ['py',  /\b(?:[A-Za-z_][\w]*|\w+\([^)]*\))\s*\.\s*from_string\s*\(\s*([^)]*?)\s*\)/g, 'Jinja2'],
  // Plain `Template(x)` import — risky enough to flag with a taint hint.
  ['py',  /\bTemplate\s*\(\s*((?:request|params|body|query|f["']|[a-z_][\w]*\s*\+)[^)]*)\)/g, 'Jinja2/Template'],
  // Handlebars.compile (Node).
  ['js',  /\bHandlebars\s*\.\s*compile\s*\(\s*([^)]*?)\s*\)/g, 'Handlebars'],
  // EJS compile/render.
  ['js',  /\bejs\s*\.\s*(?:compile|render)\s*\(\s*([^)]*?)\s*\)/g, 'EJS'],
  // Mustache render — only when first arg is dynamic.
  ['js',  /\bMustache\s*\.\s*render\s*\(\s*((?:req\.|request\.|params\.|query\.|body\.|ctx\.|`[^`]*\$\{)[^,)]*)/g, 'Mustache'],
  // Pug compile.
  ['js',  /\bpug\s*\.\s*compile\s*\(\s*([^)]*?)\s*\)/g, 'Pug'],
  // Twig dynamic template.
  ['php', /->\s*createTemplate\s*\(\s*([^)]*?)\s*\)/g, 'Twig'],
  // Velocity dynamic template evaluation.
  ['java', /\bVelocity\s*\.\s*evaluate\s*\([^,]+,[^,]+,[^,]+,\s*([^)]+)\s*\)/g, 'Velocity'],
];

function _lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

function _lang(fp) {
  if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp)) return 'js';
  if (/\.py$/i.test(fp)) return 'py';
  if (/\.php$/i.test(fp)) return 'php';
  if (/\.java$/i.test(fp)) return 'java';
  return null;
}

export function scanSSTI(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  const lang = _lang(fp);
  if (!lang) return [];
  const code = blankComments(raw, lang === 'py' ? 'py' : undefined);
  // Cheap pre-filter so we don't pay regex cost on files that don't
  // mention any template engine.
  if (!/\b(?:Jinja|jinja|Template|Handlebars|ejs|Mustache|pug|Twig|Velocity|createTemplate|from_string)\b/.test(code)) return [];
  const findings = [];
  const seen = new Set();
  const rawLines = raw.split('\n');
  for (const [plang, pat, engine] of PATTERNS) {
    if (plang !== lang) continue;
    const re = new RegExp(pat.source, pat.flags);
    let m;
    while ((m = re.exec(code))) {
      const firstArg = (m[1] || '').trim();
      const literalConst = /^\s*(['"`])(?:[^'"`\\]|\\.)*\1\s*$/.test(firstArg);
      if (literalConst) continue;        // const template body is safe
      const line = _lineOf(raw, m.index);
      // Direct taint hint inline? Or a hint in the preceding 10 lines that
      // assigns to the same identifier name we're about to feed the engine?
      let tainted = TAINT_HINT_RE.test(firstArg);
      if (!tainted && /^[a-z_][\w]*$/i.test(firstArg)) {
        const lo = Math.max(0, line - 11);
        const before = rawLines.slice(lo, line - 1).join('\n');
        const assignRe = new RegExp(`\\b${firstArg}\\s*=\\s*[^;\\n]*(?:${TAINT_HINT_RE.source})`);
        if (assignRe.test(before)) tainted = true;
      }
      if (!tainted) continue;
      const id = `ssti:${fp}:${line}:${engine}`;
      if (seen.has(id)) continue;
      seen.add(id);
      findings.push({
        id,
        file: fp, line,
        vuln: `Server-Side Template Injection (${engine})`,
        severity: 'critical',
        cwe: 'CWE-94',
        family: 'ssti',
        stride: 'Elevation of Privilege',
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation:
          'Never compile a template from user input. Pre-register templates and pass user values as variables. ' +
          'Jinja2: load templates with `jinja2.FileSystemLoader` + `env.get_template("name.html")`, then `.render(name=user_value)`. ' +
          'Handlebars: pre-compile the template; pass user values via the context object. ' +
          'EJS: same — `ejs.render(template_string_from_disk, { name: user_value })`. ' +
          'Mustache: never pass user input as the template body argument.',
        parser: 'SSTI',
        confidence: 0.85,
      });
    }
  }
  return findings;
}
