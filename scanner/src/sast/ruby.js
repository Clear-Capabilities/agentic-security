import { blankComments } from './_comment-strip.js';
// Ruby-specific detectors. Targets Rails idioms and the eval-family methods
// that make Ruby code easy to compromise when fed untrusted input.
//
//   - User input into eval / instance_eval / class_eval / module_eval
//   - send / public_send with a user-controlled method name
//   - Marshal.load on user input
//   - YAML.load (not safe_load) on user input
//   - ERB.new(...).result on user input
//   - Open / `` (backtick) with user input (command injection)
//   - Rails: attributes = params (without strong_params)
//   - Open::URI.open(user_url) — SSRF
//   - File.read(params[...]) — path traversal

const RE = {
  evalFamily: /\b(?:eval|instance_eval|class_eval|module_eval)\s*\(?\s*(?:params|request|@\w+\.params|cookies|session)\b/g,
  send: /\.(?:send|public_send)\s*\(\s*(?:params|request|@\w+\.params)\b/g,
  marshalLoad: /\bMarshal\s*\.\s*load\s*\(\s*(?:params|request|@\w+\.params|cookies|session)\b/g,
  yamlUnsafe: /\bYAML\s*\.\s*load\s*\(\s*(?:params|request|@\w+\.params|cookies|session)\b/g,
  erbResult: /\bERB\.new\s*\(\s*(?:params|request|@\w+\.params)\b[^)]*\)\s*\.\s*result/g,
  backtick: /`[^`]*#\{[^}]*\b(?:params|request|@\w+\.params)\b[^}]*\}/g,
  systemUser: /\b(?:system|exec|Open3\.capture\d*|IO\.popen)\s*\(\s*[^)]*\b(?:params|request|@\w+\.params)\b/g,
  attributesEq: /\.\s*attributes\s*=\s*params\b(?!\s*\.permit)/g,
  openSsrf: /\b(?:open|URI\.open|URI\.parse\([^)]*\)\.read)\s*\(\s*(?:params|request|@\w+\.params)\b/g,
  fileRead: /\bFile\s*\.\s*(?:read|open|new|readlines)\s*\(\s*params\s*\[/g,
  // Structural (taint-independent): an ActiveRecord query or shell command
  // built with string interpolation (#{...}) or concat is the injection shape
  // regardless of whether the value is `params` or a local variable that came
  // from params — the existing rules above require the literal `params` token
  // on the sink line, which misses `name = params[:x]; where("... #{name}")`.
  sqlInjectionStructural: /\.(?:where|find_by_sql|having|order|group|joins|select|from|pluck|update_all|delete_all|exec_query|execute|select_all|select_value|find_by)\s*\(\s*(?:"[^"\n]*#\{|['"][^'"\n]*['"]\s*\+)/g,
  cmdInjectionStructural: /(?:`[^`\n]*#\{|\b(?:system|exec)\s*\(\s*"[^"\n]*#\{|\bIO\.popen\s*\(\s*"[^"\n]*#\{|\b(?:system|exec)\s*\(\s*['"][^'"\n]*['"]\s*\+)/g,
  // Structural path traversal: File/IO op whose path is built by interpolation
  // (#{...}) or concat. `File.read("/data/" + name)` routes through a local var
  // so the `params[`-on-sink fileRead rule misses it. Containment-guarded forms
  // (File.expand_path + start_with?) are dropped by engine.js dropGuardedFindings.
  pathTraversalStructural: /\b(?:File|IO)\s*\.\s*(?:read|open|new|readlines|binread|write|foreach)\s*\(\s*(?:"[^"\n]*#\{|['"][^'"\n]*['"]\s*\+)/g,
  // Structural deserialization (taint-independent): Marshal.load / YAML.load /
  // YAML.unsafe_load are unsafe on ANY non-trivial argument — the danger is the
  // sink, not the source. The `params`-on-sink marshalLoad/yamlUnsafe rules
  // above miss `data = request.body.read; Marshal.load(data)`. A bare string
  // literal arg (Marshal.load("...")) won't match (`\w` requires an identifier).
  deserStructural: /\bMarshal\s*\.\s*load\s*\(\s*[A-Za-z_@]\w*|\bYAML\s*\.\s*(?:load|unsafe_load)\s*\(\s*[A-Za-z_@]\w*/g,
};

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanRuby(fp, raw) {
  if (!/\.rb$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  // Ruby's comment char is # (same as Python) — use the py stripper.
  const code = blankComments(raw, 'py');
  const findings = [];
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };

  for (const [key, re] of Object.entries(RE)) {
    const r = new RegExp(re.source, re.flags);
    let m;
    while ((m = r.exec(code))) {
      const line = lineOf(raw, m.index);
      const meta = {
        evalFamily: {
          vuln: 'Code Injection: eval/instance_eval/class_eval on user-controlled input',
          severity: 'critical', cwe: 'CWE-94',
          remediation: 'Never call eval on user input — there is no safe sanitization. Replace with explicit branching on enumerated values, a method dispatch table (whitelist), or a parser for a constrained DSL.',
        },
        send: {
          vuln: 'Method Reflection: send/public_send with user-controlled method name',
          severity: 'high', cwe: 'CWE-470',
          remediation: 'Validate the method name against an explicit whitelist before sending. `params[:action]` straight into `send` lets the client invoke any method on the receiver, including private ones with `send`.',
        },
        marshalLoad: {
          vuln: 'Insecure Deserialization: Marshal.load on user input',
          severity: 'critical', cwe: 'CWE-502',
          remediation: 'Marshal is unsafe by design — never use it on data crossing a trust boundary. Replace with JSON or msgpack with an explicit schema.',
        },
        yamlUnsafe: {
          vuln: 'Insecure Deserialization: YAML.load on user input',
          severity: 'critical', cwe: 'CWE-502',
          remediation: 'Replace `YAML.load(input)` with `YAML.safe_load(input, permitted_classes: [Symbol], aliases: true)` — the default `load` will instantiate arbitrary Ruby classes from a crafted document (same risk class as Marshal).',
        },
        erbResult: {
          vuln: 'Server-Side Template Injection: ERB.new(user_template).result',
          severity: 'critical', cwe: 'CWE-94',
          remediation: 'Never feed a user-supplied string into ERB. Predefine templates server-side; the client may pass *values*, never the template body.',
        },
        backtick: {
          vuln: 'Command Injection: backtick command interpolates request data',
          severity: 'critical', cwe: 'CWE-78',
          remediation: 'Use `Open3.capture2(["cmd", arg1, arg2])` with an array form so the shell does not parse anything. Backticks and `system("cmd #{params[...]}")` are pure shell injection.',
        },
        systemUser: {
          vuln: 'Command Injection: system/exec/Open3 with user-controlled input',
          severity: 'critical', cwe: 'CWE-78',
          remediation: 'Use the array form: `system(["cmd", arg])`. The string form lets the shell parse — any quoting trick wins.',
        },
        attributesEq: {
          vuln: 'Mass Assignment: model.attributes = params (no strong_params)',
          severity: 'high', cwe: 'CWE-915',
          remediation: 'Use `params.require(:user).permit(:name, :email)` — explicit allow-list. Assigning raw `params` lets the client set fields the controller never intended (admin: true, role: ...).',
        },
        openSsrf: {
          vuln: 'SSRF: open/URI.open with user-controlled URL',
          severity: 'high', cwe: 'CWE-918',
          remediation: 'Resolve and validate the host against an allow-list before fetching. `open(params[:url])` is also a path-traversal vector under older Ruby (open-uri inherits Kernel#open semantics).',
        },
        fileRead: {
          vuln: 'Path Traversal: File.read/open with user-controlled path',
          severity: 'high', cwe: 'CWE-22',
          remediation: 'Canonicalize the path and verify it stays under an allowed base: `path = File.expand_path(File.join(base, name)); raise unless path.start_with?(base)`.',
        },
        sqlInjectionStructural: {
          vuln: 'SQL Injection: ActiveRecord query built with string interpolation / concat',
          severity: 'critical', cwe: 'CWE-89',
          remediation: 'Use the parameterized form: `User.where("name = ?", name)` or `where(name: name)`. Never interpolate (`#{...}`) or concatenate values into a SQL fragment.',
        },
        cmdInjectionStructural: {
          vuln: 'Command Injection: shell command built with string interpolation / concat',
          severity: 'critical', cwe: 'CWE-78',
          remediation: 'Use `Open3.capture2("cmd", arg1, arg2)` with separate arguments (no shell). Backticks and `system("... #{x}")` run through the shell.',
        },
        pathTraversalStructural: {
          vuln: 'Path Traversal: File/IO operation built with interpolated/concatenated path',
          severity: 'high', cwe: 'CWE-22',
          remediation: 'Canonicalize and assert containment: `path = File.expand_path(File.join(base, name)); raise unless path.start_with?(base)`. Never interpolate/concatenate request input straight into a file path.',
        },
        deserStructural: {
          vuln: 'Insecure Deserialization: Marshal.load / YAML.load on a non-literal value',
          severity: 'critical', cwe: 'CWE-502', family: 'insecure-deserialization',
          remediation: 'Marshal and YAML.load instantiate arbitrary Ruby objects (RCE gadget chains). Use JSON for data crossing a trust boundary, or YAML.safe_load(input, permitted_classes: [Symbol]). Never Marshal.load attacker-controlled bytes.',
        },
      }[key];
      push({
        id: `ruby-${key}:${fp}:${line}`,
        file: fp, line,
        vuln: meta.vuln, severity: meta.severity, cwe: meta.cwe,
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: meta.remediation,
        parser: 'RUBY',
        confidence: 0.80,
      });
    }
  }
  return findings;
}

// ── PRD F1.3 — `File.join(<root>, …, <untrusted>)` ──────────────────────────
//
// The dominant Ruby CWE-22 shape on real code, and the one
// `pathTraversalStructural` above cannot reach: that rule needs a STRING
// LITERAL as the first component (`File.read("/data/" + name)`), and the real
// advisories join variables.
//
//   File.join(adapter.document_root, request.path_info.sub(/\.html$/,'') + '.html')
//     — lsegal/yard, GHSA-pxcc-8665-phx8; the fix rejects `..` segments
//   File.join(root, tenant, folder_for(key), key)
//     — basecamp/activerecord-tenanted, GHSA-pmwx-rm49-xv39; the fix raises on
//       `key.split("/").intersect?(%w[. ..])`
//
// Measured baseline before this rule: 23 cached Ruby CWE-22/CWE-79 entries,
// 0 localized hits, 18 of them producing no finding of any kind.
//
// PRECISION IS THE WHOLE DESIGN. The F1.2 attempt at Ruby resource-exhaustion
// was reverted because it fired on `File.read(File.join(__dir__, "…/data.json"))`
// — a path built entirely from constants. So:
//
//   · the LAST component must be a variable-ish expression, never a literal;
//   · a join rooted at `__dir__` / `Rails.root` / `File.dirname(__FILE__)` /
//     `Dir.pwd` is a project-relative constant path and is skipped outright;
//   · the join must actually reach a filesystem operation, either wrapped
//     directly or through a variable used by one nearby;
//   · any containment guard in the enclosing window silences it — that is the
//     whole vulnerability, so a guard means there is nothing to report.
//
// A single `if path.include?("..")` silences this, which is exactly the fix
// each of these advisories shipped.

// Trailing (?!\w) rather than \b: Ruby predicate methods end in \, and a
// word boundary after a non-word character never matches, so \
// silently failed to count as a filesystem operation — the miss that made this
// rule silent on lsegal/yard's static_caching.rb, one of the two advisories it
// was written from.
// Trailing (?!\w) rather than \b. Ruby predicate methods end in `?`, and a word
// boundary after a non-word character can never match — so `File.file?(x)` did
// not count as a filesystem operation, and this rule was silent on
// lsegal/yard's static_caching.rb, one of the two advisories it was written
// from. The rule looked correct in isolation and found nothing; the bug was one
// character of regex.
const RB_FS_OP = /\b(?:File|IO|FileUtils|Dir)\s*\.\s*(?:read|open|new|readlines|binread|binwrite|write|foreach|delete|unlink|mkdir_p|rm_rf|cp|mv|file\?|exist\?|directory\?|entries|glob)(?!\w)/;
// Constant roots: a path assembled from these is not attacker-reachable.
const RB_CONST_ROOT = /\b(?:__dir__|__FILE__|Rails\.root|Dir\.pwd|Gem\.dir|File\.dirname\s*\(\s*__FILE__)/;
// Any of these in the enclosing window means containment was considered.
const RB_PATH_GUARD = /\b(?:expand_path[\s\S]{0,200}?start_with\?|start_with\?[\s\S]{0,200}?expand_path|include\?\s*\(\s*['"]\.\.|\.\.\s*['"]\s*\)|intersect\?\s*\(\s*%w\[|cleanpath|realpath|File\s*\.\s*basename|sanitize_filename|secure_filename|ValidPath|absolute_path\?)/;
// A literal argument — the thing that must NOT be the last component.
const RB_LITERAL_ARG = /^\s*(?:['"][^'"]*['"]|:[A-Za-z_]\w*)\s*$/;

function _splitArgs(s) {
  const out = [];
  let depth = 0, cur = '';
  for (const ch of s) {
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    if (ch === ',' && depth === 0) { out.push(cur); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim()) out.push(cur);
  return out;
}

/** File.join(...) whose last component is variable and which reaches the filesystem. */
export function scanRubyPathJoin(fp, raw) {
  if (!/\.rb$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  const code = blankComments(raw, 'py');
  const lines = code.split('\n');
  const out = [];
  const seen = new Set();

  const JOIN = /\bFile\s*\.\s*join\s*\(/g;
  let m;
  while ((m = JOIN.exec(code))) {
    // Balanced scan for the closing paren of this call.
    let i = m.index + m[0].length, depth = 1;
    for (; i < code.length && depth > 0; i++) {
      if (code[i] === '(') depth++;
      else if (code[i] === ')') depth--;
    }
    if (depth !== 0) continue;
    const inner = code.slice(m.index + m[0].length, i - 1);
    const args = _splitArgs(inner);
    if (args.length < 2) continue;
    const last = args[args.length - 1];
    if (RB_LITERAL_ARG.test(last)) continue;                 // File.join(root, "index.html")
    if (RB_CONST_ROOT.test(inner)) continue;                 // project-relative constant path

    const line = code.slice(0, m.index).split('\n').length;

    // The join must reach the filesystem: wrapped directly, or assigned to a
    // variable that a nearby filesystem call uses.
    const before = code.slice(Math.max(0, m.index - 120), m.index);
    let reaches = RB_FS_OP.test(before);
    let assigned = null;
    if (!reaches) {
      const am = before.match(/([A-Za-z_@][\w]*)\s*=\s*$/);
      if (am) {
        assigned = am[1];
        const after = lines.slice(line, line + 12).join('\n');
        const use = new RegExp(`${assigned.replace('@', '@')}\\b`);
        reaches = RB_FS_OP.test(after) && use.test(after);
      }
    }
    if (!reaches) continue;

    // Containment guard anywhere in the enclosing window — that IS the fix.
    const windowText = lines.slice(Math.max(0, line - 15), line + 15).join('\n');
    if (RB_PATH_GUARD.test(windowText)) continue;

    const id = `ruby-pathJoinUnguarded:${fp}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({
      id, file: fp, line,
      vuln: 'Path Traversal: File.join builds a filesystem path from a variable component with no containment check',
      severity: 'high', cwe: 'CWE-22', family: 'path-traversal',
      parser: 'RUBY', confidence: 0.7,
      description:
        `The last component of this File.join is a variable, the result reaches a filesystem operation, and nothing in ` +
        `the surrounding code rejects \`..\` segments or asserts the resolved path stays under the base. A value ` +
        `containing \`../\` walks out of the intended directory.`,
      remediation:
        'Reject traversal segments before joining — `raise if key.split("/").intersect?(%w[. ..])` — or canonicalize ' +
        'and assert containment: `path = File.expand_path(File.join(base, name)); raise unless path.start_with?(base)`.',
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
    });
  }
  return out;
}
