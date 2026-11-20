// JavaScript/TypeScript: a function parameter interpolated into a shell command string run by exec/execSync (CWE-78).
//
// The flow engine reports command injection when a request value reaches a shell. Library code (system information, packaging, build
// helpers) never sees a request: its input is its caller's argument, and the published advisories in that shape interpolate a parameter
// into a template literal that `child_process.exec`/`execSync` hands to `/bin/sh`.
//
//   sink    exec(...) / execSync(...) whose command is a template literal, directly or through a local assigned one in the same function,
//           interpolating a parameter of the enclosing function with no quoting the shell honours and no sanitizer.
//   silent  a parameter passed through a shell or path sanitizer (or a number conversion) before the call, an interpolation that is a
//           call (it prints its result), execFile/spawn (no shell), and test code.
//
// The rule does not decide whether a caller passes attacker text; the finding says so.

import { libraryMode, isByDesignParamName, isRoleParamName } from '../dataflow/library-sources.js';

const FILE_RE = /\.(?:[cm]?[jt]s)$/i;
const EXEC_CALL = /(?<![\w$.])(?:(?:child_process|cp|childProcess)\.)?(exec|execSync)\s*\(\s*/g;
const SANITIZED = /sanitiz|escape|quote|shellEscape|parseInt|parseFloat|Number\s*\(|encodeURIComponent|basename|replace\s*\(\s*\/\[\^/i;

const lineOf = (src, idx) => src.slice(0, idx).split('\n').length;

/** The nearest enclosing function header before `idx` (within 60 lines) and its parameter names. */
function enclosingParams(src, idx) {
  const start = Math.max(0, idx - 4000);
  const window = src.slice(start, idx);
  const heads = [...window.matchAll(/\bfunction\b\s*[\w$]*\s*\(([^()]*)\)\s*\{|(?:^|[=(,:]\s*)(?:async\s+)?\(([^()]*)\)\s*(?::\s*[\w<>[\]| ]+)?\s*=>\s*\{|^\s*(?:async\s+)?(?!if\b|for\b|while\b|switch\b|catch\b)[\w$]+\s*\(([^()]*)\)\s*\{/gm)];
  if (!heads.length) return null;
  const h = heads[heads.length - 1];
  const params = (h[1] ?? h[2] ?? h[3] ?? '').split(',')
    .map((p) => p.trim().replace(/^\.\.\./, '').replace(/[:=?].*$/, '').trim())
    .filter((p) => /^[A-Za-z_$][\w$]*$/.test(p));
  return { params, bodyStart: start + h.index + h[0].length };
}

/** Bare interpolated names of a single-line template literal. */
function interpolatedNames(tpl) {
  return [...tpl.matchAll(/\$\{\s*([A-Za-z_$][\w$]*)\s*\}/g)].map((m) => m[1]);
}

// A parameter of a library function is caller input, not attacker input, unless the operator says the library's callers are
// untrusted: the same opt-in as the taint engine's caller-controlled source (`js-src-caller-controlled-param`), read per call.
// Under the narrowed model (`1`/`narrow`, dataflow/library-sources.js) a parameter that is the command by its name (`cmd`, `args`, `script`)
// or code/a callback by design is not reported here; engine.js (`_dropLibraryPurposeFindings`) then removes the findings of a package whose
// own manifest or main export says it runs commands, since only the engine holds the manifests.
export function scanJsExecParamInterpolation(fp, src) {
  const mode = libraryMode();
  if (mode === 'off') return [];
  if (!FILE_RE.test(fp) || typeof src !== 'string' || src.length > 800_000 || !/\bexec(?:Sync)?\s*\(/.test(src)) return [];
  if (/(?:^|\/)(?:__tests__|tests?|spec|fixtures?|scripts?|bin)\//i.test(fp) || /\.(?:test|spec)\.[cm]?[jt]s$/i.test(fp)) return [];
  if (!/child_process/.test(src)) return [];
  const lines = src.split('\n');
  const out = []; const seen = new Set();
  for (const m of src.matchAll(EXEC_CALL)) {
    const argAt = m.index + m[0].length;
    const fn = enclosingParams(src, m.index);
    if (!fn || !fn.params.length) continue;
    const body = src.slice(fn.bodyStart, m.index);
    let tpl = null; let tplAt = argAt;
    if (src[argAt] === '`') {
      const end = src.indexOf('`', argAt + 1);
      if (end > 0) tpl = src.slice(argAt, end + 1);
    } else {
      const id = src.slice(argAt).match(/^([A-Za-z_$][\w$]*)\s*[,)]/);
      if (id) {
        const asg = [...body.matchAll(new RegExp(`\\b(?:const|let|var)\\s+${id[1].replace(/\$/g, '\\$')}\\s*=\\s*(\`[^\`]*\`)`, 'g'))].pop();
        if (asg) { tpl = asg[1]; tplAt = fn.bodyStart + asg.index; }
      }
    }
    if (!tpl || tpl.includes('\n')) continue;
    let bad = interpolatedNames(tpl).filter((n) => fn.params.includes(n))
      .filter((n) => !new RegExp(`\\b${n.replace(/\$/g, '\\$')}\\s*=(?!=)[^;\\n]*(?:${SANITIZED.source})`, 'i').test(body))
      .filter((n) => !new RegExp(`(?:${SANITIZED.source})[\\w$.]*\\s*\\(\\s*${n.replace(/\$/g, '\\$')}\\b`, 'i').test(body));
    if (!bad.length) continue;
    if (mode === 'narrow') {
      bad = bad.filter((n) => !isByDesignParamName(n) && !isRoleParamName(n, 'cmd'));
      if (!bad.length) continue;
    }
    const line = lineOf(src, tplAt);
    const id = `js-exec-param-interpolation:${fp}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({
      id, file: fp, line,
      vuln: `Command Injection: function parameter interpolated into a shell command run by ${m[1]}`,
      severity: 'high', cwe: 'CWE-78', family: 'command-injection',
      description: `\`${bad.join('`, `')}\`, a parameter of the enclosing function, is interpolated into a command string that \`${m[1]}\` runs through the shell. A value holding \`;\`, \`|\`, \`$( )\` or a space runs other commands. Whether a caller passes attacker text is not checked here.`,
      remediation: 'Run the program without a shell (`execFileSync(\'cat\', [file])`, or read the file with `fs.readFileSync`), or validate the value against a strict pattern before use. Do not build shell command strings from arguments.',
      snippet: (lines[line - 1] || '').trim().slice(0, 200), parser: 'JS-EXEC', confidence: 0.5,
    });
  }
  return out;
}
