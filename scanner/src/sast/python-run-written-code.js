// Python: a function writes its argument to a file and runs that file with an interpreter or compiler on the host (CWE-94).
//
// Code-runner and grading backends take source text from a caller, write it to a temporary file and hand the file to `python3`, `node`,
// `bash`, `gcc` or `javac` through subprocess. The text is code the process will execute with the server's privileges; nothing in the
// call isolates it. The flow engine does not follow a value through a file on disk, so the write and the run are matched here, inside
// one function:
//
//   write   `<handle>.write(<p>)` where `<p>` is a parameter of the function (not a literal, not a value it built itself)
//   path    the written file: a name used in `open(<name>, 'w...')`, or assigned `<handle>.name` (NamedTemporaryFile)
//   run     subprocess.run/call/check_call/check_output/Popen (or os.system/os.popen) whose argument list starts with an interpreter or
//           compiler literal and holds the path name, after the write
//
// The finding is CWE-94: the defect is running caller-supplied code, not a shell metacharacter in a command. Sandboxing
// (a container, a jail, a separate unprivileged runner) is outside what the text shows, so the rule does not claim it is absent; the
// finding says to check.

const FILE_RE = /\.py$/i;
const INTERPRETERS = 'python|python2|python3|node|nodejs|deno|bun|bash|sh|zsh|ruby|perl|php|lua|Rscript|java|javac|gcc|g\\+\\+|clang|clang\\+\\+|cc|go|rustc|tsc|ts-node';
const RUNNER = '\\b(?:subprocess\\.(?:run|call|check_call|check_output|Popen)|os\\.(?:system|popen))\\s*\\(\\s*';
const ARGV = `\\[\\s*(['"])(?:[\\w./-]*/)?(?:${INTERPRETERS})(?:[\\d.]*)['"]\\s*,([^\\]]*)\\]`;
const RUN = new RegExp(RUNNER + ARGV, 'g');
// an argument list held in a local first: cmd = ['gcc', ...] ... subprocess.run(cmd, ...)
const ARGV_LOCAL = new RegExp(`\\b([A-Za-z_]\\w*)\\s*=\\s*${ARGV}`, 'g');

const lineOf = (src, idx) => src.slice(0, idx).split('\n').length;

function functions(lines) {
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const d = lines[i].match(/^(\s*)(?:async\s+)?def\s+\w+\s*\(([^)]*)\)?/);
    if (!d) continue;
    let sigEnd = i; let sig = lines[i];
    while (!/\)\s*(?:->[^:]*)?:\s*(?:#.*)?$/.test(sig) && sigEnd - i < 15 && sigEnd + 1 < lines.length) sig += lines[++sigEnd];
    const params = (sig.match(/\(([\s\S]*)\)/)?.[1] || '').split(',')
      .map((p) => p.trim().replace(/^\*+/, '').replace(/[:=].*$/s, '').trim()).filter((p) => /^[A-Za-z_]\w*$/.test(p) && p !== 'self' && p !== 'cls');
    const indent = d[1].length;
    let end = sigEnd + 1;
    while (end < lines.length && (lines[end].trim() === '' || lines[end].match(/^\s*/)[0].length > indent)) end++;
    out.push({ start: i, end, params });
  }
  return out;
}

export function scanPythonRunWrittenCode(fp, src) {
  if (!FILE_RE.test(fp) || typeof src !== 'string' || src.length > 800_000 || !/subprocess|os\.system|os\.popen/.test(src) || !/\.write\s*\(/.test(src)) return [];
  if (/(?:^|\/)(?:tests?|testing)\//i.test(fp) || /(?:^|\/)test_[^/]*\.py$|_test\.py$|conftest\.py$/.test(fp)) return [];
  const lines = src.split('\n');
  const out = []; const seen = new Set();
  for (const fn of functions(lines)) {
    if (!fn.params.length) continue;
    const startIdx = lines.slice(0, fn.start).join('\n').length + (fn.start ? 1 : 0);
    const body = lines.slice(fn.start, fn.end).join('\n');
    const writes = [...body.matchAll(/\b(\w+)\.write\s*\(\s*([A-Za-z_]\w*)\s*\)/g)].filter((w) => fn.params.includes(w[2]));
    if (!writes.length) continue;
    const firstWrite = writes[0].index;
    const paths = new Set([
      ...[...body.matchAll(/\bopen\s*\(\s*([A-Za-z_]\w*)\s*,\s*['"][wa]/g)].map((m) => m[1]),
      ...[...body.matchAll(/\b([A-Za-z_]\w*)\s*=\s*\w+\.name\b/g)].map((m) => m[1]),
    ]);
    if (!paths.size) continue;
    const runs = [...body.matchAll(RUN)].map((r) => ({ index: r.index, rest: r[2] }));
    for (const a of body.matchAll(ARGV_LOCAL)) {
      const at = body.slice(a.index).search(new RegExp(`${RUNNER}${a[1]}\\b`));
      if (at >= 0) runs.push({ index: a.index + at, rest: a[3] });
    }
    for (const r of runs) {
      if (r.index < firstWrite) continue;
      const rest = r.rest;
      const hit = [...paths].find((p) => new RegExp(`(?<![\\w.'"])${p}(?![\\w])`).test(rest));
      if (!hit) continue;
      const line = lineOf(src, startIdx + r.index);
      const id = `python-run-written-code:${fp}:${line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      const w = writes[0];
      out.push({
        id, file: fp, line,
        vuln: 'Code Injection: caller-supplied source written to a file and run with an interpreter or compiler',
        severity: 'high', cwe: 'CWE-94', family: 'code-injection',
        description: `\`${w[2]}\`, a parameter of this function, is written to \`${hit}\` (line ${lineOf(src, startIdx + w.index)}), which is then passed to an interpreter or compiler here. The text runs with this process's privileges and file system. Whether a caller passes attacker text, and whether this host is an isolated sandbox, is not checked here.`,
        remediation: 'Run submitted code only inside an isolated sandbox (a container or VM with no network, a read-only file system, an unprivileged user and CPU, memory and time limits), never directly on the application host, and authenticate and rate-limit the endpoint that accepts it.',
        snippet: (lines[line - 1] || '').trim().slice(0, 200), parser: 'PYTHON', confidence: 0.6,
      });
    }
  }
  return out;
}
