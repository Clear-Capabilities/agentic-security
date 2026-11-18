// Front matter parsed with the JavaScript engine left on (CWE-94).
//
// The gray-matter package picks the front matter language from the opening fence: `---js` or `---javascript` selects its built-in
// JavaScript engine, which evaluates the block as code. A document whose author is not fully trusted (an uploaded file, a package's
// README, a prompt file from a repository) therefore runs code in the parsing process. Calling it without an `engines` option that
// replaces `js` and `javascript` leaves that engine on. Fires only in files that import gray-matter, on calls of the imported name
// (and its `.read`); silent when the call's options name both engines (or `language` is pinned and the engines are overridden).
const FILE_RE = /\.(?:m?[jt]sx?|cjs)$/i;
const IMPORT_RE = /\bimport\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s+['"]gray-matter['"]|\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"]gray-matter['"]\s*\)/g;

/** The text of the call's argument list, balanced on brackets (strings are not special-cased; a window cap bounds it). */
function argText(code, open) {
  let depth = 0;
  for (let i = open; i < Math.min(code.length, open + 2000); i++) {
    const c = code[i];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') { depth--; if (depth === 0) return code.slice(open + 1, i); }
  }
  return code.slice(open + 1, open + 2000);
}

export function scanFrontmatterEngine(file, code) {
  if (!FILE_RE.test(file) || !code || code.length > 500_000 || !code.includes('gray-matter')) return [];
  const names = new Set();
  let m;
  const ire = new RegExp(IMPORT_RE.source, 'g');
  while ((m = ire.exec(code))) names.add(m[1] || m[2]);
  if (!names.size) return [];
  const out = []; const seen = new Set();
  for (const name of names) {
    const cre = new RegExp(`(?<![\\w$.])${name.replace(/\$/g, '\\$')}(?:\\.read)?\\s*\\(`, 'g');
    while ((m = cre.exec(code))) {
      const open = m.index + m[0].length - 1;
      const args = argText(code, open);
      if (!args.trim()) continue;
      // both JavaScript engine names replaced, or engines supplied by a variable we cannot see into
      if (/\bengines\b/.test(args) && /\bjs\b/.test(args) && /\bjavascript\b/.test(args)) continue;
      if (/\bengines\s*(?:,|\})/.test(args) || /\.\.\./.test(args)) continue;
      // an options object held in a variable: look for its engines in the file
      const optVar = args.split(',').slice(1).map((s) => s.trim()).find((s) => /^[A-Za-z_$][\w$]*$/.test(s));
      if (optVar && new RegExp(`\\b${optVar}\\b[\\s\\S]{0,400}\\bengines\\b`).test(code)) continue;
      const line = code.slice(0, m.index).split('\n').length;
      if (seen.has(line)) continue;
      seen.add(line);
      out.push({
        id: `frontmatter-engine:${file}:${line}`, file, line,
        vuln: 'Code Injection: front matter parsed with the JavaScript engine enabled',
        severity: 'high', cwe: 'CWE-94', family: 'code-injection', parser: 'FRONTMATTER',
        description: `\`${name}(...)\` parses front matter with gray-matter's default engines. A document that opens with \`---js\` or \`---javascript\` has its front matter evaluated as JavaScript in this process, so whoever writes the document runs code here.`,
        remediation: 'Pass `engines: { js: { parse: reject }, javascript: { parse: reject } }` where `reject` throws, so JavaScript front matter is refused; YAML front matter keeps working.',
        snippet: (code.split('\n')[line - 1] || '').trim().slice(0, 200),
        confidence: 0.7,
      });
    }
  }
  return out;
}
