// Caller keyword arguments forwarded as git command-line options (CWE-88).
//
// In the Python git wrapper whose commands are attributes of `repo.git` (`repo.git.rev_list(rev, **kwargs)`), every keyword argument
// becomes a command-line option: `output='/tmp/x'` turns into `--output=/tmp/x`, and options such as `--output`, `--upload-pack` or
// `--exec` write files or run programs. A function that takes `**kwargs` and passes them straight into such a call lets its caller
// add any option. The wrapper ships an unsafe-option check for this; a function that calls it (or names the unsafe options) is
// silent. Reported at the function definition, where the options enter.
//
// Only subcommands with an option that writes a file, reads one into output, or runs a program (`--output`, `--upload-pack`, `--exec`,
// `--open-files-in-pager`, `--contents`); a forwarded option on other subcommands changes behaviour but not this
const RISKY_COMMANDS = 'rev_list|log|diff|diff_tree|diff_index|diff_files|show|whatchanged|format_patch|fetch|pull|push|clone|ls_remote|archive|grep|blame';
const DEF_RE = /^([ \t]*)(?:async\s+)?def\s+(\w+)\s*\(/gm;

export function scanGitOptionInjection(file, code) {
  if (!/\.py$/i.test(file) || !code || code.length > 500_000 || !/\.git\.\w+\s*\(/.test(code)) return [];
  const lines = code.split('\n');
  const out = [];
  let m;
  const re = new RegExp(DEF_RE.source, 'gm');
  while ((m = re.exec(code))) {
    const indent = m[1].length;
    const defLine = code.slice(0, m.index).split('\n').length;
    // the signature, up to the closing `):`
    const sigEnd = code.indexOf(':\n', m.index);
    const sig = code.slice(m.index, sigEnd < 0 ? m.index + 600 : Math.min(sigEnd, m.index + 1200));
    const kw = sig.match(/\*\*(\w+)/);
    if (!kw) continue;
    // the body: following lines indented deeper than the def
    const startLine = sig.split('\n').length + defLine - 1;
    let end = startLine;
    for (let i = startLine; i < lines.length; i++) {
      const l = lines[i];
      if (l.trim() === '') continue;
      if (l.match(/^[ \t]*/)[0].length <= indent) break;
      end = i + 1;
    }
    const body = lines.slice(startLine, end).join('\n');
    const fwd = new RegExp(`\\.git\\.(?:${RISKY_COMMANDS})\\s*\\([^)]*\\*\\*${kw[1]}\\b`);
    if (!fwd.test(body)) continue;
    if (/unsafe_option|check_unsafe|_option_candidates/.test(sig + body)) continue;
    out.push({
      id: `git-option-injection:${file}:${defLine}`, file, line: defLine,
      vuln: 'Argument Injection: caller keyword arguments forwarded as git options',
      severity: 'high', cwe: 'CWE-88', family: 'argument-injection', parser: 'GIT-OPTIONS',
      description: `\`${m[2]}\` takes \`**${kw[1]}\` and passes it into a \`.git.<command>(...)\` call, where each keyword becomes a command-line option. A caller can add options such as \`--output\` (writes a file) or \`--upload-pack\`/\`--exec\` (runs a program).`,
      remediation: 'Check the forwarded options against the unsafe list before the call (the wrapper\'s `check_unsafe_options`), or accept only the specific options this function needs as named parameters.',
      snippet: (lines[defLine - 1] || '').trim().slice(0, 200),
      confidence: 0.55,
    });
  }
  return out;
}
