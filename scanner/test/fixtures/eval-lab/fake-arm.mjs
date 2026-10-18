// A stand-in "model" for the Eval Lab's tests: a deterministic command that answers the lab's request file the way a model
// would. It never reads stdin and never touches the network. Profiles:
//   good    finds concatenated shell/SQL sinks, refutes safe lookalikes, writes a working reproducer and a correct patch
//   noisy   also flags anything that merely CALLS a sink, confirms every candidate, patches with a still-vulnerable edit
//   lazy    finds nothing, refuses everything
//   garbage prints text that is not JSON
//   slow    sleeps past any sensible timeout
//   leaky   tries to read a file named like an answer key in its workspace (the lab must have removed it)
import fs from 'node:fs';
import path from 'node:path';

const profile = process.argv[2] ?? 'good';
const repro = process.argv[3] ? JSON.parse(fs.readFileSync(process.argv[3], 'utf8')) : null;
const req = JSON.parse(fs.readFileSync(process.env.AGENTIC_EVAL_REQUEST, 'utf8'));
const usage = { good: { inputTokens: 1200, outputTokens: 300 }, noisy: { inputTokens: 900, outputTokens: 250 }, lazy: { inputTokens: 100, outputTokens: 10 } }[profile] ?? { inputTokens: 500, outputTokens: 100 };

if (profile === 'garbage') { process.stdout.write('I think there might be a bug somewhere!'); process.exit(0); }
if (profile === 'slow') { setTimeout(() => {}, 600000); } else {
  const walk = (d, out = []) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p, out); else out.push(p); } return out; };
  const files = walk(req.workspace);
  const lines = (f) => fs.readFileSync(f, 'utf8').split('\n');
  const rel = (f) => path.relative(req.workspace, f).split(path.sep).join('/');
  const concatShell = /\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+)/;
  const concatSql = /\.query\s*\(\s*"[^"]*"\s*\+/;
  const callsSink = /\b(?:exec|execSync|execFile|spawnSync|query)\s*\(/;
  const out = {};
  if (req.task === 'detect') {
    const findings = [];
    for (const f of files) lines(f).forEach((l, i) => {
      if (profile === 'lazy') return;
      if (concatShell.test(l)) findings.push({ file: rel(f), line: i + 1, cwe: 'CWE-78' });
      else if (concatSql.test(l)) findings.push({ file: rel(f), line: i + 1, cwe: 'CWE-89' });
      else if (profile === 'noisy' && callsSink.test(l)) findings.push({ file: rel(f), line: i + 1, cwe: /query/.test(l) ? 'CWE-89' : 'CWE-78' });
    });
    out.findings = findings;
  } else if (req.task === 'falsify') {
    const c = req.candidates[0]; const f = files.find((x) => rel(x) === c.file);
    const line = f ? lines(f)[c.line - 1] ?? '' : '';
    out.verdicts = { [c.id]: profile === 'lazy' ? 'uncertain' : profile === 'noisy' ? 'confirmed' : (concatShell.test(line) || concatSql.test(line)) ? 'confirmed' : 'refuted' };
  } else if (req.task === 'exploit') {
    out.reproducer = profile === 'lazy' ? null : repro;
  } else if (req.task === 'patch') {
    const f = files.find((x) => rel(x) === req.target.file);
    if (profile === 'lazy' || !f) out.files = null;
    else if (profile === 'good') out.files = { [req.target.file]: "import { spawnSync } from 'node:child_process';\nconst userInput = process.argv[2] || '';\nspawnSync('echo', ['hello', userInput], { stdio: 'ignore', shell: false });\n" };
    else out.files = { [req.target.file]: fs.readFileSync(f, 'utf8').replace('stdio: \'ignore\'', "stdio: 'ignore' /* reviewed */") };
  }
  if (profile === 'leaky') out.sawAnswerKey = files.some((x) => /labels|answer|expected/i.test(path.basename(x)));
  out.usage = usage;
  process.stdout.write(JSON.stringify(out));
}
