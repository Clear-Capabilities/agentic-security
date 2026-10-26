// Can this host actually RUN a language inside the proof fabric's sandbox? "The interpreter exists" is not the same as "it runs
// confined": a namespace sandbox may not expose the interpreter's library directory, or may cap the address space below what a JVM
// reserves. A test that needs the language skips, with this reason, instead of failing or (worse) passing vacuously.
// The probe runs one tiny, known-vulnerable reproducer for the language through the real runner in a child process and reports whether
// its oracle fired.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const RUNNER = path.join(path.dirname(fileURLToPath(import.meta.url)), '../../src/posture/proof-fabric/runner.js');
const REPRODUCERS = {
  python: { lang: 'python', files: { 'a.py': "import os, sys\nos.system('echo ' + sys.argv[1])\n" }, run: ['{{PYTHON}}', 'a.py', 'x; touch {{CANARY:command}}'] },
  haskell: { lang: 'haskell', files: { 'Main.hs': 'import System.Environment (getArgs)\nimport System.Process (callCommand)\nmain :: IO ()\nmain = getArgs >>= \\a -> callCommand ("echo " ++ head a)\n' }, run: ['{{GHC}}', '-ignore-dot-ghci', '-e', ':main "x; touch {{CANARY:command}}"', 'Main.hs'] },
  java: { lang: 'java', files: { 'A.java': 'public class A { public static void main(String[] a) throws Exception { new ProcessBuilder("sh", "-c", "echo " + a[0]).inheritIO().start().waitFor(); } }' }, build: ['{{JAVAC}}', '-d', '.', 'A.java'], run: ['{{JAVA}}', '-cp', '.', 'A', 'x; touch {{CANARY:command}}'] },
};
const cache = new Map();

/** @returns {{ok: boolean, reason: string|null}} */
export function sandboxCanRun(lang) {
  if (cache.has(lang)) return cache.get(lang);
  const base = REPRODUCERS[lang];
  let result;
  if (!base) result = { ok: false, reason: `no probe for ${lang}` };
  else {
    const reproducer = { schema: 'agentic-security/reproducer', version: 1, findingId: 'probe', oracle: { type: 'command_execution', params: { canary: 'command' } }, network: 'none', ...base };
    const code = `import { runAttempt, languageSupport } from ${JSON.stringify(`file://${RUNNER}`)};
const sup = languageSupport(${JSON.stringify(lang)});
if (!sup.supported) { console.log(JSON.stringify({ ok: false, reason: sup.reason })); process.exit(0); }
const r = await runAttempt(${JSON.stringify(reproducer)}, { limits: { timeoutMs: 30000, buildTimeoutMs: 60000 } });
console.log(JSON.stringify({ ok: r.status === 'completed' && r.oracle?.fired === true, reason: r.status === 'completed' ? (r.oracle?.fired ? null : 'the oracle did not fire') : \`\${r.status}: \${(r.reasons || []).join('; ')}\` }));`;
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', code], { encoding: 'utf8', timeout: 120000 });
    try { result = JSON.parse(r.stdout.trim().split('\n').pop()); } catch { result = { ok: false, reason: `probe did not answer (${r.status ?? r.signal})` }; }
  }
  cache.set(lang, result);
  return result;
}

/** A node:test `skip` value: false when the language runs here, else the reason. */
export const skipUnlessRuns = (lang) => { const p = sandboxCanRun(lang); return p.ok ? false : `${lang} cannot run in this host's sandbox (${p.reason})`; };
