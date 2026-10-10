#!/usr/bin/env node
// PreToolUse hook for Bash: intercept destructive commands that vibe-coders
// most often regret. Either warn (default) or block.
//
// Behavior controlled by .agentic-security/destructive-guard.json:
//   { "mode": "warn" | "block" | "off", "allowedRoots": ["/abs/path", "~/code"], "disposableDirs": ["/abs/scratch"], "extraPatterns": [{...}] }
//   allowedRoots: deletion is allowed strictly INSIDE these (the root itself is protected). disposableDirs: may be deleted wholesale.
//
// File deletion is PATH-AWARE, not a text match. `rm`, `rmdir`, `unlink` and `find -delete` targets are parsed out of the command,
// resolved (~, $HOME, relative paths, `cd`, symlinks) and allowed ONLY when they are strictly inside an allowed root (default ~/code).
// Anything outside, anything that cannot be resolved statically ($VAR, command substitution, xargs), and the allowed root itself are
// blocked. It cannot see deletion done inside another program (node -e fs.rmSync, python shutil.rmtree): it guards against mistakes,
// it is not a sandbox.
//
// CommonJS, no deps.
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');

const cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const cfgPath = path.join(cwd, '.agentic-security', 'destructive-guard.json');

function readCfg() {
  try { return JSON.parse(fs.readFileSync(cfgPath, 'utf8')); }
  catch { return { mode: 'block', extraPatterns: [] }; }
}

function readStdinJSON() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', c => { data += c; });
    process.stdin.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
  });
}

// Each pattern: regex + plain-English explanation of WHY this is dangerous
// + what to do instead. Severity drives block vs warn behavior.
const PATTERNS = [
  // File deletion (rm, rmdir, unlink, find -delete) is NOT matched here: see analyzeDeletes below, which is path-aware.
  {
    name: 'DROP TABLE / DROP DATABASE',
    severity: 'critical',
    re: /\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE)\b/i,
    why: 'DDL drops are not transactional in most DBs — there is no rollback. If this targets production, your data is gone.',
    instead: 'Take a backup first:  pg_dump | psql > backup.sql   /  supabase db dump  /  mysqldump -u root db > backup.sql',
  },
  {
    name: 'supabase db reset',
    severity: 'critical',
    re: /\bsupabase\s+db\s+reset\b/,
    why: 'Wipes ALL data, recreates the schema, and re-seeds. Production-pointing config = production wipe.',
    instead: 'Confirm you are on the LOCAL project: cat supabase/config.toml | grep project_id  — and that no remote is linked.',
  },
  {
    name: 'git push --force / -f to a shared branch',
    severity: 'critical',
    re: /\bgit\s+push\s+(?:--force|-f|--force-with-lease(?!\s+))\b/,
    why: 'Force-push can overwrite teammates work on main / master / develop / any branch others have based PRs on.',
    instead: 'Use --force-with-lease and only on branches you own. Never on protected branches.',
  },
  {
    name: 'git push --force to main / master',
    severity: 'critical',
    re: /\bgit\s+push\s+(?:--force|-f|--force-with-lease)\s+\S+\s+(?:main|master|production|prod)\b/,
    why: 'Force-pushing to main/master rewrites the canonical history and can silently delete commits visible to everyone.',
    instead: "Don't. Revert the bad commit instead:  git revert <sha> && git push",
  },
  {
    name: 'git reset --hard with unsaved changes',
    severity: 'high',
    re: /\bgit\s+reset\s+--hard\b/,
    why: "git reset --hard discards all local changes — and stashed changes if you'd recently popped. There is no undo.",
    instead: 'First `git stash` to save current changes, OR `git reflog` to find the SHA you want to return to without losing work.',
  },
  {
    name: 'git clean -fdx',
    severity: 'high',
    re: /\bgit\s+clean\s+-[fdxnq]+/,
    why: 'git clean -fdx removes untracked AND gitignored files — that includes .env, node_modules build caches, and any in-progress files you forgot to git add.',
    instead: 'Dry-run first: git clean -fdxn   then targeted cleans only.',
  },
  {
    name: 'vercel --prod / vercel deploy --prod without a build step',
    severity: 'high',
    re: /\bvercel\s+(?:--prod|deploy\s+--prod|\.\.\.\s+--prod)\b/,
    why: 'Direct prod deploy skips preview-environment review. If anything is broken, your users see it.',
    instead: 'Deploy to preview first:  vercel deploy   then promote after verification:  vercel promote <url>',
  },
  {
    name: 'curl | sh / wget | bash',
    severity: 'high',
    re: /(?:curl|wget)\s+[^|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|fish)/,
    why: 'Piping a remote script straight into a shell is a supply-chain attack vector. The download server controls what executes on your machine.',
    instead: 'Download to a file first, inspect it, THEN execute:  curl -o /tmp/inst.sh URL && less /tmp/inst.sh && bash /tmp/inst.sh',
  },
  {
    name: 'chmod 777 on a file or directory',
    severity: 'high',
    re: /\bchmod\s+(?:-R\s+)?777\b/,
    why: 'World-writable permissions let any local process modify the target. On shared hosts this is exploited.',
    instead: 'Use the most restrictive mode that works:  chmod 644 (files) / chmod 755 (dirs / executables).',
  },
  {
    name: 'aws s3 rm --recursive',
    severity: 'critical',
    re: /\baws\s+s3\s+(?:rm|sync)\b[^|;\n]*--recursive/,
    why: 'aws s3 rm --recursive on a bucket is irreversible unless versioning is enabled. Vibe-coders rarely enable versioning.',
    instead: 'Verify the bucket: aws s3 ls s3://<bucket>/    Check versioning: aws s3api get-bucket-versioning --bucket <bucket>',
  },
  {
    name: 'docker system prune -a',
    severity: 'high',
    re: /\bdocker\s+system\s+prune\s+(?:-a|--all)\b/,
    why: 'Removes ALL unused images, containers, networks, and volumes — including ones you forgot you needed.',
    instead: 'Prune scoped: docker container prune  /  docker image prune   (without -a).',
  },
];


// ── Path-aware deletion analysis ────────────────────────────────────────────
const HOME = os.homedir();
function expandHome(w) {
  if (w === '~' || w === '$HOME' || w === '${HOME}') return HOME;
  const m = /^(?:~|\$HOME|\$\{HOME\})\//.exec(w);
  return m ? path.join(HOME, w.slice(m[0].length)) : w;
}
// realpath of the nearest existing ancestor plus the not-yet-existing remainder: a symlink inside an allowed root that points outside
// cannot let a deletion escape, and a target that does not exist yet is judged by where it WOULD be.
function realish(p) {
  let cur = p; const rest = [];
  for (;;) {
    try { return path.join(fs.realpathSync(cur), ...rest.slice().reverse()); } catch { /* keep climbing */ }
    const up = path.dirname(cur);
    if (up === cur) return p;
    rest.push(path.basename(cur)); cur = up;
  }
}
function allowedRootsFrom(cfg) {
  const list = Array.isArray(cfg.allowedRoots) && cfg.allowedRoots.length ? cfg.allowedRoots : [path.join(HOME, 'code')];
  return list.map((r) => expandHome(String(r))).filter((r) => path.isAbsolute(r)).map((r) => realish(path.resolve(r)));
}

// `disposableDirs`: directories that may be deleted wholesale, themselves included (scratch work areas). Unlike allowedRoots, where
// the root itself is protected.
function disposableFrom(cfg) {
  return (Array.isArray(cfg.disposableDirs) ? cfg.disposableDirs : []).map((r) => expandHome(String(r))).filter((r) => path.isAbsolute(r) && path.resolve(r) !== path.parse(path.resolve(r)).root).map((r) => realish(path.resolve(r)));
}

function matchParen(src, open) {
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === '(') depth++;
    else if (src[i] === ')') { depth--; if (depth === 0) return i; }
  }
  return src.length;
}
const isVarStart = (src, i) => src[i] === '$' && /[A-Za-z_{@*#?!0-9]/.test(src[i + 1] || '') && !/^\$(?:HOME|\{HOME\})(?![A-Za-z0-9_])/.test(src.slice(i, i + 8));

// Quote-aware split of a shell command into segments of words. Heredoc bodies are skipped. $(...) and `...` bodies are returned
// separately so they are analysed as commands too, and a word containing an unresolvable expansion is flagged `unresolved`.
function splitShell(src) {
  const segments = []; const subs = [];
  let words = []; let cur = ''; let has = false; let unresolved = false;
  const endWord = () => { if (has) words.push({ text: cur, unresolved }); cur = ''; has = false; unresolved = false; };
  const endSeg = () => { endWord(); if (words.length) segments.push(words); words = []; };
  const heredocs = [];
  let i = 0; const n = src.length;
  while (i < n) {
    const c = src[i];
    if (c === '\n') {
      endSeg(); i++;
      while (heredocs.length) {
        const h = heredocs.shift();
        while (i < n) {
          let j = src.indexOf('\n', i); if (j < 0) j = n;
          const line = src.slice(i, j); i = Math.min(j + 1, n);
          if ((h.strip ? line.trim() : line) === h.word) break;
        }
      }
      continue;
    }
    if (c === '\\' && i + 1 < n) { if (src[i + 1] !== '\n') { cur += src[i + 1]; has = true; } i += 2; continue; }
    if (c === '#' && !has) { while (i < n && src[i] !== '\n') i++; continue; }
    if (c === "'") { const j = src.indexOf("'", i + 1); const end = j < 0 ? n : j; cur += src.slice(i + 1, end); has = true; i = end + 1; continue; }
    if (c === '"') {
      i++; has = true;
      while (i < n && src[i] !== '"') {
        if (src[i] === '\\' && i + 1 < n) { cur += src[i + 1]; i += 2; continue; }
        if (src[i] === '$' && src[i + 1] === '(') { const e = matchParen(src, i + 1); subs.push(src.slice(i + 2, e)); cur += '$(...)'; unresolved = true; i = e + 1; continue; }
        if (src[i] === '`') { const e = src.indexOf('`', i + 1); const end = e < 0 ? n : e; subs.push(src.slice(i + 1, end)); cur += '`...`'; unresolved = true; i = end + 1; continue; }
        if (isVarStart(src, i)) unresolved = true;
        cur += src[i]; i++;
      }
      i++; continue;
    }
    if (c === '$' && src[i + 1] === '(') { const e = matchParen(src, i + 1); subs.push(src.slice(i + 2, e)); cur += '$(...)'; has = true; unresolved = true; i = e + 1; continue; }
    if (c === '`') { const e = src.indexOf('`', i + 1); const end = e < 0 ? n : e; subs.push(src.slice(i + 1, end)); cur += '`...`'; has = true; unresolved = true; i = end + 1; continue; }
    if (isVarStart(src, i)) unresolved = true;
    if (c === '<' && src[i + 1] === '<' && src[i + 2] !== '<') {
      let j = i + 2; let strip = false; if (src[j] === '-') { strip = true; j++; }
      while (src[j] === ' ' || src[j] === '\t') j++;
      let q = null; if (src[j] === "'" || src[j] === '"') { q = src[j]; j++; }
      let w = ''; while (j < n && !/[\s'";|&<>()]/.test(src[j])) { w += src[j]; j++; }
      if (q && src[j] === q) j++;
      if (w) heredocs.push({ word: w, strip });
      endWord(); i = j; continue;
    }
    if (c === ';' || c === '|' || c === '&' || c === '(' || c === ')') { endSeg(); i++; continue; }
    if (c === '>' || c === '<') { // a redirection is not a command word: skip the operator and its target
      endWord(); i++; if (src[i] === '>' || src[i] === '&') i++; while (src[i] === ' ') i++;
      while (i < n && !/[\s;|&()]/.test(src[i])) i++;
      continue;
    }
    if (c === ' ' || c === '\t') { endWord(); i++; continue; }
    cur += c; has = true; i++;
  }
  endSeg();
  return { segments, subs };
}

const WRAPPERS = new Set(['sudo', 'doas', 'env', 'command', 'builtin', 'time', 'nohup', 'nice', 'exec', 'xargs', 'stdbuf', 'ionice']);
const DELETERS = new Set(['rm', 'rmdir', 'unlink', 'shred', 'trash']);
const base = (w) => path.basename(w);

/**
 * Every deletion target in `command` that is not strictly inside an allowed root, as [{ target, reason }].
 * `startCwd` is where the hook runs; a `cd` between segments is followed when its argument is literal, and relative targets after a
 * `cd` that cannot be resolved are refused rather than guessed.
 */
function analyzeDeletes(command, { roots, startCwd, disposable = [] }) {
  const bad = []; const seen = new Set();
  const run = (src, cwdIn, depth) => {
    if (depth > 4) { bad.push({ target: '(nested)', reason: 'command substitution nested too deeply to check' }); return; }
    const { segments, subs } = splitShell(src);
    let cwd = cwdIn; // null = unknown
    for (const sub of subs) run(sub, cwd, depth + 1);
    for (const seg of segments) {
      let k = 0; let viaXargs = false;
      while (k < seg.length) {
        const w = seg[k].text;
        if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) { k++; continue; }
        if (WRAPPERS.has(base(w))) { if (base(w) === 'xargs') viaXargs = true; k++; while (k < seg.length && /^-/.test(seg[k].text)) k++; continue; }
        break;
      }
      if (k >= seg.length) continue;
      const cmd = base(seg[k].text); const args = seg.slice(k + 1);
      if (cmd === 'cd' || cmd === 'pushd') {
        const t = args.find((a) => !/^-/.test(a.text));
        if (!t) { cwd = HOME; continue; }
        const dest = expandHome(t.text);
        if (t.unresolved || t.text === '-' || (cwd === null && !path.isAbsolute(dest))) { cwd = null; continue; }
        cwd = path.resolve(cwd || startCwd, dest);
        continue;
      }
      let targets;
      if (DELETERS.has(cmd)) {
        targets = args.filter((a) => a.unresolved || !/^-/.test(a.text) || a.text === '-');
      } else if (cmd === 'find') {
        const deletes = args.some((a) => a.text === '-delete') || args.some((a, i) => /^-(?:exec|execdir|ok|okdir)$/.test(a.text) && DELETERS.has(base((args[i + 1] || {}).text || '')));
        if (!deletes) continue;
        targets = [];
        for (const a of args) { if (!a.unresolved && /^[-!(]/.test(a.text)) break; targets.push(a); }
        if (!targets.length) targets = [{ text: '.', unresolved: false }];
      } else continue;
      if (viaXargs && cmd !== 'find') { bad.push({ target: `${cmd} (via xargs)`, reason: 'targets come from standard input and cannot be checked; pass explicit paths' }); continue; }
      if (!targets.length) {
        if (/^-[a-zA-Z]*[rR]/.test((args.find((a) => /^-/.test(a.text)) || {}).text || '')) bad.push({ target: '(none)', reason: `${cmd} with a recursive flag and no target` });
        continue;
      }
      for (const t of targets) {
        const key = `${cwd}|${t.text}`; if (seen.has(key)) continue; seen.add(key);
        if (t.unresolved) { bad.push({ target: t.text, reason: 'the target contains a variable or command substitution, so where it points cannot be checked' }); continue; }
        const raw = expandHome(t.text);
        if (!path.isAbsolute(raw) && cwd === null) { bad.push({ target: t.text, reason: 'a relative path after a `cd` whose destination cannot be determined' }); continue; }
        const g = raw.search(/[*?[]/);
        if (g >= 0 && /\.\./.test(raw.slice(g))) { bad.push({ target: t.text, reason: 'a glob that climbs with ..' }); continue; }
        const literal = g < 0 ? raw : (raw.slice(0, raw.lastIndexOf('/', g) + 1) || '.');
        const real = realish(path.resolve(cwd || startCwd, literal));
        const strictlyInside = roots.some((r) => real !== r && real.startsWith(r + path.sep));
        const globOfRoot = g >= 0 && roots.some((r) => real === r);   // `rm ~/code/*` deletes things inside the root, not the root
        const inDisposable = disposable.some((r) => real === r || real.startsWith(r + path.sep));
        if (!strictlyInside && !globOfRoot && !inDisposable) {
          const isRoot = roots.includes(real);
          bad.push({ target: t.text, reason: isRoot ? 'that is the allowed root itself, not something inside it' : `${real} is outside the allowed root(s): ${roots.join(', ')}` });
        }
      }
    }
  };
  run(command, startCwd, 0);
  return bad;
}

function formatViolation(cmd, violations, mode, willBlock) {
  const lines = [];
  const head = willBlock
    ? `🛑 agentic-security: BLOCKED destructive command`
    : `⚠️  agentic-security: this command is destructive`;
  lines.push(head);
  lines.push('');
  lines.push(`  Command:`);
  lines.push(`    ${cmd}`);
  lines.push('');
  for (const v of violations) {
    lines.push(`  [${v.severity.toUpperCase()}] ${v.name}`);
    lines.push(`    Why:     ${v.why}`);
    lines.push(`    Instead: ${v.instead}`);
    lines.push('');
  }
  if (mode === 'block') {
    lines.push('To proceed anyway:');
    lines.push('  1. (Recommended) Run the safer alternative shown above.');
    lines.push('  2. Or, set .agentic-security/destructive-guard.json mode="warn".');
    lines.push('  3. Or, run the command yourself in a regular terminal.');
  }
  return lines.join('\n');
}


if (require.main !== module) module.exports = { analyzeDeletes, splitShell, allowedRootsFrom, disposableFrom };
else (async () => {
  const cfg = readCfg();
  if (cfg.mode === 'off') process.exit(0);

  const evt = await readStdinJSON();
  const tool = evt.tool_name || evt.toolName;
  if (tool !== 'Bash') process.exit(0);

  // X-505: capability policy advice (inert unless the operator enabled the feature
  // and named a manifest). A shell string cannot be mediated, so this only says so.
  try { const adv = await require('./lib/capability-advice.js').capabilityAdvice(evt); if (adv) process.stderr.write(adv.join('\n') + '\n'); } catch { /* best-effort */ }

  const cmd = (evt.tool_input || {}).command || '';
  if (!cmd) process.exit(0);

  const violations = [];
  for (const p of PATTERNS) {
    if (p.re.test(cmd)) violations.push(p);
  }
  // Deletion is judged by where the targets resolve to, never by the text patterns above.
  try {
    const roots = allowedRootsFrom(cfg);
    for (const d of analyzeDeletes(cmd, { roots, startCwd: cwd, disposable: disposableFrom(cfg) })) {
      violations.push({
        name: `delete outside the allowed root: ${String(d.target).slice(0, 80)}`,
        severity: 'critical',
        why: d.reason,
        instead: `Deletion is only allowed strictly inside ${roots.join(', ')}. Delete it yourself in a terminal, or add its parent to "allowedRoots" in .agentic-security/destructive-guard.json.`,
      });
    }
  } catch (e) {
    violations.push({ name: 'delete check failed (blocked to be safe)', severity: 'critical', why: String(e && e.message), instead: 'Simplify the command.' });
  }
  for (const p of (cfg.extraPatterns || [])) {
    try {
      const re = new RegExp(p.re || p.pattern, 'i');
      if (re.test(cmd)) violations.push({ ...p, name: p.name || 'user-defined pattern' });
    } catch {}
  }

  // ── Dep-add interception ────────────────────────────────────────────────
  // For `npm install <pkg>` / `pip install <pkg>` / etc., validate every
  // requested package against OSV malicious-catalog + typosquat detection
  // + project sca-policy.yml deny list BEFORE the install runs.
  let depViolations = [];
  try {
    // Lazy-load the ESM dep-add-guard from the bundle; tolerate import
    // failure (e.g. when running outside an installed plugin).
    const depGuard = await tryImportDepGuard();
    if (depGuard) {
      const reqs = depGuard.parseInstallCommand(cmd);
      for (const r of reqs) {
        const result = depGuard.inspectPackage({ ...r, scanRoot: cwd });
        if (result.decision === 'deny') {
          depViolations.push({
            name: `dep-add deny: ${r.ecosystem}:${r.name}`,
            severity: 'critical',
            hint: result.reasons.join(' | '),
          });
        } else if (result.decision === 'review') {
          depViolations.push({
            name: `dep-add review: ${r.ecosystem}:${r.name}`,
            severity: 'high',
            hint: result.reasons.join(' | '),
          });
        }
      }
    }
  } catch {}

  const allViolations = [...violations, ...depViolations];
  if (!allViolations.length) process.exit(0);

  const critical = allViolations.some(v => v.severity === 'critical');
  const willBlock = cfg.mode === 'block' && critical;
  const msg = formatViolation(cmd, allViolations, cfg.mode, willBlock);

  process.stderr.write(msg + '\n');
  process.exit(willBlock ? 2 : 0);
})();

async function tryImportDepGuard() {
  try {
    // Try ESM dynamic import for installed plugin layout.
    const mod = await import('@clear-capabilities/agentic-security-scanner/posture/dep-add-guard.js');
    return mod;
  } catch {}
  try {
    // Fall back to relative path for dev / monorepo layout.
    const here = path.dirname(__filename);
    const rel  = path.resolve(here, '..', 'scanner', 'src', 'posture', 'dep-add-guard.js');
    const fileUrl = 'file://' + rel;
    return await import(fileUrl);
  } catch {}
  return null;
}
