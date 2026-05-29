#!/usr/bin/env node
// PreToolUse hook for Bash: intercept destructive commands that vibe-coders
// most often regret. Either warn (default) or block.
//
// Behavior controlled by .agentic-security/destructive-guard.json:
//   { "mode": "warn" | "block" | "off", "extraPatterns": [{...}] }
//
// CommonJS, no deps.
'use strict';
const fs = require('fs');
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
  {
    name: 'rm -rf on a parent / home / root directory',
    severity: 'critical',
    re: /\brm\s+(?:-[rfRv]+\s+|--recursive\s+|--force\s+){1,2}(?:\/|~|\.\.|\$HOME|\/tmp\b|\/var\b)/,
    why: 'rm -rf in or above your home is irreversible. The agent may have computed a path that resolves higher than intended.',
    instead: 'Delete a specific subdirectory by absolute path, or move it to /tmp first as a safety net.',
  },
  {
    name: 'rm -rf without a specific target',
    severity: 'critical',
    re: /\brm\s+-[rfR]+\s*$/m,
    why: 'rm -rf with no target left will likely target the current shell directory or trip a shell expansion.',
    instead: 'Specify the exact path you want to delete.',
  },
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


(async () => {
  const cfg = readCfg();
  if (cfg.mode === 'off') process.exit(0);

  const evt = await readStdinJSON();
  const tool = evt.tool_name || evt.toolName;
  if (tool !== 'Bash') process.exit(0);

  const cmd = (evt.tool_input || {}).command || '';
  if (!cmd) process.exit(0);

  const violations = [];
  for (const p of PATTERNS) {
    if (p.re.test(cmd)) violations.push(p);
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
