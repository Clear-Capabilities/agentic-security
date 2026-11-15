#!/usr/bin/env node
// Builds the CLI bundle into `dist.staging/` and swaps it into `dist/` at the very end, so the working tree never holds a half-built dist.
// Why: the post-commit warm gate rebuilds in place to check "committed bundle equals a fresh build"; a build that empties `dist/` first (needed
// so stale ncc chunks never ship, 0.195.40) left the tree reading dirty for the length of the build, and a push and a scorecard measurement in
// that window were refused (0.195.41). The steps are the ones the package.json `build` script used to chain.
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..');
const STAGING = path.join(SCANNER, 'dist.staging');
const DIST = path.join(SCANNER, 'dist');

function run(cmd, args, extraEnv = {}) {
  const r = spawnSync(cmd, args, { cwd: SCANNER, stdio: 'inherit', env: { ...process.env, ...extraEnv } });
  if (r.status !== 0) { console.error(`build: ${cmd} ${args.join(' ')} exited ${r.status}`); process.exit(r.status || 1); }
}

run('node', ['scripts/vendor-java-parser.mjs']);
fs.rmSync(STAGING, { recursive: true, force: true });
const ncc = path.join(SCANNER, 'node_modules', '.bin', 'ncc');
run(ncc, ['build', 'bin/agentic-security.js', '-o', 'dist.staging', '--minify', '-e', 'web-tree-sitter', '-e', 'tree-sitter-wasms', '-e', 'z3-solver']);

// the compliance frameworks ship beside the bundle
const frameworks = path.join(STAGING, 'compliance-frameworks');
fs.rmSync(frameworks, { recursive: true, force: true });
fs.mkdirSync(frameworks, { recursive: true });
for (const f of fs.readdirSync(path.join(SCANNER, 'src', 'posture', 'compliance-frameworks'))) if (f.endsWith('.json')) fs.copyFileSync(path.join(SCANNER, 'src', 'posture', 'compliance-frameworks', f), path.join(frameworks, f));

// the Data Flow Explorer frontend
run('node', ['scripts/copy-frontend.mjs'], { AGENTIC_SECURITY_BUILD_DIST: STAGING });

// the bundle: its name, no package.json beside it, executable, a shebang, and the SHA-256 sidecar
const bundle = path.join(STAGING, 'agentic-security.mjs');
fs.renameSync(path.join(STAGING, 'index.js'), bundle);
fs.rmSync(path.join(STAGING, 'package.json'), { force: true });
fs.chmodSync(bundle, 0o755);
const content = fs.readFileSync(bundle, 'utf8');
if (!content.startsWith('#!')) fs.writeFileSync(bundle, '#!/usr/bin/env node\n' + content);
const digest = createHash('sha256').update(fs.readFileSync(bundle)).digest('hex');
fs.writeFileSync(path.join(STAGING, 'agentic-security.mjs.sha256'), `${digest}  agentic-security.mjs\n`);

// the swap: the only moment the tree changes
fs.rmSync(DIST, { recursive: true, force: true });
fs.renameSync(STAGING, DIST);
console.log(`build: dist/ replaced (${fs.readdirSync(DIST).length} entries, bundle sha256 ${digest.slice(0, 12)})`);
