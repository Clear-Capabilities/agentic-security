// Runs the fix preview (the same path the CLI `fix`, the MCP synthesize_fix and the LSP use) over the real-code true positives and prints what each
// class of finding gets: a verified patch, or a refusal with its reason. Read-only: nothing is applied.
// usage: node bench/dag/dev-haskell/fix-real.mjs <project id> [--all]
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { disableStateWrites } from '../../_lib/tree-integrity.mjs';
import { loadLanguageProject, languageFixPreview } from '../../../scanner/src/language/context.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const id = process.argv[2];
const all = process.argv.includes('--all');
const root = path.join(HERE, '.cache', id);
await disableStateWrites();
process.env.AGENTIC_SECURITY_DEEP = '1';
delete process.env.CI;
const { runScan } = await import('../../../scanner/src/runScan.js');
const { scan } = await runScan(root);
const project = loadLanguageProject(root);
const files = project.files || project;
const rows = scan.findings.filter((f) => /\.hs$/.test(f.file || '') && f.severity !== 'info' && (all || /Password hashed|Predictable random|Weak hash|Path Traversal|Command|SQL|Cross-Site|Sensitive/.test(f.vuln || '')));
for (const f of rows) {
  let r;
  try { r = await languageFixPreview(f, files); } catch (e) { r = { ok: false, status: 'error', reason: String(e.message) }; }
  console.log(`${f.file}:${f.line} [${f.cwe}] ${String(f.vuln).slice(0, 44).padEnd(44)} -> ${r.status}${r.label ? ` (${r.label})` : ''}${r.ok ? '' : `: ${String(r.reason || '').slice(0, 140)}`}`);
}

// A hand-written patch for the real password-hashing finding (gitit), pushed through the SAME gates a model-proposed patch gets:
// the deterministic fixer refuses this class, so the only route to a verified fix is a reviewed proposal. Static gates only (parse and rescan):
// the patch needs `cryptonite` and `base16-bytestring`, which this host does not build against, so the compile gate is reported as not run.
if (id === 'gitit' && process.argv.includes('--propose')) {
  const { verifyHaskellProposal } = await import('../../../scanner/src/language/haskell-fix.js');
  const file = 'src/Network/Gitit/State.hs';
  const before = files[file];
  const patched = before
    .replace('hashPassword salt pass = showDigest $ sha512 $ L.fromString $ salt ++ pass', 'hashPassword salt pass = BC.unpack (B16.encode (PBKDF2.fastPBKDF2_SHA256 (PBKDF2.Parameters { PBKDF2.iterCounts = 600000, PBKDF2.outputLength = 32 }) (BC.pack pass) (BC.pack salt)))')
    .replace('import Network.Gitit.Types', 'import Network.Gitit.Types\nimport qualified Crypto.KDF.PBKDF2 as PBKDF2\nimport qualified Data.ByteString.Char8 as BC\nimport qualified Data.ByteString.Base16 as B16');
  const f = scan.findings.find((x) => x.file === file && x.cwe === 'CWE-916');
  const v = await verifyHaskellProposal(f, { files, file, proposal: patched });
  console.log(`proposal for ${file} [CWE-916]: ${v.status}; gates: syntax=${v.gates.syntax.ok} rescan=${v.gates.rescan && v.gates.rescan.ok} originalGone=${v.gates.rescan && v.gates.rescan.originalGone} compile=${v.gates.compile.ran ? v.gates.compile.ok : 'not run'}${v.reason ? `; reason: ${v.reason}` : ''}`);
}
