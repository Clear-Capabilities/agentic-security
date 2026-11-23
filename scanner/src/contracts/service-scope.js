// Service-scoped, cross-repository context for a contract (contract-driven verification, Epic D).
//
// A contract names repositories by id and exact revision. Where those repositories are on disk is OPERATOR configuration, never the
// contract's: `rootMap` maps a repository id to a local root the operator supplied, and `authorized` lists the ids the operator allows
// this run to read. Nothing here clones, fetches or holds a credential. Each repository resolves to one state, reusing the deployment
// boundary graph's gap codes so the two layers speak one vocabulary:
//
//   resolved                the root exists, is a git checkout, and its HEAD is the contract's revision
//   access-denied           the contract names it, the operator did not authorise it: it is not read at all
//   repository-unavailable  authorised, but no root was supplied or the root does not exist
//   revision-unknown        the root is not a git checkout, so its revision cannot be established
//   version-mismatch        the checkout is at another commit than the contract pins
//
// A scope with any unresolved repository is `partial`, and every consumer reports it as such: a partial service scope never reads as
// complete service coverage (D-AC04, D-AC06).
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { hardenGitArgs, hardenGitEnv } from '../util/git-hardening.js';
import { GAP_CODES } from '../lineage/deployment/boundary-graph.js';

const STATES = Object.freeze(['resolved', 'access-denied', 'repository-unavailable', 'revision-unknown', 'version-mismatch']);
for (const s of STATES.slice(1)) if (!GAP_CODES.includes(s)) throw new Error(`service-scope state ${s} is not a boundary gap code`);

function headOf(root) {
  try {
    const r = spawnSync('git', hardenGitArgs(['rev-parse', '--verify', 'HEAD']), { cwd: root, encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'], env: hardenGitEnv() });
    return r.status === 0 ? r.stdout.trim() : null;
  } catch { return null; }
}

/**
 * @param {object} o
 * @param {object} o.contract   a validated service contract
 * @param {Record<string,string>} o.rootMap  repository id -> local root (operator configuration)
 * @param {string[]} o.authorized  repository ids the operator allows this run to read
 * @param {function} [o.readHead]  test seam: root -> commit or null
 */
export function resolveServiceScope({ contract, rootMap = {}, authorized = [], readHead = headOf } = {}) {
  const allow = new Set(authorized);
  const repositories = [];
  for (const repo of contract?.scope?.repositories || []) {
    const base = { id: repo.id, revision: repo.revision, root: null, observedRevision: null };
    if (!allow.has(repo.id)) { repositories.push({ ...base, state: 'access-denied', reason: 'the operator did not authorise this repository for the run; it was not read' }); continue; }
    const root = typeof rootMap[repo.id] === 'string' ? path.resolve(rootMap[repo.id]) : null;
    if (!root || !fs.existsSync(root) || !fs.statSync(root).isDirectory()) { repositories.push({ ...base, state: 'repository-unavailable', reason: root ? 'the supplied root does not exist' : 'no local root was supplied for this repository' }); continue; }
    const head = readHead(root);
    if (!head) { repositories.push({ ...base, root, state: 'revision-unknown', reason: 'the root is not a git checkout, so its revision cannot be established' }); continue; }
    if (head !== repo.revision) { repositories.push({ ...base, root, observedRevision: head, state: 'version-mismatch', reason: `the checkout is at ${head.slice(0, 12)}, the contract pins ${repo.revision.slice(0, 12)}` }); continue; }
    repositories.push({ ...base, root, observedRevision: head, state: 'resolved', reason: null });
  }
  const unresolved = repositories.filter((r) => r.state !== 'resolved');
  return { repositories, complete: repositories.length > 0 && unresolved.length === 0, state: unresolved.length ? 'partial' : 'complete', gaps: unresolved.map((r) => ({ code: r.state, repository: r.id, message: r.reason })) };
}

// ---- identity and authorization propagation (D-02) ------------------------------------------------------------------------------
//
// A bounded, line-level reading of how a principal and a tenant travel between components. Each record names the component (the
// repository), the file and line, the KIND of identity source, and whether that source is established by the component itself:
//
//   signed-claim             a token verified here (`jwt.verify`, `verifyToken`, `verifyIdToken`): established
//   authenticated-session    a session the component authenticated (`req.user` set by its own middleware): established
//   caller-supplied-header   an identity or tenant read from a request header (`x-tenant`, `x-user-id`, `x-forwarded-user`): NOT
//                            established; trusting it is safe only if every ingress strips the client's copy, which no single
//                            repository can show
//   message-field            a tenant or principal read from a queue message body: NOT established unless the consumer verifies a
//                            signature or re-derives the tenant from the record it touches
//
// A header or message identity that reaches a data operation unverified becomes a supported candidate; one whose use cannot be traced
// is an explicit unresolved record. Neither is ever dismissed because "the service is internal" (D-AC02, D-02).
const SIGNED = /\b(?:jwt\.verify|verifyToken|verifyIdToken|verifyJwt|jwtVerify)\s*\(/;
const HEADER_IDENTITY = /\b(?:req|request|ctx\.request|event)\.headers\s*(?:\[\s*['"`](x-(?:tenant(?:-id)?|user(?:-id)?|org(?:-id)?|account(?:-id)?|forwarded-user|principal))['"`]\s*\]|\.get\(\s*['"`](x-(?:tenant(?:-id)?|user(?:-id)?|org(?:-id)?|account(?:-id)?|forwarded-user|principal))['"`]\s*\))/i;
const HEADER_SET = /\.(?:setHeader|set)\s*\(\s*['"`](x-(?:tenant(?:-id)?|user(?:-id)?|org(?:-id)?|forwarded-user|principal))['"`]|headers\s*\[\s*['"`](x-(?:tenant(?:-id)?|user(?:-id)?|org(?:-id)?|forwarded-user|principal))['"`]\s*\]\s*=/i;
const MESSAGE_FIELD = /\b(?:msg|message|job|event|payload|body)\s*\.\s*(tenantId|tenant_id|tenant|orgId|org_id|accountId|userId|user_id)\b/;
const CONSUMER = /\.(?:consume|subscribe|process|on)\s*\(\s*['"`][\w.:-]+['"`]\s*,|\bnew\s+Worker\s*\(|\bonMessage\s*\(/;
const DATA_OP = /\b(?:db|pool|client|repo|store|knex|prisma)\s*\.\s*(?:query|execute|findOne|find|update\w*|insert\w*|delete\w*|remove|save|write|upsert)\s*\(/;
const MAX_FILES = 400; const MAX_BYTES = 400_000;

function linesOf(text) { return String(text).split('\n'); }

/**
 * @param {Array<{repository: string, files: Record<string,string>}>} components  the resolved repositories' sources
 * @returns {{ transitions: object[], candidates: object[], unresolved: object[], limits: object }}
 */
export function identityPropagation(components) {
  const transitions = []; const candidates = []; const unresolved = [];
  let filesRead = 0; let truncated = false;
  for (const comp of components || []) {
    for (const [file, text] of Object.entries(comp.files || {})) {
      if (!/\.(?:m?js|cjs|ts|py)$/i.test(file)) continue;
      if (filesRead >= MAX_FILES || typeof text !== 'string' || text.length > MAX_BYTES) { truncated = true; continue; }
      filesRead += 1;
      const lines = linesOf(text);
      const isConsumer = CONSUMER.test(text);
      const verifies = SIGNED.test(text);
      lines.forEach((l, i) => {
        const line = i + 1;
        if (SIGNED.test(l)) transitions.push({ component: comp.repository, file, line, kind: 'signed-claim', established: true });
        const hs = HEADER_SET.exec(l);
        if (hs) transitions.push({ component: comp.repository, file, line, kind: 'forwards-header', header: (hs[1] || hs[2]).toLowerCase(), established: verifies, note: verifies ? 'set from a claim this component verified' : 'set without a verification in this component' });
        const hr = hs ? null : HEADER_IDENTITY.exec(l); // an assignment to the header is a forward, not a read
        if (hr) {
          const header = (hr[1] || hr[2]).toLowerCase();
          transitions.push({ component: comp.repository, file, line, kind: 'caller-supplied-header', header, established: false });
          const window = lines.slice(i, i + 12).join('\n');
          if (!verifies && DATA_OP.test(window)) candidates.push({ component: comp.repository, file, line, kind: 'spoofable-forwarded-identity', header, statement: `the ${header} header is trusted as the principal's ${/tenant|org|account/.test(header) ? 'tenant' : 'identity'} and reaches a data operation; a client that sends the header itself is believed unless every ingress strips it`, evidence: 'static-pattern', established: false });
          else if (!verifies) unresolved.push({ component: comp.repository, file, line, kind: 'header-identity-use-not-traced', header, statement: 'a header identity is read but its use within twelve lines reaches no recognised data operation; where it goes is unresolved' });
        }
        const mf = MESSAGE_FIELD.exec(l);
        if (mf && isConsumer) {
          transitions.push({ component: comp.repository, file, line, kind: 'message-field', field: mf[1], established: false });
          const window = lines.slice(i, i + 12).join('\n');
          if (!verifies && DATA_OP.test(window)) candidates.push({ component: comp.repository, file, line, kind: 'tenant-from-message-unverified', field: mf[1], statement: `a consumer takes ${mf[1]} from the message body and uses it in a data operation without verifying it; a producer that can enqueue chooses the tenant`, evidence: 'static-pattern', established: false });
          else if (!verifies) unresolved.push({ component: comp.repository, file, line, kind: 'message-identity-use-not-traced', field: mf[1], statement: 'a message identity is read; its use is not traced to a data operation within twelve lines' });
        }
      });
    }
  }
  return { transitions, candidates, unresolved, limits: { filesRead, maxFiles: MAX_FILES, truncated } };
}

/** Read a resolved repository's sources for the propagation analysis (bounded; links and large files are skipped). */
export function readComponentSources(root, { maxFiles = MAX_FILES } = {}) {
  const files = {}; let n = 0;
  const walk = (dir, rel) => {
    for (const d of fs.readdirSync(dir, { withFileTypes: true })) {
      if (n >= maxFiles) return;
      if (d.name.startsWith('.') || d.name === 'node_modules') continue;
      const p = path.join(dir, d.name); const r = rel ? `${rel}/${d.name}` : d.name;
      if (d.isSymbolicLink()) continue;
      if (d.isDirectory()) walk(p, r);
      else if (/\.(?:m?js|cjs|ts|py)$/i.test(d.name) && fs.statSync(p).size <= MAX_BYTES) { files[r] = fs.readFileSync(p, 'utf8'); n += 1; }
    }
  };
  walk(root, '');
  return files;
}
