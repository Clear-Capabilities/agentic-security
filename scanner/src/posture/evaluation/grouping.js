// Leakage-safe grouping and splitting (QA-001.AC02).
//
// Related samples must land on the same side of the development/sealed line, or
// the sealed set is not independent of what detector work already saw. Two
// samples are related when they share any of: a vulnerable/fixed pair, an
// upstream project (a fork resolves to its parent), an advisory id (duplicate
// advisories), a commit, or a near-identical template fingerprint. Relations are
// transitive (union-find), so a chain A~B~C is one group.
//
// Pure and deterministic: group ids and split assignment depend only on the
// targets and an explicit salt, never on iteration order or a clock.

import * as crypto from 'node:crypto';

/** `https://GitHub.com/Org/Repo.git/` and `git@github.com:org/repo` normalise to `github.com/org/repo`. */
export function normalizeUpstream(url) {
  if (typeof url !== 'string' || !url.trim()) return null;
  let u = url.trim().toLowerCase();
  u = u.replace(/^[a-z+]+:\/\//, '').replace(/^git@/, '').replace(/^[^@/]+@/, '');
  u = u.replace(':', '/').replace(/\/+$/, '').replace(/\.git$/, '');
  return u || null;
}

class UnionFind {
  constructor(ids) { this.parent = new Map(ids.map((i) => [i, i])); }
  find(x) { let r = x; while (this.parent.get(r) !== r) r = this.parent.get(r); this.parent.set(x, r); return r; }
  union(a, b) { const ra = this.find(a); const rb = this.find(b); if (ra !== rb) this.parent.set(ra < rb ? rb : ra, ra < rb ? ra : rb); }
}

const KEYS = (t) => {
  const k = [];
  if (t.pairId) k.push(['pair', t.pairId]);
  const up = normalizeUpstream(t.upstream);
  if (up) k.push(['upstream', up]);
  const fork = normalizeUpstream(t.forkOf);
  if (fork) k.push(['upstream', fork]);
  for (const a of t.advisoryIds || []) k.push(['advisory', String(a).toUpperCase()]);
  for (const c of [t.preCommit, t.postCommit]) if (c) k.push(['commit', c]);
  if (t.templateFingerprint) k.push(['template', t.templateFingerprint]);
  return k;
};

/**
 * Group targets by every relation above. Returns `{ groups, groupOf }` where each
 * group is `{ groupId, members[], reasons[] }`, members sorted, groups sorted.
 */
export function groupTargets(targets) {
  const list = (targets || []).filter((t) => t && t.id);
  const uf = new UnionFind(list.map((t) => t.id));
  const byKey = new Map();
  for (const t of list) {
    for (const [kind, val] of KEYS(t)) {
      const key = `${kind}:${val}`;
      if (byKey.has(key)) uf.union(byKey.get(key).id, t.id);
      else byKey.set(key, t);
    }
  }
  const members = new Map();
  for (const t of list) { const r = uf.find(t.id); if (!members.has(r)) members.set(r, []); members.get(r).push(t.id); }
  // Which relation kinds actually linked two or more members of each group.
  const kindCount = new Map();
  for (const t of list) {
    for (const [kind, val] of KEYS(t)) {
      const gk = `${uf.find(t.id)}|${kind}:${val}`;
      kindCount.set(gk, (kindCount.get(gk) || 0) + 1);
    }
  }
  const groups = [];
  const groupOf = {};
  for (const [root, ids] of members) {
    ids.sort();
    const reasons = new Set();
    for (const [gk, n] of kindCount) if (n > 1 && gk.startsWith(`${root}|`)) reasons.add(gk.slice(root.length + 1).split(':')[0]);
    const groupId = `grp:${crypto.createHash('sha256').update(ids.join('\n')).digest('hex').slice(0, 16)}`;
    groups.push({ groupId, members: ids, reasons: [...reasons].sort() });
    for (const id of ids) groupOf[id] = groupId;
  }
  groups.sort((a, b) => a.groupId.localeCompare(b.groupId));
  return { groups, groupOf };
}

/**
 * Deterministically assign whole groups to development or sealed. A group's side
 * is a function of its id and the salt only, so adding an unrelated target never
 * moves an existing group, and no group can straddle the line.
 */
export function assignSplits(groups, { sealedFraction = 0.3, salt = '' } = {}) {
  const dev = []; const sealed = [];
  for (const g of groups) {
    const h = crypto.createHash('sha256').update(`${salt}|${g.groupId}`).digest();
    const u = h.readUInt32BE(0) / 0x100000000;
    (u < sealedFraction ? sealed : dev).push(...g.members);
  }
  return { dev: dev.sort(), sealed: sealed.sort() };
}

/** Groups whose members are spread over both sides. Empty means the split is leakage-safe. */
export function splitStraddles(groups, splits) {
  const dev = new Set(splits?.dev || []); const sealed = new Set(splits?.sealed || []);
  return (groups || []).filter((g) => g.members.some((m) => dev.has(m)) && g.members.some((m) => sealed.has(m)));
}
