// R18 (PRD §5) — semantic IaC (Terraform), variable-resolving.
//
// Regex IaC (engine.js scanIaC) matches literals on one line. Its blind spot is
// indirection: `cidr_blocks = [var.ingress]` where `variable "ingress"` defaults
// to "0.0.0.0/0" is wide-open, but the literal never appears on the resource
// line. This resolves `variable` defaults and `local` values, then evaluates a
// few high-signal misconfigurations on the RESOLVED value — catching what the
// literal scan misses, and reporting when the exposure arrives via a variable.
//
// Regex-based HCL (no new dep, consistent with the repo); bounded to the
// highest-signal AWS checks. Real `terraform plan` ingestion is the remainder.

const VAR_DEFAULT = /variable\s+"([^"]+)"\s*\{[^{}]*?default\s*=\s*(?:"([^"]*)"|(\[[^\]]*\]|true|false|[\w.\-]+))/g;
const LOCAL_BLOCK = /locals\s*\{([\s\S]*?)\n\}/g;

function buildResolver(text) {
  const vars = new Map();
  let m;
  VAR_DEFAULT.lastIndex = 0;
  while ((m = VAR_DEFAULT.exec(text))) vars.set(m[1], (m[2] !== undefined ? m[2] : m[3] || '').trim());
  const locals = new Map();
  LOCAL_BLOCK.lastIndex = 0;
  while ((m = LOCAL_BLOCK.exec(text))) {
    for (const line of m[1].split('\n')) {
      const lm = line.match(/^\s*([A-Za-z_][\w-]*)\s*=\s*(?:"([^"]*)"|([\w.\-]+))/);
      if (lm) locals.set(lm[1], (lm[2] !== undefined ? lm[2] : lm[3] || '').trim());
    }
  }
  // Resolve a raw attribute value (possibly `var.x`, `local.y`, a list, or literal).
  return function resolve(raw) {
    if (raw == null) return { value: '', viaVar: false };
    // Strip bracket/brace/quote noise anywhere (the attr capture can include a
    // trailing `}` / `]`), so a `var.x` token matches the resolver exactly.
    let v = String(raw).replace(/[[\]{}'"]/g, '').trim();
    const vm = v.match(/^var\.([\w-]+)$/);
    if (vm && vars.has(vm[1])) return { value: vars.get(vm[1]), viaVar: true, varName: vm[1] };
    const lm = v.match(/^local\.([\w-]+)$/);
    if (lm && locals.has(lm[1])) return { value: locals.get(lm[1]), viaVar: true, varName: `local.${lm[1]}` };
    return { value: v, viaVar: false };
  };
}

function lineOf(text, idx) { return text.slice(0, idx).split('\n').length; }

const CHECKS = [
  {
    id: 'open-ingress', cwe: 'CWE-284', sev: 'high',
    attr: /\b(?:cidr_blocks|ipv6_cidr_blocks)\s*=\s*(\[?[^\n]+)/g,
    bad: (val) => /\b0\.0\.0\.0\/0\b|::\/0\b/.test(val),
    vuln: 'Terraform: security-group ingress open to the world (0.0.0.0/0)',
    fix: 'Restrict cidr_blocks to known networks; never default an ingress CIDR to 0.0.0.0/0.',
  },
  {
    id: 'public-bucket', cwe: 'CWE-732', sev: 'high',
    attr: /\bacl\s*=\s*(\S+)/g,
    bad: (val) => /^public-read(?:-write)?$/.test(val),
    vuln: 'Terraform: S3 bucket ACL is public',
    fix: 'Set acl = "private" and use bucket policies / least-privilege grants instead of a public ACL.',
  },
  {
    id: 'public-db', cwe: 'CWE-668', sev: 'high',
    attr: /\bpublicly_accessible\s*=\s*(\S+)/g,
    bad: (val) => /^true$/i.test(val),
    vuln: 'Terraform: database instance is publicly accessible',
    fix: 'Set publicly_accessible = false; place the DB in a private subnet.',
  },
];

export function scanTerraform(fp, raw) {
  if (typeof raw !== 'string' || !raw) return [];
  if (!/\.tf$/i.test(fp)) return [];
  const resolve = buildResolver(raw);
  const findings = [];
  const seen = new Set();
  for (const check of CHECKS) {
    const re = new RegExp(check.attr.source, check.attr.flags);
    let m;
    while ((m = re.exec(raw))) {
      const rawVal = m[1];
      // A literal list may hold several entries; resolve each token.
      const tokens = rawVal.replace(/^\[|\]$/g, '').split(',').map(t => t.trim()).filter(Boolean);
      let hit = null;
      for (const tok of tokens.length ? tokens : [rawVal]) {
        const r = resolve(tok);
        if (check.bad(r.value)) { hit = r; break; }
      }
      if (!hit) continue;
      const line = lineOf(raw, m.index);
      const key = `${check.id}:${line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        id: `iac-tf:${check.id}:${fp}:${line}`,
        severity: check.sev,
        file: fp,
        line,
        vuln: check.vuln,
        cwe: check.cwe,
        family: 'iac-misconfig',
        parser: 'IAC-TF',
        description: `${check.vuln}.${hit.viaVar ? ` The unsafe value arrives via \`${hit.varName}\` (resolved to "${hit.value}") — a literal-only scan would miss this.` : ''}`,
        remediation: check.fix,
      });
    }
  }
  return findings;
}
