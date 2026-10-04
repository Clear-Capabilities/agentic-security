// Personal data in Nix configuration (X-004 / HS-011): a `config.<module>.<field>` option whose NAME classifies as personal data
// (PII, PHI, PCI, financial) and that is interpolated into the value of another option. Whatever the value of such an option is
// rendered into (an /etc file, a unit's environment or script, a daemon's configuration text) ends up in the Nix store, which every
// local user can read, so each reference is a field-to-store flow in the data flow graph.
//
// Honest limits:
//   * a reference is judged by its NAME and position only; whether the option holds real personal data is not known;
//   * a reference wrapped in a one-way or size-only function (`builtins.hashString`, `stringLength`) or only compared (`== ""`) is
//     PROTECTED: no flow, and the protection is recorded;
//   * credential-shaped names are the secret analyzer's (NIX-006), not this module's;
//   * static analysis of the written expression only: nothing is evaluated.

import { parseNix } from './nix-parser.js';
import { classifyDataElementName } from '../lineage/classification.js';
import { isLanguageExcludedPath } from './discovery.js';

export const NIX_PRIVACY_VERSION = 'nix-privacy/1';

const PROTECTORS = new Set(['hashString', 'hashFile', 'stringLength', 'length', 'sha256', 'sha512']);
const COMPARISONS = new Set(['==', '!=', '<', '>', '<=', '>=']);
const CONFIG_ROOTS = new Set(['config', 'osConfig']);
const PERSONAL = new Set(['PII', 'PHI', 'PCI', 'FIN', 'GEOLOCATION', 'DEVICE_ID']);

const staticName = (seg) => (seg && seg.kind === 'static' ? seg.name : null);
const keyOf = (path) => (path || []).map(staticName);

/** The destination a rendered value lands in, from the attribute path it is assigned to. Always the Nix store; the label says what. */
export function destinationOf(attr) {
  const p = attr.filter(Boolean);
  const last = p[p.length - 1];
  if (p[0] === 'environment' && p[1] === 'etc') return { label: `/etc/${p[2] || 'file'} (a store file)` };
  if (p[0] === 'systemd') {
    if (last === 'script' || /^(?:preStart|postStart|preStop|postStop|reload)$/.test(last)) return { label: 'a systemd unit script (a store file)' };
    if (p.includes('environment') || last === 'Environment') return { label: 'a systemd unit environment (a store file)' };
    return { label: 'a systemd unit (a store file)' };
  }
  if (p[0] === 'environment' && /^(?:variables|sessionVariables|shellAliases)$/.test(p[1] || '')) return { label: 'system environment variables (a store file)' };
  if (p[0] === 'networking' && p[1] === 'extraHosts') return { label: '/etc/hosts (a store file)' };
  if (p[0] === 'programs' && /^(?:bash|zsh|fish)$/.test(p[1] || '')) return { label: 'shell initialisation (a store file)' };
  return { label: `option ${p.join('.')} (rendered into the Nix store)` };
}

function* children(node) {
  if (!node || typeof node !== 'object') return;
  for (const k of Object.keys(node)) {
    if (k === 'span' || k === 'start' || k === 'end') continue;
    const v = node[k];
    if (Array.isArray(v)) { for (const x of v) if (x && typeof x === 'object') yield x; } else if (v && typeof v === 'object') yield v;
  }
}

const calleeName = (fn) => {
  let f = fn;
  while (f && (f.type === 'app')) f = f.fn;
  if (!f) return null;
  if (f.type === 'ident') return f.name;
  if (f.type === 'select') { const names = keyOf(f.attrpath); return names[names.length - 1] || null; }
  return null;
};

/**
 * @param {{files: Record<string,string>}} opts
 * @returns {{references: object[], gaps: string[]}} one reference per (file, option, personal field) occurrence
 */
export function analyzeNixPersonalData(opts = {}) {
  const references = []; const gaps = [];
  for (const [file, text] of Object.entries(opts.files || {})) {
    if (!/\.nix$/i.test(file) || typeof text !== 'string' || isLanguageExcludedPath(file)) continue;
    let rec;
    try { rec = parseNix(text, { file }); } catch (e) { gaps.push(`${file}: Nix parse failed (${String((e && e.message) || e)})`); continue; }
    if (!rec || !rec.ast) continue;
    const visitValue = (node, attr, line, prot) => {
      if (!node || typeof node !== 'object') return;
      if (node.type === 'select' && node.base && node.base.type === 'ident' && CONFIG_ROOTS.has(node.base.name)) {
        const names = keyOf(node.attrpath);
        if (names.length && names.every(Boolean)) {
          const field = names[names.length - 1];
          const classes = classifyDataElementName(field).classes.filter((c) => PERSONAL.has(c));
          if (classes.length) references.push({ file, line, field, option: `config.${names.join('.')}`, attr, classes, protected: prot });
        }
        return;
      }
      if (node.type === 'app') {
        const name = calleeName(node);
        const nowProt = prot || (name && PROTECTORS.has(name));
        // the callee chain carries no data; its arguments do
        let f = node; const args = [];
        while (f && f.type === 'app') { args.unshift(f.arg); f = f.fn; }
        for (const a of args) visitValue(a, attr, line, nowProt);
        return;
      }
      if (node.type === 'binop' && COMPARISONS.has(node.op)) { visitValue(node.left, attr, line, true); visitValue(node.right, attr, line, true); return; }
      if (node.type === 'if') { visitValue(node.cond, attr, line, true); visitValue(node.then, attr, line, prot); visitValue(node.else, attr, line, prot); return; }
      for (const c of children(node)) visitValue(c, attr, line, prot);
    };
    const visit = (node, attrPath) => {
      if (!node || typeof node !== 'object') return;
      if (node.type === 'attrset') {
        for (const b of node.bindings || []) {
          if (b.kind !== 'attr' || !b.value) continue;
          const full = [...attrPath, ...keyOf(b.path)];
          const line = (b.span && b.span.startLine) || 1;
          // a value that is an attribute set is walked as nested configuration; anything else is a value being assigned
          if (b.value.type === 'attrset') visit(b.value, full);
          else { visitValue(b.value, full, line, false); for (const c of children(b.value)) visit(c, full); }
        }
        return;
      }
      for (const c of children(node)) visit(c, attrPath);
    };
    visit(rec.ast, []);
  }
  return { references, gaps };
}
