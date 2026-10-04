// Strict argument parsing: an unknown flag, a missing value, a duplicate or an
// unexpected positional is an error, never silently ignored (PRD 6.1).
export class UsageError extends Error {
  constructor(msg) { super(msg); this.name = 'UsageError'; }
}

// spec: { flags: { name: { type: 'string'|'boolean'|'number', required?, default? } }, positionals?: number }
export function parseArgs(argv, spec) {
  const out = {};
  const positionals = [];
  const flags = spec.flags || {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') { positionals.push(...argv.slice(i + 1)); break; }
    if (!a.startsWith('--')) { positionals.push(a); continue; }
    let name = a.slice(2);
    let inline;
    const eq = name.indexOf('=');
    if (eq >= 0) { inline = name.slice(eq + 1); name = name.slice(0, eq); }
    const def = flags[name];
    if (!def) throw new UsageError(`unknown option --${name}`);
    if (Object.hasOwn(out, name)) throw new UsageError(`duplicate option --${name}`);
    if (def.type === 'boolean') {
      if (inline !== undefined) throw new UsageError(`--${name} does not take a value`);
      out[name] = true;
      continue;
    }
    let val = inline;
    if (val === undefined) {
      val = argv[++i];
      if (val === undefined || (val.startsWith('--') && val !== '--')) throw new UsageError(`--${name} requires a value`);
    }
    if (def.type === 'number') {
      const n = Number(val);
      if (!Number.isFinite(n)) throw new UsageError(`--${name} must be a number, got "${val}"`);
      out[name] = n;
    } else out[name] = val;
  }
  for (const [name, def] of Object.entries(flags)) {
    if (!Object.hasOwn(out, name)) {
      if (def.required) throw new UsageError(`missing required option --${name}`);
      if (def.default !== undefined) out[name] = def.default;
    }
  }
  const maxPos = spec.positionals ?? 0;
  if (positionals.length > maxPos) throw new UsageError(`unexpected argument "${positionals[maxPos]}"`);
  out._ = positionals;
  return out;
}
