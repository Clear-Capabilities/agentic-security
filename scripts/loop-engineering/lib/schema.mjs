// Minimal JSON Schema subset validator (type, required, properties, items,
// enum, const, pattern, minimum, maximum, minItems, minLength, additionalProperties).
// The loop tooling is deliberately dependency-free so it can run before any
// `npm install` and cannot be broken by a scanner dependency change.
export function validate(schema, value, path = '$') {
  const errs = [];
  const err = (m) => errs.push(`${path}: ${m}`);
  if (schema.const !== undefined && value !== schema.const) err(`must equal ${JSON.stringify(schema.const)}`);
  if (schema.enum && !schema.enum.includes(value)) err(`must be one of ${JSON.stringify(schema.enum)}`);
  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    const actual = value === null ? 'null' : Array.isArray(value) ? 'array' : Number.isInteger(value) ? 'integer' : typeof value;
    const ok = types.some((t) => t === actual || (t === 'number' && actual === 'integer'));
    if (!ok) { err(`expected ${types.join('|')}, got ${actual}`); return errs; }
  }
  if (typeof value === 'string') {
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) err(`does not match ${schema.pattern}`);
    if (schema.minLength != null && value.length < schema.minLength) err(`shorter than ${schema.minLength}`);
  }
  if (typeof value === 'number') {
    if (schema.minimum != null && value < schema.minimum) err(`below minimum ${schema.minimum}`);
    if (schema.maximum != null && value > schema.maximum) err(`above maximum ${schema.maximum}`);
  }
  if (Array.isArray(value)) {
    if (schema.minItems != null && value.length < schema.minItems) err(`fewer than ${schema.minItems} items`);
    if (schema.items) value.forEach((v, i) => errs.push(...validate(schema.items, v, `${path}[${i}]`)));
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const r of schema.required || []) if (!(r in value)) err(`missing required property "${r}"`);
    const props = schema.properties || {};
    for (const [k, s] of Object.entries(props)) if (k in value) errs.push(...validate(s, value[k], `${path}.${k}`));
    if (schema.additionalProperties === false) {
      for (const k of Object.keys(value)) if (!(k in props)) err(`unexpected property "${k}"`);
    } else if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
      for (const [k, v] of Object.entries(value)) if (!(k in props)) errs.push(...validate(schema.additionalProperties, v, `${path}.${k}`));
    }
  }
  return errs;
}
