// The same utilities with the prototype keys refused, and a clone into a fresh object.
const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);

export function setAtPath(target, path, value) {
  const parts = String(path).split('.');
  if (parts.some((p) => FORBIDDEN.has(p))) throw new Error('unsafe path');
  let cur = target;
  for (const key of parts.slice(0, -1)) {
    if (cur[key] === undefined) cur[key] = {};
    cur = cur[key];
  }
  cur[parts[parts.length - 1]] = value;
  return target;
}

export function deepMerge(into, from) {
  for (const k in from) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    if (from[k] && typeof from[k] === 'object') into[k] = deepMerge(into[k] || {}, from[k]);
    else into[k] = from[k];
  }
  return into;
}

export function clone(v) {
  if (!v || typeof v !== 'object') return v;
  const out = {};
  for (const k of Object.keys(v)) out[k] = clone(v[k]);
  return out;
}
