// A set-by-path utility: the path's segments are walked and the last one is written, with no prototype-key refusal.
export function setAtPath(target, path, value) {
  const parts = String(path).split('.');
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
    if (from[k] && typeof from[k] === 'object') into[k] = deepMerge(into[k] || {}, from[k]);
    else into[k] = from[k];
  }
  return into;
}
