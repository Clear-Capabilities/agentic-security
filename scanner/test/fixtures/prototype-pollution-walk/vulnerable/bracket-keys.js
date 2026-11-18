export class BracketKeys {
  assign(target, rest, value) {
    const m = rest.match(/^\[(.*?)\]([\s\S]*)$/);
    const key = m[1];
    const tail = m[2];
    if (tail === '') {
      target[key] = value;
      return;
    }
    let child;
    if (key in target) {
      child = target[key];
    } else {
      child = {};
      target[key] = child;
    }
    this.assign(child, tail, value);
  }
}

export function unset(root, path) {
  const parts = path.split('.').filter(Boolean);
  let cur = root;
  for (let i = 0; i < parts.length - 1; i++) {
    if (cur[parts[i]] == null) return;
    cur = cur[parts[i]];
  }
  delete cur[parts[parts.length - 1]];
}
