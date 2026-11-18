function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function hostPattern(host) {
  let regexStr = '^https://';
  regexStr += escapeRegex(host);
  return new RegExp(regexStr + '/');
}

export function domainPatterns(domains) {
  return domains.map((d) => `^https?:\/\/${escapeRegex(d)}\/.*`);
}

export function displayVersion(v) {
  return v.replace(/\./g, '\\.');
}
