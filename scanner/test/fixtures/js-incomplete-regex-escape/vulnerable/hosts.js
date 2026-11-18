export function hostPattern(host) {
  let regexStr = '^https://';
  regexStr += host.replace(/\./g, '\\.');
  return new RegExp(regexStr + '/');
}

export function domainPatterns(domains) {
  return domains.map((d) => `^https?:\/\/${d.replaceAll('.', '\\.')}\/.*`);
}
