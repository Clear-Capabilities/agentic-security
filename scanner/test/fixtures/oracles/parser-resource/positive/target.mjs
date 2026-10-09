// Vulnerable: nested quantifiers backtrack catastrophically on a near-match.
export function parse(input) {
  return /^(a+)+$/.test(input);
}
