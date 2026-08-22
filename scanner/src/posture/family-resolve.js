// Shared family-name resolution for compliance mappings.
//
// Extracted into its own module to break an import CYCLE: the evaluator
// (auditor-walkthrough.js) needs the resolver to count findings, and
// coverage-strength.js needs the SAME resolver to measure detector strength. When
// the resolver lived in the evaluator and the evaluator imported strength back,
// ESM handed one side an undefined binding and a defensive try/catch turned that
// into a silently missing `evidence` field — a wrong answer wearing the costume
// of a working one.
//
// One definition, no cycle, both callers import from here.

export const COMPLIANCE_FAMILY_ALIAS = {
  // ASVS spells it `sqli`; every detector emits `sql-injection` (or a
  // language-prefixed variant, which the suffix rule below does NOT cover
  // because the prefix is on the wrong end).
  'sqli': ['sql-injection', 'dart-sql-injection', 'laravel-sql-injection'],
  'auth-missing': ['broken-access-control', 'fastapi-missing-auth', 'springboot-missing-authz', 'laravel-missing-auth', 'quarkus-missing-authz'],
  'authz': ['broken-access-control', 'idor', 'springboot-missing-authz', 'quarkus-missing-authz'],
  'k8s-pod-security-privileged': ['k8s-pod-privileged'],
};

/**
 * The emitted families a `family:X` mapping resolves to, given the families a
 * scan actually produced.
 *
 * Exported because TWO callers must agree: this file's evaluator (does the
 * control have open findings?) and posture/coverage-strength.js (how good is the
 * detector behind it?). When only the evaluator knew the rule, the strength
 * module reported "unmeasured" for every aliased or suffixed mapping — a false
 * "no evidence" verdict on controls that are in fact measured, which is the
 * mirror image of the vacuous-pass bug this file already fixes. One rule, one
 * definition.
 *
 * Resolution is exact match, alias, or `<base>-<rule-slug>` suffix. The `-`
 * separator is load-bearing: without it `nosql-injection` would satisfy a
 * `sql-injection` mapping.
 */
export function resolveFamilyKeys(fam, availableKeys) {
  const bases = [fam, ...(COMPLIANCE_FAMILY_ALIAS[fam] || [])];
  const out = [];
  for (const key of availableKeys) {
    if (bases.some(b => key === b || key.startsWith(`${b}-`))) out.push(key);
  }
  return out;
}

