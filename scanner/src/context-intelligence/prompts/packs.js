//
// Question packs: ONE tightly scoped question per review job, versioned so a prompt change is a different job key and
// a result can be traced to the exact wording that produced it. A pack holds no code and no tools; it is text plus
// the metadata the verifier needs (which protection dimension the question depends on, what family/CWE a candidate
// carries, whether the answer is advisory only).
export const REVIEW_SCHEMA_VERSION = 'context-review/1';

const PACKS = [
  {
    id: 'authz-idor', version: 1, title: 'Object ownership and tenant scoping (IDOR / BOLA)', cwe: 'CWE-639', family: 'access-control', lens: 'ctx-authz-idor',
    dimension: 'ownership', multiBundle: false, advisoryOnly: false,
    invariant: 'A data object selected by an identifier the caller controls must be scoped to the authenticated principal, or that principal\'s tenant, before it is read or modified.',
    question: 'Does this entry point let a caller read or modify a data object chosen by an identifier they control without that object being scoped to their own identity or tenant?',
    guidance: [
      'Trace the untrusted identifier from where it enters to where the object is fetched or changed.',
      'Look for the scoping: a query filter naming the principal or tenant, an ownership comparison that rejects, a policy check, a row-level rule shown in the code.',
      'Authentication alone is NOT ownership. A check that the caller is logged in says nothing about whose object it is.',
      'An unguessable capability token or a public resource intentionally addressed by identifier is not a defect; say so and cite why.',
      'A control that runs after the object has already been read or written does not protect it.',
    ],
  },
  {
    id: 'authz-function', version: 1, title: 'Privileged function access (BFLA)', cwe: 'CWE-285', family: 'access-control', lens: 'ctx-authz-function',
    dimension: 'authorization-role', multiBundle: false, advisoryOnly: false,
    invariant: 'An action that only some roles may perform must check the caller\'s role or permission before it takes effect.',
    question: 'Can a caller without the required role perform a privileged action through this entry point?',
    guidance: [
      'Identify what the action does and who should be allowed to do it, from the code shown.',
      'Look for a role or permission check that rejects, placed before the action. Route-level middleware counts when it is shown.',
      'Impersonation, role parameters taken from the request and administrative paths with only authentication are the usual gaps.',
    ],
  },
  {
    id: 'cross-route-consistency', version: 1, title: 'Authorization consistency across related routes', cwe: 'CWE-863', family: 'access-control', lens: 'ctx-cross-route',
    dimension: 'ownership', multiBundle: true, advisoryOnly: false,
    invariant: 'Routes that operate on the same kind of object must enforce the same authorization rule.',
    question: 'Across the linked entry points, does one of them enforce a weaker authorization rule than its siblings for the same kind of object?',
    guidance: [
      'Compare what each linked entry point checks before it touches the shared object.',
      'Report a difference only when two entry points reach the same object and one lacks a check the other has; cite both.',
      'Different checks for genuinely different objects are not an inconsistency.',
    ],
  },
  {
    id: 'transaction-integrity', version: 1, title: 'Multi-step state change without a transaction', cwe: 'CWE-662', family: 'business-logic', lens: 'ctx-transaction',
    dimension: null, multiBundle: false, advisoryOnly: false,
    invariant: 'A change that must happen together (several writes, or a write and an external effect) must be atomic or compensated.',
    question: 'Does this entry point perform several dependent state changes where a failure part-way leaves the system inconsistent, with no transaction or compensation shown?',
    guidance: ['Name the two or more changes and the failure point between them.', 'A transaction boundary, a single atomic statement or an explicit compensation shown in the code answers the question.'],
  },
  {
    id: 'external-failure', version: 1, title: 'Outbound call failure semantics', cwe: 'CWE-703', family: 'business-logic', lens: 'ctx-external-failure',
    dimension: null, multiBundle: false, advisoryOnly: false,
    invariant: 'A call to an external service must have a bounded wait and a defined behaviour when it fails.',
    question: 'Does this entry point call an external service with no timeout, cancellation, bounded retry or defined failure behaviour, in a way that matters to correctness or security?',
    guidance: ['Cite the call and the missing or present bound.', 'Fail-open behaviour on a security decision is the important case.'],
  },
  {
    id: 'sensitive-audit', version: 1, title: 'Security-sensitive change without audit evidence', cwe: 'CWE-778', family: 'business-logic', lens: 'ctx-audit',
    dimension: null, multiBundle: false, advisoryOnly: false,
    invariant: 'A security-sensitive state change must leave a record of who did what.',
    question: 'Does this entry point make a security-sensitive change (permissions, credentials, money, deletion) with no audit record shown?',
    guidance: ['Name the sensitive change.', 'A call that records the actor and action, shown in the code, answers the question.'],
  },
  {
    id: 'business-invariant', version: 1, title: 'Cross-entity business invariant (advisory)', cwe: 'CWE-840', family: 'business-logic', lens: 'ctx-business-invariant',
    dimension: null, multiBundle: false, advisoryOnly: true,
    invariant: 'State the business rule the code appears to intend, and check the code against it.',
    question: 'Does the code violate a business rule that the code itself, its names or its comments make clear, in a way that crosses entities?',
    guidance: ['State the rule and where the code makes it clear.', 'This is advisory: report only a clear violation and say what you assumed.'],
  },
];

export const QUESTION_PACKS = Object.freeze(PACKS.map(p => Object.freeze({ ...p, guidance: Object.freeze([...p.guidance]) })));

export function packById(id) {
  const base = String(id || '').split('/')[0];
  return QUESTION_PACKS.find(p => p.id === base) || null;
}

/** `authz-idor/1` */
export function packRef(pack) { return `${pack.id}/${pack.version}`; }
