// Haskell and Nix evidence for the bundled compliance frameworks (X-011).
//
// Frameworks map a control to a finding FAMILY (`family:iac-misconfig`). The Haskell and Nix producers emit more
// specific families (`ssh-access`, `nix-fetch-integrity`, `cmdi`, ...), so each framework family below lists the
// language families whose findings are genuine evidence for it. A family is listed ONLY where the finding is the same
// kind of defect the control is about: a NixOS service running as root evidences a misconfiguration control, a
// floating flake input evidences a supply-chain control. Nothing is mapped because the words look alike.
//
// This is data, not policy: whether a control is satisfied is decided by the existing evaluator.

export const LANGUAGE_FAMILY_ALIASES = Object.freeze({
  // injection and input handling: Nix generated-script injection is the same class as command injection
  'command-injection': ['cmdi'],
  // authentication and access control (Haskell web: WAI/Scotty/Servant/Yesod)
  'auth-missing': ['missing-authentication'],
  'authz': ['broken-object-authorization', 'broken-function-authorization'],
  'broken-access-control': ['broken-object-authorization', 'broken-function-authorization'],
  // credential handling: a secret that lands in the Nix store, a derivation or a log is exposed sensitive data
  'data-exposure': ['secret-in-store', 'secret-in-build', 'secret-in-log', 'sensitive-logging', 'dependency-url-credential'],
  'key-hygiene': ['secret-in-store', 'secret-in-build'],
  // cryptography
  'crypto-weak-hash': ['weak-hash'],
  'crypto-kdf-weak': ['password-hashing'],
  'weak-crypto': ['weak-hash', 'weak-randomness', 'password-hashing'],
  // configuration of hosts, services and containers (NixOS hardening)
  'iac-misconfig': ['ssh-access', 'firewall-exposure', 'systemd-privilege', 'service-identity', 'container-declaration', 'privilege-escalation', 'nix-sandbox', 'nix-eval-native', 'nix-eval-boundary', 'nix-privilege', 'tls-runtime'],
  // software supply chain: unpinned or unverified fetches, cache trust, lock files, overlays, download-and-execute
  'supply-chain': ['nix-cache-trust', 'nix-fetch-integrity', 'nix-fetch-pin', 'nix-flake-lock', 'nix-overlay', 'nix-script-download', 'source-integrity', 'download-exec'],
  // model-assisted features
  'llm-app-security': ['llm-excessive-agency', 'llm-agent-chain', 'agent-config'],
  'agent-tool-exec': ['llm-excessive-agency'],
});

/** Every compliance family a language producer can contribute evidence to (the framework-side names). */
export const LANGUAGE_COMPLIANCE_FAMILIES = Object.freeze(new Set([
  ...Object.keys(LANGUAGE_FAMILY_ALIASES),
  // families whose emitted name already equals the framework name
  'command-injection', 'sql-injection', 'path-traversal', 'ssrf', 'xss', 'xxe', 'hardcoded-secret', 'vulnerable-dep', 'dependency-confusion', 'prompt-injection', 'license-graph', 'insecure-deserialization',
]));

/**
 * Whether Haskell/Nix analysis in this scan was incomplete, and why. An empty bucket under an incomplete analysis is
 * not evidence that a control is met, so the evaluator caps such a control at "partial". Absent information is not
 * treated as incomplete (older scan objects keep their behaviour); only a recorded condition counts.
 */
export function languageAnalysisGaps(scan) {
  const out = { present: false, incomplete: false, reasons: [] };
  const fc = (scan && (scan.fc || scan.fileContents)) || {};
  const files = Object.keys(fc).concat(Object.keys((scan && scan.depFileContents) || {}));
  out.present = files.some((f) => /\.(?:l?hs|hs-boot|hsc|nix)$|\.cabal$|(?:^|\/)(?:cabal\.project|package\.yaml|stack\.yaml|flake\.lock)/i.test(f));
  const h = scan && scan.scanHealth;
  if (!out.present || !h) return out;
  const lc = h.languageCoverage;
  const conds = Array.isArray(h.conditions) ? h.conditions : [];
  const langRe = /language|Haskell|Nix|NixOS|flake|Hackage|manifest|grammar|advisory snapshot|effective|optional mode|required analyzer/i;
  for (const c of conds) if (langRe.test(String(c))) out.reasons.push(String(c));
  if (lc && lc.optionalModes) for (const [name, m] of Object.entries(lc.optionalModes)) if (m && m.selected && !m.ran) out.reasons.push(`optional mode "${name}" was selected but did not run`);
  out.reasons = [...new Set(out.reasons)];
  out.incomplete = out.reasons.length > 0;
  return out;
}
