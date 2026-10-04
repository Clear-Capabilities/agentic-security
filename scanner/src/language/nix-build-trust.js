// Nix fetch, build, cache and supply-chain trust rules (NIX-005).
//
// Two halves, one report:
//
//   SOURCE   fetcher calls, flake inputs and locks, script downloads, import-from-derivation
//            and overlay relaxations, read from the parsed Nix AST (nix-parser.js).
//   CONFIG   nix.conf-level settings (trusted-users, signature checking, substituters, sandbox,
//            native evaluation, IFD policy), judged on the EFFECTIVE configuration produced by
//            nixos-module-resolver.js, never on raw text.
//
// Nothing here runs `nix`, evaluates a derivation, fetches a URL or executes an import: IFD and
// custom builders are reported as boundaries, not followed. Every finding is a supply-chain entry
// (`type: 'nix_build_trust'`, `ecosystem: 'nix'`), so SCA policy, SCA verdicts and scan health read
// it from the ordinary supplyChain bucket instead of a side channel.
//
// Three distinctions are kept apart on purpose:
//   - LOCKED vs FLOATING. A flake input is locked when its URL carries a commit/narHash or a
//     flake.lock node carries one; a floating ref (a branch) that the lock resolves is fine.
//     A nixpkgs fetcher with a real hash is content-pinned even if its rev is a label.
//   - APPLICABLE vs INERT hashes. A placeholder or empty hash is a finding only inside a fetcher or
//     a fixed-output derivation (`outputHash`); the same text in any other attribute is just text.
//   - SIGNED vs CONTENT-ADDRESSED. A binary-cache signature proves who produced an input-addressed
//     path; it says nothing about vulnerabilities. Content-addressed and fixed-output paths are
//     verified by their address and are never treated as unsigned input-addressed paths.

import { redactUrlsDeep } from './secrets.js';
import { parseNix, childrenOf } from './nix-parser.js';
import { buildNixIR } from './nix-ir.js';
import { loadNixGrammar } from './nix-grammar.js';
import { resolveNixosConfig } from './nixos-module-resolver.js';
import { normalizeRelease } from './nixos-option-catalog.js';
import { effectiveView as view, optionEvidence, optionAnchor } from './nixos-hardening.js';
import { isLanguageExcludedPath } from './discovery.js';
import { BUILD_TRUST_TYPE, isRegisteredLanguageProducer, registerLanguageProducer } from './contracts.js';

export { BUILD_TRUST_TYPE };
export const BUILD_TRUST_RULESET_VERSION = 'nix-build-trust/1';
export const NIX_BUILD_TRUST_PRODUCER = 'language:nix-build-trust';

const SEV_ORDER = ['info', 'low', 'medium', 'high', 'critical'];
const capSeverity = (sev, max) => (SEV_ORDER.indexOf(sev) > SEV_ORDER.indexOf(max) ? max : sev);

const CACHE_TRUST_BOUNDARY = Object.freeze({
  boundary: 'binary-cache',
  establishes: 'content integrity and signer identity of an input-addressed store path',
  doesNotEstablish: 'that the software inside the path is free of known vulnerabilities (CVE absence)',
  contentAddressed: 'content-addressed and fixed-output paths are verified by their address, not by a signature, and are not treated as unsigned input-addressed paths',
});

/** `severity` is the BASE; `kind` says what sort of claim the finding is. */
export const BUILD_TRUST_RULES = Object.freeze({
  'nix-fetch-missing-hash': { family: 'nix-fetch-integrity', kind: 'integrity', cwe: 'CWE-494', severity: 'high', ruleVersion: 1, vuln: 'Fetcher has no content hash', why: 'Without a hash the fetched bytes are not verified, so whatever the URL serves at build time becomes part of the build.', fix: 'Add the fetcher\'s hash (run the build once with lib.fakeHash and copy the reported value) or pin the source through a flake input and flake.lock.' },
  'nix-fetch-fake-hash': { family: 'nix-fetch-integrity', kind: 'integrity', cwe: 'CWE-494', severity: 'medium', ruleVersion: 1, vuln: 'Fetcher or fixed-output derivation carries a placeholder hash', why: 'An empty, all-zero or lib.fake* hash is a stand-in for a value that was never recorded; committed, it means the source has no real integrity pin.', fix: 'Replace the placeholder with the hash Nix reports on the first build, and keep it in version control.' },
  'nix-fetch-floating-rev': { family: 'nix-fetch-pin', kind: 'integrity', cwe: 'CWE-829', severity: 'high', ruleVersion: 1, vuln: 'Source revision is a moving reference', why: 'A branch name or an absent rev resolves to whatever the remote serves at that moment, so two evaluations can build different code. A hash pins the bytes, not the intent: with a hash this is only a reproducibility and update-review risk.', fix: 'Pin rev to a full commit hash (or a release tag together with its hash) and update it deliberately.' },
  'nix-fetch-insecure-transport': { family: 'nix-fetch-integrity', kind: 'integrity', cwe: 'CWE-319', severity: 'medium', ruleVersion: 1, vuln: 'Fetch uses an unencrypted transport', why: 'http:// and git:// can be altered in transit. A hash makes that detectable but turns it into a build failure or silent downgrade risk when the hash is missing.', fix: 'Use https:// (or ssh) and keep the content hash.' },
  'nix-flake-input-unlocked': { family: 'nix-flake-lock', kind: 'integrity', cwe: 'CWE-829', severity: 'medium', ruleVersion: 1, vuln: 'Flake input is not locked to a revision', why: 'An input that is neither pinned in its URL nor present in flake.lock is re-resolved on the next evaluation, so the inputs of the build can change without a reviewed diff.', fix: 'Run `nix flake lock`, commit flake.lock, or pin the input URL to a commit (github:owner/repo/<rev>).' },
  'nix-flake-nixconfig-cache': { family: 'nix-cache-trust', kind: 'policy', cwe: 'CWE-494', severity: 'low', ruleVersion: 1, vuln: 'Flake proposes its own binary cache or signing key', why: 'nixConfig lets a flake ask the user to trust an extra substituter or public key. It only takes effect when accepted (or when accept-flake-config is true), but that acceptance extends trust to whoever controls the flake.', fix: 'Accept it only for flakes you trust, and prefer configuring caches and keys system-wide.' },
  'nix-script-pipe-to-shell': { family: 'nix-script-download', kind: 'integrity', cwe: 'CWE-494', severity: 'high', ruleVersion: 1, vuln: 'Script pipes a download straight into a shell', why: 'The remote response is executed with no hash, signature or review step, so the server (or anyone on the path) decides what runs.', fix: 'Fetch the artifact with a hashed Nix fetcher and run the verified store path instead.' },
  'nix-script-tls-verification-off': { family: 'nix-script-download', kind: 'integrity', cwe: 'CWE-295', severity: 'medium', ruleVersion: 1, vuln: 'Script downloads with TLS verification disabled', why: '-k/--insecure/--no-check-certificate accepts any certificate, which allows interception of the download.', fix: 'Remove the flag and provide the CA through the build or service trust store.' },
  'nix-script-unverified-download': { family: 'nix-script-download', kind: 'integrity', cwe: 'CWE-494', severity: 'medium', ruleVersion: 1, vuln: 'Script downloads a file with no integrity check', why: 'A curl/wget in a script with no checksum comparison trusts the bytes it receives. In a sandboxed build the network is unavailable, so this is mostly a runtime-script concern.', fix: 'Compare a pinned checksum (sha256sum -c) before using the file, or fetch it with a hashed Nix fetcher.' },
  'nix-ifd-boundary': { family: 'nix-eval-boundary', kind: 'boundary', cwe: 'CWE-829', severity: 'low', ruleVersion: 1, vuln: 'Import from derivation crosses an evaluation boundary', why: 'Evaluation depends on the output of a build or a fetch, so evaluating this expression runs builder code or reaches the network. That is a boundary and a reproducibility/policy concern; it is not by itself an exploitable vulnerability.', fix: 'If policy forbids IFD, generate the file ahead of time and commit it; otherwise review the builder and its inputs as you would any build.' },
  'nix-ifd-policy-enabled': { family: 'nix-eval-boundary', kind: 'policy', cwe: 'CWE-829', severity: 'low', ruleVersion: 1, vuln: 'Import from derivation is explicitly enabled', why: 'allow-import-from-derivation = true lets evaluation trigger builds. It is the Nix default, so setting it explicitly records a policy choice rather than a defect.', fix: 'Set allow-import-from-derivation = false where evaluation must stay build-free (CI, hydra-style evaluators).' },
  'nix-unsafe-native-eval': { family: 'nix-eval-native', kind: 'policy', cwe: 'CWE-94', severity: 'high', ruleVersion: 1, vuln: 'Unsafe native code is allowed during evaluation', why: 'allow-unsafe-native-code-during-evaluation lets expressions run native code in the evaluator process, outside the build sandbox.', fix: 'Remove the setting (default false).' },
  'nix-eval-native-plugin': { family: 'nix-eval-native', kind: 'policy', cwe: 'CWE-94', severity: 'high', ruleVersion: 1, vuln: 'Evaluator loads native plugins', why: 'plugin-files loads shared libraries into the Nix evaluator and daemon, which then run with their privileges.', fix: 'Remove plugin-files unless the plugin is audited and required.' },
  'nix-extra-builtins-file': { family: 'nix-eval-native', kind: 'policy', cwe: 'CWE-94', severity: 'medium', ruleVersion: 1, vuln: 'Evaluator loads extra builtins from a file', why: 'extra-builtins-file adds builtins (typically builtins.exec) that run commands at evaluation time.', fix: 'Remove the setting, or keep the file under review and owned by root.' },
  'nix-trusted-users-widened': { family: 'nix-privilege', kind: 'policy', cwe: 'CWE-269', severity: 'medium', ruleVersion: 1, vuln: 'trusted-users grants daemon privileges beyond root', why: 'A trusted user can pass options such as extra substituters and import unsigned store paths through the daemon, which is equivalent to root on the build host.', fix: 'Leave trusted-users at ["root"] and use allowed-users or a deploy account for access.' },
  'nix-require-sigs-disabled': { family: 'nix-cache-trust', kind: 'policy', cwe: 'CWE-347', severity: 'high', ruleVersion: 1, vuln: 'Binary-cache signature checking is disabled', why: 'With require-sigs = false the store accepts input-addressed paths from any substituter without verifying a signature, so a compromised or spoofed cache can supply arbitrary binaries.', fix: 'Remove require-sigs = false and list the signing keys of the caches you use in trusted-public-keys.' },
  'nix-substituter-insecure-transport': { family: 'nix-cache-trust', kind: 'policy', cwe: 'CWE-319', severity: 'low', ruleVersion: 1, vuln: 'Binary cache is reached over plain http', why: 'Signatures keep the content intact, but plain http exposes which paths are fetched and lets a network attacker downgrade or withhold. With signature checking off it is a direct substitution risk.', fix: 'Use an https:// (or ssh://) substituter.' },
  'nix-accept-flake-config': { family: 'nix-cache-trust', kind: 'policy', cwe: 'CWE-494', severity: 'medium', ruleVersion: 1, vuln: 'Flake-supplied configuration is accepted automatically', why: 'accept-flake-config = true lets every flake you evaluate add substituters and keys without a prompt.', fix: 'Remove accept-flake-config and accept individual flakes explicitly.' },
  'nix-sandbox-disabled': { family: 'nix-sandbox', kind: 'policy', cwe: 'CWE-693', severity: 'high', ruleVersion: 1, vuln: 'Build sandbox is disabled or relaxed', why: 'Without the sandbox a build can read the host filesystem and reach the network, so a malicious or compromised derivation is not contained.', fix: 'Set sandbox = true (the default) and grant specific paths with extra-sandbox-paths if one build needs them.' },
  'nix-sandbox-sensitive-path': { family: 'nix-sandbox', kind: 'policy', cwe: 'CWE-732', severity: 'high', ruleVersion: 1, vuln: 'Sandbox exposes a sensitive host path to builds', why: 'extra-sandbox-paths mounts host paths into every build; a broad directory or a runtime socket hands builders the host.', fix: 'Expose only the single file a build needs, read-only, and never a runtime socket.' },
  'nix-build-users-group-empty': { family: 'nix-sandbox', kind: 'policy', cwe: 'CWE-250', severity: 'high', ruleVersion: 1, vuln: 'Builds run as the invoking user', why: 'An empty build-users-group makes the daemon run builders as the calling user instead of an unprivileged build account.', fix: 'Leave build-users-group at its default (nixbld).' },
  'nix-overlay-hardening-disabled': { family: 'nix-overlay', kind: 'policy', cwe: 'CWE-693', severity: 'medium', ruleVersion: 1, vuln: 'Overlay disables compiler hardening', why: 'hardeningDisable in an overlay removes stack protector, fortify, PIE or RELRO from every consumer of the overridden package.', fix: 'Disable only the single flag a build needs, for that package, with a comment explaining why.' },
  'nix-overlay-clears-vuln-marker': { family: 'nix-overlay', kind: 'policy', cwe: 'CWE-1395', severity: 'medium', ruleVersion: 1, vuln: 'Overlay clears a package\'s knownVulnerabilities', why: 'Resetting meta.knownVulnerabilities to [] removes the guard nixpkgs uses to refuse an insecure package.', fix: 'Remove the override; pin a fixed version, or list the package in permittedInsecurePackages with a dated justification.' },
  'nix-insecure-packages-permitted': { family: 'nix-overlay', kind: 'policy', cwe: 'CWE-1395', severity: 'low', ruleVersion: 1, vuln: 'Insecure packages are permitted', why: 'permittedInsecurePackages / allowInsecure waive the nixpkgs refusal to build packages marked insecure.', fix: 'Prefer upgrading; keep each permitted package named, not allowInsecure = true, and review the list regularly.' },
});

// ── small AST helpers ──────────────────────────────────────────────────────

const unparen = (n) => { let x = n; while (x && x.type === 'paren') x = x.expr; return x; };

function appChain(node) {
  const args = [];
  let fn = node;
  while (fn && fn.type === 'app') { args.unshift(fn.arg); fn = unparen(fn.fn); }
  return { fn, args };
}

/** `foo`, `lib.foo`, `pkgs.lib.foo`, `builtins.foo` -> 'foo'. */
function lastName(node) {
  const f = unparen(node);
  if (!f) return null;
  if (f.type === 'ident') return f.name;
  if (f.type === 'select' && f.attrpath.length) {
    const last = f.attrpath[f.attrpath.length - 1];
    if (last.kind === 'static') return last.name;
  }
  return null;
}

const strLiteral = (n) => { const x = unparen(n); return x && x.type === 'string' && !x.interpolated ? x.literal : undefined; };

/** Static, single-segment attributes of an attrset: name -> { node, span }. */
function attrsOf(set) {
  const map = new Map();
  for (const b of set.bindings) {
    if (b.kind === 'attr') {
      if (b.path.length === 1 && b.path[0].kind === 'static') map.set(b.path[0].name, { node: b.value, span: b.span });
    } else if (b.kind === 'inherit' && !b.from) {
      for (const nm of b.names) if (nm.kind === 'static') map.set(nm.name, { node: null, span: b.span, inherited: true });
    }
  }
  return map;
}

const HASH_ATTRS = ['hash', 'sha256', 'sha512', 'sha1', 'outputHash', 'narHash'];
const FAKE_NAMES = new Set(['fakeHash', 'fakeSha256', 'fakeSha512', 'fakeSha1']);
const COMMIT_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i;

function isFakeHash(node) {
  const n = unparen(node);
  if (!n) return false;
  const lit = strLiteral(n);
  if (lit !== undefined) {
    return lit === '' || /^sha256-A{43}=$/.test(lit) || /^sha512-A{86}==$/.test(lit) || /^sha1-A{27}=$/.test(lit) || /^0{32,}$/.test(lit);
  }
  if (n.type === 'ident' || n.type === 'select') return FAKE_NAMES.has(lastName(n));
  return false;
}

function hashState(attrs) {
  for (const k of HASH_ATTRS) {
    const a = attrs.get(k);
    if (!a) continue;
    if (!a.node) return { state: 'dynamic', attr: k, span: a.span };
    if (isFakeHash(a.node)) return { state: 'fake', attr: k, span: unparen(a.node).span };
    const n = unparen(a.node);
    if (n.type === 'string' && !n.interpolated) return { state: 'present', attr: k, span: n.span };
    return { state: 'dynamic', attr: k, span: n.span };
  }
  return { state: 'missing' };
}

function revKind(attrs) {
  const rev = attrs.get('rev');
  if (!rev) return attrs.get('tag') ? { kind: 'tag' } : { kind: 'none' };
  if (!rev.node) return { kind: 'dynamic' };
  const lit = strLiteral(rev.node);
  if (lit === undefined) return { kind: 'dynamic' };
  return COMMIT_RE.test(lit) ? { kind: 'commit', value: lit } : { kind: 'ref', value: lit };
}

// callee name -> how the fetch is judged
const FETCHERS = {
  fetchurl: 'fod', fetchzip: 'fod', fetchFromGitHub: 'fod', fetchFromGitLab: 'fod', fetchFromSourcehut: 'fod',
  fetchFromBitbucket: 'fod', fetchFromGitea: 'fod', fetchgit: 'fod', fetchpatch: 'fod', fetchpatch2: 'fod',
  fetchsvn: 'fod', fetchhg: 'fod', fetchTarball: 'fod',
  fetchGit: 'git', fetchTree: 'tree',
};

const BUILD_CALLEES = new Set(['runCommand', 'runCommandLocal', 'runCommandNoCC', 'mkDerivation', 'derivation', 'stdenv', 'buildPythonPackage', 'buildGoModule', 'buildRustPackage', 'buildNpmPackage', 'writeText', 'writeTextFile', 'writeShellScript', 'writeShellScriptBin', 'writeShellApplication', 'symlinkJoin', 'linkFarm']);
const CABAL_IFD = new Set(['callCabal2nix', 'callCabal2nixWithOptions', 'callHackage', 'callHackageDirect', 'importCabal']);
const SCRIPT_BUILDERS = new Set(['writeShellScript', 'writeShellScriptBin', 'writeScript', 'writeScriptBin', 'writeShellApplication', 'runCommand', 'runCommandLocal', 'runCommandNoCC']);
const SCRIPT_ATTR = /^(?:\w*Phase|\w*Hook|\w*[sS]cript|text|Exec\w+|(?:pre|post)[A-Z]\w*|\w*Commands?|\w*Init|\w*Setup)$/;

const PIPE_TO_SHELL = /\b(?:curl|wget|fetch)\b[^\n|]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|da|k)?sh\b|\b(?:ba|z|da)?sh\s+<\(\s*(?:curl|wget)\b|\beval\s+["']?\$\(\s*(?:curl|wget)\b|\bsh\s+-c\s+["']\$\(\s*(?:curl|wget)\b/;
const TLS_OFF_FLAG = /\b(?:curl|wget)\b[^\n]*?\s(?:-k|--insecure|--no-check-certificate)(?:\s|$)/;
const DOWNLOAD = /\b(?:curl|wget)\b[^\n]*https?:\/\//;
const VERIFY = /\b(?:sha(?:1|224|256|384|512)sum|shasum|b3sum|nix-hash|nix\s+hash|openssl\s+dgst|gpg\s+--verify|cosign\s+verify|minisign)\b/;

const HARDENING_FLAGS = new Set(['all', 'stackprotector', 'fortify', 'fortify3', 'pie', 'relro', 'bindnow', 'stackclashprotection', 'format']);

const FINAL_NAMES = new Set(['final', 'self', 'pkgsFinal', '_final']);
const PREV_NAMES = new Set(['prev', 'super', 'pkgsPrev', '_prev']);

const SENSITIVE_PATHS = [/^\/$/, /^\/(?:etc|home|root|var|run|usr|boot|dev|proc|sys)$/, /docker\.sock$/, /podman\.sock$/, /containerd\.sock$/, /^\/nix\/var\/nix\/daemon-socket/, /^\/run\/secrets/, /^\/etc\/(?:shadow|ssh)/];

// ── settings (nix.conf) reading ────────────────────────────────────────────

const LEGACY = {
  'require-sigs': ['nix.requireSignedBinaryCaches'],
  'substituters': ['nix.binaryCaches'],
  'trusted-substituters': ['nix.trustedBinaryCaches'],
  'trusted-public-keys': ['nix.binaryCachePublicKeys'],
};

const LIST_KEYS = new Set(['trusted-users', 'substituters', 'trusted-substituters', 'trusted-public-keys', 'sandbox-paths', 'extra-sandbox-paths', 'plugin-files', 'experimental-features']);

function parseExtraOptions(text) {
  const out = new Map();
  for (const raw of String(text).split('\n')) {
    const line = raw.replace(/(^|\s)#.*$/, '').trim();
    const m = /^([A-Za-z0-9-]+)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    const tokens = m[2].split(/\s+/).filter(Boolean);
    out.set(m[1], tokens);
  }
  return out;
}

const scalarOf = (tokens) => {
  const t = tokens.length === 1 ? tokens[0] : tokens.join(' ');
  if (t === 'true') return true;
  if (t === 'false') return false;
  return t;
};

function readSetting(cfg, key, extra) {
  const list = LIST_KEYS.has(key);
  const names = list ? [key, `extra-${key}`] : [key];
  const parts = [];
  for (const n of names) parts.push({ option: `nix.settings.${n}`, res: cfg.lookup(`nix.settings.${n}`) });
  for (const l of LEGACY[key] || []) parts.push({ option: l, res: cfg.lookup(l), legacy: true });
  const present = parts.filter((p) => p.res && ((p.res.sources || []).length > 0 || ((p.res.status === 'default') && p.res.valueKnown)));
  const s = { key, state: 'absent', list, values: [], items: [], possible: [], possibleItems: [], evidence: [], anchors: [], definite: true, viaText: false };
  let cond = false;
  let unknown = false;
  for (const p of present) {
    const v = view(p.res);
    s.evidence.push(optionEvidence(p.res));
    if ((p.res.sources || []).length) s.anchors.push(optionAnchor(p.res));
    if (v.state === 'known') {
      s.values.push(v.value);
      if (list && Array.isArray(v.value)) s.items.push(...v.value);
      if (!v.definite && v.via !== 'catalog-default') s.definite = false;
    } else if (v.state === 'conditional') {
      cond = true;
      s.definite = false;
      s.possible.push(...v.possible);
      s.possibleItems.push(...(v.possibleItems || []), ...(v.definiteItems || []));
      if (list) s.items.push(...(v.definiteItems || []));
    } else { unknown = true; s.definite = false; }
  }
  // nix.extraOptions is appended to nix.conf after nix.settings, so a later line wins for scalars
  if (extra && extra.text) {
    const eo = extra.text;
    for (const n of names) {
      if (!eo.lines.has(n)) continue;
      const tokens = eo.lines.get(n);
      s.viaText = true;
      s.evidence.push({ ...eo.evidence, textKey: n, locatedAt: 'option' });
      s.anchors.push(eo.anchor);
      if (list) { s.values.push(tokens); s.items.push(...tokens); } else s.values.push(scalarOf(tokens));
      if (!eo.definite) s.definite = false;
    }
  }
  if (cond) s.state = 'conditional';
  else if (s.values.length) s.state = 'known';
  else if (unknown) s.state = 'unknown';
  if (s.values.length && !cond) s.value = s.values[s.values.length - 1];
  return s;
}

/** 'yes' | 'conditional' | 'no' | 'unknown' | 'absent' for a predicate over the setting's value (or items). */
function holds(s, pred) {
  if (s.state === 'absent') return 'absent';
  if (s.state === 'unknown') return 'unknown';
  const known = s.list ? s.items : s.values.slice(-1);
  if (known.some((x) => pred(x))) return 'yes';
  if (s.state === 'conditional') return (s.list ? s.possibleItems : s.possible).some((x) => pred(x)) ? 'conditional' : 'no';
  return 'no';
}

const spanLine = (sp) => (sp && Number.isInteger(sp.startLine) ? sp.startLine : 1);

// ── analysis ───────────────────────────────────────────────────────────────

/**
 * @param {object} opts
 * @param {Record<string,string>} opts.files   rel path -> content (Nix sources, optionally flake.lock)
 * @param {string} [opts.entry]                NixOS module entry (default configuration.nix when present)
 * @param {object} [opts.target]               { release, system, args } as for resolveNixosConfig
 */
export function analyzeNixBuildTrust(opts = {}) {
  const files = opts.files || {};
  const findings = [];
  const controls = [];
  const gaps = [];
  const inventory = { fetches: [], flakeInputs: [], ifd: [], contentAddressed: [] };
  let context = { target: opts.target || null, release: null, catalog: null };

  const addFinding = (rule, { severity, file, span, name, subject, evidence, state = 'active', uncertain = false, partial = false, evidenceKind = 'source', capability = 'sca', extra = {}, line, trustBoundary }) => {
    const r = BUILD_TRUST_RULES[rule];
    let sev = severity || r.severity;
    const conditional = state === 'conditional';
    const uncertainty = [];
    if (conditional) uncertainty.push({ kind: 'unresolved-branch', detail: 'the value depends on a condition that could not be decided statically' });
    if (partial) uncertainty.push({ kind: 'unresolved-import', detail: 'the module graph is partial; an unread module could override this value' });
    if (uncertain && !conditional && !partial) uncertainty.push({ kind: 'unresolved-branch', detail: 'the effective value carries evaluation caveats' });
    if (extra.uncertainty) uncertainty.push(...extra.uncertainty);
    if (conditional || partial || uncertain) sev = capSeverity(sev, 'medium');
    const ln = Number.isInteger(line) ? line : spanLine(span);
    const { uncertainty: _u, ...rest } = extra;
    void _u;
    findings.push({
      id: `nix-build-trust:${rule}:${file || 'config'}:${subject}`,
      type: BUILD_TRUST_TYPE, ecosystem: 'nix', name: name || subject, version: null, subject,
      severity: sev, file: file || null, line: ln,
      vuln: r.vuln, cwe: r.cwe,
      description: `${r.vuln} (${subject}). ${r.why}`,
      remediation: r.fix, remediationRationale: r.why,
      parser: 'nix-build-trust', family: r.family,
      language: 'nix', capability, evidenceKind,
      scope: { target: context.target && context.target.system ? String(context.target.system) : null, configuration: opts.entry || null, component: subject },
      originalLocation: { file: file || undefined, line: ln, column: span && Number.isInteger(span.startColumn) ? span.startColumn : 0 },
      rule, ruleVersion: r.ruleVersion, rulesetVersion: BUILD_TRUST_RULESET_VERSION, baseSeverity: r.severity, kind: r.kind,
      conditional, uncertainty: uncertainty.length ? uncertainty : undefined,
      evidence, context: { ...context }, trustBoundary,
      ...rest,
    });
  };

  // ── SOURCE half ──
  const lockCache = new Map();
  const lockFor = (flakeFile) => {
    const dir = flakeFile.includes('/') ? flakeFile.slice(0, flakeFile.lastIndexOf('/')) : '';
    const lockPath = dir ? `${dir}/flake.lock` : 'flake.lock';
    if (lockCache.has(lockPath)) return lockCache.get(lockPath);
    let out = { present: false, path: lockPath };
    if (typeof files[lockPath] === 'string') {
      try {
        const doc = JSON.parse(files[lockPath]);
        out = { present: true, path: lockPath, nodes: doc.nodes || {}, root: doc.root || 'root' };
      } catch (e) {
        out = { present: true, path: lockPath, invalid: String(e.message || e) };
        gaps.push({ kind: 'invalid-flake-lock', detail: `flake.lock could not be parsed: ${out.invalid}`, file: lockPath, line: 1 });
      }
    }
    lockCache.set(lockPath, out);
    return out;
  };

  function analyzeSource(file, text) {
    const parse = parseNix(text, { file });
    if (!parse.ast) return;
    const ir = buildNixIR(parse, { file, source: text });
    const fileOverlay = ir.fileKind === 'overlay';
    const innerApps = new WeakSet();
    const handledSets = new WeakSet();
    const scriptStrings = new WeakSet();

    const fetchEntry = (callee, span, extraEntry) => {
      const e = { callee, file, line: spanLine(span), ...extraEntry };
      inventory.fetches.push(e);
      return e;
    };

    function handleFetch(name, kind, args, call) {
      const last = unparen(args[args.length - 1]);
      const span = call.span;
      if (last && last.type === 'string') {
        // shorthand: fetchTarball "url" / fetchGit "url" carries no hash and no rev
        const url = last.interpolated ? null : last.literal;
        if (kind === 'fod') {
          fetchEntry(name, span, { url, hash: 'missing', locked: false });
          addFinding('nix-fetch-missing-hash', { file, span, subject: `${name}@${spanLine(span)}`, name: url || name, evidence: { callee: name, url, form: 'string-shorthand' }, extra: { fetcher: name } });
        } else if (kind === 'git') {
          fetchEntry(name, span, { url, rev: 'none', locked: false });
          addFinding('nix-fetch-floating-rev', { file, span, subject: `${name}@${spanLine(span)}`, name: url || name, evidence: { callee: name, url, form: 'string-shorthand', rev: null }, extra: { fetcher: name } });
        }
        return;
      }
      if (!last || last.type !== 'attrset') {
        fetchEntry(name, span, { hash: 'unknown', locked: 'unknown' });
        gaps.push({ kind: 'dynamic-fetch-arguments', detail: `${name} arguments are not a literal attribute set, so its hash and revision were not judged`, file, line: spanLine(span) });
        return;
      }
      handledSets.add(last);
      const attrs = attrsOf(last);
      const hs = hashState(attrs);
      const rk = revKind(attrs);
      const urlAttr = attrs.get('url');
      const url = urlAttr && urlAttr.node ? strLiteral(urlAttr.node) : undefined;
      const ownerRepo = attrs.get('owner') && attrs.get('repo') ? `${strLiteral(attrs.get('owner').node) ?? '?'}/${strLiteral(attrs.get('repo').node) ?? '?'}` : null;
      const label = url || ownerRepo || name;
      const base = { callee: name, url: url ?? null, repo: ownerRepo, hashAttr: hs.attr || null };
      const subject = `${name}@${spanLine(span)}`;

      if (kind === 'fod') {
        const entry = fetchEntry(name, span, { url: url ?? null, repo: ownerRepo, hash: hs.state, rev: rk.kind, locked: hs.state === 'present' ? true : hs.state === 'dynamic' ? 'unknown' : false });
        if (hs.state === 'missing') {
          addFinding('nix-fetch-missing-hash', { file, span, subject, name: label, evidence: { ...base, hash: 'missing', revKind: rk.kind }, extra: { fetcher: name } });
        } else if (hs.state === 'fake') {
          addFinding('nix-fetch-fake-hash', { file, span: hs.span, subject, name: label, evidence: { ...base, hash: 'placeholder', context: 'fetcher' }, extra: { fetcher: name } });
        } else if (hs.state === 'dynamic') {
          gaps.push({ kind: 'dynamic-fetch-hash', detail: `${name} hash is not a literal, so its value was not judged`, file, line: spanLine(hs.span) });
        } else if (rk.kind === 'ref') {
          addFinding('nix-fetch-floating-rev', { file, span, subject, name: label, severity: 'low', evidence: { ...base, rev: rk.value, hash: 'present', contentPinned: true }, extra: { fetcher: name, contentPinned: true } });
        }
        if (typeof url === 'string' && /^(?:http|git):\/\//i.test(url)) {
          addFinding('nix-fetch-insecure-transport', { file, span, subject, name: label, severity: hs.state === 'present' ? 'low' : 'high', evidence: { ...base, hash: hs.state }, extra: { fetcher: name, contentPinned: hs.state === 'present' } });
        }
        void entry;
      } else if (kind === 'git') {
        const locked = rk.kind === 'commit' ? true : rk.kind === 'dynamic' ? 'unknown' : false;
        fetchEntry(name, span, { url: url ?? null, rev: rk.kind, locked });
        if (locked === false) addFinding('nix-fetch-floating-rev', { file, span, subject, name: label, evidence: { ...base, rev: rk.value ?? null, revKind: rk.kind }, extra: { fetcher: name, contentPinned: false } });
        else if (locked === 'unknown') gaps.push({ kind: 'dynamic-fetch-rev', detail: `${name} rev is computed, so its pin was not judged`, file, line: spanLine(span) });
      } else if (kind === 'tree') {
        const pinned = hs.state === 'present' || rk.kind === 'commit';
        const locked = pinned ? true : hs.state === 'dynamic' || rk.kind === 'dynamic' ? 'unknown' : false;
        fetchEntry(name, span, { url: url ?? null, hash: hs.state, rev: rk.kind, locked });
        if (locked === false) addFinding('nix-fetch-floating-rev', { file, span, subject, name: label, evidence: { ...base, hash: hs.state, revKind: rk.kind }, extra: { fetcher: name, contentPinned: false } });
        else if (locked === 'unknown') gaps.push({ kind: 'dynamic-fetch-rev', detail: `${name} pin is computed, so it was not judged`, file, line: spanLine(span) });
      }
    }

    // name -> value node, only where the binding is unambiguous within this file (IFD origin tracking)
    const env = new Map();
    const ambiguous = new Set();
    {
      const stack = [parse.ast];
      let guard = 0;
      while (stack.length && guard++ < 50_000) {
        const n = stack.pop();
        if (n.type === 'attrset' || n.type === 'let') {
          for (const b of n.bindings) {
            if (b.kind === 'attr' && b.path.length === 1 && b.path[0].kind === 'static') {
              const k = b.path[0].name;
              if (env.has(k)) ambiguous.add(k); else env.set(k, b.value);
            }
          }
        }
        for (const k of childrenOf(n)) stack.push(k);
      }
      for (const k of ambiguous) env.delete(k);
    }

    /** What produces the value of `node`? 'build' | 'fetch' | 'cabal' | null (unknown / plain). */
    function origin(node, depth = 0) {
      const n = unparen(node);
      if (!n || depth > 5) return null;
      if (n.type === 'app') {
        const { fn, args } = appChain(n);
        const name = lastName(fn);
        if (name && CABAL_IFD.has(name)) return 'cabal';
        // builtins.fetch* run in the evaluator by design and are judged by the fetch rules, not as IFD
        if (name === 'fetchTarball' || name === 'fetchGit' || name === 'fetchTree') return null;
        if (name && FETCHERS[name]) return 'fetch';
        if (name && BUILD_CALLEES.has(name)) return 'build';
        if (name === 'overrideAttrs' || name === 'override') return origin(fn.type === 'select' ? fn.base : fn, depth + 1);
        void args;
        return null;
      }
      if (n.type === 'ident') return env.has(n.name) ? origin(env.get(n.name), depth + 1) : null;
      if (n.type === 'select') return origin(n.base, depth + 1);
      if (n.type === 'binop' && n.op === '+') return origin(n.left, depth + 1) || origin(n.right, depth + 1);
      if (n.type === 'string' && n.interpolated) {
        for (const p of n.parts) if (p.kind === 'interp') { const o = origin(p.expr, depth + 1); if (o) return o; }
      }
      return null;
    }

    function handleIfd(name, args, call, viaImport) {
      const target = args[0];
      const o = origin(target);
      if (!o) return;
      const cls = o === 'fetch' ? 'resolution-boundary' : 'execution-boundary';
      const span = call.span;
      inventory.ifd.push({ file, line: spanLine(span), via: viaImport, origin: o, classification: cls });
      addFinding('nix-ifd-boundary', {
        file, span, subject: `${viaImport}@${spanLine(span)}`, name: viaImport,
        severity: o === 'fetch' ? 'info' : 'low',
        evidence: { via: viaImport, derivedFrom: o, classification: cls, executed: false },
        extra: { ifd: { classification: cls, derivedFrom: o, executed: false, exploitabilityAssumed: false } },
      });
    }

    function handleCall(call) {
      const { fn, args } = appChain(call);
      const name = lastName(fn);
      if (!name || !args.length) return;
      const f = unparen(fn);
      if (FETCHERS[name]) { handleFetch(name, FETCHERS[name], args, call); return; }
      if (f && f.type === 'ident' && f.name === 'import') { handleIfd('import', args, call, 'import'); return; }
      if (name === 'readFile' || name === 'readDir') { handleIfd(name, args, call, name); return; }
      if (CABAL_IFD.has(name)) {
        const span = call.span;
        inventory.ifd.push({ file, line: spanLine(span), via: name, origin: 'cabal', classification: 'execution-boundary' });
        addFinding('nix-ifd-boundary', { file, span, subject: `${name}@${spanLine(span)}`, name, severity: 'low', evidence: { via: name, derivedFrom: 'cabal', classification: 'execution-boundary', executed: false }, extra: { ifd: { classification: 'execution-boundary', derivedFrom: 'cabal', executed: false, exploitabilityAssumed: false } } });
        return;
      }
      if (SCRIPT_BUILDERS.has(name)) for (const a of args) { const s = unparen(a); if (s && s.type === 'string') scriptStrings.add(s); }
    }

    function handleString(node, attr) {
      const isScript = scriptStrings.has(node) || (attr && SCRIPT_ATTR.test(attr));
      if (!isScript || node.parts.length === 0) return;
      const text2 = node.parts.map((p) => (p.kind === 'text' ? p.value : '\u0001')).join('');
      const shift = /^''[ \t]*\n/.test(text.slice(node.start, node.start + 8)) ? 1 : 0;
      const lineAt = (idx) => node.span.startLine + shift + (text2.slice(0, idx).match(/\n/g) || []).length;
      const ctx = scriptStrings.has(node) || /Phase$|^(?:pre|post)[A-Z]/.test(attr || '') ? 'build-time' : 'runtime';
      const pipe = PIPE_TO_SHELL.exec(text2);
      if (pipe) {
        const ln = lineAt(pipe.index);
        addFinding('nix-script-pipe-to-shell', { file, line: ln, span: node.span, subject: `${attr || 'script'}@${ln - ((node.span && node.span.startLine) || 0)}`, name: attr || 'script', severity: ctx === 'build-time' ? 'medium' : 'high', evidence: { attribute: attr || null, context: ctx, sandboxNote: ctx === 'build-time' ? 'a sandboxed build has no network, so this runs only if the sandbox is off or the derivation is fixed-output' : undefined } });
      }
      const tls = TLS_OFF_FLAG.exec(text2);
      if (tls) {
        const ln = lineAt(tls.index);
        addFinding('nix-script-tls-verification-off', { file, line: ln, span: node.span, subject: `${attr || 'script'}@${ln - ((node.span && node.span.startLine) || 0)}`, name: attr || 'script', evidence: { attribute: attr || null, context: ctx } });
      }
      if (!pipe && DOWNLOAD.test(text2) && !VERIFY.test(text2)) {
        const m = DOWNLOAD.exec(text2);
        const ln = lineAt(m.index);
        addFinding('nix-script-unverified-download', { file, line: ln, span: node.span, subject: `${attr || 'script'}@${ln - ((node.span && node.span.startLine) || 0)}`, name: attr || 'script', severity: ctx === 'build-time' ? 'low' : 'medium', evidence: { attribute: attr || null, context: ctx } });
      }
    }

    function handleAttrset(node, ov) {
      const attrs = attrsOf(node);
      if (attrs.get('__contentAddressed')) {
        const v = unparen(attrs.get('__contentAddressed').node);
        if (v && v.type === 'ident' && v.name === 'true') inventory.contentAddressed.push({ file, line: spanLine(node.span), kind: 'content-addressed-derivation' });
      }
      if (attrs.has('outputHash') && !handledSets.has(node)) {
        const hs = hashState(new Map([['outputHash', attrs.get('outputHash')]]));
        if (hs.state === 'fake') addFinding('nix-fetch-fake-hash', { file, span: hs.span, subject: `outputHash@${spanLine(hs.span)}`, name: 'outputHash', evidence: { hashAttr: 'outputHash', context: 'fixed-output-derivation' } });
        else if (hs.state === 'present') inventory.contentAddressed.push({ file, line: spanLine(node.span), kind: 'fixed-output-derivation' });
      }
      const hd = attrs.get('hardeningDisable');
      if (hd && hd.node && ov) {
        const l = unparen(hd.node);
        const flags = l && l.type === 'list' ? l.items.map(strLiteral).filter((x) => typeof x === 'string' && HARDENING_FLAGS.has(x)) : [];
        if (flags.length) addFinding('nix-overlay-hardening-disabled', { file, span: hd.span, subject: `hardeningDisable@${spanLine(hd.span)}`, name: 'hardeningDisable', evidence: { flags, inOverlay: true }, extra: { flags } });
      }
      const kv = attrs.get('knownVulnerabilities');
      if (kv && kv.node && ov) {
        const l = unparen(kv.node);
        if (l && l.type === 'list' && l.items.length === 0) addFinding('nix-overlay-clears-vuln-marker', { file, span: kv.span, subject: `knownVulnerabilities@${spanLine(kv.span)}`, name: 'knownVulnerabilities', evidence: { inOverlay: true, value: [] } });
      }
      const pip = attrs.get('permittedInsecurePackages');
      const ai = attrs.get('allowInsecure');
      const aiTrue = ai && ai.node && unparen(ai.node).type === 'ident' && unparen(ai.node).name === 'true';
      const pipItems = pip && pip.node && unparen(pip.node).type === 'list' ? unparen(pip.node).items : [];
      if (pipItems.length || aiTrue) {
        const sp = (pipItems.length ? pip : ai).span;
        addFinding('nix-insecure-packages-permitted', { file, span: sp, subject: `${pipItems.length ? 'permittedInsecurePackages' : 'allowInsecure'}@${spanLine(sp)}`, name: pipItems.length ? 'permittedInsecurePackages' : 'allowInsecure', severity: aiTrue ? 'medium' : 'low', evidence: { packages: pipItems.map(strLiteral).filter((x) => typeof x === 'string'), blanket: !!aiTrue } });
      }
    }

    // iterative walk carrying the enclosing attribute name and overlay context
    const stack = [{ node: parse.ast, attr: null, ov: fileOverlay }];
    let guard = 0;
    while (stack.length && guard++ < 200_000) {
      const { node, attr, ov } = stack.pop();
      if (!node) continue;
      switch (node.type) {
        case 'app': {
          if (!innerApps.has(node)) {
            let x = unparen(node.fn);
            while (x && x.type === 'app') { innerApps.add(x); x = unparen(x.fn); }
            handleCall(node);
          }
          break;
        }
        case 'string': handleString(node, attr); break;
        case 'attrset': handleAttrset(node, ov); break;
        case 'lambda': {
          const body = unparen(node.body);
          if (node.param.kind === 'ident' && body && body.type === 'lambda' && body.param.kind === 'ident'
              && FINAL_NAMES.has(node.param.name) && PREV_NAMES.has(body.param.name)) {
            stack.push({ node: body.body, attr, ov: true });
            continue;
          }
          break;
        }
        default: break;
      }
      if (node.type === 'attrset' || node.type === 'let') {
        for (const b of node.bindings) {
          if (b.kind === 'attr') {
            const last = b.path[b.path.length - 1];
            stack.push({ node: b.value, attr: last && last.kind === 'static' ? last.name : null, ov });
          }
        }
        if (node.type === 'let') stack.push({ node: node.body, attr, ov });
      } else {
        for (const k of childrenOf(node)) stack.push({ node: k, attr, ov });
      }
    }

    // flake inputs and nixConfig
    if (ir.flake) {
      const lock = lockFor(file);
      for (const inp of ir.flake.inputs) {
        if (inp.follows) { inventory.flakeInputs.push({ name: inp.name, file, line: spanLine(inp.span), locked: 'follows', follows: inp.follows }); continue; }
        if (inp.dynamic || typeof inp.url !== 'string') {
          inventory.flakeInputs.push({ name: inp.name, file, line: spanLine(inp.span), locked: 'unknown' });
          gaps.push({ kind: 'dynamic-flake-input', detail: `flake input "${inp.name}" has a computed or missing url, so its pin was not judged`, file, line: spanLine(inp.span) });
          continue;
        }
        const u = inp.url;
        if (/^(?:path:|git\+file:|file:|\.{0,2}\/)/.test(u)) { inventory.flakeInputs.push({ name: inp.name, file, line: spanLine(inp.span), url: u, locked: 'local' }); continue; }
        const urlPinned = /^github:[^/]+\/[^/?#]+\/[0-9a-f]{40}(?:[?#].*)?$/i.test(u) || /[?&]rev=[0-9a-f]{40}/i.test(u) || /[?&]narHash=/.test(u);
        const floatingRef = /^github:[^/]+\/[^/?#]+\/(?![0-9a-f]{40}(?:[?#]|$))[^/?#]+/i.test(u) || /[?&]ref=/.test(u) || /^github:[^/]+\/[^/?#]+$/i.test(u);
        let locked; let by = null; let reason = null;
        let lockNode = null;
        if (lock.present && lock.nodes) {
          const rootNode = lock.nodes[lock.root];
          const key = rootNode && rootNode.inputs ? rootNode.inputs[inp.name] : undefined;
          lockNode = typeof key === 'string' ? lock.nodes[key] : null;
        }
        if (urlPinned) { locked = true; by = 'url'; }
        else if (lockNode && lockNode.locked && (lockNode.locked.rev || lockNode.locked.narHash)) { locked = true; by = 'flake.lock'; }
        else if (lock.present && lock.invalid) { locked = 'unknown'; reason = 'flake-lock-unparseable'; }
        else if (lock.present) { locked = false; reason = 'missing-from-lock'; }
        else { locked = false; reason = 'no-lock-file'; }
        inventory.flakeInputs.push({ name: inp.name, file, line: spanLine(inp.span), url: u, locked, lockedBy: by, floatingRef, reason, lockFreshness: 'not-checked' });
        if (locked === false) {
          addFinding('nix-flake-input-unlocked', { file, span: inp.span, subject: `input:${inp.name}`, name: inp.name, evidenceKind: 'lock', evidence: { input: inp.name, url: u, floatingRef, reason, lockFile: lock.path, lockPresent: lock.present }, extra: reason === 'no-lock-file' ? { uncertainty: [{ kind: 'unresolved-import', detail: 'flake.lock is not among the scanned files' }] } : {} });
        } else if (locked === true) {
          controls.push({ control: 'flake-input-locked', input: inp.name, lockedBy: by, floatingRef, file, line: spanLine(inp.span) });
        }
        if (/^(?:http|git\+http|git):\/\//i.test(u)) {
          addFinding('nix-fetch-insecure-transport', { file, span: inp.span, subject: `input:${inp.name}`, name: inp.name, severity: locked === true ? 'low' : 'high', evidenceKind: 'lock', evidence: { input: inp.name, url: u, locked }, extra: { contentPinned: locked === true } });
        }
      }
      const cacheKeys = new Set(['extra-substituters', 'substituters', 'extra-trusted-substituters', 'extra-trusted-public-keys', 'trusted-public-keys']);
      for (const b of ir.bindings) {
        if (b.scope !== 'file' || b.path[0] !== 'nixConfig' || b.path.length !== 2 || !cacheKeys.has(b.path[1])) continue;
        const items = b.value.type === 'list' ? b.value.items.length : 1;
        if (!items) continue;
        addFinding('nix-flake-nixconfig-cache', { file, span: b.span, subject: `nixConfig.${b.path[1]}`, name: b.path[1], evidenceKind: 'config', evidence: { setting: b.path[1], effective: 'only if the user accepts the flake config or accept-flake-config is true' }, trustBoundary: CACHE_TRUST_BOUNDARY });
      }
    }
  }

  for (const file of Object.keys(files).sort()) {
    if (!/\.nix$/.test(file) || isLanguageExcludedPath(file)) continue;
    try { analyzeSource(file, files[file]); } catch (e) {
      gaps.push({ kind: 'analysis-error', detail: `build-trust source analysis failed: ${String((e && e.message) || e)}`, file, line: 1 });
    }
  }

  // ── CONFIG half ──
  const entry = opts.entry || (typeof files['configuration.nix'] === 'string' ? 'configuration.nix' : null);
  let cfg = null;
  if (entry && typeof files[entry] === 'string') {
    try { cfg = resolveNixosConfig({ entry, files, target: opts.target }); } catch (e) {
      gaps.push({ kind: 'config-resolution-failed', detail: String((e && e.message) || e), file: entry, line: 1 });
    }
  }
  if (cfg) {
    context = { target: cfg.target, release: cfg.target && cfg.target.release ? normalizeRelease(cfg.target.release) : null, releaseSource: cfg.target && cfg.target.releaseSource ? cfg.target.releaseSource : undefined, catalogRevision: cfg.catalog && cfg.catalog.revision ? cfg.catalog.revision : (cfg.catalog || null), scope: 'nix.conf as applied by the NixOS module system' };
    const partial = cfg.completeness !== 'complete';
    const eoRes = cfg.lookup('nix.extraOptions');
    const eoView = view(eoRes);
    const extra = { text: eoView.state === 'known' && typeof eoView.value === 'string' ? { lines: parseExtraOptions(eoView.value), evidence: optionEvidence(eoRes), anchor: optionAnchor(eoRes), definite: !!eoView.definite } : null };
    const pkgRes = cfg.lookup('nix.package');
    const nixPackage = (pkgRes.sources || []).length ? 'set explicitly (the Nix version is not evaluated)' : 'release default (the Nix version follows the NixOS release)';
    const S = (key) => readSetting(cfg, key, extra);
    const anchorOfSetting = (s) => s.anchors[s.anchors.length - 1] || { file: entry, line: 1 };
    const emit = (rule, s, j, { severity, subject, extra: more = {}, trustBoundary } = {}) => addFinding(rule, {
      severity, file: anchorOfSetting(s).file, line: anchorOfSetting(s).line, subject: subject || `nix.settings.${s.key}`, name: `nix.settings.${s.key}`,
      state: j === 'conditional' ? 'conditional' : 'active', uncertain: !s.definite, partial, evidenceKind: 'config', capability: 'iac',
      evidence: { setting: s.key, effectiveValue: s.list ? s.items : s.value, possibleValues: s.state === 'conditional' ? (s.list ? s.possibleItems : s.possible) : undefined, viaExtraOptions: s.viaText, nixPackage, options: s.evidence },
      trustBoundary, extra: more,
    });

    // trusted-users
    {
      const s = S('trusted-users');
      const wide = (x) => typeof x === 'string' && x !== 'root';
      const j = holds(s, wide);
      if (j === 'yes' || j === 'conditional') {
        const items = (j === 'yes' ? s.items : s.possibleItems).filter(wide);
        const sev = items.some((x) => x === '*' || x === '@all') ? 'high' : 'medium';
        emit('nix-trusted-users-widened', s, j, { severity: sev, extra: { widenedBy: items } });
      } else if (s.state === 'known') controls.push({ control: 'trusted-users-root-only', option: 'nix.settings.trusted-users', applies: true, value: s.items });
    }

    // signature checking and cache transport
    const sigs = S('require-sigs');
    const features = S('experimental-features');
    const caEnabled = holds(features, (x) => x === 'ca-derivations') === 'yes';
    {
      const j = holds(sigs, (x) => x === false);
      if (j === 'yes' || j === 'conditional') {
        emit('nix-require-sigs-disabled', sigs, j, { extra: { affects: 'input-addressed paths', contentAddressedPathsAffected: false, caDerivationsEnabled: caEnabled }, trustBoundary: CACHE_TRUST_BOUNDARY });
      } else if (sigs.state === 'known') controls.push({ control: 'signatures-required', option: 'nix.settings.require-sigs', applies: true, note: caEnabled ? 'content-addressed paths are verified by address; signatures cover input-addressed paths' : undefined });
    }
    {
      const sigsOff = holds(sigs, (x) => x === false) === 'yes';
      for (const key of ['substituters', 'trusted-substituters']) {
        const s = S(key);
        const http = (x) => typeof x === 'string' && /^http:\/\//i.test(x);
        const j = holds(s, http);
        if (j === 'yes' || j === 'conditional') {
          emit('nix-substituter-insecure-transport', s, j, { severity: sigsOff ? 'high' : 'low', extra: { signaturesRequired: !sigsOff, insecureSubstituters: (j === 'yes' ? s.items : s.possibleItems).filter(http) }, trustBoundary: CACHE_TRUST_BOUNDARY });
        }
      }
    }
    {
      const s = S('accept-flake-config');
      const j = holds(s, (x) => x === true);
      if (j === 'yes' || j === 'conditional') emit('nix-accept-flake-config', s, j, { trustBoundary: CACHE_TRUST_BOUNDARY });
    }

    // sandbox
    {
      const s = S('sandbox');
      const j = holds(s, (x) => x === false || x === 'relaxed');
      if (j === 'yes' || j === 'conditional') emit('nix-sandbox-disabled', s, j, { severity: s.value === 'relaxed' ? 'medium' : 'high', extra: { mode: s.value === 'relaxed' ? 'relaxed' : 'off' } });
      else if (s.state === 'known' && s.value === true) controls.push({ control: 'sandbox-enabled', option: 'nix.settings.sandbox', applies: true });
      {
        const sp = S('sandbox-paths'); // also reads extra-sandbox-paths
        const bad = (x) => typeof x === 'string' && SENSITIVE_PATHS.some((re) => re.test(x.split('=').pop().replace(/\?$/, '')));
        const jp = holds(sp, bad);
        if (jp === 'yes' || jp === 'conditional') {
          emit('nix-sandbox-sensitive-path', sp, jp, { extra: { paths: (jp === 'yes' ? sp.items : sp.possibleItems).filter(bad) } });
        }
      }
      const bu = S('build-users-group');
      const jb = holds(bu, (x) => x === '' || (Array.isArray(x) && x.length === 0));
      if (jb === 'yes' || jb === 'conditional') emit('nix-build-users-group-empty', bu, jb);
    }

    // native evaluation and IFD policy
    {
      const s = S('allow-unsafe-native-code-during-evaluation');
      const j = holds(s, (x) => x === true);
      if (j === 'yes' || j === 'conditional') emit('nix-unsafe-native-eval', s, j);
      const pl = S('plugin-files');
      const jp = holds(pl, (x) => typeof x === 'string' && x !== '');
      if (jp === 'yes' || jp === 'conditional') emit('nix-eval-native-plugin', pl, jp);
      const eb = S('extra-builtins-file');
      const je = holds(eb, (x) => typeof x === 'string' && x !== '');
      if (je === 'yes' || je === 'conditional') emit('nix-extra-builtins-file', eb, je);
      const ifd = S('allow-import-from-derivation');
      const ji = holds(ifd, (x) => x === true);
      if (ji === 'yes' || ji === 'conditional') emit('nix-ifd-policy-enabled', ifd, ji);
      else if (ifd.state === 'known' && ifd.value === false) controls.push({ control: 'ifd-disabled', option: 'nix.settings.allow-import-from-derivation', applies: true });
      inventory.ifdPolicy = ifd.state === 'known' ? (ifd.value === false ? 'forbidden' : 'allowed') : 'unspecified';
      if (inventory.ifdPolicy === 'forbidden') {
        for (const f of findings) {
          if (f.rule === 'nix-ifd-boundary') { f.evidence = { ...f.evidence, policyBlocks: true }; f.severity = 'info'; f.description += ' Policy allow-import-from-derivation = false forbids this at evaluation time.'; }
        }
      }
    }
    for (const u of cfg.unresolved || []) {
      if (!['home-manager-function-module'].includes(u.kind)) gaps.push({ kind: u.kind, detail: u.detail, file: u.file || entry, line: 1 });
    }
    for (const t of cfg.truncated || []) gaps.push({ kind: 'truncated', detail: `module evaluation budget "${t.budget}" reached`, file: entry, line: 1 });
  }

  findings.sort((a, b) => a.id.localeCompare(b.id) || a.line - b.line);
  redactUrlsDeep(findings); redactUrlsDeep(inventory); redactUrlsDeep(gaps);
  return {
    kind: 'nix-build-trust-report', version: 1, rulesetVersion: BUILD_TRUST_RULESET_VERSION,
    target: context.target, release: context.release, catalog: context.catalogRevision || null,
    findings, controls, inventory, gaps,
    scope: { executed: false, network: false, note: 'fetch, IFD and custom builders are reported as boundaries; nothing is evaluated, fetched or run', cacheTrust: CACHE_TRUST_BOUNDARY },
  };
}

// ── language pipeline adapter ──────────────────────────────────────────────

export function ensureNixBuildTrustProducer() {
  if (!isRegisteredLanguageProducer(NIX_BUILD_TRUST_PRODUCER)) {
    registerLanguageProducer({ id: NIX_BUILD_TRUST_PRODUCER, language: 'nix', capability: 'sca', evidenceKinds: ['source', 'lock', 'config'], version: '1' });
  }
  return NIX_BUILD_TRUST_PRODUCER;
}

/**
 * Adapter for runLanguageAnalysis. The configuration half needs the whole file set, so it is
 * computed once from `opts.files` and each file receives the findings anchored in it. Gaps become
 * `unresolved` outcomes, which scan health reports.
 * @param {{files: Record<string,string>, entry?: string, target?: object}} opts
 */
export function createNixBuildTrustAdapter(opts = {}) {
  ensureNixBuildTrustProducer();
  let report = null;
  const get = () => (report = report || analyzeNixBuildTrust(opts));
  const home = () => opts.entry || 'configuration.nix';
  return {
    id: NIX_BUILD_TRUST_PRODUCER,
    language: 'nix',
    hasGrammar: () => loadNixGrammar().available,
    report: get,
    analyze(file) {
      const r = get();
      return {
        findings: r.findings.filter((f) => (f.file || home()) === file),
        unresolved: r.gaps.filter((g) => (g.file || home()) === file).map((g) => ({ line: g.line || 1, reason: `${g.kind}: ${g.detail}` })),
      };
    },
  };
}
