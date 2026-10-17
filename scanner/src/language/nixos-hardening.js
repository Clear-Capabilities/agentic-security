// NixOS service, access and host hardening rules (NIX-004).
//
// Judges the EFFECTIVE configuration produced by nixos-module-resolver.js (NIX-002),
// never raw text, so a commented-out assignment, an option on a disabled service, a
// renamed option spelled the old way, or a mkForce safe override is judged by what the
// module system would actually select. Every finding carries the option source(s),
// the effective value, the catalog revision and release, a severity and a remediation
// rationale.
//
// Three different claims are kept apart and never merged:
//   enabled    the service/option is switched on in the effective config;
//   listening  it opens a port in the model (ssh ports, an option that binds all
//              interfaces, a published container port);
//   reachable  a remote party can connect. Network topology (cloud security groups,
//              NAT, upstream firewalls) is not in the configuration, so this is ALWAYS
//              `unknown`; only the host firewall is modelled (`ingress`).
//
// A finding is capped at `medium` and marked `conditional` when the service state or
// the offending value depends on an undecidable condition, and when the module graph is
// partial. A definition that is inactive (service disabled/absent, condition false) never
// produces a finding. Nothing here runs `nix`, evaluates a derivation, or scans image
// layers: OCI/nixos-container declarations are modelled as declarations only.

import { resolveNixosConfig } from './nixos-module-resolver.js';
import { parseNix } from './nix-parser.js';
import { normalizeRelease } from './nixos-option-catalog.js';

export const HARDENING_RULESET_VERSION = 'nixos-hardening/1';

const SEV_ORDER = ['info', 'low', 'medium', 'high', 'critical'];
const capSeverity = (sev, max) => (SEV_ORDER.indexOf(sev) > SEV_ORDER.indexOf(max) ? max : sev);

/** Policy families. `severity` is the BASE; `ruleVersion` bumps when a rule's meaning changes. */
export const HARDENING_RULES = Object.freeze({
  'ssh-root-login': { family: 'ssh-access', cwe: 'CWE-250', severity: 'high', ruleVersion: 1, vuln: 'SSH permits direct root login with a password', why: 'A direct root login removes per-user accountability and gives an attacker who guesses or phishes one credential immediate full control.', fix: 'Set services.openssh.settings.PermitRootLogin = "no" (or "prohibit-password" with key-only access) and administer through a named wheel user.' },
  'ssh-password-auth': { family: 'ssh-access', cwe: 'CWE-307', severity: 'medium', ruleVersion: 1, vuln: 'SSH accepts password authentication', why: 'Passwords can be guessed or reused; key-only authentication removes the online guessing surface.', fix: 'Set services.openssh.settings.PasswordAuthentication = false and services.openssh.settings.KbdInteractiveAuthentication = false, with authorized keys on the users.' },
  'ssh-empty-passwords': { family: 'ssh-access', cwe: 'CWE-258', severity: 'high', ruleVersion: 1, vuln: 'SSH permits empty passwords', why: 'An account with an empty password becomes a login with no secret at all.', fix: 'Remove services.openssh.settings.PermitEmptyPasswords or set it to false.' },
  'firewall-disabled': { family: 'firewall-exposure', cwe: 'CWE-284', severity: 'high', ruleVersion: 1, vuln: 'Host firewall is disabled', why: 'With the NixOS firewall off every listening service is open on every interface, and the only barrier left is whatever network sits in front of the host.', fix: 'Remove networking.firewall.enable = false and open only the ports each service needs.' },
  'firewall-sensitive-port': { family: 'firewall-exposure', cwe: 'CWE-668', severity: 'high', ruleVersion: 1, vuln: 'Firewall opens a database or administration port on every interface', why: 'Database, cache and container-control ports are not designed to face untrusted networks; a global allow rule exposes them wherever the host is routable.', fix: 'Remove the port from networking.firewall.allowedTCPPorts/allowedUDPPorts, or scope it with networking.firewall.interfaces.<name>.allowedTCPPorts to a private interface.' },
  'firewall-wide-port-range': { family: 'firewall-exposure', cwe: 'CWE-668', severity: 'high', ruleVersion: 1, vuln: 'Firewall opens a very wide port range on every interface', why: 'A range that spans every port (or ten thousand or more) is a firewall that is off in everything but name: whatever listens inside it, now or after the next package change, is reachable.', fix: 'Replace the range with the specific ports the services need in networking.firewall.allowedTCPPorts, or scope a genuinely needed range with networking.firewall.interfaces.<name>.allowedTCPPortRanges to a private interface.' },
  'listener-all-interfaces': { family: 'firewall-exposure', cwe: 'CWE-668', severity: 'medium', ruleVersion: 1, vuln: 'Service is configured to listen on every interface', why: 'Binding all interfaces widens the set of networks that can reach the service beyond the host itself.', fix: 'Leave the listener on localhost, or restrict listen addresses and the firewall to the interface that needs access.' },
  'listener-trust-auth': { family: 'firewall-exposure', cwe: 'CWE-306', severity: 'high', ruleVersion: 1, vuln: 'Database authentication is "trust" for a network-wide address range', why: 'A trust rule for 0.0.0.0/0 lets any client that reaches the port in as any user without a password.', fix: 'Use scram-sha-256 in services.postgresql.authentication and limit the address range.' },
  'service-runs-as-root': { family: 'service-identity', cwe: 'CWE-250', severity: 'medium', ruleVersion: 1, vuln: 'systemd service runs as root', why: 'A compromise of a root service is a compromise of the host; a dedicated or dynamic user confines it.', fix: 'Set serviceConfig.DynamicUser = true or serviceConfig.User to a dedicated account, and add NoNewPrivileges and ProtectSystem.' },
  'service-exec-elevated': { family: 'service-identity', cwe: 'CWE-250', severity: 'medium', ruleVersion: 1, vuln: 'ExecStart uses a privilege-preserving prefix', why: 'A "+" or "!" prefix runs the command with full privileges even when User is set, defeating the identity the service appears to have.', fix: 'Drop the "+"/"!" prefix, or move the privileged step into a separate, minimal ExecStartPre unit.' },
  'systemd-dangerous-capability': { family: 'systemd-privilege', cwe: 'CWE-250', severity: 'high', ruleVersion: 1, vuln: 'systemd service holds a dangerous Linux capability', why: 'CAP_SYS_ADMIN, CAP_SYS_MODULE, CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH and similar are close to root for escape and tampering purposes.', fix: 'Remove the capability from AmbientCapabilities/CapabilityBoundingSet, or grant the narrowest one the service needs.' },
  'systemd-device-access': { family: 'systemd-privilege', cwe: 'CWE-250', severity: 'high', ruleVersion: 1, vuln: 'systemd service may access raw memory or all devices', why: 'Read/write access to /dev/mem, /dev/kmem or every character device bypasses process isolation.', fix: 'Remove the DeviceAllow entry and keep PrivateDevices = true.' },
  'systemd-filesystem-relaxed': { family: 'systemd-privilege', cwe: 'CWE-732', severity: 'medium', ruleVersion: 1, vuln: 'systemd service filesystem protection is disabled or the root is writable', why: 'ProtectSystem = false, a writable "/" or PrivateTmp = false removes the read-only/isolated view hardening provides.', fix: 'Use ProtectSystem = "strict" with explicit ReadWritePaths, and PrivateTmp = true.' },
  'systemd-no-new-privileges-off': { family: 'systemd-privilege', cwe: 'CWE-269', severity: 'low', ruleVersion: 1, vuln: 'NoNewPrivileges is explicitly disabled', why: 'With it off, a compromised process can gain privileges through setuid binaries or file capabilities.', fix: 'Remove serviceConfig.NoNewPrivileges = false, or set it to true.' },
  'sudo-passwordless-wheel': { family: 'privilege-escalation', cwe: 'CWE-250', severity: 'high', ruleVersion: 1, vuln: 'Members of wheel get passwordless root through sudo', why: 'Any process running as a wheel user, or anyone with that user\'s session, becomes root with no second factor.', fix: 'Leave security.sudo.wheelNeedsPassword at its default (true), or grant NOPASSWD only to a specific command.' },
  'sudo-nopasswd-all': { family: 'privilege-escalation', cwe: 'CWE-250', severity: 'high', ruleVersion: 1, vuln: 'sudoers grants NOPASSWD for ALL commands', why: 'An unrestricted passwordless rule is equivalent to root for the matched user or group.', fix: 'Restrict the rule to the exact commands needed, or require a password.' },
  'doas-nopass': { family: 'privilege-escalation', cwe: 'CWE-250', severity: 'high', ruleVersion: 1, vuln: 'doas permits passwordless privilege escalation', why: 'A "permit nopass" rule with no command restriction is passwordless root for the matched identity.', fix: 'Add a "cmd" restriction and drop nopass, or require authentication.' },
  'tls-verification-disabled': { family: 'tls-runtime', cwe: 'CWE-295', severity: 'medium', ruleVersion: 1, vuln: 'Service environment disables TLS certificate verification', why: 'An environment variable such as NODE_TLS_REJECT_UNAUTHORIZED = "0" is a declared intent to accept any certificate, which allows man-in-the-middle interception. It does not prove the application reads it.', fix: 'Remove the variable and provide the CA through the service trust store instead.' },
  'tls-key-in-store': { family: 'tls-runtime', cwe: 'CWE-312', severity: 'high', ruleVersion: 1, vuln: 'TLS private key is copied into the world-readable Nix store', why: 'A Nix path literal (or an interpolated path) is imported into /nix/store when the configuration is evaluated, and every local user can read the store. A private key must be a runtime path the service reads at start.', fix: 'Reference the key as a string outside the store, provisioned at runtime (systemd credentials, agenix, sops-nix): `sslCertificateKey = "/run/credentials/app.key";`.' },
  'tls-not-enforced': { family: 'tls-runtime', cwe: 'CWE-319', severity: 'medium', ruleVersion: 1, vuln: 'Virtual host explicitly serves cleartext HTTP (forceSSL = false)', why: 'forceSSL = false is a deliberate choice to keep the plain-HTTP listener open for the whole host, so credentials and session data cross the network unencrypted.', fix: 'Set `forceSSL = true` (with `enableACME = true` or a certificate) so HTTP is redirected to HTTPS.' },
  'container-privileged': { family: 'container-declaration', cwe: 'CWE-250', severity: 'high', ruleVersion: 1, vuln: 'OCI container is declared privileged or with a dangerous mount', why: '--privileged, SYS_ADMIN/ALL capabilities and the container runtime socket give the container control of the host. Image layers are NOT scanned.', fix: 'Remove --privileged and the runtime socket mount; add only the specific capability the workload needs.' },
  'container-host-network': { family: 'container-declaration', cwe: 'CWE-668', severity: 'medium', ruleVersion: 1, vuln: 'OCI container shares the host network namespace', why: 'Host networking removes network isolation, so the container can reach and bind host-local services. Image layers are NOT scanned.', fix: 'Use the default bridge and publish only the needed ports on a specific address.' },
  'user-root-equivalent-group': { family: 'privilege-escalation', cwe: 'CWE-269', severity: 'medium', ruleVersion: 1, vuln: 'A user is a member of a group that is equivalent to root', why: 'Membership of docker or lxd lets the user start a container with the host filesystem mounted, and membership of disk gives raw read and write access to the block devices. Each is root on the machine, without sudo and without a password prompt.', fix: 'Remove the group. Use rootless containers (virtualisation.docker.rootless, podman) or run the tool through sudo with a narrow rule.' },
  'user-uid-zero': { family: 'privilege-escalation', cwe: 'CWE-250', severity: 'high', ruleVersion: 1, vuln: 'A user other than root has user id 0', why: 'User id 0 is root: the kernel does not look at the name. A second account with uid 0 is a root login that audit logs, sudo rules and per-user controls do not treat as root.', fix: 'Remove the uid assignment so the account gets a normal id, or use sudo for the cases that need root.' },
  'getty-autologin': { family: 'login-access', cwe: 'CWE-306', severity: 'high', ruleVersion: 1, vuln: 'The console logs a user in without a password', why: 'services.getty.autologinUser starts a session on every virtual console with no authentication. For root that is a root shell for anyone with the keyboard, a serial line or a hypervisor console.', fix: 'Remove services.getty.autologinUser. Keep autologin to throwaway virtual machines and tests.' },
  'display-autologin': { family: 'login-access', cwe: 'CWE-306', severity: 'low', ruleVersion: 1, vuln: 'The display manager logs a user in without a password', why: 'Automatic login skips authentication at the graphical login, so anyone who can power the machine on gets the session. Disk encryption is the only remaining barrier.', fix: 'Disable autoLogin, or keep it only where physical access is controlled and the disk is encrypted.' },
  'pam-null-password': { family: 'login-access', cwe: 'CWE-258', severity: 'high', ruleVersion: 1, vuln: 'A PAM service accepts accounts with an empty password', why: 'allowNullPassword lets an account with no password log in through this service with an empty answer, which turns every passwordless account into an open login.', fix: 'Remove allowNullPassword (it defaults to false) and give every account a password hash or a key.' },
  'nix-sandbox-off': { family: 'nix-daemon-trust', cwe: 'CWE-693', severity: 'medium', ruleVersion: 1, vuln: 'The Nix build sandbox is disabled', why: 'With the sandbox off, a build can read the host filesystem and the network, so a malicious or impure derivation can steal files and secrets or change its output depending on the host.', fix: 'Remove nix.settings.sandbox = false (the default is true). Fix the one derivation that needs impurity instead of weakening every build.' },
  'nix-signatures-off': { family: 'nix-daemon-trust', cwe: 'CWE-347', severity: 'high', ruleVersion: 1, vuln: 'Nix accepts unsigned store paths', why: 'require-sigs = false lets the daemon import any store path from a client or substituter without a trusted signature, so whoever can push a path can run code as every user of that path.', fix: 'Remove nix.settings.require-sigs = false and sign the paths you copy with a key listed in trusted-public-keys.' },
  'nix-trusted-users-wildcard': { family: 'nix-daemon-trust', cwe: 'CWE-269', severity: 'high', ruleVersion: 1, vuln: 'Every user is a Nix trusted user', why: 'A trusted user can import unsigned paths and set daemon options, which is root on the machine. Listing "*" or a broad group extends that to everyone who can reach the daemon.', fix: 'Keep nix.settings.trusted-users to root (and named administrators). Give other users nix.settings.allowed-users instead.' },
  'kernel-sysctl-weakened': { family: 'kernel-hardening', cwe: 'CWE-693', severity: 'medium', ruleVersion: 1, vuln: 'A kernel hardening sysctl is set to a weaker value', why: 'Turning off address space randomisation, kernel pointer hiding or the unprivileged BPF restriction removes a mitigation that makes local exploits harder.', fix: 'Remove the boot.kernel.sysctl entry or restore the hardened value (randomize_va_space = 2, kptr_restrict = 1 or 2, unprivileged_bpf_disabled = 1).' },
  'nfs-no-root-squash': { family: 'network-filesystem', cwe: 'CWE-269', severity: 'high', ruleVersion: 1, vuln: 'NFS export keeps remote root as root', why: 'no_root_squash maps a client\'s root user to root on the exported files, so anyone with root on a client can plant setuid binaries on the server.', fix: 'Drop no_root_squash (root_squash is the default) and restrict the client list to specific hosts.' },
  'docker-tcp-no-tls': { family: 'container-declaration', cwe: 'CWE-306', severity: 'high', ruleVersion: 1, vuln: 'The Docker daemon listens on an unauthenticated TCP socket', why: 'A tcp:// host without TLS client verification gives anyone who can reach the port root on the machine, since the Docker API starts privileged containers.', fix: 'Remove the tcp:// host, or enable TLS with --tlsverify and a CA, and bind only to a private address.' },
});

/** Which rules explain each privileged entry-point kind (reconciliation join). */
const ENTRY_RULES = {
  'ssh-root-login': ['ssh-root-login'],
  'sudo-nopasswd': ['sudo-passwordless-wheel', 'sudo-nopasswd-all'],
  'doas-nopass': ['doas-nopass'],
  'root-service': ['service-runs-as-root'],
  'elevated-exec': ['service-exec-elevated'],
  'privileged-container': ['container-privileged'],
};

const SENSITIVE_PORTS =new Map([[2375, 'Docker API'], [2379, 'etcd'], [3306, 'MySQL'], [5432, 'PostgreSQL'], [5984, 'CouchDB'], [6379, 'Redis'], [9200, 'Elasticsearch'], [11211, 'memcached'], [27017, 'MongoDB']]);
const DANGEROUS_CAPS = new Set(['CAP_SYS_ADMIN', 'CAP_SYS_MODULE', 'CAP_SYS_PTRACE', 'CAP_SYS_RAWIO', 'CAP_DAC_READ_SEARCH', 'CAP_DAC_OVERRIDE', 'CAP_SYS_BOOT', 'CAP_MAC_ADMIN', 'CAP_BPF', 'CAP_NET_ADMIN', 'ALL']);
const TLS_OFF = [['NODE_TLS_REJECT_UNAUTHORIZED', (v) => v === '0'], ['GIT_SSL_NO_VERIFY', (v) => /^(1|true|yes)$/i.test(v)], ['PYTHONHTTPSVERIFY', (v) => v === '0'], ['CURL_INSECURE', (v) => /^(1|true|yes)$/i.test(v)]];

const lineOf = (s) => (s && s.span ? s.span.startLine : null);
const asList = (v) => (Array.isArray(v) ? v : []);
const stripNixHash = (text) => String(text).split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');

/** Effective-value view of one option result. */
function view(res) {
  if (!res) return { state: 'unknown' };
  if ((res.status === 'set' || res.status === 'default') && res.valueKnown) {
    return { state: 'known', value: res.value, via: res.status === 'default' ? 'catalog-default' : 'explicit', definite: !!res.definite };
  }
  if (res.status === 'conditional') return { state: 'conditional', possible: res.possibleValues || [], allKnown: !!res.allPossibleValuesKnown, definiteItems: res.definiteItems, possibleItems: res.possibleItems };
  return { state: 'unknown' };
}

/**
 * Does the option satisfy `pred`? -> 'yes' | 'no' | 'conditional' | 'unknown'.
 * 'conditional' means a value that satisfies it is possible but not certain.
 */
function judge(res, pred) {
  const v = view(res);
  if (v.state === 'known') return pred(v.value) ? 'yes' : 'no';
  if (v.state === 'conditional') {
    if (v.possible.some((p) => pred(p))) return 'conditional';
    return v.allKnown ? 'no' : 'unknown';
  }
  return 'unknown';
}

function evidenceOf(res) {
  const v = view(res);
  return {
    option: res.path, namespace: res.namespace, status: res.status,
    effectiveValue: v.state === 'known' ? v.value : undefined,
    valueSource: v.state === 'known' ? v.via : v.state,
    possibleValues: v.state === 'conditional' ? v.possible : undefined,
    precedence: res.precedence,
    sources: res.sources.map((s) => ({ file: s.file, line: lineOf(s), priority: s.priority, priorityLabel: s.priorityLabel, role: s.role, conditions: (s.conditions || []).map((c) => ({ text: c.text, outcome: c.outcome })) })),
    catalog: res.catalog,
    caveats: (res.caveats || []).map((c) => c.kind),
  };
}

function anchorOf(res) {
  const pick = res.sources.find((s) => s.role === 'winner') || res.sources.find((s) => s.role === 'conditional') || res.sources[0];
  return pick ? { file: pick.file, line: lineOf(pick) } : { file: null, line: null };
}

// Effective-value helpers, shared with the build-trust rules (NIX-005).
export { view as effectiveView, judge as judgeOption, evidenceOf as optionEvidence, anchorOf as optionAnchor };

/**
 * @param {Parameters<typeof resolveNixosConfig>[0]} opts  same input as resolveNixosConfig
 * @param {{config?: object}} [extra]  an already resolved config to reuse
 */
/** The right-hand-side AST node of the winning definition of `res`, read from its source span; null when unavailable. */
function rhsNodeOf(res, files) {
  const pick = res && (res.sources || []).find((x) => x.role === 'winner') || (res && (res.sources || [])[0]);
  const text = pick && files && files[pick.file];
  if (!pick || typeof text !== 'string' || !pick.span) return null;
  const slice = text.slice(pick.span.startOffset, pick.span.endOffset);
  let ast;
  try { ast = parseNix(`{ ${slice} }`).ast; } catch { return null; }
  const b = ast && ast.bindings && ast.bindings[0];
  return b && b.value ? b.value : null;
}
const hasPathNode = (n, depth = 0) => {
  if (!n || typeof n !== 'object' || depth > 12) return false;
  if (n.type === 'path') return true;
  for (const k of Object.keys(n)) { const v = n[k]; if (Array.isArray(v)) { if (v.some((x) => hasPathNode(x, depth + 1))) return true; } else if (v && typeof v === 'object' && hasPathNode(v, depth + 1)) return true; }
  return false;
};
// An expression that CREATES a store file from its arguments (`pkgs.writeText "k" "…"`): used as a key/cert option it puts the secret in the store
// exactly as a path literal does.
const STORE_WRITERS = new Set(['writeText', 'writeTextFile', 'writeTextDir', 'writeScript', 'writeScriptBin', 'toFile', 'copyPathToStore', 'runCommand', 'runCommandLocal']);
const isStoreCopy = (n, depth = 0) => {
  if (!n || typeof n !== 'object' || depth > 12) return false;
  if (n.type === 'app') { let h = n; while (h && h.type === 'app') h = h.fn; return !!h && ((h.type === 'select' && h.attrpath && h.attrpath.length && STORE_WRITERS.has(h.attrpath[h.attrpath.length - 1].name)) || (h.type === 'ident' && STORE_WRITERS.has(h.name))); }
  return false;
};
const strOf = (n) => (n && n.type === 'string' && typeof n.literal === 'string' ? n.literal : null);
// sudo `extraRules`: a rule is NOPASSWD for ALL when one of its `commands` is ALL (or a {command = "ALL"; options = [ "NOPASSWD" ]}) with the NOPASSWD tag.
const sudoRulesNopasswdAll = (node) => {
  if (!node || node.type !== 'list') return false;
  for (const rule of node.items || []) {
    const cmds = attrOf(rule, 'commands');
    if (!cmds || !cmds.value || cmds.value.type !== 'list') continue;
    for (const c of cmds.value.items || []) {
      if (c.type !== 'attrset') continue;
      const command = attrOf(c, 'command'); const options = attrOf(c, 'options');
      const all = command && strOf(command.value) === 'ALL';
      const nopass = options && options.value && options.value.type === 'list' && (options.value.items || []).some((x) => strOf(x) === 'NOPASSWD');
      if (all && nopass) return true;
    }
  }
  return false;
};
const attrOf = (set, name) => (set && set.type === 'attrset' ? (set.bindings || []).find((b) => b.kind === 'attr' && b.path && b.path.length === 1 && b.path[0].name === name) : null);
const isTrueNode = (n) => !!n && n.type === 'ident' && n.name === 'true';

export function analyzeNixosHardening(opts, extra = {}) {
  const cfg = extra.config || resolveNixosConfig(opts);
  const findings = [];
  const controls = [];
  const gaps = [];
  const byPath = new Map(cfg.options.map((o) => [`${o.namespace}|${o.scope || ''}|${o.path}`, o]));
  const nixos = (p) => byPath.get(`nixos||${p}`) || cfg.lookup(p);
  const partialGraph = cfg.completeness !== 'complete';
  const note = (res, purpose) => {
    if (res && (res.status === 'conflict' || res.status === 'unresolved-precedence')) gaps.push({ kind: res.status, option: res.path, purpose, reason: res.reason });
    return res;
  };

  // ── host-level facts ──
  const fwEnableRes = note(nixos('networking.firewall.enable'), 'firewall');
  const fwOn = judge(fwEnableRes, (x) => x === true);
  const fwOff = judge(fwEnableRes, (x) => x === false);
  const allowedTcp = view(note(nixos('networking.firewall.allowedTCPPorts'), 'firewall'));
  const allowedUdp = view(note(nixos('networking.firewall.allowedUDPPorts'), 'firewall'));
  const globalPorts = (v) => (v.state === 'known' ? asList(v.value) : v.state === 'conditional' ? asList(v.definiteItems) : []);
  const allowedAll = new Set([...globalPorts(allowedTcp), ...globalPorts(allowedUdp)]);
  // Port RANGES open ports exactly like single ports do. A range option that cannot be evaluated makes every firewall conclusion
  // `unknown` (never "closed"), and a range that cannot be read as {from, to} integers is disclosed, not skipped.
  const tcpRangesRes = note(nixos('networking.firewall.allowedTCPPortRanges'), 'firewall');
  const udpRangesRes = note(nixos('networking.firewall.allowedUDPPortRanges'), 'firewall');
  const readRanges = (res) => {
    const v = view(res);
    if (v.state !== 'known') return { state: v.state === 'conditional' ? 'conditional' : 'unknown', ranges: [] };
    const ranges = [];
    for (const it of asList(v.value)) {
      if (!it || !Number.isInteger(it.from) || !Number.isInteger(it.to) || it.to < it.from) return { state: 'unknown', ranges: [] };
      ranges.push({ from: it.from, to: it.to });
    }
    return { state: 'known', ranges, definite: v.definite };
  };
  const tcpRanges = readRanges(tcpRangesRes);
  const udpRanges = readRanges(udpRangesRes);
  const inTcpRange = (port) => tcpRanges.ranges.some((r) => port >= r.from && port <= r.to);
  const allowedKnown = allowedTcp.state === 'known' && allowedUdp.state === 'known' && tcpRanges.state === 'known' && udpRanges.state === 'known';
  const interfaceScoped = cfg.options.filter((o) => o.namespace === 'nixos' && /^networking\.firewall\.interfaces\.[^.]+\.allowedTCPPorts$/.test(o.path));

  /** Host-firewall ingress for a TCP port; internet reachability itself is never decided. */
  function ingressFor(port, { openFirewallRes } = {}) {
    if (fwOff === 'yes') return 'firewall-disabled';
    if (fwOn !== 'yes') return 'unknown';
    if (allowedAll.has(port) || inTcpRange(port)) return 'open-in-firewall';
    if (openFirewallRes) {
      const o = judge(openFirewallRes, (x) => x === true);
      if (o === 'yes') return 'open-in-firewall';
      if (o === 'conditional' || o === 'unknown') return 'unknown';
    }
    return allowedKnown ? (interfaceScoped.some((o) => asList(view(o).value).includes(port)) ? 'restricted-interface' : 'firewall-closed') : 'unknown';
  }

  const inventory = [];
  const entryPoints = [];
  const authz = [];
  const attackPaths = [];

  function addFinding(rule, { severity, anchor, evidence, scope, state = 'active', uncertain = false, extra: more = {}, mitigations = [] }) {
    const r = HARDENING_RULES[rule];
    const conditional = state === 'conditional';
    let sev = severity || r.severity;
    if (conditional || uncertain || partialGraph) sev = capSeverity(sev, 'medium');
    const uncertainty = [];
    if (conditional) uncertainty.push({ kind: 'unresolved-branch', detail: 'the service or value depends on a condition that could not be decided statically' });
    if (partialGraph) uncertainty.push({ kind: 'unresolved-import', detail: 'the module graph is partial; an unread module could override this value' });
    if (uncertain && !conditional) uncertainty.push({ kind: 'unresolved-branch', detail: 'the effective value carries evaluation caveats' });
    findings.push({
      id: `nixos-hardening:${rule}:${scope}`, subject: scope,
      severity: sev, file: anchor.file, line: anchor.line,
      vuln: r.vuln, cwe: r.cwe,
      description: `${r.vuln} (${scope}). ${r.why}`,
      remediation: r.fix,
      remediationRationale: r.why,
      parser: 'nixos-hardening', family: r.family,
      language: 'nix', capability: 'iac', evidenceKind: 'config', scope: 'system',
      rule, ruleVersion: r.ruleVersion, rulesetVersion: HARDENING_RULESET_VERSION, baseSeverity: r.severity,
      conditional, uncertainty: uncertainty.length ? uncertainty : undefined,
      evidence, mitigations: mitigations.length ? mitigations : undefined,
      ...more,
    });
  }

  const stateOf = (res) => {
    const j = judge(res, (x) => x === true);
    return j === 'yes' ? 'active' : j === 'conditional' ? 'conditional' : j === 'no' ? 'inactive' : 'unknown';
  };
  const hasDefs = (prefix) => cfg.options.some((o) => o.namespace === 'nixos' && o.path.startsWith(prefix));

  // ── sshd ──
  if (hasDefs('services.openssh.') || (nixos('services.openssh.enable').sources || []).length) {
    const enableRes = note(nixos('services.openssh.enable'), 'ssh');
    const openFwRes = nixos('services.openssh.openFirewall');
    const portsRes = nixos('services.openssh.ports');
    const state = stateOf(enableRes);
    const portsV = view(portsRes);
    const ports = portsV.state === 'known' ? asList(portsV.value).filter((p) => typeof p === 'number') : [];
    const ingress = ports.length ? (ports.map((p) => ingressFor(p, { openFirewallRes: openFwRes })).find((i) => i !== 'firewall-closed') || 'firewall-closed') : 'unknown';
    inventory.push({
      kind: 'declared-service', name: 'openssh', state, listening: state === 'active' ? 'yes' : state === 'conditional' ? 'unknown' : 'no', ports, ingress,
      reachability: { internet: 'unknown', reason: 'external network topology is not part of the configuration' },
      evidence: [evidenceOf(enableRes), evidenceOf(openFwRes)],
    });
    if (state === 'active' || state === 'conditional') {
      const sshState = state;
      const restricted = ingress === 'firewall-closed' || ingress === 'restricted-interface';
      const mit = restricted ? [{ kind: 'restrictive-ingress', ingress, detail: 'the host firewall does not open the ssh port globally' }] : [];
      const cap = (sev) => (restricted ? capSeverity(sev, 'medium') : sev);

      const rootRes = note(nixos('services.openssh.settings.PermitRootLogin'), 'ssh');
      const root = judge(rootRes, (x) => x === 'yes');
      if (root === 'yes' || root === 'conditional') {
        const st = root === 'conditional' || sshState === 'conditional' ? 'conditional' : 'active';
        addFinding('ssh-root-login', { severity: cap('high'), anchor: anchorOf(rootRes), scope: 'services.openssh', state: st, uncertain: !view(rootRes).definite, evidence: [evidenceOf(rootRes), evidenceOf(enableRes)], extra: { exposure: { enabled: true, listening: 'yes', ingress, reachable: 'unknown' } }, mitigations: mit });
        entryPoints.push({ id: 'ssh-root-login', kind: 'ssh-root-login', state: st, privilege: 'root', evidence: [evidenceOf(rootRes)] });
      } else if (view(rootRes).state === 'known') {
        controls.push({ control: 'ssh-root-login-restricted', value: view(rootRes).value, option: rootRes.path, applies: true });
      }

      const pwRes = note(nixos('services.openssh.settings.PasswordAuthentication'), 'ssh');
      const pw = judge(pwRes, (x) => x === true);
      if (pw === 'yes' || pw === 'conditional') {
        const st = pw === 'conditional' || sshState === 'conditional' ? 'conditional' : 'active';
        addFinding('ssh-password-auth', { severity: cap('medium'), anchor: anchorOf(pwRes), scope: 'services.openssh', state: st, uncertain: !view(pwRes).definite, evidence: [evidenceOf(pwRes)], extra: { exposure: { enabled: true, listening: 'yes', ingress, reachable: 'unknown' }, valueSource: view(pwRes).via }, mitigations: mit });
      } else if (view(pwRes).state === 'known') controls.push({ control: 'ssh-key-only', option: pwRes.path, applies: true });

      const emptyRes = nixos('services.openssh.settings.PermitEmptyPasswords');
      const empty = judge(emptyRes, (x) => x === true || x === 'yes');
      if (empty === 'yes' || empty === 'conditional') {
        addFinding('ssh-empty-passwords', { severity: cap('high'), anchor: anchorOf(emptyRes), scope: 'services.openssh', state: empty === 'conditional' || sshState === 'conditional' ? 'conditional' : 'active', uncertain: !view(emptyRes).definite, evidence: [evidenceOf(emptyRes)], mitigations: mit });
      }

      const auth = pw === 'no' ? 'key-only' : pw === 'yes' ? 'password' : 'unknown';
      if (root === 'yes' || root === 'conditional') {
        authz.push({ entryPoint: 'ssh-root-login', subject: 'network-client', authentication: auth, privilege: 'root', evidence: [evidenceOf(rootRes), evidenceOf(pwRes)] });
        attackPaths.push({ id: 'attack-path:ssh-root', entryPoint: 'ssh-root-login', steps: ['network client reaches sshd', `authenticates (${auth}) as root`, 'root shell'], requires: ['internet or network reachability of the ssh port (unknown)'], ingress, reachable: 'unknown', state: root === 'yes' && sshState === 'active' ? 'active' : 'conditional' });
      }
    }
  }

  // ── sudo / doas ──
  {
    const sudoEnable = nixos('security.sudo.enable');
    const sudoState = stateOf(sudoEnable);
    const wheelRes = note(nixos('security.sudo.wheelNeedsPassword'), 'sudo');
    const wheel = judge(wheelRes, (x) => x === false);
    if ((wheel === 'yes' || wheel === 'conditional') && sudoState !== 'inactive' && sudoState !== 'unknown') {
      const st = wheel === 'conditional' || sudoState === 'conditional' ? 'conditional' : 'active';
      addFinding('sudo-passwordless-wheel', { anchor: anchorOf(wheelRes), scope: 'security.sudo', state: st, uncertain: !view(wheelRes).definite, evidence: [evidenceOf(wheelRes), evidenceOf(sudoEnable)] });
      entryPoints.push({ id: 'sudo-wheel-nopasswd', kind: 'sudo-nopasswd', state: st, privilege: 'root', evidence: [evidenceOf(wheelRes)] });
      authz.push({ entryPoint: 'sudo-wheel-nopasswd', subject: 'local-wheel-user', authentication: 'none', privilege: 'root', evidence: [evidenceOf(wheelRes)] });
      attackPaths.push({ id: 'attack-path:wheel-sudo', entryPoint: 'sudo-wheel-nopasswd', steps: ['code runs as a wheel user', 'sudo without a password', 'root'], requires: ['a foothold as a wheel user'], state: st });
    } else if (view(wheelRes).state === 'known' && view(wheelRes).value === true) controls.push({ control: 'sudo-password-required', option: wheelRes.path, applies: sudoState === 'active' });

    const sudoCfg = note(nixos('security.sudo.extraConfig'), 'sudo');
    const sv = view(sudoCfg);
    if (sv.state === 'known' && typeof sv.value === 'string' && sudoState !== 'inactive' && sudoState !== 'unknown') {
      const text = stripNixHash(sv.value);
      if (/NOPASSWD\s*:\s*ALL\b/.test(text)) {
        addFinding('sudo-nopasswd-all', { anchor: anchorOf(sudoCfg), scope: 'security.sudo.extraConfig', state: sudoState === 'conditional' ? 'conditional' : 'active', uncertain: !sv.definite, evidence: [evidenceOf(sudoCfg)] });
        entryPoints.push({ id: 'sudo-nopasswd-all', kind: 'sudo-nopasswd', state: sudoState === 'conditional' ? 'conditional' : 'active', privilege: 'root', evidence: [evidenceOf(sudoCfg)] });
      }
    }

    const sudoRules = nixos('security.sudo.extraRules');
    if (sudoRules && sudoState !== 'inactive' && sudoState !== 'unknown' && sudoRulesNopasswdAll(rhsNodeOf(sudoRules, opts.files))) {
      addFinding('sudo-nopasswd-all', { anchor: anchorOf(sudoRules), scope: 'security.sudo.extraRules', state: sudoState === 'conditional' ? 'conditional' : 'active', uncertain: false, evidence: [evidenceOf(sudoRules)] });
      entryPoints.push({ id: 'sudo-nopasswd-all', kind: 'sudo-nopasswd', state: sudoState === 'conditional' ? 'conditional' : 'active', privilege: 'root', evidence: [evidenceOf(sudoRules)] });
    }

    const doasEnable = nixos('security.doas.enable');
    const doasState = stateOf(doasEnable);
    const doasCfg = note(nixos('security.doas.extraConfig'), 'doas');
    const dv = view(doasCfg);
    if (dv.state === 'known' && typeof dv.value === 'string' && (doasState === 'active' || doasState === 'conditional')) {
      const rules = stripNixHash(dv.value).split('\n').filter((l) => /^\s*permit\b/.test(l) && /\bnopass\b/.test(l));
      if (rules.length) {
        const unrestricted = rules.some((l) => !/\bcmd\b/.test(l));
        const st = doasState === 'conditional' ? 'conditional' : 'active';
        addFinding('doas-nopass', { severity: unrestricted ? 'high' : 'medium', anchor: anchorOf(doasCfg), scope: 'security.doas.extraConfig', state: st, uncertain: !dv.definite, evidence: [evidenceOf(doasCfg), evidenceOf(doasEnable)], extra: { restrictedToCommand: !unrestricted } });
        entryPoints.push({ id: 'doas-nopass', kind: 'doas-nopass', state: st, privilege: 'root', evidence: [evidenceOf(doasCfg)] });
      }
    }
    // The structured form: `security.doas.extraRules = [ { users = [..]; noPass = true; cmd = ".."; } ]`.
    if (doasState === 'active' || doasState === 'conditional') {
      const rulesRes = note(nixos('security.doas.extraRules'), 'doas');
      const list = rhsNodeOf(rulesRes, opts.files);
      const items = list && list.type === 'list' ? list.items : [];
      const nopass = items.filter((it) => isTrueNode((attrOf(it, 'noPass') || {}).value));
      if (nopass.length) {
        const unrestricted = nopass.some((it) => !attrOf(it, 'cmd'));
        const st = doasState === 'conditional' ? 'conditional' : 'active';
        addFinding('doas-nopass', { severity: unrestricted ? 'high' : 'medium', anchor: anchorOf(rulesRes), scope: 'security.doas.extraRules', state: st, uncertain: false, evidence: [evidenceOf(rulesRes), evidenceOf(doasEnable)], extra: { restrictedToCommand: !unrestricted } });
        entryPoints.push({ id: 'doas-nopass', kind: 'doas-nopass', state: st, privilege: 'root', evidence: [evidenceOf(rulesRes)] });
      }
    }
  }

  // ── accounts and console login ──
  // Root-equivalent groups: each of these gives the member control of the host without sudo.
  const ROOT_EQUIVALENT_GROUPS = new Map([['docker', 'start a container with the host root mounted'], ['lxd', 'start a privileged container with the host root mounted'], ['disk', 'read and write the raw block devices']]);
  for (const o of cfg.options.filter((x) => x.namespace === 'nixos' && /^users\.users\.[^.]+\.extraGroups$/.test(x.path))) {
    const name = o.path.split('.')[2];
    if (name === 'root') continue;
    const v = view(note(o, 'accounts'));
    const items = v.state === 'known' ? asList(v.value) : v.state === 'conditional' ? asList(v.definiteItems) : [];
    const bad = items.filter((g) => typeof g === 'string' && ROOT_EQUIVALENT_GROUPS.has(g));
    if (bad.length) addFinding('user-root-equivalent-group', { anchor: anchorOf(o), scope: `users.users.${name}`, state: v.state === 'conditional' ? 'conditional' : 'active', uncertain: !v.definite, evidence: [evidenceOf(o)], extra: { groups: bad, effect: bad.map((g) => `${g}: ${ROOT_EQUIVALENT_GROUPS.get(g)}`) } });
  }
  for (const o of cfg.options.filter((x) => x.namespace === 'nixos' && /^users\.users\.[^.]+\.uid$/.test(x.path))) {
    const name = o.path.split('.')[2];
    if (name === 'root') continue;
    const j = judge(note(o, 'accounts'), (x) => x === 0);
    if (j === 'yes' || j === 'conditional') addFinding('user-uid-zero', { anchor: anchorOf(o), scope: `users.users.${name}`, state: j === 'conditional' ? 'conditional' : 'active', uncertain: !view(o).definite, evidence: [evidenceOf(o)] });
  }
  const gettyRes = note(nixos('services.getty.autologinUser'), 'login');
  const gettyV = view(gettyRes);
  if (gettyV.state === 'known' && typeof gettyV.value === 'string' && gettyV.value) {
    addFinding('getty-autologin', { severity: gettyV.value === 'root' ? 'high' : 'low', anchor: anchorOf(gettyRes), scope: 'services.getty.autologinUser', state: 'active', uncertain: !gettyV.definite, evidence: [evidenceOf(gettyRes)], extra: { user: gettyV.value } });
  }
  for (const base of ['services.displayManager.autoLogin', 'services.xserver.displayManager.autoLogin']) {
    const en = note(nixos(`${base}.enable`), 'login');
    const j = judge(en, (x) => x === true);
    if (j === 'yes' || j === 'conditional') {
      const userV = view(nixos(`${base}.user`));
      addFinding('display-autologin', { severity: userV.state === 'known' && userV.value === 'root' ? 'high' : 'low', anchor: anchorOf(en), scope: base, state: j === 'conditional' ? 'conditional' : 'active', uncertain: !view(en).definite, evidence: [evidenceOf(en)], extra: userV.state === 'known' ? { user: userV.value } : {} });
    }
  }
  for (const o of cfg.options.filter((x) => x.namespace === 'nixos' && /^security\.pam\.services\.[^.]+\.allowNullPassword$/.test(x.path))) {
    const j = judge(note(o, 'login'), (x) => x === true);
    if (j === 'yes' || j === 'conditional') addFinding('pam-null-password', { anchor: anchorOf(o), scope: o.path.replace(/\.allowNullPassword$/, ''), state: j === 'conditional' ? 'conditional' : 'active', uncertain: !view(o).definite, evidence: [evidenceOf(o)] });
  }

  // ── nix daemon trust, kernel sysctls, network filesystems, docker socket ──
  const sandboxRes = note(nixos('nix.settings.sandbox'), 'nix');
  { const j = judge(sandboxRes, (x) => x === false); if (j === 'yes' || j === 'conditional') addFinding('nix-sandbox-off', { anchor: anchorOf(sandboxRes), scope: 'nix.settings.sandbox', state: j === 'conditional' ? 'conditional' : 'active', uncertain: !view(sandboxRes).definite, evidence: [evidenceOf(sandboxRes)] }); }
  const sigsRes = note(nixos('nix.settings.require-sigs'), 'nix');
  { const j = judge(sigsRes, (x) => x === false); if (j === 'yes' || j === 'conditional') addFinding('nix-signatures-off', { anchor: anchorOf(sigsRes), scope: 'nix.settings.require-sigs', state: j === 'conditional' ? 'conditional' : 'active', uncertain: !view(sigsRes).definite, evidence: [evidenceOf(sigsRes)] }); }
  const trustedRes = note(nixos('nix.settings.trusted-users'), 'nix');
  { const v = view(trustedRes);
    const items = v.state === 'known' ? asList(v.value) : v.state === 'conditional' ? asList(v.definiteItems) : [];
    if (items.some((u) => u === '*' || u === '@users' || u === '@everyone')) addFinding('nix-trusted-users-wildcard', { anchor: anchorOf(trustedRes), scope: 'nix.settings.trusted-users', state: v.state === 'conditional' ? 'conditional' : 'active', uncertain: !v.definite, evidence: [evidenceOf(trustedRes)] }); }
  const SYSCTL_WEAK = new Map([['kernel.randomize_va_space', (x) => String(x) === '0'], ['kernel.kptr_restrict', (x) => String(x) === '0'], ['kernel.unprivileged_bpf_disabled', (x) => String(x) === '0'], ['kernel.dmesg_restrict', (x) => String(x) === '0'], ['kernel.yama.ptrace_scope', (x) => String(x) === '0'], ['fs.protected_symlinks', (x) => String(x) === '0'], ['fs.protected_hardlinks', (x) => String(x) === '0']]);
  for (const o of cfg.options.filter((x) => x.namespace === 'nixos' && /^boot\.kernel\.sysctl\./.test(x.path))) {
    const key = o.path.slice('boot.kernel.sysctl.'.length).replace(/^"|"$/g, '');
    const weak = SYSCTL_WEAK.get(key);
    if (!weak) continue;
    const j = judge(note(o, 'kernel'), weak);
    if (j === 'yes' || j === 'conditional') addFinding('kernel-sysctl-weakened', { anchor: anchorOf(o), scope: `boot.kernel.sysctl.${key}`, state: j === 'conditional' ? 'conditional' : 'active', uncertain: !view(o).definite, evidence: [evidenceOf(o)], extra: { sysctl: key } });
  }
  const nfsRes = note(nixos('services.nfs.server.exports'), 'nfs');
  { const j = judge(nfsRes, (x) => typeof x === 'string' && /(^|[\s,(])no_root_squash(?=[\s,)]|$)/.test(x.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n')));
    if (j === 'yes' || j === 'conditional') addFinding('nfs-no-root-squash', { anchor: anchorOf(nfsRes), scope: 'services.nfs.server.exports', state: j === 'conditional' ? 'conditional' : 'active', uncertain: !view(nfsRes).definite, evidence: [evidenceOf(nfsRes)] }); }
  { const dockerOn = judge(nixos('virtualisation.docker.enable'), (x) => x === true);
    if (dockerOn === 'yes' || dockerOn === 'conditional') {
      const optRes = nixos('virtualisation.docker.extraOptions');
      const hostsRes = nixos('virtualisation.docker.daemon.settings.hosts');
      const tlsOn = ['tls', 'tlsverify'].some((k) => view(nixos(`virtualisation.docker.daemon.settings.${k}`)).value === true);
      const j1 = judge(optRes, (x) => typeof x === 'string' && /(?:-H|--host)[ =]+tcp:\/\//.test(x) && !/--tlsverify|--tls\b/.test(x));
      const j2 = tlsOn ? 'no' : judge(hostsRes, (x) => Array.isArray(x) && x.some((h) => typeof h === 'string' && /^tcp:\/\//.test(h)));
      const j = j1 === 'yes' ? 'yes' : j2 === 'yes' ? 'yes' : j1 === 'conditional' || j2 === 'conditional' ? 'conditional' : 'no';
      if (j === 'yes' || j === 'conditional') { const res = j1 !== 'no' ? optRes : hostsRes; addFinding('docker-tcp-no-tls', { anchor: anchorOf(res), scope: 'virtualisation.docker', state: j === 'conditional' || dockerOn === 'conditional' ? 'conditional' : 'active', uncertain: false, evidence: [evidenceOf(res)] }); }
    } }

  // ── databases / listeners ──
  if (hasDefs('services.postgresql.')) {
    const enableRes = nixos('services.postgresql.enable');
    const state = stateOf(enableRes);
    let tcpRes = nixos('services.postgresql.enableTCPIP');
    let tcp = judge(tcpRes, (x) => x === true);
    // `settings.listen_addresses` is the current spelling of the same decision: a wildcard binds every interface
    const listenRes = nixos('services.postgresql.settings.listen_addresses');
    const wildcardListen = judge(listenRes, (x) => typeof x === 'string' && x.split(',').map((a) => a.trim()).some((a) => a === '*' || a === '0.0.0.0' || a === '::'));
    if (tcp !== 'yes' && (wildcardListen === 'yes' || wildcardListen === 'conditional')) { tcpRes = listenRes; tcp = wildcardListen; }
    const ingress = ingressFor(5432);
    inventory.push({ kind: 'declared-service', name: 'postgresql', state, listening: state === 'active' ? (tcp === 'yes' ? 'yes' : tcp === 'no' ? 'localhost-only' : 'unknown') : state === 'conditional' ? 'unknown' : 'no', ports: [5432], ingress, reachability: { internet: 'unknown', reason: 'external network topology is not part of the configuration' }, evidence: [evidenceOf(enableRes), evidenceOf(tcpRes)] });
    if ((state === 'active' || state === 'conditional') && (tcp === 'yes' || tcp === 'conditional')) {
      const st = state === 'conditional' || tcp === 'conditional' ? 'conditional' : 'active';
      const restricted = ingress === 'firewall-closed' || ingress === 'restricted-interface';
      addFinding('listener-all-interfaces', { severity: restricted ? 'low' : ingress === 'open-in-firewall' || ingress === 'firewall-disabled' ? 'high' : 'medium', anchor: anchorOf(tcpRes), scope: 'services.postgresql', state: st, uncertain: !view(tcpRes).definite, evidence: [evidenceOf(tcpRes), evidenceOf(enableRes)], extra: { exposure: { enabled: true, listening: 'yes', ingress, reachable: 'unknown' } }, mitigations: restricted ? [{ kind: 'restrictive-ingress', ingress }] : [] });
    }
    const authRes = nixos('services.postgresql.authentication');
    const av = view(authRes);
    if (av.state === 'known' && typeof av.value === 'string' && (state === 'active' || state === 'conditional')) {
      const bad = stripNixHash(av.value).split('\n').some((l) => /^\s*host\S*\s+\S+\s+\S+\s+(0\.0\.0\.0\/0|::\/0)\s+trust\b/.test(l));
      if (bad) addFinding('listener-trust-auth', { anchor: anchorOf(authRes), scope: 'services.postgresql.authentication', state: state === 'conditional' ? 'conditional' : 'active', uncertain: !av.definite, evidence: [evidenceOf(authRes)] });
    }
  }
  if (hasDefs('services.nginx.')) {
    const enableRes = nixos('services.nginx.enable');
    const state = stateOf(enableRes);
    inventory.push({ kind: 'declared-service', name: 'nginx', state, listening: state === 'active' ? 'unknown' : state === 'conditional' ? 'unknown' : 'no', ports: [], ingress: 'unknown', reachability: { internet: 'unknown', reason: 'listen addresses are generated by the module and external topology is not modelled' }, evidence: [evidenceOf(enableRes)] });
  }

  // ── other services that choose their bind address ──
  // The same decision postgresql makes above. Only an EXPLICIT wildcard (or, for redis, an explicit null, which the module defines as "every interface") is reported:
  // an unset option keeps the module's own default, which the catalog does not record for these services and which is never guessed.
  const WILDCARD = (x, nullIsAll) => (x === null ? nullIsAll === true : typeof x === 'string' && x.split(/[\s,]+/).filter(Boolean).some((a) => a === '*' || a === '0.0.0.0' || a === '::' || a === '[::]'));
  const LISTENERS = [
    { name: 'redis', pattern: /^services\.redis\.servers\.([^.]+)\.bind$/, enable: (m) => `services.redis.servers.${m[1]}.enable`, portOpt: (m) => `services.redis.servers.${m[1]}.port`, port: 6379, nullIsAll: true, scope: (m) => `services.redis.servers.${m[1]}` },
    { name: 'mysql', pattern: /^services\.mysql\.settings\.mysqld\.(?:bind-address|bind_address)$/, enable: () => 'services.mysql.enable', port: 3306, scope: () => 'services.mysql' },
    { name: 'mongodb', pattern: /^services\.mongodb\.bind_ip$/, enable: () => 'services.mongodb.enable', port: 27017, scope: () => 'services.mongodb' },
    { name: 'memcached', pattern: /^services\.memcached\.listen$/, enable: () => 'services.memcached.enable', portOpt: () => 'services.memcached.port', port: 11211, scope: () => 'services.memcached' },
    { name: 'elasticsearch', pattern: /^services\.elasticsearch\.listenAddress$/, enable: () => 'services.elasticsearch.enable', portOpt: () => 'services.elasticsearch.port', port: 9200, scope: () => 'services.elasticsearch' },
    { name: 'grafana', pattern: /^services\.grafana\.settings\.server\.http_addr$/, enable: () => 'services.grafana.enable', port: 3000, scope: () => 'services.grafana' },
  ];
  for (const L of LISTENERS) {
    for (const o of cfg.options.filter((x) => x.namespace === 'nixos' && L.pattern.test(x.path))) {
      const m = L.pattern.exec(o.path);
      const listenRes = note(o, 'listener');
      const wild = judge(listenRes, (x) => WILDCARD(x, L.nullIsAll));
      if (wild !== 'yes' && wild !== 'conditional') continue;
      const enableRes = note(nixos(L.enable(m)), 'listener');
      const state = stateOf(enableRes);
      if (state !== 'active' && state !== 'conditional') continue;
      let port = L.port;
      if (L.portOpt) { const pv = view(nixos(L.portOpt(m))); if (pv.state === 'known' && Number.isInteger(pv.value) && pv.value > 0) port = pv.value; }
      const ingress = ingressFor(port);
      const scope = L.scope(m);
      inventory.push({ kind: 'declared-service', name: L.name, state, listening: 'yes', ports: [port], ingress, reachability: { internet: 'unknown', reason: 'external network topology is not part of the configuration' }, evidence: [evidenceOf(enableRes), evidenceOf(listenRes)] });
      const st = state === 'conditional' || wild === 'conditional' ? 'conditional' : 'active';
      const restricted = ingress === 'firewall-closed' || ingress === 'restricted-interface';
      addFinding('listener-all-interfaces', { severity: restricted ? 'low' : ingress === 'open-in-firewall' || ingress === 'firewall-disabled' ? 'high' : 'medium', anchor: anchorOf(listenRes), scope, state: st, uncertain: !view(listenRes).definite, evidence: [evidenceOf(listenRes), evidenceOf(enableRes)], extra: { exposure: { enabled: true, listening: 'yes', ingress, reachable: 'unknown' } }, mitigations: restricted ? [{ kind: 'restrictive-ingress', ingress }] : [] });
    }
  }

  // ── TLS material and enforcement on nginx virtual hosts ──
  if (hasDefs('services.nginx.')) {
    const nginxState = stateOf(nixos('services.nginx.enable'));
    if (nginxState === 'active' || nginxState === 'conditional') {
      const st = nginxState === 'conditional' ? 'conditional' : 'active';
      for (const o of cfg.options.filter((x) => x.namespace === 'nixos' && /^services\.nginx\.virtualHosts\..+\.(?:sslCertificateKey|sslTrustedCertificate)$/.test(x.path))) {
        const node = rhsNodeOf(o, opts.files);
        if (node && (hasPathNode(node) || isStoreCopy(node))) addFinding('tls-key-in-store', { anchor: anchorOf(o), scope: o.path, state: st, uncertain: false, evidence: [evidenceOf(o)] });
        else if (view(o).state === 'known' && typeof view(o).value === 'string') controls.push({ control: 'tls-key-runtime-path', option: o.path, applies: true });
      }
      for (const o of cfg.options.filter((x) => x.namespace === 'nixos' && /^services\.nginx\.virtualHosts\..+\.forceSSL$/.test(x.path))) {
        const j = judge(o, (x) => x === false);
        if (j === 'yes' || j === 'conditional') addFinding('tls-not-enforced', { anchor: anchorOf(o), scope: o.path, state: j === 'conditional' || st === 'conditional' ? 'conditional' : 'active', uncertain: !view(o).definite, evidence: [evidenceOf(o)] });
        else if (judge(o, (x) => x === true) === 'yes') controls.push({ control: 'tls-enforced', option: o.path, applies: true });
      }
    }
  }

  // ── firewall ──
  const listeningNow = inventory.filter((i) => i.state === 'active' && i.listening !== 'no' && i.listening !== 'localhost-only');
  if (fwOff === 'yes' || fwOff === 'conditional') {
    const st = fwOff === 'conditional' ? 'conditional' : 'active';
    addFinding('firewall-disabled', { severity: listeningNow.length ? 'high' : 'medium', anchor: anchorOf(fwEnableRes), scope: 'networking.firewall', state: st, uncertain: !view(fwEnableRes).definite, evidence: [evidenceOf(fwEnableRes)], extra: { listeningServices: listeningNow.map((i) => i.name) } });
  } else if (fwOn === 'yes') controls.push({ control: 'host-firewall-enabled', option: fwEnableRes.path, applies: true, valueSource: view(fwEnableRes).via });
  for (const res of [nixos('networking.firewall.allowedTCPPorts'), nixos('networking.firewall.allowedUDPPorts')]) {
    const v = view(res);
    const candidates = v.state === 'conditional' ? asList(v.possibleItems).concat(asList(v.definiteItems)) : globalPorts(v);
    const ports = [...new Set(candidates)].filter((p) => SENSITIVE_PORTS.has(p));
    for (const port of ports) {
      addFinding('firewall-sensitive-port', { anchor: anchorOf(res), scope: `${res.path}:${port}`, state: v.state === 'known' ? 'active' : 'conditional', uncertain: !v.definite, evidence: [evidenceOf(res)], extra: { port, portService: SENSITIVE_PORTS.get(port), exposure: { enabled: 'unknown', listening: 'unknown', ingress: fwOff === 'yes' ? 'firewall-disabled' : 'open-in-firewall', reachable: 'unknown' } } });
    }
  }
  // Port ranges opened on every interface.
  for (const [res, rg, proto] of [[tcpRangesRes, tcpRanges, 'tcp'], [udpRangesRes, udpRanges, 'udp']]) {
    if (!res) continue;
    if (rg.state !== 'known') {
      if (res.status === 'set' || res.status === 'conditional') gaps.push({ kind: 'firewall-port-ranges-unevaluated', option: res.path, purpose: 'firewall', reason: `the ${proto} port ranges could not be evaluated to {from, to} integers, so no conclusion about them is drawn (this is not a clean result)` });
      continue;
    }
    for (const r of rg.ranges) {
      const span = r.to - r.from + 1;
      const full = r.from <= 1 && r.to >= 65535;
      if (full || span >= 10000) {
        addFinding('firewall-wide-port-range', { severity: full ? 'high' : 'medium', anchor: anchorOf(res), scope: `${res.path}:${r.from}-${r.to}`, state: 'active', uncertain: !rg.definite, evidence: [evidenceOf(res)], extra: { portRange: { from: r.from, to: r.to, span, protocol: proto, everyPort: full }, exposure: { enabled: 'unknown', listening: 'unknown', ingress: fwOff === 'yes' ? 'firewall-disabled' : 'open-in-firewall', reachable: 'unknown' } } });
      } else if (proto === 'tcp') {
        for (const [port, svc] of SENSITIVE_PORTS) if (port >= r.from && port <= r.to) addFinding('firewall-sensitive-port', { anchor: anchorOf(res), scope: `${res.path}:${port}`, state: 'active', uncertain: !rg.definite, evidence: [evidenceOf(res)], extra: { port, portService: svc, viaRange: { from: r.from, to: r.to }, exposure: { enabled: 'unknown', listening: 'unknown', ingress: fwOff === 'yes' ? 'firewall-disabled' : 'open-in-firewall', reachable: 'unknown' } } });
      }
    }
  }
  for (const o of interfaceScoped) {
    const iface = o.path.split('.')[3];
    controls.push({ control: 'interface-scoped-ingress', option: o.path, interface: iface, ports: asList(view(o).value), applies: true });
  }

  // ── systemd services ──
  const services = new Map();
  for (const o of cfg.options) {
    if (o.namespace !== 'nixos' || !o.path.startsWith('systemd.services.')) continue;
    const m = /^systemd\.services\.([^.]+)\.(.+)$/.exec(o.path);
    if (!m) { gaps.push({ kind: 'unparsed-service-path', option: o.path, reason: 'service name is not a plain identifier' }); continue; }
    if (!services.has(m[1])) services.set(m[1], new Map());
    services.get(m[1]).set(m[2], o);
  }
  for (const [name, opts2] of [...services].sort((a, b) => a[0].localeCompare(b[0]))) {
    const get = (k) => opts2.get(k);
    const enRes = get('enable');
    const enJ = enRes ? judge(enRes, (x) => x === true) : 'yes';
    if (enJ === 'no') { inventory.push({ kind: 'systemd-service', name, state: 'inactive', evidence: [evidenceOf(enRes)] }); continue; }
    const anyCertain = [...opts2.values()].some((o) => o.sources.some((s) => s.role === 'winner'));
    const sstate = enJ === 'conditional' || enJ === 'unknown' ? 'conditional' : anyCertain ? 'active' : 'conditional';
    const sc = (k) => get(`serviceConfig.${k}`);

    // identity
    const userRes = sc('User');
    const dynRes = sc('DynamicUser');
    const userV = view(userRes);
    const dynJ = dynRes ? judge(dynRes, (x) => x === true) : 'no';
    let identity;
    if (dynJ === 'yes') identity = { state: 'dynamic-user', user: null, evidence: evidenceOf(dynRes) };
    else if (userRes && userV.state === 'known') identity = typeof userV.value === 'string' && userV.value !== 'root' && userV.value !== '0' ? { state: 'non-root', user: userV.value, evidence: evidenceOf(userRes) } : { state: 'root-explicit', user: userV.value, evidence: evidenceOf(userRes) };
    else if (userRes || dynJ === 'conditional' || dynJ === 'unknown') identity = { state: 'conditional', user: null, evidence: userRes ? evidenceOf(userRes) : evidenceOf(dynRes) };
    else identity = { state: 'root-default', user: 'root', evidence: null };

    // ExecStart / script identity
    const execRes = sc('ExecStart');
    const scriptRes = get('script');
    const execV = execRes ? view(execRes) : { state: 'unknown' };
    let exec = { kind: 'none', command: null, elevated: false };
    if (execV.state === 'known' && typeof execV.value === 'string') {
      const m = /^([-@:+!]*)\s*(\S*)/.exec(execV.value.trim());
      exec = { kind: 'exec-start', prefix: m[1], command: m[2] || null, elevated: /[+!]/.test(m[1]) };
    } else if (execRes) exec = { kind: 'exec-start', command: null, dynamic: true, elevated: false };
    else if (scriptRes) exec = { kind: 'generated-script', command: null, elevated: false };

    // hardening controls recorded when they apply
    const have = {};
    const ctl = (k, pred) => { const r = sc(k); return r && judge(r, pred) === 'yes' ? r : null; };
    have.noNewPrivs = ctl('NoNewPrivileges', (x) => x === true);
    have.protectSystem = ctl('ProtectSystem', (x) => x === true || x === 'strict' || x === 'full');
    have.privateTmp = ctl('PrivateTmp', (x) => x === true);
    have.privateDevices = ctl('PrivateDevices', (x) => x === true);
    have.capsRestricted = (() => { const r = sc('CapabilityBoundingSet'); const v = r && view(r); return v && v.state === 'known' && asList(v.value).every((c) => typeof c === 'string' && !DANGEROUS_CAPS.has(c.replace(/^~/, '')) || String(c).startsWith('~')) ? r : null; })();
    const applied = Object.entries(have).filter(([, r]) => r).map(([k, r]) => ({ control: k, option: r.path, applies: sstate !== 'inactive' }));
    for (const c of applied) controls.push({ ...c, service: name });
    if (identity.state === 'non-root' || identity.state === 'dynamic-user') controls.push({ control: 'non-root-identity', service: name, user: identity.user, option: (userRes || dynRes).path, applies: true });

    inventory.push({ kind: 'systemd-service', name, state: sstate, identity: { state: identity.state, user: identity.user }, exec, hardeningControls: applied.map((c) => c.control), evidence: [identity.evidence, ...[enRes].filter(Boolean).map(evidenceOf)].filter(Boolean) });

    const st = sstate === 'conditional' ? 'conditional' : 'active';
    const runnable = exec.kind !== 'none';

    // root identity
    if (runnable && (identity.state === 'root-explicit' || identity.state === 'root-default')) {
      const strong = applied.length >= 3;
      const anchor = identity.evidence && userRes ? anchorOf(userRes) : anchorOf(execRes || scriptRes || [...opts2.values()][0]);
      addFinding('service-runs-as-root', { severity: strong ? 'low' : identity.state === 'root-default' ? 'low' : 'medium', anchor, scope: `systemd.services.${name}`, state: st, uncertain: identity.state === 'root-explicit' && !view(userRes).definite, evidence: [identity.evidence, ...(execRes ? [evidenceOf(execRes)] : [])].filter(Boolean), extra: { identitySource: identity.state === 'root-default' ? 'systemd-default' : 'explicit', hardeningControls: applied.map((c) => c.control) }, mitigations: strong ? [{ kind: 'hardening-controls', controls: applied.map((c) => c.control) }] : [] });
      entryPoints.push({ id: `root-service:${name}`, kind: 'root-service', state: st, privilege: 'root', exec, evidence: [identity.evidence].filter(Boolean) });
    }
    if (exec.elevated) {
      addFinding('service-exec-elevated', { anchor: anchorOf(execRes), scope: `systemd.services.${name}`, state: st, uncertain: !execV.definite, evidence: [evidenceOf(execRes)], extra: { execPrefix: exec.prefix } });
      entryPoints.push({ id: `elevated-exec:${name}`, kind: 'elevated-exec', state: st, privilege: 'root', exec, evidence: [evidenceOf(execRes)] });
    }

    // capabilities / devices / filesystem
    for (const key of ['AmbientCapabilities', 'CapabilityBoundingSet']) {
      const r = sc(key);
      if (!r) continue;
      const v = view(r);
      const items = v.state === 'known' ? asList(v.value) : v.state === 'conditional' ? asList(v.definiteItems) : [];
      const bad = items.filter((c) => typeof c === 'string' && !c.startsWith('~') && DANGEROUS_CAPS.has(c));
      // a bounding set only limits; an ambient set grants, so only Ambient is a hard finding for non-root-looking services
      if (bad.length && (key === 'AmbientCapabilities' || identity.state !== 'root-default')) {
        addFinding('systemd-dangerous-capability', { severity: key === 'AmbientCapabilities' ? 'high' : 'medium', anchor: anchorOf(r), scope: `systemd.services.${name}.${key}`, state: st === 'conditional' || v.state === 'conditional' ? 'conditional' : 'active', uncertain: !v.definite, evidence: [evidenceOf(r)], extra: { capabilities: bad } });
      }
    }
    const dev = sc('DeviceAllow');
    if (dev) {
      const v = view(dev);
      const items = v.state === 'known' ? (Array.isArray(v.value) ? v.value : [v.value]) : [];
      const bad = items.filter((d) => typeof d === 'string' && /^(\/dev\/(k?mem|port)\b|char-\*|block-\*)(\s+\S*w\S*)?/.test(d.trim()) && /\bw/.test(d.split(/\s+/)[1] || 'rw'));
      if (bad.length) addFinding('systemd-device-access', { anchor: anchorOf(dev), scope: `systemd.services.${name}.DeviceAllow`, state: st, uncertain: !v.definite, evidence: [evidenceOf(dev)], extra: { devices: bad } });
    }
    const relaxed = [];
    const psR = sc('ProtectSystem'); if (psR && judge(psR, (x) => x === false) === 'yes') relaxed.push(psR);
    const ptR = sc('PrivateTmp'); if (ptR && judge(ptR, (x) => x === false) === 'yes') relaxed.push(ptR);
    const rwR = sc('ReadWritePaths'); if (rwR && judge(rwR, (x) => (Array.isArray(x) ? x : [x]).some((p) => p === '/' || p === '/etc' || p === '/usr')) === 'yes') relaxed.push(rwR);
    if (relaxed.length) addFinding('systemd-filesystem-relaxed', { anchor: anchorOf(relaxed[0]), scope: `systemd.services.${name}`, state: st, uncertain: relaxed.some((r) => !view(r).definite), evidence: relaxed.map(evidenceOf) });
    const nnp = sc('NoNewPrivileges');
    if (nnp && judge(nnp, (x) => x === false) === 'yes') addFinding('systemd-no-new-privileges-off', { anchor: anchorOf(nnp), scope: `systemd.services.${name}`, state: st, uncertain: !view(nnp).definite, evidence: [evidenceOf(nnp)] });

    // TLS verification
    for (const [envName, pred] of TLS_OFF) {
      const r = get(`environment.${envName}`);
      if (r && judge(r, (x) => typeof x === 'string' && pred(x)) === 'yes') addFinding('tls-verification-disabled', { anchor: anchorOf(r), scope: `systemd.services.${name}.environment.${envName}`, state: st, uncertain: !view(r).definite, evidence: [evidenceOf(r)], extra: { appFlowProven: false } });
    }
  }

  // ── OCI containers and NixOS containers (declarations only) ──
  const oci = new Map();
  for (const o of cfg.options) {
    const m = o.namespace === 'nixos' ? /^virtualisation\.oci-containers\.containers\.([^.]+)\.(.+)$/.exec(o.path) : null;
    if (!m) continue;
    if (!oci.has(m[1])) oci.set(m[1], new Map());
    oci.get(m[1]).set(m[2], o);
  }
  for (const [name, opts2] of [...oci].sort((a, b) => a[0].localeCompare(b[0]))) {
    const strs = (k) => {
      const r = opts2.get(k);
      const v = r && view(r);
      if (!v) return [];
      if (v.state === 'known') return asList(v.value).filter((x) => typeof x === 'string');
      if (v.state === 'conditional') return v.possible.flatMap((p) => asList(p)).concat(asList(v.possibleItems)).filter((x) => typeof x === 'string');
      return [];
    };
    const condOpt = ['extraOptions', 'volumes'].some((k) => opts2.get(k) && view(opts2.get(k)).state === 'conditional');
    const extraOpts = strs('extraOptions');
    const vols = strs('volumes');
    const ports = strs('ports');
    const imageRes = opts2.get('image');
    const st = !condOpt && [...opts2.values()].some((o) => o.sources.some((s) => s.role === 'winner')) ? 'active' : 'conditional';
    inventory.push({ kind: 'oci-container', name, state: st, image: imageRes && view(imageRes).state === 'known' ? view(imageRes).value : null, publishedPorts: ports, imageLayerScan: 'not-performed', evidence: [...opts2.values()].map(evidenceOf) });
    const risky = [];
    if (extraOpts.some((o) => /^--privileged(=true)?$/.test(o))) risky.push('--privileged');
    for (const o of extraOpts) { const m = /^--cap-add[= ](.+)$/.exec(o); if (m && (m[1] === 'ALL' || m[1] === 'SYS_ADMIN' || m[1] === 'CAP_SYS_ADMIN')) risky.push(`--cap-add=${m[1]}`); }
    if (vols.some((v) => /^\/(var\/)?run\/(docker|podman)\.sock(:|$)|^\/var\/run\/docker\.sock(:|$)/.test(v))) risky.push('container runtime socket mount');
    const anyRes = opts2.get('extraOptions') || opts2.get('volumes');
    if (risky.length) {
      addFinding('container-privileged', { anchor: anchorOf(anyRes), scope: `virtualisation.oci-containers.containers.${name}`, state: st, uncertain: !view(anyRes).definite, evidence: [...opts2.values()].filter((o) => ['extraOptions', 'volumes'].includes(o.path.split('.').slice(4).join('.'))).map(evidenceOf), extra: { indicators: risky, imageLayerScan: 'not-performed' } });
      entryPoints.push({ id: `privileged-container:${name}`, kind: 'privileged-container', state: st, privilege: 'host', evidence: [evidenceOf(anyRes)] });
    }
    if (extraOpts.some((o) => /^--(net|network)[= ]host$/.test(o))) addFinding('container-host-network', { anchor: anchorOf(opts2.get('extraOptions')), scope: `virtualisation.oci-containers.containers.${name}`, state: st, uncertain: !view(opts2.get('extraOptions')).definite, evidence: [evidenceOf(opts2.get('extraOptions'))], extra: { imageLayerScan: 'not-performed' } });
  }
  const ncont = new Set();
  for (const o of cfg.options) {
    const m = o.namespace === 'nixos' ? /^containers\.([^.]+)\.(.+)$/.exec(o.path) : null;
    if (m) ncont.add(m[1]);
  }
  for (const name of [...ncont].sort()) {
    const pn = cfg.options.find((o) => o.path === `containers.${name}.privateNetwork`);
    inventory.push({ kind: 'nixos-container', name, state: 'declared', privateNetwork: pn && view(pn).state === 'known' ? view(pn).value : 'unknown', imageLayerScan: 'not-applicable', evidence: pn ? [evidenceOf(pn)] : [] });
  }

  // ── coverage gaps and reconciliation ──
  for (const u of cfg.unknownOptions) gaps.push({ kind: 'unknown-option', option: u.path, reason: 'not a known option in a cataloged namespace; it may be a misspelling or removed option and may not have taken effect' });
  for (const g of cfg.unresolved) if (!['home-manager-function-module'].includes(g.kind)) gaps.push({ kind: g.kind, detail: g.detail, file: g.file });
  for (const t of cfg.truncated) gaps.push({ kind: 'truncated', budget: t.budget });
  const count = (list, s) => list.filter((i) => i.state === s).length;
  const svc = inventory.filter((i) => i.kind === 'declared-service' || i.kind === 'systemd-service');
  const reconciliation = {
    services: { total: svc.length, active: count(svc, 'active'), conditional: count(svc, 'conditional'), inactive: count(svc, 'inactive'), unknown: count(svc, 'unknown') },
    entryPoints: { total: entryPoints.length, active: count(entryPoints, 'active'), conditional: count(entryPoints, 'conditional') },
    unanalyzed: gaps,
    completeness: cfg.completeness === 'complete' && !gaps.length ? 'complete' : 'partial',
    findingsByEntryPoint: Object.fromEntries(entryPoints.map((e) => {
      const rules = ENTRY_RULES[e.kind] || [];
      const name = e.id.includes(':') ? e.id.slice(e.id.indexOf(':') + 1) : null;
      return [e.id, findings.filter((f) => rules.includes(f.rule) && (!name || f.subject.includes(name))).map((f) => f.id)];
    })),
  };
  reconciliation.consistent = reconciliation.services.total === reconciliation.services.active + reconciliation.services.conditional + reconciliation.services.inactive + reconciliation.services.unknown
    && reconciliation.entryPoints.total === reconciliation.entryPoints.active + reconciliation.entryPoints.conditional;

  findings.sort((a, b) => a.id.localeCompare(b.id));
  return {
    kind: 'nixos-hardening-report', version: 1, rulesetVersion: HARDENING_RULESET_VERSION,
    target: cfg.target, catalog: cfg.catalog, release: cfg.target.release && normalizeRelease(cfg.target.release),
    findings, controls, inventory, privilegedEntryPoints: entryPoints, authzEvidence: authz, attackPaths, reconciliation,
    scope: { imageLayerScan: 'not-performed', internetReachability: 'unknown', note: 'host firewall is modelled; external network topology is not' },
  };
}
