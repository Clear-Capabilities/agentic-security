export const id = 4171;
export const ids = [4171];
export const modules = {

/***/ 94171:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  analyzeLanguageFindings: () => (/* binding */ analyzeLanguageFindings),
  analyzeLanguageSupplyChain: () => (/* binding */ analyzeLanguageSupplyChain)
});

// UNUSED EXPORTS: nixosEntries

// EXTERNAL MODULE: ./src/language/resolved-pass.js + 3 modules
var resolved_pass = __webpack_require__(38551);
// EXTERNAL MODULE: ./src/language/nix-build-trust.js
var nix_build_trust = __webpack_require__(36668);
// EXTERNAL MODULE: ./src/language/discovery.js
var discovery = __webpack_require__(30951);
// EXTERNAL MODULE: ./src/language/haskell-supply.js + 1 modules
var haskell_supply = __webpack_require__(43436);
// EXTERNAL MODULE: ./src/language/nix-script-taint.js
var nix_script_taint = __webpack_require__(11793);
// EXTERNAL MODULE: ./src/language/nix-secrets.js
var nix_secrets = __webpack_require__(69466);
// EXTERNAL MODULE: ./src/language/nix-parser.js
var nix_parser = __webpack_require__(54352);
// EXTERNAL MODULE: ./src/language/secrets.js
var secrets = __webpack_require__(95108);
// EXTERNAL MODULE: ./src/language/haskell-manifests.js
var haskell_manifests = __webpack_require__(16522);
;// CONCATENATED MODULE: ./src/language/nix-agents.js
// Nix-launched agent and MCP service configuration (X-003).
//
// What this reads is DECLARATION: a systemd service or container whose command line starts an MCP server or
// an agent CLI, with the filesystem roots, flags, bind address, user and environment the configuration gives
// it. Every finding here is configuration evidence of a CAPABILITY, never proof that an agent exercised it
// (`declaredCapability: true`, `exercised: 'not-established'`). Bridges to the application that reads the
// configuration (an environment variable the Nix service sets and the Haskell program reads) carry explicit
// provenance on both sides, and only become `executable-linked` when the service launches an executable the
// project's own manifest builds; a matching variable name alone is a `candidate`.
//
// Static only: nothing is evaluated or launched.





const NIX_AGENTS_VERSION = 'nix-agents/1';
const PH = '￼';

const MCP_RE = /(?:@modelcontextprotocol\/|\bmcp[-_]server|\bserver[-_]mcp|\bmcp[-_]proxy|fastmcp|\buvx\s+mcp|\bnpx\b[^\n]*\bmcp\b|\s--mcp\b)/i;
const SHELL_MCP_RE = /(?:mcp[-_]server[-_](?:shell|commands|exec)|server-shell|shell-server|mcp-shell|mcp[-_]commands)/i;
const AGENT_RE = /(?:^|[/\s])(?:claude|aider|goose|codex|gemini|gemini-cli|opencode|crush|openhands|open-interpreter|interpreter|autogpt|cline)(?:\s|$|--)/i;
const AUTO_APPROVE_RE = /(?:--dangerously-skip-permissions|--dangerously-bypass[\w-]*|--yolo\b|--auto-?approve\b|--approval-mode[= ]yolo|--no-confirm\b|--yes-always\b|--permission-mode[= ]bypass\w*|-y\s+--(?:auto|run))/i;
const BIND_ALL_RE = /(?:--(?:host|listen|address|bind)[= ]\s*(?:0\.0\.0\.0|::|\[::\]|\*)|-H\s+0\.0\.0\.0|\b(?:HOST|LISTEN_ADDR|BIND(?:_ADDRESS)?)=0\.0\.0\.0)/i;
const BROAD_ROOTS = [[/(?:^|\s)\/(?:\s|$)/, '/', 'high'], [/(?:^|\s)\/(?:etc|root|nix|boot|proc|sys|usr)(?:\/\S*)?(?:\s|$)/, '/etc, /root, /nix or another system tree', 'high'], [/(?:^|\s)(?:\/home|\/var|\/mnt|\/srv\/?)(?:\s|$)/, '/home, /var or /mnt', 'medium'], [/(?:^|\s)(?:~\/?|\$HOME\/?|%h\/?)(?:\s|$)/, 'the user home directory', 'medium']];

const segName = (s) => (s && s.kind === 'static' ? s.name : null);
const unparen = (n) => { let x = n; while (x && x.type === 'paren') x = x.expr; return x; };

/** A string's text with every interpolation replaced by a placeholder (never evaluated). */
function textOf(n) {
  n = unparen(n);
  if (!n) return null;
  if (n.type === 'string') return n.parts.map((p) => (p.kind === 'text' ? p.value : PH)).join('');
  if (n.type === 'list') return n.items.map((i) => textOf(i)).filter((x) => x !== null).join(' ');
  if (n.type === 'path') return n.literal || null;
  if (n.type === 'binop' && n.op === '+') { const a = textOf(n.left); const b = textOf(n.right); return a !== null && b !== null ? a + b : null; }
  return null;
}

function collectServices(files) {
  const services = new Map();
  const get = (file, name, kind, line) => { const k = `${kind}:${name}`; if (!services.has(k)) services.set(k, { file, name, kind, line, commands: [], env: {}, user: null, dynamicUser: null, openFirewall: null, extra: {} }); return services.get(k); };
  for (const [file, text] of Object.entries(files)) {
    const parse = (0,nix_parser/* parseNix */.Z$)(text, { file });
    if (!parse.ast) continue;
    const stack = [{ n: parse.ast, path: [] }];
    while (stack.length) {
      const { n, path } = stack.pop();
      if (!n || typeof n !== 'object') continue;
      if (n.type === 'attrset') {
        for (const b of n.bindings || []) {
          if (b.kind !== 'attr' || !b.value) continue;
          const key = (b.path || []).map(segName);
          if (key.some((x) => x === null)) { stack.push({ n: b.value, path: [...path, ...key.filter(Boolean)] }); continue; }
          const full = [...path, ...key];
          const line = b.span ? b.span.startLine : null;
          let m = /^systemd\.(?:user\.)?services\.([^.]+)\.(.+)$/.exec(full.join('.'));
          let kind = 'systemd';
          const oci = /^virtualisation\.oci-containers\.containers\.([^.]+)\.(.+)$/.exec(full.join('.'));
          if (oci) { m = oci; kind = 'oci'; }
          if (m) {
            const svc = get(file, m[1], kind, line); const rest = m[2];
            const v = unparen(b.value); const t = textOf(v);
            if (kind === 'systemd') {
              if ((/^(?:script|preStart|postStart)$/.test(rest) || /^serviceConfig\.ExecStart(?:Pre)?$/.test(rest)) && t !== null) svc.commands.push({ text: t, line, file, option: rest });
              if (rest === 'serviceConfig.User' && t !== null) svc.user = { value: t, line };
              if (rest === 'serviceConfig.DynamicUser' && v && v.type === 'ident') svc.dynamicUser = { value: v.name === 'true', line };
              const env = /^environment\.(.+)$/.exec(rest);
              if (env && t !== null) svc.env[env[1]] = { text: t, line, file };
              if (rest === 'environment' && v && v.type === 'attrset') for (const eb of v.bindings) { if (eb.kind !== 'attr') continue; const ek = (eb.path || []).map(segName).filter(Boolean).join('.'); const et = textOf(eb.value); if (et !== null) svc.env[ek] = { text: et, line: eb.span ? eb.span.startLine : line, file }; }
            } else {
              if (/^(?:cmd|entrypoint)$/.test(rest) && t !== null) svc.commands.push({ text: t, line, file, option: rest });
              if (rest === 'image' && t !== null) svc.extra.image = t;
              if (rest === 'user' && t !== null) svc.user = { value: t, line };
              if (rest === 'ports' && t !== null) svc.extra.ports = t;
              if (rest === 'volumes' && t !== null) svc.extra.volumes = t;
              const env = /^environment\.(.+)$/.exec(rest);
              if (env && t !== null) svc.env[env[1]] = { text: t, line, file };
            }
          }
          stack.push({ n: b.value, path: full });
        }
      }
      for (const k of Object.keys(n)) { if (k === 'span') continue; const c = n[k]; if (c && typeof c === 'object' && !(n.type === 'attrset' && k === 'bindings')) { if (Array.isArray(c)) for (const x of c) stack.push({ n: x, path }); else stack.push({ n: c, path }); } }
    }
  }
  return [...services.values()];
}

const finding = (rule, svc, cmd, o) => ({
  id: `${rule}:${svc.file}:${o.line || svc.line}`, file: svc.file, line: o.line || svc.line, parser: 'NIX-AGENT', family: 'agent-config', rule,
  severity: o.severity, cwe: o.cwe, vuln: o.vuln, owaspLlm: 'LLM06',
  description: `${o.desc} This is configuration evidence of a declared capability; nothing shows an agent has exercised it.`,
  remediation: o.fix, language: 'nix', capability: 'iac', analysisKind: 'configuration', evidenceKind: 'config', scope: 'system', confidence: o.confidence ?? 0.7,
  declaredCapability: true, exercised: 'not-established', service: { name: svc.name, kind: svc.kind }, subject: `${svc.kind}:${svc.name}`,
  attrPath: `${svc.kind === 'oci' ? 'virtualisation.oci-containers.containers' : 'systemd.services'}.${svc.name}`,
  chain: [{ file: svc.file, line: o.line || svc.line, label: o.label || o.vuln, kind: 'config' }],
});

/**
 * @param {Record<string,string>} files  Nix sources (and, for bridges, Haskell sources and .cabal manifests)
 */
function analyzeNixAgents(files) {
  const nix = Object.fromEntries(Object.entries(files).filter(([p, t]) => /\.nix$/i.test(p) && typeof t === 'string'));
  const findings = []; const agents = []; const bridges = [];
  const services = collectServices(nix);
  for (const svc of services) {
    const all = svc.commands.map((c) => c.text).join('\n');
    const isMcp = MCP_RE.test(all) || MCP_RE.test(svc.name) || (svc.extra.image && MCP_RE.test(svc.extra.image));
    const isAgent = AGENT_RE.test(all);
    if (!isMcp && !isAgent) continue;
    const cmd = svc.commands.find((c) => MCP_RE.test(c.text) || AGENT_RE.test(c.text)) || svc.commands[0] || { text: '', line: svc.line };
    const entry = { name: svc.name, kind: isMcp ? 'mcp-server' : 'agent', launcher: svc.kind, file: svc.file, line: cmd.line || svc.line, user: svc.user ? svc.user.value : null, dynamicUser: svc.dynamicUser ? svc.dynamicUser.value : null, env: Object.keys(svc.env), declaredCapability: true, exercised: 'not-established' };
    agents.push(entry);
    const text = ` ${all.replace(new RegExp(PH, 'g'), ' ')} `;
    if (SHELL_MCP_RE.test(all)) findings.push(finding('nix-mcp-shell-server', svc, cmd, { severity: 'high', cwe: 'CWE-250', vuln: 'An MCP server that executes shell commands is launched as a service', desc: `${svc.name} starts an MCP server whose purpose is to run commands.`, fix: 'Do not expose a general shell to a model. Offer narrow tools, or run it in a sandbox with no network and a read-only root.', line: cmd.line }));
    if (isMcp) for (const [re, what, sev] of BROAD_ROOTS) if (re.test(text)) { findings.push(finding('nix-mcp-broad-filesystem', svc, cmd, { severity: sev, cwe: 'CWE-732', vuln: 'An MCP/agent service is given a broad filesystem root', desc: `${svc.name} is started with ${what} as a root the server may read or write.`, fix: 'Point the server at the one project directory it needs, and add systemd ReadWritePaths/ProtectSystem so the unit cannot reach more.', line: cmd.line })); break; }
    if (AUTO_APPROVE_RE.test(text)) findings.push(finding('nix-agent-auto-approve', svc, cmd, { severity: 'high', cwe: 'CWE-862', vuln: 'An agent is launched with permission prompts disabled', desc: `${svc.name} starts an agent with an auto-approve / skip-permissions flag, so tool use needs no confirmation.`, fix: 'Remove the flag, or run the agent in an isolated unit with a minimal allow-list.', line: cmd.line }));
    const bindAll = BIND_ALL_RE.test(text) || Object.values(svc.env).some((e) => BIND_ALL_RE.test(` ${e.text} `) || /^0\.0\.0\.0$/.test(String(e.text).trim()) && false);
    const envBind = Object.entries(svc.env).find(([k, e]) => /^(?:HOST|LISTEN_ADDR|BIND|BIND_ADDRESS|MCP_HOST)$/i.test(k) && String(e.text).trim() === '0.0.0.0');
    if (bindAll || envBind) findings.push(finding('nix-agent-network-exposed', svc, cmd, { severity: 'medium', cwe: 'CWE-668', vuln: 'An agent/MCP service listens on every interface', desc: `${svc.name} binds 0.0.0.0, so anything that can reach the host can reach the tool surface.`, fix: 'Bind 127.0.0.1 (or a unix socket) and put authentication in front of anything that must be remote.', line: envBind ? envBind[1].line : cmd.line }));
    const root = svc.kind === 'systemd' && (!svc.user || svc.user.value === 'root') && !(svc.dynamicUser && svc.dynamicUser.value);
    if (root) findings.push(finding('nix-agent-runs-as-root', svc, cmd, { severity: 'medium', cwe: 'CWE-250', vuln: 'An agent/MCP service runs as root', desc: `${svc.name} has no User or DynamicUser, so systemd runs it as root.`, fix: 'Set serviceConfig.DynamicUser = true (or a dedicated User) and grant only the paths it needs.', line: svc.line }));
    entry.environment = Object.entries(svc.env).map(([k, e]) => ({ name: k, line: e.line, valueRecorded: false }));
  }
  // bridges: a Nix service environment variable and the Haskell program that reads it
  const hsFiles = Object.entries(files).filter(([p, t]) => /\.l?hs$/i.test(p) && typeof t === 'string');
  const manifests = Object.entries(files).filter(([p, t]) => /\.cabal$/i.test(p) && typeof t === 'string').map(([path, text]) => ({ path, text }));
  const executables = new Set();
  if (manifests.length) { try { for (const pkg of (0,haskell_manifests/* analyzeHaskellManifests */.JS)(manifests).packages) for (const c of pkg.components || []) if (c.kind === 'executable') executables.add(c.name); } catch { /* no manifest evidence */ } }
  const reads = [];
  for (const [file, text] of hsFiles) {
    const toks = (0,secrets/* tokenizeHaskell */.cH)(text);
    for (let i = 0; i < toks.length; i++) {
      const t = toks[i];
      if (t.k !== 'i' || !/^(?:getEnv|lookupEnv)$/.test(t.v.replace(/^.*\./, ''))) continue;
      let j = i + 1; while (toks[j] && toks[j].k === 'x' && toks[j].v === '(') j++;
      if (toks[j] && toks[j].k === 's') { let line = 1; for (let q = 0; q < t.start; q++) if (text.charCodeAt(q) === 10) line++; reads.push({ file, line, variable: toks[j].v }); }
    }
  }
  for (const svc of services) {
    const exec = svc.commands.map((c) => c.text).join(' ');
    const launched = [...executables].filter((e) => new RegExp(`(?:^|[/\\s])${e.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:\\s|$)`).test(exec.replace(new RegExp(PH, 'g'), ' ')));
    for (const [variable, e] of Object.entries(svc.env)) {
      for (const r of reads.filter((x) => x.variable === variable)) {
        bridges.push({ kind: 'env-read', variable, status: launched.length ? 'executable-linked' : 'candidate', executable: launched[0] || null,
          nix: { service: svc.name, file: e.file, line: e.line, role: 'declares-environment' }, haskell: { file: r.file, line: r.line, role: 'reads-environment' },
          provenance: { nix: 'systemd service environment (configuration)', haskell: 'getEnv/lookupEnv literal (source)', link: launched.length ? `the service launches ${launched[0]}, an executable built by the project's cabal file` : 'only the variable name matches: no evidence this service runs that program' },
          flow: 'a runtime configuration bridge, not a data-flow proof' });
      }
    }
  }
  return { version: NIX_AGENTS_VERSION, findings, agents, bridges };
}

// EXTERNAL MODULE: ./src/language/nixos-hardening.js
var nixos_hardening = __webpack_require__(37099);
;// CONCATENATED MODULE: ./src/language/engine-pass.js
// Language supply-chain pass for the scan engine. Nix fetch/build/cache trust findings are
// supply-chain entries, so they join the ordinary `supplyChain` bucket (and from there SCA
// policy, scan health and every report) instead of a side channel. Static only: nothing here
// evaluates Nix, fetches a URL or runs a builder.










const isNixSource = (p) => /\.nix$/i.test(p);
const isFlakeLock = (p) => /(^|\/)flake\.lock$/i.test(p);

/**
 * @param {Record<string,string>} files rel path -> content (sources and manifests as the engine read them)
 * @returns {{supplyChain: object[], gaps: object[], analyzed: number}}
 */
const NIXOS_OPTION = /(?:^|[\s;{])(?:services|networking|security|systemd|users|environment|programs|boot|virtualisation|nix)\.[A-Za-z_]|(?:^|[\s;{])(?:services|networking|security|systemd|users|environment|programs|boot|virtualisation)\s*=\s*\{/m;

/** NixOS entry points of a Nix file set: every configuration.nix, else every module nothing imports (capped). */
function nixosEntries(nix, { max = 15 } = {}) {
  const conf = Object.keys(nix).filter((p) => /(?:^|\/)configuration\.nix$/i.test(p)).sort().slice(0, 5);
  const imported = new Set();
  try { const { graph } = (0,discovery/* buildImportGraph */.oK)(nix); for (const deps of graph.values()) for (const d of deps) imported.add(d); } catch { /* no import graph */ }
  const standalone = Object.keys(nix).filter((p) => !conf.includes(p) && !imported.has(p) && !/(?:^|\/)flake\.nix$/i.test(p) && NIXOS_OPTION.test(nix[p])).sort().slice(0, max);
  return [...conf, ...standalone];
}

function _baseSupplyChain(files = {}, opts = {}) {
  const nix = {};
  for (const [p, text] of Object.entries(files)) {
    if (typeof text !== 'string') continue;
    if (!(isNixSource(p) || isFlakeLock(p))) continue;
    if ((0,discovery/* isLanguageExcludedPath */.EG)(p)) continue;
    nix[p] = text;
  }
  // Haskell: Hackage advisories and source/name policy (manifests, a freeze or a plan, and the .hs imports).
  const hs = (0,haskell_supply/* analyzeHaskellSupply */.i1)(files, { root: opts.scanRoot || null, resolved: opts.resolved || null });
  const sources = Object.keys(nix).filter(isNixSource);
  if (!sources.length) {
    if (!hs.components.length) return { supplyChain: [], gaps: [], analyzed: 0 };
    return { supplyChain: hs.supplyChain, gaps: hs.gaps, analyzed: hs.components.length, haskell: hs };
  }
  // The effective configuration is decided from an ENTRY: configuration.nix when there is one, otherwise each NixOS module that
  // nothing imports (a flake's host file under any name). With no entry at all only the file-local rules run.
  const entries = nixosEntries(nix);
  const reports = entries.length ? entries.map((entry) => (0,nix_build_trust/* analyzeNixBuildTrust */.OQ)({ files: nix, entry })) : [(0,nix_build_trust/* analyzeNixBuildTrust */.OQ)({ files: nix })];
  const seenIds = new Set(); const merged = []; const gaps = [];
  for (const r of reports) {
    for (const f of r.findings) { const k = f.id || `${f.rule}|${f.file}|${f.line}`; if (!seenIds.has(k)) { seenIds.add(k); merged.push(f); } }
    for (const g of r.gaps) gaps.push(g);
  }
  return { supplyChain: [...hs.supplyChain, ...merged], gaps: [...hs.gaps, ...gaps], analyzed: sources.length + hs.components.length, haskell: hs };
}

/**
 * Findings (not supply-chain entries) from Nix: embedded-shell taint (NIX-003). Returns the findings plus the
 * coverage gaps (unsupported shells, scripts built by expressions) so scan health can report them.
 */
function analyzeLanguageFindings(files = {}) {
  const nix = {};
  for (const [p, text] of Object.entries(files)) {
    if (typeof text !== 'string' || !isNixSource(p) || (0,discovery/* isLanguageExcludedPath */.EG)(p)) continue;
    nix[p] = text;
  }
  if (!Object.keys(nix).length) return { findings: [], gaps: [], analyzed: 0 };
  const r = (0,nix_script_taint/* analyzeNixScripts */.S3)({ files: nix });
  // secret placement sees referenced data files (sopsFile / agenix file) as well as the Nix sources
  const sec = (0,nix_secrets/* analyzeNixSecrets */.D0)({ files: { ...files, ...nix } });
  let agents = { findings: [] };
  try { agents = analyzeNixAgents(files); } catch { /* agent/MCP rules are best effort */ }
  // NIX-004: effective-configuration hardening, judged per NixOS entry point (configuration.nix). A finding with no
  // option source (a catalog default decided it) is anchored to the entry file at line 1 and says so, so it can be
  // reported, attributed and suppressed instead of being lineless. The files that decided the value travel with it.
  const hardening = [];
  const effective = [];
  // Entry points: every configuration.nix, plus NixOS modules NOTHING imports (a standalone module, a flake's host file under any
  // name): its options are the only place their values are decided, and a file name is not what makes a configuration real.
  const confEntries = Object.keys(nix).filter((p) => /(?:^|\/)configuration\.nix$/i.test(p)).sort().slice(0, 5);
  const entryList = nixosEntries(nix);
  for (const entry of entryList) {
    try {
      const h = (0,nixos_hardening/* analyzeNixosHardening */.QC)({ entry, files: nix });
      effective.push({ entry, completeness: h.reconciliation && h.reconciliation.completeness, unresolved: (h.reconciliation && h.reconciliation.unanalyzed) || [], truncated: [], target: h.target });
      for (const f of h.findings) {
        const ctl = [...new Set((f.evidence || []).flatMap((e) => (e.sources || []).map((x) => x.file)).filter(Boolean))];
        const anchored = Number.isInteger(f.line) && f.file;
        hardening.push({ ...f, file: anchored ? f.file : entry, line: anchored ? f.line : 1, locationKind: anchored ? 'option-source' : 'target-level', controlFiles: ctl, entry, entryKind: confEntries.includes(entry) ? 'configuration' : 'standalone-module', optionEvidence: f.evidence, option: f.evidence && f.evidence[0] ? f.evidence[0].option : null });
      }
    } catch (e) { r.gaps.push({ kind: 'hardening-failed', file: entry, reason: String((e && e.message) || e) }); }
  }
  // Two different rules of one family can land on the same line (a one-line configuration, or several defaults that
  // anchor at the entry). The engine's per-(file, line, family) de-duplication must not merge them into one finding, so
  // each carries a site key built from what makes it a different finding. The key also feeds the stable id.
  const keyed = (list, parts) => list.map((f) => (f && f.siteKey ? f : { ...f, siteKey: parts(f).filter((x) => x !== null && x !== undefined && x !== '').join('|') }));
  const out = [
    ...keyed(r.findings, (f) => [f.rule, f.attrPath, f.sink && f.sink.command, f.generatedLocation && `${f.generatedLocation.line}:${f.generatedLocation.startColumn}`]),
    ...keyed(sec.findings, (f) => [f.rule, f.source && f.source.detail, f.destination && f.destination.label]),
    ...agents.findings,
    ...keyed(hardening, (f) => [f.rule, f.subject]),
  ];
  return { findings: out, gaps: [...r.gaps, ...sec.gaps], analyzed: r.analyzed, effectiveConfigs: effective };
}

/**
 * The language supply chain: declared and resolved Hackage dependencies, Nix inputs and build trust, and (when the project exported
 * one) the Nix closure matched against an advisory snapshot. The resolved data comes from EXPLICIT export files only.
 */
function analyzeLanguageSupplyChain(files = {}, opts = {}) {
  let resolved = null; let closure = null;
  try { resolved = (0,resolved_pass.resolvedHackageComponents)(files); } catch { resolved = null; }
  try { closure = (0,resolved_pass.analyzeNixClosure)(files, { scanRoot: opts.scanRoot || null }); } catch (e) { closure = { findings: [], gaps: [{ kind: 'closure-analysis-failed', detail: String((e && e.message) || e).slice(0, 160) }], statuses: [], sources: [], status: 'failed' }; }
  const base = _baseSupplyChain(files, { ...opts, resolved });
  if (!closure) return resolved && resolved.summary ? { ...base, resolved: resolved.summary } : base;
  return { ...base, supplyChain: [...base.supplyChain, ...closure.findings], gaps: [...(base.gaps || []), ...closure.gaps], analyzed: (base.analyzed || 0) + closure.statuses.length, resolved: resolved && resolved.summary, nixClosure: closure };
}


/***/ })

};
