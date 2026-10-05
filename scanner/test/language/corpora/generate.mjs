// QA-001 corpus generator. Deterministic: same inputs, byte-identical output.
//
//   node test/language/corpora/generate.mjs          # (re)write data/
//
// The generator refuses to write a case whose label the independent reviewer
// (lib.mjs REVIEW_RULES, a separately written description of each family)
// does not reproduce, so a mislabel has to survive two descriptions.

import { HS_UNSEEN, NIX_UNSEEN, UNSEEN_VERSION, UNSEEN_HS_NOUNS, UNSEEN_NIX_NOUNS } from './templates-unseen.mjs';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  sha256, fingerprint, normalizeSource, reviewLabel, reviewPrivacy, renameLocals,
  addMisleadingComments, reflowWhitespace, scramblePath, evaluateFixProposal, assignSplits,
} from './lib.mjs';
import { HS, NIX, HS_NOUNS, NIX_NOUNS, HS_UNKNOWN, NIX_UNKNOWN, insertHs, insertNix } from './templates.mjs';

export const HERE = path.dirname(fileURLToPath(import.meta.url));
export const DATA = path.join(HERE, 'data');
export const VERSION = 'qa001-v2';

const ECOS = {
  haskell: { lang: 'haskell', prefix: 'hs', templates: HS, nouns: HS_NOUNS, unknown: HS_UNKNOWN, insert: insertHs, ext: 'hs', main: 'src/Svc.hs' },
  nix: { lang: 'nix', prefix: 'nx', templates: NIX, nouns: NIX_NOUNS, unknown: NIX_UNKNOWN, insert: insertNix, ext: 'nix', main: 'configuration.nix' },
};

const CWE = {
  'sql-injection': 'CWE-89', 'command-injection': 'CWE-78', 'path-traversal': 'CWE-22', ssrf: 'CWE-918',
  'html-injection': 'CWE-79', 'weak-password-hash': 'CWE-916', 'weak-randomness': 'CWE-338',
  'resource-limits': 'CWE-770', 'parser-safety': 'CWE-248', 'sensitive-logging': 'CWE-532',
  'route-authentication': 'CWE-306', 'object-authorization': 'CWE-639', 'session-cookie': 'CWE-1004',
  'script-interpolation': 'CWE-78', 'secret-in-store': 'CWE-312', 'unpinned-source': 'CWE-494',
  'binary-cache-trust': 'CWE-347', 'trusted-users': 'CWE-250', 'native-eval': 'CWE-829',
  'sandbox-trust': 'CWE-693', 'ssh-access': 'CWE-287', 'service-privilege': 'CWE-250',
  'firewall-exposure': 'CWE-284', 'privilege-escalation-policy': 'CWE-269', 'tls-secret-runtime': 'CWE-319',
};

const ORIGIN_NOUNS = 5; // noun index 5 is reserved for mutation pairs and never enters the corpus
const J_VALUES = [0, 1];

function stratifiedSplit(origins) {
  const sorted = [...origins].sort((a, b) => sha256(a).localeCompare(sha256(b)));
  const n = sorted.length;
  const nTrain = Math.ceil(n * 0.5);
  const nVal = Math.round(n * 0.2);
  return new Map(sorted.map((g, i) => [g, i < nTrain ? 'train' : i < nTrain + nVal ? 'validation' : 'holdout']));
}

function buildCases(eco) {
  const E = ECOS[eco];
  const families = Object.keys(E.templates);
  const cases = [];
  const splitOf = new Map();
  for (const family of families) {
    for (const label of ['vulnerable', 'safe']) {
      const shapes = label === 'vulnerable' ? E.templates[family].vuln.map((f) => [f, null]) : E.templates[family].safe;
      const origins = [];
      shapes.forEach(([, ], s) => { for (let k = 0; k < ORIGIN_NOUNS; k++) origins.push(`${eco}|${family}|${label}|s${s}|${E.nouns[k].tbl}`); });
      const sp = stratifiedSplit(origins);
      sp.forEach((v, g) => splitOf.set(g, v));
      shapes.forEach(([gen, near], s) => {
        for (let k = 0; k < ORIGIN_NOUNS; k++) {
          const group = `${eco}|${family}|${label}|s${s}|${E.nouns[k].tbl}`;
          for (const j of J_VALUES) {
            cases.push({ ecosystem: eco, family, label, group, split: sp.get(group), nearMiss: near, source: gen(E.nouns[k], j), j });
          }
        }
      });
    }
  }
  // unknown/unmodeled: realistic vulnerable shape plus a construct the model cannot resolve.
  // They inherit the split of the vulnerable origin they derive from (same-origin rule).
  const F = families.length;
  for (let i = 0; i < 52; i++) {
    const family = families[i % F];
    const k = Math.floor(i / F) % ORIGIN_NOUNS;
    const parent = `${eco}|${family}|vulnerable|s0|${E.nouns[k].tbl}`;
    const base = E.templates[family].vuln[0](E.nouns[k], 0);
    const source = E.insert(base, E.unknown[i % E.unknown.length](E.nouns[k]));
    cases.push({ ecosystem: eco, family, label: 'unknown', group: parent, split: splitOf.get(parent), nearMiss: i % 2 ? 'conditional' : 'unresolved-construct', source, j: 0, unknownKind: i % E.unknown.length });
  }
  const seen = new Set();
  for (const c of cases) {
    c.id = `${E.prefix}-${sha256(`${c.group}|${c.label}|${c.j}|${c.unknownKind ?? ''}`).slice(0, 10)}`;
    c.path = E.main;
    c.cwe = CWE[c.family];
    c.fingerprint = fingerprint(E.lang, c.source);
    c.normalized = normalizeSource(E.lang, c.source);
    if (seen.has(c.id)) throw new Error(`id collision ${c.id}`);
    seen.add(c.id);
    const r = reviewLabel(E.lang, c.family, c.source);
    if (r !== c.label) throw new Error(`reviewer disagrees on ${c.id} ${c.family}: generator=${c.label} reviewer=${r}\n${c.source}`);
  }
  return cases;
}

// ── privacy lineage ──────────────────────────────────────────────────────────
const FIELDS = ['email', 'phone', 'ssn', 'dob', 'address', 'ipAddress', 'cardNo', 'passport', 'salary', 'diagnosis'];
// Haskell sinks use real, imported APIs (v2: the v1 sinks named functions with no import and an invented `postJson`).
const HS_SINKS = [
  { imports: [], expr: (x) => `putStrLn (${x})` },
  { imports: ['import System.IO (hPutStrLn, stderr)'], expr: (x) => `hPutStrLn stderr (${x})` },
  { imports: [], expr: (x) => `appendFile "crm.log" (${x})` },
  { imports: [], expr: (x) => `print (${x})` },
  { imports: [], expr: (x) => `writeFile "out.txt" (${x})` },
  { imports: ['import qualified Data.Text as T', 'import qualified Data.Text.IO as TIO'], expr: (x) => `TIO.putStrLn (T.pack (${x}))` },
  { imports: ['import qualified Data.ByteString as BS', 'import qualified Data.ByteString.Char8 as BC'], expr: (x) => `BS.writeFile "out.bin" (BC.pack (${x}))` },
  { imports: ['import Control.Monad (void)', 'import Network.HTTP.Simple'], expr: (x) => `void (httpNoBody (setRequestBodyJSON (${x}) (parseRequest_ "POST https://t.example/ingest")))` },
  { imports: ['import Network.Mail.SMTP', 'import qualified Data.Text.Lazy as TL'], expr: (x) => `sendMail "smtp.example.org" (simpleMail (Address Nothing "a@example.org") [Address Nothing "ops@example.org"] [] [] "export" [plainTextPart (TL.pack (${x}))])` },
  { imports: ['import System.IO (hPutStr, stdout)'], expr: (x) => `hPutStr stdout (${x})` },
];
const HS_PROT = [
  { imports: ['import Crypto.Hash (hashWith, SHA256(..))', 'import qualified Data.ByteString.Char8 as BC'], expr: (x) => `show (hashWith SHA256 (BC.pack (${x})))` },
  { imports: [], expr: (x) => `show (length (${x}))` },
  { imports: [], expr: (x) => `show (null (${x}))` },
  { imports: [], defs: "maskTail :: String -> String\nmaskTail s = replicate (length s) '*'\n\n", expr: (x) => `maskTail (${x})` },
  { imports: [], expr: (x) => `show (null (${x}) || length (${x}) > 64)` },
];
const NIX_SINKS = [
  (x) => `environment.etc."crm.log".text = "export \${${x}}";`,
  (x) => `systemd.services.crm.environment.CRM_DATA = "\${${x}}";`,
  (x) => `services.syslog.extraConfig = "\${${x}}";`,
  (x) => `networking.extraHosts = "10.0.0.1 \${${x}}";`,
  (x) => `systemd.services.crm.script = "notify \${${x}}";`,
  (x) => `environment.variables.CRM = "\${${x}}";`,
  (x) => `services.nginx.appendHttpConfig = "add_header X-Crm \${${x}};";`,
  (x) => `services.journald.extraConfig = "Storage=\${${x}}";`,
  (x) => `programs.bash.shellInit = "echo \${${x}}";`,
  (x) => `systemd.services.crm.serviceConfig.ExecStart = "/bin/crm --id \${${x}}";`,
];
const NIX_PROT = [
  (x) => `builtins.hashString "sha256" ${x}`, (x) => `toString (builtins.stringLength ${x})`,
  (x) => `(if ${x} == "" then "none" else "set")`, (x) => `(if ${x} != "" then "set" else "none")`,
  (x) => `toString (builtins.stringLength ${x} + 0)`,
];

function buildPrivacy() {
  const out = [];
  const fieldSplit = stratifiedSplit(FIELDS);
  for (const eco of ['haskell', 'nix']) {
    const E = ECOS[eco];
    FIELDS.forEach((field, f) => {
      for (let k = 0; k < 10; k++) {
        const O = FIELDS[(f + 1 + (k % 9)) % FIELDS.length];
        const ref = (fl) => (eco === 'haskell' ? `${fl} acct` : `config.services.crm.${fl}`);
        const sink = eco === 'haskell' ? HS_SINKS[k] : NIX_SINKS[k];
        const prot = eco === 'haskell' ? HS_PROT[(f + k) % 5] : NIX_PROT[(f + k) % 5];
        const make = (line, extra = {}) => (eco === 'haskell'
          ? `module Privacy where\n\n${[...new Set([...(sink.imports || []), ...(extra.imports || [])])].join('\n')}${(sink.imports || []).length || (extra.imports || []).length ? '\n\n' : ''}data Account = Account { ${FIELDS.map((x) => `${x} :: String`).join(', ')} }\n\n${extra.defs || ''}handleExport :: Account -> IO ()\nhandleExport acct = ${line}\n`
          : `{ config, lib, pkgs, ... }:\n{\n  ${line}\n}\n`);
        const sinkLine = (x) => (eco === 'haskell' ? sink.expr(x) : sink(x));
        const protExpr = (x) => (eco === 'haskell' ? prot.expr(x) : prot(x));
        const pos = make(sinkLine(ref(field)));
        const neg1 = make(sinkLine(protExpr(ref(field))), eco === 'haskell' ? prot : {});
        const neg2 = make(sinkLine(eco === 'haskell' ? `${ref(O)} ++ "/${field}"` : `${ref(O)} + "/${field}"`));
        const group = `${eco}|privacy|${field}`;
        const split = fieldSplit.get(field);
        const add = (kind, expected, source) => {
          const id = `${E.prefix}p-${sha256(`${eco}|${field}|${k}|${kind}`).slice(0, 10)}`;
          const r = reviewPrivacy(E.lang, source, field);
          if (r !== expected) throw new Error(`privacy reviewer disagrees ${id} ${field} ${kind}: ${r}\n${source}`);
          out.push({ id, ecosystem: eco, field, sinkIndex: k, kind, expected, group, split, source, path: eco === 'haskell' ? 'src/Privacy.hs' : 'configuration.nix' });
        };
        add('direct', 'flow', pos);
        if (k % 2 === 0) add('protected', 'no-flow', neg1); else add('sibling-field', 'no-flow', neg2);
        // second negative per slot so negatives reach 100: the other kind for the same (field, sink)
        if (k % 2 === 0) add('sibling-field', 'no-flow', neg2); else add('protected', 'no-flow', neg1);
      }
    });
  }
  return out;
}

// ── supply chain manifests ───────────────────────────────────────────────────
const HS_PKGS = [['aeson', '2.1.2.1'], ['text', '2.0.2'], ['bytestring', '0.11.5.3'], ['containers', '0.6.7'], ['warp', '3.3.31'], ['servant', '0.20.1'], ['persistent', '2.14.6.0'], ['http-client', '0.7.14'], ['cryptonite', '0.30'], ['yesod-core', '1.6.25.1'], ['conduit', '1.3.5'], ['lens', '5.2.3']];
const HS_BOUNDS = [(v) => `>=${v}`, (v) => `^>=${v}`, (v) => `==${v}`, (v) => `>=${v} && <${v.split('.')[0]}.${Number(v.split('.')[1]) + 1}`];

function buildSupply() {
  const out = [];
  for (let i = 0; i < 24; i++) {
    const pick = [0, 1, 2].map((d) => HS_PKGS[(i * 2 + d * 3) % HS_PKGS.length]);
    const kind = ['cabal', 'freeze', 'stack'][i % 3];
    const pkgs = pick.map(([name, version], d) => ({ name, version, bound: HS_BOUNDS[(i + d) % 4](version) }));
    const files = {};
    let expected;
    if (kind === 'cabal') {
      const test = pkgs[2];
      files['app.cabal'] = `cabal-version: 3.0\nname: app${i}\nversion: 0.1.0.${i}\n\nlibrary\n  build-depends:\n    base >=4.14 && <5\n${pkgs.slice(0, 2).map((p) => `    , ${p.name} ${p.bound}`).join('\n')}\n\ntest-suite spec\n  type: exitcode-stdio-1.0\n  main-is: Spec.hs\n  build-depends:\n    base\n    , ${test.name} ${test.bound}\n`;
      expected = { resolution: 'declared-ranges', packages: [...pkgs.slice(0, 2).map((p) => ({ name: p.name, constraint: p.bound, scope: 'library' })), { name: test.name, constraint: test.bound, scope: 'test' }] };
    } else if (kind === 'freeze') {
      files['cabal.project.freeze'] = `active-repositories: hackage.haskell.org:merge\nconstraints: ${pkgs.map((p) => `any.${p.name} ==${p.version}`).join(',\n             ')}\n`;
      expected = { resolution: 'resolved-exact', packages: pkgs.map((p) => ({ name: p.name, version: p.version })) };
    } else {
      files['stack.yaml'] = `resolver: lts-22.${10 + i}\npackages:\n  - .\nextra-deps:\n${pkgs.map((p) => `  - ${p.name}-${p.version}`).join('\n')}\n`;
      expected = { resolution: 'resolved-exact', packages: pkgs.map((p) => ({ name: p.name, version: p.version })) };
    }
    out.push({ id: `hsx-${sha256(`hs-supply-${i}`).slice(0, 10)}`, ecosystem: 'haskell', kind, files, expected });
  }
  for (let i = 0; i < 24; i++) {
    const names = ['nixpkgs', 'home-manager', 'flake-utils', 'sops-nix', 'disko', 'impermanence'];
    const chosen = [0, 1, 2].map((d) => names[(i + d * 2) % names.length]);
    const kind = ['locked', 'unpinned', 'follows'][i % 3];
    const files = {};
    let expected;
    const revOf = (nm) => sha256(`${nm}-${i}`).slice(0, 40);
    if (kind === 'unpinned') {
      files['flake.nix'] = `{\n  inputs = {\n${chosen.map((nm) => `    ${nm}.url = "github:example/${nm}";`).join('\n')}\n  };\n  outputs = { self, ... }: { };\n}\n`;
      expected = { resolution: 'unresolved', inputs: chosen.map((nm) => ({ name: nm, pinned: false })) };
    } else {
      const nodes = { root: { inputs: Object.fromEntries(chosen.map((nm) => [nm, nm])) } };
      for (const nm of chosen) nodes[nm] = { locked: { type: 'github', owner: 'example', repo: nm, rev: revOf(nm), narHash: `sha256-${Buffer.from(sha256(nm + i), 'hex').toString('base64')}` }, original: { type: 'github', owner: 'example', repo: nm } };
      if (kind === 'follows') nodes[chosen[1]].inputs = { [chosen[0]]: [chosen[0]] };
      files['flake.lock'] = `${JSON.stringify({ nodes, root: 'root', version: 7 }, null, 2)}\n`;
      files['flake.nix'] = `{\n  inputs = {\n${chosen.map((nm, d) => `    ${nm}.url = "github:example/${nm}";${kind === 'follows' && d === 1 ? `\n    ${nm}.inputs.${chosen[0]}.follows = "${chosen[0]}";` : ''}`).join('\n')}\n  };\n  outputs = { self, ... }: { };\n}\n`;
      expected = { resolution: 'locked', inputs: chosen.map((nm) => ({ name: nm, rev: revOf(nm), pinned: true })), follows: kind === 'follows' ? [{ from: chosen[1], input: chosen[0], to: chosen[0] }] : [] };
    }
    out.push({ id: `nxx-${sha256(`nx-supply-${i}`).slice(0, 10)}`, ecosystem: 'nix', kind, files, expected });
  }
  return out;
}

// ── fix proposals ────────────────────────────────────────────────────────────
function buildFixes() {
  const out = [];
  for (const eco of ['haskell', 'nix']) {
    const E = ECOS[eco];
    const families = Object.keys(E.templates);
    const F = families.length;
    const add = (tag, family, before, after, targetPath, expected) => {
      const ev = evaluateFixProposal(E.lang, family, before, { after, targetPath });
      if (ev.accepted !== expected.accepted || ev.reason !== expected.reason) throw new Error(`fix evaluator disagrees ${eco} ${family} ${tag}: ${JSON.stringify(ev)}`);
      out.push({ id: `${E.prefix}f-${sha256(`${eco}|${tag}|${family}`).slice(0, 10)}`, ecosystem: eco, family, tag, targetPath, expected, before, after });
    };
    for (let i = 0; i < 20; i++) {
      const family = families[i % F];
      const n = E.nouns[Math.floor(i / F)];
      const T = E.templates[family];
      add(`ok${i}`, family, T.vuln[0](n, 7), T.safe[0][0](n, 7), E.main, { accepted: true, reason: 'verified-safe' });
    }
    for (let i = 0; i < 10; i++) {
      const family = families[(i * 2) % F];
      const n = E.nouns[i % 4];
      const T = E.templates[family];
      const before = T.vuln[0](n, 7);
      const kind = i % 5;
      if (kind === 0) add(`rej${i}`, family, before, T.safe[0][0](n, 7), '../../etc/passwd', { accepted: false, reason: 'path-escape' });
      else if (kind === 1) add(`rej${i}`, family, before, `${T.safe[0][0](n, 7)}\n${eco === 'haskell' ? 'broken = (' : 'broken = ['}\n`, E.main, { accepted: false, reason: 'syntax' });
      else if (kind === 2) add(`rej${i}`, family, before, `${before}${eco === 'haskell' ? '-- reviewed' : '# reviewed'}\n`, E.main, { accepted: false, reason: 'no-change' });
      else if (kind === 3) add(`rej${i}`, family, before, T.vuln[1](n, 7), E.main, { accepted: false, reason: 'still-vulnerable' });
      else add(`rej${i}`, family, before, E.insert(before, E.unknown[i % E.unknown.length](n)), E.main, { accepted: false, reason: 'not-proven-safe' });
    }
  }
  return out;
}

// ── metamorphic pairs ────────────────────────────────────────────────────────
const TRANSFORMS = {
  'rename-locals': (lang, text, p) => ({ text: renameLocals(lang, text), path: p }),
  'decoy-comments': (lang, text, p) => ({ text: addMisleadingComments(lang, text), path: p }),
  'path-scramble': (lang, text, p) => ({ text: reflowWhitespace(text), path: scramblePath(p) }),
};

function buildPairs(cases) {
  const out = [];
  for (const eco of ['haskell', 'nix']) {
    const E = ECOS[eco];
    const families = Object.keys(E.templates);
    families.forEach((family, fi) => {
      Object.keys(TRANSFORMS).forEach((tname, t) => {
        const label = (t + fi) % 2 === 0 ? 'vulnerable' : 'safe';
        const parent = cases.find((c) => c.ecosystem === eco && c.family === family && c.label === label && c.group.endsWith(`|s0|${E.nouns[t].tbl}`) && c.j === 0);
        const m = TRANSFORMS[tname](E.lang, parent.source, parent.path);
        out.push({ id: `${E.prefix}m-${sha256(`${eco}|${family}|${tname}`).slice(0, 10)}`, ecosystem: eco, family, relation: 'preserve', transform: tname, parentCase: parent.id, split: parent.split, group: parent.group, base: { path: parent.path, text: parent.source }, mutant: { path: m.path, text: m.text } });
      });
      for (let t = 0; t < 3; t++) {
        const T = E.templates[family];
        const n = E.nouns[t];
        const parentGroup = `${eco}|${family}|safe|s0|${n.tbl}`;
        const split = cases.find((c) => c.group === parentGroup).split;
        const toVuln = t % 2 === 0;
        const safe = T.safe[0][0](n, 9); const vuln = T.vuln[0](n, 9);
        out.push({ id: `${E.prefix}m-${sha256(`${eco}|${family}|flip${t}`).slice(0, 10)}`, ecosystem: eco, family, relation: 'change', transform: toVuln ? 'remove-protection' : 'add-protection', parentCase: null, split, group: parentGroup, base: { path: E.main, text: toVuln ? safe : vuln }, mutant: { path: E.main, text: toVuln ? vuln : safe } });
      }
    });
  }
  return out;
}

// ── synthetic backport / patch-evidence near misses ─────────────────────────
// Controlled records, NOT real advisories (see provenance.json "synthetic").
// A backported fix on an older release line makes a lower version safe, so a
// matcher that only compares against the newest fixed version is wrong.
const RANGES = [
  { package: 'examplelib', ranges: [{ introduced: '2.0.0', fixed: '2.1.2' }, { introduced: '1.0.0', fixed: '1.5.9' }] },
  { package: 'sample-codec', ranges: [{ introduced: '0.3.0', fixed: '0.3.4' }, { introduced: '0.4.0', fixed: '0.4.2' }] },
  { package: 'demo-parser', ranges: [{ introduced: '3.0', fixed: '3.2.1' }, { introduced: '2.8', fixed: '2.8.7' }] },
];
function buildBackport() {
  const versions = {
    examplelib: ['0.9.0', '1.0.0', '1.5.8', '1.5.9', '1.6.0', '1.9.9', '2.0.0', '2.1.1', '2.1.2', '2.2.0'],
    'sample-codec': ['0.2.9', '0.3.0', '0.3.3', '0.3.4', '0.3.9', '0.4.0', '0.4.1', '0.4.2', '0.5.0'],
    'demo-parser': ['2.7', '2.8', '2.8.6', '2.8.7', '2.9', '3.0', '3.2', '3.2.1', '3.3'],
  };
  const records = RANGES.map((r) => ({ ...r, synthetic: true, id: `SYN-${sha256(r.package).slice(0, 8)}`, cases: versions[r.package].map((v) => ({ version: v })) }));
  const nixPatch = [];
  for (let i = 0; i < 6; i++) {
    const n = NIX_NOUNS[i % 5];
    const patched = i % 2 === 0;
    const adv = records[i % 3].id;
    const patchLine = patched ? `\n      patches = (old.patches or [ ]) ++ [ ./${adv}-backport.patch ];` : '';
    nixPatch.push({
      id: `nxb-${sha256(`nixpatch${i}`).slice(0, 10)}`,
      advisory: adv,
      expected: patched ? 'patched-by-backport' : 'unpatched',
      source: `{ config, lib, pkgs, ... }:\n{\n  nixpkgs.overlays = [ (final: prev: {\n    ${n.tbl}lib = prev.${n.tbl}lib.overrideAttrs (old: {\n      version = "1.5.${i}";${patchLine}\n    });\n  }) ];\n}\n`,
    });
  }
  return { records, nixPatch };
}

// ── unseen shapes (templates-unseen.mjs): a third split with code forms absent from train, validation and holdout ──────────────────────
function buildUnseen() {
  const out = [];
  for (const [eco, E, T, nouns] of [['haskell', ECOS.haskell, HS_UNSEEN, UNSEEN_HS_NOUNS], ['nix', ECOS.nix, NIX_UNSEEN, UNSEEN_NIX_NOUNS]]) {
    for (const family of Object.keys(T)) {
      for (const label of ['vulnerable', 'safe']) {
        const shapes = label === 'vulnerable' ? T[family].vuln.map((f) => [f, null]) : T[family].safe;
        shapes.forEach(([gen, near], s) => {
          for (let k = 0; k < 2; k++) {                                          // two nouns per shape
            const group = `${eco}|${family}|${label}|u${s}|${nouns[k].tbl}`;
            const source = gen(nouns[k], 0);
            const c = { ecosystem: eco, family, label, group, split: 'unseen', nearMiss: near, shape: `u${s}`, labelledBy: 'author', j: 0, source };
            c.id = `${E.prefix}u-${sha256(`${group}|${label}`).slice(0, 10)}`;
            c.path = E.main; c.cwe = CWE[family]; c.fingerprint = fingerprint(E.lang, source); c.normalized = normalizeSource(E.lang, source);
            out.push(c);
          }
        });
      }
    }
  }
  const ids = new Set(); for (const c of out) { if (ids.has(c.id)) throw new Error(`unseen id collision ${c.id}`); ids.add(c.id); }
  return out;
}

export function build() {
  const cases = [...buildCases('haskell'), ...buildCases('nix')];
  return { cases, unseen: buildUnseen(), privacy: buildPrivacy(), supply: buildSupply(), fixes: buildFixes(), pairs: buildPairs(cases), backport: buildBackport() };
}

// ── materialise ──────────────────────────────────────────────────────────────
const w = (rel, text) => { const p = path.join(DATA, rel); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, text); };
const json = (o) => `${JSON.stringify(o, null, 1)}\n`;

export function holdoutHashes(ds) {
  const h = {};
  for (const c of ds.cases) if (c.split === 'holdout') h[c.id] = sha256(c.source);
  for (const c of ds.privacy) if (c.split === 'holdout') h[c.id] = sha256(c.source);
  return Object.fromEntries(Object.entries(h).sort(([a], [b]) => a.localeCompare(b)));
}

export function materialize(ds) {
  fs.rmSync(DATA, { recursive: true, force: true });
  for (const c of ds.cases) w(`sources/${c.ecosystem}/${c.id}/${c.path}`, c.source);
  for (const c of ds.privacy) w(`sources/privacy-${c.ecosystem}/${c.id}/${c.path}`, c.source);
  for (const s of ds.supply) for (const [f, t] of Object.entries(s.files)) w(`sources/supply-${s.ecosystem}/${s.id}/${f}`, t);
  for (const f of ds.fixes) { w(`sources/fix-${f.ecosystem}/${f.id}/before/${f.targetPath.startsWith('.') ? 'target' : f.targetPath}`, f.before); w(`sources/fix-${f.ecosystem}/${f.id}/after/proposal`, f.after); }
  for (const p of ds.pairs) { w(`sources/pair-${p.ecosystem}/${p.id}/base/${p.base.path}`, p.base.text); w(`sources/pair-${p.ecosystem}/${p.id}/mutant/${p.mutant.path}`, p.mutant.text); }
  const strip = (c) => { const { source, normalized, ...rest } = c; return rest; };
  w('labels/cases.json', json(ds.cases.map(strip)));
  for (const c of ds.unseen) w(`sources-unseen/${c.ecosystem}/${c.id}/${c.path}`, c.source);
  w('labels/unseen.json', json(ds.unseen.map(strip)));
  w('labels/privacy.json', json(ds.privacy.map(({ source, ...r }) => r)));
  w('labels/supply.json', json(ds.supply.map(({ files, ...r }) => ({ ...r, files: Object.keys(files) }))));
  w('labels/fixes.json', json(ds.fixes.map(({ before, after, ...r }) => r)));
  w('labels/pairs.json', json(ds.pairs.map(({ base, mutant, ...r }) => ({ ...r, basePath: base.path, mutantPath: mutant.path }))));
  w('labels/backport.json', json({ records: ds.backport.records, nixPatch: ds.backport.nixPatch.map(({ source, ...r }) => r) }));
  for (const p of ds.backport.nixPatch) w(`sources/backport-nix/${p.id}/configuration.nix`, p.source);
  const hold = holdoutHashes(ds);
  const all = [...ds.cases, ...ds.privacy].map((c) => `${c.id}:${sha256(c.source)}:${c.label ?? c.expected}`)
    .concat(ds.supply.map((c) => `${c.id}:${sha256(JSON.stringify(c.files))}`), ds.fixes.map((c) => `${c.id}:${sha256(c.before + c.after)}`), ds.pairs.map((c) => `${c.id}:${sha256(c.base.text + c.mutant.text)}`)).sort();
  w('manifest.json', json({
    version: VERSION,
    frozen: true,
    splitPolicy: { train: 0.5, validation: 0.2, holdout: 0.3, unit: 'origin group (ecosystem, family, label, shape, noun); mutants and unknown derivatives travel with their parent' },
    holdoutHashes: hold,
    contentRollup: sha256(all.join('\n')),
    holdoutRollup: sha256(Object.entries(hold).map(([k, v]) => `${k}:${v}`).join('\n')),
    unseen: { version: UNSEEN_VERSION, cases: ds.unseen.length, rollup: sha256(ds.unseen.map((c) => `${c.id}:${sha256(c.source)}:${c.label}`).sort().join('\n')), note: 'author-labelled shapes absent from every other split; measured once per promotion; never tuned against' },
  }));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const ds = build();
  materialize(ds);
  console.log(`wrote ${ds.cases.length} cases, ${ds.unseen.length} unseen, ${ds.privacy.length} privacy, ${ds.supply.length} supply, ${ds.fixes.length} fixes, ${ds.pairs.length} pairs`);
}
