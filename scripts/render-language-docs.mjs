#!/usr/bin/env node
// Renders the generated blocks of the Haskell/Nix documentation from the code's own registries (DOC-001, DOC-002).
//
//   node scripts/render-language-docs.mjs           # rewrite the blocks in place
//   node scripts/render-language-docs.mjs --check   # exit 1 when any block differs from what the registries produce
//
// A block is the text between `<!-- generated:NAME:start -->` and `<!-- generated:NAME:end -->`. Counts and tables are derived
// from the model registries, the rule tables and the measured support registry, never typed, so a rule added or a status that
// changes makes the check fail until the page is regenerated.
import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const L = (p) => import(pathToFileURL(join(ROOT, 'scanner', 'src', 'language', p)).href);
const row = (cells) => `| ${cells.join(' | ')} |`;
const table = (head, rows) => [row(head), row(head.map(() => '---')), ...rows.map(row)].join('\n');
const by = (list, key) => list.reduce((m, x) => { (m[key(x)] ||= []).push(x); return m; }, {});
const pct = (n) => (typeof n === 'number' ? `${(n * 100).toFixed(1)}%` : 'n/a');

const CAPTURE = () => JSON.parse(readFileSync(join(ROOT, 'docs', 'examples', 'language', 'captured.json'), 'utf8'));
const EX_BLOCKS = { 'ex-hs-vuln': 'haskell-app/vulnerable', 'ex-hs-fixed': 'haskell-app/fixed', 'ex-hs-partial': 'haskell-app/partial', 'ex-nix-vuln': 'nixos-host/vulnerable', 'ex-nix-fixed': 'nixos-host/fixed', 'ex-hn-vuln': 'haskell-on-nix/vulnerable', 'ex-pp': 'polyglot-privacy' };
const FIX_BLOCKS = { 'fix-hs-logging': ['haskell-app/vulnerable', 'sensitive-logging'], 'fix-hs-sql': ['haskell-app/vulnerable', 'sql-injection'], 'fix-hs-cmd': ['haskell-app/vulnerable', 'command-injection'], 'fix-nix-ssh': ['nixos-host/vulnerable', 'ssh-access'], 'fix-nix-secret': ['nixos-host/vulnerable', 'secret-in-store'] };
const exBlock = (ex) => {
  const e = CAPTURE().examples[ex];
  const rows = e.findings.map((f) => [f.severity, `\`${f.family}\``, f.cwe || '', `${f.file}:${f.line}`]);
  return [
    `Captured from the built bundle on \`examples/${ex}\`: exit code **${e.exitCode}**, scan health **${e.health.status}**.`, '',
    rows.length ? table(['Severity', 'Family', 'CWE', 'Location'], rows) : '_No findings._',
    ...(e.health.conditions.length ? ['', 'Scan-health conditions:', ...e.health.conditions.map((c) => `- ${c}`)] : []),
    ...(e.limitations.length ? ['', `Disclosed limits: ${e.limitations.map((l) => `\`${l}\``).join(', ')}.`] : []),
  ].join('\n');
};
const fixBlock = ([ex, family]) => {
  const e = CAPTURE().examples[ex].fixPreviews.find((f) => f.family === family);
  return ['```text', `$ agentic-security fix --finding <id> --preview     # exit ${e.exitCode}`, e.text, '```'].join('\n');
};

const BLOCKS = {
  async 'hs-models'() {
    const m = await L('haskell-models.js');
    const families = by(m.HS_SINKS, (s) => `${s.family}|${s.cwe}`);
    const fam = Object.entries(families).sort().map(([k, v]) => {
      const [family, cwe] = k.split('|');
      const apis = [...new Set(v.map((s) => `${s.module}.${s.name}`))].sort();
      return [`\`${family}\``, cwe, String(apis.length), apis.slice(0, 3).map((a) => `\`${a}\``).join(', ') + (apis.length > 3 ? ', ...' : '')];
    });
    const sources = by(m.HS_SOURCES, (s) => s.provenance || 'other');
    const san = by(m.HS_SANITIZERS, (s) => (s.appliesTo || []).join('+') || 'other');
    return [
      `The model registry (\`scanner/src/language/haskell-models.js\`) holds ${m.HS_SOURCES.length} sources, ${m.HS_SINKS.length} sinks and ${m.HS_SANITIZERS.length} sanitizers. Every entry names an import-qualified function, so a function of your own with the same name never matches.`,
      '',
      table(['Sink family', 'CWE', 'APIs modelled', 'Examples'], fam),
      '',
      `Source provenances: ${Object.entries(sources).sort().map(([k, v]) => `${k} (${v.length})`).join(', ')}.`,
      '',
      `Sanitizer effects: ${Object.entries(san).sort().map(([k, v]) => `${k} (${v.length})`).join(', ')}.`,
    ].join('\n');
  },
  async 'nix-hardening'() {
    const { HARDENING_RULES, HARDENING_VERSION } = await L('nixos-hardening.js');
    const rows = Object.entries(HARDENING_RULES).map(([id, r]) => [`\`${id}\``, r.family, r.cwe, r.severity, r.vuln]);
    return [`${rows.length} rules${HARDENING_VERSION ? ` (ruleset \`${HARDENING_VERSION}\`)` : ''}, judged against the effective configuration:`, '', table(['Rule', 'Family', 'CWE', 'Severity', 'Finding'], rows)].join('\n');
  },
  async 'nix-build-trust'() {
    const { BUILD_TRUST_RULES, BUILD_TRUST_RULESET_VERSION } = await L('nix-build-trust.js');
    const rows = Object.entries(BUILD_TRUST_RULES).map(([id, r]) => [`\`${id}\``, r.family, r.cwe || '', r.severity || '', r.vuln || '']);
    return [`${rows.length} rules (ruleset \`${BUILD_TRUST_RULESET_VERSION}\`):`, '', table(['Rule', 'Family', 'CWE', 'Severity', 'Finding'], rows)].join('\n');
  },
  async 'nix-secrets'() {
    const s = await L('nix-secrets.js');
    const R = s.NIX_SECRET_RULES || s.SECRET_RULES;
    if (!R) return '_(rule table not exported)_';
    const rows = Object.entries(R).map(([id, r]) => [`\`${id}\``, r.family, r.cwe, r.vuln || '']);
    return table(['Rule', 'Family', 'CWE', 'Finding'], rows);
  },
  async 'language-metrics'() {
    const reg = JSON.parse(readFileSync(join(ROOT, 'docs', 'language-support.json'), 'utf8'));
    const out = [`Read from \`docs/language-support.json\` (generated by \`bench/language-support/promote.mjs\` from the frozen holdout, measured ${reg.generatedAt}, node ${reg.node}). Targets (PRD section 9.2): precision >= ${reg.targets.precision}, recall >= ${reg.targets.recall}, F1 >= ${reg.targets.f1}, per-family F1 >= ${reg.targets.perFamilyF1}, at least ${reg.targets.minHoldoutPerLabelPerFamily} vulnerable and ${reg.targets.minHoldoutPerLabelPerFamily} safe holdout cases per family.`, ''];
    for (const [lang, title] of [['haskell', 'Haskell'], ['nix', 'Nix and NixOS']]) {
      const l = reg.languages[lang];
      out.push(`**${title}** (corpus ${l.frozen && l.frozen.corpusVersion ? l.frozen.corpusVersion : 'qa001'}${l.frozen && l.frozen.labelsSha256 ? `, labels hash ${String(l.frozen.labelsSha256).slice(0, 12)}` : ''}${l.frozen && l.frozen.holdoutRollup ? `, holdout rollup ${String(l.frozen.holdoutRollup).slice(0, 12)}` : ''})`, '');
      const rows = Object.values(l.rows).filter((r) => r.evidence && r.evidence.f1 !== undefined).map((r) => { const e = r.evidence; return [r.capability, r.status, e.layer || 'privacy', String(e.cases ?? (e.tp + e.fp + e.fn + e.tn)), `${e.tp}/${e.fp}/${e.fn}/${e.tn}`, pct(e.precision), pct(e.recall), pct(e.f1)]; });
      out.push(table(['Capability', 'Status', 'Layer', 'Cases', 'TP/FP/FN/TN', 'Precision', 'Recall', 'F1'], rows), '');
      const fam = [];
      for (const r of Object.values(l.rows)) if (r.evidence && r.evidence.families) for (const [f, x] of Object.entries(r.evidence.families)) fam.push([r.capability, `\`${f}\``, `${x.tp}/${x.fp}/${x.fn}`, pct(x.f1)]);
      if (fam.length) out.push(table(['Capability', 'Family', 'TP/FP/FN', 'F1'], fam), '');
    }
    out.push('Layers are scored independently and a finding of a different family inside a case is counted separately, never as a miss or a hit of the family under test. The corpus is synthetic and template-generated, so these figures describe robustness over those shapes; they are not accuracy on arbitrary real-world code.');
    return out.join('\n');
  },
  async 'completion-status'() {
    const c = JSON.parse(readFileSync(join(ROOT, 'docs', 'completion-status.json'), 'utf8'));
    if (!c.remaining.length) return `All ${c.requirements.total} requirements of the Haskell and Nix/NixOS programme are verified.`;
    const rows = c.remaining.map((r) => [`\`${r.id}\``, r.state, String(r.blocker).replace(/\|/g, '/').slice(0, 160)]);
    return [`**Partial release.** ${c.requirements.verified} of ${c.requirements.total} requirements of the programme are verified (${c.verifiedPercent}% by weight); the rest are open:`, '', table(['Requirement', 'State', 'Why it is open'], rows)].join('\n');
  },
  async 'support-summary'() {
    const reg = JSON.parse(readFileSync(join(ROOT, 'docs', 'language-support.json'), 'utf8'));
    const out = [];
    for (const [lang, title] of [['haskell', 'Haskell'], ['nix', 'Nix and NixOS']]) {
      const l = reg.languages[lang];
      const rows = Object.values(l.rows).map((r) => {
        const e = r.evidence || {};
        const ev = e.f1 !== undefined ? `P ${pct(e.precision)} / R ${pct(e.recall)} / F1 ${pct(e.f1)} (${e.tp} TP, ${e.fp} FP, ${e.fn} FN)` : (r.status === 'supported' ? 'see the table' : '');
        return [r.capability, r.status, ev || (r.reasons && r.reasons[0] ? r.reasons[0].slice(0, 110) : '')];
      });
      out.push(`**${title}**`, '', table(['Capability', 'Status', 'Measured on the frozen holdout, or why not'], rows), '');
    }
    out.push(`Measured ${reg.generatedAt} on the synthetic, template-generated corpus described in [Haskell and Nix support](docs/language-support.md); ${reg.limits[0].split(':')[0].toLowerCase()}.`);
    return out.join('\n').replace(/\]\(docs\//g, '](');
  },
};
// README links are relative to the repository root; docs/ pages link relative to themselves.
const PREFIX_FIX = { 'README.md': (s) => s.replace(/\]\(language-support\.md\)/g, '](docs/language-support.md)') };

BLOCKS['pp-facts'] = async () => {
  const e = CAPTURE().examples['polyglot-privacy'];
  const g = e.dataflow;
  return [
    `AI inventory (\`scan --format aibom\`): models ${e.aibom.models.map((m) => `\`${m}\``).join(', ')}; ${e.aibom.endpoints} endpoint(s); ${e.aibom.services} declared service(s).`,
    `Dependency inventory (\`--format cyclonedx\`): ${e.sbom.map((c) => `\`${c}\``).join(', ')} (declared; no plan was supplied, so no resolved versions).`,
    g ? `Data Flow Explorer export (\`dataflow export --format json\`, schema ${g.schemaVersion}): ${g.nodeCount} nodes, ${g.edgeCount} edges; per-language coverage: ${g.coverage.languages.map((l) => `${l.language} ${l.filesAnalyzed}/${l.filesExpected} files (${l.tier})`).join(', ')}.` : '',
  ].filter(Boolean).join('\n\n');
};
for (const [k, ex] of Object.entries(EX_BLOCKS)) BLOCKS[k] = async () => exBlock(ex);
for (const [k, v] of Object.entries(FIX_BLOCKS)) BLOCKS[k] = async () => fixBlock(v);

const TARGETS = {
  'docs/guides/haskell.md': ['hs-models', 'ex-hs-vuln', 'ex-hs-fixed', 'ex-hs-partial', 'fix-hs-logging', 'fix-hs-sql', 'fix-hs-cmd'],
  'docs/guides/nix-nixos.md': ['nix-hardening', 'nix-build-trust', 'nix-secrets', 'ex-nix-vuln', 'ex-nix-fixed', 'ex-hn-vuln', 'fix-nix-ssh', 'fix-nix-secret'],
  'README.md': ['completion-status', 'support-summary'],
  'docs/examples/README.md': ['ex-hs-vuln', 'ex-hs-partial', 'ex-nix-vuln', 'ex-hn-vuln', 'ex-pp', 'pp-facts', 'fix-nix-ssh', 'fix-hs-cmd'],
  'docs/METRICS.md': ['language-metrics'],
};

export async function render({ check = false } = {}) {
  const stale = [];
  for (const [file, names] of Object.entries(TARGETS)) {
    const p = join(ROOT, file); let text = readFileSync(p, 'utf8'); const before = text;
    for (const name of names) {
      const re = new RegExp(`(<!-- generated:${name}:start -->)[\\s\\S]*?(<!-- generated:${name}:end -->)`);
      if (!re.test(text)) { stale.push(`${file}: no generated:${name} block`); continue; }
      let body = await BLOCKS[name]();
      if (name === 'support-summary') body = body.replace(/docs\/language-support\.md/g, file === 'README.md' ? 'docs/language-support.md' : 'language-support.md').replace(/\]\(language-support\.md\)/g, file === 'README.md' ? '](docs/language-support.md)' : '](language-support.md)');
      text = text.replace(re, (_, a, b) => `${a}\n${body}\n${b}`);
    }
    if (PREFIX_FIX[file]) text = PREFIX_FIX[file](text);
    if (text !== before) { if (check) stale.push(`${file}: generated blocks are stale`); else writeFileSync(p, text); }
  }
  return stale;
}

if (process.argv[1] && process.argv[1] === fileURLToPath(import.meta.url)) {
  const stale = await render({ check: process.argv.includes('--check') });
  if (stale.length) { console.error(stale.join('\n')); console.error('run `node scripts/render-language-docs.mjs`'); process.exit(1); }
  console.log(process.argv.includes('--check') ? 'generated language docs are current' : 'rendered');
}
