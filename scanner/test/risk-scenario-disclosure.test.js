// Risk-dollars scenario disclosure + confidence-weight tests
// (assurance-hardening PRD FR-801/FR-802/FR-804).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { annotateRiskDollars, RISK_MODEL_VERSION, _internals } from '../src/posture/risk-dollars.js';

const { _scenarioDisclosure, _loadConfig, ORG_SPECIFIC_DIMENSIONS, _baseProb } = _internals;

function mkProject() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'risk-scenario-'));
  fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
  return { dir, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

// ── FR-801/FR-802: scenario disclosure ──────────────────────────────────

test('_scenarioDisclosure: no config file -> scenario_default, all dimensions unconfigured', () => {
  const d = _scenarioDisclosure(null);
  assert.equal(d.status, 'scenario_default');
  assert.deepEqual(d.configuredInputs, []);
  assert.deepEqual(d.unconfiguredInputs, ORG_SPECIFIC_DIMENSIONS);
  assert.match(d.message, /NOT a likely-organizational-loss estimate/);
});

test('_scenarioDisclosure: impactUSD configured -> scenario_partially_configured, never claims full organization-specific status', () => {
  const d = _scenarioDisclosure({ impactUSD: { PII: 100 } });
  assert.equal(d.status, 'scenario_partially_configured');
  assert.ok(d.configuredInputs.includes('impactUSD'));
  assert.ok(d.unconfiguredInputs.includes('industry'), 'industry/scale/recordCount/controlStrength remain unconfigured until set');
  assert.match(d.message, /NOT a likely-organizational-loss estimate/, 'a partial config must still explicitly disclaim the stronger label');
  assert.deepEqual(d.missingRequiredInputs, ['organizationScale', 'industry', 'recordCount', 'controlStrength']);
});

// ── FR-802: the full 5-input gate ────────────────────────────────────────

test('_scenarioDisclosure: ALL FIVE required inputs configured -> scenario_organization_specific, the only status permitted to claim "likely organizational loss"', () => {
  const d = _scenarioDisclosure({
    impactUSD: { PII: 100 }, organizationScale: 'enterprise', industry: 'healthcare',
    recordCount: 500000, controlStrength: 'strong',
  });
  assert.equal(d.status, 'scenario_organization_specific');
  assert.deepEqual(d.missingRequiredInputs, []);
  assert.match(d.message, /likely organizational loss/i);
});

test('_scenarioDisclosure: four of five required inputs configured (missing controlStrength) -> still only scenario_partially_configured', () => {
  const d = _scenarioDisclosure({
    impactUSD: { PII: 100 }, organizationScale: 'enterprise', industry: 'healthcare', recordCount: 500000,
  });
  assert.equal(d.status, 'scenario_partially_configured');
  assert.deepEqual(d.missingRequiredInputs, ['controlStrength']);
  assert.doesNotMatch(d.message, /this estimate reflects a likely organizational loss/i);
});

test('_scenarioDisclosure: configuring only the bonus familyBaseProb dimension (none of the 5 required) stays scenario_partially_configured, never organization_specific', () => {
  const d = _scenarioDisclosure({ familyBaseProb: { sqli: 0.5 } });
  assert.equal(d.status, 'scenario_partially_configured');
  assert.equal(d.missingRequiredInputs.length, 5);
});

test('_loadConfig: organizationScale/industry/controlStrength are parsed as flat top-level scalars', () => {
  const p = mkProject();
  try {
    fs.writeFileSync(path.join(p.dir, '.agentic-security', 'risk-config.yml'),
      'organizationScale: enterprise\nindustry: healthcare\ncontrolStrength: strong\n');
    const cfg = _loadConfig(p.dir);
    assert.equal(cfg.organizationScale, 'enterprise');
    assert.equal(cfg.industry, 'healthcare');
    assert.equal(cfg.controlStrength, 'strong');
  } finally { p.cleanup(); }
});

test('_loadConfig: recordCount is parsed as an integer; a non-numeric value is treated as not configured', () => {
  const p = mkProject();
  try {
    fs.writeFileSync(path.join(p.dir, '.agentic-security', 'risk-config.yml'), 'recordCount: 500000\n');
    assert.equal(_loadConfig(p.dir).recordCount, 500000);
  } finally { p.cleanup(); }
  const p2 = mkProject();
  try {
    fs.writeFileSync(path.join(p2.dir, '.agentic-security', 'risk-config.yml'), 'recordCount: not-a-number\n');
    assert.equal(_loadConfig(p2.dir).recordCount, undefined, 'a non-numeric recordCount must not silently become a truthy NaN "configured" value');
  } finally { p2.cleanup(); }
});

test('_loadConfig: flat scalar keys and section blocks coexist in the same file without interfering', () => {
  const p = mkProject();
  try {
    fs.writeFileSync(path.join(p.dir, '.agentic-security', 'risk-config.yml'),
      'organizationScale: enterprise\nindustry: healthcare\nrecordCount: 500000\ncontrolStrength: strong\nimpactUSD:\n  PII: 100000\n');
    const cfg = _loadConfig(p.dir);
    assert.equal(cfg.organizationScale, 'enterprise');
    assert.deepEqual(cfg.impactUSD, { PII: 100000 });
  } finally { p.cleanup(); }
});

test('annotateRiskDollars end-to-end: all 5 required inputs configured -> every finding carries scenario_organization_specific', () => {
  const p = mkProject();
  try {
    fs.writeFileSync(path.join(p.dir, '.agentic-security', 'risk-config.yml'),
      'organizationScale: enterprise\nindustry: healthcare\nrecordCount: 500000\ncontrolStrength: strong\nimpactUSD:\n  PII: 100000\n');
    const findings = [{ id: 'f1', severity: 'high', family: 'sqli', confidence: 0.9 }];
    annotateRiskDollars(p.dir, findings);
    assert.equal(findings[0].riskDollars.scenarioStatus, 'scenario_organization_specific');
  } finally { p.cleanup(); }
});

test('annotateRiskDollars: every finding carries the same scenarioStatus for one call, and the aggregate return carries the full disclosure', () => {
  const p = mkProject();
  try {
    const findings = [
      { id: 'f1', severity: 'high', family: 'sqli', confidence: 0.9 },
      { id: 'f2', severity: 'medium', family: 'xss', confidence: 0.5 },
    ];
    const result = annotateRiskDollars(p.dir, findings);
    assert.equal(result.scenario.status, 'scenario_default');
    assert.equal(findings[0].riskDollars.scenarioStatus, 'scenario_default');
    assert.equal(findings[1].riskDollars.scenarioStatus, 'scenario_default');
  } finally { p.cleanup(); }
});

test('annotateRiskDollars: an empty findings array still returns a scenario disclosure (never silently omitted)', () => {
  const p = mkProject();
  try {
    const result = annotateRiskDollars(p.dir, []);
    assert.ok(result.scenario, 'expected a scenario disclosure even for zero findings');
    assert.equal(result.scenario.status, 'scenario_default');
  } finally { p.cleanup(); }
});

// ── Pre-existing bug found while adding familyBaseProb: multi-entry parsing ──

test('_loadConfig: a risk-config.yml with MULTIPLE impactUSD entries parses all of them, not just the first (pre-existing bug, found and fixed alongside FR-801/802)', () => {
  const p = mkProject();
  try {
    fs.writeFileSync(path.join(p.dir, '.agentic-security', 'risk-config.yml'),
      'impactUSD:\n  PII: 100\n  PHI: 200\n  PCI: 300\n');
    const cfg = _loadConfig(p.dir);
    assert.deepEqual(cfg.impactUSD, { PII: 100, PHI: 200, PCI: 300 },
      'all three entries must parse — the original regex silently dropped everything after the first');
  } finally { p.cleanup(); }
});

test('_loadConfig: a section followed by a blank line, then unrelated content, does not bleed entries across sections', () => {
  const p = mkProject();
  try {
    fs.writeFileSync(path.join(p.dir, '.agentic-security', 'risk-config.yml'),
      'impactUSD:\n  PII: 100\n\nsomeOtherKey: ignored\nfamilyBaseProb:\n  sqli: 0.5\n');
    const cfg = _loadConfig(p.dir);
    assert.deepEqual(cfg.impactUSD, { PII: 100 });
    assert.deepEqual(cfg.familyBaseProb, { sqli: 0.5 });
  } finally { p.cleanup(); }
});

// ── FR-801: familyBaseProb config override (the comment used to claim this existed; it did not) ──

test('_loadConfig: familyBaseProb override is parsed from risk-config.yml', () => {
  const p = mkProject();
  try {
    fs.writeFileSync(path.join(p.dir, '.agentic-security', 'risk-config.yml'),
      'familyBaseProb:\n  sqli: 0.5\n  custom-family: 0.75\n');
    const cfg = _loadConfig(p.dir);
    assert.ok(cfg.familyBaseProb, 'expected familyBaseProb to be parsed');
    assert.equal(cfg.familyBaseProb.sqli, 0.5);
    assert.equal(cfg.familyBaseProb['custom-family'], 0.75);
  } finally { p.cleanup(); }
});

test('_baseProb: a configured familyBaseProb override takes precedence over the built-in table', () => {
  assert.equal(_baseProb('sqli', { familyBaseProb: { sqli: 0.99 } }), 0.99);
  assert.equal(_baseProb('sqli', null), 0.18, 'unconfigured still falls back to the built-in default');
});

test('annotateRiskDollars: a configured familyBaseProb override genuinely changes the EV (not silently ignored)', () => {
  const p = mkProject();
  try {
    fs.writeFileSync(path.join(p.dir, '.agentic-security', 'risk-config.yml'), 'familyBaseProb:\n  sqli: 0.99\n');
    const withOverride = [{ id: 'f1', severity: 'high', family: 'sqli', confidence: 0.9 }];
    annotateRiskDollars(p.dir, withOverride);
    const withoutOverride = [{ id: 'f2', severity: 'high', family: 'sqli', confidence: 0.9 }];
    annotateRiskDollars(mkProject().dir, withoutOverride);
    assert.ok(withOverride[0].riskDollars.ev > withoutOverride[0].riskDollars.ev,
      `expected override (prob=0.99) to raise EV above default (prob=0.18): got ${withOverride[0].riskDollars.ev} vs ${withoutOverride[0].riskDollars.ev}`);
  } finally { p.cleanup(); }
});

// ── FR-804: the confidence-weight bug (the actual regression case) ──────

test('FR-804 regression: a finding with confidence EXACTLY 0 is no longer inflated to 0.8 — it now gets ev=0', () => {
  const p = mkProject();
  try {
    const findings = [{ id: 'f1', severity: 'low', family: 'xss', confidence: 0 }];
    annotateRiskDollars(p.dir, findings);
    assert.equal(findings[0].riskDollars.confidenceWeight, 0,
      'a real confidence of 0 must be used as-is, not silently replaced by the 0.8 "unknown" default');
    assert.equal(findings[0].riskDollars.ev, 0, 'ev must be genuinely zero when confidence is genuinely zero');
  } finally { p.cleanup(); }
});

test('FR-804 regression: a finding with a genuinely low (but nonzero) confidence is no longer floored to 0.4', () => {
  const p = mkProject();
  try {
    const findings = [{ id: 'f1', severity: 'low', family: 'xss', confidence: 0.05 }];
    annotateRiskDollars(p.dir, findings);
    assert.equal(findings[0].riskDollars.confidenceWeight, 0.05,
      'a real low confidence must not be floored up to 0.4 — that was the unjustified inflation FR-804 objects to');
  } finally { p.cleanup(); }
});

test('a finding with NO confidence field at all still defaults to 0.8 (the "genuinely unknown" case, distinct from a known low value)', () => {
  const p = mkProject();
  try {
    const findings = [{ id: 'f1', severity: 'low', family: 'xss' }]; // no .confidence at all
    annotateRiskDollars(p.dir, findings);
    assert.equal(findings[0].riskDollars.confidenceWeight, 0.8);
  } finally { p.cleanup(); }
});

test('a finding with a normal high confidence is unaffected by the fix', () => {
  const p = mkProject();
  try {
    const findings = [{ id: 'f1', severity: 'high', family: 'sqli', confidence: 0.95 }];
    annotateRiskDollars(p.dir, findings);
    assert.equal(findings[0].riskDollars.confidenceWeight, 0.95);
  } finally { p.cleanup(); }
});

// ── FR-803: range, assumptions, model version, confidence ───────────────

test('FR-803: every riskDollars carries a range, assumptions, modelVersion, and confidence', () => {
  const p = mkProject();
  try {
    const findings = [{ id: 'f1', severity: 'high', family: 'sqli', confidence: 0.9 }];
    annotateRiskDollars(p.dir, findings);
    const rd = findings[0].riskDollars;
    assert.ok(rd.range && typeof rd.range.low === 'number' && typeof rd.range.base === 'number' && typeof rd.range.high === 'number');
    assert.ok(rd.range.low <= rd.range.base && rd.range.base <= rd.range.high, 'conservative <= base <= severe');
    assert.ok(Array.isArray(rd.assumptions) && rd.assumptions.length >= 4, 'expected an assumption entry per input factor');
    assert.equal(typeof rd.modelVersion, 'string');
    assert.ok(['low', 'medium', 'high'].includes(rd.confidence));
  } finally { p.cleanup(); }
});

test('FR-803: assumptions name the actual source of each factor (traceable, not generic boilerplate)', () => {
  const p = mkProject();
  try {
    const findings = [{ id: 'f1', severity: 'high', family: 'sqli', confidence: 0.9, epssScore: 0.42 }];
    annotateRiskDollars(p.dir, findings);
    const { assumptions } = findings[0].riskDollars;
    assert.ok(assumptions.some(a => /EPSS score/.test(a)), 'an EPSS-backed probability must say so, not just "built-in table"');
    assert.ok(assumptions.some(a => /impact estimate/.test(a) && /tier:/.test(a)));
    assert.ok(assumptions.some(a => /reachability discount/.test(a) && /tier:/.test(a)));
    assert.ok(assumptions.some(a => /confidence weight/.test(a)));
  } finally { p.cleanup(); }
});

test('FR-803: confidence is "low" when scenario is unconfigured, and can reach "high" only when organization-specific and well-detected', () => {
  const p = mkProject();
  try {
    const low = [{ id: 'f1', severity: 'high', family: 'sqli', confidence: 0.9 }];
    annotateRiskDollars(p.dir, low);
    assert.equal(low[0].riskDollars.confidence, 'low', 'scenario_default must never claim high confidence');

    fs.writeFileSync(path.join(p.dir, '.agentic-security', 'risk-config.yml'),
      'organizationScale: enterprise\nindustry: healthcare\nrecordCount: 500000\ncontrolStrength: strong\nimpactUSD:\n  PII: 100000\n');
    const high = [{ id: 'f2', severity: 'high', family: 'sqli', confidence: 0.9 }];
    annotateRiskDollars(p.dir, high);
    assert.equal(high[0].riskDollars.confidence, 'high');
  } finally { p.cleanup(); }
});

test('RISK_MODEL_VERSION is a real exported semver-shaped string', () => {
  assert.match(RISK_MODEL_VERSION, /^\d+\.\d+\.\d+$/);
});

// ── FR-805: scenario comparison without touching severity ───────────────

test('FR-805: conservative/base/severe scenarios are all present and ordered, base equals the legacy ev', () => {
  const p = mkProject();
  try {
    const findings = [{ id: 'f1', severity: 'critical', family: 'sqli', confidence: 0.9 }];
    annotateRiskDollars(p.dir, findings);
    const { scenarios, ev } = findings[0].riskDollars;
    assert.ok(scenarios.conservative <= scenarios.base);
    assert.ok(scenarios.base <= scenarios.severe);
    assert.equal(scenarios.base, ev, 'the top-level ev must remain the base scenario, unchanged from before FR-805');
  } finally { p.cleanup(); }
});

test('FR-805: computing scenarios never mutates finding.severity', () => {
  const p = mkProject();
  try {
    const findings = [{ id: 'f1', severity: 'medium', family: 'xss', confidence: 0.5 }];
    annotateRiskDollars(p.dir, findings);
    assert.equal(findings[0].severity, 'medium', 'severity must be untouched by scenario computation');
  } finally { p.cleanup(); }
});

test('FR-805: a severe-scenario finding with zero confidence still has all three scenarios at 0 (discount/confidence are not perturbed, so a real zero stays zero)', () => {
  const p = mkProject();
  try {
    const findings = [{ id: 'f1', severity: 'low', family: 'xss', confidence: 0 }];
    annotateRiskDollars(p.dir, findings);
    const { scenarios } = findings[0].riskDollars;
    assert.equal(scenarios.conservative, 0);
    assert.equal(scenarios.base, 0);
    assert.equal(scenarios.severe, 0);
  } finally { p.cleanup(); }
});
