// YAML-aware GitHub Actions analysis (PRD FR 06).
//
// Replaces context-free line matching for two rules with structural analysis:
//   * template injection: is an untrusted value substituted into executable
//     script text, passed as data through env, or later evaluated as code?
//   * OIDC: `id-token: write` is read from the PARSED permissions map (a
//     commented example is not a grant), and is reported as "trust policy not
//     verifiable from the repository", never as a proven missing restriction.
//
// Pure: (file path, raw text) in, findings out. Returns null when the file is
// not parseable workflow YAML so the caller can fall back to the line rules.
// Nothing here executes workflow content.

import { load } from '../util/yaml.js';

// Event fields an outsider controls. Dispatch/reusable inputs are handled
// separately: their author's privilege is assessed, and a `choice` input with
// declared options is constrained.
const UNTRUSTED_EVENT = [
  /^github\.event\.(?:issue|pull_request|discussion)\.(?:title|body)$/,
  /^github\.event\.(?:comment|review|review_comment)\.body$/,
  /^github\.event\.pull_request\.head\.(?:ref|label|repo\.default_branch)$/,
  /^github\.event\.(?:head_commit|commits\.\*|commits\[\d+\])\.(?:message|author\.(?:name|email))$/,
  /^github\.event\.head_commit\.(?:message|author\.(?:name|email))$/,
  /^github\.event\.workflow_run\.(?:head_branch|head_commit\.message|display_title)$/,
  /^github\.head_ref$/,
];
const INPUT_EXPR = /^(?:github\.event\.inputs|inputs)\.([A-Za-z_][\w-]*)$/;
const EXPR_RE = /\$\{\{\s*([^}]*?)\s*\}\}/g;

// Second interpretation of an env-carried value: the shell re-parses its content as code.
const EVAL_SINKS = (v) => [
  new RegExp(`\\beval\\b[^\\n;|&]*\\$\\{?${v}\\b`),
  new RegExp(`\\b(?:ba|z|da)?sh\\s+-c\\s+["']?[^\\n]*\\$\\{?${v}\\b`),
  new RegExp(`\\bsource\\s+<\\(\\s*echo\\s+[^)]*\\$\\{?${v}\\b`),
  new RegExp(`\\bInvoke-Expression\\b[^\\n]*\\$(?:env:)?${v}\\b`, 'i'),
  new RegExp(`\\biex\\b[^\\n]*\\$(?:env:)?${v}\\b`, 'i'),
  new RegExp(`\\bpwsh\\s+-(?:c|command)\\b[^\\n]*\\$(?:env:)?${v}\\b`, 'i'),
];

function isUntrustedEvent(expr) { return UNTRUSTED_EVENT.some((re) => re.test(expr)); }

function untrustedIn(text, inputs) {
  const out = [];
  if (typeof text !== 'string') return out;
  for (const m of text.matchAll(EXPR_RE)) {
    const expr = m[1].trim();
    if (isUntrustedEvent(expr)) { out.push({ expr, origin: expr, kind: 'event-field' }); continue; }
    const im = INPUT_EXPR.exec(expr);
    if (im) {
      const decl = inputs[im[1]];
      // A choice input with declared options is constrained to those literals.
      if (decl && decl.type === 'choice' && Array.isArray(decl.options) && decl.options.every((o) => /^[\w.\- ]*$/.test(String(o)))) continue;
      out.push({ expr, origin: expr, kind: 'dispatch-input', input: im[1] });
    }
  }
  return out;
}

function collectInputs(doc) {
  const on = doc.on ?? doc[true]; // YAML 1.1 reads a bare `on` key as boolean true
  const inputs = {};
  if (on && typeof on === 'object') {
    for (const ev of ['workflow_dispatch', 'workflow_call']) {
      const i = on[ev]?.inputs;
      if (i && typeof i === 'object') Object.assign(inputs, i);
    }
  }
  return { on, inputs };
}

function triggers(on) {
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on.map(String);
  if (on && typeof on === 'object') return Object.keys(on);
  return [];
}

function lineOf(raw, needle, fromLine = 0) {
  const lines = raw.split('\n');
  for (let i = fromLine; i < lines.length; i++) if (lines[i].includes(needle)) return i + 1;
  for (let i = 0; i < fromLine && i < lines.length; i++) if (lines[i].includes(needle)) return i + 1;
  return 1;
}

function permissionsOf(p) {
  if (p === 'write-all') return { all: 'write' };
  return p && typeof p === 'object' ? p : {};
}

/** Remove shell comment lines so a commented example is not read as a sink. */
function stripShellComments(script, shell) {
  const hash = /^\s*#/;
  return String(script).split('\n').filter((l) => !hash.test(l)).join('\n');
}

/** A validation guard that exits before the value is used, e.g. [[ "$X" =~ ^[a-z]+$ ]] || exit 1. */
function validatedBeforeUse(script, v, useIdx) {
  const lines = script.split('\n');
  for (let i = 0; i < lines.length && i < useIdx; i++) {
    const l = lines[i];
    if (new RegExp(`\\$\\{?${v}\\b`).test(l) && /(?:=~|\bgrep\s+-[A-Za-z]*q|\bcase\b)/.test(l) && /(?:exit\s+\d|return\s+\d|\bthen\b[^\n]*exit|\|\|\s*exit)/.test(l)) return true;
    if (new RegExp(`\\$\\{?${v}\\b`).test(l) && /-notmatch|-match/.test(l) && /exit/i.test(l)) return true;
  }
  return false;
}

export function analyzeWorkflow(fp, raw) {
  let doc;
  try { doc = load(raw); } catch { return null; }
  if (!doc || typeof doc !== 'object' || typeof doc.jobs !== 'object') return null;
  const { on, inputs } = collectInputs(doc);
  const trig = triggers(on);
  const wfPerm = permissionsOf(doc.permissions);
  const wfEnv = doc.env && typeof doc.env === 'object' ? doc.env : {};
  const findings = [];
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };

  const privilegedTrigger = trig.includes('pull_request_target') || trig.includes('workflow_run');
  const dispatch = trig.includes('workflow_dispatch') || trig.includes('workflow_call');

  for (const [jobId, job] of Object.entries(doc.jobs || {})) {
    if (!job || typeof job !== 'object') continue;
    const jobPerm = job.permissions !== undefined ? permissionsOf(job.permissions) : wfPerm;
    const jobEnv = { ...wfEnv, ...(job.env && typeof job.env === 'object' ? job.env : {}) };
    const writes = Object.entries(jobPerm).filter(([, v]) => v === 'write').map(([k]) => k);
    const steps = Array.isArray(job.steps) ? job.steps : [];

    if (jobPerm['id-token'] === 'write') {
      const line = lineOf(raw, 'id-token');
      push({
        id: `pipeline:${fp}:${line}:oidc:${jobId}`, kind: 'iac', severity: 'low',
        vuln: 'Pipeline: OIDC id-token: write, cloud trust policy and audience not verifiable from the repository',
        cwe: 'CWE-1188', stride: 'Elevation of privilege', file: fp, line, snippet: 'id-token: write',
        fix: 'Confirm the cloud-side trust policy requires this repository, a specific audience and a restricted subject (branch or environment). If no step requests a token, remove the permission.',
        workflow: fp, job: jobId, step: null, disposition: 'needs-review',
        missingEvidence: ['cloud trust policy (audience and subject conditions)', 'whether any action in this job requests an OIDC token'],
        sensitiveOperation: 'OIDC token minting', privilegeBoundary: `job permissions: ${writes.join(', ') || 'none'}`,
      });
    }

    steps.forEach((step, idx) => {
      if (!step || typeof step !== 'object') return;
      const stepName = step.name || step.id || `step-${idx + 1}`;
      const stepEnv = { ...jobEnv, ...(step.env && typeof step.env === 'object' ? step.env : {}) };
      const shell = String(step.shell || job.defaults?.run?.shell || doc.defaults?.run?.shell || 'bash');

      // Untrusted code checked out under a privileged trigger.
      if (typeof step.uses === 'string' && /^actions\/checkout@/.test(step.uses) && privilegedTrigger) {
        const ref = step.with?.ref;
        if (typeof ref === 'string' && /github\.(?:event\.pull_request\.head\.(?:sha|ref)|head_ref)|workflow_run\.head_(?:sha|branch)/.test(ref)) {
          const line = lineOf(raw, String(ref).trim());
          push({
            id: `pipeline:${fp}:${line}:untrusted-checkout`, kind: 'iac', severity: 'high',
            vuln: 'Pipeline: pull_request_target checks out untrusted pull request code',
            cwe: 'CWE-829', stride: 'Tampering', file: fp, line, snippet: `ref: ${ref}`,
            fix: 'A privileged-trigger workflow runs with repository secrets. Do not check out and build the pull request head in it; use `pull_request`, or split the privileged step.',
            workflow: fp, job: jobId, step: stepName, disposition: 'needs-review',
            inputOrigin: ref, sensitiveOperation: 'checkout of attacker-controlled code', privilegeBoundary: `trigger ${trig.join(', ')}; permissions: ${writes.join(', ') || 'default'}`,
          });
        }
      }

      if (typeof step.run !== 'string') return;
      const script = stripShellComments(step.run, shell);

      // 1. Untrusted expression substituted directly into the script text.
      for (const u of untrustedIn(script, inputs)) {
        const line = lineOf(raw, '${{', lineOf(raw, step.run.split('\n')[0].trim().slice(0, 40)) - 1);
        const privileged = privilegedTrigger || writes.length > 0 || Object.keys(job.secrets || {}).length > 0 || /secrets\./.test(JSON.stringify(step));
        push({
          id: `pipeline:${fp}:${line}:script:${jobId}:${idx}:${u.expr}`, kind: 'iac',
          severity: u.kind === 'dispatch-input' && !privilegedTrigger ? 'medium' : 'critical',
          vuln: 'Pipeline: untrusted github.event input interpolated into shell context',
          cwe: 'CWE-78', stride: 'Tampering', file: fp, line, snippet: `\${{ ${u.expr} }}`,
          fix: 'Pass the value through an environment variable and reference it as data ("$VAR" / $env:VAR); never substitute it into script text.',
          workflow: fp, job: jobId, step: stepName, inputOrigin: u.origin,
          inputOriginKind: u.kind, sensitiveOperation: `shell script (${shell})`,
          privilegeBoundary: `trigger ${trig.join(', ')}; ${privileged ? 'job has write permissions or secrets' : 'job is read-only'}`,
          disposition: u.kind === 'dispatch-input' ? 'needs-review' : 'detected',
          ...(u.kind === 'dispatch-input' ? { missingEvidence: ['privilege of the dispatch input author relative to the job'] } : {}),
        });
      }

      // 2. env-carried untrusted value, then re-interpreted as code.
      for (const [name, val] of Object.entries(stepEnv)) {
        const us = untrustedIn(String(val), inputs);
        if (!us.length || !/^[A-Za-z_]\w*$/.test(name)) continue;
        const sinks = EVAL_SINKS(name);
        const hit = sinks.map((re) => re.exec(script)).find(Boolean);
        if (!hit) continue;
        const useIdx = script.slice(0, hit.index).split('\n').length - 1;
        const guarded = validatedBeforeUse(script, name, useIdx);
        const line = lineOf(raw, hit[0].trim().slice(0, 30));
        push({
          id: `pipeline:${fp}:${line}:env-eval:${jobId}:${idx}:${name}`, kind: 'iac',
          severity: guarded ? 'low' : 'critical',
          vuln: 'Pipeline: untrusted github.event input interpolated into shell context (env value later evaluated as code)',
          cwe: 'CWE-78', stride: 'Tampering', file: fp, line, snippet: hit[0].trim(),
          fix: `Env placement is not a sanitizer: \$${name} is parsed as code by this command. Treat it as data only (fixed command, argument array), or validate it against an allow-list first.`,
          workflow: fp, job: jobId, step: stepName, inputOrigin: us[0].origin, inputOriginKind: us[0].kind,
          sensitiveOperation: `second interpretation of $${name} (${shell})`,
          privilegeBoundary: `trigger ${trig.join(', ')}; permissions: ${writes.join(', ') || 'default'}`,
          disposition: guarded ? 'needs-review' : 'detected',
          guards: guarded ? [`validation of $${name} before use`] : [],
        });
      }
    });
  }
  void dispatch;
  return findings;
}
