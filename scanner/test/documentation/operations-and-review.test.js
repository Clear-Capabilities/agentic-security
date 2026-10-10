// DOC-003: the operations guides (background controller, portfolio recovery) and the offline assurance review guide. Every walk-through
// is a script the test runs with no terminal and a hard timeout, so an example that would wait for input fails here instead of
// hanging a reader. The statements about signature trust, expiry, waivers and unsupported platforms are compared with the code.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { read, REPO, script, run, node, blockWith, textBlocks, missingFrom } from './helpers.js';
import { assuranceStatement, HEADLINE, BLOCKED_HEADLINE, NOT_A_GUARANTEE } from '../../src/posture/portfolio/wording.js';
import { platformStatements } from '../../src/capabilities/probes.js';
import { syntheticManifest, manifestFacts } from '../portfolio/helpers.js';
import { PORTFOLIO_LIMITS, DEPENDENCY_DIMENSIONS } from '../../src/posture/portfolio/work-units.js';
import { HEARTBEAT, WEIGHT_RANGE } from '../../src/posture/portfolio/scheduler.js';
import { splitMarkdown } from '../../../scripts/check-assurance-docs.mjs';

const CONTROLLER = read('docs/guides/background-controller-operations.md');
const RECOVERY = read('docs/guides/portfolio-recovery.md');
const REVIEW = read('docs/guides/assurance-review.md');
const PROFILE = JSON.parse(read('scripts/loop-engineering/profiles/assurance-differentiation.json'));
const RUN_MJS = 'scripts/loop-engineering/run.mjs';

describe('[DOC-003.AC01] the guides show finite background start, live status, pause, cancellation, dependency invalidation, blocked recovery and final verification', () => {
  test('[DOC-003.AC01] the controller guide covers all seven operations, each with its command', () => {
    for (const op of ['Finite background start', 'Live status', 'Pause', 'Cancellation', 'Dependency invalidation', 'Blocked recovery', 'Final verification']) {
      assert.ok(new RegExp(`\\| ${op} \\|`).test(CONTROLLER) || new RegExp(`^## ${op}`, 'm').test(CONTROLLER), `the guide does not cover: ${op}`);
    }
    for (const cmd of ['start --background', 'status', 'pause', 'resume', 'stop --run', 'retry --requirement', 'verify --all --final', 'report --json']) assert.ok(CONTROLLER.includes(cmd), `the guide does not show: ${cmd}`);
  });

  test('[DOC-003.AC01] every controller command the guide shows is one run.mjs lists in its usage', () => {
    const usage = node(path.join(REPO, RUN_MJS), ['--help'], { cwd: REPO }).text;
    const shown = [...CONTROLLER.matchAll(/node scripts\/loop-engineering\/run\.mjs ([a-z]+)/g)].map((m) => m[1]);
    assert.ok(new Set(shown).size >= 8);
    for (const sub of new Set(shown)) assert.match(usage, new RegExp(`\\b${sub}\\b`), `"${sub}" is in the guide but not in run.mjs --help`);
  });

  test('[DOC-003.AC01] the walk-through runs end to end against the real controller, finishing every step as described', () => {
    const r = script('scripts/loop-engineering/ops-example.mjs', ['--lenient-timing'], { timeout: 240000 });
    assert.equal(r.status, 0, r.text.slice(-3000));
    assert.match(r.stdout, /every step behaved as described; the disposable repositories were removed/);
    assert.ok(!/\bFAIL\b/.test(r.stdout), 'a step failed');
    for (const phase of ['finite background start, live status, pause, resume', 'cancellation', 'dependency invalidation', 'blocked recovery', 'final verification']) assert.ok(r.stdout.includes(phase), `the walk-through skipped: ${phase}`);
    // what the guide quotes is what the controller printed
    assert.deepEqual(missingFrom(blockWith(CONTROLLER, '== finite background start'), r.text), []);
  });

  test('[DOC-003.AC01] the walk-through removed every process and directory it made', () => {
    const ps = run('ps', ['-A', '-o', 'command=']).stdout.split('\n').filter((l) => /loop-mini-/.test(l) && /run\.mjs|worker\.mjs/.test(l));
    assert.deepEqual(ps, [], 'a controller or worker from the walk-through is still running');
  });

  test('[DOC-003.AC01] the guide states the profile limits the profile file defines, and the final verification contract', () => {
    const L = PROFILE.limits;
    assert.match(CONTROLLER, new RegExp(`heartbeat every ${L.heartbeatSeconds} seconds, stale after 15`));
    assert.match(CONTROLLER, new RegExp(`worker idle stop at ${L.workerIdleSeconds} seconds, no\\s+progress stop at ${L.noProgressSeconds}`));
    assert.match(CONTROLLER, new RegExp(`${L.attemptsPerRequirement} attempts per requirement, ${L.sameFailureRepeats} repeats`));
    assert.match(CONTROLLER, new RegExp(`${L.runMaxAttempts} attempts and ${L.runWallSeconds} seconds`));
    assert.match(CONTROLLER, new RegExp(`${L.claudeBudgetUsd} and ${L.perAttemptBudgetUsd} US dollars`));
    assert.equal(PROFILE.finalVerification.required, true);
    assert.match(CONTROLLER, /single whole-tree digest/);
    assert.match(CONTROLLER, /final-evidence\.json/);
    assert.match(CONTROLLER, /`final-stale`/);
  });

  test('[DOC-003.AC01] the guide says what it does not do: it is finite, not a promise of completion, and the guide matches which suites the profile still declares not runnable', () => {
    assert.match(CONTROLLER, /It is finite\./);
    assert.match(CONTROLLER, /Nothing here promises unattended completion/);
    const notRunnable = Object.entries(PROFILE.suites).filter(([, v]) => v.notYetRunnable).length;
    assert.equal(notRunnable, 0, 'every suite has a protected wrapper, so the guide must not say any is blocked');
    assert.match(CONTROLLER, /All eleven suites are runnable/);
    assert.doesNotMatch(CONTROLLER, /ten of its eleven suites/);
  });

  test('[DOC-003.AC01] the portfolio recovery walk-through runs, converges with a fresh run, and the guide quotes its output', () => {
    const r = script('scripts/portfolio-recovery-example.mjs', [], { timeout: 120000 });
    assert.equal(r.status, 0, r.text);
    assert.ok(!/\bFAIL\b/.test(r.stdout));
    assert.deepEqual(missingFrom(blockWith(RECOVERY, '1. a worker leases a unit and crashes'), r.text), []);
    assert.deepEqual(missingFrom(blockWith(RECOVERY, 'Portfolio progress (SYNTHETIC'), r.text), []);
  });

  test('[DOC-003.AC01] the recovery guide states the lease, heartbeat, weight, dependency and limit values the code defines', () => {
    assert.deepEqual(DEPENDENCY_DIMENSIONS, ['code', 'policy', 'graph', 'invariant', 'oracle', 'toolchain']);
    assert.match(RECOVERY, /six dimensions: code, policy, graph, invariant, oracle and toolchain/);
    assert.equal(HEARTBEAT.staleAfterMs, 15000);
    assert.match(RECOVERY, /`stale` after 15 seconds without a heartbeat/);
    assert.match(RECOVERY, new RegExp(`weight from ${WEIGHT_RANGE.min} to ${WEIGHT_RANGE.max}`));
    assert.ok(PORTFOLIO_LIMITS.maxUnits > 0);
    assert.match(RECOVERY, /There is deliberately no fallback to a local write/);
  });
});

describe('[DOC-003.AC02] the assurance review guide explains signature trust, incomplete scope, expiry, waivers and retention without presenting a signature as certification', () => {
  test('[DOC-003.AC02] the walk-through runs offline, each rejection is the typed code the guide lists, and the quoted statement is what the code prints', () => {
    const r = script('scripts/assurance-review-example.mjs', [], { timeout: 120000 });
    assert.equal(r.status, 0, r.text);
    assert.ok(!/\bFAIL\b/.test(r.stdout));
    assert.deepEqual(missingFrom(blockWith(REVIEW, '1. a valid claim'), r.text), []);
    for (const code of ['BUNDLE_INVALID', 'SIGNATURE_INVALID', 'UNKNOWN_TRUST_ROOT', 'REVOKED_TRUST_ROOT', 'NO_TRUST_POLICY']) {
      assert.match(r.stdout, new RegExp(code));
      assert.ok(REVIEW.includes(`\`${code}\``), `the guide does not list ${code}`);
    }
    for (const code of ['UNSUPPORTED_BASIS', 'OVER_CLAIM', 'EVIDENCE_MISMATCH']) assert.ok(REVIEW.includes(`\`${code}\``));
    assert.match(r.stdout, /SIGNER_NOT_AUTHORIZED/);
  });

  test('[DOC-003.AC02] the guide never presents a signature as independent certification, and says the basis is self-issued', () => {
    assert.match(REVIEW, /\*\*A signature on an assurance claim is not independent certification\.\*\*/);
    assert.match(REVIEW, /`self-issued-local-key`/);
    assert.match(REVIEW, /`independentlyCertified: false`/);
    assert.match(REVIEW, /does not prove a finding is real/);
    assert.ok(REVIEW.includes(NOT_A_GUARANTEE), 'the guide quotes the not-a-guarantee line the code prints');
    assert.ok(!/\b(?:independently certified|third-party certified|certified by)\b/i.test(REVIEW.replace(/not (?:independently )?certified/gi, '')), 'a certification claim appears');
  });

  test('[DOC-003.AC02] incomplete scope: the headline the guide quotes is the one the code produces for an incomplete manifest, and for one with blocking findings', () => {
    const incomplete = assuranceStatement(syntheticManifest());
    assert.equal(incomplete.headline, `${HEADLINE}, but the mandatory scope is not fully covered`);
    assert.ok(REVIEW.includes(incomplete.headline));
    const blocked = assuranceStatement(syntheticManifest({ findings: { total: 4, blocking: 2 } }));
    assert.equal(blocked.headline, `${BLOCKED_HEADLINE}: 2`);
    assert.ok(REVIEW.includes(`${BLOCKED_HEADLINE}`.replace('Blocking findings present in completed supported checks', 'Blocking findings present in completed supported checks')) || /Blocking findings present in completed supported checks/.test(REVIEW.replace(/\s+/g, ' ')));
    assert.match(REVIEW, /A claim that omits a mandatory check from every list fails validation/);
  });

  test('[DOC-003.AC02] waivers: the Gaps line the guide quotes equals the code output, and the guide says a waiver counts toward `complete`', () => {
    const f = manifestFacts();
    const m = syntheticManifest({ checks: { ...f.checks, incomplete: [], waived: [{ id: 'replay', statement: 'runtime replay', evidenceRefs: [], reason: 'no confinement backend on this host (synthetic)', approvedBy: 'reviewer@example.test' }] } });
    const st = assuranceStatement(m);
    assert.equal(m.coverage.complete, true, 'a waived check counts toward the derived complete flag');
    assert.ok(REVIEW.includes(`Gaps: ${st.gaps.join(' | ')}`), `the guide's waiver example differs from the code: ${st.gaps.join(' | ')}`);
    assert.match(REVIEW, /a waived check counts toward the derived\s+`complete` flag/);
    assert.match(REVIEW, /not as a check that ran/);
  });

  test('[DOC-003.AC02] expiry: the guide says a signed claim carries no validity period, and the claim the code signs indeed has none', () => {
    const out = script('scripts/assurance-review-example.mjs');
    assert.match(out.stdout, /claim fields: .*\(no validity period/);
    const fields = /claim fields: ([^(]+) \(/.exec(out.stdout)[1].split(', ').map((s) => s.trim());
    assert.ok(!fields.some((k) => /expir|valid|notAfter|until/i.test(k)), `the claim has a time field: ${fields}`);
    assert.match(REVIEW, /A signed claim carries no validity period in this build\./);
    assert.match(REVIEW, /applies\s+their own freshness rule/);
  });

  test('[DOC-003.AC02] retention: the guide states the class defaults and the legal-hold and required-receipt rules the code defines', () => {
    const src = fs.readFileSync(path.join(REPO, 'scanner/src/posture/portfolio/retention.js'), 'utf8');
    assert.match(src, /365/); assert.match(src, /730/);
    assert.match(REVIEW, /replay evidence 365 days, metadata 730, model traces 30, secrets 0/);
    assert.match(REVIEW, /A\s+required current receipt is never deleted/);
    assert.match(REVIEW, /A legal hold, by id,\s+class or repository, blocks deletion/);
  });

  test('[DOC-003.AC02] the guide is honest that no command-line verb signs or verifies, and the CLI indeed has none', () => {
    assert.match(REVIEW, /No command-line verb signs or verifies a claim yet/);
    const bin = fs.readFileSync(path.join(REPO, 'scanner/bin/agentic-security.js'), 'utf8');
    assert.ok(!/signAssuranceClaim|verifyAssuranceClaim/.test(bin), 'the CLI now exposes assurance signing; update the guide');
  });
});

describe('[DOC-003.AC03] the examples avoid interactive hangs and explain explicit policy changes and unsupported enforcement platforms', () => {
  const scripts = ['scripts/loop-engineering/ops-example.mjs', 'scripts/portfolio-recovery-example.mjs', 'scripts/assurance-review-example.mjs', 'scripts/patch-replay-example.mjs',
    'scripts/tenant-invariant-example.mjs', 'scripts/graph-drift-example.mjs', 'scripts/blocked-capability-example.mjs', 'scripts/migration-example.mjs'];

  test('[DOC-003.AC03] no example script reads a terminal, prompts, or opens a socket', () => {
    for (const s of scripts) {
      const src = fs.readFileSync(path.join(REPO, s), 'utf8');
      assert.ok(!/process\.stdin|node:readline|\bprompt\(|inquirer|\bconfirm\(|\bfetch\(|node:(?:http|https|net|dgram|tls)\b/.test(src.replace(/\/\/.*$/gm, '')), `${s} is interactive or networked`);
    }
  });

  test('[DOC-003.AC03] run with stdin closed and a hard timeout, each finishes by itself (a hang would be killed and fail here)', () => {
    for (const s of ['scripts/portfolio-recovery-example.mjs', 'scripts/assurance-review-example.mjs', 'scripts/migration-example.mjs', 'scripts/blocked-capability-example.mjs']) {
      const r = script(s, [], { timeout: 60000 });
      assert.equal(r.timedOut, false, `${s} hung`);
      assert.equal(r.signal, null, `${s} was killed`);
      assert.equal(r.status, 0, `${s}: ${r.text.slice(-500)}`);
    }
  });

  test('[DOC-003.AC03] a command that would wait for input is detected by the harness (the check can fail)', () => {
    const r = node('-e', ['process.stdin.resume(); process.stdin.on("end", () => process.exit(7));'], { timeout: 5000 });
    assert.equal(r.status, 7, 'stdin is closed, so a reader sees end of input at once instead of waiting');
    const hang = node('-e', ['setInterval(() => {}, 1000)'], { timeout: 1000 });
    assert.equal(hang.timedOut, true, 'a command that never ends is killed by the timeout and reported');
  });

  test('[DOC-003.AC03] every guide says the examples need no terminal input, and the operator-facing ones state a bound', () => {
    for (const [name, md] of [['controller', CONTROLLER], ['recovery', RECOVERY], ['review', REVIEW]]) {
      assert.match(md, /no (?:terminal input|network|terminal)|nothing reads from a terminal|no terminal input/i, `${name} guide does not say it needs no terminal input`);
    }
    assert.match(CONTROLLER, /every step has a hard timeout/);
    assert.match(CONTROLLER, /Nothing here promises unattended completion/);
  });

  test('[DOC-003.AC03] explicit policy changes: limits change only by a reviewed profile edit and a new init, frozen inputs stop the run, grants are signed and single-use', () => {
    assert.match(CONTROLLER, /Raising a\s+limit or a budget is an edit to the profile by the supervising session, followed by a new `init`/);
    assert.match(CONTROLLER, /reason that begins `drift:`/);
    assert.match(CONTROLLER, /short-lived and single-use/);
    assert.match(CONTROLLER, /cannot sign the grant/);
    const controller = fs.readFileSync(path.join(REPO, 'scripts/loop-engineering/lib/controller.mjs'), 'utf8');
    assert.match(controller, /settleTerminal\('blocked', `drift: /);
    const recovery = fs.readFileSync(path.join(REPO, 'scanner/src/capabilities/recovery.js'), 'utf8');
    assert.match(recovery, /signPolicyGrant/); assert.match(recovery, /applyPolicyChange/);
  });

  test('[DOC-003.AC03] unsupported enforcement platforms: all four documents say Linux is unverified and macOS is host-proved only, and so does the code', () => {
    const ps = platformStatements();
    assert.equal(ps.linux.status, 'unverified');
    assert.equal(ps.darwin.status, 'host-proved-not-advertised');
    assert.equal(ps.win32.status, 'unsupported');
    for (const [name, md] of [['controller', CONTROLLER], ['review', REVIEW], ['recovery', RECOVERY]]) {
      assert.match(md, /Linux[^.]*unverified|unverified on Linux/, `${name} does not say Linux is unverified`);
      assert.match(md, /macOS[^.]*host-proved|host-proved[^.]*macOS/, `${name} does not say macOS is host-proved only`);
    }
    for (const md of [CONTROLLER, RECOVERY, REVIEW]) assert.ok(!/Linux[^.\n]*\b(?:is|are) (?:fully )?(?:supported|verified|enforced)\b/.test(md.replace(/unverified/g, '')), 'a guide claims Linux support');
  });

  test('[DOC-003.AC03] every command shown in a command fence of the three guides is non-interactive: no editor, pager, prompt flag or login', () => {
    for (const md of [CONTROLLER, RECOVERY, REVIEW]) {
      const fences = splitMarkdown(md).commands.map((c) => c.text).join('\n');
      assert.ok(!/\b(?:vi|vim|nano|less|more|login|read -p|--interactive|-i )\b/.test(fences), 'an interactive command is shown');
    }
    assert.ok(textBlocks(CONTROLLER).length >= 1);
  });
});
