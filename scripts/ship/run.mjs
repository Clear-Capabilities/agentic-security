// The release flow, as a state machine over an injected context (scripts/ship.mjs wires the real one; the tests wire a scripted one).
// Each phase starts the moment the previous one finishes: no human or agent polling sits between a green check and the next step.

import { staleVersionArtifacts, PHASES, ShipState, chooseReleaseSha, parseChecks, classifyChecks, findStuckJobs, classifyReleaseFailure, npmFacts, preflightProblems, waitFor, verifyArgs, parseWarm, earlyGateArgs, lateGateArgs, scratchEnv } from './lib.mjs';

const PKG = '@clear-capabilities/agentic-security-scanner';
const CRED = ['-c', "credential.helper=!gh auth git-credential"];
const VERSION_FILES = ['CLAUDE.md', 'README.md', '.claude-plugin/plugin.json', '.claude-plugin/marketplace.json', 'gemini-extension.json'];

class Stop extends Error { constructor(phase, message) { super(message); this.phase = phase; } }

/**
 * @param {object} ctx  sh(cmd,args,opts)->{code,out,err}; fetchJson(url); readFile(path); now(); sleep(ms); log(line); state: ShipState
 * @param {object} [opts] { branch?, maxRetries, stuckMinutes, checksTimeoutMin, releaseTimeoutMin, npmTimeoutMin, allowMissing, dryRun, tmpdir, releaseOnly }
 */
export async function runShip(ctx, opts = {}) {
  const o = { maxRetries: 2, stuckMinutes: 40, checksTimeoutMin: 90, releaseTimeoutMin: 60, npmTimeoutMin: 90, npmSoftSeconds: 90, closureJobs: 3, localGate: false, allowMissing: ['dependency-currency'], dryRun: false, ...opts };
  const { sh, state, log } = ctx;
  const git = (args) => { const r = sh('git', args); if (r.code !== 0) throw new Error(`git ${args.join(' ')}: ${r.err.trim().slice(0, 200)}`); return r.out; };
  const gh = (args) => sh('gh', args);
  const ghJson = (args) => { const r = gh(args); if (r.code !== 0) throw new Error(`gh ${args.slice(0, 3).join(' ')}: ${r.err.trim().slice(0, 200)}`); return JSON.parse(r.out || 'null'); };
  // Resuming: a phase already done is skipped (never re-merge, never re-tag), and the facts later phases need come back from the saved state.
  const done = (name) => o.resume && state.data.phases && state.data.phases[name] && state.data.phases[name].state === 'done' && !(name === 'npm' && state.data.npmPending);
  const phase = async (name, fn) => { if (done(name)) { log(`↷ ${name} (already done)`); return state.data.phases[name].detail; } state.begin(name); log(`▶ ${name}`); try { const detail = await fn(); state.finish(name, true, detail || null); log(`✓ ${name}${detail ? ': ' + detail : ''}`); return detail; } catch (e) { state.finish(name, false, String(e.message || e)); throw e; } };

  let branch, version, prNumber, prHead, releaseSha, tag, treeEquivalent = false;
  const originalBranch = git(['branch', '--show-current']).trim();
  // A resumed run starts clean: the stop it is continuing from is recorded in the phases, and a stale `failed` would be reported after it succeeds.
  state.set({ dryRun: o.dryRun, tmpdirGiven: Boolean(o.tmpdir), ...(o.tmpdir ? { tmpdir: o.tmpdir } : {}), ...(o.resume ? { failed: null } : {}) });
  let autoTmp = null;
  if (o.resume) { const d = state.data; branch = d.branch; version = d.version; tag = d.tag; prNumber = d.pr; prHead = d.prHead; releaseSha = d.releaseSha; treeEquivalent = Boolean(d.treeEquivalent); }

  try {
    // ── preflight: everything that would fail late, found before anything is pushed ─────────────────────────────
    await phase('preflight', async () => {
      branch = o.branch || originalBranch;
      version = JSON.parse(ctx.readFile('scanner/package.json')).version;
      tag = `v${version}`;
      const files = {}; for (const f of VERSION_FILES) { try { files[f] = ctx.readFile(f); } catch { /* an optional file */ } }
      const dirty = git(['status', '--porcelain']).split('\n').filter((l) => l && !l.startsWith('??')).length;
      let npmLatest = null; try { npmLatest = (await ctx.fetchJson(`https://registry.npmjs.org/${PKG.replace('/', '%2f')}`))['dist-tags'].latest; } catch { /* offline: the registry check is skipped, and said so */ }
      const problems = preflightProblems({ version, files, changelog: ctx.readFile('CHANGELOG.md'), npmLatest, branch, dirty, releaseOnly: o.releaseOnly });
      problems.push(...staleVersionArtifacts({ version, readFile: ctx.readFile }));
      if (o.releaseOnly) {
        // Release-only: the change was already pushed, reviewed and merged through its own pull request, so the work here is the tag and the hosted
        // release. That is only sound when main is exactly what origin has AND the hosted CI already passed on that commit.
        git(['fetch', 'origin', 'main']);
        const head = git(['rev-parse', 'HEAD']).trim();
        if (head !== git(['rev-parse', 'origin/main']).trim()) problems.push('release-only: HEAD is not origin/main (pull, or push your commits through a pull request first)');
        const ci = ghJson(['run', 'list', '--commit', head, '--workflow', 'ci', '--json', 'status,conclusion']) || [];
        if (!ci.length || !ci.every((x) => x.status === 'completed' && x.conclusion === 'success')) problems.push(`release-only: the hosted ci workflow has no green run for ${head.slice(0, 8)}; it must have passed before a release-only ship`);
      }
      if (gh(['auth', 'status']).code !== 0) problems.push('gh is not authenticated');
      // A newly published advisory or a newly outdated dependency fails the hosted check an hour in; this is the same check, run before anything is pushed.
      if (!o.skipDependencyCheck) {
        const dc = sh('node', ['scripts/dependency-currency.mjs'], { timeoutMs: 5 * 60 * 1000 });
        if (dc.code !== 0) problems.push(`dependency currency fails (the hosted check would fail the same way): ${(dc.out + dc.err).split('\n').filter((l) => /^\s*✗/.test(l)).slice(0, 2).map((l) => l.trim().slice(0, 160)).join(' | ') || 'run node scripts/dependency-currency.mjs'}`);
      }
      if (problems.length) throw new Stop('preflight', problems.join('; '));
      state.set({ branch, version, tag });
      return `${tag} from ${branch}${npmLatest ? ` (npm has ${npmLatest})` : ' (npm unreachable: not compared)'}`;
    });

    // ── push (the pre-push gate runs here; it is a control, never bypassed) ──────────────────────────────────────
    await phase('push', async () => {
      if (o.releaseOnly) return 'skipped (release-only: already on origin/main)';
      const head = git(['rev-parse', 'HEAD']).trim();
      const remote = sh('git', ['ls-remote', 'origin', `refs/heads/${branch}`]).out.split('\t')[0];
      if (remote === head) return 'already on origin';
      // The post-commit hook may be running (or have finished) the fast-tier gate for this commit in the background. With --local-gate the push
      // waits for it and reuses its verdicts. By default (0.195.6) it does not wait: the push runs the gate's hosted tier (the in-process guards,
      // seconds) and the pull request's blocking checks are the gate. A background failure already recorded stops the run here; one recorded
      // while the hosted checks run stops it before the merge (see below). Nothing is bypassed: the hook still runs, at the tier it is told.
      const warm = parseWarm(sh('node', ['scripts/gate-warm.mjs', o.localGate ? '--wait' : '--status', '--json'], { timeoutMs: 95 * 60 * 1000 }).out);
      if (warm && warm.state === 'failed') throw new Stop('push', `the background gate already failed for this commit: ${(warm.failed || []).join('; ') || 'see .agentic-security/gate-warm/gate.log'}`);
      if (warm) log(`  background gate for this commit: ${warm.state}${warm.state === 'passed' ? ' (the push reuses its cached verdicts)' : o.localGate ? '' : ' (not awaited: the hosted checks gate the merge)'}`);
      const r = sh('git', [...CRED, 'push', '-u', 'origin', branch], { timeoutMs: 60 * 60 * 1000, stream: true, env: o.localGate ? {} : { AGENTIC_SECURITY_PUSH_GATE: 'hosted' } });
      if (r.code !== 0) {
        const text = `${r.err}\n${r.out}`;
        // the gate prints one `FAIL  <check>` line per failed check: name them, not just the last lines of noise
        const failed = [...new Set(text.split('\n').filter((l) => /^FAIL\s/.test(l)).map((l) => l.replace(/^FAIL\s+/, '').trim()))];
        const why = failed.length ? `failed checks: ${failed.join('; ')}` : text.trim().split('\n').slice(-6).join(' | ');
        throw new Stop('push', `git push failed (the pre-push gate or the remote refused): ${why.slice(0, 400)}`);
      }
      // the gate prints exactly this line when every check passed; only a fast or full tier pass is evidence that the ten pre-push checks ran
      // for this head (the hosted tier runs the guards alone and proves nothing about the suites)
      if (/pre-push gate PASSED in \d+s \(tier (?:fast|full)\)/.test(`${r.err}\n${r.out}`)) state.set({ prePushPassed: head });
      return `pushed ${head.slice(0, 8)}`;
    });

    // ── pull request ─────────────────────────────────────────────────────────────────────────────────────────────
    await phase('pr', async () => {
      if (o.releaseOnly) return 'skipped (release-only: merged through its own pull request)';
      const head = git(['rev-parse', 'HEAD']).trim();
      let prs = ghJson(['pr', 'list', '--head', branch, '--state', 'open', '--json', 'number,url,headRefOid']) || [];
      if (!prs.length) {
        const title = git(['log', '-1', '--format=%s']).trim();
        const body = `Release ${tag}. See CHANGELOG.md for what changed and what was not verified.\n\n🤖 Generated with [Claude Code](https://claude.com/claude-code)`;
        const c = gh(['pr', 'create', '--base', 'main', '--head', branch, '--title', title, '--body', body]);
        if (c.code !== 0) throw new Stop('pr', `could not open the pull request: ${c.err.trim().slice(0, 200)}`);
        prs = ghJson(['pr', 'list', '--head', branch, '--state', 'open', '--json', 'number,url,headRefOid']) || [];
      }
      if (!prs.length) throw new Stop('pr', 'no pull request found after creating one');
      // The API can still report the PREVIOUS head for a second or two after a push. The branch on origin is the authority: when it is the commit just
      // gated, that is the PR head. (A stale value made the early gate's verdict and the recorded pre-push pass refer to different commits, so the
      // whole release gate ran a second time after the merge.)
      const onOrigin = sh('git', ['ls-remote', 'origin', `refs/heads/${branch}`]).out.split('\t')[0];
      prNumber = prs[0].number; prHead = onOrigin === head ? head : (prs[0].headRefOid || head);
      state.set({ pr: prNumber, prUrl: prs[0].url });
      return `#${prNumber}`;
    });

    // ── the early release gate: runs on the PR head WHILE the hosted checks run, so the two waits overlap ──────────────────────────────────
    // It is the local half of the release gate that the hosted checks do not cover (see earlyGateArgs). The merge waits for it, and so does the tag.
    const startEarlyGate = () => {
      const head = prHead;
      if (o.releaseOnly || !o.localGate) return Promise.resolve({ ok: true, nothing: true });
      if (state.data.earlyPassedFor === head) return Promise.resolve({ ok: true, reused: true });
      return (async () => {
        const { plannedCheckIds } = await import('../release-check.mjs');
        const plan = earlyGateArgs({ allIds: plannedCheckIds(), prePushPassed: state.data.prePushPassed, prHead: head });
        if (!plan.args) return { ok: true, nothing: true };
        let tmp = o.tmpdir;
        if (!tmp && ctx.makeTmpdir) { tmp = autoTmp = ctx.makeTmpdir(); state.set({ tmpdir: tmp }); }
        log(`  early release gate: ${plan.reason}`);
        const run = ctx.runNodeAsync || ((args, x) => Promise.resolve(sh('node', args, { ...x, stream: true })));
        const r = await run(['scripts/release-check.mjs', ...plan.args], { timeoutMs: 90 * 60 * 1000, env: { ...scratchEnv(tmp), AGENTIC_SECURITY_CLOSURE_JOBS: String(o.closureJobs) }, logAs: 'verify' });
        return { ok: r.code === 0, head, failed: (r.out + r.err).split('\n').filter((l) => /^(FAIL|✗)/.test(l)).slice(0, 4).join(' | ') };
      })();
    };
    const early = o.resume && done('checks') ? Promise.resolve({ ok: true, skipped: true }) : startEarlyGate();

    // ── blocking checks, with automatic recovery from a hung or infrastructure-failed job ───────────────────────
    await phase('checks', async () => {
      if (o.releaseOnly) return 'skipped (release-only: hosted ci already green on this commit)';
      const tiers = JSON.parse(ctx.readFile('.github/required-checks.json'));
      const blocking = tiers.blocking;
      const informational = tiers.informational || [];
      const retries = new Map();
      const r = await waitFor(async () => {
        const rows = parseChecks(gh(['pr', 'checks', String(prNumber)]).out);
        const c = classifyChecks(rows, blocking, { allowMissing: o.allowMissing });
        state.note('checks', `${rows.filter((x) => x.state === 'pass').length} pass, ${c.pending.length} blocking pending${c.failing.length ? `, FAILING: ${c.failing.join(', ')}` : ''}`);
        if (c.green) return { green: true };
        let rerunThisTick = false;
        const runs = ghJson(['run', 'list', '--branch', branch, '--limit', '12', '--json', 'databaseId,status,conclusion,workflowName']) || [];
        for (const run of runs.filter((x) => x.status === 'in_progress' || (x.status === 'completed' && x.conclusion === 'failure'))) {
          const jobs = (ghJson(['run', 'view', String(run.databaseId), '--json', 'jobs']) || { jobs: [] }).jobs;
          const stuck = run.status === 'in_progress' ? findStuckJobs(jobs, ctx.now(), { maxMinutes: o.stuckMinutes, exempt: informational }) : [];
          const infra = run.status === 'completed' ? classifyReleaseFailure(jobs).kind === 'infra' : false;
          if (!stuck.length && !infra) continue;
          const used = retries.get(run.databaseId) || 0;
          if (used >= o.maxRetries) throw new Stop('checks', `run ${run.databaseId} (${run.workflowName}) needed more than ${o.maxRetries} automatic re-runs`);
          retries.set(run.databaseId, used + 1);
          rerunThisTick = true;
          ctx.log(`  ${stuck.length ? `stuck: ${stuck.map((s) => `${s.name} ${s.minutes} min`).join(', ')}` : 'infrastructure failure'}: re-running ${run.workflowName} (attempt ${used + 2})`);
          state.event(`re-ran ${run.workflowName} (${stuck.length ? 'stuck job' : 'infra failure'})`);
          if (run.status === 'in_progress') { gh(['run', 'cancel', String(run.databaseId)]); await waitFor(() => (ghJson(['run', 'view', String(run.databaseId), '--json', 'status']) || {}).status === 'completed', { timeoutMs: 120000, intervalMs: 3000, now: ctx.now, sleep: ctx.sleep }); }
          gh(['run', 'rerun', String(run.databaseId), '--failed']);
        }
        if (c.failing.length) {
          // A failing blocking check that is not an infrastructure failure is a real failure: stop and say which. Stop as soon as no BLOCKING check is
          // still pending (and nothing was just re-run): an informational job that is still running (the 40 minute local-model job) cannot turn it green.
          if (!rerunThisTick && c.pending.length === 0) throw new Stop('checks', `blocking checks failed: ${c.failing.join(', ')}`);
        }
        return null;
      }, { timeoutMs: o.checksTimeoutMin * 60000, intervalMs: 5000, now: ctx.now, sleep: ctx.sleep });
      if (!r.ok) throw new Stop('checks', `blocking checks were not green after ${o.checksTimeoutMin} min`);
      return 'all blocking checks green';
    });

    const earlyResult = await early;
    sh('git', ['checkout', '--', 'bench/memory/history.jsonl', 'bench/provenance/history.jsonl', 'bench/ttff/history.jsonl']);
    if (!earlyResult.ok) throw new Stop('verify', `the early release gate failed before the merge: ${earlyResult.failed || 'see .agentic-security/ship/logs/verify.log'}`);
    if (!earlyResult.skipped && !earlyResult.nothing && !earlyResult.reused) state.set({ earlyPassedFor: earlyResult.head });
    if (o.dryRun) { log('dry run: stopping before the merge'); return { ok: true, dryRun: true, state: state.data }; }

    // The background gate may have finished while the hosted checks ran. Its failure is read here, not awaited: a recorded failure stops the
    // run before the merge; a run still going is left to finish on its own (the hosted checks already proved the tree).
    if (!o.localGate && !o.releaseOnly) {
      const late = parseWarm(sh('node', ['scripts/gate-warm.mjs', '--status', '--json']).out);
      if (late && late.state === 'failed') throw new Stop('merge', `the background gate failed for the pushed commit: ${(late.failed || []).join('; ') || 'see .agentic-security/gate-warm/gate.log'}`);
      if (late) log(`  background gate before the merge: ${late.state}${late.state === 'running' ? ' (not awaited)' : ''}`);
    }

    // ── merge, then decide what to release ──────────────────────────────────────────────────────────────────────
    let mergeSha = state.data.mergeSha;
    await phase('merge', async () => {
      if (o.releaseOnly) {
        mergeSha = prHead = releaseSha = git(['rev-parse', 'HEAD']).trim(); treeEquivalent = true;
        state.set({ releaseSha, mergeSha, prHead, treeEquivalent });
        return `skipped (release-only): releasing main at ${releaseSha.slice(0, 8)}`;
      }
      const m = gh(['pr', 'merge', String(prNumber), '--merge']);
      if (m.code !== 0) throw new Stop('merge', `could not merge: ${m.err.trim().slice(0, 200)}`);
      const v = ghJson(['pr', 'view', String(prNumber), '--json', 'mergeCommit,headRefOid,state']);
      if (!v || v.state !== 'MERGED' || !v.mergeCommit) throw new Stop('merge', 'the pull request is not merged');
      mergeSha = v.mergeCommit.oid; prHead = v.headRefOid;
      git(['fetch', 'origin']);
      const pick = chooseReleaseSha({ prHead, mergeSha, git });
      releaseSha = pick.sha; treeEquivalent = pick.treeEquivalent;
      state.set({ releaseSha, mergeSha, prHead, treeEquivalent });
      return `${pick.treeEquivalent ? 'releasing the verified PR head' : 'releasing the merge commit'} ${releaseSha.slice(0, 8)}: ${pick.why}`;
    });

    // ── verify the commit being released ────────────────────────────────────────────────────────────────────────
    await phase('verify', async () => {
      if (!treeEquivalent) {
        // the base moved, so this tree was never verified: its own CI must be green before anything else
        const ok = await waitFor(() => { const runs = ghJson(['run', 'list', '--commit', releaseSha, '--json', 'status,conclusion,workflowName']) || []; return runs.length && runs.every((x) => x.status === 'completed') ? runs : null; }, { timeoutMs: o.checksTimeoutMin * 60000, intervalMs: 20000, now: ctx.now, sleep: ctx.sleep });
        if (!ok.ok) throw new Stop('verify', `CI on ${releaseSha.slice(0, 8)} did not finish`);
        const bad = ok.value.filter((x) => x.conclusion !== 'success' && /^ci$/i.test(x.workflowName));
        if (bad.length) throw new Stop('verify', `CI failed on the merge commit ${releaseSha.slice(0, 8)}`);
      }
      git(['checkout', '--detach', releaseSha]);
      // The gate gets an EMPTY temp directory unless the operator named one: leftover temp files from earlier runs slow the suite.
      let tmp = o.tmpdir || autoTmp;
      if (!tmp && ctx.makeTmpdir) { tmp = autoTmp = ctx.makeTmpdir(); state.set({ tmpdir: tmp }); log(`  release gate TMPDIR: ${tmp} (fresh and empty)`); }
      const { plannedCheckIds } = await import('../release-check.mjs');
      if (o.releaseOnly || !o.localGate) {
        // The hosted release workflow re-runs every check with the cache off and its publish job needs all of them, so this local step is only
        // the publish blockers that can be answered here in seconds.
        const only = ['head-pushed', 'remote-ci-green', 'changelog-entry', 'version-consistency', 'scorecard-freshness', 'bundle-integrity', 'package-contents', 'dependency-currency'];
        const q = sh('node', ['scripts/release-check.mjs', '--only', only.join(',')], { stream: true, timeoutMs: 20 * 60 * 1000 });
        if (q.code !== 0) throw new Stop('verify', `the ${o.releaseOnly ? 'release-only' : 'publish-blocker'} checks failed: ${(q.out + q.err).split('\n').filter((l) => /^(FAIL|✗)/.test(l)).slice(0, 4).join(' | ')}`);
        return `${o.releaseOnly ? 'release-only' : 'publish-blocker'} checks passed on ${releaseSha.slice(0, 8)} (${only.length} publish blockers; hosted CI and the hosted release workflow run the full gate; --local-gate adds the local one)`;
      }
      const late = lateGateArgs({ allIds: plannedCheckIds(), earlyPassedFor: state.data.earlyPassedFor, releaseSha, treeEquivalent });
      const plan = late || verifyArgs({ allIds: plannedCheckIds(), treeEquivalent, prePushPassed: state.data.prePushPassed, prHead });
      log(`  release gate: ${plan.reason}`);
      const r = sh('node', ['scripts/release-check.mjs', ...plan.args], { stream: true, timeoutMs: 90 * 60 * 1000, env: tmp ? { TMPDIR: tmp, TMP: tmp, TEMP: tmp } : {} });
      sh('git', ['checkout', '--', 'bench/memory/history.jsonl', 'bench/provenance/history.jsonl', 'bench/ttff/history.jsonl']);
      if (r.code !== 0) throw new Stop('verify', `the release gate failed: ${(r.out + r.err).split('\n').filter((l) => /^(FAIL|✗)/.test(l)).slice(0, 4).join(' | ')}`);
      return `release gate passed on ${releaseSha.slice(0, 8)}${treeEquivalent ? ' (verdicts for this tree reused where identical inputs allow)' : ''}`;
    });

    // ── tag ──────────────────────────────────────────────────────────────────────────────────────────────────────
    await phase('tag', async () => {
      const existing = sh('git', ['rev-parse', '-q', '--verify', `refs/tags/${tag}^{commit}`]);
      if (existing.code === 0 && existing.out.trim() !== releaseSha) throw new Stop('tag', `tag ${tag} already exists at a different commit`);
      if (existing.code !== 0) git(['tag', '-a', tag, '-m', version, releaseSha]);
      const p = sh('git', [...CRED, 'push', 'origin', tag], { timeoutMs: 30 * 60 * 1000, stream: true });
      if (p.code !== 0) throw new Stop('tag', `pushing the tag failed: ${(p.err || p.out).trim().slice(-300)}`);
      return `${tag} -> ${releaseSha.slice(0, 8)}`;
    });

    // ── the hosted release workflow ──────────────────────────────────────────────────────────────────────────────
    await phase('release', async () => {
      const findRun = () => { const runs = ghJson(['run', 'list', '--workflow', 'release', '--limit', '6', '--json', 'databaseId,headBranch,status,conclusion']) || []; return runs.find((r) => r.headBranch === tag) || null; };
      const started = await waitFor(findRun, { timeoutMs: 10 * 60000, intervalMs: 8000, now: ctx.now, sleep: ctx.sleep });
      if (!started.ok) throw new Stop('release', 'the release workflow did not start');
      const id = started.value.databaseId; state.set({ releaseRun: id });
      let attempts = 0;
      for (;;) {
        const done = await waitFor(() => { const r = ghJson(['run', 'view', String(id), '--json', 'status,conclusion']); return r && r.status === 'completed' ? r : null; }, { timeoutMs: o.releaseTimeoutMin * 60000, intervalMs: 15000, now: ctx.now, sleep: ctx.sleep, onTick: () => state.note('release', 'workflow running') });
        if (!done.ok) throw new Stop('release', `the release workflow did not finish in ${o.releaseTimeoutMin} min`);
        if (done.value.conclusion === 'success') return `run ${id} succeeded`;
        const jobs = (ghJson(['run', 'view', String(id), '--json', 'jobs']) || { jobs: [] }).jobs;
        const cls = classifyReleaseFailure(jobs);
        if (cls.kind === 'infra' && attempts < o.maxRetries) { attempts++; ctx.log(`  release run ${id} failed for infrastructure reasons (${cls.reason}): re-running (${attempts}/${o.maxRetries})`); state.event(`re-ran the release workflow: ${cls.reason}`); gh(['run', 'rerun', String(id), '--failed']); continue; }
        throw new Stop('release', `the release workflow failed (${cls.kind}): ${cls.reason}`);
      }
    });

    // ── npm ──────────────────────────────────────────────────────────────────────────────────────────────────────
    // The workflow's publish job already ran `npm publish --provenance` and reported success; what is left is the registry showing it, which can
    // take minutes and is not something this machine can speed up. A short wait covers the usual case. If the registry is still behind after it,
    // the release is reported as shipped with the npm check PENDING (never as verified), and `--resume` re-runs only this check.
    await phase('npm', async () => {
      let last = null;
      const probe = async () => { try { last = npmFacts(await ctx.fetchJson(`https://registry.npmjs.org/${PKG.replace('/', '%2f')}`), version); } catch { return null; } return last && last.published ? last : null; };
      const soft = o.resume ? { ok: false } : await waitFor(probe, { timeoutMs: o.npmSoftSeconds * 1000, intervalMs: 5000, now: ctx.now, sleep: ctx.sleep, onTick: () => state.note('npm', 'published by the workflow, waiting for the registry to show it') });
      if (!soft.ok && !o.resume) {
        state.set({ npmPending: true });
        return `PENDING: ${version} is not yet visible on npm after ${o.npmSoftSeconds} s (the workflow reported a successful publish; the registry is behind). Not verified. Re-check with: node scripts/ship.mjs --resume`;
      }
      const seen = soft.ok ? soft : await waitFor(probe, { timeoutMs: o.npmTimeoutMin * 60000, intervalMs: 10000, maxIntervalMs: 30000, now: ctx.now, sleep: ctx.sleep, onTick: () => state.note('npm', 'published by the workflow, waiting for the registry to show it') });
      if (!seen.ok) throw new Stop('npm', `${version} did not appear on npm within ${o.npmTimeoutMin} min (the workflow reported a successful publish: this is registry propagation, not a failed release)`);
      const f = seen.value;
      if (!f.attested) throw new Stop('npm', `${version} is on npm WITHOUT a provenance attestation`);
      state.set({ npmPending: false });
      return `${version} is on npm${f.isLatest ? ' as latest' : ` (latest is ${f.latest})`}, attested, description ${f.descriptionLength} chars, README ${f.readmeLength} chars`;
    });

    // ── hosted CI attestation of the remote closure prerequisites: EVIDENCE ONLY ────────────────────────────────
    // After the release is out, say whether hosted CI attests the GHC and NixOS prerequisites for the released commit. This never blocks,
    // fails or alters a release that already published: a refusal (a red job, a missing job, gh offline) is printed and recorded, nothing more.
    try {
      const { attestFromCi, describeAttestation } = await import('../release-attest.mjs');
      const { CLOSURE_STEPS } = await import('../release-closure.mjs');
      const res = await attestFromCi({ steps: CLOSURE_STEPS, commit: releaseSha, gh: async (args) => gh(args) });
      log(`  hosted CI attestation of the remote closure prerequisites (informational; it does not gate or undo this release): ${res.refusals.length ? 'NOT all attested' : 'all attested'}`);
      for (const l of describeAttestation(res)) log(`    ${l}`);
      state.set({ remoteAttestation: { commit: releaseSha, attested: res.attestations.map((x) => x.stepId), refused: res.refusals.map((x) => ({ stepId: x.stepId, code: x.code })) } });
    } catch (e) { log(`  hosted CI attestation could not be read (informational only; the release is unaffected): ${String(e.message || e).slice(0, 160)}`); }

    state.finish('done', true); state.set({ current: 'done', finished: ctx.now() });
    // the directory made for the gate is removed once the release is out; after a stop it is kept, so the gate's leftovers can be inspected
    if (autoTmp && ctx.removeTmpdir) ctx.removeTmpdir(autoTmp);
    return { ok: true, state: state.data };
  } catch (e) {
    const phaseName = e instanceof Stop ? e.phase : (state.data.current || 'unknown');
    state.set({ failed: { phase: phaseName, message: String(e.message || e) } });
    log(`✗ ${phaseName}: ${String(e.message || e)}`);
    return { ok: false, phase: phaseName, message: String(e.message || e), state: state.data };
  } finally {
    try { if (originalBranch && git(['branch', '--show-current']).trim() !== originalBranch) sh('git', ['checkout', originalBranch]); } catch { /* best effort */ }
  }
}

export { PHASES, ShipState };
