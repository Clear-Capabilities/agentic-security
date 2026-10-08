// The release flow, as a state machine over an injected context (scripts/ship.mjs wires the real one; the tests wire a scripted one).
// Each phase starts the moment the previous one finishes: no human or agent polling sits between a green check and the next step.

import { PHASES, ShipState, chooseReleaseSha, parseChecks, classifyChecks, findStuckJobs, classifyReleaseFailure, npmFacts, preflightProblems, waitFor } from './lib.mjs';

const PKG = '@clear-capabilities/agentic-security-scanner';
const CRED = ['-c', "credential.helper=!gh auth git-credential"];
const VERSION_FILES = ['CLAUDE.md', 'README.md', '.claude-plugin/plugin.json', '.claude-plugin/marketplace.json', 'gemini-extension.json'];

class Stop extends Error { constructor(phase, message) { super(message); this.phase = phase; } }

/**
 * @param {object} ctx  sh(cmd,args,opts)->{code,out,err}; fetchJson(url); readFile(path); now(); sleep(ms); log(line); state: ShipState
 * @param {object} [opts] { branch?, maxRetries, stuckMinutes, checksTimeoutMin, releaseTimeoutMin, npmTimeoutMin, allowMissing, dryRun, tmpdir }
 */
export async function runShip(ctx, opts = {}) {
  const o = { maxRetries: 2, stuckMinutes: 40, checksTimeoutMin: 90, releaseTimeoutMin: 60, npmTimeoutMin: 90, allowMissing: ['dependency-currency'], dryRun: false, ...opts };
  const { sh, state, log } = ctx;
  const git = (args) => { const r = sh('git', args); if (r.code !== 0) throw new Error(`git ${args.join(' ')}: ${r.err.trim().slice(0, 200)}`); return r.out; };
  const gh = (args) => sh('gh', args);
  const ghJson = (args) => { const r = gh(args); if (r.code !== 0) throw new Error(`gh ${args.slice(0, 3).join(' ')}: ${r.err.trim().slice(0, 200)}`); return JSON.parse(r.out || 'null'); };
  // Resuming: a phase already done is skipped (never re-merge, never re-tag), and the facts later phases need come back from the saved state.
  const done = (name) => o.resume && state.data.phases && state.data.phases[name] && state.data.phases[name].state === 'done';
  const phase = async (name, fn) => { if (done(name)) { log(`↷ ${name} (already done)`); return state.data.phases[name].detail; } state.begin(name); log(`▶ ${name}`); try { const detail = await fn(); state.finish(name, true, detail || null); log(`✓ ${name}${detail ? ': ' + detail : ''}`); return detail; } catch (e) { state.finish(name, false, String(e.message || e)); throw e; } };

  let branch, version, prNumber, prHead, releaseSha, tag, treeEquivalent = false;
  const originalBranch = git(['branch', '--show-current']).trim();
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
      const problems = preflightProblems({ version, files, changelog: ctx.readFile('CHANGELOG.md'), npmLatest, branch, dirty });
      if (gh(['auth', 'status']).code !== 0) problems.push('gh is not authenticated');
      if (problems.length) throw new Stop('preflight', problems.join('; '));
      state.set({ branch, version, tag });
      return `${tag} from ${branch}${npmLatest ? ` (npm has ${npmLatest})` : ' (npm unreachable: not compared)'}`;
    });

    // ── push (the pre-push gate runs here; it is a control, never bypassed) ──────────────────────────────────────
    await phase('push', async () => {
      const head = git(['rev-parse', 'HEAD']).trim();
      const remote = sh('git', ['ls-remote', 'origin', `refs/heads/${branch}`]).out.split('\t')[0];
      if (remote === head) return 'already on origin';
      const r = sh('git', [...CRED, 'push', '-u', 'origin', branch], { timeoutMs: 60 * 60 * 1000, stream: true });
      if (r.code !== 0) {
        const text = `${r.err}\n${r.out}`;
        // the gate prints one `FAIL  <check>` line per failed check: name them, not just the last lines of noise
        const failed = [...new Set(text.split('\n').filter((l) => /^FAIL\s/.test(l)).map((l) => l.replace(/^FAIL\s+/, '').trim()))];
        const why = failed.length ? `failed checks: ${failed.join('; ')}` : text.trim().split('\n').slice(-6).join(' | ');
        throw new Stop('push', `git push failed (the pre-push gate or the remote refused): ${why.slice(0, 400)}`);
      }
      return `pushed ${head.slice(0, 8)}`;
    });

    // ── pull request ─────────────────────────────────────────────────────────────────────────────────────────────
    await phase('pr', async () => {
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
      prNumber = prs[0].number; prHead = prs[0].headRefOid || head;
      state.set({ pr: prNumber, prUrl: prs[0].url });
      return `#${prNumber}`;
    });

    // ── blocking checks, with automatic recovery from a hung or infrastructure-failed job ───────────────────────
    await phase('checks', async () => {
      const blocking = JSON.parse(ctx.readFile('.github/required-checks.json')).blocking;
      const retries = new Map();
      const r = await waitFor(async () => {
        const rows = parseChecks(gh(['pr', 'checks', String(prNumber)]).out);
        const c = classifyChecks(rows, blocking, { allowMissing: o.allowMissing });
        state.note('checks', `${rows.filter((x) => x.state === 'pass').length} pass, ${c.pending.length} blocking pending${c.failing.length ? `, FAILING: ${c.failing.join(', ')}` : ''}`);
        if (c.green) return { green: true };
        const runs = ghJson(['run', 'list', '--branch', branch, '--limit', '12', '--json', 'databaseId,status,conclusion,workflowName']) || [];
        for (const run of runs.filter((x) => x.status === 'in_progress' || (x.status === 'completed' && x.conclusion === 'failure'))) {
          const jobs = (ghJson(['run', 'view', String(run.databaseId), '--json', 'jobs']) || { jobs: [] }).jobs;
          const stuck = run.status === 'in_progress' ? findStuckJobs(jobs, ctx.now(), { maxMinutes: o.stuckMinutes }) : [];
          const infra = run.status === 'completed' ? classifyReleaseFailure(jobs).kind === 'infra' : false;
          if (!stuck.length && !infra) continue;
          const used = retries.get(run.databaseId) || 0;
          if (used >= o.maxRetries) throw new Stop('checks', `run ${run.databaseId} (${run.workflowName}) needed more than ${o.maxRetries} automatic re-runs`);
          retries.set(run.databaseId, used + 1);
          ctx.log(`  ${stuck.length ? `stuck: ${stuck.map((s) => `${s.name} ${s.minutes} min`).join(', ')}` : 'infrastructure failure'}: re-running ${run.workflowName} (attempt ${used + 2})`);
          state.event(`re-ran ${run.workflowName} (${stuck.length ? 'stuck job' : 'infra failure'})`);
          if (run.status === 'in_progress') { gh(['run', 'cancel', String(run.databaseId)]); await waitFor(() => (ghJson(['run', 'view', String(run.databaseId), '--json', 'status']) || {}).status === 'completed', { timeoutMs: 120000, intervalMs: 3000, now: ctx.now, sleep: ctx.sleep }); }
          gh(['run', 'rerun', String(run.databaseId), '--failed']);
        }
        if (c.failing.length) {
          // a failing blocking check that is not an infrastructure failure is a real failure: stop and say which
          const runs2 = ghJson(['run', 'list', '--branch', branch, '--limit', '12', '--json', 'databaseId,status,conclusion']) || [];
          const stillRunning = runs2.some((x) => x.status !== 'completed');
          if (!stillRunning) throw new Stop('checks', `blocking checks failed: ${c.failing.join(', ')}`);
        }
        return null;
      }, { timeoutMs: o.checksTimeoutMin * 60000, intervalMs: 15000, now: ctx.now, sleep: ctx.sleep });
      if (!r.ok) throw new Stop('checks', `blocking checks were not green after ${o.checksTimeoutMin} min`);
      return 'all blocking checks green';
    });

    if (o.dryRun) { log('dry run: stopping before the merge'); return { ok: true, dryRun: true, state: state.data }; }

    // ── merge, then decide what to release ──────────────────────────────────────────────────────────────────────
    let mergeSha = state.data.mergeSha;
    await phase('merge', async () => {
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
      const r = sh('node', ['scripts/release-check.mjs'], { stream: true, timeoutMs: 90 * 60 * 1000, env: o.tmpdir ? { TMPDIR: o.tmpdir } : {} });
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
    await phase('npm', async () => {
      let last = null;
      const seen = await waitFor(async () => { try { last = npmFacts(await ctx.fetchJson(`https://registry.npmjs.org/${PKG.replace('/', '%2f')}`), version); } catch { return null; } return last && last.published ? last : null; },
        { timeoutMs: o.npmTimeoutMin * 60000, intervalMs: 10000, maxIntervalMs: 30000, now: ctx.now, sleep: ctx.sleep, onTick: () => state.note('npm', 'published by the workflow, waiting for the registry to show it') });
      if (!seen.ok) throw new Stop('npm', `${version} did not appear on npm within ${o.npmTimeoutMin} min (the workflow reported a successful publish: this is registry propagation, not a failed release)`);
      const f = seen.value;
      if (!f.attested) throw new Stop('npm', `${version} is on npm WITHOUT a provenance attestation`);
      return `${version} is on npm${f.isLatest ? ' as latest' : ` (latest is ${f.latest})`}, attested, description ${f.descriptionLength} chars, README ${f.readmeLength} chars`;
    });

    state.finish('done', true); state.set({ current: 'done', finished: ctx.now() });
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
