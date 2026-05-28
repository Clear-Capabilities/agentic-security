// Reachability filter (FR-PREC-2).
//
// annotateReachability() in engine.js already sets f.reachable to true|false
// based on whether the finding sits in code reachable from an HTTP route. This
// module turns that signal into a precision lever: findings marked reachable=
// false are demoted to severity 'info' with f.unreachable = true.
//
// Phase 2 / Item 4 (SCA improvement plan): also demote SCA findings whose
// reachabilityTier indicates the vulnerable code is not reached by any route
// handler. Critical+manifest-only on a 500-dep transitive graph would
// otherwise drown out real reachable bugs.
//
// Disabled when scanRoot/--include-unreachable signals are present, or when
// AGENTIC_SECURITY_INCLUDE_UNREACHABLE=1 is set.

const SEVERITY_DEMOTE = {
  critical: 'medium',
  high: 'low',
  medium: 'low',
  low: 'info',
};

// SCA reachability tiers, ordered from highest urgency to lowest. A tier
// in DEMOTE_SCA_TIERS triggers severity demotion; a tier NOT in the set
// keeps full severity. route-reachable-via-function and function-reachable
// both keep full severity because the vulnerable function is provably
// called; import-reachable also keeps full severity (imported = uncertain
// but plausible). The lower three tiers get demoted.
const DEMOTE_SCA_TIERS = new Set([
  'unreachable',       // function never called from project
  'build-only',        // dev/build-time dependency only
  'manifest-only',     // declared, but no use observed
  'transitive-only',   // transitive dep, scope unclear
]);

export function demoteUnreachable(findings, opts = {}) {
  if (!Array.isArray(findings)) return;
  if (opts.includeUnreachable || process.env.AGENTIC_SECURITY_INCLUDE_UNREACHABLE === '1') return;
  // The reachability signal is only informative when the project HAS route
  // handlers. A fixture file scanned in isolation has every finding marked
  // reachable=false by annotateReachability(); demoting all of them would
  // hide real bugs the user is trying to verify.
  const haveRoutes = Array.isArray(opts.routes) ? opts.routes.length > 0 : false;
  if (!haveRoutes) return;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    if (f.unreachable) continue;
    // SCA findings: demote based on reachabilityTier instead of f.reachable
    // (the latter isn't meaningful for an SCA finding — components don't
    // have call sites in the SAST sense).
    if (f.type === 'vulnerable_dep') {
      if (!DEMOTE_SCA_TIERS.has(f.reachabilityTier)) continue;
      const beforeSca = f.severity;
      const afterSca = SEVERITY_DEMOTE[beforeSca];
      if (!afterSca || beforeSca === afterSca) continue;
      f.severity = afterSca;
      f.unreachable = true;
      f._reachabilityDemoted = beforeSca;
      f._reachabilityDemoteReason = `tier:${f.reachabilityTier}`;
      continue;
    }
    if (f.reachable !== false) continue;
    // Source has an explicit HTTP/DOM/Form/URL category → engine is confident
    // it's a user-input source even though no route was linked. Don't demote.
    if (f.source && f.source.category && /HTTP|DOM|Form|URL|Query/i.test(f.source.category)) continue;
    const before = f.severity;
    const after = SEVERITY_DEMOTE[before];
    if (!after || before === after) continue;
    f.severity = after;
    f.unreachable = true;
    f._reachabilityDemoted = before;
  }
}
