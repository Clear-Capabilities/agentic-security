//
// Capability matrix: what DCI supports, per language, entry-point kind and question pack, with the evidence behind each
// claim and its known limits. The words are used strictly:
//
//   verified      covered by reproducible fixture tests in this repository, for the BUILD half (resolution, bundling,
//                 integrity). It says nothing about how good a model's review is.
//   experimental  works on fixtures, narrow or unmeasured; no accuracy claim
//   unsupported   not implemented
//   blocked       cannot be done here, for a stated reason
//
// Review quality is `experimental` everywhere: there is no real-world adjudicated holdout in this repository, so no
// accuracy statement is made (see evaluation/ and docs/guides/context-intelligence.md).
const T = (f) => `test/context-intelligence/${f}`;

const BUILD = [
  { language: 'javascript/typescript', kind: 'http', frameworks: 'Express-style call registration (get/post/put/patch/delete/all, router.use, app.use)', status: 'verified', evidence: [T('build-js.test.js')], limits: 'Router mounts in another file and middleware factories are not followed (reported as router-mount-not-resolved); destructured and named imports are followed, re-exports and tsconfig path aliases are not.' },
  { language: 'python', kind: 'http', frameworks: 'decorator registration (Flask/FastAPI-style @app.route / @router.get), FastAPI Depends()/Security() guards', status: 'experimental', evidence: [T('build-python-haskell.test.js'), T('frameworks.test.js')], limits: 'Decorator guards are read from the decorator lines and Depends() guards from the signature (only dependencies named like an auth or user provider bind the principal); framework-level before_request hooks and Django URL conf are not modelled.' },
  { language: 'haskell', kind: 'http', frameworks: 'Scotty, WAI, Servant, Yesod (through the existing web model)', status: 'verified', evidence: [T('build-python-haskell.test.js'), T('frameworks.test.js')], limits: 'Static source analysis; the existing web model decides what a route is. Dynamic routes are reported unresolved.' },
  { language: 'php', kind: 'http', frameworks: 'Laravel Route:: registration (the entry point only)', status: 'experimental', evidence: ['test/engineering-excellence/e4-01-dci-audit.test.js'], limits: 'Measured by the E4-01 audit on one fixture: the routes resolve, but no control or sensitive operation was extracted from the handlers.' },
  { language: 'java/kotlin/c#/go/ruby/rust', kind: 'http', frameworks: 'whatever the engine route scan recognises', status: 'unsupported', evidence: [], limits: 'Measured by the E4-01 audit (docs/engineering-excellence/DCI_MATURITY.md) on one fixture per language (Spring, net/http, ASP.NET, Rails): no entry point was found, so no bundle is built.' },
  { language: 'any with a recognised surface', kind: 'webhook/queue/cron/upload/cli', frameworks: 'existing entry-point inventory', status: 'experimental', evidence: [T('build-js.test.js')], limits: 'Handler is the enclosing declaration of the surface; no framework wiring beyond that.' },
  { language: 'haskell', kind: 'compiler metadata import', frameworks: 'hie-export/1 JSON export of GHC declarations and references', status: 'experimental', evidence: [T('hie-adapter.test.js')], limits: 'Reads an export; never runs GHC or hiedb. The export is validated against the source snapshot. No export produced by a real GHC run is checked in.' },
  { language: 'any', kind: 'compiler metadata build', frameworks: 'automatic metadata generation', status: 'blocked', evidence: [], limits: 'Running a compiler on untrusted source needs a sandbox proof this build does not have (Template Haskell, custom Setup and plugins run code).' },
  { language: 'other semantic sources (TypeScript compiler API, Roslyn, go/packages, language servers)', kind: 'compiler metadata import', frameworks: '-', status: 'unsupported', evidence: [], limits: 'Extension point only: the graph schema carries a resolver field (source-static | compiler-enriched).' },
  { language: 'any', kind: 'provider batch API', frameworks: 'provider-hosted batch submission', status: 'blocked', evidence: [], limits: 'No provider batch contract is verified on this checkout. The offline batch files (request export, result import with hash checks) are implemented and tested.' },
];

export function capabilityMatrix() {
  const reviews = ['authz-idor', 'authz-function', 'cross-route-consistency', 'transaction-integrity', 'external-failure', 'sensitive-audit', 'business-invariant'].map(p => ({
    language: 'any bundle that builds', kind: `review: ${p}`, frameworks: 'governed single-turn model call over a frozen bundle', status: 'experimental',
    evidence: [T('review-queue.test.js'), T('queue-diff.test.js')], limits: 'Mechanics are tested with a fake provider; no accuracy measurement exists. The synthetic evaluation suite is a mechanism check, not an estimate.',
  }));
  return [...BUILD, ...reviews];
}
