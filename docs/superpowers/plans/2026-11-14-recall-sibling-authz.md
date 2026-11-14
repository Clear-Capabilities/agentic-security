# Recall sub-plan 1: handler skips the authorization check its siblings apply to the same subject

> Phase 3, Task 4 of `docs/superpowers/plans/2026-11-12-ga-gap-closure.md`. Executed inline (superpowers:executing-plans).

**Goal:** a detector that reports a request handler which takes a subject (a route parameter, a bound model, a loaded record) that its sibling handlers in the same file pass through an authorization check, and itself passes it through none.

**Input measured:** run `83df9f624d98` (engine 0.195.32), cluster `no_detector_candidate`, 131 dev-split misses. A read-only survey of the 131 fix diffs labelled the most common shape "handler missing the authorization check its sibling handlers make" (9 entries). Reading those 9 and the 9 object-level authorization entries against their `pre/` trees, 3 have the shape this rule can see inside one file: GHSA-r9r3-g9fp-3q4q (PHP, `$this->authorize` on `$maintenance` in 4 of 5 actions, not `show`), GHSA-jxpj-9j24-w337 (Java, `userPermissionValidator` on `env`/`release` in 5 handlers, not `get`), GHSA-382c-vx95-w3p5 (TypeScript, `requireContributorAccess(c, login)` in sibling routes, not the profile route). The rest need application intent, a cross-file view, or a conditional the rule does not model.

## Rulings (deviations from the parent plan)

- **Grouping.** The parent plan asks for (language, CWE) buckets of at least 5 dev entries. None exists in this cluster (largest: php CWE-639, 4). Grouped by code shape across languages instead. Cost if wrong: a rule built for 3 entries that does not generalize; the exit criterion below catches that.
- **CWE.** The finding carries CWE-285 (Improper Authorization), as `rbac-consistency.js` does for the same "no check while siblings check" claim. The rule cannot tell a missing function-level check (CWE-862) from a missing object-level one (CWE-639), and 285 is the class that states only what it observed.
- **Languages.** PHP, Java, JavaScript/TypeScript only: the languages with dev evidence. Go and Python are deferred until an entry shows the shape (the Go and Python dev entries in this cluster are different bugs).

## Design

`scanner/src/sast/authz-subject-consistency.js`, `scanAuthzSubjectConsistency(file, code)`, per file.

1. Units: handler-like functions. PHP `public function` (not `__*`); Java `public` methods (annotations above the method are part of the unit); JS/TS route callbacks `<x>.(get|post|put|patch|delete|all)('<path>', ... (c) => {` and exported/class methods.
2. Authorization guard: a call whose name is authorization-shaped (`authorize`, `*Permission*`, `*Access*`, `*Allowed*`, `can*`, `should*Hide*`, ...; never `authenticat*`), or a `@PreAuthorize`/`@Secured`/`@RolesAllowed` annotation.
3. Subject: an identifier passed to a guard, minus request/context and literal noise (`this`, `$this`, `c`, `ctx`, `req`, `request`, `user`, class constants, strings).
4. A unit is guarded on S when a guard in it (or its annotation) names S. A unit introduces S when S is one of its parameters or it assigns S.
5. Report a unit that introduces S, contains no authorization guard at all and does not delegate to a guarded sibling, when at least 3 units are guarded on S and they are at least 60% of the units that introduce S.
6. Line: the statement after the unit's assignment of a guarded subject when it has one (an object check needs the object), otherwise its first statement.

## Steps

- [x] Fixture pair `scanner/test/fixtures/authz-subject-consistency/{vulnerable,clean}/` per language, written from the general shape (a CRUD controller), not copied from an entry. Test `scanner/test/authz-subject-consistency.test.js`, failing first; add to `test:sast`.
- [x] Implement, wire into `engine.js` per-file dispatch, build.
- [x] Regression gates: `test:sast`, `test:smoke`, `bench:cve-replay:check`, `bench:mutation:check`, `bench:self-scan:check`, `bench:layer-recall:check`.
- [x] Dev re-measure: the 131 dev entries of the cluster, `runner.mjs --deep --selection=<file>`; localized recall and precision with n/d, and every new finding read by hand on `pre/` and `post/`.
- [x] Exit, checked once: score the cluster's 21 validation entries a single time. Exit when validation localized recall rises and localized precision stays at or above the floor for each language touched; otherwise record "does not generalize" and ship only if the rule is correct on its fixtures and lowers no precision.
- [ ] Ship as its own release with the before/after n/d in the changelog.

## Results (2026-11-14, engine at commit eab1e212, deep configuration)

| Split | Entries | Localized TP before | Localized TP after | Localized FP before | Localized FP after |
|---|---|---|---|---|---|
| dev (cluster) | 131 | 0 | 3 (GHSA-r9r3-g9fp-3q4q php, GHSA-jxpj-9j24-w337 java, GHSA-382c-vx95-w3p5 typescript) | 1 | 1 (the same python entry, not this rule) |
| validation (cluster, scored once) | 21 | 0 | 0 | 0 | 0 |

Unscored: 0 of 131 and 0 of 21.

**Exit verdict: does not generalize.** Validation localized recall did not move. The rule ships because it is correct on its fixtures and lowers no precision on either split. Across all 115,141 PHP/Java/JS/TS files of the 225 cached dev entries it fires at 6 distinct sites: the 3 targets, 2 Apollo read endpoints with the same omission that the upstream fix did not touch (`compareRelease`, `getBranchGrayRules`), and 1 probable false positive (Statamic `editFormBlueprint`).

Regression gates: `test:sast` 974/974, `test:smoke`, `bench:cve-replay:check`, `bench:mutation:check`, `bench:layer-recall:check` and `bench:self-scan:check` pass. The first self-scan found three nested-quantifier regexes in the new module (CWE-1333); they were rewritten, not baselined.
