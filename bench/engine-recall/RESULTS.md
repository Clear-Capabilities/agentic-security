# Engine recall gaps — before/after

Measured 2026-07-26 on branch `fix/engine-recall-gaps`.

Every number below comes from a command run in the measurement session that
produced this file. Where a figure could not be re-measured it says so.

| side | tree | bundle SHA-256 |
|---|---|---|
| before | worktree at `934f9da` (harness present, engine unfixed) | `02ce77d9cbab797335539bbd5f66443046f71cf21bbe6aa947b459cee3b23259` (built from `d017ee8`, the branch base) |
| after | branch tip + the catalog precision fix in this commit | `bfddbdd3288b84cc7851cf255d7ffb02eb872b77965f3b8974927d111869af72` |

Scan state (`.agentic-security/`) was wiped from every scanned tree immediately
before each run. Deep mode was forced with **both** `AGENTIC_SECURITY_DEEP=1`
and `AGENTIC_SECURITY_DEEP_IN_CI=1` where the harness does not set them itself.
`--deterministic` was never used (it exits 4 without scanning on a tree with no
rules lockfile); the proof-corpus runner's two determinism env vars were used
instead.

---

## 1. Recall — the two defects

`npm run bench:engine-recall`, before re-verified in a worktree at `934f9da`
this session (not quoted from `BASELINE.md`):

| probe | before | after |
|---|---|---|
| assign-sink, statement position `exec(c);` | `total=1 irTaint=1` | `total=1 irTaint=1` |
| assign-sink, assignment position `const out = exec(c);` | `total=0 irTaint=0` | **`total=1 irTaint=1`** |
| `match.type:'global'` sources reachable from `matchSource()` | `0/10` | **`10/10`** |

Language distribution of the 10 global entries is unchanged: `{"js":1,"rb":4,"php":5}`.

**Global sources are language-scoped.** Verified directly against
`matchSource({kind:'ident',name},file)`:

| name | `a.js` | `a.py` | `a.rb` | `a.php` |
|---|---|---|---|---|
| `location` | `js-location` | — | — | — |
| `params` | — | — | `rb-rails-params` | — |
| `session` | — | — | `rb-rails-session` | — |
| `ENV` | — | — | `rb-env` | — |
| `$_GET` | — | — | — | `php-get` |
| `_GET` | — | — | — | `php-get` |

Both sigil forms of the PHP superglobal resolve; no entry leaks across a
language boundary.

## 2. Corpus

`npm run bench:cve-replay:check` → **exit 0**, `199/199 baselined entries still
pass`. The two entries added for this work are present and green:

- `[deep] js-assign-sink-cmdi-shape: pre:TP post:TN`
- `[deep] php-superglobal-cmdi-shape: pre:TP post:TN`

## 3. Precision — the self-scan gate

Both directions of the gate were run this session.

| run | exit | result |
|---|---|---|
| `bench:self-scan:check` with the engine fixes and the **pre**-fix catalog | **1** | `scripts: baseline=24 now=31 ✗` |
| `bench:self-scan:check` with the engine fixes and the **post**-fix catalog | **0** | `no drift — per-file counts match BASELINE.json exactly` |

Per-file drift in the red run:

- `scripts/_compliance_lib.py`: 1 → 5 (+4)
- `scripts/owasp-llm-top10/scan.py`: 0 → 3 (+3)

### The 7 new findings, inspected individually

| # | file:line | id | verdict |
|---|---|---|---|
| 1 | `_compliance_lib.py:194` | `py-yaml-load` | false positive |
| 2 | `_compliance_lib.py:194` | `py-pickle-load` | false positive |
| 3 | `_compliance_lib.py:194` | `py-yaml-load-v2` | false positive |
| 4 | `owasp-llm-top10/scan.py:117` | `py-yaml-load` | false positive |
| 5 | `owasp-llm-top10/scan.py:117` | `py-pickle-load` | false positive |
| 6 | `owasp-llm-top10/scan.py:117` | `py-yaml-load-v2` | false positive |
| 7 | `_compliance_lib.py:194` | `multi-sink:open():6` | false positive (aggregate over 1–3) |

Both source lines are `rules = json.load(fh)`. `json.load` cannot execute code
and is not a deserialization sink under any reading; the catalog entries fired
because `py-yaml-load`, `py-pickle-load` and `py-yaml-load-v2` matched
`{type:'call', callee:'load'}` with **no receiver constraint**, and Task 2 made
assignment right-hand sides eligible for sink matching. The MULTI-SINK finding
is an aggregate that counted those three, so it disappears with them.

**Nothing was suppressed and the baseline was not regenerated.** The defect was
fixed at source in `scanner/src/dataflow/catalog.js` by pinning the five
overloaded Python deserialization entries to their own receiver — the same
`match.receiver` mechanism `py-flask-args-get` already used:

| entry | callee | receiver added |
|---|---|---|
| `py-yaml-load` | `load` | `^(?:yaml\|ruamel)$` |
| `py-yaml-load-v2` | `load` | `^(?:yaml\|ruamel)$` |
| `py-pickle-load` | `load` | `^(?:pickle\|cPickle\|_pickle\|dill\|jsonpickle)$` |
| `py-pickle-loads` | `loads` | `^(?:pickle\|cPickle\|_pickle\|dill\|jsonpickle)$` |
| `py-pickle-loads-v2` | `loads` | `^(?:pickle\|cPickle\|_pickle\|dill\|jsonpickle)$` |

The two `loads` entries were not in the seven self-scan findings; they were
included because a direct probe showed the identical defect. On a fixture with
`request.args.get()` flowing into four calls:

```
before: json.load → py-yaml-load, py-pickle-load, py-yaml-load-v2   (3 FP)
        json.loads → py-pickle-loads, py-pickle-loads-v2            (2 FP)
        yaml.load  → py-yaml-load, py-pickle-load, py-yaml-load-v2  (TP, plus 1 mismatched id)
        pickle.loads → py-pickle-loads, py-pickle-loads-v2          (TP)
after:  json.load → (none)      json.loads → (none)
        yaml.load  → py-yaml-load, py-yaml-load-v2   (TP kept)
        pickle.loads → py-pickle-loads, py-pickle-loads-v2 (TP kept)
```

Known cost of the receiver pin: an import-style `from yaml import load;
load(x)` has no receiver segment and no longer matches. That is the accepted
trade — `_receiverAllowed` returns false when the segment list is empty — and
the dotted form is the dominant shape in real code. It did not cost a single
corpus entry (199/199 still pass).

## 4. Precision — polyglot fixture

`npm run bench:polyglot`, run on both sides this session:

| | before (`934f9da`) | after |
|---|---|---|
| overall | TP=7 FP=0 FN=0 P=100% R=100% F1=100% | TP=7 FP=0 FN=0 P=100% R=100% F1=100% |
| incidental per case | 6 / 3 / 10 / 10 | 6 / 3 / 10 / 10 |

Identical on both sides. The committed `bench/polyglot/results/latest.json`
(dated 2026-05-19) records lower incidental counts (5 / 3 / 8 / 7); that
difference is present on the *before* side too, so it predates this branch and
is not attributable to either fix. `latest.json` was restored to its committed
state rather than refreshed here.

## 5. Precision — proof corpus (real third-party code)

The previously recorded reference figures (ghost/superset/godot coverage
94/100/100, findings 1124/860/145) came from bundle `4b740305…`, which is
neither of this branch's sides — the branch-base bundle is `02ce77d9…`. The
comparison is therefore **not** apples-to-apples, so both sides were
re-measured here. Godot's recorded 145 vs the 144 measured on both sides is
explained by that bundle difference, not by this branch.

Runner defaults (`--only ghost,superset,godot --no-determinism`), exit 0 on
both sides:

| target | coverage before → after | findings before → after |
|---|---|---|
| ghost (JS, 4271 files in scope) | 94% → 94% | 1124 → **1124** |
| superset (Python + JS) | 100% → 100% | 860 → **860** |
| godot (C/C++, scoped) | 100% → 100% | 144 → **144** |

Zero delta on every target. **But that alone is weak evidence**, because under
the default `AGENTIC_SECURITY_DEEP_FN_LIMIT=5000` the deep engine contributes
almost nothing to these targets (ghost's call graph alone has 28,711
functions), so the changed code path is barely exercised. Both sides were
therefore re-run with `AGENTIC_SECURITY_DEEP_FN_LIMIT=200000` and
`AGENTIC_SECURITY_DEEP_TIMEOUT_MS=900000`:

| target | total before → after | IR-TAINT before → after |
|---|---|---|
| ghost | 1128 → 1128 | 4 → 4 (`js-res-redirect` ×3, `js-fetch` ×1 — byte-identical sets) |
| superset | 863 → **860** | 3 → **0** |

The three superset IR-TAINT findings that disappeared were all at
`superset/superset/sqllab/api.py:562`:

```python
self.execute_model_schema.load(request.json)
```

a marshmallow schema `load()` — reported before the fix as `yaml.load`,
`pickle.load` and `yaml.load` (v2) deserialization. All three were false
positives, and all three were **pre-existing on the branch base** (that call is
in statement position, so it did not need Task 2 to fire). The catalog fix is a
net precision gain of 3 findings on real third-party code.

Every finding-count change measured is accounted for:

- superset 863 → 860 at raised fn-limit: the three marshmallow FPs above.
- ghost 1124 → 1128 between default and raised fn-limit (same side): the 4
  IR-TAINT findings the default 5000-function cap suppresses. Not a
  before/after delta.

## 6. Global catalog entries — bare-name disambiguation

Global entries carry no receiver/receiverBase, so in principle a local named
`location` / `params` / `session` / `ENV` could match as a source. Measured
impact rather than assumed:

- ghost, 4271 JS files in scope, raised fn-limit: IR-TAINT findings **4 before,
  4 after, identical ids**. Making `js-location` reachable produced zero new
  findings there.
- Constructed shadowing probes produced **0** IR-TAINT findings:
  - `.rb` with `params = "safe-literal"` / `session = "also-safe"` flowing to `system()`
  - `.js` with `const location = 'us-east-1'` flowing to `exec()`
  - `.rb` with method parameters literally named `params` and `session` flowing to `system()`
- The five PHP entries are superglobal names (`_GET`, `_POST`, `_REQUEST`,
  `_COOKIE`, `_SERVER`); a PHP variable with one of those names *is* the
  superglobal.
- Entries are language-scoped (matrix in §1), so a `params` in a `.py` or `.js`
  file cannot match the Rails entry.

**Verdict on this issue: negligible in practice on the evidence gathered, not
proven impossible.** The exposure is real for Ruby (`params`, `session`,
`cookies`) and JS (`location`) in code that shadows those names in a way the
engine tracks, and the corpus contains no Ruby or PHP third-party target
(discourse and nextcloud are unpinned and were refused by the runner), so no
large-scale Ruby/PHP evidence exists. Recommendation: leave as-is; if a
`receiverBase`-style disambiguator is added later, Ruby is the language to
target first, and it needs a pinned Ruby proof-corpus target to measure against.

## 7. Gate exit codes (all captured this session)

| command | exit |
|---|---|
| `npm run build` (after) | 0 |
| `npm run bench:engine-recall` | 0 |
| `npm run bench:self-scan:check` — pre-catalog-fix | **1** (gate proven to fail) |
| `npm run bench:self-scan:check` — post-catalog-fix | **0** |
| `npm run bench:cve-replay:check` | 0 (199/199) |
| `npm run bench:polyglot` | 0 |
| `npm test` | 0 — 1854 tests, 1854 pass, 0 fail |
| proof-corpus runner, before side | 0 (3 ok, 0 failed) |
| proof-corpus runner, after side | 0 (3 ok, 0 failed) |

## 8. Answers

1. **Assignment-position sinks detected?** Yes — `0/0 → 1/1`. The
   statement-position control is unchanged at `1/1`, so the extraction did not
   disturb the one path that already worked.
2. **All 10 global sources reachable, and language-scoped?** Yes — `0/10 →
   10/10`, and the per-language matrix in §1 shows no cross-language leakage;
   PHP resolves with and without the `$` sigil.
3. **Did precision hold?** Yes, and it improved. The self-scan gate is green
   with the baseline untouched; polyglot is unchanged at F1 100%; the corpus is
   199/199; ghost is byte-identical before and after; superset lost 3 findings
   and every one was a verified false positive. The seven findings that turned
   the gate red were all false positives and all were fixed at source rather
   than baselined.

## 9. What was measured vs inferred

Measured: everything in §§1–7 and the deltas in §8. Inferred: that the deep
engine's low contribution to the default-settings proof-corpus runs is caused
by the 5000-function cap — consistent with the raised-limit runs surfacing
extra IR-TAINT findings, but the cap was not instrumented directly. Not
measured: any Ruby or PHP third-party codebase at scale (no pinned target
exists), so the §6 verdict rests on constructed probes plus ghost's JS evidence.
