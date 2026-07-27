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

### Why a receiver pin rather than a `json` deny-list

The obvious cheaper fix is to keep the bare-name match and refuse a `json`
receiver. The superset evidence in §5 rules that out: the three false positives
there are

```python
self.execute_model_schema.load(request.json)
```

a marshmallow schema whose receiver is `execute_model_schema` — a
project-specific attribute name. No deny-list of module names could have
enumerated it, and the next codebase would supply a different one. An
allow-list of the receivers that *are* deserialization modules is the only form
of the constraint that is closed rather than open-ended, which is why the fix
takes that shape.

### The accepted trade, at its true scope

The pin is an allow-list, so it drops **every** `load`/`loads` call whose
receiver is not one of the enumerated modules — not just the receiver-less
import form. Measured on a fixture where `request.args.get()` flows into each
call, run against the pre-pin tree (`2767a70`) and the post-pin tree:

| shape | IR-TAINT before → after | other layer after | net |
|---|---|---|---|
| `yaml.load(p)` (dotted) | 3 → 1 | REGEX `yaml-unsafe-load` + PY-SAST | retained (and de-duplicated) |
| `pickle.load(p)` (dotted) | 3 → 1 | REGEX `pickle-load` + PY-SAST | retained (and de-duplicated) |
| `import yaml as y; y.load(p)` | 3 → 0 | **none** | **lost at every layer** |
| `import pickle as pk; pk.load(p)` | 3 → 0 | **none** | **lost at every layer** |
| `from yaml import load; load(p)` | 3 → 0 | **none** | **lost at every layer** |
| `torch.load(p)` | 3 → 0 | REGEX `torch-load-unsafe` | still reported |
| `joblib.load(p)` | 3 → 0 | REGEX `joblib-load` | still reported |
| `np.load(p)` | 3 → 0 | none (see below) | precision gain, not a loss |

The `torch`/`joblib`/`np` rows were never intentional taint-catalog coverage —
they were collateral hits of the bare-name match. `torch` and `joblib` keep a
dedicated SAST rule (`scanner/src/sast/model-load.js`), so only the taint-layer
path is gone. `np.load` has a SAST rule that requires a literal
`allow_pickle=True` (`numpy-allow-pickle`); a plain `np.load(p)` is not RCE, so
losing the taint-layer hit there removes a finding that should not have existed.

The three genuinely-lost shapes are lost **at every layer**: verified by
scanning the fixture with the full pipeline (not just the taint engine) and
getting zero findings on those lines. The SAST backstops are all dotted-form
with a fixed module name — `scanner/src/sast/model-load.js` (`\bpickle\.`,
`\byaml\.`), `scanner/src/sast/python-sinks.js` (`\bpickle\s*\.`,
`\byaml\s*\.`), `scanner/src/sast/deserialization-gadgets.js`
(`\b(?:pickle|cPickle|dill|marshal)\s*\.`) — so none of them can see an alias.

Not a regression, for the record: `from yaml import load as yload; yload(p)`
produced **zero** findings on the pre-pin tree too. The alias renames the callee
itself, so bare-name matching never covered it either. That gap is unchanged by
this work.

The pin cost no corpus entry (199/199 still pass), and no test in the suite
(1854/1854 pass).

**How common is the dotted form?** Counted on the two pinned proof-corpus
targets already on disk: superset has 5 dotted `yaml.load`/`pickle.load(s)`
call sites, 0 `import yaml/pickle as …` aliases and 0
`from yaml/pickle import load` imports; ghost has 0 of all three (it has no
Python). That is 5/5 dotted on the only Python target available — supporting,
but n=5 on one repository. The broader claim that the dotted form dominates
Python generally is a **judgement, not a finding**; it is not measured here and
should not be read as one.

### Regression guard for the shape given up — attempted, not added

A `pre:TP post:TN` corpus entry for the aliased form would make this trade
auditable. It was attempted and it **cannot pass**, which is the honest
outcome, so no entry was added and `bench/cve-replay/corpus-baseline.json` is
untouched at 199 entries.

Candidate `pre/` tree — a Flask route taking `request.args.get("cfg")` into
`y.load(blob)` after `import yaml as y` — scanned with the committed bundle in
deep mode:

```
findings 0    (CLI exit 0)
```

Zero findings means the entry would score `pre:TN`, not `pre:TP`, so adding it
would either fail the corpus gate or require weakening the fixture until it
tested something else. Per the corpus contract (never add an entry that does
not genuinely score `pre:TP post:TN`), it is recorded here instead:

> **Known uncovered shape.** Tainted data reaching an *aliased* or
> *bare-imported* Python deserialization call — `import yaml as y; y.load(x)`,
> `import pickle as pk; pk.load(x)`, `from yaml import load; load(x)` — is
> detected by no layer of this scanner. The taint catalog's receiver pin
> excludes it by construction; every SAST backstop is dotted-form with a
> fixed module name. Closing it needs import-alias resolution in the Python IR
> (resolving `y` → `yaml` at the call site) so the receiver constraint can be
> evaluated against the *resolved* module rather than the written identifier.
> That is the correct fix and it is out of scope here.

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
   than baselined. The fix is not free: it gives up taint-layer detection of
   aliased and bare-imported Python `load`/`loads` calls, three shapes that no
   other layer covers — see §3 for the measured scope and the recorded gap.

## 9. What was measured vs inferred

Measured: everything in §§1–7 and the deltas in §8, including every row of the
§3 trade table (each scanned on both the pre-pin tree `2767a70` and the
post-pin tree, full pipeline, not just the taint engine) and the zero-finding
result for the candidate corpus entry.

Inferred: that the deep engine's low contribution to the default-settings
proof-corpus runs is caused by the 5000-function cap — consistent with the
raised-limit runs surfacing extra IR-TAINT findings, but the cap was not
instrumented directly.

Judgement, explicitly not a finding: that the dotted `yaml.load` /
`pickle.load` form dominates Python code generally. The only measurement behind
it is 5 dotted call sites and 0 aliased/bare-import sites on superset (§3), the
sole Python target on disk.

Not measured: any Ruby or PHP third-party codebase at scale (no pinned target
exists), so the §6 verdict rests on constructed probes plus ghost's JS evidence.

---

## Appendix A — revision 1 (2026-07-26)

Revision 1 corrects a disclosure defect in this document. No engine behaviour
changed; `scanner/src/` was not touched, so the bundle is unchanged.

**What was wrong.** The first revision disclosed the cost of the receiver pin
as only the receiver-less import form (`from yaml import load; load(x)`). The
pin is an allow-list, so its real cost is every `load`/`loads` call whose
receiver is not an enumerated module — including aliased imports
(`import yaml as y; y.load(x)`) and the incidental `torch`/`joblib`/`np`
coverage the bare-name match used to provide. It also justified the design as
an "accepted trade" without using the superset marshmallow evidence that
actually rules out the cheaper alternative, and it asserted that the dotted
form dominates real code with no run behind the claim.

**What changed in §3.**

- Added *Why a receiver pin rather than a `json` deny-list*, grounded in the
  measured `self.execute_model_schema.load(request.json)` false positive: a
  project-specific receiver name that no deny-list could enumerate.
- Replaced the one-line cost statement with a measured eight-row table, each
  row scanned through the full pipeline on both the pre-pin tree (`2767a70`)
  and the post-pin tree. Three shapes are lost at **every** layer (aliased
  yaml, aliased pickle, bare-imported yaml); `torch`/`joblib` keep their SAST
  rules; `np.load` without `allow_pickle=True` was never a real sink, so
  dropping it is a precision gain.
- Recorded that `from yaml import load as yload; yload(x)` scored zero on the
  pre-pin tree as well — a pre-existing gap, not a regression from this work.
- Added the corpus-guard outcome: a `pre:TP` entry for the aliased shape was
  attempted and **cannot pass** (candidate tree scores zero findings, CLI exit
  0), so no entry was added, the baseline stays at 199, and the uncovered
  shape is recorded in prose with the fix it would need (import-alias
  resolution in the Python IR).
- Labelled the dotted-form-dominance claim a judgement, and gave the only
  measurement behind it (superset: 5 dotted, 0 aliased, 0 bare-import; ghost:
  no Python).

**Gates re-run for revision 1** — exit codes captured standalone, each from a
run in the revision-1 session:

| command | exit |
|---|---|
| `npm test` | 0 — 1854 tests, 1854 pass, 0 fail |
| `npm run bench:cve-replay:check` | 0 — 199/199, baseline untouched |
| `npm run bench:self-scan:check` | 0 — no drift, `BASELINE.json` untouched |
