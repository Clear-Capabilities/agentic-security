# Secrets — precision and recall, separately

**PRD F4.1.** Secret detection is the feature most likely to produce alert
fatigue and the one where a single bad heuristic makes the whole tool
ignorable. Before this, the entire claim rested on **three self-authored corpus
entries** and no precision number existed at all.

Precision and recall are reported separately and never combined. A single F1
would hide which half is broken, and the two halves have completely different
costs: a missed credential is one exposure, while a noisy scanner is *every*
future exposure, because nobody reads it any more.

## Results — engine 0.141.0

| | |
|---|---:|
| **format coverage** | **35/38 = 92.11%** |
| **correct silence** (hard negatives) | **28/28 = 100%** |

Still missed, deliberately: Datadog, Vercel, Algolia — see "Headroom".

## How the two halves are built, and why differently

### Recall — provider-documented formats

`formats.json` transcribes credential formats **from provider documentation**.
It is not read out of the engine's own pattern table: deriving the positive set
from `CREDENTIAL_PATTERNS` would make recall 100% by construction, which is the
defect `scripts/corpus-provenance-check.mjs` already reports about
`bench/cve-replay`.

Values are generated from a fixed seed, so a run is reproducible and no real
credential is ever committed or printed. Each is planted the way a leak actually
appears — assigned to a provider-named variable in a source file — because
several formats are only identifiable *with* nearby context, and the engine is
right to require it.

**This measures FORMAT COVERAGE.** It is not a claim about detecting real leaks
in the wild, and no ethically assemblable corpus of real leaked credentials
exists to make that claim from. Saying so is the point.

### Precision — the hard negative set

`negatives.json` is the half the PRD calls "the harder one". Every case is
high-entropy, credential-shaped, and **not** a secret:

lockfile integrity fields · git SHAs · UUIDs and ULIDs · content digests ·
inlined base64 images · SRI attributes · build-generated class names · Docker
image digests · Go module hashes · test snapshots · Terraform state lineage ids
· `.npmrc` env interpolation · an OpenAPI security scheme · **a security rule
file that defines key formats**

These appear in every real repository, thousands of instances per project. A
scanner that reports them teaches its users to ignore it.

Reported as a **correct-silence rate** rather than a precision ratio: there are
no true positives in this set for a ratio to be taken against, and dressing it
up as precision would imply a denominator that does not exist.

### The design decision this respects

The credential scanners read **raw source** — a key inside a comment is still
reported, because a comment is not a hiding place, it is where people put things
they were about to remove. That is correct and is pinned by
`test/comment-blindness.test.js`. So the negative set deliberately includes
documentation and `.env.example` cases, where the right answer is genuinely "stay
silent": a provider's own published example value and an obvious placeholder are
not credentials in any state of the world.

## What the first run found

| finding | detail |
|---|---|
| **`CRED_PREFILTER` is a whole-file gate** | A pattern whose trigger token is absent from that one regex can **never fire**, however correct the pattern is. This is the same "wired but never invoked" shape as `rate-limit.js`, `k8s-admission` and `install-script`. Any new pattern needs a prefilter token or it is dead code. |
| **No database URI shape but `jdbc:`** | `postgres://user:pass@host/db` and `mongodb+srv://…` — among the most common real leaks there are — matched nothing. The generic "Password in URL" pattern existed but could not be reached, for the prefilter reason above. |
| **GitLab, DigitalOcean, Azure Storage, Supabase, HubSpot** | absent entirely |
| **One false positive** | the JWT specimen published in the standard's own documentation. Now suppressed by **decoding the payload** and matching the documented sample subject — as narrow as the existing `AKIAIOSFODNN7EXAMPLE` rule, and verified not to suppress a real token. |
| **Duplicate reporting** | a Postgres URI matched both the new specific pattern and the generic one, reporting one secret twice. The specific name wins; it tells the reader which system to rotate. |

## What the bench itself got wrong

The first template syntax used bare `X`/`x`/`a`/`#`/`h` characters as
placeholders, which silently rewrote the **literal** text in `da2-`, `shpat_`,
`https`, `slack` and `key-`. Seven malformed values were generated and reported
as *engine* misses. Placeholders are now braced (`{H:32}`) and cannot collide.

Attributing a fixture bug to the thing under test is the specific failure this
project has paid for before, so it is recorded rather than quietly fixed.

## Headroom, and why three misses are being left alone

The bench hit **100%/100%** immediately after the first round of fixes, at which
point it could no longer fail — and a gate that cannot fail measures nothing,
which is this PRD's governing rule. Eight formats and eight negatives were added
to restore discriminating power.

Datadog, Vercel and Algolia keys are a **bare run of hex or alphanumerics with
no prefix**. They stay missed on purpose. A pattern for "32 hex characters"
would fire on every content digest, Cargo checksum, test vector and build hash
in the negative set — trading three detections for thousands of false positives,
in the feature most prone to alert fatigue. Closing this class needs
variable-name context, not another regex.

When the bench saturates again, add formats and negatives rather than declaring
victory.

## Running it

```bash
cd scanner
npm run bench:secrets-precision
```

Offline, deterministic, and under a second — so unlike `bench/sca-replay` this
one is cheap enough to be a gate. `test/secrets-coverage.test.js` pins the
findings above so they cannot silently regress.
