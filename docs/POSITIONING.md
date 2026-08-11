# Positioning

**Referenced by `CLAUDE.md`** (`ICP focus: vibecoder-first; pro is follow-on`) but never previously written. This document assembles what the repository already states or implements about audience segmentation; it does not invent new market strategy that isn't already evidenced somewhere in the product. Where the repo has an explicit "in/out call" to make and hasn't made one, that gap is stated plainly below rather than papered over.

## The two personas, as the product already implements them

`scanner/src/posture/profile.js` is the one place this segmentation is actually encoded, not just asserted in prose. `agentic-security profile set <vibecoder|pro>` switches between two default configurations:

| Dimension | `vibecoder` (default) | `pro` |
|---|---|---|
| Confidence floor | 0.9 — only very high-confidence findings shown | 0.3 — nearly everything surfaced |
| Taxonomy in output | Hidden (no CWE/CVSS/STRIDE/OWASP/MITRE by default) | Shown |
| Severity floor | high+critical only | everything down to info |
| Command surface | `/help` shows ~5 primary commands | `/help` shows the full command set |
| Suppression model | soft (`accepted.json`, 30-day, no reviewer) | audited (`suppressions.yml`, reason + reviewer + expiry required) |
| Machine-readable output | off unless asked | SARIF + JSON every scan |
| Onboarding prompts | on | off |

This table is the one part of this document that is directly verifiable against source — re-derive it from `profile.js`'s `DEFAULTS` object if it drifts.

## What "vibecoder-first" means concretely

The scattered signals that exist:

- README's `find-and-fix-everything` command is described as *"the 'just make it safe' path for **vibecoders** (people building with an AI agent doing most of the typing)."*
- The `vibecoder` profile is the **default** — a fresh install with no `profile set` command run gets the vibecoder defaults, not the pro ones (`loadProfile()` falls back to `'vibecoder'` when no profile file exists or its value is invalid).
- The vibecoder defaults above are tuned for someone who wants a small number of high-confidence, jargon-free findings and does not want a CWE taxonomy or a SARIF file by default — someone shipping code, not someone running a security programme.

The `pro` profile's defaults (audited suppression with required reviewer + expiry, full taxonomy, machine-readable output every scan) describe a different buyer: someone operating this as part of a compliance or security-review process, for whom `docs/compliance/`, the nine bundled framework mappings, and the audit/attestation machinery in `scanner/src/posture/` are the reason to use the tool at all.

## The in/out call this document does not make

`CLAUDE.md` asks this file to state an explicit in/out call — which capabilities are in scope for the vibecoder ICP and which exist only for the pro follow-on. That call was never made anywhere in the repository: no commit, comment, or doc stakes out "feature X is out of scope for vibecoder" as a decision. Writing one now, from outside the maintainer's head, would be inventing product strategy and presenting it as settled — exactly the kind of fabrication this project's own verification discipline exists to prevent elsewhere.

What can be said honestly: the `profile.js` table above is the closest thing to a real in/out call that exists today, and it is expressed as *defaults*, not *restrictions* — every capability is reachable from either profile; the profile only changes what is shown by default and how noisy the suppression model is. If a harder in/out boundary is wanted (e.g., compliance attestation genuinely gated behind `pro`, not just hidden by default), that is a product decision for the maintainer to make and record here, not one this document should guess at.

## Reference

- `scanner/src/posture/profile.js` — the implementation.
- `docs/compliance/` — the pro-oriented compliance/attestation surface.
- `README.md` "Commands" section — where `vibecoder` is used in prose.
