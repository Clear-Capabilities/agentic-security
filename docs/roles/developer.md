# Developer

<!-- seo: title="Developer guide: what to run before merge or deploy" description="The commands a developer runs before merging or deploying AI-written code, and how to read the verdict, fix a finding and know what was verified." -->

**Primary question:** What do I run before merge or deploy?

**Core workflow:** [One finding's journey](../workflows/one-findings-journey.md)

## Run these

| When | Command | Why |
|---|---|---|
| Not sure where to start | `/agentic-security:secure` | Looks at your project and names the single best next action |
| Before you merge | `agentic-security scan .` | Findings with plain-English stakes and a fix |
| Before you deploy | `/agentic-security:setup --predeploy` | Blocks `vercel`, `fly` and `wrangler` deploys on critical findings |
| While an AI writes code | `/agentic-security:setup --bodyguard` | Intercepts insecure edits before they reach disk |
| Fix | `agentic-security fix --finding <id> --preview --root .` | Preview first; apply only through verification |
| Everything at once | `/agentic-security:find-and-fix-everything` | Scan then fix, with every patch verified |

## Read the verdict correctly

- A clean result needs two things: zero actionable findings **and** a complete scan. If the scan is `partial`, you are told "cannot confirm safe to deploy". Take that literally.
- A fix is "verified" only with the legs that ran named beside it. "Verified, but NOT fully verified" means a leg was skipped.
- A finding's severity, confidence and reachability are separate. See [the evidence model](../how-it-works/evidence-model.md).

## Read more

- [5-minute demo](../quickstart/5-minute-demo.md) and [15-minute quickstart](../quickstart/15-minute-quickstart.md)
- [Fixing vulnerabilities](../guides/fixing-vulnerabilities.md)
- [Reading a finding's evidence](../walkthroughs/finding-evidence.md)
- [Responding to a leaked secret](../guides/leaked-secrets.md)
- [Local AI with Ollama](../guides/ollama.md)
- [Haskell](../guides/haskell.md) and [Nix and NixOS](../guides/nix-nixos.md)
