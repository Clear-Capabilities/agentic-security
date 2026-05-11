# agentic-security for vibecoders

> 🛡 Created by **[ClearCapabilities.Com](https://clearcapabilities.com)**.
> The boring copilot that catches what your AI assistant misses.

You're building an app. You don't have time to learn what CWE-79 means. You want a tool that tells you "you're good" or "fix this exact line" and shuts up otherwise.

That's this.

## 30-second quick start

```bash
# Inside your Claude Code session:
/security-setup           # install the plugin commands (one-time)
/ship                     # safe to deploy? yes/no
```

That's it. If `/ship` says ✅, you're done. If it says ❌, run `/fix 1` to apply the fix.

## What `/ship` actually shows you

When you're good:

```
─────────────────────────────────────────
  ✅  Safe to deploy
─────────────────────────────────────────
  • 0 critical · 0 high · 2 advisory
  • Run /fix 1 to apply the fix
```

When you're not:

```
─────────────────────────────────────────
  ❌  Not safe to deploy
─────────────────────────────────────────
  3 things to fix:

  1. routes/login.ts:34   SQL injection (1-line fix)
     → Apply patch automatically       /fix 1
  2. lib/auth.ts:18       JWT signed with weak secret
     → Apply patch automatically       /fix 2
  3. .env.example:5       AWS key committed
     → Remove and rotate                /fix 3
```

No CWE numbers. No CVSS scores. No taxonomy you have to learn. Just a verdict and a fix.

## The five commands you'll actually use

| Command | What it does |
|---------|--------------|
| `/ship` | Tells you if your app is safe to deploy. One verdict, one screen. |
| `/fix <n>` | Applies the fix for finding number `n` from your last `/ship`. |
| `/prereview` | After Claude wrote a PR, run this *before* you merge. Catches AI-typical bugs. |
| `/security-explain <n>` | "Why is this bad?" in plain English. Use when you're curious. |
| `/accept <n>` | "This is fine for now." Soft-suppresses a finding for 30 days. |

That's it. There are 30+ other commands. You don't need them.

## What's wrong with my AI-written code, typically?

The five things this tool catches that Claude misses most:

1. **SQL injection.** User input glued straight into a query. The single most common AI-generated bug.
2. **Hardcoded secrets.** API keys committed in `.env.example` or right in code. Caught at the moment of edit.
3. **Authorization holes.** `req.body.userId` used as the "owner check" instead of the authenticated user.
4. **JWT misuse.** Weak random secrets, missing algorithm pinning, `none` algorithm accepted.
5. **Prompt injection.** User input concatenated into the system prompt of an LLM call. AI assistants love writing this.

## License (in plain English)

Free for solo developers and teams of ≤ 10 people. If you're a bigger company shipping a product, email ross@clearcapabilities.com about a per-seat license. The full legal terms are in [LICENSE](../LICENSE) but the one-sentence version is: *don't resell this, don't reverse-engineer it, otherwise use it however you want for personal or small-team projects.*

## Sharing your security grade

```bash
agentic-security badge      # prints markdown for a README badge
```

Slaps a "Security A+" badge on your repo. People love this.

## How `/ship` is different from `/security-scan-all`

| | `/ship` | `/security-scan-all` |
|---|---|---|
| Output | One verdict, max 5 findings | Full per-finding list |
| Vocabulary | Plain English | CWE / CVSS visible |
| Threshold | High-confidence only (≥0.9) | All findings (≥0.3) |
| Length | One screen | As long as it takes |
| Best for | Daily flow | Audits, deep dives, CI |

You can always run `/ship --firehose` to see everything `/security-scan-all` would show.

## Want the full experience?

Most of what this tool does is hidden in vibecoder mode. If you want to see all the SAST/SCA/secrets capabilities, compliance attestations, threat models, supply-chain analysis, SBOM/AI-BOM generation, etc., read the [AppSec pro guide](./for-appsec-pros.md) or run:

```bash
agentic-security profile set pro
agentic-security scan
```

Be warned: you will see CVSS scores. There's no going back.

---

*🛡 agentic-security · created by [ClearCapabilities.Com](https://clearcapabilities.com)*
