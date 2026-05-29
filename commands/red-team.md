---
description: Roleplay an attacker against a specific finding — step-by-step exploit narrative, adversarial variants, fuzz inputs.
argument-hint: "<finding-id> [--depth quick|deep] [--persona script-kiddie|apt|insider]"
---

# /red-team

Have Claude roleplay as an attacker against a specific finding in the current scan. Produces:

- Step-by-step exploit narrative ("here's how I'd weaponize this")
- Adversarial variants ("what bypasses might I try?")
- Fuzz inputs and PoC payloads
- Defender response evaluation ("would your current controls catch this?")

## When to use

- **Before fixing**: confirm the finding is actually exploitable before paying down the fix cost
- **For training**: show a junior developer what the attack actually looks like
- **For threat modeling**: stress-test assumptions about controls
- **Before sign-off**: validate a fix actually prevents the attack vector

## What it does NOT do

- Does not run code against real systems
- Does not execute actual exploits
- Does not bypass plugin safety guards

## Implementation

Reads the finding from `.agentic-security/last-scan.json`. Calls into the existing adversary-agent pipeline:

```js
import { runAdversaryAgent } from '@clear-capabilities/agentic-security-scanner/posture/adversary-agent.js';
const verdict = await runAdversaryAgent(finding, { depth, persona });
```

The agent reads:
- The finding's code context (`Read` tool, ±30 lines)
- The project's existing controls (auth middleware, CSP, WAF imports)
- The finding's `attackerProfile` if set by threat-model-grounding (#5)

Then narrates an attack chain end-to-end. For `--depth deep`, also pulls in the defender-agent / auditor-agent pipeline (`posture/three-agent-pipeline.js`) to surface the defender's counter-moves and the auditor's verdict.

## Usage

```bash
# Default — quick attack narrative on one finding
/red-team F-abc123

# Deep — three-agent loop (attack + defense + audit)
/red-team F-abc123 --depth deep

# Persona — adjust the attacker capabilities
/red-team F-abc123 --persona apt
```

## Output

A Markdown report under `.agentic-security/red-team/<finding-id>.md`:

```
# Red team — F-abc123 (SQL injection at src/login.js:42)

## Attacker: script-kiddie

1. Reconnaissance: noticed /login form, looked for SQLi via single-quote
2. Weaponization: `' OR 1=1 --`
3. Delivery: POSTed to /login with email='...
4. Exploitation: bypassed credential check, authenticated as user[0]
5. Post-exploit: enumerated admin schema, exfiltrated user table

## Defender response

Current controls evaluated:
- WAF rule for SQLi: ✓ blocks naive payloads
- Parameterized queries elsewhere: ✗ this endpoint missed
- Rate limit: 5/min — slows but doesn't block

## Verdict

Exploitable today. Fix: parameterized query (see canonical fix in scan).
```

## Safety

The red-team agent is sandbox-only — it narrates attacks for training and validation. It does not produce working malware, does not execute against the project's running system, and refuses any request that would weaponize PII or third-party systems.
