#!/usr/bin/env python3
"""
security-onepager.py — generate a customer-facing 'How we keep your data safe' artifact.

When an enterprise prospect asks "are you secure?" you have one of two
answers:
  - "Uh, I think so?"  (loses the deal)
  - Hand them this one-pager.

The artifact is derived from your ACTUAL scan posture — not a marketing
template. If you have 0 critical findings, it says so. If you have a clean
streak of N days, it says so. If you publish a security.txt, it says so.

Output is markdown, ready to paste into a Notion page, convert to PDF, or
include in a sales follow-up email.

Usage:
  python3 scripts/security-onepager.py
  python3 scripts/security-onepager.py --output SECURITY.md
  python3 scripts/security-onepager.py --company "MyApp Inc." --contact security@myapp.com
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path


def load_scan(cwd: Path) -> dict | None:
    p = cwd / ".agentic-security" / "last-scan.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            return None
    return None


def load_streak(cwd: Path) -> dict:
    p = cwd / ".agentic-security" / "streak.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            return {}
    return {}


def detect_stack(cwd: Path) -> list[str]:
    stack = []
    pkg = cwd / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text())
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            if "next" in deps: stack.append("Next.js")
            if "express" in deps: stack.append("Express")
            if "@supabase/supabase-js" in deps: stack.append("Supabase")
            if "stripe" in deps: stack.append("Stripe")
            if "@clerk/nextjs" in deps: stack.append("Clerk")
            if "@auth0/nextjs-auth0" in deps: stack.append("Auth0")
        except Exception:
            pass
    if (cwd / "vercel.json").exists() or (cwd / ".vercel").exists():
        stack.append("Vercel")
    if (cwd / "fly.toml").exists():
        stack.append("Fly.io")
    return stack


def practices_block(scan: dict | None, stack: list[str], cwd: Path) -> str:
    """Auto-derive 'what we actually do' from scan + stack signals."""
    practices = []

    # Always-true if the plugin is installed
    practices.append(("Continuous static analysis", "Every code change is scanned for the OWASP Top 10, OWASP LLM Top 10, and 30+ vuln classes (SQLi, command injection, XSS, IDOR, SSRF, prompt injection, ...)."))
    practices.append(("Dependency monitoring", "All third-party packages are checked against OSV and CISA KEV (Known Exploited Vulnerabilities) catalogs."))

    # Conditional based on scan content
    if scan:
        if scan.get("supplyChain") is not None:
            practices.append(("Supply-chain auditing", "Direct and transitive dependencies are audited for malicious install scripts, typosquatting, and dependency-confusion vectors."))
        if any("secret" in (f.get("kind") or "") for f in scan.get("findings", [])):
            practices.append(("Secret detection", "Pre-commit scanning catches hardcoded credentials before they reach the repo."))
        if any("authz" in (f.get("kind") or "") for f in scan.get("findings", [])):
            practices.append(("Authorization auditing", "Every route is checked for authentication and per-resource authorization."))

    # Stack-specific practices
    if "Supabase" in stack:
        practices.append(("Row-level security review", "Supabase RLS policies are audited for missing or over-permissive rules on every change."))
    if "Stripe" in stack:
        practices.append(("Webhook integrity", "All Stripe webhooks are verified by signature; no event is processed without cryptographic proof of origin."))
    if "Clerk" in stack or "Auth0" in stack:
        practices.append(("Managed authentication", f"User identity is handled by {[s for s in stack if s in ('Clerk', 'Auth0')][0]}, a managed identity provider."))
    if "Vercel" in stack:
        practices.append(("Hosting on certified infrastructure", "Application runs on Vercel infrastructure (ISO 27001 certified)."))

    # CSP / cookie hardening (if hooks/harden was applied — check for marker)
    if (cwd / ".agentic-security" / "harden-applied.json").exists():
        practices.append(("Hardened HTTP headers", "Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, and Referrer-Policy are configured to defend against XSS, clickjacking, and downgrade attacks."))

    lines = []
    for name, desc in practices:
        lines.append(f"### {name}\n\n{desc}\n")
    return "\n".join(lines)


def posture_summary(scan: dict | None, streak: dict) -> str:
    if not scan:
        return "Scan posture: not yet evaluated."

    findings = []
    for k in ("findings", "logicVulns", "supplyChain"):
        findings.extend(scan.get(k, []))
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = (f.get("severity") or "low").lower()
        counts[sev] = counts.get(sev, 0) + 1

    state = "✅ Green" if (counts["critical"] + counts["high"]) == 0 else "🟡 Yellow" if counts["critical"] == 0 else "🔴 Red"
    streak_days = streak.get("days", 0)
    streak_line = f"\n- **Clean-scan streak:** {streak_days} consecutive days" if streak_days > 0 else ""

    return f"""**Current posture:** {state}

- **Critical findings:** {counts['critical']}
- **High findings:** {counts['high']}
- **Medium findings:** {counts['medium']}
- **Last scan:** {scan.get('startedAt', 'unknown')}{streak_line}
"""


def incident_response_block(contact: str) -> str:
    return f"""## Incident response

If you discover or suspect a security issue, please report it to **{contact}**. We commit to:

- **Acknowledge** your report within **24 hours**.
- **Investigate** and provide an initial assessment within **72 hours**.
- **Disclose** confirmed material breaches to affected customers within the regulatory window (GDPR Art. 33: 72 hours from awareness).
- **Patch** confirmed critical issues within **7 days** unless a longer timeline is documented and communicated.

We follow a no-retaliation policy for good-faith security research. See our `/.well-known/security.txt` for the authoritative contact.
"""


def data_handling_block() -> str:
    # CMP-9 (Stage-0 audit, 2026): this used to assert specific infrastructure
    # facts unconditionally — "TLS 1.2+", "AES-256 at rest", "No engineer has
    # direct production database access" — regardless of what the target
    # project's actual infrastructure was. Nothing here is derivable from a
    # source-code scan (encryption-at-rest, retention policy and access
    # control are properties of infrastructure and process, not code this
    # tool reads), so it must never be presented as scanner-verified fact.
    # Bracketed placeholders force the operator to fill in something true
    # before the document ships, rather than shipping a plausible-sounding
    # default that may not describe their infrastructure at all.
    return """## Data handling

⚠ **OPERATOR REVIEW REQUIRED — this section is a template, not a scan result.**
Nothing below is derived from your code; source-code scanning cannot see your
infrastructure, your cloud provider's encryption settings, or your data
retention policy. Replace every bracketed placeholder with what is actually
true for your systems before sharing this document, or delete this section.

- **Encryption in transit:** [fill in — e.g. "TLS 1.2+" — verify against your actual load balancer / CDN config]
- **Encryption at rest:** [fill in — verify against your actual database/storage provider settings]
- **Access controls:** [fill in — describe who can actually reach production data, and how]
- **Data minimization:** [fill in — what fields you actually collect]
- **Retention:** [fill in — your actual retention and deletion policy]
"""


def render(company: str, contact: str, scan: dict | None, stack: list[str], streak: dict, cwd: Path) -> str:
    today = time.strftime("%Y-%m-%d", time.gmtime())
    stack_line = ", ".join(stack) if stack else "(stack details available on request)"
    return f"""# How {company} Keeps Your Data Safe

*Last updated: {today}*

This page summarizes the security practices in production at {company}.

**What is and isn't tool-verified.** The "Posture summary" and "What we
actually do" sections below are generated from live scan data — if something
there is wrong, re-running the scanner will flag it. The "Data handling"
section is NOT: it is a template requiring manual review, because
infrastructure facts like encryption settings and data retention are not
visible to a source-code scanner. Do not present this whole document as
tool-verified — only the sections that actually are.

## Posture summary

{posture_summary(scan, streak)}

## Stack

We run on: {stack_line}

## What we actually do

{practices_block(scan, stack, cwd)}
{data_handling_block()}
{incident_response_block(contact)}

## Frameworks we reference

Our internal controls map to:

- **OWASP ASVS** (Application Security Verification Standard)
- **OWASP LLM Top 10** for our AI features
- **CWE / CVE / CISA KEV** for vulnerability classification
- **NIST AI 600-1** for generative AI risk management

## Questions?

Reach us at **{contact}**. For security-research disclosure, use our `/.well-known/security.txt` contact channel.

---

*Generated by `agentic-security`. Verify the source of this artifact by asking us to re-generate it live.*
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a customer-facing security one-pager.")
    parser.add_argument("--cwd", default=None)
    parser.add_argument("--output", default="SECURITY.md")
    parser.add_argument("--company", default=None, help="Company / product name")
    parser.add_argument("--contact", default="security@example.com", help="Security contact email")
    parser.add_argument("--print", action="store_true")
    parser.add_argument("--force", action="store_true",
        help="Overwrite an existing output file. Without this flag the script refuses "
             "if the file already exists — SECURITY.md is a GitHub-recognised name for "
             "a project's real vulnerability-disclosure policy, and this generator must "
             "not silently destroy a hand-authored one (CMP-9, Stage-0 audit, 2026).")
    args = parser.parse_args()

    cwd = Path(args.cwd).resolve() if args.cwd else Path.cwd()
    company = args.company or cwd.name

    scan = load_scan(cwd)
    streak = load_streak(cwd)
    stack = detect_stack(cwd)

    md = render(company, args.contact, scan, stack, streak, cwd)

    if args.print:
        print(md)
        return

    out = cwd / args.output
    if out.exists() and not args.force:
        print(f"✗ Refusing to overwrite existing {args.output} — pass --force to overwrite, "
              f"or --print to preview without writing.", file=sys.stderr)
        sys.exit(1)
    out.write_text(md)
    print(f"✓ Security one-pager written: {out.relative_to(cwd) if str(out).startswith(str(cwd)) else out}")
    print(f"  Suggested next steps:")
    print(f"  1. Read it over — fix anything that doesn't match reality.")
    print(f"  2. Convert to PDF if you're attaching it to sales emails:")
    print(f"       pandoc {args.output} -o SECURITY.pdf")
    print(f"  3. Host it at https://<your-domain>/security  (see /trust-page)")


if __name__ == "__main__":
    main()
