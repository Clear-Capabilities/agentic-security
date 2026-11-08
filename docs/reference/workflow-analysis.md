# GitHub Actions workflow analysis

A workflow file is parsed as YAML before any rule looks at it (`scanner/src/sast/workflow-flow.js`). Rules read the parsed jobs, steps, permissions and inputs, so a commented-out `permissions:` example is not a grant, and an expression's meaning depends on where it lands. Local composite actions under `.github/actions/` are analysed the same way. A file that does not parse as workflow YAML falls back to the line rules.

## What is reported

| Finding | When |
|---|---|
| Untrusted input interpolated into shell context | An attacker-controlled event field (issue or pull request title and body, comment bodies, head ref, commit messages) or a free-text dispatch or reusable-workflow input is substituted by `${{ }}` into a `run:` script, a `github-script` script or an input of an unknown action. Shell quotes do not make it data: substitution happens before the shell parses the line. A `choice` input whose declared options are plain literals is not reported. |
| Same, with an env value later evaluated as code | The value is passed through `env:` (which on its own is data, and not reported) and the script then re-parses it: `eval`, `sh -c`, `source <(echo ...)`, `Invoke-Expression`, `iex`, `pwsh -c`. |
| `pull_request_target` checks out untrusted code | A privileged `pull_request_target` job checks out the pull request head. |
| `workflow_run` consumes an artifact | A `workflow_run` job downloads an artifact built by the triggering run, which an outside pull request can control. |
| AI agent with write permissions on attacker-supplied content | An agent action runs on an untrusted trigger (issues, comments, `pull_request_target`, reviews, discussions) with write permissions. This is assessed as an agent-security scenario: prompt content, tool authority and approvals. |
| OIDC `id-token: write` | The parsed permissions grant `id-token: write`. The cloud trust policy and audience are not verifiable from the workflow alone, so this is never reported as a proven missing restriction. |

Every workflow finding names the workflow, job, step, input origin and its kind, the sensitive operation, the privilege boundary, any guards seen and the evidence still missing (`workflow`, `job`, `step`, `inputOrigin`, `inputOriginKind`, `sensitiveOperation`, `privilegeBoundary`, `guards`, `missingEvidence` in the JSON report).

## OIDC trust policy evidence

When a trust policy for the GitHub OIDC issuer is kept in the repository (Terraform, CloudFormation, a JSON policy), `scanner/src/sast/oidc-trust.js` classifies its `sub` (subject) conditions and records the result as `oidcTrust` on each OIDC finding:

| Status | Meaning | Effect |
|---|---|---|
| `restrictive` | Every subject pins one repository and a ref or environment | Severity `low`; the deployed policy still has to match the one in the repository |
| `permissive` | A wildcard repository or owner, a bare `*`, or an issuer trust statement with no subject condition | Severity `high`, needs review |
| `mismatched` | No subject pins this repository | Severity `high`, needs review: the policy found is not the one this workflow's token is checked against |
| `absent` | No policy for the issuer in the scanned files | Unchanged. The cloud account may still have one, so absence here closes nothing |

A policy that trusts this repository and others as well is not `mismatched`: one role is often shared by several repositories.

The repository's own name comes from the `origin` remote of the scanned tree when it is a GitHub URL (`https`, `git@` and `ssh://` forms). Inside GitHub Actions, scanning its own checkout (`GITHUB_WORKSPACE` is the scan root), `GITHUB_REPOSITORY` is used when there is no such remote. The finding records the source as `oidcTrust.ownRepositoryBasis`. With neither, the `mismatched` check is not made and the basis says so.

## What this does not do

- It does not read the cloud account. Repository evidence can raise an OIDC finding or support a `restrictive` reading. It never closes a finding.
- Remote actions are not fetched. An input passed to an unknown action is treated as possibly executed, and the assumption is stated.
- Reusable workflows in other repositories are not resolved.
