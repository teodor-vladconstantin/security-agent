# Autonomous PR security agent — design spec

Date: 2026-09-04
Hackathon: AWS "AI Agents for Humans" — track: **Professional Agents**
Deadline pressure: ~10 days from this date.

## Problem

SecurityAgent (this repo) already scans a codebase for secrets, vulnerable/typosquatted
dependencies, insecure code, IaC misconfig, and license risk, via 12 tools wired into a
Strands agent deployed on AWS Bedrock AgentCore. It currently only runs on demand — a human
invokes it via `agentcore invoke` and reads the response.

The hackathon brief explicitly penalizes this shape: "Instead of another app people open
and manage, the agent runs autonomously and only surfaces when there's a real decision to
make." An on-demand chat/CLI tool does not satisfy this, regardless of how capable it is.

## Who it's for

Developers and small teams who currently either skip security scanning on most PRs (no
time to run 6 separate tools manually) or bolt on a pile of separate CI scanners and ignore
the noisy output. The agent should do the judgment-heavy part — deciding what's worth a
human's attention — not just run tools.

## Solution

Trigger the existing deployed agent automatically on every pull request via a GitHub
Actions workflow. The agent clones the PR's code itself (new capability), runs its existing
`generate_security_report` tool, and decides whether the findings warrant a human decision.
If yes, it posts a PR comment. If the repo is clean, it does nothing — no comment, no
notification. This matches the brief's "runs quietly, surfaces only when it matters"
framing using the tools and deployment that already exist.

## Components

### 1. New tool: `clone_repo(url, ref=None)`

Added to `SecurityAgent/app/SecurityAgent/tools.py`, following the existing shallow-clone
pattern already used in `skills/fetcher.py` (`git clone --depth 1`, temp dir, cleanup on
failure). Returns the local path so the agent can pass it as `repo_path` to any of the
existing `scan_*` tools in a later tool call — no changes needed to those tools or to the
agent's tool-calling loop.

- Shallow clone (`--depth 1`) to a temp directory under the system temp dir.
- If `ref` is given, fetch and checkout that specific ref/SHA after the shallow clone.
- Public repos only for this hackathon scope — no credential handling. (Upgrade path: reuse
  the credential-ARN pattern from `skills/fetcher.py._build_git_auth_env` if private-repo
  support is needed later.)
- Enforce the same `_GIT_TIMEOUT`-style timeout as `skills/fetcher.py` so a hung clone can't
  hang the agent invocation indefinitely.

System prompt in `main.py` gets one new paragraph: when asked to review a PR/branch/URL,
call `clone_repo` first, then run `generate_security_report` (or specific `scan_*` tools)
against the returned path.

### 2. GitHub Actions workflow: `.github/workflows/security-agent-review.yml`

- Trigger: `pull_request` (`opened`, `synchronize`).
- Steps: setup Node, `npm i -g @aws/agentcore`, configure AWS credentials from repo secrets,
  `cd SecurityAgent && agentcore invoke --json "<prompt>"` where the prompt includes the
  PR's clone URL (`github.event.pull_request.head.repo.clone_url`) and head SHA
  (`github.event.pull_request.head.sha`), and instructs the agent to end its response with
  a literal sentinel line: `SECURITY_STATUS: CLEAN` or `SECURITY_STATUS: NEEDS_REVIEW`.
- The workflow parses that sentinel from the JSON response:
  - `NEEDS_REVIEW` → post the agent's full response as a PR comment (`gh pr comment` or
    `actions/github-script`).
  - `CLEAN` → exit with no comment, no other side effect.
- No `agentcore deploy` step — the workflow only invokes the already-deployed runtime, using
  the ARN already committed in `SecurityAgent/agentcore/.cli/deployed-state.json`.

### 3. AWS IAM

A new IAM user scoped to exactly one action, one resource:

- Action: `bedrock-agentcore:InvokeAgentRuntime`
- Resource: this project's runtime ARN only
  (`arn:aws:bedrock-agentcore:us-west-2:064188274873:runtime/SecurityAgent_SecurityAgent-pxP7SRE0di`)

Access key stored as `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` GitHub Actions secrets.

- ponytail: long-lived IAM user access keys, not GitHub OIDC federation. Faster to wire up
  within the 10-day window; OIDC (no long-lived credentials) is the upgrade path if this
  goes past the hackathon.

### 4. Demo repo target for testing

Reuse the already-discussed `demo_target/` fixture idea (fake secret, typosquatted package,
real-CVE package, weak Dockerfile, semgrep-flaggable code), committed under
`SecurityAgent/app/SecurityAgent/demo_target/` on a branch (e.g. `demo/vulnerable-pr-test`)
in this same repo, opened as a PR against `main`. A second, separate clean-branch PR (or the
same branch with the fixture reverted) proves the silent path. Using a branch in this repo
(not a second repo) avoids duplicating the GitHub secrets/workflow setup.

## Out of scope for this spec

- The Streamlit chat UI discussed earlier — demoted to optional/stretch, only pursued if
  time remains after the above and the required deliverables (video, Devpost text).
- OIDC federation, private-repo cloning, multi-tool orchestration beyond
  `generate_security_report`.
- Demo video production and Devpost text — tracked separately, not part of this code spec.

## Testing

- `clone_repo`: a small `if __name__ == "__main__"` self-check (matching the existing style
  in `tools.py`) that clones a small known-public repo to a temp dir and asserts the
  returned path exists and contains expected files, then cleans up.
- End-to-end: manually open one clean test PR and one vulnerable test PR against the demo
  fixture and confirm the workflow's two branches (silent vs. commented) both fire
  correctly. Not automated — this is a live AWS+GitHub integration test, out of scope for a
  unit test.
