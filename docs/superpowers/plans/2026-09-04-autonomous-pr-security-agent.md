# Autonomous PR Security Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the deployed SecurityAgent trigger automatically on every GitHub pull request, clone and scan the PR's own code, and only post a comment when it finds something CRITICAL/HIGH — staying silent otherwise — satisfying the hackathon's "runs autonomously, surfaces only when there's a real decision" requirement.

**Architecture:** One new tool (`clone_repo`) lets the existing Strands agent fetch arbitrary PR code at invocation time instead of only scanning what's baked into its container image. A GitHub Actions workflow invokes the already-deployed AgentCore runtime (via the `agentcore` CLI, using a narrowly-scoped IAM user) on every `pull_request` event, and posts the agent's response as a PR comment only when the agent's own sentinel line says review is needed.

**Tech Stack:** Python (Strands `@tool`, subprocess + git CLI — no new Python dependencies), GitHub Actions (`@aws/agentcore` npm CLI, `aws-actions/configure-aws-credentials`, `gh pr comment`), AWS IAM (scoped user + inline policy).

## Status (as of 2026-09-04)

- Tasks 1-6: **done**, each independently verified (tool self-check passes, `main.py` imports cleanly, deploy succeeded with the same runtime ARN, IAM policy confirmed via a real `agentcore invoke` call that got past `AccessDeniedException`, workflow YAML validated). All pushed to `main`.
- Task 7 (open the real demo PR, confirm a comment appears on the vulnerable one and silence on the clean one): **blocked**, not started. The account's Bedrock quota is stuck at 0 (`ThrottlingException: Too many tokens per day` on every call, even for authorized/entitled models — matches a known "bedrock-mantle endpoint" issue reported on AWS re:Post). An AWS Support "service limit increase" case was opened for this; this account only has Basic support, so there's no guaranteed response SLA. **Resume Task 7 as soon as a plain `agentcore invoke --json "say hi"` from `SecurityAgent/` stops returning a `ThrottlingException`.**
- Also still open, not part of this plan: the hackathon demo video (its centerpiece scene *is* Task 7, so it's blocked on the same thing), the Devpost text description, and the empty GitHub repo description field.

## Global Constraints

- Reuse the existing shallow-clone pattern from `SecurityAgent/app/SecurityAgent/skills/fetcher.py` (`git clone --depth 1`, temp dir, cleanup on failure) rather than inventing a new one.
- Follow the existing `tools.py` self-check style (`if __name__ == "__main__":` with `assert`, no pytest) for the new tool's test.
- No new Python dependencies — `subprocess`, `shutil`, `tempfile`, `pathlib.Path` are all stdlib.
- No `agentcore deploy` inside the GitHub Actions workflow — it only invokes the runtime that Task 3 deploys ahead of time.
- Long-lived IAM access keys as GitHub secrets for this hackathon window (not OIDC) — explicitly the ponytail-lazy choice per the approved spec; OIDC is a noted upgrade, not built now.
- Runtime ARN (fixed for this project): `arn:aws:bedrock-agentcore:us-west-2:064188274873:runtime/SecurityAgent_SecurityAgent-pxP7SRE0di`
- GitHub repo: `teodor-vladconstantin/security-agent`
- AWS region: `us-west-2`
- `agentcore` npm package version actually installed and verified this session: `@aws/agentcore@0.28.1` — pin this exact version in CI, don't float `@latest`.
- Any fake secret used in demo fixtures must use a generic, non-vendor-shaped format (e.g. a bare high-entropy string under a generic variable name) — a Stripe/AWS/GitHub-shaped fake key trips GitHub's own push-protection secret scanning and blocks the push outright, even though it's synthetic and gitleaks' generic-api-key rule catches the generic form just as reliably (verified live this session).

---

### Task 1: Add `clone_repo` tool to `tools.py`

**Files:**
- Modify: `SecurityAgent/app/SecurityAgent/tools.py:1-11` (imports)
- Modify: `SecurityAgent/app/SecurityAgent/tools.py` (add tool near the top, after the existing `scan_dependencies` tool and before the `POPULAR_PYPI` block, so it's grouped with the other "entry point" tools)
- Modify: `SecurityAgent/app/SecurityAgent/tools.py` (bottom `if __name__ == "__main__":` self-check block)

**Interfaces:**
- Produces: `clone_repo(url: str, ref: str = "") -> str` — a Strands `@tool`. On success returns the local filesystem path (plain string, no JSON) to the shallow-cloned repo, suitable for passing as the `repo_path` argument to any `scan_*` tool or `generate_security_report`. On failure returns a string starting with `"Error:"`.
- Consumes: nothing from other tasks.

- [ ] **Step 1: Add the new imports**

In `SecurityAgent/app/SecurityAgent/tools.py`, the file currently starts:

```python
import subprocess
import json
import os
import re
import time
import difflib
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from strands import tool
```

Change it to:

```python
import subprocess
import json
import os
import re
import shutil
import tempfile
import time
import difflib
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from strands import tool
```

- [ ] **Step 2: Add the `clone_repo` tool**

Immediately after the existing `scan_dependencies` tool (right before the `# Top ~200 most popular PyPI packages...` comment block that starts the `POPULAR_PYPI` section), insert:

```python
_CLONE_TIMEOUT = 60


def _clone_git_repo(url: str, ref: str = "") -> Path:
    """Shallow-clone a git repo (and optionally a specific ref/SHA) to a
    fresh temp dir. Mirrors the shallow-clone pattern in
    skills/fetcher.py._fetch_git_skill, minus skill-specific caching/
    credential handling - every PR review is a one-off, so this always
    clones fresh rather than caching by source hash."""
    dest = Path(tempfile.mkdtemp(prefix="secagent-clone-"))
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, str(dest)],
            check=True, timeout=_CLONE_TIMEOUT, capture_output=True, text=True,
        )
        if ref:
            subprocess.run(
                ["git", "fetch", "--depth", "1", "origin", ref],
                check=True, timeout=_CLONE_TIMEOUT, capture_output=True, text=True, cwd=str(dest),
            )
            subprocess.run(
                ["git", "checkout", "FETCH_HEAD"],
                check=True, timeout=_CLONE_TIMEOUT, capture_output=True, text=True, cwd=str(dest),
            )
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    return dest


@tool
def clone_repo(url: str, ref: str = "") -> str:
    """
    Shallow-clones a public git repository (optionally at a specific branch,
    tag, or commit SHA) to a local temp directory and returns that path.
    Use this first when asked to review a pull request, branch, or external
    repository URL - pass the returned path as repo_path to any of the
    scan_* tools or generate_security_report afterward. Public repos only
    (no credential handling).

    Args:
        url: HTTPS clone URL of the repository (e.g. a PR's head repo URL).
        ref: Optional branch name, tag, or commit SHA to check out after
              cloning (e.g. a PR's head SHA). Defaults to the repo's
              default branch.
    """
    try:
        path = _clone_git_repo(url, ref)
    except subprocess.TimeoutExpired:
        return f"Error: cloning '{url}' timed out after {_CLONE_TIMEOUT}s."
    except subprocess.CalledProcessError as e:
        return f"Error: failed to clone '{url}' (ref={ref or 'default'}): {e.stderr.strip()}"
    return str(path)
```

- [ ] **Step 3: Add the self-check block**

At the bottom of `tools.py`, inside the existing `if __name__ == "__main__":` block, immediately before the final `print("tools.py self-check OK")` line, insert:

```python
    cloned = clone_repo("https://github.com/octocat/Hello-World.git")
    assert os.path.isdir(cloned), cloned
    assert os.path.isfile(os.path.join(cloned, "README")), os.listdir(cloned)
    shutil.rmtree(cloned, ignore_errors=True)

    cloned_ref = clone_repo("https://github.com/octocat/Hello-World.git", ref="test")
    assert os.path.isdir(cloned_ref), cloned_ref
    shutil.rmtree(cloned_ref, ignore_errors=True)

    bad = clone_repo("https://github.com/octocat/definitely-not-a-real-repo-xyz123.git")
    assert bad.startswith("Error:"), bad
```

- [ ] **Step 4: Run the self-check**

```bash
cd SecurityAgent/app/SecurityAgent
./.venv/Scripts/python.exe tools.py
```

Expected output: `tools.py self-check OK` (this also re-runs every pre-existing assertion in the file, not just the new ones).

- [ ] **Step 5: Commit**

```bash
git add SecurityAgent/app/SecurityAgent/tools.py
git commit -m "Add clone_repo tool so the agent can fetch PR code to scan

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Tsj7XdnivQEKsQZQLFsFAj"
```

---

### Task 2: Wire `clone_repo` into the agent (`main.py`)

**Files:**
- Modify: `SecurityAgent/app/SecurityAgent/main.py:9-22` (tool import list)
- Modify: `SecurityAgent/app/SecurityAgent/main.py:30-109` (`DEFAULT_SYSTEM_PROMPT`)
- Modify: `SecurityAgent/app/SecurityAgent/main.py:117-129` (`tools.append(...)` list)

**Interfaces:**
- Consumes: `clone_repo` from `tools.py` (Task 1).
- Produces: nothing new — this task only registers an existing tool and extends the system prompt's instructions.

- [ ] **Step 1: Add `clone_repo` to the tool import list**

In `SecurityAgent/app/SecurityAgent/main.py`, change:

```python
from tools import (
    scan_for_secrets,
    scan_dependencies,
    scan_typosquatting,
    scan_code_vulnerabilities,
    scan_oss_vulnerabilities,
    scan_iac_misconfig,
    scan_git_history_secrets,
    generate_sbom,
    scan_licenses,
    scan_container_image,
    scan_dependency_confusion,
    generate_security_report,
)
```

to:

```python
from tools import (
    scan_for_secrets,
    scan_dependencies,
    scan_typosquatting,
    scan_code_vulnerabilities,
    scan_oss_vulnerabilities,
    scan_iac_misconfig,
    scan_git_history_secrets,
    generate_sbom,
    scan_licenses,
    scan_container_image,
    scan_dependency_confusion,
    generate_security_report,
    clone_repo,
)
```

- [ ] **Step 2: Register the tool**

Change:

```python
tools.append(scan_for_secrets)
tools.append(scan_dependencies)
tools.append(scan_typosquatting)
tools.append(scan_code_vulnerabilities)
tools.append(scan_oss_vulnerabilities)
tools.append(scan_iac_misconfig)
tools.append(scan_git_history_secrets)
tools.append(generate_sbom)
tools.append(scan_licenses)
tools.append(scan_container_image)
tools.append(scan_dependency_confusion)
tools.append(generate_security_report)
```

to:

```python
tools.append(scan_for_secrets)
tools.append(scan_dependencies)
tools.append(scan_typosquatting)
tools.append(scan_code_vulnerabilities)
tools.append(scan_oss_vulnerabilities)
tools.append(scan_iac_misconfig)
tools.append(scan_git_history_secrets)
tools.append(generate_sbom)
tools.append(scan_licenses)
tools.append(scan_container_image)
tools.append(scan_dependency_confusion)
tools.append(generate_security_report)
tools.append(clone_repo)
```

- [ ] **Step 3: Update the system prompt intro line**

Change the first paragraph of `DEFAULT_SYSTEM_PROMPT` from:

```python
DEFAULT_SYSTEM_PROMPT = """
You are a security assistant. When asked to check a repository, use
scan_for_secrets, scan_dependencies, scan_typosquatting,
scan_code_vulnerabilities, scan_oss_vulnerabilities, scan_iac_misconfig,
scan_git_history_secrets, generate_sbom, scan_licenses,
scan_container_image, scan_dependency_confusion, and
generate_security_report as needed. Flag anything that looks like a real,
```

to:

```python
DEFAULT_SYSTEM_PROMPT = """
You are a security assistant. When asked to check a repository, use
scan_for_secrets, scan_dependencies, scan_typosquatting,
scan_code_vulnerabilities, scan_oss_vulnerabilities, scan_iac_misconfig,
scan_git_history_secrets, generate_sbom, scan_licenses,
scan_container_image, scan_dependency_confusion, clone_repo, and
generate_security_report as needed. Flag anything that looks like a real,
```

- [ ] **Step 4: Add a `clone_repo` usage paragraph and the CI sentinel-output instructions**

Immediately before the closing `"""` of `DEFAULT_SYSTEM_PROMPT` (right after the existing `generate_security_report` paragraph, which ends `...mention it takes noticeably longer than any single tool since it runs all of them in sequence.`), insert two new paragraphs:

```python

clone_repo shallow-clones a public git repository (optionally at a given
branch/tag/commit SHA) to a local path and returns that path. Use this
FIRST whenever asked to review a pull request, branch, or external
repository URL rather than "this repository" - then pass the returned
path as repo_path to generate_security_report or the individual scan_*
tools. Do not guess at findings without actually cloning and scanning.

When a request explicitly asks you to act as an automated CI check and to
end your response with a SECURITY_STATUS line, finish your entire
response with exactly one such line, after your normal summary: emit
"SECURITY_STATUS: NEEDS_REVIEW" if generate_security_report's "_summary"
shows any CRITICAL or HIGH count greater than zero, or
"SECURITY_STATUS: CLEAN" otherwise. Never add this line unless the
request explicitly asked for it.
"""
```

(The trailing `"""` above is the same one that already closes the string — you're inserting text before it, not adding a second closing triple-quote.)

- [ ] **Step 5: Verify the module still imports cleanly**

```bash
cd SecurityAgent/app/SecurityAgent
./.venv/Scripts/python.exe -c "import main; print('main import OK')"
```

Expected output: `main import OK`

- [ ] **Step 6: Commit**

```bash
git add SecurityAgent/app/SecurityAgent/main.py
git commit -m "Register clone_repo tool and teach the agent CI sentinel output

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Tsj7XdnivQEKsQZQLFsFAj"
```

---

### Task 3: Redeploy and smoke-test `clone_repo` on the live runtime

**Files:** none (deployment + verification only, no new files)

**Interfaces:**
- Consumes: the Task 1+2 changes, already committed.
- Produces: a live deployment where `clone_repo` is available to the agent — required before Task 7's end-to-end PR test can work.

- [ ] **Step 1: Preview the deploy diff**

```bash
cd SecurityAgent
agentcore deploy --diff --json
```

Expected: only the `ContainerImageBuilder`/`ContainerBuildTrigger` custom resource shows as changed (new source hash), same shape as the prior two deploys this session. If anything else shows as changed (IAM, networking), stop and investigate before proceeding.

- [ ] **Step 2: Deploy**

```bash
agentcore deploy -y --json
```

Expected: `"success":true` in the JSON output, same `runtimeArn` as before (`arn:aws:bedrock-agentcore:us-west-2:064188274873:runtime/SecurityAgent_SecurityAgent-pxP7SRE0di` — in-place update, not a replacement).

- [ ] **Step 3: Smoke-test `clone_repo` end-to-end through the deployed agent**

```bash
agentcore invoke --json "Clone https://github.com/octocat/Hello-World.git and tell me what files are in it."
```

Expected: the JSON response's `"response"` field mentions a `README` file (proving the agent actually called `clone_repo` and inspected the result, not just answered from training data). If Bedrock is still throttled (`ThrottlingException` in the response, a known risk noted in the spec), wait and retry later rather than treating it as a code failure — do not proceed to Task 7 without a clean response here first.

---

### Task 4: Create the demo vulnerable-PR fixture branch

**Files:**
- Create (on a new branch `demo/vulnerable-pr-test`, not `main`): `requirements.txt`, `Dockerfile`, `demo-fixture-config.py`, `demo-fixture-app.py` — all at the repo root.

**Interfaces:**
- Consumes: nothing.
- Produces: a pushed branch that Task 7 opens a PR from. These files are deliberately kept off `main` so they never get baked into the production container image.

- [ ] **Step 1: Create and switch to the branch**

```bash
git checkout -b demo/vulnerable-pr-test
```

- [ ] **Step 2: Add the fixture files**

`requirements.txt`:

```
reqeusts==2.31.0
pyyaml==5.3
```

(`reqeusts` doesn't exist on PyPI — triggers `scan_typosquatting`'s CRITICAL path. `pyyaml==5.3` has a real, verified vulnerability — GHSA-6757-jp84-gxfx / CVE-2020-1747, CRITICAL — triggers `scan_oss_vulnerabilities`.)

`Dockerfile`:

```dockerfile
FROM python:3.6

COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt

ENV DEMO_API_TOKEN=7f3a9c2e8b1d4f6a0e5c9b3d7f2a8e4c6b0d3f9a1e5c7b2d4f8a0e6c3b9d1f5a

CMD ["python", "demo-fixture-app.py"]
```

(EOL base image, no `USER` directive, secret baked into `ENV` — triggers `scan_iac_misconfig` via trivy's built-in Dockerfile checks, and `scan_container_image` will find real CVEs in the ancient `python:3.6` base image. Uses a generic, non-vendor-shaped fake token rather than a Stripe/AWS/GitHub-formatted one — see Global Constraints on why: a realistic vendor-shaped key trips GitHub's own push-protection secret scanning and blocks the push, even for a synthetic value.)

`demo-fixture-config.py`:

```python
"""Demo fixture for SecurityAgent's hackathon PR-review demo - intentionally
insecure, not a real credential. Lives only on the demo/vulnerable-pr-test
branch, never merged to main."""

DEMO_API_TOKEN = "7f3a9c2e8b1d4f6a0e5c9b3d7f2a8e4c6b0d3f9a1e5c7b2d4f8a0e6c3b9d1f5a"
```

(Triggers `scan_for_secrets` — gitleaks' `generic-api-key` rule, verified live this session to fire on this exact generic token format without tripping GitHub push protection.)

`demo-fixture-app.py`:

```python
"""Demo fixture for SecurityAgent's hackathon PR-review demo - intentionally
vulnerable, not real application code."""

import subprocess
import sys


def run_backup(filename):
    subprocess.run(f"tar -czf backup.tar.gz {filename}", shell=True)


if __name__ == "__main__":
    run_backup(sys.argv[1])
```

(Unsanitized input into `shell=True` — triggers `scan_code_vulnerabilities` via Semgrep's `p/security-audit` ruleset.)

- [ ] **Step 3: Commit and push the branch**

```bash
git add requirements.txt Dockerfile demo-fixture-config.py demo-fixture-app.py
git commit -m "Add intentionally vulnerable fixtures for the PR-review demo

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Tsj7XdnivQEKsQZQLFsFAj"
git push -u origin demo/vulnerable-pr-test
```

- [ ] **Step 4: Switch back to `main`**

```bash
git checkout main
```

(Don't open the PR yet — that's Task 7, after the workflow and IAM are wired up.)

---

### Task 5: Create a scoped IAM user for the CI workflow

**⚠️ This task creates a real AWS IAM user and access key. Confirm with the user before running the `create-access-key` step — a leaked or over-broad key is a real credential exposure, not a reversible local edit.**

**Files:**
- Create (local, temporary, gitignored-by-default temp path — do not commit): a policy JSON file used only as input to `aws iam put-user-policy`.

**Interfaces:**
- Consumes: the runtime ARN (`arn:aws:bedrock-agentcore:us-west-2:064188274873:runtime/SecurityAgent_SecurityAgent-pxP7SRE0di`).
- Produces: two GitHub Actions secrets, `SECURITY_AGENT_AWS_ACCESS_KEY_ID` and `SECURITY_AGENT_AWS_SECRET_ACCESS_KEY`, that Task 6's workflow consumes by exact name.

- [ ] **Step 1: Create the IAM user**

```bash
aws iam create-user --user-name security-agent-ci-invoker
```

Expected: JSON output with `"UserName": "security-agent-ci-invoker"`.

- [ ] **Step 2: Write the scoped policy document**

Write to a scratchpad path (not inside the repo):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "bedrock-agentcore:InvokeAgentRuntime",
      "Resource": "arn:aws:bedrock-agentcore:us-west-2:064188274873:runtime/SecurityAgent_SecurityAgent-pxP7SRE0di"
    }
  ]
}
```

- [ ] **Step 3: Attach the policy**

```bash
aws iam put-user-policy \
  --user-name security-agent-ci-invoker \
  --policy-name InvokeSecurityAgentRuntime \
  --policy-document file:///path/to/the/policy.json
```

- [ ] **Step 4: Create the access key**

```bash
aws iam create-access-key --user-name security-agent-ci-invoker
```

Expected: JSON with `AccessKeyId` and `SecretAccessKey`. Copy both immediately — the secret is shown only once.

- [ ] **Step 5: Store both as GitHub Actions secrets**

```bash
gh secret set SECURITY_AGENT_AWS_ACCESS_KEY_ID --body "<AccessKeyId from step 4>"
gh secret set SECURITY_AGENT_AWS_SECRET_ACCESS_KEY --body "<SecretAccessKey from step 4>"
```

Verify:

```bash
gh secret list
```

Expected: both `SECURITY_AGENT_AWS_ACCESS_KEY_ID` and `SECURITY_AGENT_AWS_SECRET_ACCESS_KEY` listed.

- [ ] **Step 6: Sanity-check the policy actually authorizes the call**

Using the new key's values as temporary env vars (don't hardcode them anywhere in the repo):

```bash
AWS_ACCESS_KEY_ID="<AccessKeyId>" AWS_SECRET_ACCESS_KEY="<SecretAccessKey>" AWS_DEFAULT_REGION=us-west-2 \
  aws bedrock-agentcore invoke-agent-runtime \
  --agent-runtime-arn arn:aws:bedrock-agentcore:us-west-2:064188274873:runtime/SecurityAgent_SecurityAgent-pxP7SRE0di \
  --payload '{"prompt":"say hi"}' \
  /tmp/iam-check-output.json
```

Expected: no `AccessDeniedException`. If you get one naming a missing action/resource (e.g. it wants a `runtime-endpoint` sub-resource too), broaden the policy's `Resource` to `arn:aws:bedrock-agentcore:us-west-2:064188274873:runtime/SecurityAgent_SecurityAgent-pxP7SRE0di*` (trailing wildcard) and re-run `put-user-policy`, then retry this step. A `ThrottlingException` here is fine — it proves the IAM policy authorized the call; only an `AccessDeniedException` means the policy is wrong.

**Verified this session:** the bare `aws bedrock-agentcore invoke-agent-runtime` CLI call is not a reliable sanity check on this account — it hung/timed out client-side (`Read timeout on endpoint URL: "None"`) even after IAM was correctly scoped, independent of authorization. Use the actual `agentcore invoke --json "say hi"` CLI (run from `SecurityAgent/`, with the same temporary env vars) instead — it's what Task 6 actually uses. It also surfaced a second required action: the `agentcore` CLI sends an `X-Amzn-Bedrock-AgentCore-Runtime-User-Id` header, which AWS requires both `bedrock-agentcore:InvokeAgentRuntime` **and** `bedrock-agentcore:InvokeAgentRuntimeForUser` to be granted for. The policy in Step 2 above should list both actions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock-agentcore:InvokeAgentRuntime",
        "bedrock-agentcore:InvokeAgentRuntimeForUser"
      ],
      "Resource": "arn:aws:bedrock-agentcore:us-west-2:064188274873:runtime/SecurityAgent_SecurityAgent-pxP7SRE0di*"
    }
  ]
}
```

A `ThrottlingException` in the `agentcore invoke` response (rather than an `"error"` field naming `AccessDeniedException`) confirms the policy is correct.

---

### Task 6: Add the GitHub Actions workflow

**Files:**
- Create: `.github/workflows/security-agent-review.yml`

**Interfaces:**
- Consumes: `SECURITY_AGENT_AWS_ACCESS_KEY_ID` / `SECURITY_AGENT_AWS_SECRET_ACCESS_KEY` secrets (Task 5), the `agentcore invoke --json` CLI contract (JSON with a `.response` string field, verified this session), and the `SECURITY_STATUS: NEEDS_REVIEW` / `SECURITY_STATUS: CLEAN` sentinel the system prompt now emits (Task 2).
- Produces: on `pull_request` events, either a PR comment (when the agent found something) or no visible action at all (when clean) — the autonomous behavior the hackathon brief asks for.

- [ ] **Step 1: Write the workflow file**

```yaml
name: SecurityAgent PR Review

on:
  pull_request:
    types: [opened, synchronize]

permissions:
  pull-requests: write
  contents: read

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout (agentcore project config)
        uses: actions/checkout@v4

      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install agentcore CLI
        run: npm install -g @aws/agentcore@0.28.1

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.SECURITY_AGENT_AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.SECURITY_AGENT_AWS_SECRET_ACCESS_KEY }}
          aws-region: us-west-2

      - name: Invoke SecurityAgent
        id: invoke
        working-directory: SecurityAgent
        run: |
          PROMPT="A pull request was opened against ${{ github.repository }}. Clone ${{ github.event.pull_request.head.repo.clone_url }} at ref ${{ github.event.pull_request.head.sha }} and perform a full security review as an automated CI check. End your response with a SECURITY_STATUS line as instructed in your system prompt."
          agentcore invoke --json "$PROMPT" > /tmp/agent_output.json
          cat /tmp/agent_output.json
          jq -r '.response' /tmp/agent_output.json > /tmp/agent_response.txt
          if grep -q "SECURITY_STATUS: NEEDS_REVIEW" /tmp/agent_response.txt; then
            echo "needs_review=true" >> "$GITHUB_OUTPUT"
          else
            echo "needs_review=false" >> "$GITHUB_OUTPUT"
          fi

      - name: Comment on PR if review needed
        if: steps.invoke.outputs.needs_review == 'true'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: gh pr comment "${{ github.event.pull_request.number }}" --body-file /tmp/agent_response.txt
```

- [ ] **Step 2: Validate the YAML syntax locally**

```bash
python -c "import yaml; yaml.safe_load(open('.github/workflows/security-agent-review.yml'))" && echo "YAML OK"
```

Expected: `YAML OK`

- [ ] **Step 3: Commit and push to `main`**

```bash
git add .github/workflows/security-agent-review.yml
git commit -m "Add GitHub Actions workflow to autonomously review PRs

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Tsj7XdnivQEKsQZQLFsFAj"
git push
```

(The workflow only triggers on `pull_request` events, so pushing it to `main` has no immediate effect — nothing runs until Task 7 opens a PR.)

---

### Task 7: End-to-end test — open the demo PR and verify both branches of the behavior

**Files:** none (verification only).

**Interfaces:**
- Consumes: everything from Tasks 1-6.
- Produces: confirmation that the full autonomous loop works, and the actual PR comment used as demo-video footage.

- [ ] **Step 1: Open the vulnerable PR**

```bash
gh pr create --base main --head demo/vulnerable-pr-test \
  --title "Demo: intentionally vulnerable fixtures" \
  --body "Do not merge - fixtures for the SecurityAgent hackathon demo."
```

- [ ] **Step 2: Watch the workflow run**

```bash
gh run watch
```

Expected: the `SecurityAgent PR Review` run completes successfully (exit 0).

- [ ] **Step 3: Verify a comment appeared**

```bash
gh pr view demo/vulnerable-pr-test --comments
```

Expected: a comment from the bot mentioning the leaked token, the `reqeusts` typosquat, and/or the `pyyaml` CVE, ending with `SECURITY_STATUS: NEEDS_REVIEW`.

- [ ] **Step 4: Push the "fix" commit to the same PR**

```bash
git checkout demo/vulnerable-pr-test
git rm requirements.txt Dockerfile demo-fixture-config.py demo-fixture-app.py
git commit -m "Remove demo vulnerabilities"
git push
```

- [ ] **Step 5: Watch the follow-up run and verify silence**

```bash
gh run watch
gh pr view demo/vulnerable-pr-test --comments
```

Expected: the workflow run completes successfully, and **no new comment** was added by the bot (only the one from Step 3 should still be there) — confirming the "stays silent when clean" half of the behavior.

- [ ] **Step 6: Leave the PR open (don't merge)**

This PR is demo footage, not real work — leave it open (or close without merging) after recording. Do not merge `demo/vulnerable-pr-test` into `main`.

---

## Self-Review Notes

- **Spec coverage:** all 4 components from the spec (clone_repo tool, GitHub Actions workflow, IAM, demo fixtures) map to Tasks 1, 2, 5, 6, 4 respectively; the spec's testing section maps to Task 1 Step 3-4 (self-check) and Task 7 (end-to-end).
- **Type/name consistency checked:** `clone_repo(url, ref="")` signature is identical everywhere it's referenced (Task 1 definition, Task 2 system prompt description, Task 6's implicit expectation that the agent calls it). The sentinel strings `SECURITY_STATUS: NEEDS_REVIEW` / `SECURITY_STATUS: CLEAN` are byte-identical between the Task 2 system prompt and the Task 6 `grep` check.
- **No placeholders:** every step has literal, runnable code/commands; the one open-ended item (IAM policy resource ARN possibly needing a wildcard) is called out explicitly as a verify-and-adjust step in Task 5 Step 6, not left vague.
- **Revision note (this pass):** the original version of this plan used a Stripe-formatted fake key (`sk_live_...`) in the Task 4 fixtures. GitHub's push protection blocked the push outright because the format matched a real vendor pattern closely enough, even though the value was synthetic. Switched to a generic, non-vendor-shaped high-entropy token, verified live to still trigger gitleaks' `generic-api-key` rule.
