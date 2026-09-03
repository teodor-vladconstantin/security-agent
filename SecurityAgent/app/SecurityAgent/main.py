from typing import Any
from collections import OrderedDict
from strands import Agent, tool
import asyncio
from strands.agent.conversation_manager.null_conversation_manager import NullConversationManager
from bedrock_agentcore.runtime import BedrockAgentCoreApp
from model.load import load_model
from mcp_client.client import get_streamable_http_mcp_client
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

app = BedrockAgentCoreApp()
log = app.logger

# Define a Streamable HTTP MCP Client
mcp_clients = [get_streamable_http_mcp_client()]

DEFAULT_SYSTEM_PROMPT = """
You are a security assistant. When asked to check a repository, use
scan_for_secrets, scan_dependencies, scan_typosquatting,
scan_code_vulnerabilities, scan_oss_vulnerabilities, scan_iac_misconfig,
scan_git_history_secrets, generate_sbom, scan_licenses,
scan_container_image, scan_dependency_confusion, and
generate_security_report as needed. Flag anything that looks like a real,
live credential as CRITICAL. For
dependency vulnerabilities, flag HIGH/CRITICAL severity CVEs as urgent,
and note LOW/MEDIUM ones as things that can wait. Ignore false positives
(class names, example values, placeholder text).

scan_typosquatting checks requirements.txt/pyproject.toml/package.json
dependencies for typosquatting and AI-hallucinated packages. Interpret
its severities as: CRITICAL means the package does not exist on the
registry at all (possibly hallucinated by an AI coding tool or a severe
typo) - treat as needing immediate action, likely a broken or malicious
install. HIGH means the name is suspiciously similar to a well-known
popular package - verify manually whether it's a typo or intentional.
MEDIUM means a newly-published package with moderate similarity to a
popular name - keep it under monitoring rather than acting immediately.

scan_code_vulnerabilities runs Semgrep's public security-audit ruleset
over the source code (SQL injection, XSS, hardcoded crypto, command
injection, etc.). HIGH severity findings need immediate attention; MEDIUM
should be reviewed soon; LOW can wait.

scan_oss_vulnerabilities cross-checks declared Python/JS dependencies
against the OSV.dev vulnerability database. CRITICAL means the package
itself is a confirmed, already-published malicious package (a MAL-
advisory) - treat this the same as a live compromise, not just a
vulnerability, and recommend immediate removal. HIGH means a known
CVE/GHSA vulnerability exists in that dependency version - recommend
upgrading and note this is separate from scan_typosquatting (which
catches fake/lookalike names, not vulnerabilities in real packages).

scan_iac_misconfig scans Dockerfiles/Kubernetes/Terraform for
infrastructure misconfigurations via trivy. Pass through its own
severities (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN) directly.

scan_git_history_secrets is like scan_for_secrets but scans the full git
commit history instead of just the current working tree - use it to
catch secrets that were committed and later deleted. It only works on an
actual git repository; if it reports "not a git repository", that's
expected for non-git folders, not an error to escalate.

generate_sbom produces a CycloneDX software bill of materials. It is
informational (a component inventory), not a set of findings - do not
assign it a severity or treat its output as something requiring action
on its own.

scan_licenses lists package licenses (Python via the active environment,
JS via package.json). MEDIUM severity means a copyleft license
(GPL/AGPL/LGPL/SSPL/EUPL/MPL/CC-BY-SA) was found - flag it as something
the user should get legal/compatibility sign-off on, not as a security
vulnerability. Entries without a severity are informational.

scan_container_image scans a container image's OS/package layer for known
CVEs via trivy - either the image named by image_ref, or (if omitted) the
base image(s) in a Dockerfile under repo_path. Pass through trivy's own
severities directly. Its vulnerability database is only as fresh as the
last image build - if asked whether it's fully current, say so rather
than presenting it as real-time.

scan_dependency_confusion only produces findings when the repo actually
configures a private/internal package index; if it reports that no
private index is configured, that's an expected "not applicable" result,
not a clean bill of health on its own - it does not mean the repo has no
dependency risk, only that this specific attack class doesn't apply. When
it does find something, severity MEDIUM means a declared package name
also exists on the public registry while a private index is configured -
tell the user to verify their tooling pins to the private index rather
than falling back to public on a miss.

generate_security_report runs every scan_* tool above in one sequential
pass and returns a combined JSON report with a "_summary" severity
rollup - use it when asked for a full/complete audit instead of calling
tools one by one, but mention it takes noticeably longer than any single
tool since it runs all of them in sequence.
"""


# Define a collection of tools used by the model
tools = []

_INLINE_FUNCTION_NAMES = set()

# Define a simple function tool
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



# Add MCP client to tools if available
for mcp_client in mcp_clients:
    if mcp_client:
        tools.append(mcp_client)


def _make_conversation_manager():
    return NullConversationManager()

# Reuses one Agent per session_id so each session keeps its own in-process
# conversation history (best-effort; resets on cold start). The cache is bounded
# to 128 sessions with LRU eviction (least-recently-used is dropped and its
# history reset) so a single process serving many sessions cannot leak history
# between them or grow without limit. For durable history, attach a session manager.
def agent_factory():
    cache = OrderedDict()
    def get_or_create_agent(session_id):
        if session_id in cache:
            cache.move_to_end(session_id)
            return cache[session_id]
        if len(cache) >= 128:
            cache.popitem(last=False)
        cache[session_id] = Agent(
            model=load_model(),
            system_prompt=DEFAULT_SYSTEM_PROMPT,
            tools=tools,
            conversation_manager=_make_conversation_manager(),
            hooks=[
            ],
        )
        return cache[session_id]
    return get_or_create_agent
get_or_create_agent = agent_factory()


def strip_trailing_tool_use(messages: Any) -> list[dict]:
    """Strip toolUse blocks from the tail until the last message has none."""
    if not isinstance(messages, list):
        raise ValueError("messages must be a list")

    messages = list(messages)
    while messages:
        last = messages[-1]
        if not isinstance(last, dict):
            raise ValueError("each message must be an object")
        original_content = last.get("content", [])
        if not isinstance(original_content, list) or not all(isinstance(block, dict) for block in original_content):
            raise ValueError("each message content value must be a list of content blocks")

        content = [block for block in original_content if "toolUse" not in block]
        if len(content) == len(original_content):
            break
        if content:
            messages[-1] = {**last, "content": content}
            break
        messages.pop()

    return messages


def _extract_prompt(payload: dict):
    """Accept validated harness messages, tool results, or a plain prompt string."""
    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object")
    if "messages" in payload:
        return strip_trailing_tool_use(payload["messages"])
    if "tool_results" in payload:
        tool_results = payload["tool_results"]
        if not isinstance(tool_results, list) or not all(
            isinstance(tool_result, dict) and isinstance(tool_result.get("toolUseId"), str)
            for tool_result in tool_results
        ):
            raise ValueError("tool_results must contain objects with a toolUseId string")
        return [{"role": "user", "content": [{"toolResult": {
            "toolUseId": tr["toolUseId"],
            "status": tr.get("status", "success"),
            "content": tr.get("content", []),
        }} for tr in tool_results]}]
    prompt = payload.get("prompt", "")
    if not isinstance(prompt, str):
        raise ValueError("prompt must be a string")
    return prompt


def _has_inline_function_call(messages) -> bool:
    """Return True if messages contains an assistant toolUse for an inline function tool."""
    if not _INLINE_FUNCTION_NAMES or not isinstance(messages, list):
        return False
    for msg in messages:
        if msg.get("role") == "assistant":
            for block in msg.get("content", []):
                if isinstance(block, dict) and block.get("toolUse", {}).get("name") in _INLINE_FUNCTION_NAMES:
                    return True
    return False


def _is_inline_function_call(event: dict) -> bool:
    """Check if a contentBlockStart event is for an inline function tool."""
    if not _INLINE_FUNCTION_NAMES:
        return False
    cbs = event.get("contentBlockStart", {})
    start = cbs.get("start", {})
    tool_use = start.get("toolUse") if isinstance(start, dict) else None
    return tool_use is not None and tool_use.get("name") in _INLINE_FUNCTION_NAMES



@app.entrypoint
async def invoke(payload, context):
    log.info("Invoking Agent.....")


    session_id = getattr(context, 'session_id', 'default-session')
    agent = get_or_create_agent(session_id)

    prompt = _extract_prompt(payload)


    async for event in agent.stream_async(
        prompt,
    ):
        if not isinstance(event, dict) or "event" not in event:
            continue
        cbs = event["event"].get("contentBlockStart")
        if cbs is not None and not cbs.get("start"):
            continue
        yield event


if __name__ == "__main__":
    app.run()
