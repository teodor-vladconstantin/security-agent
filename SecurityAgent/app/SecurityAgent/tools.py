import subprocess
import json
from strands import tool

@tool
def scan_for_secrets(repo_path: str) -> str:
    """
    Scans a code repository for exposed secrets (API keys, tokens, passwords)
    using gitleaks. Returns a JSON list of findings, each with file, line,
    and the type of secret detected. Automatically ignores dependency
    folders like .venv and node_modules.

    Args:
        repo_path: Path to the folder to scan.
    """
    result = subprocess.run(
        [
            "gitleaks", "detect",
            "--source", repo_path,
            "--no-git",
            "--config", ".gitleaks.toml",
            "--report-format", "json",
            "--report-path", "gitleaks_report.json",
            "--exit-code", "0",
        ],
        capture_output=True,
        text=True,
    )

    try:
        with open("gitleaks_report.json", "r") as f:
            findings = json.load(f)
    except FileNotFoundError:
        return "No secrets found."

    if not findings:
        return "No secrets found."

    return json.dumps(findings, indent=2)

@tool
def scan_dependencies(repo_path: str = ".") -> str:
    """
    Scans installed Python dependencies for known security vulnerabilities
    (CVEs) using pip-audit. Returns a JSON list of vulnerable packages,
    each with the package name, installed version, and vulnerability details.

    Args:
        repo_path: Path to the project folder (currently scans the active
                    virtual environment regardless of this path).
    """
    result = subprocess.run(
        ["pip-audit", "--format", "json"],
        capture_output=True,
        text=True,
    )

    if not result.stdout.strip():
        return "No known vulnerabilities found."

    return result.stdout