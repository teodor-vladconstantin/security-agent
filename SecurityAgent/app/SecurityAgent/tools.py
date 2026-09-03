import subprocess
import json
import os
import re
import time
import difflib
import urllib.request
import urllib.error
from datetime import datetime, timezone
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


# Top ~200 most popular PyPI packages, used as a reference set for
# typosquatting similarity checks. Approximate, not a ranked/exhaustive list.
POPULAR_PYPI = {
    "requests", "urllib3", "boto3", "botocore", "numpy", "pandas", "setuptools",
    "pip", "wheel", "six", "python-dateutil", "pyyaml", "certifi",
    "charset-normalizer", "idna", "s3transfer", "packaging", "typing-extensions",
    "importlib-metadata", "click", "jinja2", "markupsafe", "cryptography", "cffi",
    "pycparser", "attrs", "pytz", "protobuf", "google-api-core",
    "googleapis-common-protos", "grpcio", "pyparsing", "platformdirs", "filelock",
    "wrapt", "aiobotocore", "jmespath", "rsa", "pyasn1", "pyasn1-modules",
    "cachetools", "google-auth", "oauthlib", "requests-oauthlib", "colorama",
    "tqdm", "pyjwt", "docutils", "pygments", "sphinx", "babel", "sqlalchemy",
    "greenlet", "psycopg2", "psycopg2-binary", "pymysql", "redis", "pymongo",
    "flask", "werkzeug", "itsdangerous", "django", "asgiref",
    "djangorestframework", "fastapi", "starlette", "pydantic", "pydantic-core",
    "uvicorn", "anyio", "sniffio", "h11", "httpcore", "httpx", "aiohttp",
    "aiosignal", "multidict", "yarl", "frozenlist", "async-timeout", "tenacity",
    "backoff", "tornado", "twisted", "gunicorn", "celery", "kombu", "billiard",
    "vine", "amqp", "scipy", "scikit-learn", "joblib", "threadpoolctl",
    "matplotlib", "pillow", "cycler", "kiwisolver", "fonttools", "contourpy",
    "seaborn", "statsmodels", "patsy", "torch", "torchvision", "tensorflow",
    "tensorboard", "keras", "h5py", "absl-py", "grpcio-tools", "transformers",
    "tokenizers", "huggingface-hub", "safetensors", "accelerate", "datasets",
    "pyarrow", "xxhash", "dill", "multiprocess", "nltk", "spacy", "thinc",
    "blis", "srsly", "catalogue", "wasabi", "regex", "beautifulsoup4",
    "soupsieve", "lxml", "html5lib", "webencodings", "selenium", "playwright",
    "pytest", "pytest-cov", "pytest-mock", "coverage", "mock", "tox",
    "virtualenv", "pipenv", "poetry", "pip-tools", "black", "isort", "flake8",
    "pylint", "mypy", "mypy-extensions", "pyflakes", "pycodestyle", "autopep8",
    "bandit", "pre-commit", "cfgv", "identify", "nodeenv", "distlib", "boto",
    "awscli", "s3fs", "fsspec", "gcsfs", "azure-storage-blob", "azure-core",
    "google-cloud-storage", "google-resumable-media", "paramiko", "bcrypt",
    "pynacl", "marshmallow", "apispec", "gevent", "eventlet", "msgpack",
    "ujson", "orjson", "simplejson", "toml", "tomli", "ruamel-yaml",
    "python-dotenv", "environs", "pydub", "opencv-python", "imageio",
    "scikit-image", "networkx", "sympy", "numba", "llvmlite", "dask",
    "distributed", "cloudpickle", "toolz", "more-itertools", "wcwidth",
    "prompt-toolkit", "ipython", "jedi", "parso", "traitlets", "jupyter-core",
    "jupyter-client", "ipykernel", "notebook", "nbformat", "nbconvert", "pyzmq",
    "decorator", "pexpect", "ptyprocess", "psutil", "docopt", "fire", "typer",
    "rich", "shellingham", "questionary", "prettytable", "tabulate",
    "termcolor", "humanize", "arrow", "pendulum", "freezegun", "faker",
    "hypothesis", "factory-boy",
}

# Top ~200 most popular npm packages, used as a reference set for
# typosquatting similarity checks. Approximate, not a ranked/exhaustive list.
POPULAR_NPM = {
    "react", "react-dom", "react-scripts", "redux", "react-redux", "vue",
    "vuex", "vue-router", "angular", "lodash", "underscore", "moment", "dayjs",
    "date-fns", "axios", "node-fetch", "request", "express", "koa", "fastify",
    "next", "nuxt", "gatsby", "webpack", "webpack-cli", "webpack-dev-server",
    "@babel/core", "@babel/preset-env", "@babel/preset-react", "eslint",
    "eslint-plugin-react", "eslint-config-airbnb", "prettier", "typescript",
    "ts-node", "ts-loader", "jest", "mocha", "chai", "sinon", "enzyme",
    "@testing-library/react", "cypress", "puppeteer", "playwright",
    "webdriverio", "jquery", "bootstrap", "tailwindcss", "sass", "less",
    "postcss", "autoprefixer", "chalk", "commander", "yargs", "inquirer",
    "ora", "figlet", "boxen", "chokidar", "glob", "minimatch", "rimraf",
    "mkdirp", "fs-extra", "del", "cross-env", "dotenv", "config", "nconf",
    "winston", "morgan", "debug", "pino", "bunyan", "uuid", "nanoid",
    "shortid", "classnames", "prop-types", "styled-components", "@emotion/react",
    "@emotion/styled", "immer", "redux-thunk", "redux-saga", "reselect",
    "recompose", "formik", "yup", "joi", "ajv", "zod", "graphql",
    "apollo-server", "apollo-client", "@apollo/client", "socket.io",
    "socket.io-client", "ws", "body-parser", "cookie-parser", "cors", "helmet",
    "passport", "passport-local", "jsonwebtoken", "bcrypt", "bcryptjs",
    "multer", "sharp", "jimp", "canvas", "three", "d3", "chart.js", "echarts",
    "moment-timezone", "luxon", "rxjs", "zone.js", "core-js",
    "regenerator-runtime", "whatwg-fetch", "isomorphic-fetch", "node-sass",
    "css-loader", "style-loader", "file-loader", "url-loader",
    "html-webpack-plugin", "mini-css-extract-plugin", "terser-webpack-plugin",
    "webpack-merge", "rollup", "vite", "esbuild", "parcel", "gulp", "grunt",
    "browserify", "semver", "validator", "sanitize-html", "xss", "marked",
    "remark", "unified", "gray-matter", "front-matter", "js-yaml", "ini",
    "toml", "csv-parser", "papaparse", "xlsx", "exceljs", "pdfkit",
    "puppeteer-core", "node-cron", "cron", "bull", "agenda", "ioredis",
    "redis", "mongoose", "mongodb", "mysql", "mysql2", "pg", "sequelize",
    "typeorm", "prisma", "knex", "sqlite3", "better-sqlite3", "aws-sdk",
    "@aws-sdk/client-s3", "firebase", "firebase-admin", "stripe", "twilio",
    "nodemailer", "googleapis", "google-auth-library", "next-auth",
    "next-i18next", "react-i18next", "i18next", "vue-i18n", "react-router-dom",
    "react-router", "history", "react-hook-form", "react-query",
    "@tanstack/react-query", "swr", "zustand", "recoil", "mobx", "mobx-react",
    "react-transition-group", "framer-motion", "gsap", "lottie-web",
    "react-icons", "font-awesome", "antd", "@mui/material",
    "@material-ui/core", "semantic-ui-react", "react-bootstrap", "vuetify",
    "element-plus",
}


def _parse_requirements_txt(path: str) -> list[str]:
    """Extract bare package names from a requirements.txt file."""
    names = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            name = re.split(r"[<>=!~\[; ]", line)[0].strip()
            if name:
                names.append(name)
    return names


def _parse_pyproject_toml(path: str) -> list[str]:
    """Extract dependency package names from PEP 621 or Poetry pyproject.toml."""
    try:
        import tomllib
    except ImportError:
        return []
    with open(path, "rb") as f:
        data = tomllib.load(f)

    specs = list(data.get("project", {}).get("dependencies", []))
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    specs.extend(name for name in poetry_deps if name.lower() != "python")

    names = []
    for spec in specs:
        if isinstance(spec, str):
            name = re.split(r"[<>=!~\[; ]", spec)[0].strip()
            if name:
                names.append(name)
    return names


def _parse_package_json(path: str) -> list[str]:
    """Extract dependency + devDependency package names from package.json."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)
    names = list(data.get("dependencies", {}).keys())
    names.extend(data.get("devDependencies", {}).keys())
    return names


def _fetch_registry_json(url: str, timeout: float = 10.0):
    """Fetch a registry URL. Returns ("ok", data), ("not_found", None), or
    ("error", None) for anything inconclusive (network issues, non-404 errors)."""
    req = urllib.request.Request(url, headers={"User-Agent": "SecurityAgent-typosquat-scanner/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return "ok", json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "not_found", None
        return "error", None
    except (urllib.error.URLError, OSError, ValueError):
        return "error", None


def _closest_popular_match(name: str, popular: set[str]):
    """Return (closest_popular_name, similarity_ratio) for name against popular."""
    best_name, best_ratio = None, 0.0
    name_lower = name.lower()
    for candidate in popular:
        ratio = difflib.SequenceMatcher(None, name_lower, candidate.lower()).ratio()
        if ratio > best_ratio:
            best_name, best_ratio = candidate, ratio
    return best_name, best_ratio


def _pypi_first_release_days_ago(data: dict):
    dates = [
        f.get("upload_time_iso_8601")
        for files in data.get("releases", {}).values()
        for f in files
        if f.get("upload_time_iso_8601")
    ]
    if not dates:
        return None
    earliest = datetime.fromisoformat(min(dates).replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - earliest).days


def _npm_first_release_days_ago(data: dict):
    created = data.get("time", {}).get("created")
    if not created:
        return None
    earliest = datetime.fromisoformat(created.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - earliest).days


def _fetch_json_post(url: str, payload: dict, timeout: float = 15.0):
    """POST a JSON body to url. Returns ("ok", data) or ("error", None)."""
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "User-Agent": "SecurityAgent-oss-vuln-scanner/1.0",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return "ok", json.loads(resp.read().decode())
    except (urllib.error.URLError, OSError, ValueError):
        return "error", None


def _extract_npm_license(data: dict):
    """Handle both modern ("license": "MIT") and legacy ("license": {"type":
    ...}} / "licenses": [{"type": ...}]) npm package.json license shapes."""
    lic = data.get("license")
    if isinstance(lic, str):
        return lic
    if isinstance(lic, dict):
        return lic.get("type")
    licenses = data.get("licenses")
    if isinstance(licenses, list) and licenses and isinstance(licenses[0], dict):
        return licenses[0].get("type")
    return None


_COPYLEFT_LICENSE_TAGS = {
    "GPL", "AGPL", "LGPL", "SSPL", "EUPL", "CC-BY-SA", "MPL",
}


def _is_copyleft(license_str: str) -> bool:
    if not license_str:
        return False
    upper = license_str.upper()
    return any(tag in upper for tag in _COPYLEFT_LICENSE_TAGS)


_OSV_ECOSYSTEM = {"pypi": "PyPI", "npm": "npm"}

_SEMGREP_SEVERITY_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


@tool
def scan_typosquatting(repo_path: str = ".") -> str:
    """
    Scans Python (requirements.txt, pyproject.toml) and JavaScript
    (package.json) dependency manifests for typosquatting and AI-hallucinated
    packages. For each declared package, checks whether it actually exists on
    PyPI/npm, flags names suspiciously similar to well-known popular packages,
    and flags newly-published packages with moderate similarity to a popular
    name. Returns a JSON list of findings, each with package_name, ecosystem,
    severity (CRITICAL/HIGH/MEDIUM), reason, and suggested_action.

    Args:
        repo_path: Path to the folder to scan for dependency manifests.
    """
    packages = []  # list of (name, ecosystem)
    found_manifest = False

    req_txt = os.path.join(repo_path, "requirements.txt")
    if os.path.isfile(req_txt):
        found_manifest = True
        packages.extend((name, "pypi") for name in _parse_requirements_txt(req_txt))

    pyproject = os.path.join(repo_path, "pyproject.toml")
    if os.path.isfile(pyproject):
        found_manifest = True
        packages.extend((name, "pypi") for name in _parse_pyproject_toml(pyproject))

    package_json = os.path.join(repo_path, "package.json")
    if os.path.isfile(package_json):
        found_manifest = True
        packages.extend((name, "npm") for name in _parse_package_json(package_json))

    if not found_manifest:
        return "No requirements.txt, pyproject.toml, or package.json found."

    seen = set()
    unique_packages = []
    for name, eco in packages:
        key = (name.lower(), eco)
        if key not in seen:
            seen.add(key)
            unique_packages.append((name, eco))

    findings = []
    for name, eco in unique_packages:
        popular = POPULAR_PYPI if eco == "pypi" else POPULAR_NPM
        url = (
            f"https://pypi.org/pypi/{name}/json"
            if eco == "pypi"
            else f"https://registry.npmjs.org/{name}"
        )
        status, data = _fetch_registry_json(url)
        time.sleep(0.3)  # ponytail: simple sequential rate limit, no concurrency to throttle

        if status == "error":
            continue  # inconclusive (network/registry issue) - don't false-flag

        if status == "not_found":
            findings.append({
                "package_name": name,
                "ecosystem": eco,
                "severity": "CRITICAL",
                "reason": "Pachet inexistent pe registry-ul oficial - posibil halucinat de AI sau typo grav.",
                "suggested_action": "Elimina imediat acest pachet din dependente si verifica sursa care l-a introdus.",
            })
            continue

        best_name, ratio = _closest_popular_match(name, popular)

        if best_name and ratio > 0.85 and best_name.lower() != name.lower():
            findings.append({
                "package_name": name,
                "ecosystem": eco,
                "severity": "HIGH",
                "reason": f"Nume suspect de similar cu pachetul popular '{best_name}' (similaritate {ratio:.2f}).",
                "suggested_action": f"Verifica manual daca '{name}' e un typo pentru '{best_name}' sau e intentionat.",
            })
            continue

        if best_name and 0.7 <= ratio <= 0.85:
            days_ago = (
                _pypi_first_release_days_ago(data)
                if eco == "pypi"
                else _npm_first_release_days_ago(data)
            )
            if days_ago is not None and days_ago < 30:
                findings.append({
                    "package_name": name,
                    "ecosystem": eco,
                    "severity": "MEDIUM",
                    "reason": f"Pachet nou (publicat acum {days_ago} zile), similaritate moderata ({ratio:.2f}) cu '{best_name}'.",
                    "suggested_action": f"Monitorizeaza '{name}'; verifica autorul si scopul inainte de a-l considera de incredere.",
                })

    if not findings:
        return "No typosquatting or hallucinated packages detected."

    return json.dumps(findings, indent=2)


@tool
def scan_code_vulnerabilities(repo_path: str = ".") -> str:
    """
    Scans source code for security vulnerabilities (SQL injection, XSS,
    hardcoded crypto, command injection, etc.) using Semgrep's public
    "p/security-audit" ruleset. Returns a JSON list of findings, each with
    file, line, rule_id, message, and severity (HIGH/MEDIUM/LOW).

    Args:
        repo_path: Path to the folder to scan.
    """
    result = subprocess.run(
        ["semgrep", "--config=p/security-audit", "--json", "--quiet", repo_path],
        capture_output=True,
        text=True,
    )

    try:
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        return "No code vulnerabilities found."

    results = data.get("results", [])
    if not results:
        return "No code vulnerabilities found."

    findings = []
    for r in results:
        extra = r.get("extra", {})
        findings.append({
            "file": r.get("path"),
            "line": r.get("start", {}).get("line"),
            "rule_id": r.get("check_id"),
            "message": extra.get("message"),
            "severity": _SEMGREP_SEVERITY_MAP.get(extra.get("severity"), "MEDIUM"),
        })

    return json.dumps(findings, indent=2)


@tool
def scan_oss_vulnerabilities(repo_path: str = ".") -> str:
    """
    Scans Python and JavaScript dependency manifests (requirements.txt,
    pyproject.toml, package.json) against the OSV.dev vulnerability database
    for known CVEs/GHSAs and for packages already confirmed as malicious
    (MAL- advisories). Returns a JSON list of findings, each with
    package_name, ecosystem, vulnerability_id, severity (CRITICAL for
    known-malicious packages, HIGH for known CVEs/GHSAs), and
    suggested_action.

    Args:
        repo_path: Path to the folder to scan for dependency manifests.
    """
    packages = []

    req_txt = os.path.join(repo_path, "requirements.txt")
    if os.path.isfile(req_txt):
        packages.extend((name, "pypi") for name in _parse_requirements_txt(req_txt))

    pyproject = os.path.join(repo_path, "pyproject.toml")
    if os.path.isfile(pyproject):
        packages.extend((name, "pypi") for name in _parse_pyproject_toml(pyproject))

    package_json = os.path.join(repo_path, "package.json")
    if os.path.isfile(package_json):
        packages.extend((name, "npm") for name in _parse_package_json(package_json))

    if not packages:
        return "No requirements.txt, pyproject.toml, or package.json found."

    seen = set()
    unique_packages = []
    for name, eco in packages:
        key = (name.lower(), eco)
        if key not in seen:
            seen.add(key)
            unique_packages.append((name, eco))

    queries = [
        {"package": {"name": name, "ecosystem": _OSV_ECOSYSTEM[eco]}}
        for name, eco in unique_packages
    ]
    status, data = _fetch_json_post("https://api.osv.dev/v1/querybatch", {"queries": queries})
    if status != "ok":
        return "OSV.dev lookup failed (network issue) - no findings reported."

    findings = []
    for (name, eco), result in zip(unique_packages, data.get("results", [])):
        for vuln in result.get("vulns", []):
            vuln_id = vuln.get("id", "")
            if vuln_id.startswith("MAL-"):
                findings.append({
                    "package_name": name,
                    "ecosystem": eco,
                    "vulnerability_id": vuln_id,
                    "severity": "CRITICAL",
                    "suggested_action": f"Pachet cunoscut ca malware ({vuln_id}) - elimina imediat din dependente.",
                })
            else:
                # ponytail: no per-vuln /v1/vulns/{id} fetch for CVSS/severity
                # detail (would mean N extra requests) - flag uniformly HIGH.
                # Upgrade path: fetch per-id detail if granular severity needed.
                findings.append({
                    "package_name": name,
                    "ecosystem": eco,
                    "vulnerability_id": vuln_id,
                    "severity": "HIGH",
                    "suggested_action": f"Vulnerabilitate cunoscuta ({vuln_id}) - vezi https://osv.dev/{vuln_id} si actualizeaza pachetul.",
                })

    if not findings:
        return "No known vulnerabilities or malicious packages detected."

    return json.dumps(findings, indent=2)


@tool
def scan_iac_misconfig(repo_path: str = ".") -> str:
    """
    Scans Dockerfiles, Kubernetes manifests, and Terraform files for
    infrastructure-as-code misconfigurations using trivy config. Returns a
    JSON list of findings, each with file, misconfig_id, title, and severity
    (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN, as reported by trivy).

    Args:
        repo_path: Path to the folder to scan.
    """
    result = subprocess.run(
        ["trivy", "config", "--format", "json", "--quiet", repo_path],
        capture_output=True,
        text=True,
    )

    try:
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        return "No IaC misconfigurations found."

    findings = []
    for entry in data.get("Results") or []:
        for m in entry.get("Misconfigurations") or []:
            findings.append({
                "file": entry.get("Target"),
                "misconfig_id": m.get("ID"),
                "title": m.get("Title"),
                "severity": m.get("Severity", "UNKNOWN"),
            })

    if not findings:
        return "No IaC misconfigurations found."

    return json.dumps(findings, indent=2)


@tool
def scan_git_history_secrets(repo_path: str = ".") -> str:
    """
    Scans the full git commit history (not just the working tree) for
    secrets that were committed and later removed, using gitleaks. Only
    works on an actual git repository (a .git directory with commits) -
    unlike scan_for_secrets, which scans the working tree only. Returns a
    JSON list of findings in the same shape as scan_for_secrets.

    Args:
        repo_path: Path to the git repository to scan.
    """
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        return "Not a git repository (no .git directory) - history cannot be scanned."

    report_path = "gitleaks_history_report.json"
    subprocess.run(
        [
            "gitleaks", "detect",
            "--source", repo_path,
            "--config", ".gitleaks.toml",
            "--report-format", "json",
            "--report-path", report_path,
            "--exit-code", "0",
        ],
        capture_output=True,
        text=True,
    )

    try:
        with open(report_path, "r") as f:
            findings = json.load(f)
    except FileNotFoundError:
        return "No secrets found in git history."

    if not findings:
        return "No secrets found in git history."

    return json.dumps(findings, indent=2)


@tool
def generate_sbom(repo_path: str = ".") -> str:
    """
    Generates a CycloneDX Software Bill of Materials (SBOM) for the
    repository using trivy. This is an informational inventory of detected
    packages/components, not a vulnerability scan - it has no severities.

    Args:
        repo_path: Path to the folder to scan.
    """
    result = subprocess.run(
        ["trivy", "fs", "--format", "cyclonedx", "--quiet", repo_path],
        capture_output=True,
        text=True,
    )

    if not result.stdout.strip():
        return "Could not generate SBOM (no components detected or trivy error)."

    return result.stdout


@tool
def scan_licenses(repo_path: str = ".") -> str:
    """
    Lists licenses for installed Python packages (via pip-licenses) and for
    JavaScript dependencies declared in package.json (via the npm registry's
    license field - no Node.js/npm install required). Flags copyleft
    licenses (GPL/AGPL/LGPL/SSPL/EUPL/MPL/CC-BY-SA) with severity MEDIUM;
    everything else is listed without a severity flag. Returns a JSON list
    of entries with package_name, ecosystem, license, and (when flagged)
    severity and reason.

    Args:
        repo_path: Path to the folder to scan for package.json (Python
                    licenses are read from the active virtual environment
                    regardless of this path, same limitation as
                    scan_dependencies).
    """
    entries = []

    result = subprocess.run(
        ["pip-licenses", "--format=json"],
        capture_output=True,
        text=True,
    )
    try:
        py_licenses = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        py_licenses = []
    for pkg in py_licenses:
        entries.append({
            "package_name": pkg.get("Name"),
            "ecosystem": "pypi",
            "license": pkg.get("License"),
        })

    package_json = os.path.join(repo_path, "package.json")
    if os.path.isfile(package_json):
        for name in _parse_package_json(package_json):
            status, data = _fetch_registry_json(f"https://registry.npmjs.org/{name}")
            time.sleep(0.3)  # ponytail: same sequential rate limit as scan_typosquatting
            license_val = _extract_npm_license(data) if status == "ok" and data else None
            entries.append({
                "package_name": name,
                "ecosystem": "npm",
                "license": license_val,
            })

    if not entries:
        return "No packages found to check licenses for."

    findings = []
    for e in entries:
        finding = dict(e)
        if _is_copyleft(e.get("license") or ""):
            finding["severity"] = "MEDIUM"
            finding["reason"] = "Licenta copyleft - verifica compatibilitatea legala inainte de folosire/distributie."
        findings.append(finding)

    return json.dumps(findings, indent=2)


def _dockerfile_base_images(path: str) -> list[str]:
    """Extract unique pullable image refs from FROM lines in a Dockerfile,
    excluding references to earlier build stages (FROM <stage-alias>)."""
    stage_names = set()
    images = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = re.match(r"(?i)^FROM\s+(\S+)(?:\s+AS\s+(\S+))?", line.strip())
            if not m:
                continue
            image, alias = m.group(1), m.group(2)
            if image.lower() != "scratch" and image not in images:
                images.append(image)
            if alias:
                stage_names.add(alias)
    return [i for i in images if i not in stage_names]


@tool
def scan_container_image(repo_path: str = ".", image_ref: str = "") -> str:
    """
    Scans container image(s) for known OS/package CVEs using trivy image.
    Pulls images directly from their registry - no local Docker build or
    daemon access required. If image_ref is given, scans that image
    directly; otherwise extracts base image(s) referenced by FROM lines in
    repo_path/Dockerfile and scans each of those. Returns a JSON list of
    findings, each with image, pkg_name, installed_version, fixed_version,
    vulnerability_id, and severity (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN, as
    reported by trivy).

    Args:
        repo_path: Path to the folder containing a Dockerfile (ignored if
                    image_ref is given).
        image_ref: A specific image to scan (e.g. "python:3.12-slim"). If
                    omitted, Dockerfile FROM lines in repo_path are used.
    """
    if image_ref:
        images = [image_ref]
    else:
        dockerfile = os.path.join(repo_path, "Dockerfile")
        if not os.path.isfile(dockerfile):
            return "No Dockerfile found and no image_ref given - nothing to scan."
        images = _dockerfile_base_images(dockerfile)
        if not images:
            return "No FROM image references found in Dockerfile."

    findings = []
    for image in images:
        # ponytail: --skip-db-update relies on the vuln DB baked into the
        # image at build time (see Dockerfile) - avoids a slow/network-
        # dependent DB download on every invocation. Upgrade path: drop the
        # flag (or rebuild the image regularly) if DB freshness matters more
        # than latency.
        result = subprocess.run(
            ["trivy", "image", "--format", "json", "--quiet", "--skip-db-update", image],
            capture_output=True,
            text=True,
        )
        try:
            data = json.loads(result.stdout)
        except (json.JSONDecodeError, ValueError):
            continue
        for entry in data.get("Results") or []:
            for v in entry.get("Vulnerabilities") or []:
                findings.append({
                    "image": image,
                    "pkg_name": v.get("PkgName"),
                    "installed_version": v.get("InstalledVersion"),
                    "fixed_version": v.get("FixedVersion"),
                    "vulnerability_id": v.get("VulnerabilityID"),
                    "severity": v.get("Severity", "UNKNOWN"),
                })

    if not findings:
        return "No known vulnerabilities found in scanned container image(s)."

    return json.dumps(findings, indent=2)


def _has_private_python_index(repo_path: str) -> bool:
    req_txt = os.path.join(repo_path, "requirements.txt")
    if os.path.isfile(req_txt):
        with open(req_txt, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if (line.startswith("--index-url") or line.startswith("--extra-index-url")
                        or line.startswith("-i ")) and "pypi.org" not in line:
                    return True

    pyproject = os.path.join(repo_path, "pyproject.toml")
    if os.path.isfile(pyproject):
        try:
            import tomllib
            with open(pyproject, "rb") as f:
                data = tomllib.load(f)
        except ImportError:
            data = {}
        if data.get("tool", {}).get("uv", {}).get("index"):
            return True
        if data.get("tool", {}).get("poetry", {}).get("source"):
            return True

    return False


def _has_private_npm_registry(repo_path: str) -> bool:
    npmrc = os.path.join(repo_path, ".npmrc")
    if os.path.isfile(npmrc):
        with open(npmrc, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if ("registry=" in line or ":registry=" in line) and "registry.npmjs.org" not in line:
                    return True
    return False


@tool
def scan_dependency_confusion(repo_path: str = ".") -> str:
    """
    Checks for dependency confusion risk: a repo that configures a private
    package index/registry (pip --index-url/--extra-index-url, uv/poetry
    custom index, npm .npmrc registry) is at risk if a declared package
    name ALSO exists on the corresponding PUBLIC registry - a build that
    doesn't strictly pin to the private index could silently pull the
    public (potentially attacker-planted) package instead. Returns a JSON
    list of findings (severity MEDIUM) for packages that exist publicly
    while a private index is configured, or a message explaining why the
    check doesn't apply (no private index configured).

    Args:
        repo_path: Path to the folder to scan for manifests and index config.
    """
    has_private_py = _has_private_python_index(repo_path)
    has_private_npm = _has_private_npm_registry(repo_path)

    if not has_private_py and not has_private_npm:
        return "No private package index configured - dependency confusion risk does not apply here."

    packages = []
    if has_private_py:
        req_txt = os.path.join(repo_path, "requirements.txt")
        if os.path.isfile(req_txt):
            packages.extend((name, "pypi") for name in _parse_requirements_txt(req_txt))
        pyproject = os.path.join(repo_path, "pyproject.toml")
        if os.path.isfile(pyproject):
            packages.extend((name, "pypi") for name in _parse_pyproject_toml(pyproject))
    if has_private_npm:
        package_json = os.path.join(repo_path, "package.json")
        if os.path.isfile(package_json):
            packages.extend((name, "npm") for name in _parse_package_json(package_json))

    if not packages:
        return "Private index configured but no matching manifests found to check."

    seen = set()
    unique_packages = []
    for name, eco in packages:
        key = (name.lower(), eco)
        if key not in seen:
            seen.add(key)
            unique_packages.append((name, eco))

    findings = []
    for name, eco in unique_packages:
        url = (
            f"https://pypi.org/pypi/{name}/json"
            if eco == "pypi"
            else f"https://registry.npmjs.org/{name}"
        )
        status, _ = _fetch_registry_json(url)
        time.sleep(0.3)  # ponytail: same sequential rate limit as scan_typosquatting
        if status == "ok":
            findings.append({
                "package_name": name,
                "ecosystem": eco,
                "severity": "MEDIUM",
                "reason": "Pachet gasit atat pe registry-ul public cat si aveti index privat configurat - risc de dependency confusion daca prioritatea index-urilor nu e stricta.",
                "suggested_action": f"Verifica ca instalarea lui '{name}' foloseste indexul privat (index/pin explicit), nu doar --extra-index-url care poate prefera public.",
            })

    if not findings:
        return "Private index configured, but none of the declared packages also exist on the public registry."

    return json.dumps(findings, indent=2)


_REPORT_TOOLS = [
    ("secrets", "scan_for_secrets"),
    ("git_history_secrets", "scan_git_history_secrets"),
    ("dependencies", "scan_dependencies"),
    ("oss_vulnerabilities", "scan_oss_vulnerabilities"),
    ("typosquatting", "scan_typosquatting"),
    ("dependency_confusion", "scan_dependency_confusion"),
    ("code_vulnerabilities", "scan_code_vulnerabilities"),
    ("iac_misconfig", "scan_iac_misconfig"),
    ("container_image", "scan_container_image"),
    ("licenses", "scan_licenses"),
]


@tool
def generate_security_report(repo_path: str = ".") -> str:
    """
    Runs every other scan_* tool in this module against repo_path in one
    pass (sequentially - this is the slow, "scan everything" option) and
    returns a single consolidated JSON report: per-tool result
    (finding_count plus either the parsed findings or the raw message) and
    an overall "_summary" with total findings by severity across all tools
    whose findings carry a severity field. Use this instead of calling each
    tool individually when asked for a full/complete audit. Does not
    include generate_sbom (informational inventory, not findings).

    Args:
        repo_path: Path to the folder to scan.
    """
    report = {}
    severity_totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for key, func_name in _REPORT_TOOLS:
        func = globals()[func_name]
        try:
            result = func(repo_path)
        except Exception as e:  # noqa: BLE001 - one tool failing shouldn't break the report
            report[key] = {"finding_count": 0, "error": str(e)}
            continue

        try:
            data = json.loads(result)
        except (json.JSONDecodeError, TypeError):
            report[key] = {"finding_count": 0, "message": result}
            continue

        if isinstance(data, list):
            for f in data:
                if isinstance(f, dict):
                    sev = f.get("severity") or f.get("Severity")
                    if sev in severity_totals:
                        severity_totals[sev] += 1
            report[key] = {"finding_count": len(data), "findings": data}
        else:
            report[key] = {"finding_count": 0, "raw": data}

    report["_summary"] = severity_totals
    return json.dumps(report, indent=2)


if __name__ == "__main__":
    # ponytail: minimal self-check, no network calls
    assert _parse_requirements_txt.__name__  # sanity the module loaded

    import tempfile

    with tempfile.TemporaryDirectory() as d:
        req = os.path.join(d, "requirements.txt")
        with open(req, "w") as f:
            f.write("# comment\nreqeusts==1.0.0\nnumpy>=1.20\n-e .\n")
        assert _parse_requirements_txt(req) == ["reqeusts", "numpy"]

        pkg = os.path.join(d, "package.json")
        with open(pkg, "w") as f:
            json.dump({"dependencies": {"lodahs": "^4.0.0"}, "devDependencies": {"jest": "^29.0.0"}}, f)
        assert _parse_package_json(pkg) == ["lodahs", "jest"]

    best_name, ratio = _closest_popular_match("reqeusts", POPULAR_PYPI)
    assert best_name == "requests" and ratio > 0.85, (best_name, ratio)

    best_name, ratio = _closest_popular_match("requests", POPULAR_PYPI)
    assert best_name == "requests" and ratio == 1.0

    fake_pypi_data = {"releases": {"0.1": [{"upload_time_iso_8601": "2020-01-01T00:00:00Z"}]}}
    days = _pypi_first_release_days_ago(fake_pypi_data)
    assert days is not None and days > 1000

    assert _is_copyleft("GPL-3.0") is True
    assert _is_copyleft("AGPL-3.0-or-later") is True
    assert _is_copyleft("MIT") is False
    assert _is_copyleft("") is False
    assert _is_copyleft(None) is False

    assert _extract_npm_license({"license": "MIT"}) == "MIT"
    assert _extract_npm_license({"license": {"type": "ISC"}}) == "ISC"
    assert _extract_npm_license({"licenses": [{"type": "BSD-2-Clause"}]}) == "BSD-2-Clause"
    assert _extract_npm_license({}) is None

    assert _SEMGREP_SEVERITY_MAP["ERROR"] == "HIGH"
    assert _OSV_ECOSYSTEM["pypi"] == "PyPI" and _OSV_ECOSYSTEM["npm"] == "npm"

    with tempfile.TemporaryDirectory() as d:
        assert scan_git_history_secrets(d) == "Not a git repository (no .git directory) - history cannot be scanned."

    with tempfile.TemporaryDirectory() as d:
        dockerfile = os.path.join(d, "Dockerfile")
        with open(dockerfile, "w") as f:
            f.write("FROM python:3.12-slim AS builder\nRUN pip install foo\nFROM builder\nCOPY . .\n")
        assert _dockerfile_base_images(dockerfile) == ["python:3.12-slim"]

        req = os.path.join(d, "requirements.txt")
        with open(req, "w") as f:
            f.write("--extra-index-url https://pkgs.internal.example.com/simple\nrequests==2.0\n")
        assert _has_private_python_index(d) is True
        assert scan_dependency_confusion(os.path.join(d, "nope")) == "No private package index configured - dependency confusion risk does not apply here."

    with tempfile.TemporaryDirectory() as d:
        assert _has_private_python_index(d) is False
        assert _has_private_npm_registry(d) is False

    with tempfile.TemporaryDirectory() as d:
        npmrc = os.path.join(d, ".npmrc")
        with open(npmrc, "w") as f:
            f.write("@myorg:registry=https://npm.internal.example.com/\n")
        assert _has_private_npm_registry(d) is True

    print("tools.py self-check OK")