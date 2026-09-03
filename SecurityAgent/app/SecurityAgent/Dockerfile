FROM public.ecr.aws/docker/library/python:3.12-slim-trixie

ARG TARGETARCH

# Install gitleaks + trivy, arch-matched to the actual build platform via
# TARGETARCH (set automatically by buildx). Previously gitleaks was
# hardcoded to linux_arm64, which silently fails to exec on an amd64 build
# (e.g. local `agentcore dev` on a non-ARM host) - subprocess.run doesn't
# check the exit code, so scan_for_secrets would report a false "no
# secrets found" instead of erroring.
RUN apt-get update && apt-get install -y --no-install-recommends curl git \
    && case "$TARGETARCH" in \
         amd64) GITLEAKS_ARCH=x64; TRIVY_ARCH=64bit ;; \
         arm64) GITLEAKS_ARCH=arm64; TRIVY_ARCH=ARM64 ;; \
         *) echo "Unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
       esac \
    && curl -sSL -o /tmp/gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_${GITLEAKS_ARCH}.tar.gz" \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && rm /tmp/gitleaks.tar.gz \
    && curl -sSL -o /tmp/trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-${TRIVY_ARCH}.tar.gz" \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm /tmp/trivy.tar.gz \
    && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
# Note: `git` is kept installed (not purged) - gitleaks shells out to the
# real `git` binary for history scanning (scan_git_history_secrets), it
# does not use an embedded git implementation.

RUN pip install --no-cache-dir uv

ARG UV_DEFAULT_INDEX
ARG UV_INDEX

WORKDIR /app

ENV UV_SYSTEM_PYTHON=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_NO_PROGRESS=1 \
    PYTHONUNBUFFERED=1 \
    DOCKER_CONTAINER=1 \
    UV_DEFAULT_INDEX=${UV_DEFAULT_INDEX} \
    UV_INDEX=${UV_INDEX} \
    PATH="/app/.venv/bin:$PATH"

RUN useradd -m -u 1000 bedrock_agentcore

# WORKDIR (above) creates /app while root is still active, so it's
# root-owned; without this, bedrock_agentcore can overwrite files that
# already exist in /app (e.g. re-running scan_for_secrets) but can't
# create new ones there (e.g. scan_git_history_secrets writing its own
# report for the first time) - a silent permission-denied that tools
# ignore because subprocess.run's exit code isn't checked.
RUN chown bedrock_agentcore:bedrock_agentcore /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY --chown=bedrock_agentcore:bedrock_agentcore . .
RUN uv sync --frozen --no-dev

USER bedrock_agentcore

# Repos handed to scan_git_history_secrets may be owned by a different uid
# than the container's runtime user (e.g. copied/mounted in) - modern git
# refuses to operate on those ("detected dubious ownership") unless
# explicitly trusted. Trust all paths: this container only ever scans
# repos it's asked to scan, there's no untrusted-multi-tenant filesystem.
RUN git config --global --add safe.directory '*'

# AgentCore Runtime service contract ports
# https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-service-contract.html
# 8080: HTTP Mode
# 8000: MCP Mode
# 9000: A2A Mode
EXPOSE 8080 8000 9000

CMD ["opentelemetry-instrument", "python", "-m", "main"]
