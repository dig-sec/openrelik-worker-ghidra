FROM ubuntu:24.04

RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

ARG GHIDRA_DOWNLOAD_URL
ARG GHIDRA_ZIP_SHA256=""
ARG GHIDRA_VERSION="unknown"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    openjdk-21-jdk-headless \
    unzip \
    && rm -rf /var/lib/apt/lists/*

RUN test -n "${GHIDRA_DOWNLOAD_URL}" || (echo "GHIDRA_DOWNLOAD_URL is required" && false)
RUN curl -fsSL "${GHIDRA_DOWNLOAD_URL}" -o /tmp/ghidra.zip \
    && if [ -n "${GHIDRA_ZIP_SHA256}" ]; then echo "${GHIDRA_ZIP_SHA256}  /tmp/ghidra.zip" | sha256sum -c -; fi \
    && mkdir -p /opt \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && extracted_dir="$(find /opt -maxdepth 1 -type d -name 'ghidra_*' | head -n 1)" \
    && test -n "${extracted_dir}" \
    && mv "${extracted_dir}" /opt/ghidra \
    && rm -f /tmp/ghidra.zip

ARG OPENRELIK_PYDEBUG
ENV OPENRELIK_PYDEBUG=${OPENRELIK_PYDEBUG:-0}
ARG OPENRELIK_PYDEBUG_PORT
ENV OPENRELIK_PYDEBUG_PORT=${OPENRELIK_PYDEBUG_PORT:-5678}

RUN groupadd --gid 10001 openrelik \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin openrelik

WORKDIR /openrelik

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
COPY pyproject.toml ./
RUN uv sync --no-install-project --no-dev

COPY . ./
RUN uv sync --no-dev

RUN mkdir -p /opt/ghidra_scripts /openrelik/tmp /usr/share/openrelik/data \
    && cp -r /openrelik/ghidra_scripts/* /opt/ghidra_scripts/ \
    && chmod -R 0555 /opt/ghidra_scripts \
    && chown -R openrelik:openrelik /openrelik /usr/share/openrelik /tmp

ENV PATH="/openrelik/.venv/bin:$PATH"
ENV GHIDRA_VERSION="${GHIDRA_VERSION}"
ENV GHIDRA_ANALYZE_HEADLESS="/opt/ghidra/support/analyzeHeadless"
ENV GHIDRA_SCRIPT_PATH="/opt/ghidra_scripts"
ENV GHIDRA_HEADLESS_MAXMEM="4G"
ENV GHIDRA_ACTIVE_PROCESSORS="2"
ENV GHIDRA_TMPDIR="/tmp"
ENV GHIDRA_SCRIPTS_GIT_SHA="unknown"
ENV HOME="/tmp"

USER 10001:10001

CMD ["celery", "--app=src.app", "worker", "--task-events", "--concurrency=1", "--loglevel=INFO", "-Q", "openrelik-worker-ghidra"]
