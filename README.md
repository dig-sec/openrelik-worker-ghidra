# openrelik-worker-ghidra

Secure headless Ghidra worker for OpenRelik.

This worker is designed for untrusted binaries and produces deterministic artifacts that other workers can parse:

- `summary.json` (metadata, hashes, architecture/compiler IDs, entry points, imports/exports, segments)
- `functions.jsonl` (function-level records)
- `strings.json` (defined strings with reference counts)
- optional `decompile.jsonl` (one JSON record per decompiled function)
- optional `ai-summary.json` (LLM-generated investigator summary via Ollama or OpenAI)

## Security model

This repo assumes defense in depth:

- container runs as non-root user (`10001:10001`)
- runtime should be `network_mode: none`
- runtime should use read-only root filesystem
- all Linux capabilities dropped
- `no-new-privileges` enabled
- strict limits for memory, CPU, and pids
- temporary headless project in `/tmp` and deleted by default
- LLM enrichment is opt-in (`llm_provider=none` by default)

A hardened compose example is included in `docker-compose.secure.example.yml`.

## Task contract

Task name:

- `openrelik-worker-ghidra.tasks.analyze-headless`

Task config fields:

- `timeout_seconds` (`60-1800`, default `600`)
- `decompile_mode` (`off|entrypoints|all`, default `entrypoints`)
- `export_formats` (`json|json+decompile`, default `json`)
- `keep_project` (`false` by default)
- `llm_provider` (`none|ollama|openai`, default `none`)
- `llm_model` (required when `llm_provider` is not `none`)
- `ollama_url` (default `http://ollama:11434`)
- `openai_api_key` (optional config field, falls back to `OPENAI_API_KEY`)
- `openai_base_url` (default `https://api.openai.com/v1`)
- `llm_timeout_seconds` (`5-300`, default `45`)
- `llm_max_tokens` (`64-8192`, default `512`, used for OpenAI)
- `llm_temperature` (`0-2`, default `0`)

Secure defaults:

- `GHIDRA_HEADLESS_MAXMEM=4G`
- `GHIDRA_ACTIVE_PROCESSORS=2`
- queue concurrency should remain `1` (or at most `2`)

LLM note:

- `llm_provider=openai` requires outbound network access and an API key.
- `llm_provider=ollama` works with a local/adjacent Ollama endpoint (for example `http://ollama:11434`).

## Headless invocation pattern

The worker runs `analyzeHeadless` with post-scripts like:

```bash
analyzeHeadless \
  /tmp/sample-0001 OpenRelikProj0001 \
  -import /work/input/sample.bin \
  -analysisTimeoutPerFile 600 \
  -scriptPath /opt/ghidra_scripts \
  -postScript ExportSummaryJson.java /work/output/sample-0001.summary.json 11.2.1 <scripts-sha> \
  -postScript ExportFunctionsJsonl.java /work/output/sample-0001.functions.jsonl \
  -postScript ExportStringsJson.java /work/output/sample-0001.strings.json \
  -deleteProject
```

If `export_formats=json+decompile`, the worker also runs:

```bash
-postScript ExportDecompileJsonl.java /work/output/sample-0001.decompile.jsonl entrypoints 600
```

## Build image

Pin Ghidra by passing explicit build args:

```bash
docker build \
  --build-arg GHIDRA_DOWNLOAD_URL="https://<pinned-ghidra-zip-url>" \
  --build-arg GHIDRA_ZIP_SHA256="<zip-sha256>" \
  --build-arg GHIDRA_VERSION="<version>" \
  -t openrelik-worker-ghidra:local .
```

## Run tests

```bash
uv run pytest
```
