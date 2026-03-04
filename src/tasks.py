import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request

from openrelik_worker_common.file_utils import create_output_file
from openrelik_worker_common.task_utils import create_task_result, get_input_files

from .app import celery

TASK_NAME = "openrelik-worker-ghidra.tasks.analyze-headless"

DEFAULT_TIMEOUT_SECONDS = 600
MIN_TIMEOUT_SECONDS = 60
MAX_TIMEOUT_SECONDS = 1800
DEFAULT_DECOMPILE_MODE = "entrypoints"
DEFAULT_EXPORT_FORMAT = "json"
DEFAULT_MAX_MEMORY = "4G"
DEFAULT_ANALYZE_HEADLESS = "/opt/ghidra/support/analyzeHeadless"
DEFAULT_SCRIPT_PATH = "/opt/ghidra_scripts"
DEFAULT_ACTIVE_PROCESSORS = 2

DEFAULT_LLM_PROVIDER = "none"
DEFAULT_OLLAMA_URL = "http://ollama:11434"
DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"
DEFAULT_LLM_TIMEOUT_SECONDS = 45
DEFAULT_LLM_MAX_TOKENS = 512
DEFAULT_LLM_TEMPERATURE = 0.0

ALLOWED_DECOMPILE_MODES = {"off", "entrypoints", "all"}
ALLOWED_EXPORT_FORMATS = {"json", "json+decompile"}
ALLOWED_LLM_PROVIDERS = {"none", "ollama", "openai"}

LLM_SYSTEM_PROMPT = (
    "You are an incident response reverse engineering assistant. "
    "Respond with valid JSON only using keys: overview, capabilities, iocs, "
    "notable_functions, notable_strings, confidence."
)

TASK_METADATA = {
    "display_name": "Ghidra headless analysis",
    "description": (
        "Analyze binaries with secure headless Ghidra and export deterministic "
        "JSON artifacts for downstream OpenRelik workers."
    ),
    "task_config": [
        {
            "name": "timeout_seconds",
            "label": "Analysis timeout per file (seconds)",
            "description": "Range 60-1800. Default 600.",
            "type": "text",
            "required": True,
            "default_value": str(DEFAULT_TIMEOUT_SECONDS),
        },
        {
            "name": "decompile_mode",
            "label": "Decompile scope",
            "description": "off | entrypoints | all. Default entrypoints.",
            "type": "text",
            "required": True,
            "default_value": DEFAULT_DECOMPILE_MODE,
        },
        {
            "name": "export_formats",
            "label": "Export format",
            "description": "json | json+decompile. Default json.",
            "type": "text",
            "required": True,
            "default_value": DEFAULT_EXPORT_FORMAT,
        },
        {
            "name": "keep_project",
            "label": "Keep temporary Ghidra project",
            "description": "Keep headless project directory for debugging (default: false).",
            "type": "checkbox",
            "required": True,
            "default_value": False,
        },
        {
            "name": "llm_provider",
            "label": "LLM provider",
            "description": "none | ollama | openai. Default none.",
            "type": "text",
            "required": True,
            "default_value": DEFAULT_LLM_PROVIDER,
        },
        {
            "name": "llm_model",
            "label": "LLM model",
            "description": "Model name when llm_provider is ollama/openai.",
            "type": "text",
            "required": False,
            "default_value": "llama3.1:8b-instruct",
        },
        {
            "name": "ollama_url",
            "label": "Ollama URL",
            "description": "Base URL for Ollama API (default: http://ollama:11434).",
            "type": "text",
            "required": False,
            "default_value": DEFAULT_OLLAMA_URL,
        },
        {
            "name": "openai_api_key",
            "label": "OpenAI API key",
            "description": "Optional, overrides OPENAI_API_KEY environment variable.",
            "type": "text",
            "required": False,
        },
        {
            "name": "openai_base_url",
            "label": "OpenAI base URL",
            "description": "Optional, defaults to https://api.openai.com/v1.",
            "type": "text",
            "required": False,
            "default_value": DEFAULT_OPENAI_BASE_URL,
        },
        {
            "name": "llm_timeout_seconds",
            "label": "LLM timeout seconds",
            "description": "HTTP timeout for LLM calls. Range 5-300. Default 45.",
            "type": "text",
            "required": False,
            "default_value": str(DEFAULT_LLM_TIMEOUT_SECONDS),
        },
        {
            "name": "llm_max_tokens",
            "label": "LLM max tokens",
            "description": "OpenAI max_tokens value. Range 64-8192. Default 512.",
            "type": "text",
            "required": False,
            "default_value": str(DEFAULT_LLM_MAX_TOKENS),
        },
        {
            "name": "llm_temperature",
            "label": "LLM temperature",
            "description": "Sampling temperature in range 0-2. Default 0.",
            "type": "text",
            "required": False,
            "default_value": str(DEFAULT_LLM_TEMPERATURE),
        },
    ],
}


@dataclass(frozen=True)
class LLMConfig:
    provider: str
    model: str
    endpoint: str
    api_key: str | None
    timeout_seconds: int
    max_tokens: int
    temperature: float


@dataclass(frozen=True)
class AnalysisConfig:
    timeout_seconds: int
    decompile_mode: str
    export_format: str
    include_decompile: bool
    keep_project: bool
    analyze_headless_bin: str
    script_path: str
    max_memory: str
    ghidra_version: str
    scripts_git_sha: str
    active_processors: int
    llm_config: LLMConfig | None


def _to_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    return bool(value)


def _parse_bounded_int(
    value: Any,
    *,
    default: int,
    minimum: int,
    maximum: int,
    field_name: str,
) -> int:
    if value is None or str(value).strip() == "":
        return default

    try:
        parsed = int(str(value).strip())
    except ValueError as exc:
        raise RuntimeError(f"{field_name} must be an integer") from exc

    if parsed < minimum or parsed > maximum:
        raise RuntimeError(f"{field_name} must be in range {minimum}-{maximum}")

    return parsed


def _parse_bounded_float(
    value: Any,
    *,
    default: float,
    minimum: float,
    maximum: float,
    field_name: str,
) -> float:
    if value is None or str(value).strip() == "":
        return default

    try:
        parsed = float(str(value).strip())
    except ValueError as exc:
        raise RuntimeError(f"{field_name} must be a number") from exc

    if parsed < minimum or parsed > maximum:
        raise RuntimeError(f"{field_name} must be in range {minimum}-{maximum}")

    return parsed


def _parse_timeout_seconds(value: Any) -> int:
    return _parse_bounded_int(
        value,
        default=DEFAULT_TIMEOUT_SECONDS,
        minimum=MIN_TIMEOUT_SECONDS,
        maximum=MAX_TIMEOUT_SECONDS,
        field_name="task_config.timeout_seconds",
    )


def _parse_decompile_mode(value: Any) -> str:
    mode = (str(value).strip().lower() if value is not None else DEFAULT_DECOMPILE_MODE)
    if mode not in ALLOWED_DECOMPILE_MODES:
        raise RuntimeError(
            "task_config.decompile_mode must be one of: "
            + ", ".join(sorted(ALLOWED_DECOMPILE_MODES))
        )
    return mode


def _parse_export_format(value: Any) -> str:
    export_format = (str(value).strip().lower() if value is not None else DEFAULT_EXPORT_FORMAT)
    if export_format not in ALLOWED_EXPORT_FORMATS:
        raise RuntimeError(
            "task_config.export_formats must be one of: "
            + ", ".join(sorted(ALLOWED_EXPORT_FORMATS))
        )
    return export_format


def _parse_active_processors(value: Any) -> int:
    return _parse_bounded_int(
        value,
        default=DEFAULT_ACTIVE_PROCESSORS,
        minimum=1,
        maximum=32,
        field_name="GHIDRA_ACTIVE_PROCESSORS",
    )


def _parse_llm_provider(value: Any) -> str:
    provider = (str(value).strip().lower() if value is not None else DEFAULT_LLM_PROVIDER)
    if provider not in ALLOWED_LLM_PROVIDERS:
        raise RuntimeError(
            "task_config.llm_provider must be one of: "
            + ", ".join(sorted(ALLOWED_LLM_PROVIDERS))
        )
    return provider


def _parse_llm_config(task_config: dict[str, Any]) -> LLMConfig | None:
    provider = _parse_llm_provider(task_config.get("llm_provider"))
    if provider == "none":
        return None

    model = str(task_config.get("llm_model") or os.getenv("LLM_MODEL") or "").strip()
    if not model:
        raise RuntimeError("task_config.llm_model is required when llm_provider is enabled")

    timeout_seconds = _parse_bounded_int(
        task_config.get("llm_timeout_seconds"),
        default=DEFAULT_LLM_TIMEOUT_SECONDS,
        minimum=5,
        maximum=300,
        field_name="task_config.llm_timeout_seconds",
    )
    max_tokens = _parse_bounded_int(
        task_config.get("llm_max_tokens"),
        default=DEFAULT_LLM_MAX_TOKENS,
        minimum=64,
        maximum=8192,
        field_name="task_config.llm_max_tokens",
    )
    temperature = _parse_bounded_float(
        task_config.get("llm_temperature"),
        default=DEFAULT_LLM_TEMPERATURE,
        minimum=0.0,
        maximum=2.0,
        field_name="task_config.llm_temperature",
    )

    if provider == "ollama":
        endpoint = str(task_config.get("ollama_url") or os.getenv("OLLAMA_URL") or DEFAULT_OLLAMA_URL)
        endpoint = endpoint.strip()
        if not endpoint:
            raise RuntimeError("task_config.ollama_url cannot be empty for llm_provider=ollama")
        return LLMConfig(
            provider=provider,
            model=model,
            endpoint=endpoint,
            api_key=None,
            timeout_seconds=timeout_seconds,
            max_tokens=max_tokens,
            temperature=temperature,
        )

    endpoint = str(
        task_config.get("openai_base_url")
        or os.getenv("OPENAI_BASE_URL")
        or DEFAULT_OPENAI_BASE_URL
    ).strip()
    if not endpoint:
        raise RuntimeError("task_config.openai_base_url cannot be empty for llm_provider=openai")

    api_key = str(task_config.get("openai_api_key") or os.getenv("OPENAI_API_KEY") or "").strip()
    if not api_key:
        raise RuntimeError(
            "task_config.openai_api_key or OPENAI_API_KEY is required for llm_provider=openai"
        )

    return LLMConfig(
        provider=provider,
        model=model,
        endpoint=endpoint,
        api_key=api_key,
        timeout_seconds=timeout_seconds,
        max_tokens=max_tokens,
        temperature=temperature,
    )


def _parse_analysis_config(task_config: dict[str, Any]) -> AnalysisConfig:
    timeout_seconds = _parse_timeout_seconds(task_config.get("timeout_seconds"))
    decompile_mode = _parse_decompile_mode(task_config.get("decompile_mode"))
    export_format = _parse_export_format(task_config.get("export_formats"))
    include_decompile = export_format == "json+decompile"

    if include_decompile and decompile_mode == "off":
        raise RuntimeError(
            "task_config.decompile_mode cannot be off when task_config.export_formats=json+decompile"
        )

    return AnalysisConfig(
        timeout_seconds=timeout_seconds,
        decompile_mode=decompile_mode,
        export_format=export_format,
        include_decompile=include_decompile,
        keep_project=_to_bool(task_config.get("keep_project"), default=False),
        analyze_headless_bin=os.getenv("GHIDRA_ANALYZE_HEADLESS", DEFAULT_ANALYZE_HEADLESS),
        script_path=os.getenv("GHIDRA_SCRIPT_PATH", DEFAULT_SCRIPT_PATH),
        max_memory=os.getenv("GHIDRA_HEADLESS_MAXMEM", DEFAULT_MAX_MEMORY),
        ghidra_version=os.getenv("GHIDRA_VERSION", "unknown"),
        scripts_git_sha=os.getenv("GHIDRA_SCRIPTS_GIT_SHA", "unknown"),
        active_processors=_parse_active_processors(os.getenv("GHIDRA_ACTIVE_PROCESSORS")),
        llm_config=_parse_llm_config(task_config),
    )


def _sample_prefix(index: int, input_file: dict[str, Any]) -> str:
    display_name = input_file.get("display_name") or Path(input_file["path"]).name
    stem = Path(display_name).stem
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._")
    if not sanitized:
        sanitized = "sample"
    return f"sample-{index:04d}-{sanitized}"


def _shell_join(command: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def _build_subprocess_env(config: AnalysisConfig) -> dict[str, str]:
    env = os.environ.copy()
    env["GHIDRA_HEADLESS_MAXMEM"] = config.max_memory

    cpu_opt = f"-XX:ActiveProcessorCount={config.active_processors}"
    current_java_tool_options = env.get("JAVA_TOOL_OPTIONS", "").strip()
    if cpu_opt not in current_java_tool_options:
        env["JAVA_TOOL_OPTIONS"] = f"{current_java_tool_options} {cpu_opt}".strip()

    env.setdefault("HOME", "/tmp")
    return env


def _build_headless_command(
    config: AnalysisConfig,
    project_directory: Path,
    project_name: str,
    input_file_path: str,
    summary_path: str,
    functions_path: str,
    strings_path: str,
    decompile_path: str | None,
) -> list[str]:
    command = [
        config.analyze_headless_bin,
        str(project_directory),
        project_name,
        "-import",
        input_file_path,
        "-analysisTimeoutPerFile",
        str(config.timeout_seconds),
        "-scriptPath",
        config.script_path,
        "-postScript",
        "ExportSummaryJson.java",
        summary_path,
        config.ghidra_version,
        config.scripts_git_sha,
        "-postScript",
        "ExportFunctionsJsonl.java",
        functions_path,
        "-postScript",
        "ExportStringsJson.java",
        strings_path,
    ]

    if config.include_decompile:
        if not decompile_path:
            raise RuntimeError("decompile output path is required when include_decompile is true")
        command.extend(
            [
                "-postScript",
                "ExportDecompileJsonl.java",
                decompile_path,
                config.decompile_mode,
                str(config.timeout_seconds),
            ]
        )

    if not config.keep_project:
        command.append("-deleteProject")

    return command


def _run_headless(command: list[str], env: dict[str, str], timeout_seconds: int) -> subprocess.CompletedProcess:
    hard_timeout = timeout_seconds + 120
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=hard_timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"analyzeHeadless timed out after {hard_timeout} seconds") from exc


def _dir_debug_context(dir_path: Path) -> str:
    """Return a diagnostic block describing a directory's ownership, permissions, and contents."""
    lines = [f"  path:             {dir_path}"]
    try:
        st = dir_path.stat()
        lines.append(f"  mode:             {stat.filemode(st.st_mode)}")
        lines.append(f"  owner uid:gid:    {st.st_uid}:{st.st_gid}")
    except OSError as exc:
        lines.append(f"  stat failed:      {exc}")
    try:
        entries = sorted(p.name for p in dir_path.iterdir())
        preview = entries[:20]
        suffix = f" … (+{len(entries) - 20} more)" if len(entries) > 20 else ""
        lines.append(f"  contents:         {preview}{suffix}")
    except OSError as exc:
        lines.append(f"  listing failed:   {exc}")
    lines.append(f"  effective uid:gid: {os.getuid()}:{os.getgid()}")
    return "\n".join(lines)


def _check_output_dir_writable(output_path: str) -> None:
    """Fail fast with a clear diagnostic if the output directory is missing or not writable."""
    out_dir = Path(output_path)

    if not out_dir.exists():
        raise RuntimeError(
            f"Output directory does not exist: {out_dir}\n"
            + _dir_debug_context(out_dir.parent)
        )

    if not out_dir.is_dir():
        raise RuntimeError(f"Output path is not a directory: {out_dir}")

    probe = out_dir / ".openrelik_write_probe"
    try:
        probe.write_bytes(b"")
        probe.unlink()
    except OSError as exc:
        try:
            st = out_dir.stat()
            mode_str = stat.filemode(st.st_mode)
            owner = f"{st.st_uid}:{st.st_gid}"
        except OSError:
            mode_str = "unknown"
            owner = "unknown"
        raise RuntimeError(
            f"Output directory is not writable by this process.\n"
            f"  path:              {out_dir}\n"
            f"  mode:              {mode_str}\n"
            f"  owner uid:gid:     {owner}\n"
            f"  effective uid:gid: {os.getuid()}:{os.getgid()}\n"
            f"  error:             {exc}\n"
            f"Fix: ensure the output directory is writable by uid {os.getuid()}."
        ) from exc


def _validate_required_artifacts(paths: list[str], output_path: str | None = None) -> None:
    missing_paths = [path for path in paths if not Path(path).exists()]
    if missing_paths:
        context = f"Missing expected output artifacts: {', '.join(missing_paths)}"
        if output_path:
            context += "\nOutput directory context:\n" + _dir_debug_context(Path(output_path))
        raise RuntimeError(context)


def _read_json_file(path: str) -> Any:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _read_jsonl_preview(path: str, limit: int) -> list[Any]:
    records = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if len(records) >= limit:
                break
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def _build_llm_payload(
    summary_path: str,
    functions_path: str,
    strings_path: str,
    decompile_path: str | None,
) -> dict[str, Any]:
    summary = _read_json_file(summary_path)
    strings_data = _read_json_file(strings_path)

    strings_preview = []
    if isinstance(strings_data, dict):
        raw_strings = strings_data.get("strings")
        if isinstance(raw_strings, list):
            strings_preview = raw_strings[:40]

    payload = {
        "summary": summary,
        "functions_preview": _read_jsonl_preview(functions_path, limit=40),
        "strings_preview": strings_preview,
    }

    if decompile_path and Path(decompile_path).exists():
        payload["decompile_preview"] = _read_jsonl_preview(decompile_path, limit=8)

    return payload


def _http_json_post(
    url: str,
    payload: dict[str, Any],
    timeout_seconds: int,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    request_headers = {"Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)

    request = urllib_request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=request_headers,
        method="POST",
    )

    try:
        with urllib_request.urlopen(request, timeout=timeout_seconds) as response:
            response_body = response.read().decode("utf-8")
    except urllib_error.HTTPError as exc:
        error_body = ""
        if exc.fp is not None:
            error_body = exc.fp.read().decode("utf-8", errors="replace")
        message = error_body or str(exc.reason)
        raise RuntimeError(f"LLM HTTP error ({exc.code}): {message}") from exc
    except urllib_error.URLError as exc:
        raise RuntimeError(f"LLM request failed: {exc.reason}") from exc

    try:
        parsed = json.loads(response_body)
    except json.JSONDecodeError as exc:
        raise RuntimeError("LLM response was not valid JSON") from exc

    if not isinstance(parsed, dict):
        raise RuntimeError("LLM response JSON root must be an object")

    return parsed


def _extract_openai_content(response: dict[str, Any]) -> str:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        raise RuntimeError("OpenAI response missing choices")

    first_choice = choices[0]
    if not isinstance(first_choice, dict):
        raise RuntimeError("OpenAI response choice format invalid")

    message = first_choice.get("message")
    if not isinstance(message, dict):
        raise RuntimeError("OpenAI response missing choices[0].message")

    content = message.get("content")
    if isinstance(content, str):
        return content.strip()

    if isinstance(content, list):
        text_parts = []
        for part in content:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                text_parts.append(part["text"])
        return "\n".join(text_parts).strip()

    raise RuntimeError("OpenAI response content format is unsupported")


def _generate_llm_summary(llm_config: LLMConfig, payload: dict[str, Any]) -> str:
    user_message = (
        "Summarize the following reverse engineering artifacts for investigators. "
        "Artifacts JSON:\n"
        + json.dumps(payload, sort_keys=True)
    )

    if llm_config.provider == "ollama":
        url = llm_config.endpoint.rstrip("/") + "/api/chat"
        response = _http_json_post(
            url=url,
            timeout_seconds=llm_config.timeout_seconds,
            payload={
                "model": llm_config.model,
                "stream": False,
                "messages": [
                    {"role": "system", "content": LLM_SYSTEM_PROMPT},
                    {"role": "user", "content": user_message},
                ],
                "options": {
                    "temperature": llm_config.temperature,
                },
            },
        )

        message = response.get("message")
        if not isinstance(message, dict) or not isinstance(message.get("content"), str):
            raise RuntimeError("Ollama response missing message.content")
        return message["content"].strip()

    response = _http_json_post(
        url=llm_config.endpoint.rstrip("/") + "/chat/completions",
        timeout_seconds=llm_config.timeout_seconds,
        headers={"Authorization": f"Bearer {llm_config.api_key}"},
        payload={
            "model": llm_config.model,
            "temperature": llm_config.temperature,
            "max_tokens": llm_config.max_tokens,
            "messages": [
                {"role": "system", "content": LLM_SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
        },
    )
    return _extract_openai_content(response)


@celery.task(bind=True, name=TASK_NAME, metadata=TASK_METADATA)
def command(
    self,
    pipe_result: str | None = None,
    input_files: list | None = None,
    output_path: str | None = None,
    workflow_id: str | None = None,
    task_config: dict[str, Any] | None = None,
) -> str:
    task_config = task_config or {}
    input_files = get_input_files(pipe_result, input_files or [])

    if not input_files:
        raise ValueError("No input files provided")
    if not output_path:
        raise ValueError("output_path is required")

    config = _parse_analysis_config(task_config)
    subprocess_env = _build_subprocess_env(config)

    _check_output_dir_writable(output_path)

    output_files = []
    command_strings = []
    samples_manifest = []

    total_samples = len(input_files)

    for sample_index, input_file in enumerate(input_files, start=1):
        sample_path = input_file.get("path")
        if not sample_path or not os.path.exists(sample_path):
            raise RuntimeError(f"Input file does not exist: {sample_path}")

        sample_id = _sample_prefix(sample_index, input_file)

        summary_output = create_output_file(
            output_path,
            display_name=f"{sample_id}.summary.json",
            data_type="openrelik:ghidra:summary",
        )
        functions_output = create_output_file(
            output_path,
            display_name=f"{sample_id}.functions.jsonl",
            data_type="openrelik:ghidra:functions",
        )
        strings_output = create_output_file(
            output_path,
            display_name=f"{sample_id}.strings.json",
            data_type="openrelik:ghidra:strings",
        )

        decompile_output = None
        if config.include_decompile:
            decompile_output = create_output_file(
                output_path,
                display_name=f"{sample_id}.decompile.jsonl",
                data_type="openrelik:ghidra:decompile",
            )

        project_directory = Path(
            tempfile.mkdtemp(prefix=f"{sample_id}-", dir=os.getenv("GHIDRA_TMPDIR", "/tmp"))
        )
        project_name = f"OpenRelikProj{sample_index:04d}"

        command_line = _build_headless_command(
            config=config,
            project_directory=project_directory,
            project_name=project_name,
            input_file_path=sample_path,
            summary_path=summary_output.path,
            functions_path=functions_output.path,
            strings_path=strings_output.path,
            decompile_path=decompile_output.path if decompile_output else None,
        )
        command_strings.append(_shell_join(command_line))

        try:
            process = _run_headless(
                command=command_line,
                env=subprocess_env,
                timeout_seconds=config.timeout_seconds,
            )
        finally:
            if not config.keep_project:
                shutil.rmtree(project_directory, ignore_errors=True)

        if process.returncode != 0:
            stderr = (process.stderr or "").strip()
            stdout = (process.stdout or "").strip()
            parts = []
            if stderr:
                parts.append(f"stderr:\n{stderr}")
            if stdout:
                parts.append(f"stdout:\n{stdout}")
            error_text = "\n".join(parts) if parts else "No stderr/stdout captured"
            raise RuntimeError(
                f"analyzeHeadless failed for '{sample_path}' with exit code "
                f"{process.returncode}:\n{error_text}"
            )

        expected_paths = [summary_output.path, functions_output.path, strings_output.path]
        if decompile_output:
            expected_paths.append(decompile_output.path)
        _validate_required_artifacts(expected_paths, output_path=output_path)

        ai_summary_output = None
        if config.llm_config:
            ai_summary_output = create_output_file(
                output_path,
                display_name=f"{sample_id}.ai-summary.json",
                data_type="openrelik:ghidra:ai-summary",
            )
            llm_payload = _build_llm_payload(
                summary_path=summary_output.path,
                functions_path=functions_output.path,
                strings_path=strings_output.path,
                decompile_path=decompile_output.path if decompile_output else None,
            )
            llm_summary = _generate_llm_summary(config.llm_config, llm_payload)
            with open(ai_summary_output.path, "w", encoding="utf-8") as ai_summary_handle:
                json.dump(
                    {
                        "provider": config.llm_config.provider,
                        "model": config.llm_config.model,
                        "summary": llm_summary,
                        "source_files": {
                            "summary": summary_output.display_name,
                            "functions": functions_output.display_name,
                            "strings": strings_output.display_name,
                            "decompile": decompile_output.display_name if decompile_output else None,
                        },
                    },
                    ai_summary_handle,
                    indent=2,
                )
            _validate_required_artifacts([ai_summary_output.path], output_path=output_path)

        output_files.extend([summary_output, functions_output, strings_output])
        if decompile_output:
            output_files.append(decompile_output)
        if ai_summary_output:
            output_files.append(ai_summary_output)

        sample_manifest = {
            "sample_id": sample_id,
            "input_path": sample_path,
            "input_display_name": input_file.get("display_name") or Path(sample_path).name,
            "summary": summary_output.display_name,
            "functions": functions_output.display_name,
            "strings": strings_output.display_name,
        }
        if config.keep_project:
            sample_manifest["project_directory"] = str(project_directory)
        if decompile_output:
            sample_manifest["decompile"] = decompile_output.display_name
        if ai_summary_output:
            sample_manifest["ai_summary"] = ai_summary_output.display_name
        samples_manifest.append(sample_manifest)

        self.send_event(
            "task-progress",
            data={
                "processed_samples": sample_index,
                "total_samples": total_samples,
                "last_sample": sample_manifest["input_display_name"],
            },
        )

    manifest_output = create_output_file(
        output_path,
        display_name="ghidra_manifest.json",
        data_type="openrelik:ghidra:manifest",
    )

    manifest_data = {
        "schema_version": 1,
        "worker": "openrelik-worker-ghidra",
        "ghidra_version": config.ghidra_version,
        "scripts_git_sha": config.scripts_git_sha,
        "analysis_timeout_seconds": config.timeout_seconds,
        "decompile_mode": config.decompile_mode,
        "export_format": config.export_format,
        "max_memory": config.max_memory,
        "llm": (
            {
                "provider": config.llm_config.provider,
                "model": config.llm_config.model,
                "endpoint": config.llm_config.endpoint,
            }
            if config.llm_config
            else None
        ),
        "samples": samples_manifest,
    }
    with open(manifest_output.path, "w", encoding="utf-8") as manifest_handle:
        json.dump(manifest_data, manifest_handle, indent=2)

    output_files.append(manifest_output)

    return create_task_result(
        output_files=[output_file.to_dict() for output_file in output_files],
        workflow_id=workflow_id,
        command=" && ".join(command_strings),
        meta={
            "samples": len(samples_manifest),
            "timeout_seconds": config.timeout_seconds,
            "decompile_mode": config.decompile_mode,
            "export_format": config.export_format,
            "ghidra_version": config.ghidra_version,
            "llm_provider": config.llm_config.provider if config.llm_config else "none",
            "llm_model": config.llm_config.model if config.llm_config else "",
        },
    )
