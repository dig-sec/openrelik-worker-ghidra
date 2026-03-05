import json
import socket
from pathlib import Path
from unittest.mock import patch
from urllib import error as urllib_error

import pytest

from src import tasks


class DummyResultFile:
    def __init__(self, path: Path, display_name: str):
        self.path = str(path)
        self.display_name = display_name

    def to_dict(self):
        return {"path": self.path, "display_name": self.display_name}


def test_parse_analysis_config_defaults(monkeypatch):
    monkeypatch.delenv("GHIDRA_ANALYZE_HEADLESS", raising=False)
    monkeypatch.delenv("GHIDRA_SCRIPT_PATH", raising=False)
    monkeypatch.delenv("GHIDRA_HEADLESS_MAXMEM", raising=False)
    monkeypatch.delenv("GHIDRA_ACTIVE_PROCESSORS", raising=False)

    config = tasks._parse_analysis_config({})

    assert config.timeout_seconds == 600
    assert config.decompile_mode == "focused"
    assert config.export_format == "json"
    assert config.include_decompile is False
    assert config.keep_project is False
    assert config.max_memory == "4G"
    assert config.focused_decompile_limit == 80
    assert config.llm_config is None


def test_parse_analysis_config_timeout_validation():
    with pytest.raises(RuntimeError, match="timeout_seconds"):
        tasks._parse_analysis_config({"timeout_seconds": "abc"})

    with pytest.raises(RuntimeError, match="range"):
        tasks._parse_analysis_config({"timeout_seconds": "30"})


def test_parse_analysis_config_requires_decompile_mode_when_exporting_decompile():
    with pytest.raises(RuntimeError, match="decompile_mode"):
        tasks._parse_analysis_config(
            {"export_formats": "json+decompile", "decompile_mode": "off"}
        )


def test_parse_analysis_config_openai_requires_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        tasks._parse_analysis_config(
            {
                "llm_provider": "openai",
                "llm_model": "gpt-4o-mini",
            }
        )


def test_parse_analysis_config_ollama(monkeypatch):
    monkeypatch.delenv("OLLAMA_URL", raising=False)

    config = tasks._parse_analysis_config(
        {
            "llm_provider": "ollama",
            "llm_model": "llama3.1:8b-instruct",
            "ollama_url": "http://ollama:11434",
        }
    )

    assert config.llm_config is not None
    assert config.llm_config.provider == "ollama"
    assert config.llm_config.model == "llama3.1:8b-instruct"
    assert config.llm_config.endpoint == "http://ollama:11434"


def test_build_headless_command_includes_expected_flags(tmp_path):
    config = tasks.AnalysisConfig(
        timeout_seconds=600,
        decompile_mode="entrypoints",
        export_format="json+decompile",
        include_decompile=True,
        keep_project=False,
        analyze_headless_bin="/opt/ghidra/support/analyzeHeadless",
        script_path="/opt/ghidra_scripts",
        max_memory="4G",
        ghidra_version="11.2.1",
        scripts_git_sha="deadbeef",
        active_processors=2,
        focused_decompile_limit=80,
        llm_config=None,
    )

    command = tasks._build_headless_command(
        config=config,
        project_directory=tmp_path,
        project_name="OpenRelikProj0001",
        input_file_path="/work/input/sample.bin",
        summary_path="/work/output/summary.json",
        functions_path="/work/output/functions.jsonl",
        strings_path="/work/output/strings.json",
        decompile_path="/work/output/decompile.jsonl",
    )

    assert "-analysisTimeoutPerFile" in command
    assert "-scriptPath" in command
    assert "ExportSummaryJson.java" in command
    assert "ExportFunctionsJsonl.java" in command
    assert "ExportStringsJson.java" in command
    assert "ExportDecompileJsonl.java" in command
    assert "-deleteProject" in command


def _fake_subprocess_run(args, capture_output, text, check, timeout, env):
    del capture_output, text, check, timeout, env

    class FakeProcess:
        def __init__(self):
            self.returncode = 0
            self.stdout = "analysis completed"
            self.stderr = ""

    for index, token in enumerate(args):
        if token != "-postScript":
            continue
        output_file = Path(args[index + 2])
        output_file.parent.mkdir(parents=True, exist_ok=True)
        if output_file.suffix == ".jsonl":
            output_file.write_text('{"ok":true}\n', encoding="utf-8")
        else:
            output_file.write_text("{}\n", encoding="utf-8")

    return FakeProcess()


def test_command_success(monkeypatch, tmp_path):
    input_file = tmp_path / "sample.bin"
    input_file.write_bytes(b"MZ")

    output_dir = tmp_path / "out"
    output_dir.mkdir()

    created_paths = []

    def fake_create_output_file(output_path, display_name, data_type=None):
        del data_type
        path = Path(output_path) / display_name
        created_paths.append(path)
        return DummyResultFile(path=path, display_name=display_name)

    monkeypatch.setattr("src.tasks.create_output_file", fake_create_output_file)
    monkeypatch.setattr("src.tasks.subprocess.run", _fake_subprocess_run)
    monkeypatch.setattr(tasks.command, "send_event", lambda *args, **kwargs: None)

    result = tasks.command.run(
        pipe_result=None,
        input_files=[{"path": str(input_file), "display_name": "sample.bin"}],
        output_path=str(output_dir),
        workflow_id="wf-1",
        task_config={
            "timeout_seconds": "600",
            "decompile_mode": "entrypoints",
            "export_formats": "json+decompile",
            "keep_project": False,
            "llm_provider": "none",
        },
    )

    assert isinstance(result, str)
    assert any(path.name.endswith("summary.json") for path in created_paths)
    assert any(path.name.endswith("functions.jsonl") for path in created_paths)
    assert any(path.name.endswith("strings.json") for path in created_paths)
    assert any(path.name.endswith("decompile.jsonl") for path in created_paths)
    assert (output_dir / "ghidra_manifest.json").exists()

    manifest = json.loads((output_dir / "ghidra_manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1
    assert manifest["samples"][0]["input_display_name"] == "sample.bin"
    assert "decompile" in manifest["samples"][0]
    assert manifest["llm"] is None


def test_command_with_llm_summary(monkeypatch, tmp_path):
    input_file = tmp_path / "sample.bin"
    input_file.write_bytes(b"MZ")

    output_dir = tmp_path / "out"
    output_dir.mkdir()

    def fake_create_output_file(output_path, display_name, data_type=None):
        del data_type
        path = Path(output_path) / display_name
        return DummyResultFile(path=path, display_name=display_name)

    monkeypatch.setattr("src.tasks.create_output_file", fake_create_output_file)
    monkeypatch.setattr("src.tasks.subprocess.run", _fake_subprocess_run)
    monkeypatch.setattr("src.tasks._generate_llm_summary", lambda llm_config, payload: "{\"overview\":\"ok\"}")
    monkeypatch.setattr(tasks.command, "send_event", lambda *args, **kwargs: None)

    result = tasks.command.run(
        pipe_result=None,
        input_files=[{"path": str(input_file), "display_name": "sample.bin"}],
        output_path=str(output_dir),
        workflow_id="wf-llm",
        task_config={
            "timeout_seconds": "600",
            "decompile_mode": "entrypoints",
            "export_formats": "json",
            "llm_provider": "ollama",
            "llm_model": "llama3.1:8b-instruct",
            "ollama_url": "http://ollama:11434",
        },
    )

    assert isinstance(result, str)
    ai_summary_files = list(output_dir.glob("*.ai-summary.json"))
    assert ai_summary_files

    ai_summary = json.loads(ai_summary_files[0].read_text(encoding="utf-8"))
    assert ai_summary["provider"] == "ollama"
    assert ai_summary["model"] == "llama3.1:8b-instruct"

    manifest = json.loads((output_dir / "ghidra_manifest.json").read_text(encoding="utf-8"))
    assert manifest["llm"]["provider"] == "ollama"
    assert "ai_summary" in manifest["samples"][0]


def test_task_metadata_contract():
    assert tasks.TASK_NAME == "openrelik-worker-ghidra.tasks.analyze-headless"
    assert tasks.TASK_METADATA["display_name"] == "Ghidra headless analysis"
    task_config_names = {item["name"] for item in tasks.TASK_METADATA["task_config"]}
    assert {
        "timeout_seconds",
        "decompile_mode",
        "export_formats",
        "keep_project",
        "llm_provider",
        "llm_model",
        "ollama_url",
        "openai_api_key",
        "openai_base_url",
        "llm_timeout_seconds",
        "llm_max_tokens",
        "llm_temperature",
    }.issubset(task_config_names)


# ---------------------------------------------------------------------------
# LLM timeout configuration parsing
# ---------------------------------------------------------------------------


class TestLLMTimeoutConfig:
    """Validate llm_timeout_seconds parsing and boundary enforcement."""

    def test_ollama_default_timeout(self, monkeypatch):
        """Default LLM timeout is 45s — may be too low for CPU-only Ollama."""
        monkeypatch.delenv("OLLAMA_URL", raising=False)
        config = tasks._parse_analysis_config(
            {
                "llm_provider": "ollama",
                "llm_model": "llama3.1:8b-instruct",
                "ollama_url": "http://ollama:11434",
            }
        )
        assert config.llm_config.timeout_seconds == 45

    def test_ollama_high_timeout_for_cpu(self, monkeypatch):
        """CPU Ollama may need 120-300s; ensure high values are accepted."""
        monkeypatch.delenv("OLLAMA_URL", raising=False)
        config = tasks._parse_analysis_config(
            {
                "llm_provider": "ollama",
                "llm_model": "llama3.1:8b-instruct",
                "ollama_url": "http://ollama:11434",
                "llm_timeout_seconds": "300",
            }
        )
        assert config.llm_config.timeout_seconds == 300

    def test_ollama_timeout_at_upper_bound(self, monkeypatch):
        """300 is the max — make sure it's accepted."""
        monkeypatch.delenv("OLLAMA_URL", raising=False)
        config = tasks._parse_analysis_config(
            {
                "llm_provider": "ollama",
                "llm_model": "llama3.1:8b-instruct",
                "ollama_url": "http://ollama:11434",
                "llm_timeout_seconds": "300",
            }
        )
        assert config.llm_config.timeout_seconds == 300

    def test_ollama_timeout_exceeds_max_rejected(self):
        """Values above 300 must be rejected."""
        with pytest.raises(RuntimeError, match="range"):
            tasks._parse_analysis_config(
                {
                    "llm_provider": "ollama",
                    "llm_model": "llama3.1:8b-instruct",
                    "ollama_url": "http://ollama:11434",
                    "llm_timeout_seconds": "600",
                }
            )

    def test_ollama_timeout_below_min_rejected(self):
        """Values below 5 must be rejected."""
        with pytest.raises(RuntimeError, match="range"):
            tasks._parse_analysis_config(
                {
                    "llm_provider": "ollama",
                    "llm_model": "llama3.1:8b-instruct",
                    "ollama_url": "http://ollama:11434",
                    "llm_timeout_seconds": "2",
                }
            )

    def test_ollama_timeout_non_numeric_rejected(self):
        with pytest.raises(RuntimeError, match="integer"):
            tasks._parse_analysis_config(
                {
                    "llm_provider": "ollama",
                    "llm_model": "llama3.1:8b-instruct",
                    "ollama_url": "http://ollama:11434",
                    "llm_timeout_seconds": "slow",
                }
            )

    def test_llm_max_tokens_bounds(self):
        """Max tokens range is 64-8192."""
        with pytest.raises(RuntimeError, match="range"):
            tasks._parse_analysis_config(
                {
                    "llm_provider": "ollama",
                    "llm_model": "llama3.1:8b-instruct",
                    "ollama_url": "http://ollama:11434",
                    "llm_max_tokens": "10",
                }
            )

    def test_llm_temperature_bounds(self):
        """Temperature range is 0-2."""
        with pytest.raises(RuntimeError, match="range"):
            tasks._parse_analysis_config(
                {
                    "llm_provider": "ollama",
                    "llm_model": "llama3.1:8b-instruct",
                    "ollama_url": "http://ollama:11434",
                    "llm_temperature": "3.0",
                }
            )


# ---------------------------------------------------------------------------
# _http_json_post timeout and error handling
# ---------------------------------------------------------------------------


class TestHttpJsonPost:
    """Validate _http_json_post properly wraps network errors."""

    def test_url_timeout_raises_runtime_error(self, monkeypatch):
        """Socket timeout from slow Ollama must become a clear RuntimeError."""

        def fake_urlopen(request, timeout=None):
            raise urllib_error.URLError(socket.timeout("timed out"))

        monkeypatch.setattr("src.tasks.urllib_request.urlopen", fake_urlopen)

        with pytest.raises(RuntimeError, match="LLM request failed"):
            tasks._http_json_post(
                url="http://ollama:11434/api/chat",
                payload={"model": "test"},
                timeout_seconds=5,
            )

    def test_connection_refused_raises_runtime_error(self, monkeypatch):
        """Ollama not running must give a clear RuntimeError, not a raw exception."""

        def fake_urlopen(request, timeout=None):
            raise urllib_error.URLError(ConnectionRefusedError("Connection refused"))

        monkeypatch.setattr("src.tasks.urllib_request.urlopen", fake_urlopen)

        with pytest.raises(RuntimeError, match="LLM request failed"):
            tasks._http_json_post(
                url="http://ollama:11434/api/chat",
                payload={"model": "test"},
                timeout_seconds=45,
            )

    def test_http_500_raises_runtime_error(self, monkeypatch):
        """Ollama internal error => clear RuntimeError with status code."""
        import io

        def fake_urlopen(request, timeout=None):
            exc = urllib_error.HTTPError(
                url="http://ollama:11434/api/chat",
                code=500,
                msg="Internal Server Error",
                hdrs={},
                fp=io.BytesIO(b"model not found"),
            )
            raise exc

        monkeypatch.setattr("src.tasks.urllib_request.urlopen", fake_urlopen)

        with pytest.raises(RuntimeError, match="LLM HTTP error.*500.*model not found"):
            tasks._http_json_post(
                url="http://ollama:11434/api/chat",
                payload={"model": "test"},
                timeout_seconds=45,
            )

    def test_invalid_json_response_raises_runtime_error(self, monkeypatch):
        """If Ollama returns garbage, we get a clear error."""
        import io
        from http.client import HTTPResponse
        from unittest.mock import MagicMock

        mock_response = MagicMock()
        mock_response.read.return_value = b"not json at all"
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = lambda s, *a: None

        monkeypatch.setattr("src.tasks.urllib_request.urlopen", lambda *a, **kw: mock_response)

        with pytest.raises(RuntimeError, match="not valid JSON"):
            tasks._http_json_post(
                url="http://ollama:11434/api/chat",
                payload={"model": "test"},
                timeout_seconds=45,
            )


# ---------------------------------------------------------------------------
# _generate_llm_summary — Ollama path
# ---------------------------------------------------------------------------


class TestGenerateLLMSummaryOllama:
    """Validate the Ollama code path in _generate_llm_summary."""

    @staticmethod
    def _make_ollama_config(timeout_seconds=45):
        return tasks.LLMConfig(
            provider="ollama",
            model="llama3.1:8b-instruct",
            endpoint="http://ollama:11434",
            api_key=None,
            timeout_seconds=timeout_seconds,
            max_tokens=512,
            temperature=0.0,
        )

    def test_ollama_success_returns_content(self, monkeypatch):
        """Ollama success path: response.message.content is returned."""

        def fake_http_post(url, payload, timeout_seconds, headers=None):
            assert "/api/chat" in url
            assert payload["model"] == "llama3.1:8b-instruct"
            assert payload["stream"] is False
            assert any(
                msg["role"] == "system" for msg in payload["messages"]
            )
            return {
                "message": {
                    "content": '{"overview":"test malware","capabilities":[],'
                    '"iocs":[],"notable_functions":[],"notable_strings":[],'
                    '"confidence":"high"}'
                }
            }

        monkeypatch.setattr("src.tasks._http_json_post", fake_http_post)

        result = tasks._generate_llm_summary(self._make_ollama_config(), {"summary": {}})
        parsed = json.loads(result)
        assert "overview" in parsed
        assert "confidence" in parsed

    def test_ollama_timeout_propagates(self, monkeypatch):
        """When _http_json_post raises a timeout, it propagates as RuntimeError."""

        def fake_http_post(url, payload, timeout_seconds, headers=None):
            raise RuntimeError("LLM request failed: timed out")

        monkeypatch.setattr("src.tasks._http_json_post", fake_http_post)

        with pytest.raises(RuntimeError, match="timed out"):
            tasks._generate_llm_summary(self._make_ollama_config(timeout_seconds=5), {"summary": {}})

    def test_ollama_missing_message_content(self, monkeypatch):
        """Ollama returns JSON without message.content => clear error."""

        def fake_http_post(url, payload, timeout_seconds, headers=None):
            return {"done": True}

        monkeypatch.setattr("src.tasks._http_json_post", fake_http_post)

        with pytest.raises(RuntimeError, match="message.content"):
            tasks._generate_llm_summary(self._make_ollama_config(), {"summary": {}})

    def test_ollama_uses_configured_timeout(self, monkeypatch):
        """The timeout_seconds from LLMConfig is passed to _http_json_post."""
        captured = {}

        def fake_http_post(url, payload, timeout_seconds, headers=None):
            captured["timeout"] = timeout_seconds
            return {"message": {"content": "{}"}}

        monkeypatch.setattr("src.tasks._http_json_post", fake_http_post)

        tasks._generate_llm_summary(self._make_ollama_config(timeout_seconds=180), {"summary": {}})
        assert captured["timeout"] == 180

    def test_ollama_system_prompt_asks_for_structured_keys(self, monkeypatch):
        """System prompt must request the keys needed for useful analysis output."""
        captured_payload = {}

        def fake_http_post(url, payload, timeout_seconds, headers=None):
            captured_payload.update(payload)
            return {"message": {"content": "{}"}}

        monkeypatch.setattr("src.tasks._http_json_post", fake_http_post)

        tasks._generate_llm_summary(self._make_ollama_config(), {"summary": {}})

        system_msg = next(
            m["content"] for m in captured_payload["messages"] if m["role"] == "system"
        )
        for key in ["overview", "capabilities", "iocs", "notable_functions", "notable_strings", "confidence"]:
            assert key in system_msg, f"System prompt missing key: {key}"


# ---------------------------------------------------------------------------
# _build_llm_payload — validate sufficient context for good analysis
# ---------------------------------------------------------------------------


class TestBuildLLMPayload:
    """Ensure the payload sent to the LLM has enough context to produce useful output."""

    @staticmethod
    def _write_artifacts(tmp_path):
        """Write realistic Ghidra artifacts for testing."""
        summary_path = tmp_path / "summary.json"
        summary_path.write_text(
            json.dumps(
                {
                    "program_name": "suspicious.exe",
                    "language_id": "x86:LE:64:default",
                    "compiler_spec_id": "windows",
                    "md5": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb924"
                    "27ae41e4649b934ca495991b7852b855",
                    "entry_points": ["0x00401000"],
                    "imports": ["kernel32.dll::CreateFileA", "ws2_32.dll::connect"],
                    "exports": [],
                    "function_count": 42,
                    "strings_count": 150,
                }
            ),
            encoding="utf-8",
        )

        functions_path = tmp_path / "functions.jsonl"
        functions = [
            {
                "name": "entry",
                "entry_point": "0x00401000",
                "size": 120,
                "signature": "int entry(void)",
                "callers_count": 0,
                "callees_count": 5,
                "callers": [],
                "callees": ["FUN_00401100", "FUN_00401300"],
                "imported_calls": [],
                "string_refs": [],
            },
            {
                "name": "FUN_00401100",
                "entry_point": "0x00401100",
                "size": 340,
                "signature": "void FUN_00401100(char * param_1, int param_2)",
                "callers_count": 1,
                "callees_count": 3,
                "callers": ["entry"],
                "callees": ["connect", "socket", "send"],
                "imported_calls": ["ws2_32.dll::connect", "ws2_32.dll::socket", "ws2_32.dll::send"],
                "string_refs": ["http://evil.example.com/c2"],
            },
            {
                "name": "FUN_00401300",
                "entry_point": "0x00401300",
                "size": 85,
                "signature": "int FUN_00401300(void)",
                "callers_count": 2,
                "callees_count": 1,
                "callers": ["entry", "FUN_00401100"],
                "callees": ["CreateFileA"],
                "imported_calls": ["KERNEL32.DLL::CreateFileA"],
                "string_refs": [],
            },
        ]
        functions_path.write_text(
            "\n".join(json.dumps(f) for f in functions) + "\n", encoding="utf-8"
        )

        strings_path = tmp_path / "strings.json"
        strings_path.write_text(
            json.dumps(
                {
                    "count": 4,
                    "strings": [
                        {"address": "0x00405000", "value": "C:\\Windows\\Temp\\payload.dll", "ref_count": 2},
                        {"address": "0x00405040", "value": "http://evil.example.com/c2", "ref_count": 1},
                        {"address": "0x00405080", "value": "cmd.exe /c whoami", "ref_count": 1},
                        {"address": "0x004050c0", "value": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "ref_count": 1},
                    ],
                }
            ),
            encoding="utf-8",
        )

        decompile_path = tmp_path / "decompile.jsonl"
        decompile_records = [
            {
                "name": "entry",
                "entry_point": "0x00401000",
                "signature": "int entry(void)",
                "status": "ok",
                "decompile": (
                    "int entry(void) {\n"
                    "  FUN_00401100(\"http://evil.example.com/c2\", 443);\n"
                    "  FUN_00401300();\n"
                    "  return 0;\n"
                    "}\n"
                ),
            },
            {
                "name": "FUN_00401100",
                "entry_point": "0x00401100",
                "signature": "void FUN_00401100(char * param_1, int param_2)",
                "status": "ok",
                "decompile": (
                    "void FUN_00401100(char * param_1, int param_2) {\n"
                    "  SOCKET s = socket(AF_INET, SOCK_STREAM, 0);\n"
                    "  connect(s, &server_addr, sizeof(server_addr));\n"
                    "  send(s, beacon_data, beacon_len, 0);\n"
                    "  recv(s, response_buf, 4096, 0);\n"
                    "}\n"
                ),
            },
        ]
        decompile_path.write_text(
            "\n".join(json.dumps(r) for r in decompile_records) + "\n", encoding="utf-8"
        )

        return str(summary_path), str(functions_path), str(strings_path), str(decompile_path)

    def test_payload_includes_all_artifact_sections(self, tmp_path):
        """The LLM payload must include summary, functions, strings, and decompile."""
        summary, functions, strings, decompile = self._write_artifacts(tmp_path)
        payload = tasks._build_llm_payload(summary, functions, strings, decompile)

        assert "summary" in payload
        assert "functions_preview" in payload
        assert "strings_preview" in payload
        assert "decompile_preview" in payload

    def test_payload_summary_has_key_metadata(self, tmp_path):
        """Summary should carry enough metadata for the LLM to identify the binary."""
        summary, functions, strings, decompile = self._write_artifacts(tmp_path)
        payload = tasks._build_llm_payload(summary, functions, strings, decompile)

        s = payload["summary"]
        assert s["program_name"] == "suspicious.exe"
        assert "md5" in s
        assert "sha256" in s
        assert "imports" in s
        assert s["function_count"] == 42

    def test_payload_functions_preview_populated(self, tmp_path):
        """Functions preview must contain function records ranked by significance."""
        summary, functions, strings, decompile = self._write_artifacts(tmp_path)
        payload = tasks._build_llm_payload(summary, functions, strings, decompile)

        funcs = payload["functions_preview"]
        assert len(funcs) == 3
        # FUN_00401100 should rank highest (large, has imports + strings)
        assert funcs[0]["name"] == "FUN_00401100"
        assert "signature" in funcs[0]

    def test_payload_strings_preview_populated(self, tmp_path):
        """Strings preview must contain suspicious strings for the LLM to flag."""
        summary, functions, strings, decompile = self._write_artifacts(tmp_path)
        payload = tasks._build_llm_payload(summary, functions, strings, decompile)

        string_values = [s["value"] for s in payload["strings_preview"]]
        assert any("evil.example.com" in v for v in string_values)
        assert any("cmd.exe" in v for v in string_values)

    def test_payload_decompile_preview_has_code(self, tmp_path):
        """Decompile preview must contain actual C pseudocode for the LLM to analyze."""
        summary, functions, strings, decompile = self._write_artifacts(tmp_path)
        payload = tasks._build_llm_payload(summary, functions, strings, decompile)

        decomps = payload["decompile_preview"]
        assert len(decomps) == 2
        # Both decompiled functions should be present
        all_code = " ".join(d["decompile"] for d in decomps)
        assert "connect" in all_code
        assert "socket" in all_code
        # FUN_00401100 should rank first (has imports + strings)
        assert decomps[0]["name"] == "FUN_00401100"
        assert decomps[0]["status"] == "ok"

    def test_payload_without_decompile(self, tmp_path):
        """When decompile_path is None, payload should still be valid."""
        summary, functions, strings, _ = self._write_artifacts(tmp_path)
        payload = tasks._build_llm_payload(summary, functions, strings, None)

        assert "summary" in payload
        assert "functions_preview" in payload
        assert "strings_preview" in payload
        assert "decompile_preview" not in payload

    def test_payload_respects_function_limit(self, tmp_path):
        """Functions preview is capped at 80 entries."""
        summary_path, _, strings_path, _ = self._write_artifacts(tmp_path)

        big_functions = tmp_path / "big_functions.jsonl"
        lines = []
        for i in range(100):
            lines.append(json.dumps({"name": f"FUN_{i:08x}", "entry_point": f"0x{i:08x}"}))
        big_functions.write_text("\n".join(lines) + "\n", encoding="utf-8")

        payload = tasks._build_llm_payload(summary_path, str(big_functions), strings_path, None)
        assert len(payload["functions_preview"]) == 80

    def test_payload_respects_decompile_limit(self, tmp_path):
        """Decompile preview is capped at 30 entries."""
        summary_path, functions_path, strings_path, _ = self._write_artifacts(tmp_path)

        big_decompile = tmp_path / "big_decompile.jsonl"
        lines = []
        for i in range(50):
            lines.append(
                json.dumps(
                    {"name": f"FUN_{i}", "entry_point": f"0x{i:08x}", "status": "ok", "decompile": f"void FUN_{i}() {{}}"}
                )
            )
        big_decompile.write_text("\n".join(lines) + "\n", encoding="utf-8")

        payload = tasks._build_llm_payload(
            summary_path, functions_path, strings_path, str(big_decompile)
        )
        assert len(payload["decompile_preview"]) == 30


# ---------------------------------------------------------------------------
# _extract_openai_content edge cases
# ---------------------------------------------------------------------------


class TestExtractOpenAIContent:
    """Validate OpenAI response parsing for various formats."""

    def test_standard_string_content(self):
        response = {"choices": [{"message": {"content": '{"overview":"test"}'}}]}
        assert tasks._extract_openai_content(response) == '{"overview":"test"}'

    def test_list_content_parts(self):
        response = {
            "choices": [
                {"message": {"content": [{"text": "part1"}, {"text": "part2"}]}}
            ]
        }
        assert tasks._extract_openai_content(response) == "part1\npart2"

    def test_empty_choices_raises(self):
        with pytest.raises(RuntimeError, match="missing choices"):
            tasks._extract_openai_content({"choices": []})

    def test_missing_message_raises(self):
        with pytest.raises(RuntimeError, match="missing choices.*message"):
            tasks._extract_openai_content({"choices": [{"index": 0}]})

    def test_null_content_raises(self):
        with pytest.raises(RuntimeError, match="unsupported"):
            tasks._extract_openai_content({"choices": [{"message": {"content": None}}]})


# ---------------------------------------------------------------------------
# End-to-end: command() with LLM timeout failure
# ---------------------------------------------------------------------------


def test_command_ollama_timeout_aborts_gracefully(monkeypatch, tmp_path):
    """When Ollama times out (slow CPU), the task fails with a clear RuntimeError
    mentioning the timeout — not a cryptic traceback."""
    input_file = tmp_path / "sample.bin"
    input_file.write_bytes(b"MZ")

    output_dir = tmp_path / "out"
    output_dir.mkdir()

    def fake_create_output_file(output_path, display_name, data_type=None):
        path = Path(output_path) / display_name
        return DummyResultFile(path=path, display_name=display_name)

    monkeypatch.setattr("src.tasks.create_output_file", fake_create_output_file)
    monkeypatch.setattr("src.tasks.subprocess.run", _fake_subprocess_run)
    monkeypatch.setattr(tasks.command, "send_event", lambda *args, **kwargs: None)

    def fake_generate_llm_timeout(llm_config, payload):
        raise RuntimeError(
            f"LLM request failed: timed out after {llm_config.timeout_seconds}s"
        )

    monkeypatch.setattr("src.tasks._generate_llm_summary", fake_generate_llm_timeout)

    with pytest.raises(RuntimeError, match="timed out"):
        tasks.command.run(
            pipe_result=None,
            input_files=[{"path": str(input_file), "display_name": "sample.bin"}],
            output_path=str(output_dir),
            workflow_id="wf-timeout",
            task_config={
                "timeout_seconds": "600",
                "decompile_mode": "entrypoints",
                "export_formats": "json",
                "llm_provider": "ollama",
                "llm_model": "llama3.1:8b-instruct",
                "ollama_url": "http://ollama:11434",
                "llm_timeout_seconds": "120",
            },
        )


def test_command_with_decompile_and_llm_produces_complete_output(monkeypatch, tmp_path):
    """Full pipeline: decompile + LLM produces all expected artifacts with good content."""
    input_file = tmp_path / "sample.bin"
    input_file.write_bytes(b"MZ")

    output_dir = tmp_path / "out"
    output_dir.mkdir()

    def fake_create_output_file(output_path, display_name, data_type=None):
        path = Path(output_path) / display_name
        return DummyResultFile(path=path, display_name=display_name)

    # Write realistic artifact content in subprocess fake
    def fake_subprocess_run_realistic(args, capture_output, text, check, timeout, env):
        class FakeProcess:
            def __init__(self):
                self.returncode = 0
                self.stdout = "analysis completed"
                self.stderr = ""

        for index, token in enumerate(args):
            if token != "-postScript":
                continue
            script_name = args[index + 1]
            output_file = Path(args[index + 2])
            output_file.parent.mkdir(parents=True, exist_ok=True)

            if "Summary" in script_name:
                output_file.write_text(
                    json.dumps(
                        {
                            "program_name": "sample.bin",
                            "language_id": "x86:LE:64:default",
                            "md5": "abc123",
                            "sha256": "def456",
                            "imports": ["kernel32.dll::VirtualAlloc", "ws2_32.dll::send"],
                            "function_count": 10,
                            "strings_count": 25,
                        }
                    ),
                    encoding="utf-8",
                )
            elif "Functions" in script_name:
                output_file.write_text(
                    json.dumps({"name": "main", "entry_point": "0x401000", "size": 200})
                    + "\n",
                    encoding="utf-8",
                )
            elif "Strings" in script_name:
                output_file.write_text(
                    json.dumps(
                        {
                            "count": 2,
                            "strings": [
                                {"address": "0x405000", "value": "http://c2.example.com", "ref_count": 1},
                                {"address": "0x405040", "value": "cmd.exe", "ref_count": 1},
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
            elif "Decompile" in script_name:
                output_file.write_text(
                    json.dumps(
                        {
                            "name": "main",
                            "status": "ok",
                            "decompile": "int main() { connect(s, addr, len); return 0; }",
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )

        return FakeProcess()

    llm_response = json.dumps(
        {
            "overview": "Network-capable binary that connects to a remote C2 server.",
            "capabilities": ["network_communication", "command_execution"],
            "iocs": ["http://c2.example.com"],
            "notable_functions": [{"name": "main", "purpose": "Establishes C2 connection"}],
            "notable_strings": ["http://c2.example.com", "cmd.exe"],
            "confidence": "high",
        }
    )

    def fake_generate_llm(llm_config, payload):
        # Verify the payload has the data the LLM needs
        assert "summary" in payload
        assert "functions_preview" in payload
        assert "strings_preview" in payload
        assert "decompile_preview" in payload
        assert len(payload["decompile_preview"]) > 0
        return llm_response

    def fake_generate_annotations(llm_config, functions_path, decompile_path, summary_path):
        return [
            {
                "name": "main",
                "likely_name": "establish_c2_connection",
                "purpose": "Connects to remote C2 server.",
                "confidence": "high",
                "evidence": ["calls connect()"],
            }
        ]

    monkeypatch.setattr("src.tasks.create_output_file", fake_create_output_file)
    monkeypatch.setattr("src.tasks.subprocess.run", fake_subprocess_run_realistic)
    monkeypatch.setattr("src.tasks._generate_llm_summary", fake_generate_llm)
    monkeypatch.setattr("src.tasks._generate_function_annotations", fake_generate_annotations)
    monkeypatch.setattr(tasks.command, "send_event", lambda *args, **kwargs: None)

    result = tasks.command.run(
        pipe_result=None,
        input_files=[{"path": str(input_file), "display_name": "sample.bin"}],
        output_path=str(output_dir),
        workflow_id="wf-full",
        task_config={
            "timeout_seconds": "600",
            "decompile_mode": "entrypoints",
            "export_formats": "json+decompile",
            "llm_provider": "ollama",
            "llm_model": "llama3.1:8b-instruct",
            "ollama_url": "http://ollama:11434",
            "llm_timeout_seconds": "180",
        },
    )

    assert isinstance(result, str)

    # Verify AI summary was written with structured content
    ai_files = list(output_dir.glob("*.ai-summary.json"))
    assert ai_files, "AI summary file must be created"
    ai_summary = json.loads(ai_files[0].read_text(encoding="utf-8"))
    assert ai_summary["provider"] == "ollama"
    assert ai_summary["model"] == "llama3.1:8b-instruct"
    assert ai_summary["summary_valid_json"] is True

    # The summary field is now stored as a parsed dict (validated JSON)
    parsed_summary = ai_summary["summary"]
    assert isinstance(parsed_summary, dict)
    assert "overview" in parsed_summary
    assert "capabilities" in parsed_summary
    assert "iocs" in parsed_summary
    assert "notable_functions" in parsed_summary
    assert parsed_summary["confidence"] == "high"

    # Verify decompile artifact exists
    decompile_files = list(output_dir.glob("*.decompile.jsonl"))
    assert decompile_files, "Decompile file must be created"

    # Verify annotations artifact exists
    annotation_files = list(output_dir.glob("*.ai-annotations.jsonl"))
    assert annotation_files, "AI annotations file must be created"
    ann_content = annotation_files[0].read_text(encoding="utf-8").strip()
    annotations = [json.loads(line) for line in ann_content.split("\n") if line.strip()]
    assert len(annotations) == 1
    assert annotations[0]["likely_name"] == "establish_c2_connection"
    assert annotations[0]["confidence"] == "high"

    # Verify manifest references all artifacts
    manifest = json.loads((output_dir / "ghidra_manifest.json").read_text(encoding="utf-8"))
    sample = manifest["samples"][0]
    assert "decompile" in sample
    assert "ai_summary" in sample
    assert "ai_annotations" in sample
    assert manifest["llm"]["provider"] == "ollama"
    assert manifest["decompile_mode"] == "entrypoints"
    assert manifest["export_format"] == "json+decompile"


# ---------------------------------------------------------------------------
# _score_function — significance ranking
# ---------------------------------------------------------------------------


class TestScoreFunction:
    """Validate function significance scoring."""

    def test_function_with_imports_and_strings_scores_highest(self):
        """Functions with imported API calls and string refs should rank highest."""
        plain = {"size": 100, "callers_count": 1, "imported_calls": [], "string_refs": []}
        has_imports = {"size": 100, "callers_count": 1, "imported_calls": ["connect"], "string_refs": []}
        has_both = {
            "size": 100, "callers_count": 1,
            "imported_calls": ["connect", "socket"],
            "string_refs": ["http://evil.com"],
        }

        assert tasks._score_function(has_imports) > tasks._score_function(plain)
        assert tasks._score_function(has_both) > tasks._score_function(has_imports)

    def test_larger_functions_score_higher(self):
        small = {"size": 10, "callers_count": 0, "imported_calls": [], "string_refs": []}
        large = {"size": 500, "callers_count": 0, "imported_calls": [], "string_refs": []}
        assert tasks._score_function(large) > tasks._score_function(small)

    def test_more_callers_score_higher(self):
        few = {"size": 100, "callers_count": 1, "imported_calls": [], "string_refs": []}
        many = {"size": 100, "callers_count": 10, "imported_calls": [], "string_refs": []}
        assert tasks._score_function(many) > tasks._score_function(few)

    def test_empty_function_has_nonzero_score(self):
        minimal = {}
        assert tasks._score_function(minimal) >= 1


class TestRankFunctions:
    """Validate function ranking order."""

    def test_ranks_by_score_descending(self):
        functions = [
            {"name": "small", "size": 10},
            {"name": "large_with_imports", "size": 500, "imported_calls": ["connect"]},
            {"name": "medium", "size": 200},
        ]
        ranked = tasks._rank_functions(functions)
        assert ranked[0]["name"] == "large_with_imports"
        assert ranked[-1]["name"] == "small"


# ---------------------------------------------------------------------------
# _parse_annotation_response — LLM annotation validation
# ---------------------------------------------------------------------------


class TestParseAnnotationResponse:
    """Validate parsing and validation of LLM annotation JSON."""

    def test_valid_json_array(self):
        raw = json.dumps([
            {
                "name": "FUN_001",
                "likely_name": "get_socket_connection",
                "purpose": "Creates a TCP socket and connects to a server.",
                "confidence": "high",
                "evidence": ["calls socket()", "calls connect()"],
            }
        ])
        result = tasks._parse_annotation_response(raw)
        assert len(result) == 1
        assert result[0]["likely_name"] == "get_socket_connection"
        assert result[0]["confidence"] == "high"
        assert len(result[0]["evidence"]) == 2

    def test_wrapped_in_annotations_key(self):
        raw = json.dumps({"annotations": [
            {
                "name": "FUN_002",
                "likely_name": "decrypt_config",
                "purpose": "Decrypts configuration data.",
                "confidence": "medium",
                "evidence": [],
            }
        ]})
        result = tasks._parse_annotation_response(raw)
        assert len(result) == 1
        assert result[0]["likely_name"] == "decrypt_config"

    def test_markdown_fenced_json(self):
        raw = '```json\n[{"name":"FUN_003","likely_name":"main_loop","purpose":"Event loop.","confidence":"low","evidence":[]}]\n```'
        result = tasks._parse_annotation_response(raw)
        assert len(result) == 1
        assert result[0]["likely_name"] == "main_loop"

    def test_missing_required_keys_filtered(self):
        raw = json.dumps([
            {"name": "FUN_004", "likely_name": "ok", "purpose": "test", "confidence": "high"},
            {"name": "FUN_005"},  # missing required keys
        ])
        result = tasks._parse_annotation_response(raw)
        assert len(result) == 1

    def test_invalid_json_returns_empty(self):
        result = tasks._parse_annotation_response("not valid json at all")
        assert result == []

    def test_invalid_confidence_corrected_to_low(self):
        raw = json.dumps([
            {
                "name": "FUN_006",
                "likely_name": "something",
                "purpose": "does stuff",
                "confidence": "very_high",
                "evidence": [],
            }
        ])
        result = tasks._parse_annotation_response(raw)
        assert len(result) == 1
        assert result[0]["confidence"] == "low"

    def test_non_list_evidence_becomes_empty(self):
        raw = json.dumps([
            {
                "name": "FUN_007",
                "likely_name": "test_fn",
                "purpose": "testing",
                "confidence": "medium",
                "evidence": "not a list",
            }
        ])
        result = tasks._parse_annotation_response(raw)
        assert len(result) == 1
        assert result[0]["evidence"] == []


# ---------------------------------------------------------------------------
# _validate_llm_json
# ---------------------------------------------------------------------------


class TestValidateLLMJson:
    """Validate LLM summary JSON parsing and validation."""

    def test_valid_json_object(self):
        result = tasks._validate_llm_json('{"overview": "test", "confidence": "high"}')
        assert result is not None
        assert result["overview"] == "test"

    def test_markdown_fenced_json(self):
        raw = '```json\n{"overview": "fenced"}\n```'
        result = tasks._validate_llm_json(raw)
        assert result is not None
        assert result["overview"] == "fenced"

    def test_invalid_json_returns_none(self):
        result = tasks._validate_llm_json("this is not json")
        assert result is None

    def test_non_object_returns_none(self):
        result = tasks._validate_llm_json("[1, 2, 3]")
        assert result is None


# ---------------------------------------------------------------------------
# _build_annotation_chunks
# ---------------------------------------------------------------------------


class TestBuildAnnotationChunks:
    """Validate annotation chunk building for LLM input."""

    @staticmethod
    def _write_test_artifacts(tmp_path):
        summary_path = tmp_path / "summary.json"
        summary_path.write_text(json.dumps({
            "program_name": "test.exe",
            "language_id": "x86:LE:64:default",
            "imports": [{"library": "ws2_32.dll", "symbol": "connect"}],
        }), encoding="utf-8")

        functions_path = tmp_path / "functions.jsonl"
        funcs = [
            {
                "name": "FUN_001", "entry_point": "0x001", "size": 200,
                "callers": ["entry"], "callees": ["connect"],
                "imported_calls": ["ws2_32.dll::connect"],
                "string_refs": ["http://evil.com"],
            },
            {
                "name": "FUN_002", "entry_point": "0x002", "size": 50,
                "callers": [], "callees": [],
                "imported_calls": [], "string_refs": [],
            },
        ]
        functions_path.write_text(
            "\n".join(json.dumps(f) for f in funcs) + "\n", encoding="utf-8"
        )

        decompile_path = tmp_path / "decompile.jsonl"
        decs = [
            {
                "name": "FUN_001", "entry_point": "0x001", "status": "ok",
                "decompile": "void FUN_001() { connect(s, addr, len); }",
            },
            {
                "name": "FUN_002", "entry_point": "0x002", "status": "ok",
                "decompile": "int FUN_002() { return 0; }",
            },
        ]
        decompile_path.write_text(
            "\n".join(json.dumps(d) for d in decs) + "\n", encoding="utf-8"
        )

        return str(summary_path), str(functions_path), str(decompile_path)

    def test_chunks_include_binary_context(self, tmp_path):
        summary, functions, decompile = self._write_test_artifacts(tmp_path)
        chunks = tasks._build_annotation_chunks(functions, decompile, summary)
        assert len(chunks) >= 1
        assert "binary_context" in chunks[0]
        assert chunks[0]["binary_context"]["program_name"] == "test.exe"

    def test_chunks_include_enriched_functions(self, tmp_path):
        summary, functions, decompile = self._write_test_artifacts(tmp_path)
        chunks = tasks._build_annotation_chunks(functions, decompile, summary)
        all_funcs = [f for chunk in chunks for f in chunk["functions"]]
        assert len(all_funcs) == 2
        # FUN_001 should come first (higher score)
        assert all_funcs[0]["name"] == "FUN_001"
        assert "decompile" in all_funcs[0]
        assert "imported_calls" in all_funcs[0]
        assert "string_refs" in all_funcs[0]

    def test_chunking_respects_max_per_chunk(self, tmp_path):
        summary, functions, decompile = self._write_test_artifacts(tmp_path)
        chunks = tasks._build_annotation_chunks(
            functions, decompile, summary, max_functions_per_chunk=1
        )
        assert len(chunks) == 2
        assert len(chunks[0]["functions"]) == 1
        assert len(chunks[1]["functions"]) == 1


# ---------------------------------------------------------------------------
# Focused mode parsing
# ---------------------------------------------------------------------------


class TestFocusedMode:
    """Validate focused decompile mode configuration."""

    def test_focused_mode_accepted(self):
        config = tasks._parse_analysis_config({"decompile_mode": "focused"})
        assert config.decompile_mode == "focused"
        assert config.focused_decompile_limit == 80

    def test_focused_decompile_limit_custom(self):
        config = tasks._parse_analysis_config({
            "decompile_mode": "focused",
            "focused_decompile_limit": "120",
        })
        assert config.focused_decompile_limit == 120

    def test_focused_decompile_limit_bounds(self):
        with pytest.raises(RuntimeError, match="range"):
            tasks._parse_analysis_config({
                "decompile_mode": "focused",
                "focused_decompile_limit": "5",
            })

    def test_focused_mode_in_headless_command(self, tmp_path):
        config = tasks.AnalysisConfig(
            timeout_seconds=600,
            decompile_mode="focused",
            export_format="json+decompile",
            include_decompile=True,
            keep_project=False,
            analyze_headless_bin="/opt/ghidra/support/analyzeHeadless",
            script_path="/opt/ghidra_scripts",
            max_memory="4G",
            ghidra_version="11.2.1",
            scripts_git_sha="deadbeef",
            active_processors=2,
            focused_decompile_limit=80,
            llm_config=None,
        )

        command = tasks._build_headless_command(
            config=config,
            project_directory=tmp_path,
            project_name="TestProj",
            input_file_path="/work/input/sample.bin",
            summary_path="/work/output/summary.json",
            functions_path="/work/output/functions.jsonl",
            strings_path="/work/output/strings.json",
            decompile_path="/work/output/decompile.jsonl",
        )

        # Verify focused:80 is passed to Ghidra script
        assert "focused:80" in command
        assert "ExportDecompileJsonl.java" in command
