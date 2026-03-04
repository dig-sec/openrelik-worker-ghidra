import json
from pathlib import Path

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
    assert config.decompile_mode == "entrypoints"
    assert config.export_format == "json"
    assert config.include_decompile is False
    assert config.keep_project is False
    assert config.max_memory == "4G"
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
