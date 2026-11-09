"""Tests for AI-BOM Layer 4 (CodeGraph) safety: opt-in gate and indexing a temp copy."""

from __future__ import annotations

import logging

import pytest

from xbom.models import ScanConfig
from xbom.modules.aibom import codegraph
from xbom.modules.aibom.scanner import AibomModule


def _fail(*args, **kwargs):
    raise AssertionError("CodeGraph should not run")


class TestLayer4Gate:
    def test_skipped_without_allow_build_tools(self, tmp_path, monkeypatch, caplog):
        monkeypatch.setattr(codegraph, "is_falkordb_available", _fail)
        monkeypatch.setattr(codegraph, "analyze_with_codegraph", _fail)
        config = ScanConfig(target=str(tmp_path), enrich=True)

        with caplog.at_level(logging.WARNING):
            count = AibomModule()._run_codegraph_analysis(tmp_path, {"components": []}, config)

        assert count == 0
        assert "--allow-build-tools" in caplog.text

    def test_runs_with_allow_build_tools(self, tmp_path, monkeypatch):
        monkeypatch.setattr(codegraph, "is_falkordb_available", lambda: True)
        monkeypatch.setattr(
            codegraph,
            "analyze_with_codegraph",
            lambda path, config: {"components": [{"name": "SearchTool", "category": "agent-tool"}]},
        )
        config = ScanConfig(target=str(tmp_path), enrich=True, allow_build_tools=True)
        bom = {"components": []}

        assert AibomModule()._run_codegraph_analysis(tmp_path, bom, config) == 1
        assert bom["components"][0]["name"] == "SearchTool"


class TestIndexingWorkspace:
    @pytest.fixture
    def project(self, tmp_path):
        proj = tmp_path / "myproj"
        (proj / "src").mkdir(parents=True)
        (proj / "src" / "agent.py").write_text("class Agent: ...\n")
        (proj / ".git").mkdir()
        (proj / ".git" / "config").write_text("[core]\n")
        (proj / "node_modules" / "pkg").mkdir(parents=True)
        (proj / "tests").mkdir()
        (proj / "tests" / "test_agent.py").write_text("")
        return proj

    def test_indexes_copy_and_maps_paths_back(self, project, monkeypatch):
        seen = {}

        def fake_index(path):
            seen["path"] = path
            seen["files"] = sorted(str(p.relative_to(path)) for p in path.rglob("*"))
            # The real indexer creates a venv and installs dependencies in the folder it indexes
            (path / "venv").mkdir()
            return f"xbom_{path.name}"

        def fake_agent(graph_name, config):
            work = seen["path"].resolve()
            return {
                "components": [{"name": "Agent", "file_path": f"{work}/src/agent.py"}],
                "relationships": [{"source": "Agent", "file_path": "src/agent.py"}],
                "architecture": {"pattern": "minimal", "entry_points": [f"{work}/src/agent.py:run"]},
            }

        monkeypatch.setattr(codegraph, "index_project", fake_index)
        monkeypatch.setattr(codegraph, "_run_codegraph_agent", fake_agent)
        monkeypatch.setattr(codegraph, "cleanup", lambda graph_name: None)

        result = codegraph.analyze_with_codegraph(project, ScanConfig(target=str(project)))

        # Indexed a copy with the same directory name, without ignored folders
        assert seen["path"] != project
        assert seen["path"].name == project.name
        assert seen["files"] == ["src", "src/agent.py"]
        # The project itself is untouched and the workspace is gone
        assert not (project / "venv").exists()
        assert not seen["path"].exists()
        # Paths point back at the real project; relative paths are left alone
        assert result["components"][0]["file_path"] == str(project / "src" / "agent.py")
        assert result["relationships"][0]["file_path"] == "src/agent.py"
        assert result["architecture"]["entry_points"] == [f"{project}/src/agent.py:run"]

    def test_workspace_removed_when_agent_fails(self, project, monkeypatch):
        seen = {}

        def fake_index(path):
            seen["path"] = path
            return "xbom_myproj"

        monkeypatch.setattr(codegraph, "index_project", fake_index)
        monkeypatch.setattr(codegraph, "_run_codegraph_agent", lambda *a: (_ for _ in ()).throw(RuntimeError("boom")))
        monkeypatch.setattr(codegraph, "cleanup", lambda graph_name: None)

        with pytest.raises(RuntimeError, match="boom"):
            codegraph.analyze_with_codegraph(project, ScanConfig(target=str(project)))
        assert not seen["path"].exists()
