"""Tests for the cdxgen wrapper's sandboxing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from xbom.modules.sbom import cdxgen
from xbom.utils.subprocess import RunResult


@pytest.fixture
def fake_cdxgen(monkeypatch):
    """Capture cdxgen invocations and write a minimal BOM to the requested output path."""
    calls = []

    def fake_run(cmd, **kwargs):
        if cmd[0] == "node":
            return RunResult(0, "v23.11.0\n", "", cmd)
        calls.append((cmd, kwargs))
        out = Path(cmd[cmd.index("--output") + 1])
        out.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))
        return RunResult(0, "", "", cmd)

    cdxgen._node_permission_flag.cache_clear()
    monkeypatch.delenv("NODE_OPTIONS", raising=False)
    monkeypatch.setattr(cdxgen, "run", fake_run)
    monkeypatch.setattr(cdxgen, "get_version", lambda: "11.0.0")
    yield calls
    cdxgen._node_permission_flag.cache_clear()


def test_sandboxed_by_default(fake_cdxgen, tmp_path):
    cdxgen.generate_sbom(tmp_path)

    (cmd, kwargs), = fake_cdxgen
    assert "--no-install-deps" in cmd
    env = kwargs["env"]
    assert env["NODE_OPTIONS"].startswith("--permission ")
    assert "--allow-child-process" not in env["NODE_OPTIONS"]
    # Writes and temp files are confined to cdxgen's private work dir
    work_dir = str(kwargs["cwd"])
    assert f'--allow-fs-write="{work_dir}/*"' in env["NODE_OPTIONS"]
    assert env["TMPDIR"].startswith(work_dir)


def test_allow_build_tools_disables_sandbox(fake_cdxgen, tmp_path):
    cdxgen.generate_sbom(tmp_path, allow_build_tools=True)

    (cmd, kwargs), = fake_cdxgen
    assert "--no-install-deps" not in cmd
    assert kwargs["env"] is None


def test_cbom_crypto_layer_skipped_when_sandboxed(fake_cdxgen, monkeypatch, tmp_path):
    from xbom.models import ScanConfig
    from xbom.modules.cbom import cdxgen_crypto

    monkeypatch.setattr(cdxgen_crypto, "find_tool", lambda name: "/usr/bin/cdxgen")
    (tmp_path / "app.py").write_text("import hashlib\n")

    assert cdxgen_crypto.run_cdxgen_crypto(tmp_path, ScanConfig(target=str(tmp_path))) == []
    assert fake_cdxgen == []


def test_invalid_json_raises_runtime_error(monkeypatch, tmp_path):
    def fake_run(cmd, **kwargs):
        Path(cmd[cmd.index("--output") + 1]).write_text("{not json")
        return RunResult(0, "", "", cmd)

    monkeypatch.setattr(cdxgen, "run", fake_run)
    with pytest.raises(RuntimeError, match="invalid JSON"):
        cdxgen.generate_sbom(tmp_path, allow_build_tools=True)


@pytest.mark.parametrize(
    ("version", "flag"),
    [
        ("v24.1.0", "--permission"),
        ("v23.5.0", "--permission"),
        ("v23.4.0", "--experimental-permission"),
        ("v22.13.1", "--permission"),
        ("v22.12.0", "--experimental-permission"),
        ("v20.11.0", "--experimental-permission"),
        ("v18.19.0", None),
    ],
)
def test_node_permission_flag(monkeypatch, version, flag):
    monkeypatch.setattr(cdxgen, "run", lambda cmd, **kw: RunResult(0, version, "", cmd))
    cdxgen._node_permission_flag.cache_clear()
    try:
        assert cdxgen._node_permission_flag() == flag
    finally:
        cdxgen._node_permission_flag.cache_clear()


def test_old_node_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(cdxgen, "run", lambda cmd, **kw: RunResult(0, "v18.19.0", "", cmd))
    cdxgen._node_permission_flag.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="--allow-build-tools"):
            cdxgen.generate_sbom(tmp_path)
    finally:
        cdxgen._node_permission_flag.cache_clear()
