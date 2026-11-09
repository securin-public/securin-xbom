"""cdxgen subprocess wrapper for SBOM and CBOM generation."""

from __future__ import annotations

import functools
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from xbom.config import get_tool_path
from xbom.utils.cyclonedx import add_tool_to_metadata, load_bom_json
from xbom.utils.subprocess import check_tool_version, run


def get_version() -> str | None:
    """Get installed cdxgen version."""
    return check_tool_version(get_tool_path("cdxgen"), "--version")


def generate_sbom(
    project_path: Path,
    *,
    project_type: str | None = None,
    include_crypto: bool = False,
    allow_build_tools: bool = False,
    verbose: bool = False,
) -> dict[str, Any]:
    """Run cdxgen to generate a CycloneDX SBOM.

    Args:
        project_path: Path to the project.
        project_type: Force a project type (e.g., "python", "java"). Auto-detected if None.
        include_crypto: If True, include crypto BOM data (Java/Python only).
        allow_build_tools: If True, let cdxgen install dependencies and run the project's
            build tools and wrappers (npm/pip install, mvnw, gradlew). This executes code
            from the scanned project, so it is only safe for trusted projects. When False,
            cdxgen runs sandboxed and builds the SBOM from manifests and lock files.
        verbose: Enable verbose logging.

    Returns:
        CycloneDX 1.6 JSON dict.
    """
    cdxgen = get_tool_path("cdxgen")

    with tempfile.TemporaryDirectory(prefix="xbom-cdxgen-") as work:
        work_dir = Path(work)
        output_path = work_dir / "bom.json"

        cmd = [
            cdxgen,
            "--spec-version", "1.6",
            "--output", str(output_path),
        ]

        if project_type:
            cmd.extend(["--type", project_type])

        if include_crypto:
            cmd.append("--include-crypto")

        env = None
        if not allow_build_tools:
            # Sandboxed cdxgen can't run package managers, so let failing extractors
            # fall back to manifest parsing instead of aborting the scan.
            cmd.extend(["--no-install-deps", "--no-fail-on-error"])
            env = _sandbox_env(work_dir)

        cmd.append(str(project_path))

        result = run(cmd, cwd=work_dir, timeout=300, verbose=verbose, env=env)

        if not result.success:
            raise RuntimeError(f"cdxgen failed (exit {result.returncode}): {result.stderr}")

        if not output_path.exists() or output_path.stat().st_size == 0:
            raise RuntimeError("cdxgen produced no output file")

        try:
            bom = load_bom_json(output_path)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"cdxgen produced invalid JSON: {e}") from e

    # Tag that cdxgen was the tool used
    version = get_version()
    add_tool_to_metadata(bom, "cdxgen", version)

    return bom


def _sandbox_env(work_dir: Path) -> dict[str, str]:
    """Environment that runs cdxgen under Node's permission model.

    Child processes are denied, so cdxgen can't run the scanned project's package
    managers or build wrappers (mvnw, gradlew, npm/pip install) even though it would
    otherwise do so for some project types regardless of --no-install-deps. Writes
    are confined to work_dir.
    """
    flag = _node_permission_flag()
    if not flag:
        raise RuntimeError(
            "Node.js >= 20 is required to run cdxgen sandboxed. Upgrade Node.js, or pass "
            "--allow-build-tools if you trust the project being scanned."
        )

    tmp_dir = work_dir / "tmp"
    tmp_dir.mkdir()
    node_options = f'{flag} --allow-fs-read=* --allow-fs-write="{work_dir}/*"'
    if existing := os.environ.get("NODE_OPTIONS"):
        node_options = f"{existing} {node_options}"

    return {
        "NODE_OPTIONS": node_options,
        "TMPDIR": str(tmp_dir),
        "TMP": str(tmp_dir),
        "TEMP": str(tmp_dir),
    }


@functools.cache
def _node_permission_flag() -> str | None:
    """Return the Node.js flag that enables the permission model, or None if unsupported."""
    result = run(["node", "--version"], timeout=10)
    m = re.match(r"v(\d+)\.(\d+)", result.stdout.strip()) if result.success else None
    if not m:
        return None
    major, minor = int(m.group(1)), int(m.group(2))
    # The flag lost its "experimental" prefix in 22.13 / 23.5
    if (major, minor) >= (23, 5) or (major == 22 and minor >= 13):
        return "--permission"
    if major >= 20:
        return "--experimental-permission"
    return None
