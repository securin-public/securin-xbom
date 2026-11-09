"""Python framework extractors — FastAPI, Flask, Django."""

from __future__ import annotations

import re
from pathlib import Path

from xbom.modules.apibom.extractors.base import (
    ApiEndpoint,
    FrameworkExtractor,
    _load_rules,
)

# ---------------------------------------------------------------------------
# Cached compiled patterns
# ---------------------------------------------------------------------------

_fw_config: dict | None = None


def _get_fw_config() -> dict:
    global _fw_config
    if _fw_config is None:
        _fw_config = _load_rules("frameworks")["python"]
    return _fw_config


def _compile_detect(fw: str) -> list[re.Pattern[str]]:
    return [re.compile(p) for p in _get_fw_config()[fw]["detect"]]


def _compile_auth(fw: str) -> list[re.Pattern[str]]:
    return [re.compile(p) for p in _get_fw_config()[fw].get("auth_indicators", [])]


# ---------------------------------------------------------------------------
# FastAPI extractor
# ---------------------------------------------------------------------------


class FastAPIExtractor(FrameworkExtractor):
    """Extract routes from FastAPI applications."""

    @property
    def framework_name(self) -> str:
        return "fastapi"

    def detect(self, content: str) -> bool:
        return any(p.search(content) for p in _compile_detect("fastapi"))

    def extract(self, file_path: Path, content: str, rel_path: str) -> list[ApiEndpoint]:
        cfg = _get_fw_config()["fastapi"]
        endpoints: list[ApiEndpoint] = []
        lines = content.splitlines()

        # Detect router prefix in file
        prefix = ""
        for pat_str in cfg.get("router_prefix", []):
            m = re.search(pat_str, content)
            if m:
                prefix = m.group(1).rstrip("/")
                break

        # Auth in FastAPI(dependencies=[...]) / APIRouter(dependencies=[...]) covers every route
        auth_patterns = _compile_auth("fastapi")
        file_has_auth = _has_app_level_auth(content, auth_patterns)

        # Extract routes
        for route_cfg in cfg["routes"]:
            pattern = re.compile(route_cfg["pattern"])
            for i, line in enumerate(lines, 1):
                m = pattern.search(line)
                if not m:
                    continue

                method_grp = route_cfg.get("method_group")
                path_grp = route_cfg.get("path_group")

                method = m.group(method_grp).upper() if method_grp and m.group(method_grp) else "*"
                path = m.group(path_grp) if path_grp and m.group(path_grp) else ""

                if not path:
                    continue

                full_path = prefix + path if prefix else path

                # Check for auth on this specific endpoint (its decorators and signature)
                endpoint_auth = file_has_auth or _route_has_auth(lines, i - 1, auth_patterns)

                endpoints.append(
                    ApiEndpoint(
                        path=full_path,
                        method=method,
                        framework="fastapi",
                        source_file=rel_path,
                        source_line=i,
                        category="internal-endpoint",
                        auth_detected=endpoint_auth,
                    )
                )

        # Websocket endpoints
        for ws_pat_str in cfg.get("websocket", []):
            ws_pattern = re.compile(ws_pat_str)
            for i, line in enumerate(lines, 1):
                m = ws_pattern.search(line)
                if m:
                    ws_path = prefix + m.group(1) if prefix else m.group(1)
                    endpoints.append(
                        ApiEndpoint(
                            path=ws_path,
                            method="WS",
                            framework="fastapi",
                            source_file=rel_path,
                            source_line=i,
                            category="websocket",
                        )
                    )

        return endpoints


# ---------------------------------------------------------------------------
# Flask extractor
# ---------------------------------------------------------------------------


class FlaskExtractor(FrameworkExtractor):
    """Extract routes from Flask applications."""

    @property
    def framework_name(self) -> str:
        return "flask"

    def detect(self, content: str) -> bool:
        return any(p.search(content) for p in _compile_detect("flask"))

    def extract(self, file_path: Path, content: str, rel_path: str) -> list[ApiEndpoint]:
        cfg = _get_fw_config()["flask"]
        endpoints: list[ApiEndpoint] = []
        lines = content.splitlines()

        # Detect Blueprint prefix
        prefix = ""
        for pat_str in cfg.get("router_prefix", []):
            m = re.search(pat_str, content)
            if m and m.group(1):
                prefix = m.group(1).rstrip("/")
                break

        auth_patterns = _compile_auth("flask")

        for route_cfg in cfg["routes"]:
            pattern = re.compile(route_cfg["pattern"])
            for i, line in enumerate(lines, 1):
                m = pattern.search(line)
                if not m:
                    continue

                path_grp = route_cfg.get("path_group")
                method_grp = route_cfg.get("method_group")
                default_method = route_cfg.get("default_method", "*")

                path = m.group(path_grp) if path_grp and m.group(path_grp) else ""
                if not path:
                    continue

                full_path = prefix + path if prefix else path

                # Parse methods from group (e.g. '"GET", "POST"') or use default
                if method_grp:
                    raw = m.group(method_grp) if m.lastindex and m.lastindex >= method_grp else None
                    methods = _parse_method_list(raw) if raw else [default_method]
                else:
                    methods = [default_method]

                endpoint_auth = _route_has_auth(lines, i - 1, auth_patterns)

                for method in methods:
                    endpoints.append(
                        ApiEndpoint(
                            path=full_path,
                            method=method.upper(),
                            framework="flask",
                            source_file=rel_path,
                            source_line=i,
                            category="internal-endpoint",
                            auth_detected=endpoint_auth,
                        )
                    )

        return endpoints


# ---------------------------------------------------------------------------
# Django extractor
# ---------------------------------------------------------------------------


class DjangoExtractor(FrameworkExtractor):
    """Extract routes from Django/DRF applications."""

    @property
    def framework_name(self) -> str:
        return "django"

    def detect(self, content: str) -> bool:
        return any(p.search(content) for p in _compile_detect("django"))

    def extract(self, file_path: Path, content: str, rel_path: str) -> list[ApiEndpoint]:
        cfg = _get_fw_config()["django"]
        endpoints: list[ApiEndpoint] = []
        lines = content.splitlines()

        auth_patterns = _compile_auth("django")

        for route_cfg in cfg["routes"]:
            pattern = re.compile(route_cfg["pattern"])
            for i, line in enumerate(lines, 1):
                m = pattern.search(line)
                if not m:
                    continue

                path_grp = route_cfg.get("path_group")
                method_grp = route_cfg.get("method_group")
                default_method = route_cfg.get("default_method", "*")

                path = ""
                if path_grp and m.lastindex and m.lastindex >= path_grp:
                    path = m.group(path_grp) or ""

                methods = [default_method]
                if method_grp and m.lastindex and m.lastindex >= method_grp:
                    raw = m.group(method_grp)
                    if raw:
                        methods = _parse_method_list(raw)

                # Django paths: ensure leading slash
                if path and not path.startswith("/"):
                    path = "/" + path

                endpoint_auth = _route_has_auth(lines, i - 1, auth_patterns)

                for method in methods:
                    endpoints.append(
                        ApiEndpoint(
                            path=path or "/",
                            method=method.upper(),
                            framework="django",
                            source_file=rel_path,
                            source_line=i,
                            category="internal-endpoint",
                            auth_detected=endpoint_auth,
                        )
                    )

        return endpoints


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_method_list(raw: str) -> list[str]:
    """Parse methods from a string like '"GET", "POST"' or 'GET|POST'."""
    # Strip quotes and split by comma or pipe
    cleaned = raw.replace("'", "").replace('"', "").strip()
    if "|" in cleaned:
        return [m.strip() for m in cleaned.split("|") if m.strip()]
    return [m.strip() for m in cleaned.split(",") if m.strip()]


_DEF_RE = re.compile(r"\s*(?:async\s+)?def\s")
_APP_CALL_RE = re.compile(r"\b(?:FastAPI|APIRouter)\s*\(")
_MAX_BLOCK_LINES = 50


def _route_has_auth(lines: list[str], line_idx: int, auth_patterns: list[re.Pattern[str]]) -> bool:
    """Check for auth on the route defined at lines[line_idx]."""
    block = _route_block(lines, line_idx)
    return any(p.search(block) for p in auth_patterns)


def _route_block(lines: list[str], line_idx: int) -> str:
    """Return the source that determines a single route's auth.

    For a decorator, that's the decorator stack plus the decorated function's
    signature (FastAPI dependencies live in the signature, Flask/DRF auth in the
    decorators). For anything else, e.g. Django's path("x/", login_required(view)),
    it's the call starting on that line.
    """
    limit = min(len(lines), line_idx + _MAX_BLOCK_LINES)

    if not lines[line_idx].lstrip().startswith("@"):
        end, depth = line_idx, 0
        while end < limit:
            depth += lines[end].count("(") - lines[end].count(")")
            if depth <= 0:
                break
            end += 1
        return "\n".join(lines[line_idx : end + 1])

    start = line_idx
    while start > 0 and lines[start - 1].lstrip().startswith("@"):
        start -= 1

    end = line_idx
    while end < limit and not _DEF_RE.match(lines[end]):
        end += 1
    # Extend to the line that closes the signature
    while end < limit and not lines[end].split("#", 1)[0].rstrip().endswith(":"):
        end += 1
    return "\n".join(lines[start : end + 1])


def _has_app_level_auth(content: str, auth_patterns: list[re.Pattern[str]]) -> bool:
    """Check for auth in FastAPI(...)/APIRouter(...) dependencies, which apply to all their routes."""
    for m in _APP_CALL_RE.finditer(content):
        args = _call_args(content, m.end())
        if "dependencies" in args and any(p.search(args) for p in auth_patterns):
            return True
    return False


def _call_args(content: str, start: int) -> str:
    """Return a call's argument text, from just after its "(" to the matching ")"."""
    depth = 1
    for i in range(start, len(content)):
        if content[i] == "(":
            depth += 1
        elif content[i] == ")":
            depth -= 1
            if depth == 0:
                return content[start:i]
    return content[start:]


# All Python extractors
PYTHON_EXTRACTORS: list[type[FrameworkExtractor]] = [
    FastAPIExtractor,
    FlaskExtractor,
    DjangoExtractor,
]
