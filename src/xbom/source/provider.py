"""Source provider abstraction for resolving scan targets to local paths."""

from __future__ import annotations

import re
import shutil
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

from xbom.config import get_token_for_provider
from xbom.models import SourceInfo
from xbom.utils.subprocess import run


class SourceProvider(ABC):
    """Base class for source providers."""

    @abstractmethod
    def resolve(self, target: str, *, branch: str | None = None, token: str | None = None) -> SourceInfo:
        """Resolve a target (path or URL) to a local path with metadata."""

    @abstractmethod
    def cleanup(self, info: SourceInfo) -> None:
        """Clean up any temporary resources."""


class LocalProvider(SourceProvider):
    """Handles local filesystem paths."""

    def resolve(self, target: str, *, branch: str | None = None, token: str | None = None) -> SourceInfo:
        path = Path(target).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Path does not exist: {path}")
        if not path.is_dir():
            raise NotADirectoryError(f"Not a directory: {path}")

        # Try to get git info if it's a git repo
        commit_sha = None
        actual_branch = None
        result = run(["git", "rev-parse", "HEAD"], cwd=path)
        if result.success:
            commit_sha = result.stdout.strip()
        result = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=path)
        if result.success:
            actual_branch = result.stdout.strip()

        return SourceInfo(
            local_path=path,
            provider="local",
            branch=actual_branch,
            commit_sha=commit_sha,
        )

    def cleanup(self, info: SourceInfo) -> None:
        pass  # Nothing to clean up for local paths


class GitProvider(SourceProvider):
    """Handles remote git repositories (GitHub, GitLab, Bitbucket)."""

    def __init__(self, provider_name: str):
        self.provider_name = provider_name

    def resolve(self, target: str, *, branch: str | None = None, token: str | None = None) -> SourceInfo:
        token = get_token_for_provider(self.provider_name, token)
        org, repo = self._parse_url(target)

        clone_url = self._build_clone_url(target, token)
        tmp_path = Path(tempfile.mkdtemp(prefix="xbom-"))
        repo_path = tmp_path / repo

        # Shallow clone for speed
        cmd = ["git", "clone", "--depth", "1"]
        if branch:
            cmd.extend(["--branch", branch])
        cmd.extend([clone_url, str(repo_path)])

        result = run(cmd, timeout=120)
        if not result.success:
            shutil.rmtree(tmp_path, ignore_errors=True)
            raise RuntimeError(f"git clone failed: {result.stderr}")

        # Get commit SHA
        commit_result = run(["git", "rev-parse", "HEAD"], cwd=repo_path)
        commit_sha = commit_result.stdout.strip() if commit_result.success else None

        # Get actual branch
        branch_result = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_path)
        actual_branch = branch_result.stdout.strip() if branch_result.success else branch

        return SourceInfo(
            local_path=repo_path,
            provider=self.provider_name,
            org=org,
            repo=repo,
            branch=actual_branch,
            commit_sha=commit_sha,
            url=target,
            temp_dir=tmp_path,
        )

    def cleanup(self, info: SourceInfo) -> None:
        # Only ever remove the directory resolve() created, never a path derived from the URL
        if info.temp_dir:
            shutil.rmtree(info.temp_dir, ignore_errors=True)

    def _parse_url(self, url: str) -> tuple[str, str]:
        """Extract org and repo from a git URL."""
        # HTTPS: https://github.com/org/repo or https://github.com/org/repo.git
        # SSH: git@github.com:org/repo.git
        for pattern in (r"https?://[^/]+/([^/]+)/([^/]+?)(?:\.git)?/?$", r"git@[^:]+:([^/]+)/([^/]+?)(?:\.git)?$"):
            match = re.match(pattern, url)
            if match:
                org, repo = match.group(1), match.group(2)
                # "." or ".." would make the clone path escape the temp dir
                if {org, repo} & {".", ".."}:
                    raise ValueError(f"Invalid repository path in git URL: {url}")
                return org, repo
        raise ValueError(f"Cannot parse git URL: {url}")

    def _build_clone_url(self, url: str, token: str | None) -> str:
        """Inject token into HTTPS clone URL if available."""
        if not token or not url.startswith(("http://", "https://")):
            return url
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise ValueError(f"Refusing to send a git token over {parts.scheme}://, use an https:// URL")
        # https://github.com/... → https://x-access-token:TOKEN@github.com/...
        host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
        netloc = f"x-access-token:{quote(token, safe='')}@{host}"
        if parts.port:
            netloc += f":{parts.port}"
        return urlunsplit(parts._replace(netloc=netloc))


# Provider registry
_PROVIDERS: dict[str, type[SourceProvider]] = {}

# Hosts whose provider, and so which env token is sent, can be inferred from the URL.
# Matched exactly: a substring match would send the token to look-alike hosts.
_KNOWN_HOSTS = {
    "github.com": "github",
    "gitlab.com": "gitlab",
    "bitbucket.org": "bitbucket",
}

_PROVIDER_NAMES = {"github", "gitlab", "bitbucket", "git"}


def detect_provider(target: str, provider: str | None = None) -> SourceProvider:
    """Auto-detect the appropriate source provider for a target.

    Args:
        target: Local path or git URL.
        provider: Explicit provider for URL targets (e.g. "gitlab" for a self-hosted
            GitLab), which also selects the env token to use.
    """
    if not target.startswith(("http://", "https://", "git@")):
        return LocalProvider()

    if provider:
        if provider not in _PROVIDER_NAMES:
            raise ValueError(f"Unknown provider '{provider}'. Valid providers: {', '.join(sorted(_PROVIDER_NAMES))}")
        return GitProvider(provider)

    host = target[len("git@") :].split(":", 1)[0] if target.startswith("git@") else urlsplit(target).hostname
    return GitProvider(_KNOWN_HOSTS.get((host or "").lower(), "git"))
