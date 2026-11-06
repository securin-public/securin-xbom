"""Tests for source provider resolution."""

from __future__ import annotations

from pathlib import Path

import pytest

from xbom.models import SourceInfo
from xbom.source import provider as provider_mod
from xbom.source.provider import GitProvider, LocalProvider, detect_provider
from xbom.utils.subprocess import RunResult


class TestDetectProvider:
    def test_known_hosts(self):
        assert detect_provider("https://github.com/org/repo").provider_name == "github"
        assert detect_provider("https://gitlab.com/org/repo").provider_name == "gitlab"
        assert detect_provider("https://bitbucket.org/org/repo").provider_name == "bitbucket"
        assert detect_provider("git@github.com:org/repo.git").provider_name == "github"

    @pytest.mark.parametrize(
        "url",
        [
            "https://github.com.evil.example/org/repo",
            "https://evil.example/github.com/repo",
            "https://gitlab.evil.example/org/repo",
            "git@github.com.evil.example:org/repo.git",
        ],
    )
    def test_lookalike_hosts_get_no_env_token(self, url, monkeypatch):
        monkeypatch.setenv("XBOM_GITHUB_TOKEN", "ghp_secret")
        monkeypatch.setenv("XBOM_GITLAB_TOKEN", "glpat_secret")
        p = detect_provider(url)
        assert p.provider_name == "git"
        assert provider_mod.get_token_for_provider(p.provider_name) is None

    def test_explicit_provider_for_self_hosted(self):
        assert detect_provider("https://git.example.com/org/repo", "gitlab").provider_name == "gitlab"

    def test_unknown_provider_rejected(self):
        with pytest.raises(ValueError, match="Unknown provider"):
            detect_provider("https://github.com/org/repo", "svn")

    def test_non_urls_are_local(self):
        assert isinstance(detect_provider("."), LocalProvider)
        assert isinstance(detect_provider("./github.com-mirror"), LocalProvider)


class TestCloneUrl:
    def test_token_injected_for_https(self):
        url = GitProvider("github")._build_clone_url("https://github.com/org/repo", "t@k/en")
        assert url == "https://x-access-token:t%40k%2Fen@github.com/org/repo"

    def test_token_refused_over_http(self):
        with pytest.raises(ValueError, match="https"):
            GitProvider("github")._build_clone_url("http://github.com/org/repo", "tok")

    def test_ssh_and_tokenless_urls_unchanged(self):
        g = GitProvider("github")
        assert g._build_clone_url("git@github.com:org/repo.git", "tok") == "git@github.com:org/repo.git"
        assert g._build_clone_url("http://github.com/org/repo", None) == "http://github.com/org/repo"


class TestParseUrl:
    def test_parses_https_and_ssh(self):
        g = GitProvider("github")
        assert g._parse_url("https://github.com/org/repo.git") == ("org", "repo")
        assert g._parse_url("git@github.com:org/repo.git") == ("org", "repo")

    @pytest.mark.parametrize(
        "url", ["https://gitlab.com/org/..git", "https://gitlab.com/org/.", "https://gitlab.com/../repo"]
    )
    def test_dot_segments_rejected(self, url):
        with pytest.raises(ValueError, match="Invalid repository path"):
            GitProvider("gitlab")._parse_url(url)


class TestCleanup:
    def test_removes_only_temp_dir(self, tmp_path):
        temp_dir = tmp_path / "xbom-abc"
        (temp_dir / "repo").mkdir(parents=True)
        sibling = tmp_path / "keep-me"
        sibling.mkdir()

        info = SourceInfo(local_path=temp_dir / "repo", provider="github", temp_dir=temp_dir)
        GitProvider("github").cleanup(info)

        assert not temp_dir.exists()
        assert sibling.exists()

    def test_without_temp_dir_removes_nothing(self, tmp_path):
        info = SourceInfo(local_path=tmp_path / "repo", provider="github")
        (tmp_path / "repo").mkdir()
        GitProvider("github").cleanup(info)
        assert (tmp_path / "repo").exists()

    def test_failed_clone_removes_temp_dir(self, tmp_path, monkeypatch):
        temp_dir = tmp_path / "xbom-abc"
        temp_dir.mkdir()
        monkeypatch.setattr(provider_mod.tempfile, "mkdtemp", lambda **kw: str(temp_dir))
        monkeypatch.setattr(provider_mod, "run", lambda *a, **kw: RunResult(128, "", "fatal: not found", []))

        with pytest.raises(RuntimeError, match="git clone failed"):
            GitProvider("github").resolve("https://github.com/org/repo")
        assert not temp_dir.exists()
        assert Path(tmp_path).exists()
