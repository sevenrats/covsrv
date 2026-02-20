"""Tests for covsrv.config — the declarative ConfigManager."""

from __future__ import annotations

import pytest

from covsrv.config import (
    ConfigManager,
)

# =====================================================================
# Parsing — from_str
# =====================================================================

MINIMAL_TOML = """\
[global]
report_key = "global-key"
public_url = "http://localhost:9000"
session_secret = "s3cret"
auth_enabled = true
auth_cache_ttl = 120

[providers.my-gitea]
type = "gitea"
url = "https://gitea.example.com"
report_key = "gitea-prov-key"
client_id = "cid"
client_secret = "csec"

[providers.my-gitea.owners.sevenrats]
report_key = "owner-key"

[providers.my-gitea.repos."sevenrats/covsrv"]
report_key = "repo-key"

[providers.gh]
type = "github"
url = "https://github.com"
report_key = "gh-key"
"""

MULTI_GITHUB_TOML = """\
[providers.github-public]
type = "github"
url = "https://github.com"
report_key = "pub-key"

[providers.github-enterprise]
type = "github"
url = "https://github.corp.example.com"
report_key = "ent-key"
client_id = "ent-cid"
client_secret = "ent-csec"
"""


class TestFromStr:
    def test_global_section(self):
        cfg = ConfigManager.from_str(MINIMAL_TOML)
        g = cfg.global_config
        assert g.report_key == "global-key"
        assert g.public_url == "http://localhost:9000"
        assert g.session_secret == "s3cret"
        assert g.auth_enabled is True
        assert g.auth_cache_ttl == 120

    def test_providers_parsed(self):
        cfg = ConfigManager.from_str(MINIMAL_TOML)
        assert "my-gitea" in cfg.providers
        assert "gh" in cfg.providers

    def test_provider_fields(self):
        cfg = ConfigManager.from_str(MINIMAL_TOML)
        gt = cfg.get_provider("my-gitea")
        assert gt is not None
        assert gt.type == "gitea"
        assert gt.url == "https://gitea.example.com"
        assert gt.report_key == "gitea-prov-key"
        assert gt.client_id == "cid"
        assert gt.client_secret == "csec"

    def test_provider_oauth_configured(self):
        cfg = ConfigManager.from_str(MINIMAL_TOML)
        gt = cfg.get_provider("my-gitea")
        assert gt is not None
        assert gt.oauth_configured is True
        gh = cfg.get_provider("gh")
        assert gh is not None
        assert gh.oauth_configured is False

    def test_owner_section(self):
        cfg = ConfigManager.from_str(MINIMAL_TOML)
        gt = cfg.get_provider("my-gitea")
        assert gt is not None
        assert "sevenrats" in gt.owners
        assert gt.owners["sevenrats"].report_key == "owner-key"

    def test_repo_section(self):
        cfg = ConfigManager.from_str(MINIMAL_TOML)
        gt = cfg.get_provider("my-gitea")
        assert gt is not None
        assert "sevenrats/covsrv" in gt.repos
        assert gt.repos["sevenrats/covsrv"].report_key == "repo-key"

    def test_url_trailing_slash_stripped(self):
        cfg = ConfigManager.from_str(
            '[providers.x]\ntype = "gitea"\nurl = "https://example.com/"'
        )
        x = cfg.get_provider("x")
        assert x is not None
        assert x.url == "https://example.com"

    def test_multiple_same_type(self):
        cfg = ConfigManager.from_str(MULTI_GITHUB_TOML)
        assert "github-public" in cfg.providers
        assert "github-enterprise" in cfg.providers
        pub = cfg.get_provider("github-public")
        ent = cfg.get_provider("github-enterprise")
        assert pub is not None
        assert ent is not None
        assert pub.type == "github"
        assert ent.type == "github"

    def test_missing_type_raises(self):
        with pytest.raises(ValueError, match="type"):
            ConfigManager.from_str('[providers.bad]\nurl = "http://x"')

    def test_missing_url_raises(self):
        with pytest.raises(ValueError, match="url"):
            ConfigManager.from_str('[providers.bad]\ntype = "github"')

    def test_invalid_provider_name_raises(self):
        with pytest.raises(ValueError, match="invalid"):
            ConfigManager.from_str(
                '[providers."bad name!"]\ntype = "github"\nurl = "http://x"'
            )


class TestDefault:
    def test_empty(self):
        cfg = ConfigManager.default()
        assert cfg.global_config.report_key is None
        assert len(cfg.providers) == 0


class TestProviderUrl:
    def test_known_provider(self):
        cfg = ConfigManager.from_str(MINIMAL_TOML)
        assert cfg.provider_url("my-gitea") == "https://gitea.example.com"

    def test_unknown_provider(self):
        cfg = ConfigManager.from_str(MINIMAL_TOML)
        assert cfg.provider_url("nope") is None


# =====================================================================
# Report-key verification (hierarchical)
# =====================================================================


class TestVerifyReportKey:
    def setup_method(self):
        self.cfg = ConfigManager.from_str(MINIMAL_TOML)

    def test_repo_level_key_matches(self):
        assert self.cfg.verify_report_key("repo-key", "my-gitea", "sevenrats", "covsrv")

    def test_owner_level_key_matches(self):
        assert self.cfg.verify_report_key(
            "owner-key", "my-gitea", "sevenrats", "other-repo"
        )

    def test_provider_level_key_matches(self):
        assert self.cfg.verify_report_key(
            "gitea-prov-key", "my-gitea", "someone", "some-repo"
        )

    def test_global_key_matches(self):
        assert self.cfg.verify_report_key(
            "global-key", "my-gitea", "anyone", "any-repo"
        )

    def test_global_key_works_for_all_providers(self):
        assert self.cfg.verify_report_key("global-key", "gh", "x", "y")

    def test_wrong_key_denied(self):
        assert not self.cfg.verify_report_key(
            "wrong", "my-gitea", "sevenrats", "covsrv"
        )

    def test_unknown_provider_denied(self):
        assert not self.cfg.verify_report_key("global-key", "nosuch", "x", "y")

    def test_repo_key_does_not_work_for_other_repo(self):
        assert not self.cfg.verify_report_key(
            "repo-key", "my-gitea", "sevenrats", "other"
        )

    def test_owner_key_does_not_work_for_other_owner(self):
        assert not self.cfg.verify_report_key(
            "owner-key", "my-gitea", "someone-else", "covsrv"
        )

    def test_provider_key_does_not_work_for_other_provider(self):
        assert not self.cfg.verify_report_key("gitea-prov-key", "gh", "x", "y")

    def test_no_global_key(self):
        cfg = ConfigManager.from_str(MULTI_GITHUB_TOML)
        assert not cfg.verify_report_key("anything", "github-public", "x", "y")
        # But the provider key should still work
        assert cfg.verify_report_key("pub-key", "github-public", "x", "y")


# =====================================================================
# Auth subsystem integration
# =====================================================================


class TestToAuthConfig:
    def test_produces_auth_config(self):
        cfg = ConfigManager.from_str(MINIMAL_TOML)
        auth_cfg = cfg.to_auth_config()
        assert auth_cfg.enabled is True
        assert auth_cfg.session_secret == "s3cret"
        assert auth_cfg.cache_ttl == 120
        assert auth_cfg.public_app_url == "http://localhost:9000"

    def test_only_oauth_providers_included(self):
        cfg = ConfigManager.from_str(MINIMAL_TOML)
        auth_cfg = cfg.to_auth_config()
        # my-gitea has client creds → included
        assert "my-gitea" in auth_cfg.providers
        # gh has no client creds → excluded
        assert "gh" not in auth_cfg.providers

    def test_url_to_provider_mapping(self):
        cfg = ConfigManager.from_str(MINIMAL_TOML)
        auth_cfg = cfg.to_auth_config()
        assert auth_cfg.url_to_provider["https://gitea.example.com"] == "my-gitea"

    def test_github_api_urls(self):
        cfg = ConfigManager.from_str(MINIMAL_TOML)
        entry = cfg.get_provider("gh")
        assert entry is not None
        pc = cfg.to_auth_provider_config(entry)
        assert pc.api_base_url == "https://api.github.com"
        assert pc.authorize_url == "https://github.com/login/oauth/authorize"

    def test_github_enterprise_api_urls(self):
        cfg = ConfigManager.from_str(MULTI_GITHUB_TOML)
        entry = cfg.get_provider("github-enterprise")
        assert entry is not None
        pc = cfg.to_auth_provider_config(entry)
        assert pc.api_base_url == "https://github.corp.example.com/api/v3"

    def test_gitea_api_urls(self):
        cfg = ConfigManager.from_str(MINIMAL_TOML)
        entry = cfg.get_provider("my-gitea")
        assert entry is not None
        pc = cfg.to_auth_provider_config(entry)
        assert pc.api_base_url == "https://gitea.example.com/api/v1"
        assert "userinfo" in pc.userinfo_url

    def test_unknown_type_raises(self):
        cfg = ConfigManager.from_str(
            '[providers.x]\ntype = "gitlab"\nurl = "http://x"\nclient_id = "a"\nclient_secret = "b"'
        )
        entry = cfg.get_provider("x")
        assert entry is not None
        with pytest.raises(ValueError, match="Unknown provider type"):
            cfg.to_auth_provider_config(entry)


# =====================================================================
# from_file (integration)
# =====================================================================


class TestFromFile:
    def test_loads_from_path(self, tmp_path):
        p = tmp_path / "config.toml"
        p.write_text(MINIMAL_TOML)
        cfg = ConfigManager.from_file(p)
        assert cfg.global_config.report_key == "global-key"
        assert "my-gitea" in cfg.providers

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            ConfigManager.from_file(tmp_path / "nope.toml")
