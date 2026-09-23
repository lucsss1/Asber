"""Application settings.

Every external credential is optional. Empty strings in the environment
(e.g. ``NVD_API_KEY=``) are treated as "not configured".
Secrets are wrapped in ``SecretStr`` so they never appear in logs or API output.
"""
from __future__ import annotations

import os
from functools import lru_cache

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://asber:asber@db:5432/asber"
    redis_url: str | None = None

    # Optional credentials
    nvd_api_key: SecretStr | None = None
    github_token: SecretStr | None = None
    virustotal_api_key: SecretStr | None = None
    otx_api_key: SecretStr | None = None
    abusech_auth_key: SecretStr | None = None

    # HTTP behaviour
    http_user_agent: str = "Asber/0.1 (personal threat-intelligence dashboard; local use)"
    http_timeout_seconds: float = 30.0
    http_max_retries: int = 4

    # Source tuning
    nvd_initial_days: int = 14
    nvd_track_days: int = 120
    nvd_enrich_per_run: int = 25
    nvd_cache_days: int = 7
    github_max_cves_per_run: int = 15
    github_recheck_hours: int = 24
    github_extra_queries: str = ""  # ';'-separated GitHub search queries
    github_watch_repos: str = ""  # comma-separated owner/repo list
    sources_enabled: str = ""  # comma-separated keys forced ON
    sources_disabled: str = ""  # comma-separated keys forced OFF
    run_on_startup: bool = True

    # Safety switches (never enabled by default)
    malware_download_enabled: bool = False

    # Optional AI layer (Phase 3)
    ai_provider: str = "none"

    # API
    cors_origins: str = "http://localhost:3000"
    api_rate_limit_per_minute: int = 240
    # Proxies allowed to set X-Forwarded-For (CIDR or plain address, comma
    # separated). Empty means "no proxy in front": the peer address is used.
    trusted_proxy_ips: str = ""
    log_level: str = "INFO"

    @field_validator(
        "nvd_api_key", "github_token", "virustotal_api_key", "otx_api_key", "abusech_auth_key",
        mode="before",
    )
    @classmethod
    def _empty_secret_is_none(cls, v):
        if v is None or (isinstance(v, str) and not v.strip()):
            return None
        return v

    @field_validator("database_url", mode="before")
    @classmethod
    def _use_psycopg3(cls, v):
        """Managed platforms hand out `postgres://` / `postgresql://` URLs.

        SQLAlchemy would read those as "use psycopg2", which this project does
        not install, so the driver is pinned explicitly.
        """
        if isinstance(v, str):
            for prefix in ("postgres://", "postgresql://"):
                if v.startswith(prefix):
                    return "postgresql+psycopg://" + v[len(prefix):]
        return v

    @field_validator("redis_url", mode="before")
    @classmethod
    def _empty_is_none(cls, v):
        return None if isinstance(v, str) and not v.strip() else v

    # ---- helpers -------------------------------------------------------
    @staticmethod
    def secret(value: SecretStr | None) -> str | None:
        return value.get_secret_value() if value else None

    @staticmethod
    def _csv(value: str, sep: str = ",") -> list[str]:
        return [x.strip() for x in value.split(sep) if x.strip()]

    @property
    def enabled_overrides(self) -> set[str]:
        return set(self._csv(self.sources_enabled))

    @property
    def disabled_overrides(self) -> set[str]:
        return set(self._csv(self.sources_disabled))

    @property
    def trusted_proxy_list(self) -> list[str]:
        return self._csv(self.trusted_proxy_ips)

    @property
    def github_queries(self) -> list[str]:
        return self._csv(self.github_extra_queries, ";")

    @property
    def github_repos(self) -> list[str]:
        return self._csv(self.github_watch_repos)

    def interval_override(self, source_key: str) -> int | None:
        """``SOURCE_INTERVAL_CISA_KEV=900`` overrides a source's polling interval (seconds)."""
        raw = os.environ.get(f"SOURCE_INTERVAL_{source_key.upper()}")
        if raw and raw.strip().isdigit():
            return max(300, int(raw))  # never poll more often than every 5 minutes
        return None

    def configured_credentials(self) -> dict[str, bool]:
        return {
            "NVD_API_KEY": self.nvd_api_key is not None,
            "GITHUB_TOKEN": self.github_token is not None,
            "VIRUSTOTAL_API_KEY": self.virustotal_api_key is not None,
            "OTX_API_KEY": self.otx_api_key is not None,
            "ABUSECH_AUTH_KEY": self.abusech_auth_key is not None,
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()
