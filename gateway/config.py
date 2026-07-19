"""
Module purpose
--------------

Load and validate runtime configuration from environment variables (and
a local ``.env`` file for development). All secrets — provider API keys,
the audit HMAC key, the administrative API key — come from the
environment only and are held as Pydantic ``SecretStr`` values so they
do not appear in reprs or accidental logs.

Security responsibility
-----------------------

Refuse to start with unsafe configuration. In particular, the insecure
built-in development HMAC key, an empty key, or a too-short key are only
tolerated when ``APP_ENV`` is ``development`` or ``test``; in
``production`` they raise ``ConfigurationError`` at startup. A silent
fallback here would make every audit MAC forgeable by anyone who read
the public source code.

Important limitation
--------------------

This module validates configuration shape and strength, not secrecy of
the runtime environment itself: if the host's environment variables are
readable by an attacker, all derived guarantees fail (see
docs/THREAT_MODEL.md).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import AliasChoices, Field, SecretStr, ValidationError, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .errors import ConfigurationError

#: Placeholder HMAC key for development and test runs only. It is public
#: knowledge (it is in this file), so any MAC made with it is forgeable.
INSECURE_DEV_KEY = "insecure-dev-key-set-GATEWAY_AUDIT_HMAC_KEY"

#: Minimum HMAC key length accepted in production (characters). 32 gives
#: at least 128 bits of entropy for a reasonably random key.
MIN_HMAC_KEY_LENGTH = 32


class AppEnv(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Runtime settings. Reads environment variables (case-insensitive)
    and, for local development, a ``.env`` file in the working directory.
    The ``.env`` loading behaviour is documented in the README."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        populate_by_name=True,
    )

    app_env: AppEnv = Field(
        default=AppEnv.DEVELOPMENT, validation_alias=AliasChoices("app_env", "APP_ENV")
    )
    provider: Literal["mock", "openai", "anthropic"] = Field(
        default="mock", validation_alias=AliasChoices("provider", "GATEWAY_PROVIDER")
    )
    openai_api_key: SecretStr = Field(
        default=SecretStr(""), validation_alias=AliasChoices("openai_api_key", "OPENAI_API_KEY")
    )
    openai_base_url: str = Field(
        default="https://api.openai.com/v1",
        validation_alias=AliasChoices("openai_base_url", "OPENAI_BASE_URL"),
    )
    anthropic_api_key: SecretStr = Field(
        default=SecretStr(""),
        validation_alias=AliasChoices("anthropic_api_key", "ANTHROPIC_API_KEY"),
    )
    anthropic_base_url: str = Field(
        default="https://api.anthropic.com",
        validation_alias=AliasChoices("anthropic_base_url", "ANTHROPIC_BASE_URL"),
    )
    audit_db_path: str = Field(
        default="audit_log.db", validation_alias=AliasChoices("audit_db_path", "GATEWAY_AUDIT_DB")
    )
    audit_hmac_key: SecretStr = Field(
        default=SecretStr(""),
        validation_alias=AliasChoices("audit_hmac_key", "GATEWAY_AUDIT_HMAC_KEY"),
    )
    admin_api_key: SecretStr = Field(
        default=SecretStr(""),
        validation_alias=AliasChoices("admin_api_key", "GATEWAY_ADMIN_API_KEY"),
    )
    audit_checkpoint_path: str = Field(
        default="",
        validation_alias=AliasChoices("audit_checkpoint_path", "GATEWAY_AUDIT_CHECKPOINT"),
    )
    policy_file: str = Field(
        default="", validation_alias=AliasChoices("policy_file", "GATEWAY_POLICY_FILE")
    )
    score_threshold: float = Field(
        default=0.4,
        ge=0.0,
        le=1.0,
        validation_alias=AliasChoices("score_threshold", "GATEWAY_SCORE_THRESHOLD"),
    )
    response_scan_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices("response_scan_enabled", "GATEWAY_RESPONSE_SCAN"),
    )
    audit_store_redacted_content: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "audit_store_redacted_content", "GATEWAY_AUDIT_STORE_REDACTED_CONTENT"
        ),
    )
    provider_timeout_seconds: float = Field(
        default=30.0,
        gt=0.0,
        le=600.0,
        validation_alias=AliasChoices("provider_timeout_seconds", "GATEWAY_PROVIDER_TIMEOUT"),
    )

    @model_validator(mode="after")
    def _enforce_security_rules(self) -> Settings:
        """
        Validate secret-dependent rules that Pydantic field types cannot.

        Security reason:
            Starting with a missing or well-known HMAC key silently
            produces an audit log whose MACs anyone can forge. Starting a
            real provider without credentials produces confusing runtime
            failures after PII has already been processed. Both must be
            startup errors, not warnings.
        """
        hmac_key = self.audit_hmac_key.get_secret_value()

        if self.app_env in (AppEnv.DEVELOPMENT, AppEnv.TEST):
            # Development convenience: substitute the (clearly labelled)
            # insecure key so the prototype runs out of the box.
            if not hmac_key:
                self.audit_hmac_key = SecretStr(INSECURE_DEV_KEY)
        else:  # production
            if not hmac_key:
                raise ConfigurationError(
                    "GATEWAY_AUDIT_HMAC_KEY is required when APP_ENV=production."
                )
            if hmac_key == INSECURE_DEV_KEY:
                raise ConfigurationError(
                    "The insecure development HMAC key cannot be used in production."
                )
            if len(hmac_key) < MIN_HMAC_KEY_LENGTH:
                raise ConfigurationError(
                    f"GATEWAY_AUDIT_HMAC_KEY must be at least {MIN_HMAC_KEY_LENGTH} "
                    "characters in production."
                )
            if self.provider == "openai" and not self.openai_api_key.get_secret_value():
                raise ConfigurationError("OPENAI_API_KEY is required for the openai provider.")
            if self.provider == "anthropic" and not self.anthropic_api_key.get_secret_value():
                raise ConfigurationError(
                    "ANTHROPIC_API_KEY is required for the anthropic provider."
                )
        return self

    @property
    def audit_hmac_key_bytes(self) -> bytes:
        return self.audit_hmac_key.get_secret_value().encode("utf-8")

    @property
    def audit_endpoints_enabled(self) -> bool:
        """Audit endpoints are disabled unless an admin key is configured."""
        return bool(self.admin_api_key.get_secret_value())

    @classmethod
    def load(cls, **overrides: object) -> Settings:
        """
        Build settings, converting Pydantic validation failures into the
        gateway's own ConfigurationError so callers handle one type.
        """
        try:
            return cls(**overrides)  # type: ignore[arg-type]
        except ValidationError as exc:
            # Summarize which fields failed without echoing their values,
            # which could include partially typed secrets.
            fields = ", ".join(sorted({str(e["loc"][0]) for e in exc.errors()})) or "unknown"
            raise ConfigurationError(f"Invalid configuration value(s) for: {fields}.") from exc

    @classmethod
    def from_env(cls) -> Settings:
        """Kept for compatibility with earlier revisions of this project."""
        return cls.load()
