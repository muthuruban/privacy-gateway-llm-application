"""Configuration validation: environment-dependent HMAC key rules,
provider credential requirements, threshold ranges, and .env loading.

All settings are passed explicitly (with _env_file=None) so the tests
are independent of the developer's real environment and .env file.
"""

from __future__ import annotations

import pytest

from gateway.config import INSECURE_DEV_KEY, AppEnv, Settings
from gateway.errors import ConfigurationError

STRONG_KEY = "a-strong-hmac-key-0123456789abcdef-0123"  # 39 chars


def make(**overrides):
    defaults: dict[str, object] = {"_env_file": None, "provider": "mock"}
    defaults.update(overrides)
    return Settings.load(**defaults)


class TestDevelopmentAndTest:
    def test_default_env_is_development(self):
        settings = make(audit_hmac_key="")
        assert settings.app_env is AppEnv.DEVELOPMENT

    def test_missing_key_falls_back_to_dev_key_in_development(self):
        settings = make(app_env="development", audit_hmac_key="")
        assert settings.audit_hmac_key.get_secret_value() == INSECURE_DEV_KEY

    def test_missing_key_falls_back_to_dev_key_in_test_env(self):
        settings = make(app_env="test", audit_hmac_key="")
        assert settings.audit_hmac_key.get_secret_value() == INSECURE_DEV_KEY

    def test_weak_custom_key_accepted_in_development(self):
        settings = make(app_env="development", audit_hmac_key="short")
        assert settings.audit_hmac_key.get_secret_value() == "short"


class TestProductionRefusals:
    def test_missing_hmac_key_refused(self):
        with pytest.raises(ConfigurationError):
            make(app_env="production", audit_hmac_key="")

    def test_dev_key_refused(self):
        with pytest.raises(ConfigurationError):
            make(app_env="production", audit_hmac_key=INSECURE_DEV_KEY)

    def test_short_key_refused(self):
        with pytest.raises(ConfigurationError):
            make(app_env="production", audit_hmac_key="only-thirty-one-characters-long")

    def test_strong_key_accepted(self):
        settings = make(app_env="production", audit_hmac_key=STRONG_KEY)
        assert settings.app_env is AppEnv.PRODUCTION

    def test_openai_without_key_refused(self):
        with pytest.raises(ConfigurationError):
            make(
                app_env="production",
                audit_hmac_key=STRONG_KEY,
                provider="openai",
                openai_api_key="",
            )

    def test_openai_with_key_accepted(self):
        settings = make(
            app_env="production",
            audit_hmac_key=STRONG_KEY,
            provider="openai",
            openai_api_key="sk-synthetic-test-value",
        )
        assert settings.provider == "openai"

    def test_anthropic_without_key_refused(self):
        with pytest.raises(ConfigurationError):
            make(
                app_env="production",
                audit_hmac_key=STRONG_KEY,
                provider="anthropic",
                anthropic_api_key="",
            )


class TestFieldValidation:
    def test_invalid_threshold_refused(self):
        with pytest.raises(ConfigurationError):
            make(score_threshold=1.5)
        with pytest.raises(ConfigurationError):
            make(score_threshold=-0.1)

    def test_invalid_provider_refused(self):
        with pytest.raises(ConfigurationError):
            make(provider="watson")

    def test_invalid_app_env_refused(self):
        with pytest.raises(ConfigurationError):
            make(app_env="staging")

    def test_configuration_error_does_not_echo_values(self):
        with pytest.raises(ConfigurationError) as excinfo:
            make(provider="watson-secret-name")
        assert "watson-secret-name" not in str(excinfo.value)

    def test_secrets_not_in_repr(self):
        settings = make(audit_hmac_key=STRONG_KEY, openai_api_key="sk-synthetic")
        assert STRONG_KEY not in repr(settings)
        assert "sk-synthetic" not in repr(settings)


class TestAdminAndModes:
    def test_audit_endpoints_disabled_without_admin_key(self):
        assert make(audit_hmac_key="x").audit_endpoints_enabled is False

    def test_audit_endpoints_enabled_with_admin_key(self):
        settings = make(audit_hmac_key="x", admin_api_key="admin-secret-1234")
        assert settings.audit_endpoints_enabled is True

    def test_privacy_modes_off_by_default(self):
        settings = make(audit_hmac_key="x")
        assert settings.response_scan_enabled is False
        assert settings.audit_store_redacted_content is False


class TestDotEnvLoading:
    def test_env_file_loaded_in_development(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text(
            "APP_ENV=development\nGATEWAY_PROVIDER=mock\nGATEWAY_SCORE_THRESHOLD=0.6\n",
            encoding="utf-8",
        )
        settings = Settings.load(_env_file=str(env_file))
        assert settings.app_env is AppEnv.DEVELOPMENT
        assert settings.score_threshold == 0.6

    def test_explicit_overrides_beat_env_file(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("GATEWAY_SCORE_THRESHOLD=0.6\n", encoding="utf-8")
        settings = Settings.load(_env_file=str(env_file), score_threshold=0.2)
        assert settings.score_threshold == 0.2
