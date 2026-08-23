"""Fail-closed behaviour: when privacy-critical processing fails, the
provider must never be called and the failure must not leak content."""

from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest

from gateway import gateway_api
from gateway.errors import AuditWriteError, ProviderTimeoutError
from gateway.policy import DEFAULT_POLICY
from gateway.tokenization import TokenizationContext
from tests.conftest import post_chat


def _db_text(audit) -> str:
    with sqlite3.connect(audit.db_path) as conn:
        return "\n".join(str(row) for row in conn.execute("SELECT * FROM audit_log").fetchall())


class BrokenAnalyzeMediator:
    """Detector that crashes with PII embedded in the exception text."""

    policy = dict(DEFAULT_POLICY)

    def analyze(self, text):
        raise RuntimeError("model crashed while reading crash.victim@example.com")

    def apply(self, text, results, context):  # pragma: no cover - unreached
        return text


class BrokenApplyMediator:
    """Detection works, sanitization crashes."""

    policy = dict(DEFAULT_POLICY)

    def analyze(self, text):
        return [SimpleNamespace(entity_type="EMAIL_ADDRESS", score=0.9, start=0, end=5)]

    def apply(self, text, results, context):
        raise RuntimeError("tokenizer exploded near apply.victim@example.com")


class TestDetectorFailure:
    def test_detector_failure_makes_zero_provider_calls(self, gateway_factory, caplog):
        client, mock, audit = gateway_factory(mediator_override=BrokenAnalyzeMediator())
        with caplog.at_level("DEBUG"):
            response = post_chat(client, content="Hello crash.victim@example.com")
        assert response.status_code == 500
        assert response.json()["error"]["code"] == "PGW-DETECTOR-FAILURE"
        assert mock.requests_seen == []  # nothing crossed the boundary
        # Safe audit evidence exists; the raw exception text does not.
        assert audit.latest().payload["event"] == "detector_failure"
        assert "crash.victim@example.com" not in _db_text(audit)
        assert "crash.victim@example.com" not in response.text
        assert "crash.victim@example.com" not in caplog.text

    def test_sanitization_failure_makes_zero_provider_calls(self, gateway_factory):
        client, mock, audit = gateway_factory(mediator_override=BrokenApplyMediator())
        response = post_chat(client, content="Hello there")
        assert response.status_code == 500
        assert response.json()["error"]["code"] == "PGW-DETECTOR-FAILURE"
        assert mock.requests_seen == []
        assert "apply.victim@example.com" not in _db_text(audit)


class TestResponseScanFailure:
    def test_failure_after_provider_contact_is_audited_truthfully(self, gateway_factory, caplog):
        class BrokenResponseMediator:
            def analyze(self, text):
                raise RuntimeError("scan failed near generated.secret@example.net")

            def apply(self, text, results, context):  # pragma: no cover - analyze raises first
                return text

        client, mock, audit = gateway_factory(
            response_scan_enabled=True,
            responder=lambda model, messages: "Contact generated.secret@example.net",
        )
        client.app.state.response_mediator = BrokenResponseMediator()

        with caplog.at_level("DEBUG"):
            response = post_chat(client, content="No personal information here.")

        assert response.status_code == 500
        assert response.json()["error"]["code"] == "PGW-RESPONSE-SCAN-FAILURE"
        assert "not sent to the provider" not in response.text
        assert len(mock.requests_seen) == 1
        record = audit.latest()
        assert record.payload["event"] == "response_scan_failure"
        assert record.payload["provider_contacted"] is True
        assert record.payload["response_returned_to_client"] is False
        assert "generated.secret@example.net" not in response.text
        assert "generated.secret@example.net" not in _db_text(audit)
        assert "generated.secret@example.net" not in caplog.text


class TestProviderFailure:
    def test_timeout_becomes_safe_error_with_audit_record(self, gateway_factory):
        class TimeoutProvider:
            async def chat(self, model, messages, **params):
                raise ProviderTimeoutError()

        client, _, audit = gateway_factory(llm_client=TimeoutProvider())
        response = post_chat(client, content="Anything")
        assert response.status_code == 504
        assert response.json()["error"]["code"] == "PGW-PROVIDER-TIMEOUT"
        record = audit.latest()
        assert record.payload["event"] == "provider_error"
        assert record.payload["error_code"] == "PGW-PROVIDER-TIMEOUT"

    def test_token_context_is_cleared_when_provider_fails(self, gateway_factory, monkeypatch):
        contexts = []

        class TrackingTokenizationContext(TokenizationContext):
            def __init__(self, request_text=""):
                super().__init__(request_text)
                contexts.append(self)

        class TimeoutProvider:
            async def chat(self, model, messages, **params):
                raise ProviderTimeoutError()

        monkeypatch.setattr(gateway_api, "TokenizationContext", TrackingTokenizationContext)
        client, _, _ = gateway_factory(llm_client=TimeoutProvider())
        response = post_chat(client, content="Email alice@example.com about the report.")

        assert response.status_code == 504
        assert len(contexts) == 1
        assert len(contexts[0]) == 0
        assert contexts[0].token_to_value == {}


class TestAuditFailure:
    def test_success_path_requires_audit_write(self, gateway_factory, monkeypatch):
        client, _, audit = gateway_factory()

        def broken_append(payload):
            raise AuditWriteError()

        monkeypatch.setattr(audit, "append", broken_append)
        response = post_chat(client, content="No PII here at all.")
        # A cycle that cannot be audited must not succeed silently.
        assert response.status_code == 500
        assert response.json()["error"]["code"] == "PGW-AUDIT-WRITE"

    def test_audit_failure_does_not_leak_content(self, gateway_factory, monkeypatch):
        client, _, audit = gateway_factory()

        def broken_append(payload):
            raise AuditWriteError()

        monkeypatch.setattr(audit, "append", broken_append)
        response = post_chat(client, content="Write to leak.check@example.com")
        assert "leak.check@example.com" not in response.text


class TestConfigFailure:
    def test_invalid_policy_file_prevents_startup(self, make_settings, tmp_path):
        from gateway.errors import ConfigurationError
        from gateway.gateway_api import create_app

        bad = tmp_path / "policy.json"
        bad.write_text('{"EMAIL_ADDRESS": "not-an-action"}')
        settings = make_settings(policy_file=str(bad))
        with pytest.raises(ConfigurationError):
            create_app(settings=settings)
