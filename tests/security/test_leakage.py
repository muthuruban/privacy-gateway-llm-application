"""Leak hunting: raw PII must not reach the provider boundary, the audit
database, API error responses, or application logs — including PII that
the provider itself generates or that rides along in exceptions."""

from __future__ import annotations

import sqlite3

from tests.conftest import MEDIATED_PROMPT, MEDIATED_SECRETS, post_chat


def _db_text(audit) -> str:
    with sqlite3.connect(audit.db_path) as conn:
        return "\n".join(str(row) for row in conn.execute("SELECT * FROM audit_log").fetchall())


class TestProviderBoundary:
    def test_no_raw_fixture_value_reaches_provider(self, gateway_factory):
        client, mock, _ = gateway_factory()
        post_chat(client, content=MEDIATED_PROMPT)
        sent = str(mock.requests_seen)
        for secret in MEDIATED_SECRETS:
            assert secret not in sent


class TestAuditStore:
    def test_default_record_is_metadata_only(self, gateway_factory):
        client, _, audit = gateway_factory()
        post_chat(client, content=MEDIATED_PROMPT)
        payload = audit.latest().payload
        # No content fields at all — only hashes and metadata.
        assert "sanitized_messages" not in payload
        assert "sanitized_response" not in payload
        assert "redacted_messages" not in payload
        assert payload["contains_redacted_content"] is False
        assert len(payload["prompt_hash"]) == 64
        assert len(payload["response_hash"]) == 64

    def test_no_raw_fixture_value_in_audit_db(self, gateway_factory):
        client, _, audit = gateway_factory()
        post_chat(client, content=MEDIATED_PROMPT)
        db_text = _db_text(audit)
        for secret in MEDIATED_SECRETS:
            assert secret not in db_text

    def test_no_token_mapping_in_audit_db(self, gateway_factory):
        client, _, audit = gateway_factory()
        response = post_chat(client, content="Mail alice@example.com.")
        assert response.status_code == 200
        db_text = _db_text(audit)
        assert "alice@example.com" not in db_text
        assert "token_to_value" not in db_text

    def test_provider_generated_pii_not_stored_raw(self, gateway_factory):
        # The provider invents PII that was never in the prompt.
        client, _, audit = gateway_factory(
            responder=lambda model, messages: (
                "Try emailing generated.contact@example.net or phone 212-555-0199."
            )
        )
        response = post_chat(client, content="Who should I ask about invoices?")
        assert response.status_code == 200
        # Default response policy: returned to the caller unmodified...
        assert "generated.contact@example.net" in response.text
        # ...but never written to the audit store as raw text.
        db_text = _db_text(audit)
        assert "generated.contact@example.net" not in db_text
        assert "212-555-0199" not in db_text

    def test_redacted_content_mode_stores_no_raw_values(self, gateway_factory):
        client, _, audit = gateway_factory(audit_store_redacted_content=True)
        post_chat(client, content=MEDIATED_PROMPT)
        payload = audit.latest().payload
        assert payload["contains_redacted_content"] is True
        assert "redacted_messages" in payload
        db_text = _db_text(audit)
        for secret in MEDIATED_SECRETS:
            assert secret not in db_text


class TestResponseHandling:
    def test_response_scan_redacts_provider_generated_pii(self, gateway_factory):
        client, _, _ = gateway_factory(
            response_scan_enabled=True,
            responder=lambda model, messages: "Contact generated.contact@example.net about this.",
        )
        response = post_chat(client, content="Who should I contact?")
        assert response.status_code == 200
        content = response.json()["choices"][0]["message"]["content"]
        assert "generated.contact@example.net" not in content
        assert "[REDACTED:EMAIL_ADDRESS]" in content

    def test_response_scan_does_not_destroy_rehydrated_tokens(self, gateway_factory):
        # Scan runs before rehydration: the caller still gets their own
        # tokenized values back even with scanning enabled.
        client, _, _ = gateway_factory(response_scan_enabled=True)
        response = post_chat(client, content="Mail alice@example.com about the report.")
        content = response.json()["choices"][0]["message"]["content"]
        assert "alice@example.com" in content

    def test_unknown_token_from_provider_left_unchanged(self, gateway_factory):
        fake = "[[PGW_0BADF00D_EMAIL_ADDRESS_7]]"
        client, _, _ = gateway_factory(
            responder=lambda model, messages: f"The reference {fake} is unknown to me."
        )
        response = post_chat(client, content="Mail alice@example.com.")
        assert fake in response.json()["choices"][0]["message"]["content"]


class TestErrorPaths:
    def test_provider_exception_text_never_escapes(self, gateway_factory, caplog):
        class LeakyProvider:
            async def chat(self, model, messages, **params):
                raise ValueError("connection failed for user hidden.bob@example.com")

        client, _, audit = gateway_factory(llm_client=LeakyProvider())
        with caplog.at_level("DEBUG"):
            response = post_chat(client, content="Anything at all.")
        assert response.status_code == 502
        assert response.json()["error"]["code"] == "PGW-PROVIDER-RESPONSE"
        assert "hidden.bob@example.com" not in response.text
        assert "hidden.bob@example.com" not in _db_text(audit)
        assert "hidden.bob@example.com" not in caplog.text
        assert audit.latest().payload["error_code"] == "PGW-PROVIDER-RESPONSE"

    def test_normal_requests_do_not_log_content(self, gateway_factory, caplog):
        client, _, _ = gateway_factory()
        with caplog.at_level("DEBUG"):
            post_chat(client, content=MEDIATED_PROMPT)
        for secret in MEDIATED_SECRETS:
            assert secret not in caplog.text
