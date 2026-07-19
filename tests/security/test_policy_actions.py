"""The four policy actions observed at the provider boundary, including
proof that BLOCK produces zero provider calls and stores no values."""

from __future__ import annotations

import sqlite3

from gateway.policy import PolicyAction
from tests.conftest import BLOCKED_PROMPT, post_chat


def _db_text(audit) -> str:
    """Entire audit database as text, for raw-value leak searches."""
    with sqlite3.connect(audit.db_path) as conn:
        blob = "\n".join(str(row) for row in conn.execute("SELECT * FROM audit_log").fetchall())
    return blob


class TestAllow:
    def test_allow_sends_value_unchanged_and_records_it(self, gateway_factory):
        client, mock, audit = gateway_factory(policy={"EMAIL_ADDRESS": PolicyAction.ALLOW})
        response = post_chat(client, content="Reach me at carol@example.com.")
        assert response.status_code == 200
        # The value crossed the boundary — by explicit policy.
        assert "carol@example.com" in mock.requests_seen[-1]["messages"][0]["content"]
        # And the audit record says so, without storing the value.
        decisions = audit.latest().payload["policy_decisions"]
        allow = next(d for d in decisions if d["entity_type"] == "EMAIL_ADDRESS")
        assert allow["action"] == "allow"
        assert allow["count"] >= 1
        assert "carol@example.com" not in _db_text(audit)

    def test_allowed_date_recorded_under_default_policy(self, gateway_factory):
        client, _, audit = gateway_factory()
        post_chat(client, content="Let's schedule this for 25 December 2025.")
        decisions = audit.latest().payload["policy_decisions"]
        assert any(d["entity_type"] == "DATE_TIME" and d["action"] == "allow" for d in decisions)


class TestTokenize:
    def test_tokenize_sends_placeholder_only(self, gateway_factory):
        client, mock, _ = gateway_factory()
        post_chat(client, content="Mail alice@example.com please.")
        sent = mock.requests_seen[-1]["messages"][0]["content"]
        assert "alice@example.com" not in sent
        assert "[[PGW_" in sent


class TestRedact:
    def test_redact_sends_marker_and_continues(self, gateway_factory):
        client, mock, _ = gateway_factory()
        response = post_chat(client, content="My NINO is AB 12 34 56 C.")
        assert response.status_code == 200  # request continued
        sent = mock.requests_seen[-1]["messages"][0]["content"]
        assert "AB 12 34 56 C" not in sent
        assert "[REDACTED:UK_NINO]" in sent


class TestBlock:
    def test_block_rejects_request_with_clear_error(self, gateway_factory):
        client, _, _ = gateway_factory()
        response = post_chat(client, content=BLOCKED_PROMPT)
        assert response.status_code == 400
        error = response.json()["error"]
        assert error["code"] == "privacy_policy_blocked"
        assert error["blocked_entity_types"] == ["CREDIT_CARD"]
        assert "4111" not in response.text

    def test_block_makes_zero_provider_calls(self, gateway_factory):
        client, mock, _ = gateway_factory()
        post_chat(client, content=BLOCKED_PROMPT)
        assert mock.requests_seen == []

    def test_block_in_any_message_blocks_whole_request(self, gateway_factory):
        client, mock, _ = gateway_factory()
        response = client.post(
            "/v1/chat/completions",
            json={
                "model": "m",
                "messages": [
                    {"role": "user", "content": "Innocent question."},
                    {"role": "user", "content": BLOCKED_PROMPT},
                ],
            },
        )
        assert response.status_code == 400
        assert mock.requests_seen == []

    def test_multiple_blocked_entity_types_listed(self, gateway_factory):
        client, mock, _ = gateway_factory()
        response = post_chat(
            client,
            content="Card 4111 1111 1111 1111 and SSN 856-45-6789.",
        )
        assert response.status_code == 400
        blocked = response.json()["error"]["blocked_entity_types"]
        assert "CREDIT_CARD" in blocked
        assert "US_SSN" in blocked
        assert mock.requests_seen == []

    def test_blocked_values_never_stored_or_logged(self, gateway_factory, caplog):
        client, _, audit = gateway_factory()
        with caplog.at_level("DEBUG"):
            post_chat(client, content=BLOCKED_PROMPT)
        record = audit.latest()
        assert record.payload["event"] == "policy_blocked"
        assert record.payload["request_blocked"] is True
        db_text = _db_text(audit)
        assert "4111" not in db_text
        assert "4111" not in caplog.text
        # Blocked requests get no prompt hash either: hashing the raw,
        # unsanitized prompt would allow dictionary confirmation attacks.
        assert "prompt_hash" not in record.payload

    def test_mixed_policy_blocked_request_still_records_other_decisions(self, gateway_factory):
        client, _, audit = gateway_factory()
        post_chat(
            client,
            content="I'm John Smith, card 4111 1111 1111 1111, email js@example.com.",
        )
        decisions = {d["entity_type"]: d for d in audit.latest().payload["policy_decisions"]}
        assert decisions["CREDIT_CARD"]["request_blocked"] is True
        assert decisions["EMAIL_ADDRESS"]["action"] == "tokenize"
        assert decisions["EMAIL_ADDRESS"]["request_blocked"] is False
