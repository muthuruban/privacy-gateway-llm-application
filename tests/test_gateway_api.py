"""End-to-end gateway tests through the FastAPI app with a mock provider.

The key invariants exercised here:

1. The provider never receives raw PII (the mock records what it saw).
2. The calling application gets real values back (rehydration).
3. The audit log stores only sanitized data, and the chain verifies.
"""

import pytest
from fastapi.testclient import TestClient

from gateway.audit_logger import AuditLogger
from gateway.config import Settings
from gateway.gateway_api import create_app
from gateway.llm_client import MockLLMClient


@pytest.fixture
def gateway(tmp_path, mediator):
    """(TestClient, MockLLMClient, AuditLogger) wired into one app."""
    logger = AuditLogger(db_path=str(tmp_path / "audit.db"), hmac_key=b"test-key")
    mock = MockLLMClient()
    app = create_app(
        settings=Settings(provider="mock", audit_db_path=str(tmp_path / "audit.db")),
        mediator=mediator,
        logger=logger,
        llm_client=mock,
    )
    return TestClient(app), mock, logger


PII_PROMPT = (
    "Hi, I'm John Smith (john.smith@example.com). "
    "My card number is 4111 1111 1111 1111."
)


def _chat(client, content=PII_PROMPT, **overrides):
    body = {
        "model": "test-model",
        "messages": [{"role": "user", "content": content}],
        **overrides,
    }
    response = client.post("/v1/chat/completions", json=body)
    assert response.status_code == 200
    return response


class TestProviderBoundary:
    def test_provider_never_sees_raw_pii(self, gateway):
        client, mock, _ = gateway
        _chat(client)
        sent = str(mock.requests_seen[-1])
        assert "john.smith@example.com" not in sent
        assert "4111" not in sent
        assert "[[EMAIL_ADDRESS_1]]" in sent
        assert "[REDACTED:CREDIT_CARD]" in sent

    def test_client_response_is_rehydrated(self, gateway):
        client, _, _ = gateway
        response = _chat(client)
        content = response.json()["choices"][0]["message"]["content"]
        # Tokenized values are restored for the caller...
        assert "john.smith@example.com" in content
        # ...but blocked values are gone forever.
        assert "4111 1111 1111 1111" not in content
        assert "[REDACTED:CREDIT_CARD]" in content

    def test_rehydration_can_be_disabled(self, gateway):
        client, _, _ = gateway
        response = _chat(client, rehydrate=False)
        content = response.json()["choices"][0]["message"]["content"]
        assert "john.smith@example.com" not in content
        assert "[[EMAIL_ADDRESS_1]]" in content


class TestAuditTrail:
    def test_every_request_is_logged_and_chain_verifies(self, gateway):
        client, _, logger = gateway
        _chat(client)
        _chat(client, content="What is the capital of France?")
        entries = logger.entries()
        assert len(entries) == 2
        assert logger.verify_chain().valid

    def test_audit_entry_contains_no_raw_pii(self, gateway):
        client, _, logger = gateway
        _chat(client)
        stored = str(logger.entries()[-1].payload)
        assert "john.smith@example.com" not in stored
        assert "4111" not in stored
        assert "John Smith" not in stored

    def test_audit_entry_records_findings_metadata(self, gateway):
        client, _, logger = gateway
        response = _chat(client)
        payload = logger.entries()[-1].payload
        findings = payload["pii_findings"]
        assert findings["EMAIL_ADDRESS"]["action"] == "tokenize"
        assert findings["CREDIT_CARD"]["action"] == "block"
        assert payload["provider"] == "mock"
        assert response.headers["X-Audit-Entry-Id"] == str(logger.entries()[-1].id)

    def test_audit_endpoints(self, gateway):
        client, _, _ = gateway
        _chat(client)
        entries = client.get("/v1/audit/entries").json()
        assert len(entries) == 1
        verify = client.get("/v1/audit/verify").json()
        assert verify["valid"] is True
        assert verify["entries_checked"] == 1


class TestHealth:
    def test_health(self, gateway):
        client, _, _ = gateway
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
