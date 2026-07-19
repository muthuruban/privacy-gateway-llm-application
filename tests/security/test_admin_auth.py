"""Administrative audit endpoints: disabled by default, key-gated,
paginated, and free of sensitive fields."""

from __future__ import annotations

from tests.conftest import MEDIATED_SECRETS, post_chat

ADMIN_KEY = "synthetic-admin-key-abcdef123456"
HEADER = "X-Admin-Api-Key"


class TestAccessControl:
    def test_endpoints_disabled_without_configured_key(self, gateway_factory):
        client, _, _ = gateway_factory()  # no admin key configured
        for path in ("/v1/audit/entries", "/v1/audit/verify"):
            response = client.get(path, headers={HEADER: "anything"})
            assert response.status_code == 403

    def test_missing_credential_rejected(self, gateway_factory):
        client, _, _ = gateway_factory(admin_api_key=ADMIN_KEY)
        assert client.get("/v1/audit/entries").status_code == 401

    def test_invalid_credential_rejected(self, gateway_factory):
        client, _, _ = gateway_factory(admin_api_key=ADMIN_KEY)
        response = client.get("/v1/audit/entries", headers={HEADER: "wrong-key"})
        assert response.status_code == 401
        # The error reveals nothing about the expected credential.
        assert ADMIN_KEY not in response.text

    def test_valid_credential_accepted(self, gateway_factory):
        client, _, _ = gateway_factory(admin_api_key=ADMIN_KEY)
        post_chat(client)
        entries = client.get("/v1/audit/entries", headers={HEADER: ADMIN_KEY})
        assert entries.status_code == 200
        assert entries.json()["total"] == 1
        verify = client.get("/v1/audit/verify", headers={HEADER: ADMIN_KEY})
        assert verify.status_code == 200
        assert verify.json()["status"] == "valid"

    def test_admin_key_never_logged(self, gateway_factory, caplog):
        client, _, _ = gateway_factory(admin_api_key=ADMIN_KEY)
        with caplog.at_level("DEBUG"):
            client.get("/v1/audit/entries", headers={HEADER: ADMIN_KEY})
            client.get("/v1/audit/entries", headers={HEADER: "wrong-key"})
        assert ADMIN_KEY not in caplog.text


class TestPagination:
    def _client_with_records(self, gateway_factory, n=5):
        client, _, _ = gateway_factory(admin_api_key=ADMIN_KEY)
        for i in range(n):
            post_chat(client, content=f"Request number {i} with no PII.")
        return client

    def test_limit_and_offset(self, gateway_factory):
        client = self._client_with_records(gateway_factory)
        body = client.get("/v1/audit/entries?limit=2&offset=2", headers={HEADER: ADMIN_KEY}).json()
        assert body["total"] == 5
        assert [r["id"] for r in body["records"]] == [3, 4]

    def test_default_limit_applied(self, gateway_factory):
        client = self._client_with_records(gateway_factory, n=3)
        body = client.get("/v1/audit/entries", headers={HEADER: ADMIN_KEY}).json()
        assert body["limit"] == 50
        assert len(body["records"]) == 3

    def test_maximum_page_size_enforced(self, gateway_factory):
        client = self._client_with_records(gateway_factory, n=1)
        response = client.get("/v1/audit/entries?limit=500", headers={HEADER: ADMIN_KEY})
        assert response.status_code == 422


class TestResponseMinimisation:
    def test_no_sensitive_fields_in_entries(self, gateway_factory):
        client, _, _ = gateway_factory(admin_api_key=ADMIN_KEY)
        post_chat(client)
        body = client.get("/v1/audit/entries", headers={HEADER: ADMIN_KEY})
        text = body.text
        for secret in MEDIATED_SECRETS:
            assert secret not in text
        assert "token_to_value" not in text
        assert "sanitized_messages" not in text

    def test_redacted_research_content_not_exposed_over_api(self, gateway_factory):
        client, _, _ = gateway_factory(admin_api_key=ADMIN_KEY, audit_store_redacted_content=True)
        post_chat(client)
        body = client.get("/v1/audit/entries", headers={HEADER: ADMIN_KEY}).json()
        record = body["records"][0]
        assert record["payload"]["contains_redacted_content"] is True
        assert "redacted_messages" not in record["payload"]
