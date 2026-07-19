"""End-to-end pipeline behaviour through the FastAPI app with the mock
provider, plus the strict API-scope validation."""

from __future__ import annotations

import asyncio
import re

import httpx

from gateway.gateway_api import create_app
from gateway.llm_client import MockLLMClient
from tests.conftest import post_chat

EMAIL_TOKEN = re.compile(r"\[\[PGW_[0-9A-F]{8}_EMAIL_ADDRESS_\d+\]\]")


class TestPipeline:
    def test_happy_path_mediates_and_rehydrates(self, gateway_factory):
        client, mock, audit = gateway_factory()
        response = post_chat(client)
        assert response.status_code == 200

        provider_saw = mock.requests_seen[-1]["messages"][0]["content"]
        assert "john.smith@example.com" not in provider_saw
        assert EMAIL_TOKEN.search(provider_saw)
        assert "[REDACTED:UK_NINO]" in provider_saw
        assert "25 December 2025" in provider_saw  # allowed entity untouched

        content = response.json()["choices"][0]["message"]["content"]
        assert "john.smith@example.com" in content  # tokenized → restored
        assert "AB 12 34 56 C" not in content  # redacted → gone forever
        assert "[REDACTED:UK_NINO]" in content

        assert response.headers["X-Audit-Entry-Id"] == str(audit.latest().id)
        assert response.headers["X-Gateway-Request-Id"]

    def test_all_roles_are_mediated(self, gateway_factory):
        client, mock, _ = gateway_factory()
        response = client.post(
            "/v1/chat/completions",
            json={
                "model": "m",
                "messages": [
                    {"role": "system", "content": "The user is carol@example.com."},
                    {"role": "user", "content": "Write to dave@example.com."},
                    {"role": "assistant", "content": "I emailed dave@example.com."},
                ],
            },
        )
        assert response.status_code == 200
        sent = str(mock.requests_seen[-1]["messages"])
        assert "carol@example.com" not in sent
        assert "dave@example.com" not in sent
        # Same value in different messages → one token; different values
        # → different tokens (the cross-message collision fix).
        tokens = set(EMAIL_TOKEN.findall(sent))
        assert len(tokens) == 2

    def test_repeated_value_across_messages_restores_correctly(self, gateway_factory):
        client, _, _ = gateway_factory()
        response = client.post(
            "/v1/chat/completions",
            json={
                "model": "m",
                "messages": [
                    {"role": "user", "content": "First: alice@example.com."},
                    {"role": "user", "content": "Second: bob@example.com."},
                ],
            },
        )
        # The mock echoes the last user message; bob must come back as
        # bob, not alice (the overwrite defect this refactor fixes).
        content = response.json()["choices"][0]["message"]["content"]
        assert "bob@example.com" in content
        assert "alice@example.com" not in content

    def test_rehydration_can_be_disabled(self, gateway_factory):
        client, _, _ = gateway_factory()
        response = post_chat(client, rehydrate=False)
        content = response.json()["choices"][0]["message"]["content"]
        assert "john.smith@example.com" not in content
        assert EMAIL_TOKEN.search(content)

    def test_token_like_user_text_survives_round_trip(self, gateway_factory):
        client, mock, _ = gateway_factory()
        lookalike = "[[PGW_ABCDEF01_EMAIL_ADDRESS_1]]"
        response = post_chat(client, content=f"Please explain {lookalike} to me.")
        assert lookalike in mock.requests_seen[-1]["messages"][0]["content"]
        assert lookalike in response.json()["choices"][0]["message"]["content"]

    def test_multiple_choices_all_rehydrated(self, gateway_factory):
        class TwoChoiceClient(MockLLMClient):
            async def chat(self, model, messages, **params):
                base = await super().chat(model, messages, **params)
                echo = base["choices"][0]["message"]["content"]
                base["choices"] = [
                    {
                        "index": i,
                        "message": {"role": "assistant", "content": echo},
                        "finish_reason": "stop",
                    }
                    for i in range(2)
                ]
                return base

        client, _, _ = gateway_factory(llm_client=TwoChoiceClient())
        response = post_chat(client, content="Contact alice@example.com.")
        for choice in response.json()["choices"]:
            assert "alice@example.com" in choice["message"]["content"]

    def test_concurrent_requests_do_not_cross_contaminate(self, gateway_factory, make_settings):
        _, _, _ = gateway_factory()  # warm the session mediator
        settings = make_settings()
        app = create_app(settings=settings, llm_client=MockLLMClient())
        emails = [f"user{i}@example.com" for i in range(6)]

        async def _run():
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://gw") as ac:
                tasks = [
                    ac.post(
                        "/v1/chat/completions",
                        json={
                            "model": "m",
                            "messages": [{"role": "user", "content": f"Mail {email} today."}],
                        },
                    )
                    for email in emails
                ]
                return await asyncio.gather(*tasks)

        responses = asyncio.run(_run())
        for email, response in zip(emails, responses, strict=True):
            content = response.json()["choices"][0]["message"]["content"]
            assert email in content  # own value restored
            for other in emails:
                if other != email:
                    assert other not in content  # nobody else's value

    def test_health(self, gateway_factory):
        client, _, _ = gateway_factory()
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok", "provider": "mock"}


class TestStrictApiScope:
    """The endpoint is a limited OpenAI-style surface: unsupported fields
    and shapes are rejected, not silently ignored."""

    def _assert_invalid(self, client, body, needle=None):
        response = client.post("/v1/chat/completions", json=body)
        assert response.status_code == 422
        payload = response.json()
        assert payload["error"]["code"] == "request_invalid"
        if needle:
            assert needle in str(payload["error"]["details"])
        return payload

    def test_unknown_field_rejected(self, gateway_factory):
        client, _, _ = gateway_factory()
        body = {"model": "m", "messages": [{"role": "user", "content": "hi"}], "surprise": 1}
        self._assert_invalid(client, body, "surprise")

    def test_unsupported_openai_features_rejected(self, gateway_factory):
        client, _, _ = gateway_factory()
        for field, value in [
            ("stream", True),
            ("tools", [{"type": "function"}]),
            ("tool_choice", "auto"),
            ("functions", []),
            ("function_call", "auto"),
        ]:
            body = {"model": "m", "messages": [{"role": "user", "content": "hi"}], field: value}
            self._assert_invalid(client, body, field)

    def test_unsupported_role_rejected(self, gateway_factory):
        client, _, _ = gateway_factory()
        body = {"model": "m", "messages": [{"role": "tool", "content": "hi"}]}
        self._assert_invalid(client, body)

    def test_non_text_content_rejected(self, gateway_factory):
        client, _, _ = gateway_factory()
        body = {
            "model": "m",
            "messages": [
                {"role": "user", "content": [{"type": "image_url", "image_url": {"url": "x"}}]}
            ],
        }
        self._assert_invalid(client, body)

    def test_empty_messages_rejected(self, gateway_factory):
        client, _, _ = gateway_factory()
        self._assert_invalid(client, {"model": "m", "messages": []})

    def test_too_many_messages_rejected(self, gateway_factory):
        client, _, _ = gateway_factory()
        messages = [{"role": "user", "content": "hi"}] * 51
        self._assert_invalid(client, {"model": "m", "messages": messages})

    def test_oversized_message_rejected(self, gateway_factory):
        client, _, _ = gateway_factory()
        body = {"model": "m", "messages": [{"role": "user", "content": "x" * 20_001}]}
        self._assert_invalid(client, body)

    def test_oversized_total_request_rejected(self, gateway_factory):
        client, _, _ = gateway_factory()
        messages = [{"role": "user", "content": "x" * 19_000} for _ in range(4)]
        self._assert_invalid(client, {"model": "m", "messages": messages})

    def test_invalid_temperature_rejected(self, gateway_factory):
        client, _, _ = gateway_factory()
        body = {"model": "m", "messages": [{"role": "user", "content": "hi"}], "temperature": 3.0}
        self._assert_invalid(client, body)

    def test_invalid_max_tokens_rejected(self, gateway_factory):
        client, _, _ = gateway_factory()
        body = {"model": "m", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 0}
        self._assert_invalid(client, body)

    def test_oversized_metadata_rejected(self, gateway_factory):
        client, _, _ = gateway_factory()
        body = {
            "model": "m",
            "messages": [{"role": "user", "content": "hi"}],
            "metadata": {f"k{i}": "v" for i in range(17)},
        }
        self._assert_invalid(client, body)

    def test_validation_error_does_not_echo_input_values(self, gateway_factory):
        client, _, _ = gateway_factory()
        body = {
            "model": "m",
            "messages": [{"role": "user", "content": "hi"}],
            "leaked_field": "secret.person@example.com",
        }
        response = client.post("/v1/chat/completions", json=body)
        assert response.status_code == 422
        assert "secret.person@example.com" not in response.text

    def test_unknown_message_field_rejected(self, gateway_factory):
        client, _, _ = gateway_factory()
        body = {
            "model": "m",
            "messages": [{"role": "user", "content": "hi", "name": "alice"}],
        }
        self._assert_invalid(client, body)
