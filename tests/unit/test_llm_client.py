"""Provider adapters: request translation, response normalization, and
mapping of every failure mode to typed errors with fixed safe messages.
No live provider calls — all traffic goes through httpx.MockTransport.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from gateway.config import Settings
from gateway.errors import ProviderAuthError, ProviderResponseError, ProviderTimeoutError
from gateway.llm_client import (
    AnthropicAdapter,
    MockLLMClient,
    OpenAIAdapter,
    build_client,
)

MESSAGES = [
    {"role": "system", "content": "Be brief."},
    {"role": "user", "content": "Summarize [[PGW_AAAAAAAA_PERSON_1]]'s request."},
]


def run(coro):
    return asyncio.run(coro)


def openai_response(*contents: str) -> dict:
    return {
        "id": "cmpl-1",
        "model": "gpt-test",
        "choices": [
            {
                "index": i,
                "message": {"role": "assistant", "content": c},
                "finish_reason": "stop",
            }
            for i, c in enumerate(contents)
        ],
        "usage": {"prompt_tokens": 3, "completion_tokens": 5},
        "provider_debug_field": {"internal": "should be dropped"},
    }


class TestOpenAIAdapter:
    def test_request_translation(self):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["auth"] = request.headers.get("Authorization")
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json=openai_response("hello"))

        adapter = OpenAIAdapter(
            "sk-synthetic", "https://api.test.example/v1", transport=httpx.MockTransport(handler)
        )
        result = run(adapter.chat("gpt-test", MESSAGES, temperature=0.5))
        assert seen["url"] == "https://api.test.example/v1/chat/completions"
        assert seen["auth"] == "Bearer sk-synthetic"
        assert seen["body"]["model"] == "gpt-test"
        assert seen["body"]["messages"] == MESSAGES
        assert seen["body"]["temperature"] == 0.5
        assert result["choices"][0]["message"]["content"] == "hello"

    def test_normalization_drops_unknown_fields_and_keeps_choices(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=openai_response("one", "two"))

        adapter = OpenAIAdapter("k", transport=httpx.MockTransport(handler))
        result = run(adapter.chat("gpt-test", MESSAGES))
        assert "provider_debug_field" not in result
        assert [c["message"]["content"] for c in result["choices"]] == ["one", "two"]
        assert result["usage"] == {"prompt_tokens": 3, "completion_tokens": 5}

    def test_timeout_maps_to_typed_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("simulated timeout")

        adapter = OpenAIAdapter("k", transport=httpx.MockTransport(handler))
        with pytest.raises(ProviderTimeoutError):
            run(adapter.chat("gpt-test", MESSAGES))

    @pytest.mark.parametrize("status", [401, 403])
    def test_auth_failure_maps_to_typed_error(self, status):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status, json={"error": "bad key sk-echo-1234"})

        adapter = OpenAIAdapter("k", transport=httpx.MockTransport(handler))
        with pytest.raises(ProviderAuthError) as excinfo:
            run(adapter.chat("gpt-test", MESSAGES))
        assert "sk-echo-1234" not in str(excinfo.value)

    def test_server_error_maps_to_response_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="stack trace with alice@example.com")

        adapter = OpenAIAdapter("k", transport=httpx.MockTransport(handler))
        with pytest.raises(ProviderResponseError) as excinfo:
            run(adapter.chat("gpt-test", MESSAGES))
        assert "alice@example.com" not in str(excinfo.value)

    def test_non_json_body_maps_to_response_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="<html>not json</html>")

        adapter = OpenAIAdapter("k", transport=httpx.MockTransport(handler))
        with pytest.raises(ProviderResponseError):
            run(adapter.chat("gpt-test", MESSAGES))

    def test_missing_choices_maps_to_response_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"unexpected": True})

        adapter = OpenAIAdapter("k", transport=httpx.MockTransport(handler))
        with pytest.raises(ProviderResponseError):
            run(adapter.chat("gpt-test", MESSAGES))


class TestAnthropicAdapter:
    def test_request_translation_moves_system_to_top_level(self):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["api_key"] = request.headers.get("x-api-key")
            seen["body"] = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "id": "msg-1",
                    "model": "claude-test",
                    "content": [{"type": "text", "text": "hi there"}],
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 7, "output_tokens": 2},
                },
            )

        adapter = AnthropicAdapter(
            "sk-ant-synthetic",
            "https://anthropic.test.example",
            transport=httpx.MockTransport(handler),
        )
        result = run(adapter.chat("claude-test", MESSAGES, max_tokens=99))
        assert seen["url"] == "https://anthropic.test.example/v1/messages"
        assert seen["api_key"] == "sk-ant-synthetic"
        assert seen["body"]["system"] == "Be brief."
        assert all(m["role"] != "system" for m in seen["body"]["messages"])
        assert seen["body"]["max_tokens"] == 99
        assert result["choices"][0]["message"]["content"] == "hi there"
        assert result["usage"] == {"prompt_tokens": 7, "completion_tokens": 2}
        assert result["choices"][0]["finish_reason"] == "end_turn"

    def test_malformed_response_maps_to_response_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"content": "not-a-list"})

        adapter = AnthropicAdapter("k", transport=httpx.MockTransport(handler))
        with pytest.raises(ProviderResponseError):
            run(adapter.chat("claude-test", MESSAGES))


class TestMockClient:
    def test_records_requests_and_echoes(self):
        client = MockLLMClient()
        result = run(client.chat("m", [{"role": "user", "content": "ping"}]))
        assert client.requests_seen[0]["messages"][0]["content"] == "ping"
        assert "ping" in result["choices"][0]["message"]["content"]

    def test_scripted_responder(self):
        client = MockLLMClient(responder=lambda model, messages: "scripted output")
        result = run(client.chat("m", [{"role": "user", "content": "x"}]))
        assert result["choices"][0]["message"]["content"] == "scripted output"


class TestBuildClient:
    def _settings(self, provider: str) -> Settings:
        return Settings.load(
            _env_file=None,
            app_env="test",
            provider=provider,
            openai_api_key="sk-synthetic",
            anthropic_api_key="sk-ant-synthetic",
        )

    def test_builds_each_provider(self):
        assert isinstance(build_client(self._settings("mock")), MockLLMClient)
        assert isinstance(build_client(self._settings("openai")), OpenAIAdapter)
        assert isinstance(build_client(self._settings("anthropic")), AnthropicAdapter)
