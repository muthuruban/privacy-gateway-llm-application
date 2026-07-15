"""Provider-agnostic LLM clients.

The gateway talks to providers through one small interface, ``LLMClient``:
give it an OpenAI-style ``model`` + ``messages`` request, get an
OpenAI-style response dict back. Each provider adapter handles its own
wire format, so adding a provider means adding one class here — the
mediator, logger, and API layer are untouched.

Three implementations:

* ``OpenAIClient``    — passes the request through to any OpenAI-compatible
  ``/chat/completions`` endpoint.
* ``AnthropicClient`` — translates to/from the Anthropic Messages API.
* ``MockLLMClient``   — no network at all; echoes what it received. Used by
  the demo and tests, and doubles as proof of what the "provider" actually
  saw (it should only ever see placeholder tokens, never raw PII).
"""

from __future__ import annotations

from typing import Any, Protocol

import httpx

from .config import Settings


class LLMClient(Protocol):
    """Minimal provider interface: OpenAI-style request in, response out."""

    async def chat(self, model: str, messages: list[dict], **params: Any) -> dict:
        ...


class OpenAIClient:
    def __init__(self, api_key: str, base_url: str = "https://api.openai.com/v1"):
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")

    async def chat(self, model: str, messages: list[dict], **params: Any) -> dict:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{self._base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self._api_key}"},
                json={"model": model, "messages": messages, **params},
            )
            response.raise_for_status()
            return response.json()


class AnthropicClient:
    """Adapter that presents the Anthropic Messages API behind the same
    OpenAI-style interface, so the rest of the gateway is provider-blind."""

    def __init__(self, api_key: str, base_url: str = "https://api.anthropic.com"):
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")

    async def chat(self, model: str, messages: list[dict], **params: Any) -> dict:
        # Anthropic takes the system prompt as a top-level field.
        system_parts = [m["content"] for m in messages if m["role"] == "system"]
        chat_messages = [m for m in messages if m["role"] != "system"]

        body: dict[str, Any] = {
            "model": model,
            "messages": chat_messages,
            "max_tokens": params.pop("max_tokens", 1024),
            **params,
        }
        if system_parts:
            body["system"] = "\n".join(system_parts)

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{self._base_url}/v1/messages",
                headers={
                    "x-api-key": self._api_key,
                    "anthropic-version": "2023-06-01",
                },
                json=body,
            )
            response.raise_for_status()
            data = response.json()

        # Translate back to the OpenAI response shape the gateway exposes.
        text = "".join(
            block["text"] for block in data.get("content", []) if block.get("type") == "text"
        )
        return {
            "id": data.get("id", ""),
            "object": "chat.completion",
            "model": data.get("model", model),
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": text},
                    "finish_reason": data.get("stop_reason", "stop"),
                }
            ],
            "usage": {
                "prompt_tokens": data.get("usage", {}).get("input_tokens", 0),
                "completion_tokens": data.get("usage", {}).get("output_tokens", 0),
            },
        }


class MockLLMClient:
    """Offline stand-in for a real provider.

    Records every request it receives (``requests_seen``) so tests and the
    demo can assert that no raw PII ever crossed the provider boundary, and
    echoes the last user message back so tokens flow through the full
    rehydration path.
    """

    def __init__(self) -> None:
        self.requests_seen: list[dict] = []

    async def chat(self, model: str, messages: list[dict], **params: Any) -> dict:
        self.requests_seen.append({"model": model, "messages": messages, **params})
        last_user = next(
            (m["content"] for m in reversed(messages) if m["role"] == "user"), ""
        )
        return {
            "id": "mock-completion-1",
            "object": "chat.completion",
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": f"[mock LLM] I received your message: {last_user}",
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0},
        }


def build_client(settings: Settings) -> LLMClient:
    """Instantiate the provider selected in configuration."""
    if settings.provider == "openai":
        return OpenAIClient(settings.openai_api_key, settings.openai_base_url)
    if settings.provider == "anthropic":
        return AnthropicClient(settings.anthropic_api_key, settings.anthropic_base_url)
    if settings.provider == "mock":
        return MockLLMClient()
    raise ValueError(f"Unknown provider: {settings.provider!r}")
