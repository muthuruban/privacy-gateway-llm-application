"""
Module purpose
--------------

Provider adapters. Each adapter accepts an already-mediated
(provider-safe) request, translates it to one provider's wire format,
and returns a normalized OpenAI-style response dict. Adding a provider
means adding one adapter class; the mediator, logger, and API layer are
untouched.

Security responsibility
-----------------------

* Adapters are constructed with only their own credentials and endpoint
  — they never see token mappings, the audit HMAC key, or the admin key.
* Every transport or provider failure is converted into a typed gateway
  error carrying a fixed safe message. Raw provider exceptions and
  response bodies can contain echoes of prompts, API keys, and
  infrastructure details, so their text is never propagated.
* Responses are rebuilt field-by-field into a known shape; unknown
  provider fields are dropped rather than passed through.

Important limitation
--------------------

Adapters cannot verify that the text they receive was actually
mediated; that ordering is enforced by the orchestration layer in
gateway_api.py.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

import httpx

from .config import Settings
from .errors import ProviderAuthError, ProviderResponseError, ProviderTimeoutError


class LLMClient(Protocol):
    """Minimal adapter interface: provider-safe OpenAI-style request in,
    normalized OpenAI-style response out."""

    async def chat(
        self, model: str, messages: list[dict[str, str]], **params: Any
    ) -> dict[str, Any]: ...


def _normalize_openai_response(data: Any, fallback_model: str) -> dict[str, Any]:
    """
    Rebuild a provider response into the gateway's fixed response shape.

    Security reason:
        Copying only known fields (instead of passing the provider dict
        through) means unexpected provider fields — echoes, debug data,
        headers — cannot silently reach the caller or the audit path.

    Raises:
        ProviderResponseError: if the response does not contain the
            minimally required structure.
    """
    try:
        choices_in = data["choices"]
        if not isinstance(choices_in, list) or not choices_in:
            raise TypeError("choices must be a non-empty list")
        choices_out = []
        for index, choice in enumerate(choices_in):
            content = choice["message"]["content"]
            if not isinstance(content, str):
                raise TypeError("message content must be a string")
            choices_out.append(
                {
                    "index": index,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": str(choice.get("finish_reason") or "stop"),
                }
            )
        usage_in = data.get("usage") or {}
        return {
            "id": str(data.get("id") or ""),
            "object": "chat.completion",
            "model": str(data.get("model") or fallback_model),
            "choices": choices_out,
            "usage": {
                "prompt_tokens": int(usage_in.get("prompt_tokens") or 0),
                "completion_tokens": int(usage_in.get("completion_tokens") or 0),
            },
        }
    except (KeyError, TypeError, ValueError, IndexError, AttributeError) as exc:
        raise ProviderResponseError() from exc


async def _post_json(
    url: str,
    headers: dict[str, str],
    body: dict[str, Any],
    timeout: float,
    transport: httpx.AsyncBaseTransport | None,
) -> dict[str, Any]:
    """POST and return parsed JSON, mapping every failure mode to a typed
    gateway error with a fixed message (see module header)."""
    try:
        async with httpx.AsyncClient(timeout=timeout, transport=transport) as client:
            response = await client.post(url, headers=headers, json=body)
    except httpx.TimeoutException as exc:
        raise ProviderTimeoutError() from exc
    except httpx.HTTPError as exc:
        raise ProviderResponseError() from exc

    if response.status_code in (401, 403):
        raise ProviderAuthError()
    if response.status_code >= 400:
        raise ProviderResponseError()
    try:
        data = response.json()
    except ValueError as exc:
        raise ProviderResponseError() from exc
    if not isinstance(data, dict):
        raise ProviderResponseError()
    return data


class OpenAIAdapter:
    """Adapter for any OpenAI-compatible ``/chat/completions`` endpoint."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.openai.com/v1",
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._transport = transport

    async def chat(
        self, model: str, messages: list[dict[str, str]], **params: Any
    ) -> dict[str, Any]:
        data = await _post_json(
            f"{self._base_url}/chat/completions",
            {"Authorization": f"Bearer {self._api_key}"},
            {"model": model, "messages": messages, **params},
            self._timeout,
            self._transport,
        )
        return _normalize_openai_response(data, model)


class AnthropicAdapter:
    """Adapter presenting the Anthropic Messages API behind the same
    OpenAI-style interface, so the rest of the gateway is provider-blind."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.anthropic.com",
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._transport = transport

    async def chat(
        self, model: str, messages: list[dict[str, str]], **params: Any
    ) -> dict[str, Any]:
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

        data = await _post_json(
            f"{self._base_url}/v1/messages",
            {"x-api-key": self._api_key, "anthropic-version": "2023-06-01"},
            body,
            self._timeout,
            self._transport,
        )

        try:
            text = "".join(
                block["text"] for block in data["content"] if block.get("type") == "text"
            )
            usage = data.get("usage") or {}
            return {
                "id": str(data.get("id") or ""),
                "object": "chat.completion",
                "model": str(data.get("model") or model),
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": text},
                        "finish_reason": str(data.get("stop_reason") or "stop"),
                    }
                ],
                "usage": {
                    "prompt_tokens": int(usage.get("input_tokens") or 0),
                    "completion_tokens": int(usage.get("output_tokens") or 0),
                },
            }
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise ProviderResponseError() from exc


class MockLLMClient:
    """Offline stand-in for a real provider.

    Records every request it receives (``requests_seen``) so tests and
    the demo can prove what actually crossed the provider boundary, and
    echoes the last user message (or a scripted response) so tokens flow
    through the full rehydration path.
    """

    def __init__(self, responder: Callable[[str, list[dict[str, str]]], str] | None = None) -> None:
        self.requests_seen: list[dict[str, Any]] = []
        self._responder = responder

    async def chat(
        self, model: str, messages: list[dict[str, str]], **params: Any
    ) -> dict[str, Any]:
        self.requests_seen.append({"model": model, "messages": messages, **params})
        if self._responder is not None:
            content = self._responder(model, messages)
        else:
            last_user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
            content = f"[mock LLM] I received your message: {last_user}"
        return {
            "id": "mock-completion-1",
            "object": "chat.completion",
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0},
        }


def build_client(settings: Settings) -> LLMClient:
    """Instantiate the configured provider adapter, handing it only the
    narrow values it needs (its key, endpoint, and timeout) — never the
    settings object's audit or admin secrets."""
    if settings.provider == "openai":
        return OpenAIAdapter(
            settings.openai_api_key.get_secret_value(),
            settings.openai_base_url,
            settings.provider_timeout_seconds,
        )
    if settings.provider == "anthropic":
        return AnthropicAdapter(
            settings.anthropic_api_key.get_secret_value(),
            settings.anthropic_base_url,
            settings.provider_timeout_seconds,
        )
    return MockLLMClient()
