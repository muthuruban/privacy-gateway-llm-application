"""Shared fixtures for the whole test suite.

The PII mediator is expensive to construct (it loads a spaCy model), so
one instance is shared across the session; tests needing a different
policy use ``clone_with_policy``, which reuses the loaded engines. All
PII values in this suite are synthetic (example.com addresses, reserved
test card/phone numbers, invented names).
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

from gateway.config import Settings
from gateway.gateway_api import create_app
from gateway.llm_client import LLMClient, MockLLMClient
from gateway.pii_mediator import PIIMediator
from gateway.policy import PolicyAction

#: Standard synthetic PII prompt used across tests: tokenized (email,
#: person, phone), redacted (NINO), and allowed (date) entities — but no
#: BLOCK entities, so the request goes through.
MEDIATED_PROMPT = (
    "Hi, I'm John Smith. Email me at john.smith@example.com or call "
    "+44 7911 123456. My national insurance number is AB 12 34 56 C. "
    "Let's meet on 25 December 2025."
)

#: Synthetic values that must never cross the provider boundary or reach
#: the audit store for MEDIATED_PROMPT under the default policy.
MEDIATED_SECRETS = ["john.smith@example.com", "+44 7911 123456", "AB 12 34 56 C", "John Smith"]

#: Prompt containing a BLOCK-policy entity (synthetic test card number).
BLOCKED_PROMPT = "Please charge my card 4111 1111 1111 1111 for the invoice."


@pytest.fixture(scope="session")
def mediator() -> PIIMediator:
    return PIIMediator()


@pytest.fixture
def make_settings(tmp_path) -> Callable[..., Settings]:
    def _make(**overrides: object) -> Settings:
        defaults: dict[str, object] = {
            "_env_file": None,
            "app_env": "test",
            "provider": "mock",
            "audit_db_path": str(tmp_path / "audit.db"),
            "audit_hmac_key": "unit-test-hmac-key-0123456789abcdef",
        }
        defaults.update(overrides)
        return Settings.load(**defaults)

    return _make


@pytest.fixture
def gateway_factory(make_settings, mediator):
    """Build a wired gateway app for tests.

    Returns (TestClient, provider_client, audit_logger). The provider is
    the offline mock unless an ``llm_client`` is injected; its
    ``requests_seen`` list is the ground truth for what crossed the
    provider boundary.
    """

    def _make(
        *,
        policy: dict[str, PolicyAction] | None = None,
        responder=None,
        llm_client: LLMClient | None = None,
        mediator_override: object | None = None,
        **settings_overrides: object,
    ):
        settings = make_settings(**settings_overrides)
        med = mediator_override or (
            mediator.clone_with_policy(policy) if policy is not None else mediator
        )
        client = llm_client if llm_client is not None else MockLLMClient(responder=responder)
        app = create_app(settings=settings, mediator=med, llm_client=client)
        return TestClient(app), client, app.state.audit_logger

    return _make


def post_chat(client: TestClient, content: str = MEDIATED_PROMPT, **overrides):
    """POST a minimal chat completion request."""
    body: dict[str, object] = {
        "model": "test-model",
        "messages": [{"role": "user", "content": content}],
    }
    body.update(overrides)
    return client.post("/v1/chat/completions", json=body)
