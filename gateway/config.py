"""Policy and runtime configuration for the privacy gateway.

All secrets (provider API keys, audit signing key) are loaded from
environment variables only — never hardcoded and never written to disk
by this module.

The PII policy maps a Presidio entity type to one of three actions:

* ``tokenize`` — replace the entity with a reversible placeholder token.
  The token→value mapping lives only in memory for the lifetime of the
  single request, so the real value can be restored in the response sent
  back to the calling application, but never reaches the LLM provider.
* ``block``    — replace the entity with an irreversible redaction marker.
  There is no mapping; the value cannot be recovered anywhere downstream.
* ``allow``    — leave the entity untouched.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class PolicyAction(str, Enum):
    TOKENIZE = "tokenize"
    BLOCK = "block"
    ALLOW = "allow"


#: Default policy applied when no policy file is configured.
#: Identity-linked but conversationally useful entities are tokenized so the
#: LLM can still reason about them as stable placeholders; high-sensitivity
#: financial/government identifiers are blocked outright.
DEFAULT_POLICY: dict[str, PolicyAction] = {
    "PERSON": PolicyAction.TOKENIZE,
    "EMAIL_ADDRESS": PolicyAction.TOKENIZE,
    "PHONE_NUMBER": PolicyAction.TOKENIZE,
    "LOCATION": PolicyAction.TOKENIZE,
    "IP_ADDRESS": PolicyAction.TOKENIZE,
    "CREDIT_CARD": PolicyAction.BLOCK,
    "US_SSN": PolicyAction.BLOCK,
    "UK_NINO": PolicyAction.BLOCK,
    "IBAN_CODE": PolicyAction.BLOCK,
    "DATE_TIME": PolicyAction.ALLOW,
}

#: Placeholder HMAC key used only when GATEWAY_AUDIT_HMAC_KEY is unset.
#: Fine for local development and the demo; a real deployment must set its
#: own key or signatures provide no authenticity guarantee.
_DEV_HMAC_KEY = "insecure-dev-key-set-GATEWAY_AUDIT_HMAC_KEY"


def load_policy(path: str | os.PathLike | None = None) -> dict[str, PolicyAction]:
    """Load an entity→action policy from a JSON file, or return the default.

    The JSON format is a flat object, e.g.::

        {"PERSON": "tokenize", "CREDIT_CARD": "block", "DATE_TIME": "allow"}
    """
    if path is None:
        return dict(DEFAULT_POLICY)
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return {entity: PolicyAction(action) for entity, action in raw.items()}


@dataclass
class Settings:
    """Runtime settings, resolved from environment variables via ``from_env``."""

    provider: str = "mock"  # "openai" | "anthropic" | "mock"
    openai_api_key: str = ""
    openai_base_url: str = "https://api.openai.com/v1"
    anthropic_api_key: str = ""
    anthropic_base_url: str = "https://api.anthropic.com"
    audit_db_path: str = "audit_log.db"
    audit_hmac_key: bytes = b""
    policy: dict[str, PolicyAction] = field(default_factory=lambda: dict(DEFAULT_POLICY))
    score_threshold: float = 0.4  # minimum Presidio confidence to act on

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            provider=os.environ.get("GATEWAY_PROVIDER", "mock"),
            openai_api_key=os.environ.get("OPENAI_API_KEY", ""),
            openai_base_url=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
            anthropic_base_url=os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com"),
            audit_db_path=os.environ.get("GATEWAY_AUDIT_DB", "audit_log.db"),
            audit_hmac_key=os.environ.get("GATEWAY_AUDIT_HMAC_KEY", _DEV_HMAC_KEY).encode("utf-8"),
            policy=load_policy(os.environ.get("GATEWAY_POLICY_FILE") or None),
            score_threshold=float(os.environ.get("GATEWAY_SCORE_THRESHOLD", "0.4")),
        )
