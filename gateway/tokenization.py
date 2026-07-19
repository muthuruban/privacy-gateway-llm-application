"""
Module purpose
--------------

Provide the request-scoped tokenization context: the object that mints
reversible placeholder tokens for PII values and restores them in
responses. One context is created per API request and shared across
every message in that request.

Security responsibility
-----------------------

* Two different values can never receive the same token, and the same
  value always receives the same token, within one request. Without a
  shared context, per-message counters could mint ``..._EMAIL_ADDRESS_1``
  twice and restore the wrong person's data.
* Tokens carry a high-entropy request namespace so they cannot collide
  with user-supplied text and cannot be guessed by the provider.
* Rehydration only ever replaces exact, whole tokens that this context
  minted. Unknown, forged, partial, or foreign-request tokens are left
  untouched.

Important limitation
--------------------

The token↔value mapping lives in process memory. This module does not
protect against an attacker who can read the gateway process's memory —
the trusted-host assumption is documented in docs/THREAT_MODEL.md.
"""

from __future__ import annotations

import re
import secrets

# Full-token pattern: [[PGW_<8-hex-namespace>_<ENTITY_TYPE>_<counter>]]
# Rehydration substitutes only complete matches of this pattern, so a
# truncated or edited token can never match.
TOKEN_PATTERN = re.compile(r"\[\[PGW_[0-9A-F]{8}_[A-Z][A-Z0-9_]*_[0-9]+\]\]")

_NAMESPACE_ATTEMPTS = 32


class TokenizationContext:
    """
    Request-scoped token registry.

    Security reason:
        Sharing one context across all messages of a request prevents
        token collisions between messages; scoping it to a single request
        prevents any mapping reuse between requests. The mapping is never
        persisted — it dies with the request.
    """

    def __init__(self, request_text: str = "") -> None:
        """
        Args:
            request_text: The concatenated original text of the request.
                The generated namespace is checked against it so that a
                (however unlikely) pre-existing occurrence of the
                namespace string cannot make user text look like a token.
        """
        namespace = ""
        for _ in range(_NAMESPACE_ATTEMPTS):
            candidate = secrets.token_hex(4).upper()
            if candidate not in request_text:
                namespace = candidate
                break
        if not namespace:  # pragma: no cover - astronomically unlikely
            raise RuntimeError("could not generate a collision-free namespace")

        self.namespace = namespace
        self.token_to_value: dict[str, str] = {}
        self._value_to_token: dict[tuple[str, str], str] = {}
        self._counters: dict[str, int] = {}

    def token_for(self, entity_type: str, value: str) -> str:
        """
        Return the placeholder token for ``value``, minting one if needed.

        The same (entity_type, value) pair always maps to the same token
        within this context, so the LLM sees one stable referent per
        distinct value.
        """
        key = (entity_type, value)
        existing = self._value_to_token.get(key)
        if existing is not None:
            return existing

        self._counters[entity_type] = self._counters.get(entity_type, 0) + 1
        token = f"[[PGW_{self.namespace}_{entity_type}_{self._counters[entity_type]}]]"
        self._value_to_token[key] = token
        self.token_to_value[token] = value
        return token

    def rehydrate(self, text: str) -> str:
        """
        Restore this context's tokens in ``text``; leave everything else.

        Security reason:
            Substitution happens in a single pass keyed by exact token
            lookup. Tokens minted by other requests, tokens invented by
            the model or the user, and partial matches all fail the
            dictionary lookup and pass through unchanged — so rehydration
            can never be tricked into inserting someone else's data.
        """

        def _replace(match: re.Match[str]) -> str:
            token = match.group(0)
            return self.token_to_value.get(token, token)

        return TOKEN_PATTERN.sub(_replace, text)

    def clear(self) -> None:
        """Drop all mappings once request processing has completed, so the
        raw values do not linger in reachable state longer than needed."""
        self.token_to_value.clear()
        self._value_to_token.clear()
        self._counters.clear()

    def __len__(self) -> int:
        return len(self.token_to_value)
