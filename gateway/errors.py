"""
Module purpose
--------------

Define the gateway's internal error codes and typed exceptions. Every
failure that crosses a trust boundary (an API response, an audit record,
an operational log line) is represented by one of these types.

Security responsibility
-----------------------

This module guarantees that error information leaving the gateway is a
fixed, safe string chosen by us — never the raw text of an underlying
exception. Provider and library exceptions can contain prompts, personal
data, API keys, and internal endpoints, so their messages must never be
persisted or returned to callers.

Important limitation
--------------------

These classes cannot stop other code from logging a raw exception
directly. Call sites must catch third-party exceptions and re-raise one
of these types; the test suite checks the known paths.
"""

from __future__ import annotations

from enum import StrEnum


class ErrorCode(StrEnum):
    """Safe internal error codes. These strings may appear in audit
    records, API responses, and logs — they carry no request content."""

    POLICY_BLOCKED = "PGW-POLICY-BLOCKED"
    PROVIDER_TIMEOUT = "PGW-PROVIDER-TIMEOUT"
    PROVIDER_AUTH = "PGW-PROVIDER-AUTH"
    PROVIDER_RESPONSE = "PGW-PROVIDER-RESPONSE"
    DETECTOR_FAILURE = "PGW-DETECTOR-FAILURE"
    RESPONSE_SCAN_FAILURE = "PGW-RESPONSE-SCAN-FAILURE"
    AUDIT_WRITE = "PGW-AUDIT-WRITE"
    CONFIG_INVALID = "PGW-CONFIG-INVALID"


class GatewayError(Exception):
    """
    Base class for all gateway failures.

    Security reason:
        The ``safe_message`` is a fixed string defined in this module. If
        call sites attached dynamic text (e.g. a provider's exception
        message), prompts or secrets could leak into API responses and
        audit records.
    """

    code: ErrorCode = ErrorCode.CONFIG_INVALID
    http_status: int = 500
    safe_message: str = "Internal gateway error."
    category: str = "internal"

    def __init__(self, safe_message: str | None = None) -> None:
        # Only accept an override that call sites deliberately wrote as a
        # constant; never pass str(exc) of a third-party exception here.
        if safe_message is not None:
            self.safe_message = safe_message
        super().__init__(self.safe_message)


class PolicyBlockedError(GatewayError):
    """Raised when the privacy policy requires rejecting the whole request."""

    code = ErrorCode.POLICY_BLOCKED
    http_status = 400
    safe_message = "The request was blocked by the configured privacy policy."
    category = "policy"

    def __init__(self, blocked_entity_types: list[str]) -> None:
        # Entity *types* (e.g. "CREDIT_CARD") are safe metadata; detected
        # *values* must never be attached to this exception.
        super().__init__()
        self.blocked_entity_types = sorted(set(blocked_entity_types))


class ProviderTimeoutError(GatewayError):
    code = ErrorCode.PROVIDER_TIMEOUT
    http_status = 504
    safe_message = "The LLM provider did not respond in time."
    category = "provider"


class ProviderAuthError(GatewayError):
    code = ErrorCode.PROVIDER_AUTH
    http_status = 502
    safe_message = "Authentication with the LLM provider failed."
    category = "provider"


class ProviderResponseError(GatewayError):
    code = ErrorCode.PROVIDER_RESPONSE
    http_status = 502
    safe_message = "The LLM provider returned an unusable response."
    category = "provider"


class DetectorFailureError(GatewayError):
    """
    Raised when PII detection or sanitization fails.

    Security reason:
        The gateway fails closed: if it cannot prove a prompt was
        mediated, the prompt must not reach the provider. Treating a
        detector crash as a recoverable condition would silently forward
        raw PII.
    """

    code = ErrorCode.DETECTOR_FAILURE
    http_status = 500
    safe_message = "Privacy mediation failed; the request was not sent to the provider."
    category = "privacy"


class ResponseScanFailureError(GatewayError):
    """Raised when configured provider-response privacy scanning fails.

    The provider has already been called at this stage, so this error is
    intentionally distinct from request-side detector failure. The failed
    response is withheld from the client and the audit record states that
    provider contact already occurred.
    """

    code = ErrorCode.RESPONSE_SCAN_FAILURE
    http_status = 500
    safe_message = (
        "Privacy scanning of the provider response failed; the response was not returned "
        "to the client."
    )
    category = "privacy"


class AuditWriteError(GatewayError):
    code = ErrorCode.AUDIT_WRITE
    http_status = 500
    safe_message = "The audit record could not be written."
    category = "audit"


class ConfigurationError(GatewayError):
    code = ErrorCode.CONFIG_INVALID
    http_status = 500
    safe_message = "The gateway configuration is invalid."
    category = "config"
