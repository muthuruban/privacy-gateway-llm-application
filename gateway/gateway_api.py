"""
Module purpose
--------------

The FastAPI application that wires the PII mediator, policy engine,
provider adapter, and audit logger into one request pipeline. This is a
*limited OpenAI-style text chat endpoint for the dissertation prototype*
— it does not implement the full OpenAI API.

Request lifecycle for ``POST /v1/chat/completions``::

    validate strictly (unknown fields rejected)
      → detect PII in every message (one shared tokenization context)
      → BLOCK check: if any blocked entity type, reject before any
        provider contact
      → sanitize (tokenize / redact; allowed entities pass through)
      → provider adapter call (typed errors only)
      → optional response scan (redact provider-generated PII)
      → append privacy-minimised audit record (metadata + hashes only)
      → rehydrate this request's tokens for the caller
      → clear the token mapping

Security responsibility
-----------------------

* Ordering: the audit record is written from safe metadata before
  rehydration, and the token mapping exists only as a local variable in
  the request handler — raw PII cannot reach the provider, the audit
  store, or the logs by construction of this pipeline.
* Fail closed: if detection or sanitization fails for any reason, the
  request stops before the provider boundary and returns a safe error.
* Admin surface: audit endpoints are disabled unless an administrative
  API key is configured, and comparisons are constant-time.

Important limitation
--------------------

The pipeline can only mediate what the detector finds; false negatives
travel to the provider unchanged. See docs/SECURITY_GUARANTEES.md.
"""

from __future__ import annotations

import hmac as hmac_module
import logging
import time
import uuid
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .audit_logger import AuditLogger, sha256_canonical
from .checkpoint import CheckpointStore, LocalFileCheckpointStore
from .config import Settings
from .errors import (
    DetectorFailureError,
    ErrorCode,
    GatewayError,
    PolicyBlockedError,
    ProviderResponseError,
)
from .llm_client import LLMClient, build_client
from .logging_utils import configure_safe_logging
from .pii_mediator import PIIMediator
from .policy import (
    PolicyAction,
    blocked_entity_types,
    build_decisions,
    load_policy,
)
from .tokenization import TokenizationContext

logger = logging.getLogger("privacy_gateway")

# API limits (documented in the README). Requests beyond these are
# rejected with a validation error rather than silently truncated.
MAX_MESSAGES = 50
MAX_CONTENT_CHARS = 20_000
MAX_TOTAL_CHARS = 60_000
MAX_METADATA_ITEMS = 16
MAX_METADATA_VALUE_CHARS = 256

_ADMIN_HEADER = "X-Admin-Api-Key"


class ChatMessage(BaseModel):
    """One chat message. Content must be plain text — structured content
    arrays (images, audio, tool results) are out of scope and rejected."""

    model_config = ConfigDict(extra="forbid")

    role: Literal["system", "user", "assistant"]
    content: str = Field(max_length=MAX_CONTENT_CHARS)


class ChatCompletionRequest(BaseModel):
    """Strict request model.

    Security note:
        ``extra="forbid"`` rejects unsupported OpenAI fields (stream,
        tools, functions, ...) instead of silently ignoring them. A
        silently dropped ``tools`` field could make a caller believe a
        capability was applied when it was not.
    """

    model_config = ConfigDict(extra="forbid")

    model: str = Field(min_length=1, max_length=128)
    messages: list[ChatMessage] = Field(min_length=1, max_length=MAX_MESSAGES)
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    max_tokens: int | None = Field(default=None, ge=1, le=32_768)
    #: Caller-side annotation only: not forwarded to the provider and not
    #: stored in the audit log (it could contain anything).
    metadata: dict[str, str] = Field(default_factory=dict)
    #: Set false to receive the sanitized (tokenized) response instead of
    #: having real values restored.
    rehydrate: bool = True

    @model_validator(mode="after")
    def _enforce_size_limits(self) -> ChatCompletionRequest:
        total = sum(len(m.content) for m in self.messages)
        if total > MAX_TOTAL_CHARS:
            raise ValueError(f"total message content exceeds {MAX_TOTAL_CHARS} characters")
        if len(self.metadata) > MAX_METADATA_ITEMS:
            raise ValueError(f"metadata may contain at most {MAX_METADATA_ITEMS} items")
        for key, value in self.metadata.items():
            if len(key) > 64 or len(value) > MAX_METADATA_VALUE_CHARS:
                raise ValueError("metadata keys/values exceed the size limits")
        return self


def _error_body(code: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, **extra}}


def create_app(
    settings: Settings | None = None,
    mediator: PIIMediator | None = None,
    audit_logger: AuditLogger | None = None,
    llm_client: LLMClient | None = None,
) -> FastAPI:
    """Build the gateway app. Components default to the configured ones
    but can each be injected independently (used heavily by the tests)."""
    settings = settings or Settings.load()
    configure_safe_logging()
    policy = load_policy(settings.policy_file or None)

    checkpoint_store: CheckpointStore | None = None
    if settings.audit_checkpoint_path:
        checkpoint_store = LocalFileCheckpointStore(settings.audit_checkpoint_path)

    app = FastAPI(
        title="Privacy Gateway for LLM APIs",
        version="0.2.0",
        description="A limited OpenAI-style text chat endpoint for the dissertation prototype.",
    )
    app.state.settings = settings
    app.state.policy = policy
    # An injected mediator keeps its own policy (tests rely on this); a
    # constructed one uses the configured policy file or default.
    app.state.mediator = mediator or PIIMediator(
        policy=policy, score_threshold=settings.score_threshold
    )
    app.state.audit_logger = audit_logger or AuditLogger(
        db_path=settings.audit_db_path,
        hmac_key=settings.audit_hmac_key_bytes,
        checkpoint_store=checkpoint_store,
    )
    app.state.checkpoint_store = checkpoint_store
    app.state.llm_client = llm_client or build_client(settings)

    # Response-scan mediator: same engines, but every mediated entity
    # type becomes REDACT (response tokens make no sense — there is no
    # authorised place to restore provider-generated values).
    if settings.response_scan_enabled:
        response_policy = {
            entity: (PolicyAction.ALLOW if action is PolicyAction.ALLOW else PolicyAction.REDACT)
            for entity, action in app.state.mediator.policy.items()
        }
        app.state.response_mediator = app.state.mediator.clone_with_policy(response_policy)
    else:
        app.state.response_mediator = None

    @app.exception_handler(GatewayError)
    async def _gateway_error_handler(request: Request, exc: GatewayError) -> JSONResponse:
        # Security note: only the fixed safe message and safe metadata
        # are returned — never the underlying exception text.
        if isinstance(exc, PolicyBlockedError):
            body = _error_body(
                "privacy_policy_blocked",
                exc.safe_message,
                blocked_entity_types=exc.blocked_entity_types,
            )
        else:
            body = _error_body(exc.code.value, exc.safe_message)
        return JSONResponse(status_code=exc.http_status, content=body)

    @app.exception_handler(RequestValidationError)
    async def _validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Security note: Pydantic's default error payload echoes the
        # offending input value, which may contain PII; strip it and
        # return only the field location and the failure description.
        details = [
            {
                "field": ".".join(str(part) for part in err.get("loc", [])),
                "problem": err.get("msg", ""),
            }
            for err in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content=_error_body(
                "request_invalid",
                "The request is not valid for this limited OpenAI-style endpoint.",
                details=details,
            ),
        )

    def require_admin(request: Request) -> None:
        """
        Gate for audit endpoints.

        Security reason:
            The audit log is an attack-reconnaissance target even without
            raw content (traffic patterns, entity statistics). Endpoints
            are disabled entirely unless an admin key is configured, and
            the comparison is constant-time to avoid timing side-channels.
        """
        configured = settings.admin_api_key.get_secret_value()
        if not configured:
            raise AdminDisabledError()
        supplied = request.headers.get(_ADMIN_HEADER, "")
        if not hmac_module.compare_digest(supplied.encode("utf-8"), configured.encode("utf-8")):
            raise AdminUnauthorizedError()

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "provider": settings.provider}

    @app.post("/v1/chat/completions")
    async def chat_completions(body: ChatCompletionRequest, request: Request) -> JSONResponse:
        state = request.app.state
        mediator: PIIMediator = state.mediator
        audit: AuditLogger = state.audit_logger
        started = time.perf_counter()
        request_id = str(uuid.uuid4())

        def _base_payload() -> dict[str, Any]:
            return {
                "schema": "privacy_gateway_audit",
                "request_id": request_id,
                "provider": settings.provider,
                "model": body.model,
                "duration_ms": round((time.perf_counter() - started) * 1000, 1),
            }

        # ------ Fail-closed zone: detection and policy evaluation ------
        # Security note: any unexpected failure below must prevent the
        # provider call. Continuing with the unmediated prompt would
        # silently forward raw PII.
        token_context: TokenizationContext | None = None
        try:
            texts = [m.content for m in body.messages]
            token_context = TokenizationContext("\n".join(texts))
            per_message_results = [mediator.analyze(text) for text in texts]
            decisions = build_decisions(
                (
                    (r.entity_type, float(r.score))
                    for results in per_message_results
                    for r in results
                ),
                mediator.policy,
            )
        except Exception as exc:
            _audit_safe(
                audit,
                {
                    **_base_payload(),
                    "event": "detector_failure",
                    "status": "error",
                    "request_blocked": False,
                    "response_status": 500,
                    "error_code": ErrorCode.DETECTOR_FAILURE.value,
                },
            )
            logger.warning("detector_failure request_id=%s", request_id)
            raise DetectorFailureError() from exc

        blocked = blocked_entity_types(decisions)
        if blocked:
            # Security note: BLOCK means zero provider contact. Only the
            # entity *types* are recorded — never the detected values.
            _audit_safe(
                audit,
                {
                    **_base_payload(),
                    "event": "policy_blocked",
                    "status": "blocked",
                    "request_blocked": True,
                    "response_status": 400,
                    "error_code": ErrorCode.POLICY_BLOCKED.value,
                    "policy_decisions": [d.model_dump() for d in decisions],
                    "blocked_entity_types": blocked,
                },
            )
            logger.info("policy_blocked request_id=%s types=%s", request_id, ",".join(blocked))
            raise PolicyBlockedError(blocked)

        try:
            sanitized_messages = [
                {"role": message.role, "content": mediator.apply(text, results, token_context)}
                for message, text, results in zip(
                    body.messages, texts, per_message_results, strict=True
                )
            ]
        except Exception as exc:
            _audit_safe(
                audit,
                {
                    **_base_payload(),
                    "event": "detector_failure",
                    "status": "error",
                    "request_blocked": False,
                    "response_status": 500,
                    "error_code": ErrorCode.DETECTOR_FAILURE.value,
                    "policy_decisions": [d.model_dump() for d in decisions],
                },
            )
            logger.warning("sanitization_failure request_id=%s", request_id)
            raise DetectorFailureError() from exc
        # ------------- end fail-closed detection zone ------------------

        prompt_hash = sha256_canonical(sanitized_messages)

        params: dict[str, Any] = {}
        if body.temperature is not None:
            params["temperature"] = body.temperature
        if body.max_tokens is not None:
            params["max_tokens"] = body.max_tokens

        provider_started = time.perf_counter()
        try:
            provider_response = await state.llm_client.chat(
                body.model, sanitized_messages, **params
            )
        except GatewayError as exc:
            _audit_safe(
                audit,
                {
                    **_base_payload(),
                    "event": "provider_error",
                    "status": "error",
                    "request_blocked": False,
                    "response_status": exc.http_status,
                    "error_code": exc.code.value,
                    "policy_decisions": [d.model_dump() for d in decisions],
                    "prompt_hash": prompt_hash,
                },
            )
            logger.warning("provider_error request_id=%s code=%s", request_id, exc.code.value)
            raise
        except Exception as exc:
            # Security note: an unrecognized exception from an adapter is
            # mapped to a fixed safe code; its message may contain echoes
            # of the request or credentials and is never persisted.
            _audit_safe(
                audit,
                {
                    **_base_payload(),
                    "event": "provider_error",
                    "status": "error",
                    "request_blocked": False,
                    "response_status": 502,
                    "error_code": ErrorCode.PROVIDER_RESPONSE.value,
                    "policy_decisions": [d.model_dump() for d in decisions],
                    "prompt_hash": prompt_hash,
                },
            )
            logger.warning("provider_error request_id=%s code=unmapped", request_id)
            raise ProviderResponseError() from exc
        provider_duration_ms = round((time.perf_counter() - provider_started) * 1000, 1)

        response_hash = sha256_canonical(
            [c.get("message", {}).get("content", "") for c in provider_response.get("choices", [])]
        )

        # Optional response scan: redact provider-generated PII before
        # the response is returned. This runs *before* rehydration so
        # restored caller values are never re-detected and destroyed.
        response_scanned = False
        if state.response_mediator is not None:
            try:
                for choice in provider_response.get("choices", []):
                    content = choice.get("message", {}).get("content")
                    if isinstance(content, str):
                        scan_results = state.response_mediator.analyze(content)
                        choice["message"]["content"] = state.response_mediator.apply(
                            content, scan_results, None
                        )
                response_scanned = True
            except Exception as exc:
                # Fail closed: an unscanned response must not be returned
                # when the operator asked for scanning.
                logger.warning("response_scan_failure request_id=%s", request_id)
                raise DetectorFailureError() from exc

        audit_payload: dict[str, Any] = {
            **_base_payload(),
            "event": "chat_completion",
            "status": "ok",
            "request_blocked": False,
            "response_status": 200,
            "error_code": None,
            "policy_decisions": [d.model_dump() for d in decisions],
            "prompt_hash": prompt_hash,
            "response_hash": response_hash,
            "provider_duration_ms": provider_duration_ms,
            "response_scanned": response_scanned,
            "rehydrated_for_client": body.rehydrate,
            "contains_redacted_content": False,
        }

        # Optional research/debug mode: store irreversibly redacted
        # message content. Never enabled by default; documented caveat:
        # redacted text can still contain undetected sensitive data.
        if settings.audit_store_redacted_content:
            audit_payload["contains_redacted_content"] = True
            audit_payload["redacted_messages"] = [
                {
                    "role": message.role,
                    "content": mediator.redact_all(text, results),
                }
                for message, text, results in zip(
                    body.messages, texts, per_message_results, strict=True
                )
            ]

        record = _audit_or_fail(audit, audit_payload)

        # Rehydration happens last, after the audit record is sealed, and
        # only for the calling application.
        if body.rehydrate and token_context is not None and len(token_context):
            for choice in provider_response.get("choices", []):
                content = choice.get("message", {}).get("content")
                if isinstance(content, str):
                    choice["message"]["content"] = token_context.rehydrate(content)
        token_context.clear()

        logger.info(
            "chat_completion request_id=%s status=ok duration_ms=%s",
            request_id,
            audit_payload["duration_ms"],
        )
        return JSONResponse(
            content=provider_response,
            headers={
                "X-Gateway-Request-Id": request_id,
                "X-Audit-Entry-Id": str(record.id),
            },
        )

    @app.get("/v1/audit/entries", dependencies=[Depends(require_admin)])
    async def audit_entries(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        audit: AuditLogger = request.app.state.audit_logger
        records = audit.entries(limit=limit, offset=offset)
        return {
            "total": audit.count(),
            "limit": limit,
            "offset": offset,
            "records": [
                {
                    "id": r.id,
                    "schema_version": r.schema_version,
                    "timestamp": r.timestamp,
                    # Optional redacted research content is not exposed
                    # over the API even to admins; it is DB-only.
                    "payload": {k: v for k, v in r.payload.items() if k != "redacted_messages"},
                    "prev_hash": r.prev_hash,
                    "record_mac": r.record_mac,
                }
                for r in records
            ],
        }

    @app.get("/v1/audit/verify", dependencies=[Depends(require_admin)])
    async def audit_verify(request: Request) -> dict[str, Any]:
        audit: AuditLogger = request.app.state.audit_logger
        result = audit.verify_with_store(request.app.state.checkpoint_store)
        return {
            "status": result.status.value,
            "entries_checked": result.entries_checked,
            "first_invalid_id": result.first_invalid_id,
            "reason": result.reason,
            "tail_verified": result.tail_verified,
        }

    return app


class AdminDisabledError(GatewayError):
    code = ErrorCode.CONFIG_INVALID
    http_status = 403
    safe_message = "Audit endpoints are disabled (no administrative API key is configured)."
    category = "auth"


class AdminUnauthorizedError(GatewayError):
    code = ErrorCode.CONFIG_INVALID
    http_status = 401
    safe_message = "Invalid or missing administrative credential."
    category = "auth"


def _audit_safe(audit: AuditLogger, payload: dict[str, Any]) -> None:
    """Best-effort audit write on error paths: the original error is more
    useful to the caller than a cascading audit failure, so a failed
    write here is logged (without content) but not raised."""
    try:
        audit.append(payload)
    except GatewayError:
        logger.error("audit_write_failed during error handling")


def _audit_or_fail(audit: AuditLogger, payload: dict[str, Any]) -> Any:
    """Audit write on the success path: mandatory. A completed cycle
    without audit evidence violates the design, so the request fails."""
    return audit.append(payload)


def main() -> None:  # pragma: no cover - manual entry point
    """Entry point for ``python -m gateway.gateway_api``."""
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    uvicorn.run(create_app(), host="127.0.0.1", port=8000)


if __name__ == "__main__":  # pragma: no cover
    main()
