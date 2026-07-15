"""FastAPI gateway: the PII mediator and audit logger wired around an LLM proxy.

Request lifecycle for ``POST /v1/chat/completions``::

    client request
      → sanitize every message (PII mediator)          [outbound mediation]
      → forward sanitized messages to the provider     [LLM proxy]
      → append audit entry (sanitized data only)       [audit logger]
      → rehydrate tokens in the response content       [inbound mediation]
      → return response to the calling application

Ordering matters: the audit entry is written from the *sanitized* request
and the provider's *raw* (still-tokenized) response, before rehydration —
so raw PII can never appear in the audit store. The token↔value mapping
exists only as a local variable inside the request handler and dies with it.

The mediator, logger, and provider client are constructed in ``create_app``
and injected via ``app.state``; each is replaceable independently (e.g. a
Postgres-backed logger, a different PII engine) without touching the others.
"""

from __future__ import annotations

import time
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .audit_logger import AuditLogger
from .config import Settings
from .llm_client import build_client
from .pii_mediator import PIIMediator


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: str
    messages: list[ChatMessage]
    temperature: float | None = None
    max_tokens: int | None = None
    metadata: dict = Field(default_factory=dict)
    #: Set false to receive the sanitized (tokenized) response instead of
    #: having real values restored — useful when the calling application
    #: itself must not handle raw PII.
    rehydrate: bool = True


def create_app(
    settings: Settings | None = None,
    mediator: PIIMediator | None = None,
    logger: AuditLogger | None = None,
    llm_client=None,
) -> FastAPI:
    """Build the gateway app. Components default to the configured ones but
    can each be injected independently (used heavily by the tests)."""
    settings = settings or Settings.from_env()

    app = FastAPI(title="Privacy Gateway for LLM APIs", version="0.1.0")
    app.state.settings = settings
    app.state.mediator = mediator or PIIMediator(
        policy=settings.policy, score_threshold=settings.score_threshold
    )
    app.state.audit_logger = logger or AuditLogger(
        db_path=settings.audit_db_path, hmac_key=settings.audit_hmac_key
    )
    app.state.llm_client = llm_client or build_client(settings)

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "provider": settings.provider}

    @app.post("/v1/chat/completions")
    async def chat_completions(body: ChatCompletionRequest, request: Request) -> JSONResponse:
        mediator: PIIMediator = request.app.state.mediator
        audit_logger: AuditLogger = request.app.state.audit_logger
        started = time.perf_counter()
        request_id = str(uuid.uuid4())

        # --- Outbound mediation: sanitize every message before it leaves. ---
        token_mapping: dict[str, str] = {}  # lives only for this request
        sanitized_messages: list[dict] = []
        all_findings: list[dict] = []
        for message in body.messages:
            result = mediator.sanitize(message.content)
            token_mapping.update(result.mapping)
            sanitized_messages.append({"role": message.role, "content": result.text})
            all_findings.append(result.findings)
        findings = PIIMediator.merge_findings(all_findings)

        # --- LLM proxy: only the sanitized messages cross this boundary. ---
        params: dict = {}
        if body.temperature is not None:
            params["temperature"] = body.temperature
        if body.max_tokens is not None:
            params["max_tokens"] = body.max_tokens
        try:
            provider_response = await request.app.state.llm_client.chat(
                body.model, sanitized_messages, **params
            )
        except Exception as exc:
            audit_logger.append(
                {
                    "request_id": request_id,
                    "event": "provider_error",
                    "provider": settings.provider,
                    "model": body.model,
                    "pii_findings": findings,
                    "error": str(exc)[:500],
                }
            )
            raise HTTPException(status_code=502, detail="LLM provider request failed") from exc

        # --- Audit: sanitized request + raw (still-tokenized) response. ---
        audit_entry = audit_logger.append(
            {
                "request_id": request_id,
                "event": "chat_completion",
                "provider": settings.provider,
                "model": body.model,
                "sanitized_messages": sanitized_messages,
                "sanitized_response": provider_response,
                "pii_findings": findings,
                "rehydrated_for_client": body.rehydrate,
                "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            }
        )

        # --- Inbound mediation: restore real values for the caller only. ---
        response_payload = provider_response
        if body.rehydrate and token_mapping:
            for choice in response_payload.get("choices", []):
                content = choice.get("message", {}).get("content")
                if isinstance(content, str):
                    choice["message"]["content"] = mediator.rehydrate(content, token_mapping)

        return JSONResponse(
            content=response_payload,
            headers={
                "X-Gateway-Request-Id": request_id,
                "X-Audit-Entry-Id": str(audit_entry.id),
            },
        )

    @app.get("/v1/audit/entries")
    async def audit_entries(request: Request) -> list[dict]:
        """The audit log is safe to expose: it never contains raw PII."""
        return [
            {
                "id": e.id,
                "timestamp": e.timestamp,
                "payload": e.payload,
                "prev_hash": e.prev_hash,
                "entry_hash": e.entry_hash,
                "signature": e.signature,
            }
            for e in request.app.state.audit_logger.entries()
        ]

    @app.get("/v1/audit/verify")
    async def audit_verify(request: Request) -> dict:
        result = request.app.state.audit_logger.verify_chain()
        return {
            "valid": result.valid,
            "entries_checked": result.entries_checked,
            "first_invalid_id": result.first_invalid_id,
            "reason": result.reason,
        }

    return app


def main() -> None:
    """Entry point for ``python -m gateway.gateway_api``."""
    import uvicorn

    uvicorn.run(create_app(), host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
