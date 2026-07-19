# Architecture

## Component overview

| Component | Module | Responsibility |
|---|---|---|
| API orchestration | `gateway/gateway_api.py` | strict validation, pipeline ordering, fail-closed handling, admin gating |
| PII mediator | `gateway/pii_mediator.py` | detection (Presidio + custom UK NINO recognizer), tokenize/redact application |
| Tokenization context | `gateway/tokenization.py` | request-scoped token minting and exact-match rehydration |
| Policy engine | `gateway/policy.py` | four-action policy, decision records |
| Provider adapters | `gateway/llm_client.py` | wire-format translation, timeouts, typed errors, response normalization |
| Audit logger | `gateway/audit_logger.py` | hash-chained, HMAC-authenticated, concurrency-safe audit records |
| External checkpoint | `gateway/checkpoint.py` | tail-deletion/rollback detection anchor stored outside the DB |
| Configuration | `gateway/config.py` | environment-validated settings, secrets from env only |

Each component is injected into `create_app()` and independently
replaceable (the tests replace every one of them); the gateway pattern
is general-purpose, not a hardcoded pipeline.

## Data flow

```mermaid
flowchart LR
    C[Client application] -->|"prompt (may contain PII)"| V[Strict validation]
    V --> D[PII detection<br/>incl. ALLOW entities]
    D --> P{Policy}
    P -->|"any BLOCK entity"| B["HTTP 400<br/>privacy_policy_blocked"]
    B -.->|"safe metadata"| A[(Audit store)]
    P -->|otherwise| S[Sanitize:<br/>tokenize + redact]
    S -->|"provider-safe prompt"| PA[Provider adapter]
    PA -->|"HTTPS"| L[External LLM provider]
    L --> PA
    PA --> RS["Optional response scan<br/>(redact new PII)"]
    RS -.->|"metadata + hashes only"| A
    RS --> R[Rehydrate request tokens]
    R -->|"response with restored values"| C
    A --> CP[(External checkpoint<br/>outside the DB)]
```

The **trust boundary** sits between the provider adapter and the
external LLM provider: everything to the right of it sees only
provider-safe text. The audit store receives only metadata and hashes,
in every path (success, blocked, provider error, detector failure).

## Request processing sequence

```mermaid
sequenceDiagram
    participant C as Client
    participant G as Gateway
    participant M as Mediator
    participant A as Audit log
    participant P as Provider

    C->>G: POST /v1/chat/completions
    G->>G: strict validation (extra fields → 422)
    G->>G: create TokenizationContext (fresh namespace)
    G->>M: analyze every message (all policy entities)
    alt any BLOCK entity detected
        G->>A: append policy_blocked (types + counts only)
        G-->>C: 400 privacy_policy_blocked
    else detector raises
        G->>A: append detector_failure (safe code only)
        G-->>C: 500 PGW-DETECTOR-FAILURE (no provider call)
    else mediated
        G->>M: apply (tokenize via shared context, redact)
        G->>P: provider-safe messages only
        P-->>G: response (tokens echoed back, maybe new PII)
        opt response scan enabled
            G->>M: redact detected entities in response
        end
        G->>A: append chat_completion (decisions + hashes)
        G->>G: rehydrate this request's tokens, clear context
        G-->>C: response + X-Audit-Entry-Id
    end
```

## Token lifecycle

1. **Create** — one `TokenizationContext` per API request; its 8-hex
   namespace is random (`secrets`) and checked against the request text.
2. **Mint** — each detected TOKENIZE value gets
   `[[PGW_<ns>_<TYPE>_<n>]]`; the same value in any message of the
   request reuses its token; different values can never share one.
3. **Travel** — only tokens cross the provider boundary; the mapping
   never leaves the request handler's local variable.
4. **Rehydrate** — after the audit record is sealed, exact whole-token
   matches from *this* context are replaced in the response. Unknown,
   forged, partial, or foreign-request tokens pass through unchanged.
5. **Destroy** — the mapping is cleared when the request completes; it
   is never persisted anywhere.

## Audit path

Every request outcome appends exactly one record:

| Event | When | Payload highlights |
|---|---|---|
| `chat_completion` | success | decisions, prompt/response hashes, durations |
| `policy_blocked` | BLOCK entity found | decisions, blocked types; **no prompt hash** (the prompt was never sanitized, and hashing raw PII would enable dictionary confirmation) |
| `provider_error` | adapter failure | safe error code, decisions, prompt hash |
| `detector_failure` | mediation failure | safe error code only |

Records are hash-chained (`prev_hash`) and HMAC-authenticated
(`record_mac`); appends run in a single `BEGIN IMMEDIATE` SQLite
transaction (read predecessor + insert together) so concurrent writers
cannot fork the chain. After each append the configured checkpoint
store receives the newest (id, MAC) pair.

## Failure paths

All failures map to fixed internal codes (`gateway/errors.py`); raw
exception text never reaches API responses, audit records, or logs.

| Failure | Behaviour | Code |
|---|---|---|
| detection/sanitization crash | stop before provider, 500 | `PGW-DETECTOR-FAILURE` |
| policy block | stop before provider, 400 | `privacy_policy_blocked` |
| provider timeout | 504 | `PGW-PROVIDER-TIMEOUT` |
| provider auth | 502 | `PGW-PROVIDER-AUTH` |
| provider malformed/HTTP error | 502 | `PGW-PROVIDER-RESPONSE` |
| audit write failure (success path) | request fails, 500 | `PGW-AUDIT-WRITE` |
| invalid configuration | refuse startup | `PGW-CONFIG-INVALID` |
