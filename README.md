# Privacy Gateway for LLM APIs

A provider-agnostic proxy that sits between a developer's application and any
LLM API (OpenAI, Anthropic, ...). On every request/response cycle it performs
two functions:

1. **PII-aware prompt mediation** — detects PII in outbound prompts
   (Microsoft Presidio) and, per configurable policy, either *tokenizes* it
   reversibly or *blocks* it irreversibly before anything reaches the LLM
   provider. Tokenized values are rehydrated in the response for the calling
   application only.
2. **Cryptographically verifiable audit logging** — every cycle is recorded
   in a hash-chained, HMAC-signed log. Any edit, deletion, or reordering of a
   past entry is detectable, and `verify_chain()` pinpoints the first
   tampered entry.

```
Client App → Gateway (PII Mediator → LLM Proxy → Audit Logger) → LLM Provider
                                    ↓
                          Tamper-evident audit store (SQLite)
```

## Layout

| Path | Purpose |
|---|---|
| `gateway/pii_mediator.py` | Presidio wrapper: detection, tokenize/block/allow policy, rehydration |
| `gateway/audit_logger.py` | Hash-chained + HMAC-signed SQLite audit log, `verify_chain()` |
| `gateway/llm_client.py` | Provider adapters (OpenAI, Anthropic, offline mock) behind one interface |
| `gateway/gateway_api.py` | FastAPI app wiring mediator → proxy → logger |
| `gateway/config.py` | Policy + runtime settings, secrets from environment only |
| `tests/` | Detection fixtures, round-trip, tamper detection, end-to-end API tests |
| `demo.py` | Scripted end-to-end walkthrough, including a tampering demonstration |

The mediator, logger, and provider client are independent modules injected
into the app in `create_app()` — each can be swapped (e.g. Postgres-backed
logger, different PII engine, new provider) without touching the others.

## Setup

Requires Python 3.11+.

```bash
python -m venv .venv
# Windows:              .venv\Scripts\activate
# macOS/Linux:          source .venv/bin/activate
pip install -r requirements.txt
```

The requirements file includes the spaCy English model (`en_core_web_sm`) as
a direct wheel URL, so no separate `spacy download` step is needed.

> **Note (Windows + antivirus TLS scanning):** if `pip install` fails with
> `CERTIFICATE_VERIFY_FAILED` and you run an antivirus that inspects HTTPS
> (e.g. Avast), point pip at its CA bundle instead of disabling verification:
> `$env:PIP_CERT = 'C:\ProgramData\Avast Software\Avast\wscert.pem'`

## Running the demo

Fully offline against the built-in mock provider:

```bash
python demo.py
```

The demo shows: the original PII-laden prompt → the sanitized prompt the
provider actually received → the response before and after rehydration → the
signed audit entry → a deliberate SQLite tampering attempt being caught by
`verify_chain()`.

## Running the gateway

```bash
# Offline mock provider (default):
python -m gateway.gateway_api

# Against a real provider:
export GATEWAY_PROVIDER=openai   OPENAI_API_KEY=sk-...
# or
export GATEWAY_PROVIDER=anthropic   ANTHROPIC_API_KEY=sk-ant-...
export GATEWAY_AUDIT_HMAC_KEY=<long-random-secret>
python -m gateway.gateway_api
```

Then point any OpenAI-style client at the gateway:

```bash
curl http://127.0.0.1:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "Email john.smith@example.com about the invoice."}]
      }'
```

Endpoints:

| Endpoint | Purpose |
|---|---|
| `POST /v1/chat/completions` | Mediated, logged proxy to the configured provider |
| `GET /v1/audit/entries` | The audit log (safe to expose — contains no raw PII) |
| `GET /v1/audit/verify` | Walk the chain; report first tampered entry, if any |
| `GET /health` | Liveness + configured provider |

Every completion response carries `X-Audit-Entry-Id` and
`X-Gateway-Request-Id` headers linking it to its audit entry. Pass
`"rehydrate": false` in the request body to receive the tokenized response
instead of having real values restored.

## Configuration

All settings come from environment variables (see `.env.example`):

| Variable | Default | Purpose |
|---|---|---|
| `GATEWAY_PROVIDER` | `mock` | `mock` \| `openai` \| `anthropic` |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | — | Provider credentials |
| `GATEWAY_AUDIT_HMAC_KEY` | insecure dev key | Audit signing key — **set in any real deployment** |
| `GATEWAY_AUDIT_DB` | `audit_log.db` | SQLite path for the audit log |
| `GATEWAY_POLICY_FILE` | built-in default | JSON file mapping entity types to actions |
| `GATEWAY_SCORE_THRESHOLD` | `0.4` | Minimum Presidio confidence to act on |

### PII policy

A policy maps Presidio entity types to one of three actions:

* `tokenize` — reversible placeholder (`[[EMAIL_ADDRESS_1]]`). The
  token→value mapping lives only in memory for the single request; the LLM
  never sees the real value, the caller gets it back.
* `block` — irreversible marker (`[REDACTED:CREDIT_CARD]`). Unrecoverable
  everywhere downstream.
* `allow` — left untouched.

Default policy: PERSON, EMAIL_ADDRESS, PHONE_NUMBER, LOCATION, IP_ADDRESS are
tokenized; CREDIT_CARD, US_SSN, UK_NINO, IBAN_CODE are blocked; DATE_TIME is
allowed. A custom `UK_NINO` recognizer (HMRC-format National Insurance
numbers) is registered on top of Presidio's built-ins as a worked example of
extending entity coverage.

Override via `GATEWAY_POLICY_FILE`, e.g.:

```json
{"PERSON": "tokenize", "CREDIT_CARD": "block", "DATE_TIME": "allow"}
```

## Audit log design

Each entry stores `(id, timestamp, payload, prev_hash, entry_hash, signature)`:

* `entry_hash = SHA-256(id | timestamp | payload | prev_hash)` — covers the
  entry's content *and* its position in the chain.
* `prev_hash` is the previous entry's `entry_hash` (genesis entries use 64
  zeros), so edits, deletions, and reordering all break linkage.
* `signature = HMAC-SHA256(key, entry_hash)` — an attacker with database
  write access can recompute hashes for a rewritten chain, but cannot forge
  signatures without the key, which lives outside the database.

`verify_chain()` walks the log from genesis, checking id sequence, linkage,
recomputed hashes, and signatures, and returns the first entry that fails
with a human-readable reason.

The payload is sanitized *by construction*: the gateway logs the sanitized
request and the provider's raw response — which itself only ever contained
placeholder tokens — before rehydration happens.

## Tests

```bash
python -m pytest tests/ -v
```

27 tests cover: detection against a labelled PII fixture set, tokenization
round-trip correctness, block-policy irreversibility, chain verification,
tamper detection (content edit, deletion, reordering, re-hash-without-key,
wrong key), and the end-to-end API invariants (provider never sees raw PII;
caller gets rehydrated values; audit trail stays sanitized and verifiable).

## Non-goals (v1)

* Not a consumer-facing chat filter or browser extension.
* Not a replacement for provider-side moderation or safety filtering.
* Text only — no image/audio PII handling.
