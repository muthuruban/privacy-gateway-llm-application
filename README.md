# Privacy Gateway for PII-Aware LLM Prompt Mediation and HMAC-Authenticated Audit Logging

An MSc Cybersecurity dissertation prototype: a provider-agnostic gateway
that sits between a client application and an external LLM provider
(OpenAI, Anthropic, or an offline mock). On every request it performs:

1. **PII-aware prompt mediation** — Microsoft Presidio detection plus a
   configurable per-entity policy with four distinct actions: `allow`
   (pass through, but record it), `tokenize` (reversible request-scoped
   placeholder), `redact` (irreversible replacement), and `block`
   (reject the whole request before any provider contact).
2. **HMAC-authenticated audit logging** — a hash-chained, tamper-evident
   audit log storing privacy-minimised metadata only (entity types,
   actions, counts, content hashes — never prompts, responses, raw PII,
   or token mappings).

> **Scope:** this is *a limited OpenAI-style text chat endpoint for the
> dissertation prototype*. It is **not** OpenAI-API compatible, not a
> hardened product, and **no production-readiness claim is made**.

```
Client App → Gateway (detect → policy → tokenize/redact/allow|block → adapter) → LLM Provider
                          ↓
             Tamper-evident audit store (SQLite) + external checkpoint
```

Detailed design documents live in [docs/](docs/):
[ARCHITECTURE](docs/ARCHITECTURE.md) ·
[THREAT_MODEL](docs/THREAT_MODEL.md) ·
[SECURITY_GUARANTEES](docs/SECURITY_GUARANTEES.md) ·
[EVALUATION_GUIDE](docs/EVALUATION_GUIDE.md) ·
[AI_USE_DECLARATION_TEMPLATE](docs/AI_USE_DECLARATION_TEMPLATE.md)

## Layout

| Path | Purpose |
|---|---|
| `gateway/pii_mediator.py` | Presidio wrapper: detection (incl. allowed entities), tokenize/redact application, custom UK NINO recognizer |
| `gateway/tokenization.py` | Request-scoped token context: high-entropy namespace, collision-free minting, exact-match rehydration |
| `gateway/policy.py` | Four-action policy model, decision records, policy file loading |
| `gateway/audit_logger.py` | Hash-chained + HMAC-authenticated SQLite log, `verify_chain()`, concurrency-safe appends |
| `gateway/checkpoint.py` | External checkpoint abstraction (tail-deletion/rollback detection) + local demo store |
| `gateway/llm_client.py` | Provider adapters (OpenAI, Anthropic, offline mock) behind one interface, typed errors |
| `gateway/gateway_api.py` | FastAPI orchestration: strict request models, fail-closed pipeline, admin-gated audit endpoints |
| `gateway/config.py` | Pydantic Settings: environment-validated configuration, secrets from env only |
| `gateway/errors.py` | Safe internal error codes (`PGW-*`) and typed exceptions |
| `tests/unit` · `tests/integration` · `tests/security` | 162 automated tests (see below) |
| `evaluation/` | Reproducible dissertation evaluation utilities |
| `demo.py` | Scripted end-to-end walkthrough including tamper and tail-deletion demos |

## Supported Python

Developed and verified on Python 3.12; the codebase targets **3.11+**
(CI runs 3.11 and 3.12).

## Installation

```bash
python -m venv .venv
# Windows:      .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt          # runtime (includes spaCy model)
pip install -r requirements-dev.txt      # tests + quality tooling
```

> **Windows + antivirus TLS scanning:** if `pip install` fails with
> `CERTIFICATE_VERIFY_FAILED` and you run an antivirus that inspects
> HTTPS (e.g. Avast), point pip at its CA bundle instead of disabling
> verification, e.g.
> `$env:PIP_CERT = 'C:\ProgramData\Avast Software\Avast\wscert.pem'`.

## Configuration

All configuration comes from environment variables; for local
development a `.env` file in the working directory is loaded
automatically (documented behaviour — see `.env.example` for every
option with safe placeholders). Secrets are held as Pydantic
`SecretStr` values and never hardcoded.

| Variable | Default | Purpose |
|---|---|---|
| `APP_ENV` | `development` | `development` \| `test` \| `production` |
| `GATEWAY_PROVIDER` | `mock` | `mock` \| `openai` \| `anthropic` |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | — | provider credential (required for that provider in production) |
| `GATEWAY_AUDIT_HMAC_KEY` | dev-only fallback | audit MAC key; **min. 32 chars and required in production** |
| `GATEWAY_ADMIN_API_KEY` | unset | enables + protects the audit endpoints |
| `GATEWAY_AUDIT_DB` | `audit_log.db` | SQLite audit database path |
| `GATEWAY_AUDIT_CHECKPOINT` | unset | external checkpoint file path (enables tail verification) |
| `GATEWAY_POLICY_FILE` | built-in default | JSON entity→action policy override |
| `GATEWAY_SCORE_THRESHOLD` | `0.4` | minimum detector confidence (0–1) |
| `GATEWAY_RESPONSE_SCAN` | `false` | scan/redact provider-generated PII in responses |
| `GATEWAY_AUDIT_STORE_REDACTED_CONTENT` | `false` | research mode: store irreversibly redacted content in audit records |

**Startup refusals.** With `APP_ENV=production` the gateway refuses to
start when the HMAC key is missing, empty, shorter than 32 characters,
or equal to the published development key; when the selected provider's
API key is missing; or when any value (threshold, provider, policy
action) is invalid. The insecure development key is accepted only in
`development`/`test`.

### Policy actions

```json
{"PERSON": "tokenize", "UK_NINO": "redact", "CREDIT_CARD": "block", "DATE_TIME": "allow"}
```

* `allow` — value passes to the provider unchanged; the detection is
  still recorded, so the audit trail shows PII knowingly crossed the
  boundary.
* `tokenize` — replaced by `[[PGW_<8-hex>_<TYPE>_<n>]]`. The namespace
  is random per request; the mapping lives only in request memory and is
  restored only in the response to the caller.
* `redact` — replaced by `[REDACTED:<TYPE>]`, unrecoverable everywhere.
* `block` — the whole request is rejected with HTTP 400 and error code
  `privacy_policy_blocked`; the provider is never contacted; only entity
  *types* are recorded.

Default policy: PERSON, EMAIL_ADDRESS, PHONE_NUMBER, LOCATION,
IP_ADDRESS → tokenize; UK_NINO, IBAN_CODE → redact; CREDIT_CARD,
US_SSN → block; DATE_TIME → allow.

## Running

```bash
python demo.py                 # offline end-to-end walkthrough
python -m gateway.gateway_api  # start the gateway on 127.0.0.1:8000
```

```bash
curl http://127.0.0.1:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o-mini",
       "messages": [{"role": "user", "content": "Email john.smith@example.com about the invoice."}]}'
```

### API surface (limited, strictly validated)

| Endpoint | Purpose |
|---|---|
| `POST /v1/chat/completions` | mediated, audited text chat proxy |
| `GET /v1/audit/entries?limit=&offset=` | paginated audit records (admin key required) |
| `GET /v1/audit/verify` | chain verification incl. checkpoint status (admin key required) |
| `GET /health` | liveness + configured provider |

Supported request fields: `model`, `messages` (roles
system/user/assistant, plain-text content only), `temperature`,
`max_tokens`, `metadata` (small, not forwarded, not audited),
`rehydrate`. **Everything else is rejected with HTTP 422**, including
`stream`, `tools`, `tool_choice`, `functions`, `function_call`, and
structured (image/audio) content. Limits: ≤50 messages, ≤20 000 chars
per message, ≤60 000 chars total.

Every completion response carries `X-Gateway-Request-Id` and
`X-Audit-Entry-Id` headers linking it to its audit record.

### Administrative audit access

The audit endpoints are **disabled** unless `GATEWAY_ADMIN_API_KEY` is
set; requests must present it in the `X-Admin-Api-Key` header
(constant-time comparison; 403 when disabled, 401 on bad credential).
Responses are paginated (max 200/page) and never include content fields.

## Audit log design (accurate terminology)

Each record stores `(id, schema_version, timestamp, payload, prev_hash,
record_hash, record_mac)`:

* `record_hash = SHA-256(id | schema_version | timestamp |
  canonical_payload | prev_hash)` — deterministic UTF-8 canonical JSON,
  stable field order, stable UTC timestamps.
* `record_mac = HMAC-SHA-256(key, record_hash)` — **keyed integrity
  verification**, checked with `hmac.compare_digest`.

**What HMAC gives you (and what it does not).** SHA-256 produces a
content fingerprint; HMAC-SHA-256 authenticates it under a shared
secret. Anyone holding the secret can produce a valid MAC, so the log
is *tamper-evident to a verifier who holds the key*. It is **not** a
digital signature: there is no public verifiability and no
non-repudiation. Protecting `GATEWAY_AUDIT_HMAC_KEY` is essential.

**Detects:** modification of retained records, reordering, interior
deletion, insertion, and re-hashing without the key.
**Cannot detect internally:** deletion of the newest record(s),
deletion of the whole database, or rollback to an older valid copy — a
truncated chain is still a valid chain. `verify_chain()` reports these
honestly (`valid` with `tail_verified: false`) instead of pretending.
Configure `GATEWAY_AUDIT_CHECKPOINT` to store an external checkpoint
(latest record id + MAC) after every append; verification against it
detects tail deletion and rollback up to the checkpoint. The bundled
file-based store demonstrates the mechanism only — a real deployment
must hold checkpoints in a separate trust domain.

SQLite appends run inside `BEGIN IMMEDIATE` transactions with busy
timeout and retry, so concurrent writers cannot fork the chain or
duplicate ids. SQLite is adequate for this single-host prototype, not
for a distributed deployment.

## Fail-closed behaviour

If PII detection, policy evaluation, or sanitization fails for any
reason, the request stops **before** the provider boundary and returns
`PGW-DETECTOR-FAILURE`; the raw prompt is never forwarded unmediated.
Provider failures are mapped to fixed safe codes
(`PGW-PROVIDER-TIMEOUT`, `PGW-PROVIDER-AUTH`, `PGW-PROVIDER-RESPONSE`)
— raw provider exception text is never persisted or returned. The
trade-off: a detector outage makes the gateway unavailable rather than
unsafe; for this system privacy is prioritised over availability.

## Tests and quality tooling

```bash
pytest                          # 162 tests (unit / integration / security)
pytest --cov --cov-report=term  # with coverage (gate: 85%; currently ~96%)
ruff check .                    # lint
ruff format --check .           # formatting
mypy                            # static types (gateway package)
bandit -c pyproject.toml -r gateway
```

No live provider calls anywhere in the suite — provider adapters are
tested through `httpx.MockTransport` and the offline mock. All PII in
fixtures is synthetic. CI (GitHub Actions) runs all of the above on
Python 3.11 and 3.12.

## Known limitations

* **Detection is statistical.** Presidio misses entities (false
  negatives); anything undetected is forwarded untouched regardless of
  policy. See docs/SECURITY_GUARANTEES.md for exactly what is and is
  not claimed.
* Providers can generate *new* PII in responses. By default responses
  are returned as received (only hashes are audited);
  `GATEWAY_RESPONSE_SCAN=true` enables best-effort redaction of
  detected entities in responses.
* The optional redacted-content audit mode
  (`GATEWAY_AUDIT_STORE_REDACTED_CONTENT=true`) stores text that has
  been irreversibly redacted **for detected entities only** — redacted
  text can still contain undetected sensitive information. Off by
  default; leave it off unless you need it for research.
* Tail deletion / rollback of the audit database is only detectable
  against an external checkpoint (see above).
* English-language detection only; text-only (no image/audio) in v1.
* Supported providers: OpenAI-compatible `/chat/completions` endpoints
  and the Anthropic Messages API, via adapters; other providers require
  a new adapter.
