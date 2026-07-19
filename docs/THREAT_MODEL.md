# Threat model

## Protected assets

1. **Raw PII in prompts** — names, emails, phone numbers, government
   identifiers, card numbers supplied by end users of the client
   application.
2. **The token↔value mapping** — the only route from a placeholder back
   to a real value during a request.
3. **The audit log's integrity** — the evidential value of the record
   of what crossed the provider boundary.
4. **Secrets** — the audit HMAC key, the admin API key, provider API
   keys.

## Actors

| Actor | Trust | Notes |
|---|---|---|
| Client application | trusted for its own data | receives rehydrated values; can disable rehydration |
| Gateway operator | trusted | holds all secrets and the host |
| External LLM provider | **untrusted** for PII | must only ever see provider-safe text |
| Audit verifier | holds the HMAC key | can check integrity, not publicly |
| Attacker with DB write access | untrusted | primary audit-tampering adversary |
| Network attacker | untrusted | TLS assumed for provider traffic |

## Trust assumptions

* **Trusted gateway host.** The gateway process, its memory, its
  environment variables, and its local files are trusted. An attacker
  who can read process memory obtains live token mappings; one who can
  read the environment obtains every key. No in-process mechanism
  defends against a compromised host.
* **Detector best-effort.** Presidio's recognizers are assumed to have
  useful but imperfect recall. Every guarantee is bounded by detection.
* **Checkpoint separation.** Tail-deletion/rollback detection assumes
  the checkpoint is stored where the DB attacker cannot rewrite it. The
  bundled local-file store does *not* satisfy this — it demonstrates the
  mechanism only.

## Attack surfaces

1. The public `POST /v1/chat/completions` endpoint (input validation,
   oversized payloads, placeholder spoofing in prompts).
2. The admin audit endpoints (credential guessing, information
   disclosure through records).
3. The provider channel (malicious/malformed responses, token forgery
   in responses, provider-generated PII, exception content).
4. The audit database file (modification, reordering, deletion,
   duplication, rollback).
5. Configuration/environment (weak or default keys, missing
   credentials).
6. Operational logs (content leakage via third-party debug loggers).

## In-scope attacks (addressed and tested)

| Attack | Defence |
|---|---|
| PII in prompts reaching the provider | detection + tokenize/redact/block before the adapter; fail-closed on detector failure |
| Wrong-value restoration across messages | one request-level tokenization context; distinct values can never share a token |
| Placeholder spoofing (user or model supplies fake/partial tokens) | high-entropy namespace + exact whole-token lookup; unknown tokens pass through untouched |
| Cross-request token replay | mappings are request-scoped and cleared; namespaces differ per request |
| Audit record modification / reordering / interior deletion / insertion | hash chain over (id, content, prev_hash) |
| Re-hashing the chain after tampering | per-record HMAC under a key held outside the DB |
| Tail deletion / rollback (with checkpoint configured) | external checkpoint comparison |
| Provider exception content reaching logs/audit/API | typed errors with fixed messages; unmapped exceptions wrapped |
| Provider-generated PII persisted in the audit store | metadata-only records; response hash instead of text |
| Unauthorised audit access | endpoints disabled by default; constant-time admin key check |
| Weak/default HMAC key in production | startup refusal |
| Unsupported API fields silently ignored | `extra="forbid"`, explicit 422 |
| Third-party debug logs leaking prompt fragments | content-leaking loggers pinned to INFO |

## Out-of-scope attacks (documented, not defended)

* **Compromised gateway host** (memory scraping, env exfiltration, log
  tampering at the OS level).
* **HMAC-key compromise** — the holder can forge arbitrarily long valid
  chains; the log then proves nothing. Key rotation/HSM storage is
  future work.
* **Checkpoint-store compromise** when it shares the DB's trust domain
  (as the demo file store does).
* **Detector false negatives** — undetected PII crosses the boundary
  under whatever policy would have applied to it. This is inherent to
  statistical NER; measured, not prevented (see EVALUATION_GUIDE.md).
* **Semantic leakage** — an LLM can sometimes infer identity from
  context that contains no detectable entity (writing style, role
  descriptions, rare event details). No entity-level mechanism prevents
  this.
* **Traffic analysis** of the gateway↔provider channel (timing, sizes).
* **Denial of service** beyond basic request-size limits.
* **Malicious client applications** — a caller that already holds the
  PII it submits learns nothing new from rehydration, but rate limiting
  and caller authentication are not implemented in this prototype.

## Provider-generated PII

The provider can emit PII that never appeared in the prompt (memorised
training data, hallucinated contact details). Default handling: the
response is returned to the caller as received (their choice to use a
generative model), while the audit store keeps only a hash. With
`GATEWAY_RESPONSE_SCAN=true`, detected entities in responses are
irreversibly redacted before return — subject to the same false-negative
limitation as request scanning.

## Database tampering, tail truncation, and rollback

An attacker with SQLite write access can modify, reorder, delete, or
duplicate records: all detected by the chain + MAC (tested per class in
`tests/unit/test_audit_logger.py`). The same attacker can also truncate
the tail or restore an older complete copy; the internal chain cannot
distinguish this from a legitimately shorter log — `verify_chain()`
reports `valid` with `tail_verified: false` rather than a fake
detection. With an external checkpoint the verifier detects both,
bounded by checkpoint freshness (records appended after the last
checkpoint are unprotected until the next one is written; the gateway
checkpoints after every append when configured).
