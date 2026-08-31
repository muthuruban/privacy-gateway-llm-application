# Privacy Gateway for PII-Aware LLM Prompt Mediation and HMAC-Authenticated Audit Logging

An MSc Cybersecurity dissertation prototype: a provider-agnostic privacy gateway that sits between a client application and an external LLM provider (OpenAI-compatible, Anthropic, or an offline mock).

On each request it performs:

1. **PII-aware prompt mediation** using Microsoft Presidio plus a configurable per-entity policy with four actions:
   - `allow` - pass the value through unchanged, but record the decision.
   - `tokenize` - replace the value with a reversible request-scoped placeholder.
   - `redact` - replace the value irreversibly.
   - `block` - reject the entire request before provider contact.
2. **HMAC-authenticated audit logging** using a hash-chained, tamper-evident audit log that stores privacy-minimised metadata rather than complete prompts, responses, raw PII, or token mappings.

> **Scope:** this is a limited OpenAI-style text chat endpoint developed as a dissertation research prototype. It is **not** a complete OpenAI-compatible API, not a hardened production product, and no production-readiness claim is made.

```text
Client App -> Gateway (detect -> policy -> tokenize/redact/allow|block -> adapter) -> LLM Provider
                         |
                         v
             Tamper-evident audit store (SQLite)
                         |
                         v
                  External checkpoint
```

Detailed design documents are available in [`docs/`](docs/):

- [ARCHITECTURE](docs/ARCHITECTURE.md)
- [THREAT_MODEL](docs/THREAT_MODEL.md)
- [SECURITY_GUARANTEES](docs/SECURITY_GUARANTEES.md)
- [EVALUATION_GUIDE](docs/EVALUATION_GUIDE.md)
- [AI_USE_DECLARATION_TEMPLATE](docs/AI_USE_DECLARATION_TEMPLATE.md)

## Final evaluated dissertation revision

The quantitative dissertation evaluation was executed against:

```text
Commit: 0c047e040ea745509f894fb5ffca86968ae985f6
Python: 3.12.0
```

This commit is the **frozen evaluated implementation** referenced by the dissertation and generated evaluation outputs.

Later commits may update documentation such as this README without changing the evaluated implementation. Such documentation-only commits should **not** replace the evaluated commit identifier above unless the implementation is changed and the complete evaluation is rerun.

### Final evaluation summary

| Evaluation | Final result |
|---|---|
| Automated tests | 165 passed |
| Statement coverage | 96.10% |
| Ruff lint | Passed |
| Ruff formatting | Passed |
| Mypy | No issues in 11 source files |
| Bandit | No findings |
| Detection dataset | 24 synthetic cases |
| Detection precision | 0.7647 |
| Detection recall | 0.9286 |
| Detection F1 | 0.8387 |
| Leakage evaluation | 112 checks |
| Mediation failures | 0 |
| Detector false-negative appearances | 4 appearances caused by 2 missed telephone values |
| Explicitly allowed appearances | 2 |
| Full gateway + audit latency | 19.08 ms median |
| Full gateway + audit p95 | 26.69 ms |
| Audit-integrity evaluation | 13 scenarios; all matched documented expected behaviour |

The reported dissertation measurements use the offline mock provider and therefore measure the gateway's own behaviour and local processing overhead rather than live commercial-provider network latency.

## Repository layout

| Path | Purpose |
|---|---|
| `gateway/pii_mediator.py` | Presidio wrapper: detection, configured transformations, and custom UK NINO recognition |
| `gateway/tokenization.py` | Request-scoped token context: high-entropy namespace, collision-resistant minting, exact-match restoration, lifecycle cleanup |
| `gateway/policy.py` | Four-action policy model, decision records, and policy-file loading |
| `gateway/audit_logger.py` | Hash-chained and HMAC-authenticated SQLite audit log with chain verification and concurrency-safe appends |
| `gateway/checkpoint.py` | Checkpoint abstraction for tail-deletion and rollback verification plus local demonstration store |
| `gateway/llm_client.py` | OpenAI-compatible, Anthropic, and offline mock provider adapters behind a common interface |
| `gateway/gateway_api.py` | FastAPI orchestration, strict request models, fail-closed processing, response scanning, and admin-gated audit endpoints |
| `gateway/config.py` | Environment-validated Pydantic Settings configuration |
| `gateway/errors.py` | Safe internal `PGW-*` error codes and typed exceptions |
| `tests/unit` | Unit tests |
| `tests/integration` | Integration and API-pipeline tests |
| `tests/security` | Security and adversarial tests |
| `evaluation/run_detection_evaluation.py` | Labelled PII-detection evaluation |
| `evaluation/run_leakage_evaluation.py` | Provider/output/audit/log/error leakage evaluation |
| `evaluation/run_latency_benchmark.py` | Local latency benchmark |
| `evaluation/run_audit_attack_evaluation.py` | Audit-tampering and checkpoint evaluation |
| `evaluation/datasets/` | Synthetic evaluation data |
| `demo.py` | Scripted end-to-end demonstration |

## Supported Python

Developed and finally evaluated on **Python 3.12.0**.

The codebase targets Python **3.11+** and CI is configured for Python 3.11 and 3.12.

## Installation

```bash
python -m venv .venv
```

Activate the environment:

```powershell
# Windows PowerShell
.venv\Scripts\Activate.ps1
```

```bash
# macOS/Linux
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

The runtime requirements include the spaCy model used by Presidio.

> **Windows and antivirus TLS inspection:** if `pip install` fails with `CERTIFICATE_VERIFY_FAILED` because local antivirus software is intercepting HTTPS, configure pip to use the antivirus CA bundle rather than disabling certificate verification.

## Configuration

Configuration is supplied through environment variables. A local `.env` file is loaded for development; see `.env.example` for the available settings.

| Variable | Default | Purpose |
|---|---|---|
| `APP_ENV` | `development` | `development`, `test`, or `production` |
| `GATEWAY_PROVIDER` | `mock` | `mock`, `openai`, or `anthropic` |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | - | Provider credential when the corresponding provider is selected |
| `GATEWAY_AUDIT_HMAC_KEY` | Development-only fallback | HMAC key; required and validated in production |
| `GATEWAY_ADMIN_API_KEY` | unset | Enables and protects audit administration endpoints |
| `GATEWAY_AUDIT_DB` | `audit_log.db` | SQLite audit-database path |
| `GATEWAY_AUDIT_CHECKPOINT` | unset | Checkpoint store path used for tail verification |
| `GATEWAY_POLICY_FILE` | Built-in default | JSON entity-to-action policy override |
| `GATEWAY_SCORE_THRESHOLD` | `0.4` | Minimum PII-detector confidence |
| `GATEWAY_RESPONSE_SCAN` | `false` | Enables best-effort response PII scanning/redaction |
| `GATEWAY_AUDIT_STORE_REDACTED_CONTENT` | `false` | Research-only mode for storing redacted content |

### Production startup validation

With `APP_ENV=production`, the gateway refuses to start when required security configuration is invalid, including an absent or unsafe HMAC key, a missing credential for the selected live provider, or invalid provider/policy/threshold configuration.

## Policy actions

Example policy:

```json
{
  "PERSON": "tokenize",
  "UK_NINO": "redact",
  "CREDIT_CARD": "block",
  "DATE_TIME": "allow"
}
```

- `allow` - the original value can cross the provider boundary and the decision is recorded.
- `tokenize` - replaces the detected value with a request-scoped token such as `[[PGW_<8-hex>_<TYPE>_<n>]]`.
- `redact` - replaces the value with `[REDACTED:<TYPE>]`.
- `block` - rejects the complete request before provider contact.

For tokenisation, the random namespace and mapping exist only for the current request. Restoration uses exact current-request tokens, and the request-scoped mapping is cleared when processing terminates, including failure paths.

Default policy:

- `PERSON`, `EMAIL_ADDRESS`, `PHONE_NUMBER`, `LOCATION`, `IP_ADDRESS` -> `tokenize`
- `UK_NINO`, `IBAN_CODE` -> `redact`
- `CREDIT_CARD`, `US_SSN` -> `block`
- `DATE_TIME` -> `allow`

## Running the gateway

Offline demonstration:

```bash
python demo.py
```

Start the API:

```bash
python -m gateway.gateway_api
```

Default development address:

```text
http://127.0.0.1:8000
```

Example request:

```bash
curl http://127.0.0.1:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Email john.smith@example.com about the invoice."}]}'
```

## API surface

| Endpoint | Purpose |
|---|---|
| `POST /v1/chat/completions` | Mediated and audited text-chat request |
| `GET /v1/audit/entries?limit=&offset=` | Paginated audit metadata; admin credential required |
| `GET /v1/audit/verify` | Audit-chain and checkpoint verification; admin credential required |
| `GET /health` | Liveness and configured-provider information |

The prototype accepts a deliberately restricted request schema. Unsupported features such as streaming, tools/functions, and structured image/audio content are rejected rather than silently ignored.

Every successful completion response includes `X-Gateway-Request-Id` and `X-Audit-Entry-Id` headers.

## Administrative audit access

Audit administration endpoints are disabled unless `GATEWAY_ADMIN_API_KEY` is configured.

Requests must provide the credential in:

```text
X-Admin-Api-Key
```

Credential comparison uses constant-time comparison. Audit responses are paginated and do not expose complete prompt or response content.

## Fail-closed behaviour

### Request-side privacy failures

If PII detection, policy evaluation, or request mediation fails before provider contact, processing stops and the raw request is not forwarded unmediated.

The design therefore prioritises confidentiality over availability for privacy-critical request-side failures.

### Provider failures

Provider errors are mapped to stable safe error codes such as:

```text
PGW-PROVIDER-TIMEOUT
PGW-PROVIDER-AUTH
PGW-PROVIDER-RESPONSE
```

Raw provider exception text is not returned to the caller or persisted as audit content.

### Response-scan failure

If optional response scanning is enabled and fails **after the provider has already been contacted**, the provider response is withheld from the client.

The failure is represented using:

```text
PGW-RESPONSE-SCAN-FAILURE
```

The corresponding audit outcome records that provider contact occurred but that the failed response was not returned. This distinguishes a post-provider response-processing failure from a request-side fail-closed event.

## Audit log design

Each audit record stores fields including:

```text
id
schema_version
timestamp
payload
prev_hash
record_hash
record_mac
```

Conceptually:

```text
record_hash = SHA-256(id | schema_version | timestamp | canonical_payload | prev_hash)
record_mac  = HMAC-SHA-256(key, record_hash)
```

HMAC provides keyed integrity verification. It is **not** a digital signature and does not provide public verifiability or non-repudiation.

### Internal chain detection

Within the documented threat model, the authenticated chain can detect manipulation such as modification of retained record data, predecessor alteration, reordering, interior deletion, unauthorised re-hashing, and verification with the wrong HMAC key.

### Checkpoints and tail verification

An internally valid hash chain cannot by itself establish that the newest records have not been deleted or that the database has not been rolled back to an older valid state.

Checkpoint comparison is therefore used to test tail deletion, complete database deletion, and rollback to an older valid database.

A **valid but stale checkpoint** authenticates the historical state represented by that checkpoint, but it does **not** verify the current audit tail. The verifier therefore distinguishes historical checkpoint validity from current-tail verification.

The bundled file-based checkpoint store is a research demonstration. A production deployment would require checkpoint protection in a separate trust domain.

SQLite appends use transactional write handling appropriate to the single-host prototype. SQLite is not presented as a distributed audit-store architecture.

## Tests and quality checks

Run the automated suite:

```bash
pytest
```

Run with coverage:

```bash
pytest --cov --cov-report=term
```

Run the remaining quality checks:

```bash
ruff check .
ruff format --check .
mypy
bandit -c pyproject.toml -r gateway
```

Final evaluated results:

```text
165 tests passed
96.10% statement coverage
Ruff lint passed
Ruff formatting passed
Mypy: no issues in 11 source files
Bandit: no findings
```

The configured coverage gate is 85%.

No live provider calls are required by the test suite; provider adapters are exercised through mock transports and the offline mock provider.

## Reproducing the dissertation evaluations

The repository contains four dedicated evaluation utilities:

```bash
python evaluation/run_detection_evaluation.py
python evaluation/run_leakage_evaluation.py
python evaluation/run_latency_benchmark.py
python evaluation/run_audit_attack_evaluation.py
```

The evaluation utilities write machine-readable result artefacts containing environment/configuration information and source-version provenance. See [`docs/EVALUATION_GUIDE.md`](docs/EVALUATION_GUIDE.md) for the repository's detailed evaluation procedure and any optional command-line settings.

For strict reproduction of the dissertation's published measurements, first check out the frozen evaluated implementation:

```bash
git checkout 0c047e040ea745509f894fb5ffca86968ae985f6
```

Then recreate the documented environment, install the dependencies, and run the test, quality, and evaluation commands above.

Performance values can vary across hardware and operating systems. The dissertation therefore treats the recorded latency values as measurements from the documented evaluation environment, not universal timings.

## Final dissertation evaluation results

### PII detection

Across 24 synthetic labelled cases:

```text
TP = 26
FP = 8
FN = 2

Precision = 0.7647
Recall    = 0.9286
F1        = 0.8387
```

The two false negatives were labelled `PHONE_NUMBER` values. Detection quality varies by entity type and the aggregate metrics should not be interpreted as a guarantee for unseen data.

### Leakage evaluation

Across 112 explicit checks:

```text
Mediation failures:                  0
Detector false-negative appearances: 4
Explicitly allowed appearances:      2
Audit-store findings:                0
Log findings:                        0
Error-response findings:             0
```

The four false-negative appearances were caused by two missed telephone values, each observed at the mock-provider boundary and application output.

The defensible conclusion is:

> No detected value assigned a protective action bypassed mediation in the evaluated cases; however, detector false negatives can still cross the provider boundary.

### Latency

For a 121-character synthetic prompt, 50 measured iterations were recorded after five warm-up iterations using the offline mock provider:

| Configuration | Median (ms) | p95 (ms) |
|---|---:|---:|
| Mock provider only | 2.02 | 2.72 |
| Detection only | 9.01 | 14.51 |
| Detection + tokenisation | 7.65 | 12.20 |
| Full gateway + audit | 19.08 | 26.69 |

These figures measure local prototype overhead only.

### Audit integrity

Thirteen audit-integrity scenarios were evaluated and all produced the documented expected outcomes.

Modification, reordering, and interior-deletion scenarios were detected by internal verification. Tail deletion, complete deletion, and rollback required checkpoint comparison.

The stale-checkpoint test confirmed that an older valid checkpoint can authenticate historical state without verifying the current tail.

## Known limitations

- **PII detection is probabilistic.** Undetected values are not mediated by policy.
- **Explicitly allowed PII can cross the provider boundary by design.**
- Providers may generate new PII in responses. Optional response scanning is best effort rather than a complete guarantee.
- Research-only redacted-content audit mode can still retain undetected sensitive information and is disabled by default.
- Tail deletion and rollback require a sufficiently protected external checkpoint.
- HMAC security depends on protection of the shared secret.
- The prototype is English-focused and text-only.
- Streaming, tools/function calling, multimodal content, and distributed deployment are outside the implemented scope.
- The main evaluation used synthetic data and an offline mock provider.
- The prototype was not evaluated with real patient data, a live healthcare organisation, or production-scale workloads.

## Research interpretation

This project should not be interpreted as claiming invention of PII detection, tokenisation, LLM gateway mediation, hash chaining, or HMAC.

Its contribution is the **engineering integration and evaluation** of configurable per-entity PII mediation, request-scoped reversible tokenisation, provider abstraction, privacy-minimised auditing, HMAC-authenticated hash chaining, and explicit checkpoint semantics within one self-hosted research prototype.
