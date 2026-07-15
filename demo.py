"""End-to-end demo of the privacy gateway.

Walks one request through every stage and prints what each boundary sees:

1. A prompt containing PII is sent to the gateway.
2. The sanitized prompt — what the LLM provider actually receives — is
   shown (tokenized + redacted, no raw PII).
3. The LLM's response is shown twice: as the provider produced it (tokens
   intact) and as the calling application receives it (rehydrated).
4. The corresponding tamper-evident audit entry is printed.
5. One stored entry is deliberately modified in SQLite, and
   ``verify_chain()`` pinpoints the tampering.

Runs fully offline against the built-in mock provider by default. Set
GATEWAY_PROVIDER=openai (with OPENAI_API_KEY) or GATEWAY_PROVIDER=anthropic
(with ANTHROPIC_API_KEY) to run against a real provider instead.

Usage:  python demo.py
"""

import json
import os
import sqlite3
import tempfile

from fastapi.testclient import TestClient

from gateway.audit_logger import AuditLogger
from gateway.config import Settings
from gateway.gateway_api import create_app
from gateway.llm_client import MockLLMClient, build_client

WIDTH = 74


def banner(title: str) -> None:
    print()
    print("=" * WIDTH)
    print(f"  {title}")
    print("=" * WIDTH)


def main() -> None:
    # A fresh, throwaway audit DB so the demo is repeatable.
    db_path = os.path.join(tempfile.mkdtemp(prefix="gateway-demo-"), "audit.db")
    settings = Settings.from_env()
    settings.audit_db_path = db_path

    audit_logger = AuditLogger(db_path=db_path, hmac_key=settings.audit_hmac_key)
    llm_client = build_client(settings)
    app = create_app(settings=settings, logger=audit_logger, llm_client=llm_client)
    client = TestClient(app)

    prompt = (
        "Hi, I'm John Smith. Please email the contract to "
        "john.smith@example.com or call me on +44 7911 123456. "
        "For billing use card 4111 1111 1111 1111, and my national "
        "insurance number is AB 12 34 56 C."
    )

    banner("1. Original prompt (as the client application sends it)")
    print(prompt)

    response = client.post(
        "/v1/chat/completions",
        json={
            "model": os.environ.get("GATEWAY_DEMO_MODEL", "demo-model"),
            "messages": [{"role": "user", "content": prompt}],
        },
    )
    response.raise_for_status()
    audit_id = int(response.headers["X-Audit-Entry-Id"])
    entry = next(e for e in audit_logger.entries() if e.id == audit_id)

    banner("2. Sanitized prompt (what the LLM provider actually received)")
    if isinstance(llm_client, MockLLMClient):
        # The mock records exactly what crossed the provider boundary.
        print(llm_client.requests_seen[-1]["messages"][0]["content"])
    else:
        print(entry.payload["sanitized_messages"][0]["content"])
    print()
    print("PII findings:", json.dumps(entry.payload["pii_findings"], indent=2))

    banner("3a. Provider response, before rehydration (tokens intact)")
    print(entry.payload["sanitized_response"]["choices"][0]["message"]["content"])

    banner("3b. Response delivered to the client (tokens rehydrated)")
    print(response.json()["choices"][0]["message"]["content"])
    print()
    print("Note: tokenized values (name, email, phone) are restored for the")
    print("client only; blocked values (card, NINO) stay redacted forever.")

    banner("4. Audit log entry (hash-chained + HMAC-signed, no raw PII)")
    print(f"id:         {entry.id}")
    print(f"timestamp:  {entry.timestamp}")
    print(f"prev_hash:  {entry.prev_hash}")
    print(f"entry_hash: {entry.entry_hash}")
    print(f"signature:  {entry.signature}")
    print(f"payload:    {json.dumps(entry.payload, indent=2)[:800]} ...")

    verification = audit_logger.verify_chain()
    print(f"\nverify_chain(): valid={verification.valid} "
          f"({verification.entries_checked} entries checked)")

    banner("5. Tampering with the stored entry - and detecting it")
    print(f"Rewriting payload of entry {entry.id} directly in SQLite...")
    tampered = dict(entry.payload)
    tampered["pii_findings"] = {}  # attacker hides that PII was ever present
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE audit_log SET payload = ? WHERE id = ?",
            (json.dumps(tampered, sort_keys=True, separators=(",", ":")), entry.id),
        )

    verification = audit_logger.verify_chain()
    print()
    print(f"verify_chain(): valid={verification.valid}")
    print(f"first invalid entry: {verification.first_invalid_id}")
    print(f"reason: {verification.reason}")

    banner("Demo complete")
    print(f"Audit DB left at: {db_path}")


if __name__ == "__main__":
    main()
