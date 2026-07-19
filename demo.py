"""End-to-end demo of the privacy gateway.

Walks through every core behaviour and prints what each trust boundary
actually sees:

1. A prompt with tokenize/redact/allow entities is mediated; the
   provider's view, and the response before/after rehydration, are shown.
2. A prompt with a BLOCK-policy entity (synthetic test card number) is
   rejected before any provider contact.
3. The corresponding privacy-minimised audit records are shown.
4. A stored record is tampered with directly in SQLite and
   verify_chain() pinpoints it.
5. The tail-deletion limitation is demonstrated honestly: deleting the
   newest record is invisible to the internal chain, and detected only
   against the external checkpoint.

Runs fully offline against the built-in mock provider by default. All
PII values are synthetic.

Usage:  python demo.py
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile

from fastapi.testclient import TestClient

from gateway.audit_logger import AuditLogger
from gateway.checkpoint import LocalFileCheckpointStore
from gateway.config import Settings
from gateway.gateway_api import create_app
from gateway.llm_client import MockLLMClient

WIDTH = 74


def banner(title: str) -> None:
    print()
    print("=" * WIDTH)
    print(f"  {title}")
    print("=" * WIDTH)


def main() -> None:
    # Fresh throwaway working directory so the demo is repeatable.
    workdir = tempfile.mkdtemp(prefix="gateway-demo-")
    db_path = os.path.join(workdir, "audit.db")
    checkpoint_path = os.path.join(workdir, "checkpoint.json")

    settings = Settings.load(
        _env_file=None,
        app_env="development",
        provider="mock",
        audit_db_path=db_path,
        audit_checkpoint_path=checkpoint_path,
        audit_hmac_key="demo-only-hmac-key-do-not-use-in-production",
    )
    checkpoint_store = LocalFileCheckpointStore(checkpoint_path)
    audit = AuditLogger(db_path, settings.audit_hmac_key_bytes, checkpoint_store=checkpoint_store)
    mock_provider = MockLLMClient()
    app = create_app(settings=settings, audit_logger=audit, llm_client=mock_provider)
    client = TestClient(app, raise_server_exceptions=False)

    # ---------------------------------------------------------- 1
    prompt = (
        "Hi, I'm John Smith. Please email the contract to "
        "john.smith@example.com or call me on +44 7911 123456. My "
        "national insurance number is AB 12 34 56 C. Deliver it by "
        "25 December 2025."
    )
    banner("1a. Original prompt (as the client application sends it)")
    print(prompt)

    response = client.post(
        "/v1/chat/completions",
        json={"model": "demo-model", "messages": [{"role": "user", "content": prompt}]},
    )
    response.raise_for_status()

    banner("1b. Provider-safe prompt (what the LLM provider actually received)")
    print(mock_provider.requests_seen[-1]["messages"][0]["content"])
    print()
    print("tokenize -> [[PGW_...]] placeholders (reversible, this request only)")
    print("redact   -> [REDACTED:UK_NINO]      (irreversible)")
    print("allow    -> the date passed through, and is recorded as allowed")

    banner("1c. Response delivered to the client (tokens rehydrated)")
    print(response.json()["choices"][0]["message"]["content"])

    # ---------------------------------------------------------- 2
    banner("2. BLOCK policy: request rejected before any provider contact")
    calls_before = len(mock_provider.requests_seen)
    blocked = client.post(
        "/v1/chat/completions",
        json={
            "model": "demo-model",
            "messages": [{"role": "user", "content": "Charge card 4111 1111 1111 1111 for this."}],
        },
    )
    print(f"HTTP status: {blocked.status_code}")
    print(json.dumps(blocked.json(), indent=2))
    print(
        f"Provider calls made for this request: {len(mock_provider.requests_seen) - calls_before}"
    )

    # ---------------------------------------------------------- 3
    banner("3. Audit records (privacy-minimised: metadata and hashes only)")
    for record in audit.entries():
        payload = record.payload
        print(f"record {record.id}: event={payload['event']}, status={payload['status']}")
        decisions = payload.get("policy_decisions", [])
        for d in decisions:
            print(f"    {d['entity_type']:<14} action={d['action']:<8} count={d['count']}")
        if payload.get("prompt_hash"):
            print(f"    prompt_hash:   {payload['prompt_hash'][:32]}...")
        print(f"    record_mac:    {record.record_mac[:32]}...")

    verification = audit.verify_with_store(checkpoint_store)
    print(
        f"\nverify: status={verification.status.value}, "
        f"entries_checked={verification.entries_checked}, "
        f"tail_verified={verification.tail_verified}"
    )

    # ---------------------------------------------------------- 4
    banner("4. Tampering with a stored record - and detecting it")
    target = audit.entries()[0]
    tampered = dict(target.payload)
    tampered["policy_decisions"] = []  # attacker hides that PII was found
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE audit_log SET payload = ? WHERE id = ?",
            (json.dumps(tampered, sort_keys=True, separators=(",", ":")), target.id),
        )
    result = audit.verify_chain()
    print(f"status:           {result.status.value}")
    print(f"first invalid id: {result.first_invalid_id}")
    print(f"reason:           {result.reason}")

    # Restore the original payload so the chain is intact for part 5.
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE audit_log SET payload = ? WHERE id = ?",
            (
                json.dumps(target.payload, sort_keys=True, separators=(",", ":")),
                target.id,
            ),
        )

    # ---------------------------------------------------------- 5
    banner("5. Tail deletion: the honest limitation, and the checkpoint fix")
    with sqlite3.connect(db_path) as conn:
        last_id = conn.execute("SELECT MAX(id) FROM audit_log").fetchone()[0]
        conn.execute("DELETE FROM audit_log WHERE id = ?", (last_id,))
    print(f"Deleted the newest record (id {last_id}) directly in SQLite.\n")

    internal = audit.verify_chain()
    print("Internal chain only:")
    print(f"    status={internal.status.value} (a truncated chain is still a valid chain!)")
    print(f"    tail_verified={internal.tail_verified}")

    external = audit.verify_with_store(checkpoint_store)
    print("Against the external checkpoint:")
    print(f"    status={external.status.value}")
    print(f"    reason: {external.reason}")

    banner("Demo complete")
    print(f"Working files in: {workdir}")


if __name__ == "__main__":
    main()
