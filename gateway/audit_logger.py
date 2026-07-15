"""Tamper-evident audit logging.

Every request/response cycle through the gateway produces one audit entry.
Two independent mechanisms make the log tamper-evident:

1. **Hash chaining** — each entry stores ``prev_hash``, the SHA-256 hash of
   the previous entry. Modifying, deleting, or reordering any past entry
   breaks the chain at that point, because the next entry's ``prev_hash``
   no longer matches.
2. **Per-entry HMAC signature** — each entry's hash is signed with
   HMAC-SHA256 under a key held outside the database. An attacker with
   write access to the database file can rewrite an entry *and* recompute
   its hash and every downstream ``prev_hash``, but cannot forge the
   signatures without the key.

``verify_chain`` walks the log from the genesis entry and reports the first
entry at which either mechanism fails.

Only sanitized data is ever passed to ``append`` — the audit trail must
never contain raw PII. Enforcing that is the caller's job (the gateway
logs the sanitized request and the provider's raw response, which only
ever contained placeholder tokens).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone

#: prev_hash of the first (genesis) entry.
GENESIS_HASH = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT NOT NULL,
    payload    TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    signature  TEXT NOT NULL
);
"""


@dataclass
class AuditEntry:
    id: int
    timestamp: str
    payload: dict
    prev_hash: str
    entry_hash: str
    signature: str


@dataclass
class ChainVerificationResult:
    valid: bool
    entries_checked: int
    #: id of the first entry that fails verification, if any.
    first_invalid_id: int | None = None
    reason: str | None = None


def _canonical_json(payload: dict) -> str:
    """Deterministic JSON encoding, so hashes are reproducible."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _compute_entry_hash(entry_id: int, timestamp: str, payload_json: str, prev_hash: str) -> str:
    """Hash over every field of the entry, including its position (id) and
    the previous entry's hash — so content edits, renumbering, reordering,
    and deletion are all detectable."""
    material = f"{entry_id}|{timestamp}|{payload_json}|{prev_hash}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class AuditLogger:
    """Append-only, hash-chained, HMAC-signed audit log backed by SQLite."""

    def __init__(self, db_path: str, hmac_key: bytes):
        self.db_path = db_path
        self._hmac_key = hmac_key
        # Appends must be serialized: each entry's prev_hash depends on the
        # entry before it.
        self._write_lock = threading.Lock()
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _sign(self, entry_hash: str) -> str:
        return hmac.new(self._hmac_key, entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()

    def append(self, payload: dict) -> AuditEntry:
        """Append one audit entry. ``payload`` must already be sanitized."""
        payload_json = _canonical_json(payload)
        timestamp = datetime.now(timezone.utc).isoformat()

        with self._write_lock, self._connect() as conn:
            row = conn.execute(
                "SELECT id, entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if row is None:
                next_id, prev_hash = 1, GENESIS_HASH
            else:
                next_id, prev_hash = row[0] + 1, row[1]

            entry_hash = _compute_entry_hash(next_id, timestamp, payload_json, prev_hash)
            signature = self._sign(entry_hash)
            conn.execute(
                "INSERT INTO audit_log (id, timestamp, payload, prev_hash, entry_hash, signature)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (next_id, timestamp, payload_json, prev_hash, entry_hash, signature),
            )

        return AuditEntry(next_id, timestamp, payload, prev_hash, entry_hash, signature)

    def entries(self) -> list[AuditEntry]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, timestamp, payload, prev_hash, entry_hash, signature"
                " FROM audit_log ORDER BY id"
            ).fetchall()
        return [
            AuditEntry(r[0], r[1], json.loads(r[2]), r[3], r[4], r[5]) for r in rows
        ]

    def verify_chain(self) -> ChainVerificationResult:
        """Walk the whole log and return the first point of tampering, if any.

        Checks, per entry: hash-chain linkage to the previous entry,
        integrity of the entry's own hash, and the HMAC signature.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, timestamp, payload, prev_hash, entry_hash, signature"
                " FROM audit_log ORDER BY id"
            ).fetchall()

        expected_prev = GENESIS_HASH
        expected_id = 1
        for entry_id, timestamp, payload_json, prev_hash, entry_hash, signature in rows:
            if entry_id != expected_id:
                return ChainVerificationResult(
                    False, len(rows), entry_id,
                    f"entry id {entry_id} breaks sequence (expected {expected_id}):"
                    " an entry was deleted or renumbered",
                )
            if prev_hash != expected_prev:
                return ChainVerificationResult(
                    False, len(rows), entry_id,
                    "prev_hash does not match the previous entry's hash:"
                    " chain linkage broken (edit, reorder, or deletion upstream)",
                )
            recomputed = _compute_entry_hash(entry_id, timestamp, payload_json, prev_hash)
            if recomputed != entry_hash:
                return ChainVerificationResult(
                    False, len(rows), entry_id,
                    "stored entry_hash does not match recomputed hash:"
                    " entry content was modified",
                )
            if not hmac.compare_digest(self._sign(entry_hash), signature):
                return ChainVerificationResult(
                    False, len(rows), entry_id,
                    "HMAC signature invalid: entry was re-hashed without the signing key",
                )
            expected_prev = entry_hash
            expected_id += 1

        return ChainVerificationResult(True, len(rows))
