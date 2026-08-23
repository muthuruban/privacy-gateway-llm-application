"""
Module purpose
--------------

Write and verify the tamper-evident audit log: a hash-chained sequence
of HMAC-authenticated records in SQLite. Each record stores privacy-safe
metadata about one request/response cycle — never prompts, responses,
raw PII, or token mappings.

Security responsibility
-----------------------

* Integrity: each record's hash covers its content, its position (id),
  and the previous record's hash, so edits, interior deletions,
  reordering, and insertions are detectable. A per-record HMAC-SHA-256
  under a key held outside the database means an attacker with database
  write access cannot recompute a consistent chain without the key.
* Concurrency: appends run inside a single ``BEGIN IMMEDIATE``
  transaction that reads the previous record and inserts the next one,
  so concurrent writers (multiple logger instances, threads, or
  processes) cannot fork the chain or duplicate ids.

Important terminology note
--------------------------

HMAC is a *keyed integrity* mechanism, not a digital signature. Anyone
holding the shared secret can produce a valid MAC, so this log offers
tamper evidence to a verifier who holds the key — it does not offer
public verifiability or non-repudiation.

Important limitation
--------------------

The internal chain cannot independently detect deletion of the newest
record(s), deletion of the whole database, or replacement with an older
valid copy: a truncated chain is still a valid chain. Detecting those
requires comparing against an external checkpoint stored outside the
database (see gateway/checkpoint.py and docs/SECURITY_GUARANTEES.md).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from .checkpoint import AuditCheckpoint, CheckpointStore
from .errors import AuditWriteError

#: prev_hash of the first (genesis) record.
GENESIS_HASH = "0" * 64

#: Version of the audit record schema, covered by the record hash so a
#: verifier knows exactly how to recompute it.
AUDIT_SCHEMA_VERSION = 2

_BUSY_TIMEOUT_MS = 5000
_APPEND_RETRIES = 5

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id             INTEGER PRIMARY KEY,
    schema_version INTEGER NOT NULL,
    timestamp      TEXT NOT NULL,
    payload        TEXT NOT NULL,
    prev_hash      TEXT NOT NULL,
    record_hash    TEXT NOT NULL,
    record_mac     TEXT NOT NULL
);
"""


class ChainStatus(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    EMPTY = "empty"
    UNVERIFIABLE_AGAINST_EXTERNAL_CHECKPOINT = "unverifiable_against_external_checkpoint"


@dataclass
class AuditRecord:
    id: int
    schema_version: int
    timestamp: str
    payload: dict[str, Any]
    prev_hash: str
    record_hash: str
    record_mac: str


@dataclass
class ChainVerificationResult:
    status: ChainStatus
    #: Number of records actually examined before verification stopped
    #: (equals the total only when the whole chain was walked).
    entries_checked: int
    first_invalid_id: int | None = None
    reason: str | None = None
    #: True only when the newest record was confirmed against an external
    #: checkpoint. The internal chain alone can never establish this.
    tail_verified: bool = False


def canonical_json(payload: dict[str, Any]) -> str:
    """Deterministic UTF-8 JSON encoding (sorted keys, fixed separators)
    so the same payload always produces the same bytes to hash."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_canonical(payload: dict[str, Any] | list[Any] | str) -> str:
    """SHA-256 fingerprint of a JSON-serializable value. Used to bind an
    audit record to content (prompt/response) without storing it."""
    if not isinstance(payload, str):
        payload = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _utc_now() -> str:
    """Stable UTC timestamp format used in every record."""
    return datetime.now(UTC).isoformat(timespec="microseconds")


def _compute_record_hash(
    record_id: int, schema_version: int, timestamp: str, payload_json: str, prev_hash: str
) -> str:
    """
    Hash over all fields of the record, including its id and prev_hash.

    Security reason:
        Including the id makes renumbering detectable; including
        prev_hash chains the record to its predecessor so reordering and
        interior deletion break verification.
    """
    material = f"{record_id}|{schema_version}|{timestamp}|{payload_json}|{prev_hash}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class AuditLogger:
    """Append-only, hash-chained, HMAC-authenticated audit log (SQLite).

    SQLite with a single-writer transaction is adequate for this
    prototype's single-host deployment; a distributed deployment would
    need a database with stronger multi-node coordination.
    """

    def __init__(
        self,
        db_path: str,
        hmac_key: bytes,
        checkpoint_store: CheckpointStore | None = None,
    ) -> None:
        self.db_path = db_path
        self._hmac_key = hmac_key
        self._checkpoint_store = checkpoint_store
        self._connect().close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        # Idempotent schema creation on every connection: verification of
        # a deleted-and-recreated database must report "empty" (a real,
        # documented limitation) instead of crashing on a missing table.
        conn.execute(_SCHEMA)
        conn.commit()
        return conn

    def _mac(self, record_hash: str) -> str:
        return hmac.new(self._hmac_key, record_hash.encode("utf-8"), hashlib.sha256).hexdigest()

    def append(self, payload: dict[str, Any]) -> AuditRecord:
        """
        Append one audit record. ``payload`` must already be privacy-safe
        metadata — this method persists exactly what it is given.

        Security reason:
            The previous record is read and the new record inserted
            inside one ``BEGIN IMMEDIATE`` transaction. Without that,
            two concurrent writers could both read the same predecessor
            and fork the chain (two records with the same prev_hash).

        Raises:
            AuditWriteError: if the record cannot be durably written.
                Callers treat this as fatal for the request — a cycle
                without audit evidence must not succeed silently.
        """
        payload_json = canonical_json(payload)

        last_error: Exception | None = None
        for attempt in range(_APPEND_RETRIES):
            try:
                record = self._append_once(payload_json, payload)
                break
            except sqlite3.OperationalError as exc:
                # Another writer may hold the lock longer than the busy
                # timeout; back off briefly and retry.
                last_error = exc
                time.sleep(0.05 * (attempt + 1))
        else:
            raise AuditWriteError() from last_error

        if self._checkpoint_store is not None:
            # The checkpoint is the tail-deletion defence; failing to
            # update it silently would quietly void that property.
            try:
                self._checkpoint_store.save(
                    AuditCheckpoint(
                        last_record_id=record.id,
                        last_record_mac=record.record_mac,
                        created_at=_utc_now(),
                    )
                )
            except OSError as exc:
                raise AuditWriteError() from exc
        return record

    def _append_once(self, payload_json: str, payload: dict[str, Any]) -> AuditRecord:
        timestamp = _utc_now()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT id, record_hash FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if row is None:
                next_id, prev_hash = 1, GENESIS_HASH
            else:
                next_id, prev_hash = int(row[0]) + 1, str(row[1])

            record_hash = _compute_record_hash(
                next_id, AUDIT_SCHEMA_VERSION, timestamp, payload_json, prev_hash
            )
            record_mac = self._mac(record_hash)
            conn.execute(
                "INSERT INTO audit_log"
                " (id, schema_version, timestamp, payload, prev_hash, record_hash, record_mac)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    next_id,
                    AUDIT_SCHEMA_VERSION,
                    timestamp,
                    payload_json,
                    prev_hash,
                    record_hash,
                    record_mac,
                ),
            )
            conn.commit()
        except BaseException:
            # Roll back completely rather than leave a partial chain.
            conn.rollback()
            raise
        finally:
            conn.close()

        return AuditRecord(
            next_id, AUDIT_SCHEMA_VERSION, timestamp, payload, prev_hash, record_hash, record_mac
        )

    def count(self) -> int:
        # Note: sqlite3's "with conn" manages transactions, not closing;
        # closing.close() is required or the file handle lingers (which
        # also breaks database deletion on Windows).
        with closing(self._connect()) as conn:
            return int(conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0])

    def entries(self, limit: int | None = None, offset: int = 0) -> list[AuditRecord]:
        query = (
            "SELECT id, schema_version, timestamp, payload, prev_hash, record_hash, record_mac"
            " FROM audit_log ORDER BY id"
        )
        params: tuple[int, ...] = ()
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            params = (limit, offset)
        with closing(self._connect()) as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            AuditRecord(
                int(r[0]), int(r[1]), str(r[2]), json.loads(r[3]), str(r[4]), str(r[5]), str(r[6])
            )
            for r in rows
        ]

    def latest(self) -> AuditRecord | None:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT id, schema_version, timestamp, payload, prev_hash, record_hash,"
                " record_mac FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        return AuditRecord(
            int(row[0]),
            int(row[1]),
            str(row[2]),
            json.loads(row[3]),
            str(row[4]),
            str(row[5]),
            str(row[6]),
        )

    def create_checkpoint(self) -> AuditCheckpoint | None:
        """Checkpoint the current tail (or None for an empty log)."""
        last = self.latest()
        if last is None:
            return None
        return AuditCheckpoint(
            last_record_id=last.id, last_record_mac=last.record_mac, created_at=_utc_now()
        )

    def verify_chain(self, checkpoint: AuditCheckpoint | None = None) -> ChainVerificationResult:
        """
        Walk the log from the genesis record and report the first point
        of tampering, if any.

        Per record it checks: id sequence, linkage to the previous
        record's hash, the recomputed record hash, and the HMAC.

        Integrity limitation:
            Without ``checkpoint``, a chain whose newest records were
            deleted — or a database rolled back to an older valid copy —
            still verifies as ``valid``. This method reports what it can
            actually establish (``tail_verified`` stays False) rather
            than pretending to detect tail deletion.

        Args:
            checkpoint: externally stored expectation about the tail.
                The record it names must exist with a matching MAC. Only
                a checkpoint for the current newest record verifies the
                current tail; an older valid checkpoint verifies history
                only up to that record.

        Returns:
            ChainVerificationResult; ``entries_checked`` is the number of
            records actually examined, including a failing one.
        """
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT id, schema_version, timestamp, payload, prev_hash, record_hash,"
                " record_mac FROM audit_log ORDER BY id"
            ).fetchall()

        if not rows:
            if checkpoint is not None:
                return ChainVerificationResult(
                    ChainStatus.INVALID,
                    0,
                    None,
                    "the external checkpoint expects records, but the log is empty"
                    " (complete deletion or replacement)",
                )
            return ChainVerificationResult(ChainStatus.EMPTY, 0)

        checked = 0
        expected_prev = GENESIS_HASH
        expected_id = 1
        macs_by_id: dict[int, str] = {}
        for record_id, schema_version, timestamp, payload_json, prev_hash, record_hash, mac in rows:
            checked += 1
            record_id = int(record_id)
            if record_id != expected_id:
                return ChainVerificationResult(
                    ChainStatus.INVALID,
                    checked,
                    record_id,
                    f"record id {record_id} breaks the sequence (expected {expected_id}):"
                    " a record was deleted, duplicated, or renumbered",
                )
            if prev_hash != expected_prev:
                return ChainVerificationResult(
                    ChainStatus.INVALID,
                    checked,
                    record_id,
                    "prev_hash does not match the previous record's hash: chain linkage"
                    " broken (edit, reorder, or deletion upstream)",
                )
            recomputed = _compute_record_hash(
                record_id, int(schema_version), timestamp, payload_json, prev_hash
            )
            if recomputed != record_hash:
                return ChainVerificationResult(
                    ChainStatus.INVALID,
                    checked,
                    record_id,
                    "stored record_hash does not match the recomputed hash: record"
                    " content was modified",
                )
            if not hmac.compare_digest(self._mac(record_hash), mac):
                return ChainVerificationResult(
                    ChainStatus.INVALID,
                    checked,
                    record_id,
                    "record MAC invalid: the record was re-hashed without the audit key",
                )
            macs_by_id[record_id] = mac
            expected_prev = record_hash
            expected_id += 1

        if checkpoint is not None:
            expected_mac = macs_by_id.get(checkpoint.last_record_id)
            if expected_mac is None:
                return ChainVerificationResult(
                    ChainStatus.INVALID,
                    checked,
                    None,
                    f"the external checkpoint expects record {checkpoint.last_record_id},"
                    " which is missing (tail deletion or database rollback)",
                )
            if not hmac.compare_digest(expected_mac, checkpoint.last_record_mac):
                return ChainVerificationResult(
                    ChainStatus.INVALID,
                    checked,
                    checkpoint.last_record_id,
                    "the record named by the external checkpoint has a different MAC"
                    " (rewritten history or checkpoint mismatch)",
                )
            latest_id = int(rows[-1][0])
            if checkpoint.last_record_id != latest_id:
                return ChainVerificationResult(
                    ChainStatus.VALID,
                    checked,
                    None,
                    "the external checkpoint verifies history through record "
                    f"{checkpoint.last_record_id}, but the current tail is record {latest_id}; "
                    "the checkpoint is stale and does not verify the current tail",
                    tail_verified=False,
                )
            return ChainVerificationResult(ChainStatus.VALID, checked, tail_verified=True)

        return ChainVerificationResult(ChainStatus.VALID, checked)

    def verify_with_store(self, store: CheckpointStore | None) -> ChainVerificationResult:
        """Verify against a checkpoint store, reporting the tail as
        unverifiable when the store has no checkpoint yet."""
        if store is None:
            return self.verify_chain()
        checkpoint = store.load()
        if checkpoint is None:
            result = self.verify_chain()
            if result.status is ChainStatus.VALID:
                return ChainVerificationResult(
                    ChainStatus.UNVERIFIABLE_AGAINST_EXTERNAL_CHECKPOINT,
                    result.entries_checked,
                    None,
                    "internal chain is consistent, but no external checkpoint exists to"
                    " verify the tail against",
                )
            return result
        return self.verify_chain(checkpoint)
