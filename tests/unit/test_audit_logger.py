"""Audit chain: happy path, every detectable tampering class, the
honestly-reported undetectable classes (tail deletion, complete
deletion, rollback), checkpoint verification, and entries_checked
accuracy."""

from __future__ import annotations

import shutil
import sqlite3

import pytest

from gateway.audit_logger import (
    AuditLogger,
    ChainStatus,
    _compute_record_hash,
)
from gateway.checkpoint import AuditCheckpoint, LocalFileCheckpointStore

KEY = b"unit-test-audit-key"


@pytest.fixture
def logger(tmp_path):
    return AuditLogger(db_path=str(tmp_path / "audit.db"), hmac_key=KEY)


def _populate(logger: AuditLogger, n: int = 5) -> None:
    for i in range(1, n + 1):
        logger.append({"request_id": f"req-{i}", "note": f"entry {i}"})


class TestHappyPath:
    def test_empty_log_reports_empty_status(self, logger):
        result = logger.verify_chain()
        assert result.status is ChainStatus.EMPTY
        assert result.entries_checked == 0

    def test_intact_chain_is_valid(self, logger):
        _populate(logger)
        result = logger.verify_chain()
        assert result.status is ChainStatus.VALID
        assert result.entries_checked == 5
        assert result.first_invalid_id is None
        assert result.tail_verified is False  # no checkpoint given

    def test_records_are_linked(self, logger):
        _populate(logger, 3)
        records = logger.entries()
        assert records[0].prev_hash == "0" * 64
        assert records[1].prev_hash == records[0].record_hash
        assert records[2].prev_hash == records[1].record_hash

    def test_payload_round_trip_and_schema_version(self, logger):
        appended = logger.append({"request_id": "abc", "entity_counts": {"PERSON": 2}})
        stored = logger.entries()[-1]
        assert stored.payload == {"request_id": "abc", "entity_counts": {"PERSON": 2}}
        assert stored.schema_version == 2
        assert stored.id == appended.id

    def test_entries_pagination(self, logger):
        _populate(logger, 5)
        page = logger.entries(limit=2, offset=2)
        assert [r.id for r in page] == [3, 4]
        assert logger.count() == 5


class TestDetectableTampering:
    def test_content_modification_detected_at_right_record(self, logger):
        _populate(logger)
        with sqlite3.connect(logger.db_path) as conn:
            conn.execute(
                "UPDATE audit_log SET payload = ? WHERE id = 3",
                ('{"note":"entry 3 falsified","request_id":"req-3"}',),
            )
        result = logger.verify_chain()
        assert result.status is ChainStatus.INVALID
        assert result.first_invalid_id == 3
        assert result.entries_checked == 3  # records 1..3 examined
        assert "modified" in result.reason

    def test_timestamp_modification_detected(self, logger):
        _populate(logger, 3)
        with sqlite3.connect(logger.db_path) as conn:
            conn.execute(
                "UPDATE audit_log SET timestamp = '2001-01-01T00:00:00+00:00' WHERE id = 2"
            )
        result = logger.verify_chain()
        assert result.status is ChainStatus.INVALID
        assert result.first_invalid_id == 2

    def test_prev_hash_modification_detected(self, logger):
        _populate(logger, 3)
        with sqlite3.connect(logger.db_path) as conn:
            conn.execute("UPDATE audit_log SET prev_hash = ? WHERE id = 3", ("f" * 64,))
        result = logger.verify_chain()
        assert result.status is ChainStatus.INVALID
        assert result.first_invalid_id == 3
        assert "linkage" in result.reason

    def test_middle_deletion_detected(self, logger):
        _populate(logger)
        with sqlite3.connect(logger.db_path) as conn:
            conn.execute("DELETE FROM audit_log WHERE id = 2")
        result = logger.verify_chain()
        assert result.status is ChainStatus.INVALID
        assert result.first_invalid_id == 3
        assert result.entries_checked == 2  # examined records 1 and 3

    def test_reordering_detected(self, logger):
        _populate(logger)
        with sqlite3.connect(logger.db_path) as conn:
            conn.execute("UPDATE audit_log SET id = 99 WHERE id = 2")
            conn.execute("UPDATE audit_log SET id = 2 WHERE id = 3")
            conn.execute("UPDATE audit_log SET id = 3 WHERE id = 99")
        result = logger.verify_chain()
        assert result.status is ChainStatus.INVALID
        assert result.first_invalid_id == 2

    def test_duplicate_record_detected(self, logger):
        _populate(logger, 5)
        with sqlite3.connect(logger.db_path) as conn:
            row = conn.execute(
                "SELECT schema_version, timestamp, payload, prev_hash, record_hash,"
                " record_mac FROM audit_log WHERE id = 3"
            ).fetchone()
            conn.execute("INSERT INTO audit_log VALUES (6, ?, ?, ?, ?, ?, ?)", row)
        result = logger.verify_chain()
        assert result.status is ChainStatus.INVALID
        assert result.first_invalid_id == 6

    def test_rehash_without_key_detected(self, logger):
        """An attacker who rewrites a record and recomputes hashes (and
        downstream prev_hash values) still fails on the MAC, because they
        do not hold the shared audit key."""
        _populate(logger, 2)
        with sqlite3.connect(logger.db_path) as conn:
            row = conn.execute("SELECT timestamp, prev_hash FROM audit_log WHERE id = 1").fetchone()
            forged_payload = '{"note":"forged","request_id":"req-1"}'
            forged_hash = _compute_record_hash(1, 2, row[0], forged_payload, row[1])
            conn.execute(
                "UPDATE audit_log SET payload = ?, record_hash = ? WHERE id = 1",
                (forged_payload, forged_hash),
            )
            conn.execute("UPDATE audit_log SET prev_hash = ? WHERE id = 2", (forged_hash,))
        result = logger.verify_chain()
        assert result.status is ChainStatus.INVALID
        assert result.first_invalid_id == 1
        assert result.entries_checked == 1  # stopped at the first record
        assert "MAC" in result.reason

    def test_wrong_key_fails_at_first_record(self, tmp_path):
        db = str(tmp_path / "audit.db")
        AuditLogger(db_path=db, hmac_key=b"key-one").append({"a": 1})
        result = AuditLogger(db_path=db, hmac_key=b"key-two").verify_chain()
        assert result.status is ChainStatus.INVALID
        assert result.first_invalid_id == 1
        assert result.entries_checked == 1


class TestDocumentedLimitations:
    """These attacks are NOT internally detectable; the verifier must say
    so honestly rather than fake a failure, and must detect them when an
    external checkpoint is available."""

    def test_tail_deletion_not_detected_internally(self, logger):
        _populate(logger, 5)
        with sqlite3.connect(logger.db_path) as conn:
            conn.execute("DELETE FROM audit_log WHERE id = 5")
        result = logger.verify_chain()
        # Honest result: the remaining chain IS valid; tail unverified.
        assert result.status is ChainStatus.VALID
        assert result.entries_checked == 4
        assert result.tail_verified is False

    def test_tail_deletion_detected_with_checkpoint(self, logger):
        _populate(logger, 5)
        checkpoint = logger.create_checkpoint()
        with sqlite3.connect(logger.db_path) as conn:
            conn.execute("DELETE FROM audit_log WHERE id = 5")
        result = logger.verify_chain(checkpoint)
        assert result.status is ChainStatus.INVALID
        assert "tail deletion" in result.reason

    def test_stale_checkpoint_does_not_verify_current_tail(self, logger):
        _populate(logger, 3)
        checkpoint = logger.create_checkpoint()
        _populate(logger, 2)

        result = logger.verify_chain(checkpoint)

        assert result.status is ChainStatus.VALID
        assert result.entries_checked == 5
        assert result.tail_verified is False
        assert "stale" in result.reason

    def test_multiple_trailing_deletion_with_and_without_checkpoint(self, logger):
        _populate(logger, 5)
        checkpoint = logger.create_checkpoint()
        with sqlite3.connect(logger.db_path) as conn:
            conn.execute("DELETE FROM audit_log WHERE id >= 4")
        assert logger.verify_chain().status is ChainStatus.VALID  # limitation
        assert logger.verify_chain(checkpoint).status is ChainStatus.INVALID

    def test_complete_deletion_with_and_without_checkpoint(self, tmp_path):
        db = tmp_path / "audit.db"
        logger = AuditLogger(db_path=str(db), hmac_key=KEY)
        _populate(logger, 3)
        checkpoint = logger.create_checkpoint()
        db.unlink()
        # Internally: an empty log is just an empty log (limitation).
        assert logger.verify_chain().status is ChainStatus.EMPTY
        # Against the checkpoint: provably wrong.
        result = logger.verify_chain(checkpoint)
        assert result.status is ChainStatus.INVALID
        assert "empty" in result.reason

    def test_rollback_to_old_valid_copy(self, tmp_path):
        db = tmp_path / "audit.db"
        snapshot = tmp_path / "audit-snapshot.db"
        logger = AuditLogger(db_path=str(db), hmac_key=KEY)
        _populate(logger, 3)
        shutil.copyfile(db, snapshot)  # attacker keeps an old valid copy
        _populate(logger, 2)  # records 4 and 5
        checkpoint = logger.create_checkpoint()
        shutil.copyfile(snapshot, db)  # rollback
        # Internally: the old copy is a perfectly valid chain (limitation).
        internal = logger.verify_chain()
        assert internal.status is ChainStatus.VALID
        assert internal.entries_checked == 3
        # Against the checkpoint: record 5 is missing → detected.
        result = logger.verify_chain(checkpoint)
        assert result.status is ChainStatus.INVALID
        assert "rollback" in result.reason


class TestCheckpointStore:
    def test_local_store_round_trip(self, tmp_path):
        store = LocalFileCheckpointStore(tmp_path / "checkpoint.json")
        assert store.load() is None
        checkpoint = AuditCheckpoint(3, "ab" * 32, "2026-01-01T00:00:00+00:00")
        store.save(checkpoint)
        assert store.load() == checkpoint

    def test_corrupt_checkpoint_treated_as_missing(self, tmp_path):
        path = tmp_path / "checkpoint.json"
        path.write_text("{not json")
        assert LocalFileCheckpointStore(path).load() is None

    def test_verify_with_store_reports_unverifiable_without_checkpoint(self, logger, tmp_path):
        _populate(logger, 2)
        store = LocalFileCheckpointStore(tmp_path / "checkpoint.json")
        result = logger.verify_with_store(store)
        assert result.status is ChainStatus.UNVERIFIABLE_AGAINST_EXTERNAL_CHECKPOINT

    def test_logger_updates_configured_store_on_append(self, tmp_path):
        store = LocalFileCheckpointStore(tmp_path / "checkpoint.json")
        logger = AuditLogger(str(tmp_path / "audit.db"), KEY, checkpoint_store=store)
        _populate(logger, 2)
        checkpoint = store.load()
        assert checkpoint is not None
        assert checkpoint.last_record_id == 2
        result = logger.verify_with_store(store)
        assert result.status is ChainStatus.VALID
        assert result.tail_verified is True

    def test_mismatched_checkpoint_mac_detected(self, logger):
        _populate(logger, 2)
        bad = AuditCheckpoint(2, "0" * 64, "2026-01-01T00:00:00+00:00")
        result = logger.verify_chain(bad)
        assert result.status is ChainStatus.INVALID
        assert result.first_invalid_id == 2
