"""Audit logger tests: chain integrity on the happy path, and detection of
content tampering, reordering, deletion, and signature forgery."""

import sqlite3

import pytest

from gateway.audit_logger import AuditLogger

KEY = b"test-signing-key"


@pytest.fixture
def logger(tmp_path):
    return AuditLogger(db_path=str(tmp_path / "audit.db"), hmac_key=KEY)


def _populate(logger: AuditLogger, n: int = 5) -> None:
    for i in range(1, n + 1):
        logger.append({"request_id": f"req-{i}", "note": f"entry {i}"})


class TestHappyPath:
    def test_empty_log_verifies(self, logger):
        result = logger.verify_chain()
        assert result.valid
        assert result.entries_checked == 0

    def test_intact_chain_verifies(self, logger):
        _populate(logger)
        result = logger.verify_chain()
        assert result.valid
        assert result.entries_checked == 5
        assert result.first_invalid_id is None

    def test_entries_are_linked(self, logger):
        _populate(logger, 3)
        entries = logger.entries()
        assert entries[0].prev_hash == "0" * 64
        assert entries[1].prev_hash == entries[0].entry_hash
        assert entries[2].prev_hash == entries[1].entry_hash

    def test_payload_round_trip(self, logger):
        entry = logger.append({"request_id": "abc", "pii_findings": {"PERSON": 2}})
        stored = logger.entries()[-1]
        assert stored.payload == {"request_id": "abc", "pii_findings": {"PERSON": 2}}
        assert stored.id == entry.id


class TestTamperDetection:
    def test_content_edit_is_detected_at_the_right_entry(self, logger):
        _populate(logger)
        # Attacker rewrites the payload of entry 3 directly in SQLite.
        with sqlite3.connect(logger.db_path) as conn:
            conn.execute(
                "UPDATE audit_log SET payload = ? WHERE id = 3",
                ('{"note":"entry 3 — falsified","request_id":"req-3"}',),
            )
        result = logger.verify_chain()
        assert not result.valid
        assert result.first_invalid_id == 3
        assert "modified" in result.reason

    def test_deletion_is_detected(self, logger):
        _populate(logger)
        with sqlite3.connect(logger.db_path) as conn:
            conn.execute("DELETE FROM audit_log WHERE id = 2")
        result = logger.verify_chain()
        assert not result.valid
        assert result.first_invalid_id == 3

    def test_reordering_is_detected(self, logger):
        _populate(logger)
        # Swap the ids of entries 2 and 3.
        with sqlite3.connect(logger.db_path) as conn:
            conn.execute("UPDATE audit_log SET id = 99 WHERE id = 2")
            conn.execute("UPDATE audit_log SET id = 2 WHERE id = 3")
            conn.execute("UPDATE audit_log SET id = 3 WHERE id = 99")
        result = logger.verify_chain()
        assert not result.valid
        assert result.first_invalid_id == 2

    def test_rehash_without_key_is_detected(self, logger):
        """An attacker who recomputes hashes for the whole chain still fails
        on the HMAC signature, because they don't hold the signing key."""
        from gateway.audit_logger import _compute_entry_hash

        _populate(logger, 2)
        with sqlite3.connect(logger.db_path) as conn:
            row = conn.execute(
                "SELECT timestamp, prev_hash FROM audit_log WHERE id = 1"
            ).fetchone()
            forged_payload = '{"note":"forged","request_id":"req-1"}'
            forged_hash = _compute_entry_hash(1, row[0], forged_payload, row[1])
            conn.execute(
                "UPDATE audit_log SET payload = ?, entry_hash = ? WHERE id = 1",
                (forged_payload, forged_hash),
            )
            # Also fix up entry 2's prev_hash, as a capable attacker would.
            conn.execute(
                "UPDATE audit_log SET prev_hash = ? WHERE id = 2", (forged_hash,)
            )
        result = logger.verify_chain()
        assert not result.valid
        assert result.first_invalid_id == 1
        assert "signature" in result.reason.lower()

    def test_wrong_key_fails_verification(self, tmp_path):
        db = str(tmp_path / "audit.db")
        AuditLogger(db_path=db, hmac_key=b"key-one").append({"a": 1})
        result = AuditLogger(db_path=db, hmac_key=b"key-two").verify_chain()
        assert not result.valid
        assert result.first_invalid_id == 1
