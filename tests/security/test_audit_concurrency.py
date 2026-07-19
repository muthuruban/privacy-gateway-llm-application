"""Concurrent audit writes: multiple logger instances and threads must
produce a gap-free, fork-free, fully valid chain. The object-level lock
of the previous design could not guarantee this — the single-writer
SQLite transaction (BEGIN IMMEDIATE) does."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from gateway.audit_logger import AuditLogger, ChainStatus

KEY = b"concurrency-test-key"


def _hammer(loggers: list[AuditLogger], writes: int) -> None:
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [
            pool.submit(loggers[i % len(loggers)].append, {"write_index": i}) for i in range(writes)
        ]
        for future in futures:
            future.result()  # propagate any failure


class TestConcurrentWrites:
    def test_two_instances_many_threads_no_lost_writes(self, tmp_path):
        db = str(tmp_path / "audit.db")
        loggers = [AuditLogger(db, KEY), AuditLogger(db, KEY)]
        _hammer(loggers, writes=40)

        records = loggers[0].entries()
        assert len(records) == 40  # no write lost
        assert [r.id for r in records] == list(range(1, 41))  # unique, gap-free

    def test_chain_remains_valid_after_concurrent_writes(self, tmp_path):
        db = str(tmp_path / "audit.db")
        loggers = [AuditLogger(db, KEY), AuditLogger(db, KEY)]
        _hammer(loggers, writes=30)

        result = loggers[1].verify_chain()
        assert result.status is ChainStatus.VALID
        assert result.entries_checked == 30

    def test_no_fork_two_records_never_share_prev_hash(self, tmp_path):
        db = str(tmp_path / "audit.db")
        loggers = [AuditLogger(db, KEY), AuditLogger(db, KEY), AuditLogger(db, KEY)]
        _hammer(loggers, writes=30)

        prev_hashes = [r.prev_hash for r in loggers[0].entries()]
        assert len(prev_hashes) == len(set(prev_hashes))

    def test_single_instance_multithreaded(self, tmp_path):
        logger = AuditLogger(str(tmp_path / "audit.db"), KEY)
        _hammer([logger], writes=25)
        assert logger.count() == 25
        assert logger.verify_chain().status is ChainStatus.VALID
