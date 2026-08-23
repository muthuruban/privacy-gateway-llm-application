"""Audit-attack evaluation: replay every tampering class from the
threat model against scratch databases and check that the verifier's
observed behaviour matches the documented claims — including the
honestly-undetectable classes (tail deletion, complete deletion,
rollback), which must verify as valid/empty internally and be caught
only against the external checkpoint.

Usage:  python -m evaluation.run_audit_attack_evaluation
"""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from evaluation.common import environment_metadata, write_results
from gateway.audit_logger import AuditLogger, _compute_record_hash
from gateway.checkpoint import AuditCheckpoint

KEY = b"audit-attack-evaluation-key"


def _fresh_logger(records: int = 5) -> tuple[AuditLogger, Path]:
    workdir = Path(tempfile.mkdtemp(prefix="gateway-audit-attack-"))
    logger = AuditLogger(str(workdir / "audit.db"), KEY)
    for i in range(1, records + 1):
        logger.append({"request_id": f"req-{i}", "note": f"record {i}"})
    return logger, workdir


def _sql(logger: AuditLogger, statement: str, params: tuple = ()) -> None:
    with sqlite3.connect(logger.db_path) as conn:
        conn.execute(statement, params)


def _scenarios() -> list[dict[str, Any]]:
    scenarios: list[dict[str, Any]] = []

    def run(name: str, expected_internal: str, attack, use_checkpoint: bool = False) -> None:
        logger, _ = _fresh_logger()
        checkpoint = logger.create_checkpoint()
        attack(logger)
        internal = logger.verify_chain()
        entry: dict[str, Any] = {
            "scenario": name,
            "expected_internal_status": expected_internal,
            "observed_internal_status": internal.status.value,
            "observed_first_invalid_id": internal.first_invalid_id,
            "internal_matches_expectation": internal.status.value == expected_internal,
        }
        if use_checkpoint:
            with_cp = logger.verify_chain(checkpoint)
            entry["expected_with_checkpoint"] = "invalid"
            entry["observed_with_checkpoint"] = with_cp.status.value
            entry["checkpoint_matches_expectation"] = with_cp.status.value == "invalid"
        scenarios.append(entry)

    run(
        "modify_record_content",
        "invalid",
        lambda lg: _sql(lg, "UPDATE audit_log SET payload = '{}' WHERE id = 3"),
    )
    run(
        "modify_timestamp",
        "invalid",
        lambda lg: _sql(
            lg, "UPDATE audit_log SET timestamp = '2001-01-01T00:00:00+00:00' WHERE id = 2"
        ),
    )
    run(
        "modify_prev_hash",
        "invalid",
        lambda lg: _sql(lg, "UPDATE audit_log SET prev_hash = ? WHERE id = 4", ("f" * 64,)),
    )
    run(
        "delete_middle_record",
        "invalid",
        lambda lg: _sql(lg, "DELETE FROM audit_log WHERE id = 3"),
    )

    def reorder(lg: AuditLogger) -> None:
        _sql(lg, "UPDATE audit_log SET id = 99 WHERE id = 2")
        _sql(lg, "UPDATE audit_log SET id = 2 WHERE id = 3")
        _sql(lg, "UPDATE audit_log SET id = 3 WHERE id = 99")

    run("reorder_records", "invalid", reorder)

    def duplicate(lg: AuditLogger) -> None:
        with sqlite3.connect(lg.db_path) as conn:
            row = conn.execute(
                "SELECT schema_version, timestamp, payload, prev_hash, record_hash,"
                " record_mac FROM audit_log WHERE id = 2"
            ).fetchone()
            conn.execute("INSERT INTO audit_log VALUES (6, ?, ?, ?, ?, ?, ?)", row)

    run("duplicate_record", "invalid", duplicate)

    def rehash_without_key(lg: AuditLogger) -> None:
        with sqlite3.connect(lg.db_path) as conn:
            timestamp, prev_hash = conn.execute(
                "SELECT timestamp, prev_hash FROM audit_log WHERE id = 1"
            ).fetchone()
            forged = '{"note":"forged"}'
            forged_hash = _compute_record_hash(1, 2, timestamp, forged, prev_hash)
            conn.execute(
                "UPDATE audit_log SET payload = ?, record_hash = ? WHERE id = 1",
                (forged, forged_hash),
            )
            conn.execute("UPDATE audit_log SET prev_hash = ? WHERE id = 2", (forged_hash,))

    run("rehash_without_hmac_key", "invalid", rehash_without_key)

    # Wrong verifier key: model a verifier holding a different secret.
    logger, _ = _fresh_logger()
    wrong = AuditLogger(logger.db_path, b"a-different-key").verify_chain()
    scenarios.append(
        {
            "scenario": "verify_with_wrong_key",
            "expected_internal_status": "invalid",
            "observed_internal_status": wrong.status.value,
            "observed_first_invalid_id": wrong.first_invalid_id,
            "internal_matches_expectation": wrong.status.value == "invalid",
        }
    )

    # --- Documented limitations: internal validity is the CORRECT result.
    run(
        "tail_deletion",
        "valid",
        lambda lg: _sql(lg, "DELETE FROM audit_log WHERE id = 5"),
        use_checkpoint=True,
    )
    run(
        "multiple_trailing_deletion",
        "valid",
        lambda lg: _sql(lg, "DELETE FROM audit_log WHERE id >= 4"),
        use_checkpoint=True,
    )
    run(
        "complete_database_deletion",
        "empty",
        lambda lg: Path(lg.db_path).unlink(),
        use_checkpoint=True,
    )

    def rollback() -> None:
        logger, workdir = _fresh_logger(records=3)
        snapshot = workdir / "snapshot.db"
        shutil.copyfile(logger.db_path, snapshot)
        logger.append({"note": "record 4"})
        logger.append({"note": "record 5"})
        checkpoint: AuditCheckpoint = logger.create_checkpoint()  # type: ignore[assignment]
        shutil.copyfile(snapshot, logger.db_path)
        internal = logger.verify_chain()
        with_cp = logger.verify_chain(checkpoint)
        scenarios.append(
            {
                "scenario": "rollback_to_old_valid_database",
                "expected_internal_status": "valid",
                "observed_internal_status": internal.status.value,
                "observed_first_invalid_id": internal.first_invalid_id,
                "internal_matches_expectation": internal.status.value == "valid",
                "expected_with_checkpoint": "invalid",
                "observed_with_checkpoint": with_cp.status.value,
                "checkpoint_matches_expectation": with_cp.status.value == "invalid",
            }
        )

    rollback()

    # A legitimate historical checkpoint verifies the chain only through
    # that record. It must not be reported as proof of a newer current tail.
    logger, _ = _fresh_logger(records=3)
    stale_checkpoint: AuditCheckpoint = logger.create_checkpoint()  # type: ignore[assignment]
    logger.append({"note": "record 4"})
    logger.append({"note": "record 5"})
    internal = logger.verify_chain()
    with_cp = logger.verify_chain(stale_checkpoint)
    stale_ok = with_cp.status.value == "valid" and with_cp.tail_verified is False
    scenarios.append(
        {
            "scenario": "stale_checkpoint_current_tail",
            "expected_internal_status": "valid",
            "observed_internal_status": internal.status.value,
            "observed_first_invalid_id": internal.first_invalid_id,
            "internal_matches_expectation": internal.status.value == "valid",
            "expected_with_checkpoint": "valid",
            "observed_with_checkpoint": with_cp.status.value,
            "expected_tail_verified": False,
            "observed_tail_verified": with_cp.tail_verified,
            "checkpoint_matches_expectation": stale_ok,
        }
    )
    return scenarios


def main() -> None:
    scenarios = _scenarios()
    all_ok = True
    for s in scenarios:
        checks = [s["internal_matches_expectation"], s.get("checkpoint_matches_expectation", True)]
        ok = all(checks)
        all_ok = all_ok and ok
        cp = (
            f", with checkpoint: {s['observed_with_checkpoint']}"
            if "observed_with_checkpoint" in s
            else ""
        )
        print(
            f"{'OK  ' if ok else 'FAIL'} {s['scenario']:<32} internal: "
            f"{s['observed_internal_status']} (expected {s['expected_internal_status']}){cp}"
        )

    payload = {
        "evaluation": "audit_attacks",
        "scenarios": scenarios,
        "all_match_documentation": all_ok,
        "environment": environment_metadata({"records_per_scenario": 5}),
    }
    path = write_results("audit_attacks", payload)
    print(f"\nAll scenarios match documented claims: {all_ok}")
    print(f"Results written to {path}")
    raise SystemExit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
