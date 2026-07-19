"""
Module purpose
--------------

Define the external audit checkpoint: a small record of the newest audit
entry (id + MAC), stored *outside* the audit database, that lets a
verifier detect tail deletion and database rollback.

Security responsibility
-----------------------

The internal hash chain cannot prove that the newest records were not
deleted, or that the whole database was not replaced by an older valid
copy — a truncated chain is still a valid chain. Comparing the database
against a checkpoint held elsewhere closes that gap for all records up
to the checkpoint.

Important limitation
--------------------

A checkpoint is only as trustworthy as where it is stored. The
LocalFileCheckpointStore below writes a JSON file on the same host and
exists to demonstrate the mechanism in this prototype; an attacker who
can rewrite the audit database can usually rewrite a local file too. A
real deployment must place checkpoints in a separate trust domain
(different host, append-only store, or a write-once service).
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

CHECKPOINT_VERSION = 1


@dataclass(frozen=True)
class AuditCheckpoint:
    """The externally stored expectation about the audit log's tail."""

    last_record_id: int
    last_record_mac: str
    created_at: str  # UTC ISO 8601
    version: int = CHECKPOINT_VERSION


class CheckpointStore(Protocol):
    """Anything that can persist and return the latest checkpoint."""

    def save(self, checkpoint: AuditCheckpoint) -> None: ...

    def load(self) -> AuditCheckpoint | None: ...


class LocalFileCheckpointStore:
    """JSON-file checkpoint store for the dissertation prototype.

    Trust assumption: the file lives outside the audit database but on
    the same host, so it only demonstrates the verification mechanism —
    it does not provide an independent trust domain (see module header).
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)

    def save(self, checkpoint: AuditCheckpoint) -> None:
        # Write-then-rename so a crash cannot leave a half-written
        # checkpoint that would make every later verification fail.
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=self._path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(asdict(checkpoint), handle)
            os.replace(tmp_name, self._path)
        except OSError:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
            raise

    def load(self) -> AuditCheckpoint | None:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return AuditCheckpoint(
                last_record_id=int(data["last_record_id"]),
                last_record_mac=str(data["last_record_mac"]),
                created_at=str(data["created_at"]),
                version=int(data.get("version", CHECKPOINT_VERSION)),
            )
        except FileNotFoundError:
            return None
        except (OSError, ValueError, KeyError):
            # A corrupt checkpoint is treated as "no checkpoint": the
            # verifier will report the tail as unverifiable rather than
            # inventing a failure it cannot substantiate.
            return None
