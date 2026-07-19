"""
Module purpose
--------------

Safe logging configuration for the gateway process.

Security responsibility
-----------------------

The gateway's own log statements never include prompt content, token
mappings, or secrets — but third-party libraries do not honour that
rule. Presidio's analyzer, for example, logs fragments of the text
surrounding a detection at DEBUG level ("Found context keyword ...").
If an operator enables global DEBUG logging, those fragments — raw PII
included — would land in the application logs.

``configure_safe_logging`` therefore pins the known content-leaking
library loggers to INFO (or stricter), so a global DEBUG setting cannot
switch them on by accident.

Important limitation
--------------------

This is a targeted allowlist, not a general PII filter for log records.
An operator who *explicitly* re-enables DEBUG on these loggers, or adds
a new content-logging dependency, steps outside the tested guarantee —
that trade-off is documented in docs/SECURITY_GUARANTEES.md.
"""

from __future__ import annotations

import logging

#: Loggers known to emit request-content fragments below INFO level.
_CONTENT_LEAKING_LOGGERS = (
    "presidio-analyzer",
    "presidio-anonymizer",
    # Presidio's optional detection-explanation trace; it describes
    # matched text and is not needed by the gateway.
    "decision_process",
)


def configure_safe_logging() -> None:
    """
    Pin content-leaking third-party loggers to INFO or stricter.

    Security reason:
        A global ``logging.basicConfig(level=DEBUG)`` (a one-line,
        common debugging step) must not silently start writing raw
        prompt fragments to the operational logs.
    """
    for name in _CONTENT_LEAKING_LOGGERS:
        third_party = logging.getLogger(name)
        if third_party.level == logging.NOTSET or third_party.level < logging.INFO:
            third_party.setLevel(logging.INFO)
