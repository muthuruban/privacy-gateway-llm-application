"""Leakage evaluation: push every dataset case through the full gateway
and search for the known synthetic values at each boundary:

1. provider-boundary requests (captured by the mock adapter),
2. the audit database (raw file scan),
3. API responses returned on error paths and with rehydration disabled,
4. captured application logs.

Every hit is reported, categorised by root cause:

* ``allowed_crossing``       — the policy action is "allow"; appearing at
  the provider boundary is deliberate and policy-recorded.
* ``detector_false_negative`` — the detector never found the value, so no
  policy could act on it. This is the documented statistical limitation
  of NER-based detection; it is reported, not hidden.
* ``mediation_failure``       — the value WAS detected and still appeared
  somewhere. This would be a pipeline bug and must be zero; the harness
  exits non-zero if any occur. Any appearance in the audit database or
  logs is always classified as a failure, whatever the detector did.

Usage:  python -m evaluation.run_leakage_evaluation
"""

from __future__ import annotations

import io
import logging
import tempfile
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from evaluation.common import environment_metadata, load_dataset, write_results
from evaluation.run_detection_evaluation import _overlaps, _spans_of
from gateway.config import Settings
from gateway.gateway_api import create_app
from gateway.llm_client import MockLLMClient
from gateway.pii_mediator import PIIMediator
from gateway.policy import DEFAULT_POLICY, PolicyAction


def main() -> None:
    cases = load_dataset()
    workdir = tempfile.mkdtemp(prefix="gateway-leak-eval-")
    db_path = str(Path(workdir) / "audit.db")

    settings = Settings.load(
        _env_file=None,
        app_env="test",
        provider="mock",
        audit_db_path=db_path,
        audit_hmac_key="leakage-evaluation-hmac-key-000001",
    )
    mock = MockLLMClient()
    mediator = PIIMediator()
    app = create_app(settings=settings, mediator=mediator, llm_client=mock)
    client = TestClient(app, raise_server_exceptions=False)

    # Capture ALL application logging emitted during the run.
    log_buffer = io.StringIO()
    handler = logging.StreamHandler(log_buffer)
    handler.setLevel(logging.DEBUG)
    logging.getLogger().addHandler(handler)

    responses_text: list[str] = []
    try:
        for case in cases:
            # Rehydration disabled: the caller-visible output should
            # then contain no tokenized values either.
            response = client.post(
                "/v1/chat/completions",
                json={
                    "model": "leak-eval",
                    "messages": [{"role": "user", "content": case["text"]}],
                    "rehydrate": False,
                },
            )
            responses_text.append(response.text)
    finally:
        logging.getLogger().removeHandler(handler)

    provider_text = str(mock.requests_seen)
    audit_text = Path(db_path).read_bytes().decode("utf-8", errors="replace")
    output_text = "\n".join(responses_text)
    logs_text = log_buffer.getvalue()

    surfaces = {
        "provider_boundary": provider_text,
        "audit_database": audit_text,
        "application_output": output_text,
        "captured_logs": logs_text,
    }

    mediation_failures: list[dict[str, Any]] = []
    detector_false_negatives: list[dict[str, Any]] = []
    allowed_crossings: list[dict[str, Any]] = []
    checked = 0
    for case in cases:
        # Root-cause check: what did the detector actually find here?
        detections = mediator.analyze(case["text"])

        for entity in case["entities"]:
            action = DEFAULT_POLICY.get(entity["type"])
            # Type-aware: a value only counts as detected when a detection
            # of the SAME entity type overlaps it — a phone number caught
            # only as a DATE_TIME fragment (an allowed type) gave the
            # pipeline nothing to mediate, which is a detector miss.
            value_spans = _spans_of(case["text"], entity["value"])
            was_detected = any(
                det.entity_type == entity["type"]
                and any(_overlaps((det.start, det.end), span) for span in value_spans)
                for det in detections
            )
            for surface, haystack in surfaces.items():
                checked += 1
                if entity["value"] not in haystack:
                    continue
                finding = {
                    "case": case["id"],
                    "type": entity["type"],
                    "surface": surface,
                    "policy_action": action.value if action else None,
                }
                if action is PolicyAction.ALLOW and surface in (
                    "provider_boundary",
                    "application_output",
                ):
                    allowed_crossings.append(finding)
                elif not was_detected and surface in (
                    "provider_boundary",
                    "application_output",
                ):
                    # Documented limitation: nothing the pipeline could
                    # act on. Audit/log appearances are never excusable
                    # this way (they should hold no content at all).
                    detector_false_negatives.append(finding)
                else:
                    mediation_failures.append(finding)

    print(f"cases: {len(cases)}, value/surface checks: {checked}")
    print(f"allowed crossings (policy 'allow'):        {len(allowed_crossings)}")
    print(f"detector false negatives (documented):     {len(detector_false_negatives)}")
    for finding in detector_false_negatives:
        print(f"  FN   {finding['type']} -> {finding['surface']} [case {finding['case']}]")
    print(f"MEDIATION FAILURES (must be zero):         {len(mediation_failures)}")
    for finding in mediation_failures:
        print(
            f"  LEAK {finding['type']} ({finding['policy_action']}) -> "
            f"{finding['surface']} [case {finding['case']}]"
        )

    payload = {
        "evaluation": "leakage",
        "cases": len(cases),
        "checks": checked,
        "mediation_failures": mediation_failures,
        "detector_false_negatives": detector_false_negatives,
        "allowed_crossings": allowed_crossings,
        "environment": environment_metadata({"policy": "default", "rehydrate": False}),
    }
    path = write_results("leakage", payload)
    print(f"\nResults written to {path}")
    raise SystemExit(1 if mediation_failures else 0)


if __name__ == "__main__":
    main()
