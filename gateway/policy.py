"""
Module purpose
--------------

Define the privacy policy model: the four actions the gateway can take
for a detected entity type, the default policy, policy-file loading, and
the safe PolicyDecision records that describe what was decided.

Security responsibility
-----------------------

* BLOCK and REDACT are distinct: REDACT irreversibly replaces a value
  and lets the request continue; BLOCK rejects the whole request before
  any provider contact. Conflating them would silently forward requests
  the operator intended to stop.
* ALLOW is an explicit, recorded decision — allowed entities are still
  detected, so the audit trail can show that PII knowingly crossed the
  provider boundary.
* PolicyDecision carries only entity types, actions, counts, and score
  ranges — never detected values.

Important limitation
--------------------

A policy can only act on what the detector finds. Undetected PII
(false negatives) is not covered by any action, including BLOCK.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from .errors import ConfigurationError


class PolicyAction(StrEnum):
    ALLOW = "allow"  # keep the value; record that it was allowed
    TOKENIZE = "tokenize"  # reversible request-scoped placeholder
    REDACT = "redact"  # irreversible replacement; request continues
    BLOCK = "block"  # reject the whole request; no provider call


#: Default policy. Identity-linked but conversationally useful entities
#: are tokenized; UK NINO and IBAN are irreversibly redacted; card and
#: SSN data blocks the request outright; dates are explicitly allowed
#: (and still detected, so the allowance is auditable).
DEFAULT_POLICY: dict[str, PolicyAction] = {
    "PERSON": PolicyAction.TOKENIZE,
    "EMAIL_ADDRESS": PolicyAction.TOKENIZE,
    "PHONE_NUMBER": PolicyAction.TOKENIZE,
    "LOCATION": PolicyAction.TOKENIZE,
    "IP_ADDRESS": PolicyAction.TOKENIZE,
    "UK_NINO": PolicyAction.REDACT,
    "IBAN_CODE": PolicyAction.REDACT,
    "CREDIT_CARD": PolicyAction.BLOCK,
    "US_SSN": PolicyAction.BLOCK,
    "DATE_TIME": PolicyAction.ALLOW,
}


class PolicyDecision(BaseModel):
    """One per detected entity type per request. Safe to persist: contains
    metadata about the decision, never the detected value."""

    model_config = ConfigDict(frozen=True)

    entity_type: str
    action: PolicyAction
    count: int
    score_min: float
    score_max: float
    request_blocked: bool
    reason_code: str


def load_policy(path: str | os.PathLike[str] | None = None) -> dict[str, PolicyAction]:
    """
    Load an entity→action policy from a JSON file, or return the default.

    Raises:
        ConfigurationError: if the file is unreadable or contains an
            unknown action name. An invalid policy must stop startup —
            guessing at intent could forward data the operator meant to
            block.
    """
    if path is None:
        return dict(DEFAULT_POLICY)
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return {entity: PolicyAction(action) for entity, action in raw.items()}
    except (OSError, ValueError) as exc:
        raise ConfigurationError(
            "The privacy policy file could not be loaded or contains an unknown action."
        ) from exc


def build_decisions(
    detections: Iterable[tuple[str, float]],
    policy: dict[str, PolicyAction],
) -> list[PolicyDecision]:
    """
    Summarize raw detections into one PolicyDecision per entity type.

    Args:
        detections: (entity_type, confidence_score) pairs for every
            detection across all messages of one request.
        policy: the active entity→action policy.

    Returns:
        Decisions sorted by entity type, with counts and score ranges.
    """
    grouped: dict[str, list[float]] = {}
    for entity_type, score in detections:
        if entity_type in policy:
            grouped.setdefault(entity_type, []).append(score)

    decisions = []
    for entity_type in sorted(grouped):
        scores = grouped[entity_type]
        action = policy[entity_type]
        decisions.append(
            PolicyDecision(
                entity_type=entity_type,
                action=action,
                count=len(scores),
                score_min=round(min(scores), 3),
                score_max=round(max(scores), 3),
                request_blocked=action is PolicyAction.BLOCK,
                reason_code=f"policy_{action.value}",
            )
        )
    return decisions


def blocked_entity_types(decisions: Iterable[PolicyDecision]) -> list[str]:
    """Entity types whose policy action requires rejecting the request."""
    return [d.entity_type for d in decisions if d.request_blocked]
