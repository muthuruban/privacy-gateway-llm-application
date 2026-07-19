"""Policy model: four distinct actions, decision building, file loading."""

from __future__ import annotations

import json

import pytest

from gateway.errors import ConfigurationError
from gateway.policy import (
    DEFAULT_POLICY,
    PolicyAction,
    blocked_entity_types,
    build_decisions,
    load_policy,
)


class TestPolicyActions:
    def test_four_distinct_actions_exist(self):
        assert {a.value for a in PolicyAction} == {"allow", "tokenize", "redact", "block"}

    def test_default_policy_uses_all_four_actions(self):
        actions = set(DEFAULT_POLICY.values())
        assert actions == set(PolicyAction)

    def test_block_and_redact_are_distinct_defaults(self):
        assert DEFAULT_POLICY["CREDIT_CARD"] is PolicyAction.BLOCK
        assert DEFAULT_POLICY["UK_NINO"] is PolicyAction.REDACT


class TestLoadPolicy:
    def test_none_returns_default_copy(self):
        policy = load_policy(None)
        assert policy == DEFAULT_POLICY
        policy["PERSON"] = PolicyAction.BLOCK
        assert DEFAULT_POLICY["PERSON"] is PolicyAction.TOKENIZE

    def test_loads_valid_file(self, tmp_path):
        path = tmp_path / "policy.json"
        path.write_text(json.dumps({"EMAIL_ADDRESS": "redact", "PERSON": "allow"}))
        policy = load_policy(path)
        assert policy == {
            "EMAIL_ADDRESS": PolicyAction.REDACT,
            "PERSON": PolicyAction.ALLOW,
        }

    def test_unknown_action_raises_configuration_error(self, tmp_path):
        path = tmp_path / "policy.json"
        path.write_text(json.dumps({"EMAIL_ADDRESS": "obfuscate"}))
        with pytest.raises(ConfigurationError):
            load_policy(path)

    def test_missing_file_raises_configuration_error(self, tmp_path):
        with pytest.raises(ConfigurationError):
            load_policy(tmp_path / "nope.json")


class TestBuildDecisions:
    def test_groups_by_entity_type_with_counts_and_scores(self):
        decisions = build_decisions(
            [
                ("EMAIL_ADDRESS", 0.9),
                ("EMAIL_ADDRESS", 0.7),
                ("CREDIT_CARD", 1.0),
            ],
            DEFAULT_POLICY,
        )
        by_type = {d.entity_type: d for d in decisions}
        email = by_type["EMAIL_ADDRESS"]
        assert email.action is PolicyAction.TOKENIZE
        assert email.count == 2
        assert email.score_min == 0.7
        assert email.score_max == 0.9
        assert email.request_blocked is False
        assert email.reason_code == "policy_tokenize"
        card = by_type["CREDIT_CARD"]
        assert card.request_blocked is True
        assert card.reason_code == "policy_block"

    def test_entities_outside_policy_are_ignored(self):
        decisions = build_decisions([("URL", 0.9)], DEFAULT_POLICY)
        assert decisions == []

    def test_empty_detections_give_empty_decisions(self):
        assert build_decisions([], DEFAULT_POLICY) == []

    def test_blocked_entity_types_helper(self):
        decisions = build_decisions(
            [("EMAIL_ADDRESS", 0.9), ("CREDIT_CARD", 1.0), ("US_SSN", 0.85)],
            DEFAULT_POLICY,
        )
        assert blocked_entity_types(decisions) == ["CREDIT_CARD", "US_SSN"]

    def test_decisions_contain_no_values_field(self):
        decision = build_decisions([("EMAIL_ADDRESS", 0.9)], DEFAULT_POLICY)[0]
        assert set(decision.model_dump()) == {
            "entity_type",
            "action",
            "count",
            "score_min",
            "score_max",
            "request_blocked",
            "reason_code",
        }
