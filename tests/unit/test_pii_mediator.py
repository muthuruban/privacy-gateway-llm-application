"""PII mediator: detection against a labelled fixture set, policy
application (tokenize/redact/allow), block refusal, and cross-message
tokenization through one shared context."""

from __future__ import annotations

import pytest

from gateway.policy import DEFAULT_POLICY, PolicyAction
from gateway.tokenization import TOKEN_PATTERN, TokenizationContext

# Labelled fixture set: (text, PII substrings that must not survive
# sanitization under the default policy, entity types expected among the
# detections). All values are synthetic.
LABELLED_FIXTURES = [
    (
        "Hi, my name is John Smith and my email is john.smith@example.com.",
        ["john.smith@example.com"],
        {"EMAIL_ADDRESS"},
    ),
    (
        "Please call me on +44 7911 123456 tomorrow.",
        ["+44 7911 123456"],
        {"PHONE_NUMBER"},
    ),
    (
        # A validly formatted NINO: the recognizer follows HMRC prefix
        # rules, which exclude the reserved example prefix "QQ".
        "My national insurance number is AB 12 34 56 C.",
        ["AB 12 34 56 C"],
        {"UK_NINO"},
    ),
    (
        "Contact Alice Johnson at alice.johnson@example.com or 212-555-0142.",
        ["alice.johnson@example.com", "212-555-0142"],
        {"EMAIL_ADDRESS", "PHONE_NUMBER"},
    ),
]


def _mediate(mediator, text, context=None):
    results = mediator.analyze(text)
    # Note: "context or ..." would discard an *empty* passed-in context
    # (it is falsy via __len__); the identity check keeps it.
    ctx = context if context is not None else TokenizationContext(text)
    return mediator.apply(text, results, ctx), results


class TestDetection:
    def test_labelled_fixtures_are_sanitized(self, mediator):
        for text, pii_values, expected_types in LABELLED_FIXTURES:
            sanitized, results = _mediate(mediator, text)
            for value in pii_values:
                assert value not in sanitized, (
                    f"PII value {value!r} survived sanitization: {sanitized!r}"
                )
            detected = {r.entity_type for r in results}
            assert expected_types <= detected, (
                f"Expected {expected_types} among detections for {text!r}, got {detected}"
            )

    def test_clean_text_passes_through_unchanged(self, mediator):
        text = "Explain the difference between a list and a tuple."
        sanitized, results = _mediate(mediator, text)
        assert sanitized == text
        assert results == []

    def test_empty_text(self, mediator):
        assert mediator.analyze("") == []
        assert mediator.apply("", [], None) == ""

    def test_block_entities_are_still_detected(self, mediator):
        # BLOCK is enforced by the caller; detection must still find the
        # entity so the caller has something to enforce.
        results = mediator.analyze("Charge card 4111 1111 1111 1111 please.")
        assert "CREDIT_CARD" in {r.entity_type for r in results}

    def test_allow_entities_are_still_detected(self, mediator):
        # ALLOW is a recorded decision, not an exclusion from detection.
        text = "Let's meet on 25 December 2025 to review."
        results = mediator.analyze(text)
        assert "DATE_TIME" in {r.entity_type for r in results}
        sanitized = mediator.apply(text, results, TokenizationContext(text))
        assert "25 December 2025" in sanitized  # allowed → untouched


class TestApplyActions:
    def test_tokenize_round_trip(self, mediator):
        text = "Email john.smith@example.com and call +44 7911 123456."
        ctx = TokenizationContext(text)
        sanitized, _ = _mediate(mediator, text, ctx)
        assert "john.smith@example.com" not in sanitized
        assert TOKEN_PATTERN.search(sanitized)
        assert ctx.rehydrate(sanitized) == text

    def test_redact_is_irreversible(self, mediator):
        text = "My national insurance number is AB 12 34 56 C."
        ctx = TokenizationContext(text)
        sanitized, _ = _mediate(mediator, text, ctx)
        assert "[REDACTED:UK_NINO]" in sanitized
        assert "AB 12 34 56 C" not in sanitized
        # No mapping exists, so rehydration cannot restore it.
        assert "AB 12 34 56 C" not in ctx.rehydrate(sanitized)

    def test_apply_refuses_block_entities(self, mediator):
        text = "Charge card 4111 1111 1111 1111 please."
        results = mediator.analyze(text)
        with pytest.raises(RuntimeError, match="BLOCK"):
            mediator.apply(text, results, TokenizationContext(text))

    def test_apply_refuses_tokenize_without_context(self, mediator):
        text = "Email john.smith@example.com."
        results = mediator.analyze(text)
        with pytest.raises(RuntimeError, match="[Cc]ontext"):
            mediator.apply(text, results, None)

    def test_redact_all_removes_every_detection(self, mediator):
        text = "I'm John Smith, email john.smith@example.com, meet on 25 December 2025."
        results = mediator.analyze(text)
        redacted = mediator.redact_all(text, results)
        assert "john.smith@example.com" not in redacted
        assert "John Smith" not in redacted
        assert "[REDACTED:EMAIL_ADDRESS]" in redacted


class TestCrossMessageContext:
    def test_two_different_emails_in_two_messages_get_distinct_tokens(self, mediator):
        # The original defect this design fixes: per-message counters
        # minted the same placeholder for different values.
        ctx = TokenizationContext()
        first, _ = _mediate(mediator, "Email alice@example.com", ctx)
        second, _ = _mediate(mediator, "Email bob@example.com", ctx)
        tokens_first = TOKEN_PATTERN.findall(first)
        tokens_second = TOKEN_PATTERN.findall(second)
        assert tokens_first and tokens_second
        assert set(tokens_first).isdisjoint(tokens_second)
        assert ctx.rehydrate(first) == "Email alice@example.com"
        assert ctx.rehydrate(second) == "Email bob@example.com"

    def test_repeated_email_across_messages_reuses_token(self, mediator):
        ctx = TokenizationContext()
        first, _ = _mediate(mediator, "Write to alice@example.com now.", ctx)
        second, _ = _mediate(mediator, "Remind alice@example.com tomorrow.", ctx)
        tokens = set(TOKEN_PATTERN.findall(first)) | set(TOKEN_PATTERN.findall(second))
        assert len(tokens) == 1

    def test_multiple_entity_types_across_messages(self, mediator):
        ctx = TokenizationContext()
        _mediate(mediator, "I'm Alice Johnson, alice@example.com.", ctx)
        _mediate(mediator, "Bob Roberts is on +44 7911 123456.", ctx)
        joined = " ".join(ctx.token_to_value)
        assert "EMAIL_ADDRESS" in joined
        assert "PERSON" in joined
        assert "PHONE_NUMBER" in joined
        # Every mapping restores its own original value.
        assert (
            ctx.token_to_value[next(t for t in ctx.token_to_value if "EMAIL_ADDRESS" in t)]
            == "alice@example.com"
        )


class TestCloneWithPolicy:
    def test_clone_shares_engines_but_not_policy(self, mediator):
        clone = mediator.clone_with_policy({"EMAIL_ADDRESS": PolicyAction.REDACT})
        assert clone.analyzer is mediator.analyzer
        assert clone.policy != mediator.policy
        assert mediator.policy == DEFAULT_POLICY

    def test_clone_applies_its_own_policy(self, mediator):
        clone = mediator.clone_with_policy({"EMAIL_ADDRESS": PolicyAction.REDACT})
        text = "Email alice@example.com"
        sanitized = clone.apply(text, clone.analyze(text), None)
        assert "[REDACTED:EMAIL_ADDRESS]" in sanitized
