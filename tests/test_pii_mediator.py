"""PII mediator tests: detection against a labelled fixture set,
tokenization round-trip correctness, and block-vs-tokenize policy handling."""

from gateway.config import PolicyAction
from gateway.pii_mediator import PIIMediator

# Small labelled fixture set: (text, PII substrings that must not survive
# sanitization, entity types expected among the findings).
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
        "My card number is 4111 1111 1111 1111, please update my billing.",
        ["4111 1111 1111 1111"],
        {"CREDIT_CARD"},
    ),
    (
        # Note: a *validly formatted* NINO. The recognizer follows HMRC
        # rules, which exclude prefixes like QQ (reserved for examples).
        "My national insurance number is AB 12 34 56 C.",
        ["AB 12 34 56 C"],
        {"UK_NINO"},
    ),
    (
        "Contact Sarah Connor at sarah.connor@skynet.io or 212-555-0142.",
        ["sarah.connor@skynet.io", "212-555-0142"],
        {"EMAIL_ADDRESS", "PHONE_NUMBER"},
    ),
]


class TestDetection:
    def test_labelled_fixtures_are_sanitized(self, mediator):
        for text, pii_values, expected_types in LABELLED_FIXTURES:
            result = mediator.sanitize(text)
            for value in pii_values:
                assert value not in result.text, (
                    f"PII value {value!r} survived sanitization: {result.text!r}"
                )
            assert expected_types <= set(result.findings), (
                f"Expected {expected_types} among findings for {text!r}, "
                f"got {set(result.findings)}"
            )

    def test_clean_text_passes_through_unchanged(self, mediator):
        # No detectable entities at all — note that e.g. "France" would be
        # tokenized, because LOCATION is under mediation in the policy.
        text = "Explain the difference between a list and a tuple."
        result = mediator.sanitize(text)
        assert result.text == text
        assert result.mapping == {}
        assert result.findings == {}

    def test_empty_text(self, mediator):
        result = mediator.sanitize("")
        assert result.text == ""
        assert result.mapping == {}


class TestTokenization:
    def test_round_trip_restores_original(self, mediator):
        text = "Email john.smith@example.com and call +44 7911 123456."
        result = mediator.sanitize(text)
        assert "john.smith@example.com" not in result.text
        restored = PIIMediator.rehydrate(result.text, result.mapping)
        assert restored == text

    def test_same_value_gets_same_token(self, mediator):
        text = (
            "Write to john.smith@example.com today. "
            "Yesterday john.smith@example.com asked about the invoice."
        )
        result = mediator.sanitize(text)
        email_tokens = [t for t in result.mapping if t.startswith("[[EMAIL_ADDRESS")]
        assert len(email_tokens) == 1
        assert result.text.count(email_tokens[0]) == 2

    def test_distinct_values_get_distinct_tokens(self, mediator):
        text = "Email alice@example.com and bob@example.com."
        result = mediator.sanitize(text)
        email_tokens = [t for t in result.mapping if t.startswith("[[EMAIL_ADDRESS")]
        assert len(email_tokens) == 2

    def test_rehydrate_only_touches_known_tokens(self, mediator):
        text = "Reply to [[EMAIL_ADDRESS_1]] and leave [[SOMETHING_ELSE_1]] alone."
        mapping = {"[[EMAIL_ADDRESS_1]]": "alice@example.com"}
        restored = PIIMediator.rehydrate(text, mapping)
        assert restored == "Reply to alice@example.com and leave [[SOMETHING_ELSE_1]] alone."


class TestBlockPolicy:
    def test_blocked_entity_is_irreversibly_redacted(self, mediator):
        text = "My card number is 4111 1111 1111 1111."
        result = mediator.sanitize(text)
        assert "[REDACTED:CREDIT_CARD]" in result.text
        # No mapping entry exists, so rehydration cannot restore it.
        assert "4111" not in str(result.mapping)
        restored = PIIMediator.rehydrate(result.text, result.mapping)
        assert "4111 1111 1111 1111" not in restored

    def test_allowed_entity_is_untouched(self):
        # DATE_TIME is "allow" in this policy: dates must survive.
        mediator = PIIMediator(
            policy={
                "EMAIL_ADDRESS": PolicyAction.TOKENIZE,
                "DATE_TIME": PolicyAction.ALLOW,
            }
        )
        text = "Meet me on 25 December at alice@example.com."
        result = mediator.sanitize(text)
        assert "25 December" in result.text
        assert "alice@example.com" not in result.text

    def test_findings_contain_no_raw_values(self, mediator):
        text = "I am John Smith, card 4111 1111 1111 1111, email js@example.com."
        result = mediator.sanitize(text)
        findings_str = str(result.findings)
        for raw in ("John Smith", "4111", "js@example.com"):
            assert raw not in findings_str
        for info in result.findings.values():
            assert set(info) == {"action", "count"}
