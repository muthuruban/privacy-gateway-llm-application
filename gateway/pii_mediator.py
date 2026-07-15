"""PII mediation: detection, policy-driven sanitization, and rehydration.

Wraps Microsoft Presidio (analyzer + anonymizer). For every piece of text
on the outbound path:

1. The Presidio ``AnalyzerEngine`` detects PII entities.
2. Each detected entity is handled according to the configured policy:
   * ``tokenize`` → replaced with a reversible placeholder such as
     ``[[EMAIL_ADDRESS_1]]``. The placeholder→value mapping is returned to
     the caller and held only in memory for the single request.
   * ``block``    → replaced with an irreversible ``[REDACTED:TYPE]`` marker.
   * ``allow``    → left untouched (the entity is not even requested from
     the analyzer).
3. On the inbound path, ``rehydrate`` substitutes the placeholders in the
   LLM's response back to the original values — for the calling
   application only. The LLM provider never sees the real values.

The same original value is always mapped to the same token within one
request, so the LLM can reason about "[[PERSON_1]]" as a stable referent.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from .config import PolicyAction

# UK National Insurance number, e.g. "QQ 12 34 56 C". Not shipped with
# Presidio, so registered as a custom recognizer — this also demonstrates
# how the gateway's entity coverage is extended.
_UK_NINO_PATTERN = Pattern(
    name="uk_nino",
    regex=r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b",
    score=0.6,
)


def _build_uk_nino_recognizer() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="UK_NINO",
        name="UkNinoRecognizer",
        patterns=[_UK_NINO_PATTERN],
        context=["nino", "national insurance", "ni number"],
    )


@dataclass
class SanitizationResult:
    """Outcome of sanitizing one piece of text."""

    text: str
    #: token → original value, for reversible (tokenized) entities only.
    mapping: dict[str, str] = field(default_factory=dict)
    #: entity_type → {"action": ..., "count": ...} — safe to persist in the
    #: audit log because it contains no raw PII values.
    findings: dict[str, dict] = field(default_factory=dict)


class PIIMediator:
    """Policy-driven PII sanitizer/rehydrator built on Presidio."""

    def __init__(
        self,
        policy: dict[str, PolicyAction],
        score_threshold: float = 0.4,
        language: str = "en",
        spacy_model: str = "en_core_web_sm",
    ):
        self.policy = policy
        self.score_threshold = score_threshold
        self.language = language

        nlp_engine = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": language, "model_name": spacy_model}],
            }
        ).create_engine()
        self.analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine, supported_languages=[language]
        )
        self.analyzer.registry.add_recognizer(_build_uk_nino_recognizer())
        self.anonymizer = AnonymizerEngine()

    def sanitize(self, text: str) -> SanitizationResult:
        """Detect PII in ``text`` and apply the configured policy."""
        # Only ask the analyzer for entity types the policy acts on.
        active_entities = [
            entity
            for entity, action in self.policy.items()
            if action is not PolicyAction.ALLOW
        ]
        if not active_entities or not text:
            return SanitizationResult(text=text)

        analyzer_results = self.analyzer.analyze(
            text=text,
            entities=active_entities,
            language=self.language,
            score_threshold=self.score_threshold,
        )
        if not analyzer_results:
            return SanitizationResult(text=text)

        mapping: dict[str, str] = {}       # token → original value
        value_to_token: dict[tuple[str, str], str] = {}  # (type, value) → token
        counters: dict[str, int] = {}      # entity type → next token index
        findings: dict[str, dict] = {}

        def _tokenize(entity_type: str):
            """Build a per-entity-type operator that mints reversible tokens."""

            def _operator(original: str) -> str:
                key = (entity_type, original)
                if key not in value_to_token:
                    counters[entity_type] = counters.get(entity_type, 0) + 1
                    token = f"[[{entity_type}_{counters[entity_type]}]]"
                    value_to_token[key] = token
                    mapping[token] = original
                return value_to_token[key]

            return _operator

        operators: dict[str, OperatorConfig] = {}
        for entity in active_entities:
            if self.policy[entity] is PolicyAction.TOKENIZE:
                operators[entity] = OperatorConfig(
                    "custom", {"lambda": _tokenize(entity)}
                )
            else:  # PolicyAction.BLOCK — irreversible, no mapping kept.
                operators[entity] = OperatorConfig(
                    "replace", {"new_value": f"[REDACTED:{entity}]"}
                )

        anonymized = self.anonymizer.anonymize(
            text=text, analyzer_results=analyzer_results, operators=operators
        )

        # Summarize what was found, without recording any raw values.
        for result in analyzer_results:
            entry = findings.setdefault(
                result.entity_type,
                {"action": self.policy[result.entity_type].value, "count": 0},
            )
            entry["count"] += 1

        return SanitizationResult(text=anonymized.text, mapping=mapping, findings=findings)

    @staticmethod
    def rehydrate(text: str, mapping: dict[str, str]) -> str:
        """Replace placeholder tokens in ``text`` with their original values.

        Used on the LLM's response before it is returned to the calling
        application. Blocked (redacted) entities have no mapping entry and
        therefore stay redacted forever.
        """
        for token, original in mapping.items():
            text = text.replace(token, original)
        return text

    @staticmethod
    def merge_findings(per_message: list[dict[str, dict]]) -> dict[str, dict]:
        """Combine findings from several sanitized texts into one summary."""
        merged: dict[str, dict] = {}
        for findings in per_message:
            for entity_type, info in findings.items():
                entry = merged.setdefault(
                    entity_type, {"action": info["action"], "count": 0}
                )
                entry["count"] += info["count"]
        return merged
